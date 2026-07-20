use std::{
    io,
    pin::Pin,
    task::{Context, Poll},
};

use bytes::{Buf, BufMut, BytesMut};
use futures::{Sink, Stream, ready};
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
use tracing::{debug, trace};

use crate::{
    proxy::{AnyStream, datagram::UdpPacket},
    session::SocksAddr,
};

pub(crate) const VERSION: u8 = 2;
pub(crate) const LEGACY_VERSION: u8 = 1;
pub(crate) const MAGIC_ADDRESS: &str = "sp.v2.udp-over-tcp.arpa";
pub(crate) const LEGACY_MAGIC_ADDRESS: &str = "sp.udp-over-tcp.arpa";
const MAX_PACKET_LENGTH: usize = u16::MAX as usize;

pub(crate) fn request_destination(version: u8) -> io::Result<SocksAddr> {
    let host = match version {
        VERSION => MAGIC_ADDRESS,
        LEGACY_VERSION => LEGACY_MAGIC_ADDRESS,
        _ => {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                format!("unknown udp-over-tcp protocol version: {version}"),
            ));
        }
    };
    SocksAddr::try_from((host.to_owned(), 0))
}

/// Encode the sing UoT v2 connect request. The address uses the standard
/// SOCKS address serializer, exactly as `sing/common/uot.WriteRequest` does.
pub(crate) fn encode_connect_request(destination: &SocksAddr) -> BytesMut {
    let mut request = BytesMut::with_capacity(1 + destination.size());
    request.put_u8(1); // isConnect = true
    destination.write_buf(&mut request);
    request
}

/// A connected UoT packet stream. Both legacy v1 and connect-mode v2 use the
/// same big-endian u16 length framing once their version-specific handshake
/// has completed.
pub(crate) struct ConnectedDatagram {
    inner: AnyStream,
    target_addr: SocksAddr,

    write_buf: BytesMut,
    pending_packet: Option<UdpPacket>,
    flushed: bool,

    header_read: usize,
    packet_len: Option<usize>,
    packet_buf: BytesMut,
    length_buf: [u8; 2],
}

impl ConnectedDatagram {
    pub(crate) fn new(inner: AnyStream, target_addr: SocksAddr) -> Self {
        Self {
            inner,
            target_addr,
            write_buf: BytesMut::new(),
            pending_packet: None,
            flushed: true,
            header_read: 0,
            packet_len: None,
            packet_buf: BytesMut::new(),
            length_buf: [0; 2],
        }
    }

    fn write_packet(&mut self, payload: &[u8]) -> io::Result<()> {
        if payload.len() > MAX_PACKET_LENGTH {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                format!(
                    "udp payload too large for UoT: {} > {}",
                    payload.len(),
                    MAX_PACKET_LENGTH
                ),
            ));
        }

        self.write_buf.clear();
        self.write_buf.put_u16(payload.len() as u16);
        self.write_buf.put_slice(payload);
        Ok(())
    }
}

impl Sink<UdpPacket> for ConnectedDatagram {
    type Error = io::Error;

    fn poll_ready(
        self: Pin<&mut Self>,
        context: &mut Context<'_>,
    ) -> Poll<Result<(), Self::Error>> {
        if !self.flushed {
            match self.poll_flush(context)? {
                Poll::Ready(()) => {}
                Poll::Pending => return Poll::Pending,
            }
        }
        Poll::Ready(Ok(()))
    }

    fn start_send(self: Pin<&mut Self>, packet: UdpPacket) -> io::Result<()> {
        let this = self.get_mut();
        if this.pending_packet.is_some() {
            return Err(io::Error::new(
                io::ErrorKind::WouldBlock,
                "previous UoT packet is not yet sent",
            ));
        }
        this.write_packet(&packet.data)?;
        this.pending_packet = Some(packet);
        this.flushed = false;
        Ok(())
    }

    fn poll_flush(
        self: Pin<&mut Self>,
        context: &mut Context<'_>,
    ) -> Poll<io::Result<()>> {
        if self.flushed {
            return Poll::Ready(Ok(()));
        }

        let this = self.get_mut();
        let mut inner = Pin::new(&mut this.inner);
        while !this.write_buf.is_empty() {
            let written =
                ready!(inner.as_mut().poll_write(context, &this.write_buf))?;
            if written == 0 {
                return Poll::Ready(Err(io::Error::new(
                    io::ErrorKind::WriteZero,
                    "failed to write UoT packet",
                )));
            }
            this.write_buf.advance(written);
        }
        ready!(inner.poll_flush(context))?;

        if let Some(packet) = &this.pending_packet {
            trace!("sent UoT udp packet, len={}", packet.data.len());
        }
        this.pending_packet = None;
        this.flushed = true;
        Poll::Ready(Ok(()))
    }

    fn poll_close(
        mut self: Pin<&mut Self>,
        context: &mut Context<'_>,
    ) -> Poll<io::Result<()>> {
        ready!(self.as_mut().poll_flush(context))?;
        Pin::new(&mut self.get_mut().inner).poll_shutdown(context)
    }
}

impl Stream for ConnectedDatagram {
    type Item = UdpPacket;

    fn poll_next(
        self: Pin<&mut Self>,
        context: &mut Context<'_>,
    ) -> Poll<Option<Self::Item>> {
        let this = self.get_mut();
        let mut inner = Pin::new(&mut this.inner);

        loop {
            if this.packet_len.is_none() {
                let mut length_read =
                    ReadBuf::new(&mut this.length_buf[this.header_read..]);
                match ready!(inner.as_mut().poll_read(context, &mut length_read)) {
                    Ok(()) => {
                        let read = length_read.filled().len();
                        if read == 0 {
                            return Poll::Ready(None);
                        }
                        this.header_read += read;
                        if this.header_read < this.length_buf.len() {
                            continue;
                        }

                        let packet_len =
                            u16::from_be_bytes(this.length_buf) as usize;
                        this.header_read = 0;
                        if packet_len == 0 {
                            continue;
                        }
                        this.packet_len = Some(packet_len);
                        this.packet_buf.clear();
                        this.packet_buf.reserve(packet_len);
                    }
                    Err(error) => {
                        debug!("failed to read UoT udp length header: {error}");
                        return Poll::Ready(None);
                    }
                }
            }

            if let Some(packet_len) = this.packet_len {
                let remaining = packet_len - this.packet_buf.len();
                let read = {
                    let spare = this.packet_buf.spare_capacity_mut();
                    let mut read_buf = ReadBuf::uninit(&mut spare[..remaining]);
                    match inner.as_mut().poll_read(context, &mut read_buf) {
                        Poll::Pending => return Poll::Pending,
                        Poll::Ready(Err(error)) => {
                            debug!("failed to read UoT udp payload: {error}");
                            return Poll::Ready(None);
                        }
                        Poll::Ready(Ok(())) => read_buf.filled().len(),
                    }
                };
                if read == 0 {
                    return Poll::Ready(None);
                }
                // SAFETY: AsyncRead initialized exactly `read` bytes in the
                // spare capacity passed above.
                unsafe { this.packet_buf.advance_mut(read) };

                if this.packet_buf.len() == packet_len {
                    let data = this.packet_buf.split_to(packet_len).to_vec();
                    this.packet_len = None;
                    return Poll::Ready(Some(UdpPacket {
                        data,
                        src_addr: this.target_addr.clone(),
                        dst_addr: this.target_addr.clone(),
                        inbound_user: None,
                    }));
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use futures::{SinkExt, StreamExt};
    use tokio::io::{AsyncReadExt, AsyncWriteExt, duplex};

    use super::*;

    #[test]
    fn request_destinations_match_sing_uot() {
        assert_eq!(
            request_destination(VERSION).unwrap(),
            SocksAddr::Domain(MAGIC_ADDRESS.to_owned(), 0)
        );
        assert_eq!(
            request_destination(LEGACY_VERSION).unwrap(),
            SocksAddr::Domain(LEGACY_MAGIC_ADDRESS.to_owned(), 0)
        );
        assert!(request_destination(3).is_err());
    }

    #[test]
    fn v2_connect_request_uses_standard_socks_address() {
        let destination =
            SocksAddr::try_from(("dns.example".to_owned(), 53)).unwrap();
        let request = encode_connect_request(&destination);
        assert_eq!(request[0], 1);
        assert_eq!(SocksAddr::try_from(&request[1..]).unwrap(), destination);
    }

    #[tokio::test]
    async fn connected_datagram_has_sing_length_framing() {
        let target = SocksAddr::from((std::net::Ipv4Addr::LOCALHOST, 53));
        let (client, mut server) = duplex(1024);
        let mut datagram = ConnectedDatagram::new(Box::new(client), target.clone());

        let packet = UdpPacket {
            data: b"query".to_vec(),
            src_addr: target.clone(),
            dst_addr: target.clone(),
            inbound_user: None,
        };
        datagram.send(packet).await.unwrap();

        assert_eq!(server.read_u16().await.unwrap(), 5);
        let mut payload = [0u8; 5];
        server.read_exact(&mut payload).await.unwrap();
        assert_eq!(&payload, b"query");

        server.write_u16(5).await.unwrap();
        server.write_all(b"reply").await.unwrap();
        let reply = datagram.next().await.unwrap();
        assert_eq!(reply.data, b"reply");
        assert_eq!(reply.src_addr, target);
    }
}
