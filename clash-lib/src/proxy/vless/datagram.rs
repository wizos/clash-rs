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

const MAX_PACKET_LENGTH: usize = u16::MAX as usize;

pub struct OutboundDatagramVless {
    inner: AnyStream,
    remote_addr: SocksAddr,
    packet_addr: bool,

    // Write state
    write_buf: BytesMut,
    pending_packet: Option<UdpPacket>,

    // Read state
    length_buf: [u8; 2],
    length_read: usize,
    read_buf: Vec<u8>,
    payload_read: usize,

    // State tracking
    flushed: bool,
}

impl OutboundDatagramVless {
    pub fn new(inner: AnyStream, remote_addr: SocksAddr, packet_addr: bool) -> Self {
        Self {
            inner,
            remote_addr,
            packet_addr,
            write_buf: BytesMut::new(),
            pending_packet: None,
            length_buf: [0; 2],
            length_read: 0,
            read_buf: Vec::new(),
            payload_read: 0,
            flushed: true,
        }
    }

    fn write_packet(&mut self, packet: &UdpPacket) -> Result<(), io::Error> {
        self.write_buf.clear();

        let encoded;
        let payload = if self.packet_addr {
            encoded =
                super::super::packetaddr::encode(&packet.dst_addr, &packet.data)?;
            encoded.as_slice()
        } else {
            packet.data.as_slice()
        };

        // VLESS UDP packet format is simpler than expected:
        // Just 2-byte length + payload data
        // No address encoding in the packet data phase!

        if payload.len() > MAX_PACKET_LENGTH {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                format!(
                    "packet too large: {} > {}",
                    payload.len(),
                    MAX_PACKET_LENGTH
                ),
            ));
        }

        // Write length header (big-endian)
        self.write_buf.put_u16(payload.len() as u16);

        // Write payload
        self.write_buf.put_slice(payload);

        trace!("encoded VLESS UDP packet: len={}", payload.len());
        Ok(())
    }
}

impl Sink<UdpPacket> for OutboundDatagramVless {
    type Error = io::Error;

    fn poll_ready(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<Result<(), Self::Error>> {
        if !self.flushed {
            match self.poll_flush(cx)? {
                Poll::Ready(()) => {}
                Poll::Pending => return Poll::Pending,
            }
        }
        Poll::Ready(Ok(()))
    }

    fn start_send(self: Pin<&mut Self>, item: UdpPacket) -> Result<(), Self::Error> {
        let this = self.get_mut();

        if this.pending_packet.is_some() {
            return Err(io::Error::new(
                io::ErrorKind::WouldBlock,
                "previous packet not yet sent",
            ));
        }

        let total_len = item.data.len();
        if total_len == 0 {
            return Ok(()); // Skip empty packets
        }

        // VLESS uses one unsigned 16-bit length prefix. Splitting a datagram
        // changes its semantics, so reject unrepresentable values rather than
        // silently truncating them.
        this.write_packet(&item)?;
        this.pending_packet = Some(item);
        this.flushed = false;

        Ok(())
    }

    fn poll_flush(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<Result<(), Self::Error>> {
        if self.flushed {
            return Poll::Ready(Ok(()));
        }

        let this = self.get_mut();

        if this.write_buf.is_empty() {
            this.flushed = true;
            this.pending_packet = None;
            return Poll::Ready(Ok(()));
        }

        let mut inner = Pin::new(&mut this.inner);

        // Write the encoded packet
        while !this.write_buf.is_empty() {
            let n = ready!(inner.as_mut().poll_write(cx, &this.write_buf))?;
            if n == 0 {
                return Poll::Ready(Err(io::Error::new(
                    io::ErrorKind::WriteZero,
                    "failed to write packet data",
                )));
            }
            this.write_buf.advance(n);
        }

        // Flush the underlying stream
        ready!(inner.poll_flush(cx))?;

        if let Some(packet) = &this.pending_packet {
            debug!("sent VLESS UDP packet, data_len={}", packet.data.len());
        }

        this.flushed = true;
        this.pending_packet = None;

        Poll::Ready(Ok(()))
    }

    fn poll_close(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<Result<(), Self::Error>> {
        ready!(self.as_mut().poll_flush(cx))?;
        Pin::new(&mut self.get_mut().inner).poll_shutdown(cx)
    }
}

impl Stream for OutboundDatagramVless {
    type Item = UdpPacket;

    fn poll_next(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<Option<Self::Item>> {
        let this = self.get_mut();

        loop {
            if this.read_buf.is_empty() {
                while this.length_read < this.length_buf.len() {
                    let mut read_buf =
                        ReadBuf::new(&mut this.length_buf[this.length_read..]);
                    match ready!(
                        Pin::new(&mut this.inner).poll_read(cx, &mut read_buf)
                    ) {
                        Ok(()) if read_buf.filled().is_empty() => {
                            if this.length_read != 0 {
                                debug!(
                                    "VLESS UDP stream closed in the middle of a \
                                     length header"
                                );
                            }
                            return Poll::Ready(None);
                        }
                        Ok(()) => this.length_read += read_buf.filled().len(),
                        Err(error) => {
                            debug!(
                                "failed to read VLESS UDP length header: {error}"
                            );
                            return Poll::Ready(None);
                        }
                    }
                }

                let packet_len = u16::from_be_bytes(this.length_buf) as usize;
                this.length_read = 0;
                if packet_len == 0 {
                    trace!("received empty VLESS UDP packet");
                    continue;
                }
                this.read_buf.resize(packet_len, 0);
                this.payload_read = 0;
                trace!("expecting VLESS UDP packet of {packet_len} bytes");
            }

            while this.payload_read < this.read_buf.len() {
                let mut read_buf =
                    ReadBuf::new(&mut this.read_buf[this.payload_read..]);
                match ready!(Pin::new(&mut this.inner).poll_read(cx, &mut read_buf))
                {
                    Ok(()) if read_buf.filled().is_empty() => {
                        debug!("VLESS UDP stream closed in the middle of a packet");
                        return Poll::Ready(None);
                    }
                    Ok(()) => this.payload_read += read_buf.filled().len(),
                    Err(error) => {
                        debug!("failed to read VLESS UDP packet: {error}");
                        return Poll::Ready(None);
                    }
                }
            }

            let data = std::mem::take(&mut this.read_buf);
            this.payload_read = 0;
            trace!("received complete VLESS UDP packet, len={}", data.len());
            let (src_addr, data) = if this.packet_addr {
                match super::super::packetaddr::decode(&data) {
                    Ok((address, payload)) => (address, payload.to_vec()),
                    Err(error) => {
                        debug!("failed to decode VLESS packetaddr packet: {error}");
                        return Poll::Ready(None);
                    }
                }
            } else {
                (this.remote_addr.clone(), data)
            };
            return Poll::Ready(Some(UdpPacket {
                data,
                src_addr,
                dst_addr: this.remote_addr.clone(),
                inbound_user: None,
            }));
        }
    }
}

#[cfg(test)]
mod tests {
    use futures::{SinkExt, StreamExt};
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    use super::*;

    fn packet(data: Vec<u8>) -> UdpPacket {
        UdpPacket::new(
            data,
            SocksAddr::any_ipv4(),
            SocksAddr::Domain("dns.example".to_owned(), 53),
        )
    }

    #[tokio::test]
    async fn sends_complete_large_datagram() {
        let (client, mut server) = tokio::io::duplex(128 * 1024);
        let remote = SocksAddr::Domain("dns.example".to_owned(), 53);
        let mut datagram =
            OutboundDatagramVless::new(Box::new(client), remote, false);
        let payload = vec![0x5a; 60_000];

        datagram.send(packet(payload.clone())).await.unwrap();

        let length = server.read_u16().await.unwrap() as usize;
        let mut received = vec![0; length];
        server.read_exact(&mut received).await.unwrap();
        assert_eq!(length, payload.len());
        assert_eq!(received, payload);
    }

    #[tokio::test]
    async fn rejects_datagram_larger_than_u16_frame() {
        let (client, _server) = tokio::io::duplex(64);
        let remote = SocksAddr::Domain("dns.example".to_owned(), 53);
        let mut datagram =
            OutboundDatagramVless::new(Box::new(client), remote, false);

        let error = datagram
            .send(packet(vec![0; MAX_PACKET_LENGTH + 1]))
            .await
            .unwrap_err();
        assert_eq!(error.kind(), io::ErrorKind::InvalidInput);
    }

    #[tokio::test]
    async fn reassembles_fragmented_stream_into_one_datagram() {
        let (client, mut server) = tokio::io::duplex(64);
        let remote = SocksAddr::Domain("dns.example".to_owned(), 53);
        let mut datagram =
            OutboundDatagramVless::new(Box::new(client), remote, false);
        let payload = b"fragmented-vless-udp-payload".to_vec();
        let expected = payload.clone();

        tokio::spawn(async move {
            let length = (payload.len() as u16).to_be_bytes();
            server.write_all(&length[..1]).await.unwrap();
            tokio::task::yield_now().await;
            server.write_all(&length[1..]).await.unwrap();
            for byte in payload {
                server.write_all(&[byte]).await.unwrap();
                tokio::task::yield_now().await;
            }
        });

        let received = datagram.next().await.unwrap();
        assert_eq!(received.data, expected);
        assert!(datagram.next().await.is_none());
    }
}
