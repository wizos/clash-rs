use std::{
    hash::{BuildHasher, Hash, Hasher, RandomState},
    io,
    net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr},
    pin::Pin,
    sync::OnceLock,
    task::{Context, Poll},
};

use bytes::{Buf, BufMut, BytesMut};
use futures::{Sink, Stream, ready};
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
use tracing::debug;

use crate::{
    proxy::{AnyStream, datagram::UdpPacket},
    session::SocksAddr,
};

const STATUS_NEW: u8 = 1;
const STATUS_KEEP: u8 = 2;
const STATUS_END: u8 = 3;
const STATUS_KEEP_ALIVE: u8 = 4;
const OPTION_DATA: u8 = 1;
const OPTION_ERROR: u8 = 2;
const NETWORK_UDP: u8 = 2;
const MIN_FRAME_LENGTH: usize = 4;
const READ_BUFFER_SIZE: usize = 16 * 1024;

pub(crate) struct OutboundDatagramXudp {
    inner: AnyStream,
    remote_addr: SocksAddr,
    global_id: Option<[u8; 8]>,
    request_written: bool,
    write_buf: BytesMut,
    pending_packet: bool,
    read_buf: BytesMut,
    read_scratch: Vec<u8>,
}

impl OutboundDatagramXudp {
    pub(crate) fn new(
        inner: AnyStream,
        remote_addr: SocksAddr,
        source: SocketAddr,
    ) -> Self {
        Self {
            inner,
            remote_addr,
            global_id: global_id(source),
            request_written: false,
            write_buf: BytesMut::new(),
            pending_packet: false,
            read_buf: BytesMut::new(),
            read_scratch: vec![0; READ_BUFFER_SIZE],
        }
    }

    fn encode_packet(&mut self, packet: &UdpPacket) -> io::Result<()> {
        if packet.data.len() > u16::MAX as usize {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                format!(
                    "XUDP datagram is too large: {} > {}",
                    packet.data.len(),
                    u16::MAX
                ),
            ));
        }
        let mut address = BytesMut::new();
        encode_address(&packet.dst_addr, &mut address)?;

        self.write_buf.clear();
        if !self.request_written {
            let global_id_len = self.global_id.map(|_| 8).unwrap_or_default();
            let frame_length = 5 + address.len() + global_id_len;
            self.write_buf.put_u16(frame_length as u16);
            self.write_buf.put_u16(0);
            self.write_buf.put_u8(STATUS_NEW);
            self.write_buf.put_u8(OPTION_DATA);
            self.write_buf.put_u8(NETWORK_UDP);
            self.write_buf.extend_from_slice(&address);
            if let Some(global_id) = self.global_id {
                self.write_buf.extend_from_slice(&global_id);
            }
            self.request_written = true;
        } else {
            self.write_buf.put_u16((5 + address.len()) as u16);
            self.write_buf.put_u16(0);
            self.write_buf.put_u8(STATUS_KEEP);
            self.write_buf.put_u8(OPTION_DATA);
            self.write_buf.put_u8(NETWORK_UDP);
            self.write_buf.extend_from_slice(&address);
        }
        self.write_buf.put_u16(packet.data.len() as u16);
        self.write_buf.extend_from_slice(&packet.data);
        Ok(())
    }
}

impl Sink<UdpPacket> for OutboundDatagramXudp {
    type Error = io::Error;

    fn poll_ready(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<Result<(), Self::Error>> {
        if self.pending_packet {
            ready!(self.as_mut().poll_flush(cx))?;
        }
        Poll::Ready(Ok(()))
    }

    fn start_send(mut self: Pin<&mut Self>, packet: UdpPacket) -> io::Result<()> {
        if self.pending_packet {
            return Err(io::Error::new(
                io::ErrorKind::WouldBlock,
                "previous XUDP datagram has not been flushed",
            ));
        }
        self.encode_packet(&packet)?;
        self.pending_packet = true;
        Ok(())
    }

    fn poll_flush(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<Result<(), Self::Error>> {
        while !self.write_buf.is_empty() {
            let this = &mut *self;
            let written =
                ready!(Pin::new(&mut this.inner).poll_write(cx, &this.write_buf))?;
            if written == 0 {
                return Poll::Ready(Err(io::Error::new(
                    io::ErrorKind::WriteZero,
                    "failed to write XUDP datagram",
                )));
            }
            self.write_buf.advance(written);
        }
        ready!(Pin::new(&mut self.inner).poll_flush(cx))?;
        self.pending_packet = false;
        Poll::Ready(Ok(()))
    }

    fn poll_close(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<Result<(), Self::Error>> {
        ready!(self.as_mut().poll_flush(cx))?;
        Pin::new(&mut self.inner).poll_shutdown(cx)
    }
}

impl Stream for OutboundDatagramXudp {
    type Item = UdpPacket;

    fn poll_next(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<Option<Self::Item>> {
        loop {
            let parse_result = {
                let this = &mut *self;
                parse_packet(&mut this.read_buf, &this.remote_addr)
            };
            match parse_result {
                Ok(ParseResult::Packet(source, data)) => {
                    return Poll::Ready(Some(UdpPacket {
                        data,
                        src_addr: source,
                        dst_addr: SocksAddr::any_ipv4(),
                        inbound_user: None,
                    }));
                }
                Ok(ParseResult::Skip) => continue,
                Ok(ParseResult::End) => return Poll::Ready(None),
                Ok(ParseResult::Incomplete) => {}
                Err(error) => {
                    debug!("failed to decode XUDP response: {error}");
                    return Poll::Ready(None);
                }
            }

            let this = &mut *self;
            let mut read = ReadBuf::new(&mut this.read_scratch);
            match ready!(Pin::new(&mut this.inner).poll_read(cx, &mut read)) {
                Ok(()) if read.filled().is_empty() => {
                    if !this.read_buf.is_empty() {
                        debug!("XUDP stream closed with a partial frame");
                    }
                    return Poll::Ready(None);
                }
                Ok(()) => this.read_buf.extend_from_slice(read.filled()),
                Err(error) => {
                    debug!("failed to read XUDP response: {error}");
                    return Poll::Ready(None);
                }
            }
        }
    }
}

enum ParseResult {
    Incomplete,
    Skip,
    Packet(SocksAddr, Vec<u8>),
    End,
}

fn parse_packet(
    buffer: &mut BytesMut,
    default_destination: &SocksAddr,
) -> io::Result<ParseResult> {
    if buffer.len() < 2 {
        return Ok(ParseResult::Incomplete);
    }
    let frame_length = u16::from_be_bytes([buffer[0], buffer[1]]) as usize;
    if frame_length < MIN_FRAME_LENGTH {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!("invalid XUDP frame length {frame_length}"),
        ));
    }
    let header_end = 2 + frame_length;
    if buffer.len() < header_end {
        return Ok(ParseResult::Incomplete);
    }

    let status = buffer[4];
    let option = buffer[5];
    if option & OPTION_ERROR != 0 {
        return Err(io::Error::other("XUDP peer closed with an error"));
    }
    let destination = match status {
        STATUS_NEW => {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "unexpected XUDP new frame from server",
            ));
        }
        STATUS_KEEP if frame_length != MIN_FRAME_LENGTH => {
            if frame_length < 6 || buffer[6] != NETWORK_UDP {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "invalid XUDP UDP frame header",
                ));
            }
            let (destination, _) = decode_address(&buffer[7..header_end])?;
            destination
        }
        STATUS_KEEP => default_destination.clone(),
        STATUS_END => {
            buffer.advance(header_end);
            return Ok(ParseResult::End);
        }
        STATUS_KEEP_ALIVE => default_destination.clone(),
        status => {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                format!("unknown XUDP status {status}"),
            ));
        }
    };

    if option & OPTION_DATA == 0 {
        buffer.advance(header_end);
        return Ok(ParseResult::Skip);
    }
    if buffer.len() < header_end + 2 {
        return Ok(ParseResult::Incomplete);
    }
    let payload_length =
        u16::from_be_bytes([buffer[header_end], buffer[header_end + 1]]) as usize;
    let packet_end = header_end + 2 + payload_length;
    if buffer.len() < packet_end {
        return Ok(ParseResult::Incomplete);
    }
    let data = buffer[header_end + 2..packet_end].to_vec();
    buffer.advance(packet_end);
    Ok(ParseResult::Packet(destination, data))
}

fn encode_address(address: &SocksAddr, buffer: &mut BytesMut) -> io::Result<()> {
    if let SocksAddr::Domain(domain, _) = address
        && domain.len() > u8::MAX as usize
    {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "XUDP destination domain is too long",
        ));
    }
    address.write_to_buf_vmess(buffer);
    Ok(())
}

fn decode_address(buffer: &[u8]) -> io::Result<(SocksAddr, usize)> {
    if buffer.len() < 3 {
        return Err(io::Error::new(
            io::ErrorKind::UnexpectedEof,
            "truncated XUDP destination",
        ));
    }
    let port = u16::from_be_bytes([buffer[0], buffer[1]]);
    match buffer[2] {
        0x01 if buffer.len() >= 7 => Ok((
            SocksAddr::Ip(SocketAddr::new(
                IpAddr::V4(Ipv4Addr::new(
                    buffer[3], buffer[4], buffer[5], buffer[6],
                )),
                port,
            )),
            7,
        )),
        0x03 if buffer.len() >= 19 => {
            let mut octets = [0; 16];
            octets.copy_from_slice(&buffer[3..19]);
            Ok((
                SocksAddr::Ip(SocketAddr::new(
                    IpAddr::V6(Ipv6Addr::from(octets)),
                    port,
                )),
                19,
            ))
        }
        0x02 if buffer.len() >= 4 => {
            let domain_length = buffer[3] as usize;
            if buffer.len() < 4 + domain_length {
                return Err(io::Error::new(
                    io::ErrorKind::UnexpectedEof,
                    "truncated XUDP domain destination",
                ));
            }
            let domain = std::str::from_utf8(&buffer[4..4 + domain_length])
                .map_err(|error| {
                    io::Error::new(
                        io::ErrorKind::InvalidData,
                        format!("invalid XUDP domain destination: {error}"),
                    )
                })?
                .to_owned();
            Ok((SocksAddr::Domain(domain, port), 4 + domain_length))
        }
        0x01 | 0x02 | 0x03 => Err(io::Error::new(
            io::ErrorKind::UnexpectedEof,
            "truncated XUDP destination address",
        )),
        family => Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!("unknown XUDP address family {family:#04x}"),
        )),
    }
}

fn global_id(source: SocketAddr) -> Option<[u8; 8]> {
    if source.ip().is_unspecified() || source.port() == 0 {
        return None;
    }
    static HASH_STATE: OnceLock<RandomState> = OnceLock::new();
    let mut hasher = HASH_STATE.get_or_init(RandomState::new).build_hasher();
    source.hash(&mut hasher);
    Some(hasher.finish().to_ne_bytes())
}

#[cfg(test)]
mod tests {
    use futures::{SinkExt, StreamExt};
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    use super::*;

    fn packet(destination: SocksAddr, payload: &[u8]) -> UdpPacket {
        UdpPacket::new(payload.to_vec(), SocksAddr::any_ipv4(), destination)
    }

    #[tokio::test]
    async fn writes_new_then_keep_frames_with_complete_datagrams() {
        let destination = SocksAddr::Domain("dns.example".to_owned(), 53);
        let (client, mut server) = tokio::io::duplex(4096);
        let mut xudp = OutboundDatagramXudp::new(
            Box::new(client),
            destination.clone(),
            "127.0.0.1:1234".parse().unwrap(),
        );

        xudp.send(packet(destination.clone(), b"first"))
            .await
            .unwrap();
        let frame_length = server.read_u16().await.unwrap() as usize;
        let mut first = vec![0; frame_length + 2 + 5];
        server.read_exact(&mut first).await.unwrap();
        assert_eq!(&first[..2], &[0, 0]);
        assert_eq!(first[2], STATUS_NEW);
        assert_eq!(first[3], OPTION_DATA);
        assert_eq!(first[4], NETWORK_UDP);
        assert_eq!(&first[first.len() - 5..], b"first");

        xudp.send(packet(destination, b"second")).await.unwrap();
        let frame_length = server.read_u16().await.unwrap() as usize;
        let mut second = vec![0; frame_length + 2 + 6];
        server.read_exact(&mut second).await.unwrap();
        assert_eq!(second[2], STATUS_KEEP);
        assert_eq!(&second[second.len() - 6..], b"second");
    }

    #[tokio::test]
    async fn reassembles_fragmented_response_and_decodes_source() {
        let default = SocksAddr::Ip("1.1.1.1:53".parse().unwrap());
        let source = SocksAddr::Domain("reply.example".to_owned(), 5353);
        let (client, mut server) = tokio::io::duplex(4096);
        let mut xudp = OutboundDatagramXudp::new(
            Box::new(client),
            default,
            "0.0.0.0:0".parse().unwrap(),
        );
        let mut address = BytesMut::new();
        encode_address(&source, &mut address).unwrap();
        let mut wire = BytesMut::new();
        wire.put_u16((5 + address.len()) as u16);
        wire.put_u16(0);
        wire.put_u8(STATUS_KEEP);
        wire.put_u8(OPTION_DATA);
        wire.put_u8(NETWORK_UDP);
        wire.extend_from_slice(&address);
        wire.put_u16(8);
        wire.extend_from_slice(b"response");

        for byte in wire {
            server.write_all(&[byte]).await.unwrap();
            tokio::task::yield_now().await;
        }
        let response = xudp.next().await.unwrap();
        assert_eq!(response.src_addr, source);
        assert_eq!(response.data, b"response");
    }

    #[test]
    fn address_codec_matches_vmess_wire_format() {
        for address in [
            SocksAddr::Ip("1.2.3.4:53".parse().unwrap()),
            SocksAddr::Ip("[2001:db8::1]:443".parse().unwrap()),
            SocksAddr::Domain("example.com".to_owned(), 80),
        ] {
            let mut encoded = BytesMut::new();
            encode_address(&address, &mut encoded).unwrap();
            let (decoded, consumed) = decode_address(&encoded).unwrap();
            assert_eq!(decoded, address);
            assert_eq!(consumed, encoded.len());
        }
    }
}
