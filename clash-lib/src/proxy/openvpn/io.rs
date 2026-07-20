use std::{io, sync::Arc};

use async_trait::async_trait;
use futures::{
    SinkExt, StreamExt,
    stream::{SplitSink, SplitStream},
};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt, ReadHalf, WriteHalf},
    sync::Mutex,
};

use crate::{
    proxy::{AnyOutboundDatagram, AnyStream, datagram::UdpPacket},
    session::SocksAddr,
};

use super::control::PacketIo;

pub(super) struct TcpPacketIo {
    reader: Mutex<ReadHalf<AnyStream>>,
    writer: Mutex<WriteHalf<AnyStream>>,
}

impl TcpPacketIo {
    pub(super) fn new(stream: AnyStream) -> Arc<Self> {
        let (reader, writer) = tokio::io::split(stream);
        Arc::new(Self {
            reader: Mutex::new(reader),
            writer: Mutex::new(writer),
        })
    }
}

#[async_trait]
impl PacketIo for TcpPacketIo {
    async fn read_packet(&self) -> io::Result<Vec<u8>> {
        let mut reader = self.reader.lock().await;
        let length = reader.read_u16().await? as usize;
        if length == 0 {
            return Err(invalid("empty openvpn TCP packet"));
        }
        let mut packet = vec![0u8; length];
        reader.read_exact(&mut packet).await?;
        Ok(packet)
    }

    async fn write_packet(&self, packet: &[u8]) -> io::Result<()> {
        let length = u16::try_from(packet.len())
            .map_err(|_| invalid("openvpn TCP packet exceeds 65535 bytes"))?;
        let mut writer = self.writer.lock().await;
        writer.write_u16(length).await?;
        writer.write_all(packet).await?;
        writer.flush().await
    }

    async fn close(&self) -> io::Result<()> {
        self.writer.lock().await.shutdown().await
    }
}

pub(super) struct UdpPacketIo {
    sink: Mutex<SplitSink<AnyOutboundDatagram, UdpPacket>>,
    stream: Mutex<SplitStream<AnyOutboundDatagram>>,
    destination: SocksAddr,
}

impl UdpPacketIo {
    pub(super) fn new(
        datagram: AnyOutboundDatagram,
        destination: SocksAddr,
    ) -> Arc<Self> {
        let (sink, stream) = datagram.split();
        Arc::new(Self {
            sink: Mutex::new(sink),
            stream: Mutex::new(stream),
            destination,
        })
    }
}

#[async_trait]
impl PacketIo for UdpPacketIo {
    async fn read_packet(&self) -> io::Result<Vec<u8>> {
        self.stream
            .lock()
            .await
            .next()
            .await
            .map(|packet| packet.data)
            .ok_or_else(|| io::Error::from(io::ErrorKind::BrokenPipe))
    }

    async fn write_packet(&self, packet: &[u8]) -> io::Result<()> {
        let packet = UdpPacket::new(
            packet.to_vec(),
            SocksAddr::any_ipv4(),
            self.destination.clone(),
        );
        let mut sink = self.sink.lock().await;
        sink.send(packet).await?;
        sink.flush().await
    }

    async fn close(&self) -> io::Result<()> {
        self.sink.lock().await.close().await
    }
}

fn invalid(message: impl Into<String>) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, message.into())
}

#[cfg(test)]
mod tests {
    use super::{PacketIo, TcpPacketIo};

    #[tokio::test]
    async fn tcp_packet_framing_round_trip() {
        let (client, server) = tokio::io::duplex(1024);
        let client = TcpPacketIo::new(Box::new(client));
        let server = TcpPacketIo::new(Box::new(server));
        client.write_packet(b"one packet").await.unwrap();
        assert_eq!(server.read_packet().await.unwrap(), b"one packet");
    }
}
