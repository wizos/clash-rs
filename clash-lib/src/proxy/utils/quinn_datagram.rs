use std::{
    fmt,
    io::{self, IoSliceMut},
    net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr},
    pin::Pin,
    sync::{Arc, Mutex},
    task::{Context, Poll},
};

use futures::{SinkExt, StreamExt};
use quinn::{AsyncUdpSocket, UdpPoller, udp::Transmit};
use tokio::sync::mpsc;

use crate::{
    proxy::{AnyOutboundDatagram, datagram::UdpPacket},
    session::SocksAddr,
};

/// Adapts clash-rs' destination-aware outbound datagram abstraction to the
/// socket interface expected by Quinn. This keeps QUIC transports compatible
/// with `connect-via` chains instead of bypassing the selected connector with
/// a direct UDP socket.
pub struct QuinnDatagramSocket {
    send: mpsc::UnboundedSender<Vec<u8>>,
    recv: Mutex<mpsc::UnboundedReceiver<io::Result<Vec<u8>>>>,
    local_addr: SocketAddr,
    remote_addr: SocketAddr,
}

impl fmt::Debug for QuinnDatagramSocket {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("QuinnDatagramSocket")
            .field("local_addr", &self.local_addr)
            .field("remote_addr", &self.remote_addr)
            .finish()
    }
}

impl QuinnDatagramSocket {
    pub fn new(
        datagram: AnyOutboundDatagram,
        destination: SocksAddr,
        remote_addr: SocketAddr,
    ) -> Arc<Self> {
        let local_addr = match remote_addr.ip() {
            IpAddr::V4(_) => SocketAddr::new(Ipv4Addr::UNSPECIFIED.into(), 0),
            IpAddr::V6(_) => SocketAddr::new(Ipv6Addr::UNSPECIFIED.into(), 0),
        };
        let (send, mut send_rx) = mpsc::unbounded_channel::<Vec<u8>>();
        let (recv_tx, recv) = mpsc::unbounded_channel::<io::Result<Vec<u8>>>();
        let (mut sink, mut stream) = datagram.split();
        tokio::spawn(async move {
            loop {
                tokio::select! {
                    packet = send_rx.recv() => {
                        let Some(packet) = packet else {
                            break;
                        };
                        let packet = UdpPacket::new(
                            packet,
                            SocksAddr::Ip(local_addr),
                            destination.clone(),
                        );
                        if let Err(error) = sink.send(packet).await {
                            let _ = recv_tx.send(Err(error));
                            break;
                        }
                    }
                    packet = stream.next() => {
                        let Some(packet) = packet else {
                            let _ = recv_tx.send(Err(io::Error::new(
                                io::ErrorKind::BrokenPipe,
                                "outbound datagram closed",
                            )));
                            break;
                        };
                        if recv_tx.send(Ok(packet.data)).is_err() {
                            break;
                        }
                    }
                }
            }
        });

        Arc::new(Self {
            send,
            recv: Mutex::new(recv),
            local_addr,
            remote_addr,
        })
    }
}

#[derive(Debug)]
struct AlwaysWritable;

impl UdpPoller for AlwaysWritable {
    fn poll_writable(
        self: Pin<&mut Self>,
        _cx: &mut Context<'_>,
    ) -> Poll<io::Result<()>> {
        Poll::Ready(Ok(()))
    }
}

impl AsyncUdpSocket for QuinnDatagramSocket {
    fn create_io_poller(self: Arc<Self>) -> Pin<Box<dyn UdpPoller>> {
        Box::pin(AlwaysWritable)
    }

    fn try_send(&self, transmit: &Transmit<'_>) -> io::Result<()> {
        if transmit
            .segment_size
            .is_some_and(|size| size != transmit.contents.len())
        {
            return Err(io::Error::new(
                io::ErrorKind::Unsupported,
                "segmented QUIC datagrams are not supported by the connector \
                 adapter",
            ));
        }
        self.send.send(transmit.contents.to_vec()).map_err(|_| {
            io::Error::new(io::ErrorKind::BrokenPipe, "QUIC datagram closed")
        })
    }

    fn poll_recv(
        &self,
        cx: &mut Context<'_>,
        bufs: &mut [IoSliceMut<'_>],
        meta: &mut [quinn::udp::RecvMeta],
    ) -> Poll<io::Result<usize>> {
        if bufs.is_empty() || meta.is_empty() {
            return Poll::Ready(Ok(0));
        }
        let mut recv = self.recv.lock().map_err(|_| {
            io::Error::other("QUIC datagram receive lock was poisoned")
        })?;
        match Pin::new(&mut *recv).poll_recv(cx) {
            Poll::Ready(Some(Ok(packet))) => {
                if packet.len() > bufs[0].len() {
                    return Poll::Ready(Err(io::Error::new(
                        io::ErrorKind::InvalidData,
                        "received QUIC datagram exceeds Quinn buffer",
                    )));
                }
                bufs[0][..packet.len()].copy_from_slice(&packet);
                meta[0] = quinn::udp::RecvMeta {
                    addr: self.remote_addr,
                    len: packet.len(),
                    stride: packet.len(),
                    ecn: None,
                    dst_ip: None,
                };
                Poll::Ready(Ok(1))
            }
            Poll::Ready(Some(Err(error))) => Poll::Ready(Err(error)),
            Poll::Ready(None) => Poll::Ready(Err(io::Error::new(
                io::ErrorKind::BrokenPipe,
                "QUIC datagram receive channel closed",
            ))),
            Poll::Pending => Poll::Pending,
        }
    }

    fn local_addr(&self) -> io::Result<SocketAddr> {
        Ok(self.local_addr)
    }

    fn may_fragment(&self) -> bool {
        false
    }
}
