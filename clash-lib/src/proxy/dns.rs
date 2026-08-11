use std::{
    collections::HashMap,
    fmt::Debug,
    io,
    pin::Pin,
    task::{Context, Poll},
};

use async_trait::async_trait;
use erased_serde::Serialize as ErasedSerialize;
use futures::{Sink, SinkExt, Stream};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio_util::sync::PollSender;

use crate::{
    app::{
        dispatcher::{
            BoxedChainedDatagram, BoxedChainedStream, ChainedDatagram,
            ChainedDatagramWrapper, ChainedStream, ChainedStreamWrapper,
        },
        dns::{ThreadSafeDNSResolver, exchange_with_resolver},
    },
    common::errors::new_io_error,
    proxy::{
        ConnectorType, DialWithConnector, OutboundHandler, OutboundType,
        PlainProxyAPIResponse, datagram::UdpPacket,
    },
    session::Session,
};

/// Mihomo-compatible `type: dns` outbound. It never opens a network socket:
/// DNS wire messages are relayed to the core's configured resolver instead.
pub struct Handler {
    name: String,
}

impl Handler {
    pub fn new(name: &str) -> Self {
        Self {
            name: name.to_owned(),
        }
    }
}

impl Debug for Handler {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Dns").field("name", &self.name).finish()
    }
}

impl DialWithConnector for Handler {}

pub(crate) async fn relay_tcp<S>(mut stream: S, resolver: ThreadSafeDNSResolver)
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    loop {
        let size = match stream.read_u16().await {
            Ok(size) => size as usize,
            Err(error) if error.kind() == io::ErrorKind::UnexpectedEof => break,
            Err(error) => {
                tracing::debug!("dns TCP read failed: {error}");
                break;
            }
        };
        let mut data = vec![0u8; size];
        if let Err(error) = stream.read_exact(&mut data).await {
            tracing::debug!("dns TCP payload read failed: {error}");
            break;
        }
        let request = match hickory_proto::op::Message::from_vec(&data) {
            Ok(request) => request,
            Err(error) => {
                tracing::debug!("dns TCP decode failed: {error}");
                break;
            }
        };
        let response = match exchange_with_resolver(&resolver, &request, true).await
        {
            Ok(response) => response,
            Err(error) => {
                tracing::debug!("dns TCP exchange failed: {error}");
                break;
            }
        };
        let data = match response.to_vec() {
            Ok(data) => data,
            Err(error) => {
                tracing::debug!("dns TCP encode failed: {error}");
                break;
            }
        };
        if data.len() > u16::MAX as usize
            || stream.write_u16(data.len() as u16).await.is_err()
            || stream.write_all(&data).await.is_err()
        {
            break;
        }
    }
}

#[async_trait]
impl OutboundHandler for Handler {
    fn name(&self) -> &str {
        &self.name
    }

    fn proto(&self) -> OutboundType {
        OutboundType::Dns
    }

    async fn support_udp(&self) -> bool {
        true
    }

    async fn connect_stream(
        &self,
        _sess: &Session,
        resolver: ThreadSafeDNSResolver,
    ) -> io::Result<BoxedChainedStream> {
        let (client, relay) = tokio::io::duplex(128 * 1024);
        tokio::spawn(relay_tcp(relay, resolver));

        let stream = ChainedStreamWrapper::new(client);
        stream.append_to_chain(self.name()).await;
        Ok(Box::new(stream))
    }

    async fn connect_datagram(
        &self,
        _sess: &Session,
        resolver: ThreadSafeDNSResolver,
    ) -> io::Result<BoxedChainedDatagram> {
        let datagram = DnsDatagram::new(resolver);
        let datagram = ChainedDatagramWrapper::new(datagram);
        datagram.append_to_chain(self.name()).await;
        Ok(Box::new(datagram))
    }

    async fn support_connector(&self) -> ConnectorType {
        ConnectorType::None
    }

    fn try_as_plain_handler(&self) -> Option<&dyn PlainProxyAPIResponse> {
        Some(self)
    }
}

#[async_trait]
impl PlainProxyAPIResponse for Handler {
    async fn as_map(&self) -> HashMap<String, Box<dyn ErasedSerialize + Send>> {
        HashMap::new()
    }
}

#[derive(Debug)]
struct DnsDatagram {
    send_tx: PollSender<UdpPacket>,
    recv_rx: tokio::sync::mpsc::Receiver<UdpPacket>,
    worker: tokio::task::JoinHandle<()>,
}

impl DnsDatagram {
    fn new(resolver: ThreadSafeDNSResolver) -> Self {
        let (send_tx, mut send_rx) = tokio::sync::mpsc::channel::<UdpPacket>(32);
        let (recv_tx, recv_rx) = tokio::sync::mpsc::channel::<UdpPacket>(32);
        let worker = tokio::spawn(async move {
            while let Some(packet) = send_rx.recv().await {
                let request =
                    match hickory_proto::op::Message::from_vec(&packet.data) {
                        Ok(request) => request,
                        Err(error) => {
                            tracing::debug!(
                                "dns outbound UDP decode failed: {error}"
                            );
                            continue;
                        }
                    };
                let response =
                    match exchange_with_resolver(&resolver, &request, true).await {
                        Ok(response) => response,
                        Err(error) => {
                            tracing::debug!(
                                "dns outbound UDP exchange failed: {error}"
                            );
                            continue;
                        }
                    };
                let data = match response.to_vec() {
                    Ok(data) => data,
                    Err(error) => {
                        tracing::debug!("dns outbound UDP encode failed: {error}");
                        continue;
                    }
                };
                if recv_tx
                    .send(UdpPacket {
                        data,
                        src_addr: packet.dst_addr,
                        dst_addr: packet.src_addr,
                        inbound_user: packet.inbound_user,
                    })
                    .await
                    .is_err()
                {
                    break;
                }
            }
        });
        Self {
            send_tx: PollSender::new(send_tx),
            recv_rx,
            worker,
        }
    }
}

impl Drop for DnsDatagram {
    fn drop(&mut self) {
        self.worker.abort();
    }
}

impl Sink<UdpPacket> for DnsDatagram {
    type Error = io::Error;

    fn poll_ready(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<Result<(), Self::Error>> {
        self.send_tx
            .poll_ready_unpin(cx)
            .map_err(|_| new_io_error("dns outbound send channel closed"))
    }

    fn start_send(
        mut self: Pin<&mut Self>,
        item: UdpPacket,
    ) -> Result<(), Self::Error> {
        self.send_tx
            .start_send_unpin(item)
            .map_err(|_| new_io_error("dns outbound send channel closed"))
    }

    fn poll_flush(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<Result<(), Self::Error>> {
        self.send_tx
            .poll_flush_unpin(cx)
            .map_err(|_| new_io_error("dns outbound send channel flush failed"))
    }

    fn poll_close(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<Result<(), Self::Error>> {
        self.send_tx
            .poll_close_unpin(cx)
            .map_err(|_| new_io_error("dns outbound send channel close failed"))
    }
}

impl Stream for DnsDatagram {
    type Item = UdpPacket;

    fn poll_next(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<Option<Self::Item>> {
        self.recv_rx.poll_recv(cx)
    }
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;

    use futures::{SinkExt, StreamExt};
    use hickory_proto::{
        op::{Message, MessageType, OpCode, Query},
        rr::{Name, RData, Record, RecordType, rdata::A},
    };

    use super::*;
    use crate::{
        app::dns::MockClashResolver,
        session::{Network, SocksAddr},
    };

    fn resolver() -> ThreadSafeDNSResolver {
        let mut resolver = MockClashResolver::new();
        resolver.expect_fake_ip_enabled().return_const(false);
        resolver.expect_exchange().returning(|request| {
            let mut response = Message::new(
                request.metadata.id,
                MessageType::Response,
                OpCode::Query,
            );
            response.add_queries(request.queries.clone());
            response.add_answer(Record::from_rdata(
                request.queries[0].name().clone(),
                60,
                RData::A(A("203.0.113.7".parse().unwrap())),
            ));
            Ok(response)
        });
        Arc::new(resolver)
    }

    fn request() -> Message {
        let mut request = Message::new(0x1234, MessageType::Query, OpCode::Query);
        request.add_query(Query::query(
            Name::from_ascii("dns-outbound.example.").unwrap(),
            RecordType::A,
        ));
        request
    }

    #[tokio::test]
    async fn relays_udp_query_to_internal_resolver() {
        let handler = Handler::new("dns-out");
        let session = Session {
            network: Network::Udp,
            destination: SocksAddr::Domain("dns.example".into(), 53),
            ..Default::default()
        };
        let mut datagram = handler
            .connect_datagram(&session, resolver())
            .await
            .unwrap();
        datagram
            .send(UdpPacket {
                data: request().to_vec().unwrap(),
                src_addr: "127.0.0.1:53000"
                    .parse::<std::net::SocketAddr>()
                    .unwrap()
                    .into(),
                dst_addr: "127.0.0.1:53"
                    .parse::<std::net::SocketAddr>()
                    .unwrap()
                    .into(),
                inbound_user: None,
            })
            .await
            .unwrap();

        let response =
            tokio::time::timeout(std::time::Duration::from_secs(1), datagram.next())
                .await
                .unwrap()
                .unwrap();
        let response = Message::from_vec(&response.data).unwrap();
        assert_eq!(response.metadata.id, 0x1234);
        assert_eq!(response.answers.len(), 1);
    }

    #[tokio::test]
    async fn relays_tcp_framed_query_to_internal_resolver() {
        let handler = Handler::new("dns-out");
        let mut stream = handler
            .connect_stream(&Session::default(), resolver())
            .await
            .unwrap();
        let request = request().to_vec().unwrap();
        stream.write_u16(request.len() as u16).await.unwrap();
        stream.write_all(&request).await.unwrap();
        stream.flush().await.unwrap();

        let size = tokio::time::timeout(
            std::time::Duration::from_secs(1),
            stream.read_u16(),
        )
        .await
        .unwrap()
        .unwrap() as usize;
        let mut response = vec![0u8; size];
        stream.read_exact(&mut response).await.unwrap();
        let response = Message::from_vec(&response).unwrap();
        assert_eq!(response.metadata.id, 0x1234);
        assert_eq!(response.answers.len(), 1);
    }
}
