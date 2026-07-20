use std::{
    collections::HashMap,
    fmt::Debug,
    io,
    pin::Pin,
    sync::Arc,
    task::{Context, Poll},
};

use async_smux::MuxBuilder;
use async_trait::async_trait;
use bytes::{BufMut, BytesMut};
use erased_serde::Serialize as ErasedSerialize;
use futures::{Sink, SinkExt, Stream};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio_util::sync::PollSender;
use tracing::debug;

use crate::{
    Error,
    app::{
        dispatcher::{
            BoxedChainedDatagram, BoxedChainedStream, ChainedDatagram,
            ChainedDatagramWrapper, ChainedStream, ChainedStreamWrapper,
        },
        dns::ThreadSafeDNSResolver,
    },
    common::errors::new_io_error,
    impl_default_connector,
    proxy::{
        AnyStream, ConnectorType, DialWithConnector, HandlerCommonOptions,
        OutboundHandler, OutboundType, PlainProxyAPIResponse,
        datagram::UdpPacket,
        transport::Transport,
        utils::{GLOBAL_DIRECT_CONNECTOR, RemoteConnector},
    },
    session::{Session, SocksAddr},
};

const RELAY_VERSION: u8 = 0x01;
const COMMAND_CONNECT: u8 = 0x01;
const FLAG_UDP: u8 = 0x80;
const FEATURE_USER_AUTH: u8 = 0x01;
const FEATURE_ADDRESS: u8 = 0x02;
const FEATURE_NETWORK: u8 = 0x04;
const NETWORK_TCP: u16 = 0;
const NETWORK_UDP: u16 = 1;

pub struct HandlerOptions {
    pub name: String,
    pub common_opts: HandlerCommonOptions,
    pub server: String,
    pub port: u16,
    pub forward: bool,
    pub udp: bool,
    pub mux: bool,
    pub username: String,
    pub password: String,
    pub tls: Option<Box<dyn Transport>>,
}

pub struct Handler {
    opts: HandlerOptions,
    connector: tokio::sync::RwLock<Option<Arc<dyn RemoteConnector>>>,
}

impl Handler {
    pub fn new(opts: HandlerOptions) -> Result<Self, Error> {
        if opts.server.is_empty() || opts.port == 0 {
            return Err(Error::InvalidConfig(format!(
                "gost-relay {} requires a valid server and port",
                opts.name
            )));
        }
        if opts.username.len() > u8::MAX as usize
            || opts.password.len() > u8::MAX as usize
        {
            return Err(Error::InvalidConfig(format!(
                "gost-relay {} username or password is too long",
                opts.name
            )));
        }
        Ok(Self {
            opts,
            connector: Default::default(),
        })
    }
}

impl_default_connector!(Handler);

impl Debug for Handler {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("GostRelay")
            .field("name", &self.opts.name)
            .finish()
    }
}

#[async_trait]
impl OutboundHandler for Handler {
    fn name(&self) -> &str {
        &self.opts.name
    }

    fn server_name(&self) -> Option<&str> {
        Some(&self.opts.server)
    }

    fn proto(&self) -> OutboundType {
        OutboundType::GostRelay
    }

    async fn support_udp(&self) -> bool {
        self.opts.udp
    }

    async fn connect_stream(
        &self,
        sess: &Session,
        resolver: ThreadSafeDNSResolver,
    ) -> io::Result<BoxedChainedStream> {
        let connector = self.connector.read().await;
        self.connect_stream_with_connector(
            sess,
            resolver,
            connector
                .as_ref()
                .unwrap_or(&GLOBAL_DIRECT_CONNECTOR.clone())
                .as_ref(),
        )
        .await
    }

    async fn connect_datagram(
        &self,
        sess: &Session,
        resolver: ThreadSafeDNSResolver,
    ) -> io::Result<BoxedChainedDatagram> {
        let connector = self.connector.read().await;
        self.connect_datagram_with_connector(
            sess,
            resolver,
            connector
                .as_ref()
                .unwrap_or(&GLOBAL_DIRECT_CONNECTOR.clone())
                .as_ref(),
        )
        .await
    }

    async fn support_connector(&self) -> ConnectorType {
        ConnectorType::All
    }

    async fn connect_stream_with_connector(
        &self,
        sess: &Session,
        resolver: ThreadSafeDNSResolver,
        connector: &dyn RemoteConnector,
    ) -> io::Result<BoxedChainedStream> {
        let stream = self
            .relay_stream_with_resolver(connector, sess, resolver, false)
            .await?;
        let stream = ChainedStreamWrapper::new(stream);
        stream.append_to_chain(self.name()).await;
        Ok(Box::new(stream))
    }

    async fn connect_datagram_with_connector(
        &self,
        sess: &Session,
        resolver: ThreadSafeDNSResolver,
        connector: &dyn RemoteConnector,
    ) -> io::Result<BoxedChainedDatagram> {
        if !self.opts.udp {
            return Err(new_io_error("gost-relay UDP is disabled"));
        }
        let stream = self
            .relay_stream_with_resolver(connector, sess, resolver, true)
            .await?;
        let datagram = RelayDatagram::new(stream, sess);
        let datagram = ChainedDatagramWrapper::new(datagram);
        datagram.append_to_chain(self.name()).await;
        Ok(Box::new(datagram))
    }

    fn try_as_plain_handler(&self) -> Option<&dyn PlainProxyAPIResponse> {
        Some(self)
    }
}

impl Handler {
    async fn relay_stream_with_resolver(
        &self,
        connector: &dyn RemoteConnector,
        sess: &Session,
        resolver: ThreadSafeDNSResolver,
        udp: bool,
    ) -> io::Result<AnyStream> {
        let mut stream = connector
            .connect_stream(
                resolver,
                &self.opts.server,
                self.opts.port,
                sess.iface.as_ref(),
                #[cfg(target_os = "linux")]
                sess.so_mark,
            )
            .await?;

        if let Some(tls) = self.opts.tls.as_ref() {
            stream = tls.proxy_stream(stream).await?;
        }
        if self.opts.mux {
            let (mux, _acceptor, worker) =
                MuxBuilder::client().with_connection(stream).build();
            tokio::spawn(async move {
                if let Err(error) = worker.await {
                    debug!("gost-relay smux worker stopped: {error}");
                }
            });
            stream = Box::new(mux.connect().map_err(new_io_error)?);
        }

        write_request(
            &mut stream,
            COMMAND_CONNECT | if udp { FLAG_UDP } else { 0 },
            (!self.opts.forward).then_some(&sess.destination),
            if udp { NETWORK_UDP } else { NETWORK_TCP },
            &self.opts.username,
            &self.opts.password,
        )
        .await?;
        read_response(&mut stream).await?;
        Ok(stream)
    }
}

#[async_trait]
impl PlainProxyAPIResponse for Handler {
    async fn as_map(&self) -> HashMap<String, Box<dyn ErasedSerialize + Send>> {
        HashMap::from([
            ("server".to_owned(), Box::new(self.opts.server.clone()) as _),
            ("port".to_owned(), Box::new(self.opts.port) as _),
            ("udp".to_owned(), Box::new(self.opts.udp) as _),
            ("mux".to_owned(), Box::new(self.opts.mux) as _),
        ])
    }
}

async fn write_request(
    stream: &mut AnyStream,
    command: u8,
    target: Option<&SocksAddr>,
    network: u16,
    username: &str,
    password: &str,
) -> io::Result<()> {
    let request = encode_request(command, target, network, username, password)?;
    stream.write_all(&request).await
}

fn encode_request(
    command: u8,
    target: Option<&SocksAddr>,
    network: u16,
    username: &str,
    password: &str,
) -> io::Result<Vec<u8>> {
    let mut features = Vec::new();
    if !username.is_empty() || !password.is_empty() {
        if username.len() > u8::MAX as usize || password.len() > u8::MAX as usize {
            return Err(new_io_error("gost-relay username or password too long"));
        }
        let mut auth = BytesMut::new();
        auth.put_u8(username.len() as u8);
        auth.put_slice(username.as_bytes());
        auth.put_u8(password.len() as u8);
        auth.put_slice(password.as_bytes());
        encode_feature(&mut features, FEATURE_USER_AUTH, &auth)?;
    }
    if let Some(target) = target {
        let mut address = BytesMut::new();
        target.write_buf(&mut address);
        encode_feature(&mut features, FEATURE_ADDRESS, &address)?;
    }
    encode_feature(&mut features, FEATURE_NETWORK, &network.to_be_bytes())?;
    if features.len() > u16::MAX as usize {
        return Err(new_io_error("gost-relay feature list too large"));
    }

    let mut request = BytesMut::with_capacity(4 + features.len());
    request.put_u8(RELAY_VERSION);
    request.put_u8(command);
    request.put_u16(features.len() as u16);
    request.put_slice(&features);
    Ok(request.to_vec())
}

fn encode_feature(output: &mut Vec<u8>, kind: u8, payload: &[u8]) -> io::Result<()> {
    if payload.len() > u16::MAX as usize {
        return Err(new_io_error("gost-relay feature payload too large"));
    }
    output.push(kind);
    output.extend_from_slice(&(payload.len() as u16).to_be_bytes());
    output.extend_from_slice(payload);
    Ok(())
}

async fn read_response(stream: &mut AnyStream) -> io::Result<()> {
    let mut header = [0u8; 4];
    stream.read_exact(&mut header).await?;
    if header[0] != RELAY_VERSION {
        return Err(new_io_error(format!(
            "gost-relay bad response version: {}",
            header[0]
        )));
    }
    if header[1] != 0 {
        return Err(new_io_error(format!(
            "gost-relay connect failed with status 0x{:02x} ({})",
            header[1],
            status_text(header[1])
        )));
    }
    let feature_len = u16::from_be_bytes([header[2], header[3]]) as usize;
    if feature_len != 0 {
        let mut discard = vec![0u8; feature_len];
        stream.read_exact(&mut discard).await?;
    }
    Ok(())
}

fn status_text(status: u8) -> &'static str {
    match status {
        0x00 => "ok",
        0x01 => "bad request",
        0x02 => "unauthorized",
        0x03 => "forbidden",
        0x04 => "timeout",
        0x05 => "service unavailable",
        0x06 => "host unreachable",
        0x07 => "network unreachable",
        0x08 => "internal server error",
        _ => "unknown",
    }
}

struct RelayDatagram {
    send_tx: PollSender<UdpPacket>,
    recv_rx: tokio::sync::mpsc::Receiver<UdpPacket>,
    workers: Vec<tokio::task::JoinHandle<()>>,
}

impl RelayDatagram {
    fn new(stream: AnyStream, sess: &Session) -> Self {
        let (send_tx, mut send_rx) = tokio::sync::mpsc::channel::<UdpPacket>(32);
        let (recv_tx, recv_rx) = tokio::sync::mpsc::channel::<UdpPacket>(32);
        let (mut reader, mut writer) = tokio::io::split(stream);
        let source = SocksAddr::from(sess.source);
        let destination = sess.destination.clone();
        let inbound_user = sess.inbound_user.clone();

        let write_worker = tokio::spawn(async move {
            while let Some(packet) = send_rx.recv().await {
                if packet.data.len() > u16::MAX as usize
                    || writer.write_u16(packet.data.len() as u16).await.is_err()
                    || writer.write_all(&packet.data).await.is_err()
                    || writer.flush().await.is_err()
                {
                    break;
                }
            }
        });
        let read_worker = tokio::spawn(async move {
            while let Ok(size) = reader.read_u16().await {
                let mut data = vec![0u8; size as usize];
                if reader.read_exact(&mut data).await.is_err()
                    || recv_tx
                        .send(UdpPacket {
                            data,
                            src_addr: destination.clone(),
                            dst_addr: source.clone(),
                            inbound_user: inbound_user.clone(),
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
            workers: vec![write_worker, read_worker],
        }
    }
}

impl Drop for RelayDatagram {
    fn drop(&mut self) {
        for worker in &self.workers {
            worker.abort();
        }
    }
}

impl Sink<UdpPacket> for RelayDatagram {
    type Error = io::Error;

    fn poll_ready(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<Result<(), Self::Error>> {
        self.send_tx
            .poll_ready_unpin(cx)
            .map_err(|_| new_io_error("gost-relay UDP send channel closed"))
    }

    fn start_send(
        mut self: Pin<&mut Self>,
        item: UdpPacket,
    ) -> Result<(), Self::Error> {
        self.send_tx
            .start_send_unpin(item)
            .map_err(|_| new_io_error("gost-relay UDP send channel closed"))
    }

    fn poll_flush(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<Result<(), Self::Error>> {
        self.send_tx
            .poll_flush_unpin(cx)
            .map_err(|_| new_io_error("gost-relay UDP send channel flush failed"))
    }

    fn poll_close(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<Result<(), Self::Error>> {
        self.send_tx
            .poll_close_unpin(cx)
            .map_err(|_| new_io_error("gost-relay UDP send channel close failed"))
    }
}

impl Stream for RelayDatagram {
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
    use super::*;

    #[test]
    fn encodes_mihomo_gost_relay_request() {
        let request = encode_request(
            COMMAND_CONNECT,
            Some(&SocksAddr::Domain("example.com".to_owned(), 443)),
            NETWORK_TCP,
            "u",
            "p",
        )
        .unwrap();
        assert_eq!(
            request,
            vec![
                1, 1, 0, 30, 1, 0, 4, 1, b'u', 1, b'p', 2, 0, 15, 3, 11, b'e', b'x',
                b'a', b'm', b'p', b'l', b'e', b'.', b'c', b'o', b'm', 1, 187, 4, 0,
                2, 0, 0,
            ]
        );
    }

    #[test]
    fn forward_mode_omits_target_feature() {
        let request =
            encode_request(COMMAND_CONNECT, None, NETWORK_TCP, "", "").unwrap();
        assert_eq!(request, vec![1, 1, 0, 5, 4, 0, 2, 0, 0]);
    }
}
