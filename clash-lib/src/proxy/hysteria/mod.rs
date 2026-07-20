mod codec;
mod congestion;
mod datagram;
mod udp_hop;
mod xplus;

use self::{
    congestion::{Burtal, DynController},
    datagram::{HysteriaDatagramOutbound, UdpSession},
};
use super::{
    ConnectorType, DialWithConnector, OutboundHandler, OutboundType,
    PlainProxyAPIResponse, converters::hysteria::PortGenerator, datagram::UdpPacket,
    utils::new_udp_socket,
};
use crate::{
    app::{
        dispatcher::{
            BoxedChainedDatagram, BoxedChainedStream, ChainedDatagram,
            ChainedDatagramWrapper, ChainedStreamWrapper,
        },
        dns::ThreadSafeDNSResolver,
    },
    common::tls::DefaultTlsVerifier,
    proxy::transport::{
        TlsEchOptions, build_rustls_client_config_with_optional_ech,
    },
    session::{Session, SocksAddr},
};
use anyhow::anyhow;
use bytes::{Bytes, BytesMut};
use codec::Fragments;
use erased_serde::Serialize as ErasedSerialize;
use quinn::{
    ClientConfig, Connection, TokioRuntime, crypto::rustls::QuicClientConfig,
};
use quinn_proto::TransportConfig;
use std::{
    collections::HashMap,
    fmt::{Debug, Formatter},
    io,
    net::SocketAddr,
    path::PathBuf,
    pin::Pin,
    sync::{Arc, RwLock, atomic::AtomicU32},
    task::{Context, Poll},
};
use tokio::{
    io::{AsyncRead, AsyncWrite, ReadBuf},
    sync::{Mutex, OnceCell},
};
use tracing::{debug, trace, warn};

#[derive(Clone)]
pub struct XPlusObfs {
    pub key: Vec<u8>,
}

#[derive(Clone)]
pub enum Obfs {
    XPlus(XPlusObfs),
}

#[derive(Clone)]
pub struct HystOption {
    pub name: String,
    pub addr: SocksAddr,
    pub ports: Option<PortGenerator>,
    pub sni: Option<String>,
    pub auth: Vec<u8>,
    pub obfs: Option<Obfs>,
    pub skip_cert_verify: bool,
    pub alpn: Vec<String>,
    pub up_bps: u64,
    pub down_bps: u64,
    pub fingerprint: Option<String>,
    pub ca: Option<PathBuf>,
    pub fast_open: bool,
    pub hop_interval: Option<u64>,
    pub disable_mtu_discovery: bool,
    #[allow(dead_code)]
    pub ca_str: Option<String>,
    #[allow(dead_code)]
    pub recv_window_conn: Option<u64>,
    #[allow(dead_code)]
    pub recv_window: Option<u64>,
    pub ech: Option<TlsEchOptions>,
    pub tls_cert: Option<String>,
    pub tls_key: Option<String>,
}

pub struct Handler {
    opts: HystOption,
    ep_config: quinn::EndpointConfig,
    client_config: OnceCell<quinn::ClientConfig>,
    conn: Mutex<Option<Arc<HysteriaConnection>>>,
    next_session_id: AtomicU32,
    // support udp is decided by server
    support_udp: RwLock<bool>,
}

impl Debug for Handler {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("HystClient").finish()
    }
}

impl Handler {
    // 15 MB/s
    const DEFAULT_CONN_RECV_WINDOW: u64 = 67108864;
    const DEFAULT_MAX_IDLE_TIMEOUT: std::time::Duration =
        std::time::Duration::from_secs(300);
    const DEFAULT_STREAM_RECV_WINDOW: u64 = 15728640;

    // 64 MB/s

    pub fn new(opts: HystOption) -> Self {
        if opts.ca.is_some() {
            warn!("hysteria does not support ca yet");
        }
        let ep_config = quinn::EndpointConfig::default();

        Self {
            opts,
            ep_config,
            client_config: OnceCell::new(),
            next_session_id: AtomicU32::new(0),
            conn: Mutex::new(None),
            support_udp: RwLock::new(true),
        }
    }

    async fn client_config(&self) -> io::Result<&quinn::ClientConfig> {
        self.client_config
            .get_or_try_init(|| async {
                let verify = Arc::new(DefaultTlsVerifier::try_new(
                    self.opts.fingerprint.clone(),
                    self.opts.skip_cert_verify,
                )?);
                let mut tls_config = build_rustls_client_config_with_optional_ech(
                    verify,
                    self.opts.tls_cert.as_deref(),
                    self.opts.tls_key.as_deref(),
                    self.opts.ech.as_ref(),
                    self.opts.sni.as_deref().unwrap_or(""),
                )
                .await?;
                tls_config.alpn_protocols = if self.opts.alpn.is_empty() {
                    vec![b"hysteria".to_vec()]
                } else {
                    self.opts
                        .alpn
                        .iter()
                        .map(|value| value.as_bytes().to_vec())
                        .collect()
                };
                let quic_config = QuicClientConfig::try_from(tls_config)
                    .map_err(io::Error::other)?;
                let mut client_config = ClientConfig::new(Arc::new(quic_config));
                let mut transport = TransportConfig::default();
                if self.opts.disable_mtu_discovery {
                    transport.mtu_discovery_config(None);
                }
                transport.max_idle_timeout(Some(
                    Self::DEFAULT_MAX_IDLE_TIMEOUT.try_into().unwrap(),
                ));
                transport
                    .keep_alive_interval(Some(std::time::Duration::from_secs(10)));
                let recv_window_conn = self
                    .opts
                    .recv_window_conn
                    .unwrap_or(Self::DEFAULT_STREAM_RECV_WINDOW);
                let recv_window = self
                    .opts
                    .recv_window
                    .unwrap_or(Self::DEFAULT_CONN_RECV_WINDOW);
                transport.stream_receive_window(
                    quinn_proto::VarInt::from_u64(recv_window_conn).unwrap(),
                );
                transport.receive_window(
                    quinn_proto::VarInt::from_u64(recv_window).unwrap(),
                );
                client_config.transport_config(Arc::new(transport));
                Ok(client_config)
            })
            .await
    }

    // connect and auth
    async fn new_authed_connection_inner(
        &self,
        sess: &Session,
        resolver: ThreadSafeDNSResolver,
    ) -> anyhow::Result<Connection> {
        tracing::trace!(
            "hysteria new_authed_connection_inner: starting connection to {:?}",
            self.opts.addr
        );
        // Everytime we establish a new session, we should lookup the server
        // address. maybe it changed since it use ddns
        let server_socket_addr = match self.opts.addr.clone() {
            SocksAddr::Ip(ip) => ip,
            SocksAddr::Domain(d, port) => {
                let ip = resolver
                    .resolve(d.as_str(), true)
                    .await?
                    .ok_or_else(|| anyhow!("resolve domain {} failed", d))?;
                SocketAddr::new(ip, port)
            }
        };

        let create_socket = || async {
            new_udp_socket(
                None,
                sess.iface.as_ref(),
                #[cfg(target_os = "linux")]
                sess.so_mark,
                Some(server_socket_addr),
            )
            .await
        };

        let mut ep = if let Some(obfs) = self.opts.obfs.as_ref() {
            match obfs {
                Obfs::XPlus(xplus_obfs) => {
                    let socket = create_socket().await?;
                    let obfs = xplus::XPlus::new(
                        socket.into_std()?,
                        xplus_obfs.key.to_vec(),
                    )?;

                    quinn::Endpoint::new_with_abstract_socket(
                        self.ep_config.clone(),
                        None,
                        Arc::new(obfs),
                        Arc::new(TokioRuntime),
                    )?
                }
            }
        } else if let Some(port_gen) = self.opts.ports.as_ref() {
            let hop_interval =
                self.opts.hop_interval.map(std::time::Duration::from_secs);
            let udp_hop = udp_hop::UdpHop::new(
                server_socket_addr.port(),
                port_gen.clone(),
                hop_interval,
            )?;
            quinn::Endpoint::new_with_abstract_socket(
                self.ep_config.clone(),
                None,
                Arc::new(udp_hop),
                Arc::new(TokioRuntime),
            )?
        } else {
            let socket = create_socket().await?;

            quinn::Endpoint::new(
                self.ep_config.clone(),
                None,
                socket.into_std()?,
                Arc::new(TokioRuntime),
            )?
        };

        ep.set_default_client_config(self.client_config().await?.clone());

        tracing::trace!("hysteria connecting to server: {:?}", server_socket_addr);
        let session = ep
            .connect(server_socket_addr, self.opts.sni.as_deref().unwrap_or(""))?
            .await?;
        tracing::trace!("hysteria QUIC connection established");

        // Auth via binary protocol on a bidi stream
        let (ok, _server_send_bps, server_recv_bps, _msg) = Self::auth(
            &session,
            &self.opts.auth,
            self.opts.up_bps,
            self.opts.down_bps,
        )
        .await?;
        if !ok {
            return Err(anyhow!("hysteria auth failed"));
        }
        tracing::trace!("hysteria authentication successful");

        // Set congestion controller based on server's reported receive BPS
        match session
            .congestion_state()
            .into_any()
            .downcast::<DynController>()
        {
            Ok(any) => {
                any.set_controller(Box::new(Burtal::new(
                    server_recv_bps,
                    session.clone(),
                )));
            }
            Err(_) => {
                trace!("congestion controller is not set");
            }
        }

        Ok(session)
    }

    /// Perform the binary auth handshake on a QUIC bidi stream.
    /// Returns (ok, server_send_bps, server_recv_bps, message)
    async fn auth(
        conn: &quinn::Connection,
        auth: &[u8],
        send_bps: u64,
        recv_bps: u64,
    ) -> anyhow::Result<(bool, u64, u64, String)> {
        use codec::{ReadServerHello, WriteClientHello};

        let mut stream = conn.open_bi().await?;

        // Send ClientHello
        WriteClientHello::write(&mut stream.0, send_bps, recv_bps, auth).await?;

        // Read ServerHello
        let server_hello = ReadServerHello::read(&mut stream.1).await?;

        // Close the control stream
        stream.0.finish()?;

        Ok((
            server_hello.ok,
            server_hello.send_bps,
            server_hello.recv_bps,
            server_hello.message,
        ))
    }

    pub async fn new_authed_connection(
        &self,
        sess: &Session,
        resolver: ThreadSafeDNSResolver,
    ) -> std::io::Result<Arc<HysteriaConnection>> {
        let mut quinn_conn_lock = self.conn.lock().await;

        match (*quinn_conn_lock)
            .as_ref()
            .filter(|s| match s.conn.close_reason() {
                Some(reason) => {
                    tracing::debug!("old connection closed: {:?}", reason);
                    false
                }
                None => true,
            }) {
            Some(s) => Ok(s.clone()),
            None => {
                let session = self
                    .new_authed_connection_inner(sess, resolver)
                    .await
                    .map_err(|e| {
                        std::io::Error::other(format!(
                            "connect to {} failed: {}",
                            self.opts.addr, e
                        ))
                    })?;
                let session = Arc::new(session);
                let hyst_conn = HysteriaConnection::new_with_task_loop(session);
                *quinn_conn_lock = Some(hyst_conn.clone());
                Ok(hyst_conn)
            }
        }
    }
}

impl DialWithConnector for Handler {}

#[async_trait::async_trait]
impl OutboundHandler for Handler {
    fn name(&self) -> &str {
        &self.opts.name
    }

    fn server_name(&self) -> Option<&str> {
        self.opts.addr.domain()
    }

    fn proto(&self) -> OutboundType {
        OutboundType::Hysteria
    }

    async fn support_udp(&self) -> bool {
        *self.support_udp.read().unwrap()
    }

    async fn support_connector(&self) -> ConnectorType {
        ConnectorType::Tcp
    }

    async fn connect_stream(
        &self,
        sess: &Session,
        resolver: ThreadSafeDNSResolver,
    ) -> std::io::Result<BoxedChainedStream> {
        let authed_conn = self.new_authed_connection(sess, resolver.clone()).await?;
        let hy_stream = authed_conn.connect_tcp(sess, self.opts.fast_open).await?;
        Ok(Box::new(ChainedStreamWrapper::new(Box::new(hy_stream))))
    }

    /// connect to remote target via UDP
    async fn connect_datagram(
        &self,
        sess: &Session,
        resolver: ThreadSafeDNSResolver,
    ) -> std::io::Result<BoxedChainedDatagram> {
        let authed_conn = self.new_authed_connection(sess, resolver.clone()).await?;
        let next_session_id = self
            .next_session_id
            .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        let hy_datagram = authed_conn.connect_udp(sess, next_session_id).await?;
        let s = ChainedDatagramWrapper::new(hy_datagram);
        s.append_to_chain(self.name()).await;
        Ok(Box::new(s))
    }

    fn try_as_plain_handler(&self) -> Option<&dyn PlainProxyAPIResponse> {
        Some(self as _)
    }
}

#[async_trait::async_trait]
impl PlainProxyAPIResponse for Handler {
    async fn as_map(&self) -> HashMap<String, Box<dyn ErasedSerialize + Send>> {
        let mut m = HashMap::new();
        let (server, port) = match &self.opts.addr {
            crate::session::SocksAddr::Ip(addr) => {
                (addr.ip().to_string(), addr.port())
            }
            crate::session::SocksAddr::Domain(host, port) => (host.clone(), *port),
        };
        m.insert("server".to_owned(), Box::new(server) as _);
        m.insert("port".to_owned(), Box::new(port) as _);
        if let Some(sni) = self.opts.sni.as_ref() {
            m.insert("sni".to_owned(), Box::new(sni.clone()) as _);
        }
        if self.opts.skip_cert_verify {
            m.insert("skip-cert-verify".to_owned(), Box::new(true) as _);
        }
        if let Some(obfs) = self.opts.obfs.as_ref() {
            m.insert(
                "obfs".to_owned(),
                Box::new(
                    match obfs {
                        Obfs::XPlus(_) => "xplus",
                    }
                    .to_owned(),
                ) as _,
            );
        }
        if !self.opts.alpn.is_empty() {
            m.insert("alpn".to_owned(), Box::new(self.opts.alpn.clone()) as _);
        }
        m.insert("up".to_owned(), Box::new(self.opts.up_bps) as _);
        m.insert("down".to_owned(), Box::new(self.opts.down_bps) as _);
        m
    }
}

pub struct HysteriaConnection {
    pub conn: Arc<quinn::Connection>,
    pub udp_sessions: Arc<tokio::sync::Mutex<HashMap<u32, UdpSession>>>,
}

impl HysteriaConnection {
    pub fn new_with_task_loop(conn: Arc<quinn::Connection>) -> Arc<Self> {
        let s = Arc::new(Self {
            conn,
            udp_sessions: Arc::new(tokio::sync::Mutex::new(HashMap::new())),
        });
        tokio::spawn(Self::spawn_tasks(s.clone()));

        s
    }

    async fn spawn_tasks(self: Arc<Self>) {
        tracing::trace!("hysteria spawn_tasks: starting datagram receive loop");
        let err = loop {
            tokio::select! {
                res = self.conn.read_datagram() => {
                    match res {
                        Ok(pkt) => {
                            tracing::trace!("hysteria received datagram: {} bytes", pkt.len());
                            self.clone().recv_packet(pkt).await
                        },
                        Err(e) => {
                            tracing::error!("hysteria read datagram error: {}", e);
                            break e;
                        }
                    }
                }
            }
        };
        tracing::warn!("hysteria connection error: {:?}", err);
    }

    pub async fn connect_tcp(
        &self,
        sess: &Session,
        fast_open: bool,
    ) -> std::io::Result<HystStream> {
        use codec::{ReadServerResponse, WriteClientRequest};

        let (mut tx, mut rx) = self.conn.open_bi().await?;

        // Send ClientRequest for TCP (udp=false)
        WriteClientRequest::write_tcp(&mut tx, &sess.destination)
            .await
            .map_err(|e| std::io::Error::other(e.to_string()))?;

        if !fast_open {
            // Read ServerResponse
            let resp = ReadServerResponse::read(&mut rx)
                .await
                .map_err(|e| std::io::Error::other(e.to_string()))?;
            if !resp.ok {
                return Err(std::io::Error::other(format!(
                    "server response error, msg: {:?}",
                    resp.message
                )));
            } else {
                debug!(
                    "hysteria tcp request success: session_id: {}, msg: {:?}",
                    resp.udp_session_id, resp.message
                );
            }
        }

        Ok(HystStream {
            send: tx,
            recv: rx,
            established: !fast_open,
        })
    }

    pub async fn connect_udp(
        self: Arc<Self>,
        sess: &Session,
        _session_id: u32,
    ) -> std::io::Result<HysteriaDatagramOutbound> {
        use codec::{ReadServerResponse, WriteClientRequest};

        tracing::trace!("hysteria connect udp, sess: {:?}", sess);

        // Open a bidi stream for UDP session negotiation
        let (mut tx, mut rx) = self.conn.open_bi().await?;

        // Send ClientRequest for UDP (udp=false in the request, per protocol)
        WriteClientRequest::write_udp(&mut tx)
            .await
            .map_err(|e| std::io::Error::other(e.to_string()))?;

        // Read ServerResponse to get the server-assigned UDP session ID
        let resp = ReadServerResponse::read(&mut rx)
            .await
            .map_err(|e| std::io::Error::other(e.to_string()))?;

        if !resp.ok {
            return Err(std::io::Error::other(format!(
                "hysteria udp connection rejected: {:?}",
                resp.message
            )));
        }

        let server_session_id = resp.udp_session_id;
        tracing::debug!(
            "hysteria udp session established: server_session_id={}",
            server_session_id
        );

        // Hold the stream open in the background (the server uses the stream
        // lifecycle to know when the session is done)
        let hold_stream = tokio::spawn(async move {
            let mut buf = [0u8; 1024];
            // Read from the stream until it's closed
            while let Ok(_) = tokio::io::AsyncReadExt::read(&mut rx, &mut buf).await
            {
                // Just drain
            }
        });

        let datagram = HysteriaDatagramOutbound::new(
            server_session_id,
            self.clone(),
            sess.destination.clone(),
        )
        .await;

        // Store the hold task so it doesn't get dropped
        let _ = hold_stream;

        Ok(datagram)
    }

    pub fn send_packet(
        &self,
        pkt: Bytes,
        addr: SocksAddr,
        session_id: u32,
        pkt_id: u16,
    ) -> std::io::Result<()> {
        tracing::trace!(
            "hysteria send_packet: session_id={}, pkt_id={}, addr={:?}, data_len={}",
            session_id,
            pkt_id,
            addr,
            pkt.len()
        );

        let max_frag_size = match self.conn.max_datagram_size() {
            Some(x) => {
                tracing::trace!("hysteria max_frag_size={}", x);
                x
            }
            None => {
                tracing::error!("hysteria udp mtu not set");
                return Err(std::io::Error::other(
                    "hysteria udp mtu not set, please check your \
                     disable_mtu_discovery option",
                ));
            }
        };
        let fragments = Fragments::new(session_id, pkt_id, addr, max_frag_size, pkt);
        let mut frag_count = 0;
        for frag in fragments {
            frag_count += 1;
            tracing::trace!(
                "hysteria sending fragment #{} for session_id={}",
                frag_count,
                session_id
            );
            self.conn
                .send_datagram(frag)
                .map_err(std::io::Error::other)?;
        }
        tracing::trace!(
            "hysteria sent {} fragments for session_id={}",
            frag_count,
            session_id
        );
        Ok(())
    }

    pub async fn recv_packet(self: Arc<Self>, pkt: Bytes) {
        tracing::trace!("hysteria recv_packet: {} bytes", pkt.len());
        let mut buf: BytesMut = pkt.into();
        let pkt = match codec::HysUdpPacket::decode(&mut buf) {
            Ok(p) => p,
            Err(e) => {
                tracing::warn!("hysteria failed to decode UDP packet: {}", e);
                return;
            }
        };
        let session_id = pkt.session_id;
        let mut udp_sessions = self.udp_sessions.lock().await;
        match udp_sessions.get_mut(&session_id) {
            Some(session) => {
                tracing::trace!(
                    "hysteria found session {}, feeding packet",
                    session_id
                );
                if let Some(pkt) = session.feed(pkt) {
                    tracing::trace!(
                        "hysteria complete packet received for session {}: {} \
                         bytes to {:?}",
                        session_id,
                        pkt.data.len(),
                        session.local_addr
                    );
                    let _ = session
                        .incoming
                        .send(UdpPacket {
                            data: pkt.data,
                            src_addr: pkt.addr,
                            dst_addr: session.local_addr.clone(),
                            inbound_user: None,
                        })
                        .await;
                } else {
                    tracing::trace!(
                        "hysteria packet fragment buffered for session {}",
                        session_id
                    );
                }
            }
            _ => {
                tracing::warn!("hysteria udp session not found: {}", session_id);
            }
        }
    }
}

pub struct HystStream {
    send: quinn::SendStream,
    recv: quinn::RecvStream,
    #[allow(dead_code)]
    established: bool,
}

impl Debug for HystStream {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("HystStream").finish()
    }
}

impl AsyncRead for HystStream {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<std::io::Result<()>> {
        Pin::new(&mut self.get_mut().recv).poll_read(cx, buf)
    }
}

impl AsyncWrite for HystStream {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<std::io::Result<usize>> {
        Pin::new(&mut self.get_mut().send)
            .poll_write(cx, buf)
            .map_err(|e| {
                tracing::error!("hysteria write error: {}", e);
                e.into()
            })
    }

    fn poll_flush(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<std::io::Result<()>> {
        Pin::new(&mut self.get_mut().send).poll_flush(cx)
    }

    fn poll_shutdown(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<std::io::Result<()>> {
        Pin::new(&mut self.get_mut().send).poll_shutdown(cx)
    }
}
