use std::{
    collections::HashMap,
    fmt::Debug,
    io,
    net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr},
    pin::Pin,
    sync::{
        Arc,
        atomic::{AtomicUsize, Ordering},
    },
    task::{Context, Poll},
    time::Duration,
};

use async_trait::async_trait;
use base64::{Engine, engine::general_purpose::STANDARD as BASE64};
use bytes::{Buf, Bytes};
use erased_serde::Serialize as ErasedSerialize;
use futures::{Sink, SinkExt, Stream};
use http::{Method, Request, StatusCode, Uri, Version};
use tokio::{
    io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt},
    sync::watch,
    time::Instant,
};
use tokio_util::sync::{CancellationToken, PollSender};
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
    common::{
        errors::{map_io_error, new_io_error},
        tls::DefaultTlsVerifier,
    },
    impl_default_connector,
    proxy::{
        AnyStream, ConnectorType, DialWithConnector, HandlerCommonOptions,
        OutboundHandler, OutboundType, PlainProxyAPIResponse,
        datagram::UdpPacket,
        transport::{
            Http2Stream, TlsEchOptions, Transport,
            build_rustls_client_config_with_optional_ech,
        },
        utils::{GLOBAL_DIRECT_CONNECTOR, QuinnDatagramSocket, RemoteConnector},
    },
    session::{Session, SocksAddr},
};

const UDP_MAGIC_ADDRESS: &str = "_udp2";
const UDP_STATIC_HEADER_LENGTH: usize = 16 + 2 + 16 + 2;
const MAX_UDP_PAYLOAD: usize = u16::MAX as usize;
const APP_NAME: &str = "FlClash";
const HEALTH_CHECK_MAGIC_ADDRESS: &str = "_check";
const HEALTH_CHECK_INTERVAL: Duration = Duration::from_secs(7);
const QUIC_MAX_IDLE_TIMEOUT: Duration = Duration::from_secs(74);
const QUIC_STREAM_RECEIVE_WINDOW: u64 = 131_072;

type H3Sender = h3::client::SendRequest<h3_quinn::OpenStreams, Bytes>;

pub struct QuicTlsOptions {
    sni: String,
    skip_cert_verify: bool,
    certificate_fingerprint: Option<String>,
    ech: Option<TlsEchOptions>,
    tls_cert: Option<String>,
    tls_key: Option<String>,
}

impl QuicTlsOptions {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        sni: String,
        skip_cert_verify: bool,
        certificate_fingerprint: Option<String>,
        ech: Option<TlsEchOptions>,
        tls_cert: Option<String>,
        tls_key: Option<String>,
    ) -> Self {
        Self {
            sni,
            skip_cert_verify,
            certificate_fingerprint,
            ech,
            tls_cert,
            tls_key,
        }
    }

    async fn client_config(&self) -> io::Result<quinn::ClientConfig> {
        let verifier = Arc::new(DefaultTlsVerifier::try_new(
            self.certificate_fingerprint.clone(),
            self.skip_cert_verify,
        )?);
        let mut tls = build_rustls_client_config_with_optional_ech(
            verifier,
            self.tls_cert.as_deref(),
            self.tls_key.as_deref(),
            self.ech.as_ref(),
            &self.sni,
        )
        .await?;
        tls.alpn_protocols = vec![b"h3".to_vec()];
        if std::env::var("SSLKEYLOGFILE").is_ok() {
            tls.key_log = Arc::new(rustls::KeyLogFile::new());
        }
        let crypto = quinn::crypto::rustls::QuicClientConfig::try_from(tls)
            .map_err(io::Error::other)?;
        Ok(quinn::ClientConfig::new(Arc::new(crypto)))
    }
}

pub struct HandlerOptions {
    pub name: String,
    pub common_opts: HandlerCommonOptions,
    pub server: String,
    pub port: u16,
    pub username: String,
    pub password: String,
    pub udp: bool,
    pub tls: Box<dyn Transport>,
    pub health_check: bool,
    pub quic: bool,
    pub quic_tls: Option<QuicTlsOptions>,
    pub congestion_controller: Option<String>,
    pub cwnd: u64,
    pub bbr_profile: Option<String>,
    pub max_connections: usize,
    pub min_streams: usize,
    pub max_streams: usize,
}

pub struct Handler {
    opts: HandlerOptions,
    authorization: String,
    connector: tokio::sync::RwLock<Option<Arc<dyn RemoteConnector>>>,
    h2_pool: tokio::sync::Mutex<Vec<H2PoolEntry>>,
    h3_pool: tokio::sync::Mutex<Vec<H3PoolEntry>>,
}

impl Handler {
    pub fn new(mut opts: HandlerOptions) -> Result<Self, Error> {
        if opts.name.is_empty() || opts.server.is_empty() || opts.port == 0 {
            return Err(Error::InvalidConfig(
                "trusttunnel requires name, server and port".to_owned(),
            ));
        }
        if opts.quic && opts.quic_tls.is_none() {
            return Err(Error::InvalidConfig(
                "trusttunnel QUIC mode requires HTTP/3 TLS options".to_owned(),
            ));
        }
        if opts.max_connections == 0
            && opts.min_streams == 0
            && opts.max_streams == 0
        {
            opts.max_connections = 8;
            opts.min_streams = 5;
        }
        let authorization = format!(
            "Basic {}",
            BASE64.encode(format!("{}:{}", opts.username, opts.password))
        );
        Ok(Self {
            opts,
            authorization,
            connector: Default::default(),
            h2_pool: Default::default(),
            h3_pool: Default::default(),
        })
    }

    async fn open_h2_tunnel(
        &self,
        connector: &dyn RemoteConnector,
        sess: &Session,
        resolver: ThreadSafeDNSResolver,
        authority: &str,
        udp: bool,
    ) -> io::Result<AnyStream> {
        let (mut client, counter, health_reset) =
            self.pooled_h2_client(connector, sess, resolver).await?;

        let uri = Uri::builder()
            .scheme("https")
            .authority(authority)
            .path_and_query("/")
            .build()
            .map_err(map_io_error)?;
        let user_agent = if udp {
            format!("{} {UDP_MAGIC_ADDRESS}", std::env::consts::OS)
        } else {
            format!(
                "{} {APP_NAME}/{}",
                std::env::consts::OS,
                env!("CLASH_VERSION_OVERRIDE")
            )
        };
        let request = Request::builder()
            .method(Method::CONNECT)
            .uri(uri)
            .version(Version::HTTP_2)
            .header("user-agent", user_agent)
            .header("proxy-authorization", &self.authorization)
            .body(())
            .map_err(map_io_error)?;
        let (response, sender) =
            client.send_request(request, false).map_err(map_io_error)?;
        let response = response.await.map_err(map_io_error)?;
        if response.status() != StatusCode::OK {
            return Err(new_io_error(format!(
                "trusttunnel server returned HTTP {}",
                response.status()
            )));
        }
        if let Some(health_reset) = health_reset {
            let _ = health_reset.send(Instant::now());
        }
        Ok(Box::new(CountedHttp2Stream {
            stream: Http2Stream::new(response.into_body(), sender),
            _counter: counter,
        }))
    }

    async fn pooled_h2_client(
        &self,
        connector: &dyn RemoteConnector,
        sess: &Session,
        resolver: ThreadSafeDNSResolver,
    ) -> io::Result<(
        h2::client::SendRequest<bytes::Bytes>,
        StreamCounter,
        Option<watch::Sender<Instant>>,
    )> {
        loop {
            let mut pool = self.h2_pool.lock().await;
            let selection = pool
                .iter()
                .enumerate()
                .min_by_key(|(_, entry)| entry.active.load(Ordering::Relaxed))
                .map(|(index, entry)| (index, entry.active.load(Ordering::Relaxed)));
            let create = should_create_client(
                pool.len(),
                selection.map(|(_, active)| active),
                self.opts.max_connections,
                self.opts.min_streams,
                self.opts.max_streams,
            );
            if create {
                let entry = self
                    .new_h2_client(connector, sess, resolver.clone())
                    .await?;
                pool.push(entry);
            }
            let index = if create {
                pool.len() - 1
            } else {
                selection.unwrap().0
            };
            let entry = &pool[index];
            let sender = entry.sender.clone();
            let identity = entry.active.clone();
            let counter = StreamCounter::new(identity.clone());
            let health_reset = entry.health_reset.clone();
            drop(pool);
            match sender.ready().await {
                Ok(sender) => return Ok((sender, counter, health_reset)),
                Err(error) => {
                    drop(counter);
                    let mut pool = self.h2_pool.lock().await;
                    if let Some(index) = pool.iter().position(|entry| {
                        Arc::ptr_eq(&entry.active, &identity)
                            && entry.active.load(Ordering::Relaxed) == 0
                    }) {
                        pool.remove(index);
                    }
                    debug!("discarding closed trusttunnel H2 client: {error}");
                }
            }
        }
    }

    async fn new_h2_client(
        &self,
        connector: &dyn RemoteConnector,
        sess: &Session,
        resolver: ThreadSafeDNSResolver,
    ) -> io::Result<H2PoolEntry> {
        let raw = connector
            .connect_stream(
                resolver,
                &self.opts.server,
                self.opts.port,
                sess.iface.as_ref(),
                #[cfg(target_os = "linux")]
                sess.so_mark,
            )
            .await?;
        let tls = self.opts.tls.proxy_stream(raw).await?;
        let (client, connection) = h2::client::Builder::new()
            .initial_connection_window_size(0x7fff_ffff)
            .initial_window_size(0x7fff_ffff)
            .enable_push(false)
            .handshake(tls)
            .await
            .map_err(map_io_error)?;
        tokio::spawn(async move {
            if let Err(error) = connection.await {
                debug!("trusttunnel HTTP/2 connection stopped: {error}");
            }
        });
        let active = Arc::new(AtomicUsize::new(0));
        let cancellation = CancellationToken::new();
        let health_reset = if self.opts.health_check {
            let (health_reset, receiver) = watch::channel(Instant::now());
            tokio::spawn(run_health_checks(
                client.clone(),
                self.authorization.clone(),
                receiver,
                cancellation.clone(),
            ));
            Some(health_reset)
        } else {
            None
        };
        Ok(H2PoolEntry {
            sender: client,
            active,
            health_reset,
            cancellation,
        })
    }

    async fn open_h3_tunnel(
        &self,
        connector: &dyn RemoteConnector,
        sess: &Session,
        resolver: ThreadSafeDNSResolver,
        authority: &str,
        udp: bool,
    ) -> io::Result<AnyStream> {
        let uri = Uri::builder()
            .scheme("https")
            .authority(authority)
            .path_and_query("/")
            .build()
            .map_err(map_io_error)?;
        let user_agent = if udp {
            format!("{} {UDP_MAGIC_ADDRESS}", std::env::consts::OS)
        } else {
            format!(
                "{} {APP_NAME}/{}",
                std::env::consts::OS,
                env!("CLASH_VERSION_OVERRIDE")
            )
        };

        loop {
            let (mut client, counter, health_reset, identity) = self
                .pooled_h3_client(connector, sess, resolver.clone())
                .await?;
            let request = Request::builder()
                .method(Method::CONNECT)
                .uri(uri.clone())
                .version(Version::HTTP_3)
                .header("user-agent", &user_agent)
                .header("proxy-authorization", &self.authorization)
                .body(())
                .map_err(map_io_error)?;
            let mut stream = match client.send_request(request).await {
                Ok(stream) => stream,
                Err(error) => {
                    drop(counter);
                    self.discard_h3_client(&identity, &error.to_string()).await;
                    continue;
                }
            };
            let response = match stream.recv_response().await {
                Ok(response) => response,
                Err(error) => {
                    drop(counter);
                    self.discard_h3_client(&identity, &error.to_string()).await;
                    continue;
                }
            };
            if response.status() != StatusCode::OK {
                return Err(new_io_error(format!(
                    "trusttunnel server returned HTTP {}",
                    response.status()
                )));
            }
            if let Some(health_reset) = health_reset {
                let _ = health_reset.send(Instant::now());
            }

            let (mut upload, mut download) = stream.split();
            let (application, worker) = tokio::io::duplex(64 * 1024);
            let (mut input, mut output) = tokio::io::split(worker);
            tokio::spawn(async move {
                let mut buffer = vec![0u8; 64 * 1024];
                loop {
                    match input.read(&mut buffer).await {
                        Ok(0) => {
                            let _ = upload.finish().await;
                            break;
                        }
                        Ok(size) => {
                            if upload
                                .send_data(Bytes::copy_from_slice(&buffer[..size]))
                                .await
                                .is_err()
                            {
                                break;
                            }
                        }
                        Err(_) => break,
                    }
                }
            });
            tokio::spawn(async move {
                loop {
                    match download.recv_data().await {
                        Ok(Some(mut data)) => {
                            let length = data.remaining();
                            if output
                                .write_all(&data.copy_to_bytes(length))
                                .await
                                .is_err()
                            {
                                break;
                            }
                        }
                        Ok(None) | Err(_) => break,
                    }
                }
                let _ = output.shutdown().await;
            });
            return Ok(Box::new(CountedHttp3Stream {
                stream: application,
                _counter: counter,
            }));
        }
    }

    async fn pooled_h3_client(
        &self,
        connector: &dyn RemoteConnector,
        sess: &Session,
        resolver: ThreadSafeDNSResolver,
    ) -> io::Result<(
        H3Sender,
        StreamCounter,
        Option<watch::Sender<Instant>>,
        Arc<AtomicUsize>,
    )> {
        let mut pool = self.h3_pool.lock().await;
        let selection = pool
            .iter()
            .enumerate()
            .min_by_key(|(_, entry)| entry.active.load(Ordering::Relaxed))
            .map(|(index, entry)| (index, entry.active.load(Ordering::Relaxed)));
        let create = should_create_client(
            pool.len(),
            selection.map(|(_, active)| active),
            self.opts.max_connections,
            self.opts.min_streams,
            self.opts.max_streams,
        );
        if create {
            let entry = self
                .new_h3_client(connector, sess, resolver.clone())
                .await?;
            pool.push(entry);
        }
        let index = if create {
            pool.len() - 1
        } else {
            selection.expect("non-empty pool must have a selection").0
        };
        let entry = &pool[index];
        let identity = entry.active.clone();
        let counter = StreamCounter::new(identity.clone());
        Ok((
            entry.sender.clone(),
            counter,
            entry.health_reset.clone(),
            identity,
        ))
    }

    async fn new_h3_client(
        &self,
        connector: &dyn RemoteConnector,
        sess: &Session,
        resolver: ThreadSafeDNSResolver,
    ) -> io::Result<H3PoolEntry> {
        let remote_ip = resolver
            .resolve(&self.opts.server, true)
            .await
            .map_err(map_io_error)?
            .ok_or_else(|| {
                new_io_error("failed to resolve trusttunnel HTTP/3 server")
            })?;
        let remote_addr = SocketAddr::new(remote_ip, self.opts.port);
        let destination =
            SocksAddr::Domain(self.opts.server.clone(), self.opts.port);
        let datagram = connector
            .connect_datagram(
                resolver,
                None,
                destination.clone(),
                sess.iface.as_ref(),
                #[cfg(target_os = "linux")]
                sess.so_mark,
            )
            .await?;
        let tls = self.opts.quic_tls.as_ref().ok_or_else(|| {
            new_io_error("trusttunnel HTTP/3 TLS options are missing")
        })?;
        let mut client_config = tls.client_config().await?;
        let mut transport = quinn::TransportConfig::default();
        transport
            .max_idle_timeout(Some(
                QUIC_MAX_IDLE_TIMEOUT.try_into().map_err(io::Error::other)?,
            ))
            .stream_receive_window(
                QUIC_STREAM_RECEIVE_WINDOW
                    .try_into()
                    .map_err(io::Error::other)?,
            );
        configure_quic_congestion(
            &mut transport,
            self.opts.congestion_controller.as_deref(),
            self.opts.cwnd,
            self.opts.bbr_profile.as_deref(),
        );
        client_config.transport_config(Arc::new(transport));

        let socket = QuinnDatagramSocket::new(datagram, destination, remote_addr);
        let mut endpoint = quinn::Endpoint::new_with_abstract_socket(
            quinn::EndpointConfig::default(),
            None,
            socket,
            Arc::new(quinn::TokioRuntime),
        )?;
        endpoint.set_default_client_config(client_config);
        let connection = endpoint
            .connect(remote_addr, &tls.sni)
            .map_err(io::Error::other)?
            .await
            .map_err(io::Error::other)?;
        let connection_guard = connection.clone();
        let h3_connection = h3_quinn::Connection::new(connection);
        let (mut driver, sender) = h3::client::builder()
            .build::<_, _, Bytes>(h3_connection)
            .await
            .map_err(io::Error::other)?;
        tokio::spawn(async move {
            let error = driver.wait_idle().await;
            debug!("trusttunnel HTTP/3 connection stopped: {error}");
            drop(endpoint);
        });

        let active = Arc::new(AtomicUsize::new(0));
        let cancellation = CancellationToken::new();
        let health_reset = if self.opts.health_check {
            let (health_reset, receiver) = watch::channel(Instant::now());
            tokio::spawn(run_h3_health_checks(
                sender.clone(),
                self.authorization.clone(),
                receiver,
                cancellation.clone(),
            ));
            Some(health_reset)
        } else {
            None
        };
        Ok(H3PoolEntry {
            sender,
            active,
            health_reset,
            cancellation,
            connection: connection_guard,
        })
    }

    async fn discard_h3_client(&self, identity: &Arc<AtomicUsize>, error: &str) {
        let mut pool = self.h3_pool.lock().await;
        if let Some(index) = pool.iter().position(|entry| {
            Arc::ptr_eq(&entry.active, identity)
                && entry.active.load(Ordering::Relaxed) == 0
        }) {
            pool.remove(index);
        }
        debug!("discarding closed trusttunnel H3 client: {error}");
    }
}

fn should_create_client(
    pool_size: usize,
    least_active: Option<usize>,
    max_connections: usize,
    min_streams: usize,
    max_streams: usize,
) -> bool {
    let Some(least_active) = least_active else {
        return true;
    };
    if least_active == 0 {
        return false;
    }
    if max_connections > 0 {
        return pool_size < max_connections && least_active >= min_streams;
    }
    // This deliberately creates a new connection when max-streams is zero.
    // It matches Mihomo's PoolClient behavior for unusual partial pool
    // configurations such as setting min-streams without max-connections.
    max_streams == 0 || least_active >= max_streams
}

fn configure_quic_congestion(
    transport: &mut quinn::TransportConfig,
    controller: Option<&str>,
    cwnd: u64,
    bbr_profile: Option<&str>,
) {
    match controller
        .unwrap_or_default()
        .trim()
        .to_ascii_lowercase()
        .as_str()
    {
        "" => {}
        "cubic" => {
            transport.congestion_controller_factory(Arc::new(
                quinn::congestion::CubicConfig::default(),
            ));
        }
        "new_reno" | "new-reno" => {
            transport.congestion_controller_factory(Arc::new(
                quinn::congestion::NewRenoConfig::default(),
            ));
        }
        "bbr" | "bbr_meta_v1" | "bbr_meta_v2" => {
            let mut config = quinn::congestion::BbrConfig::default();
            config.initial_window(cwnd.max(32).saturating_mul(1_200));
            transport.congestion_controller_factory(Arc::new(config));
            if bbr_profile.is_some_and(|profile| !profile.trim().is_empty()) {
                debug!(
                    "trusttunnel maps Mihomo BBR profile `{}` to Quinn BBR",
                    bbr_profile.unwrap()
                );
            }
        }
        unknown => {
            debug!(
                "trusttunnel keeps the default QUIC congestion controller for \
                 `{unknown}`"
            );
        }
    }
}

struct H2PoolEntry {
    sender: h2::client::SendRequest<bytes::Bytes>,
    active: Arc<AtomicUsize>,
    health_reset: Option<watch::Sender<Instant>>,
    cancellation: CancellationToken,
}

struct H3PoolEntry {
    sender: H3Sender,
    active: Arc<AtomicUsize>,
    health_reset: Option<watch::Sender<Instant>>,
    cancellation: CancellationToken,
    connection: quinn::Connection,
}

impl Drop for H3PoolEntry {
    fn drop(&mut self) {
        self.cancellation.cancel();
        self.connection.close(0u32.into(), b"");
    }
}

impl Drop for H2PoolEntry {
    fn drop(&mut self) {
        self.cancellation.cancel();
    }
}

async fn run_health_checks(
    sender: h2::client::SendRequest<bytes::Bytes>,
    authorization: String,
    mut reset: watch::Receiver<Instant>,
    cancellation: CancellationToken,
) {
    let mut deadline = *reset.borrow() + HEALTH_CHECK_INTERVAL;
    loop {
        tokio::select! {
            _ = cancellation.cancelled() => return,
            changed = reset.changed() => {
                if changed.is_err() {
                    return;
                }
                deadline = *reset.borrow_and_update() + HEALTH_CHECK_INTERVAL;
            }
            _ = tokio::time::sleep_until(deadline) => {
                if let Err(error) = send_health_check(&sender, &authorization).await {
                    debug!("trusttunnel health check failed: {error}");
                }
                deadline = Instant::now() + HEALTH_CHECK_INTERVAL;
            }
        }
    }
}

async fn send_health_check(
    sender: &h2::client::SendRequest<bytes::Bytes>,
    authorization: &str,
) -> io::Result<()> {
    let uri = Uri::builder()
        .scheme("https")
        .authority(HEALTH_CHECK_MAGIC_ADDRESS)
        .path_and_query("/")
        .build()
        .map_err(map_io_error)?;
    let request = Request::builder()
        .method(Method::CONNECT)
        .uri(uri)
        .version(Version::HTTP_2)
        .header("user-agent", std::env::consts::OS)
        .header("proxy-authorization", authorization)
        .body(())
        .map_err(map_io_error)?;
    let mut sender = sender.clone().ready().await.map_err(map_io_error)?;
    let (response, _) = sender.send_request(request, true).map_err(map_io_error)?;
    let response = response.await.map_err(map_io_error)?;
    if response.status() != StatusCode::OK {
        return Err(new_io_error(format!(
            "trusttunnel health check returned HTTP {}",
            response.status()
        )));
    }
    Ok(())
}

async fn run_h3_health_checks(
    sender: H3Sender,
    authorization: String,
    mut reset: watch::Receiver<Instant>,
    cancellation: CancellationToken,
) {
    let mut deadline = *reset.borrow() + HEALTH_CHECK_INTERVAL;
    loop {
        tokio::select! {
            _ = cancellation.cancelled() => return,
            changed = reset.changed() => {
                if changed.is_err() {
                    return;
                }
                deadline = *reset.borrow_and_update() + HEALTH_CHECK_INTERVAL;
            }
            _ = tokio::time::sleep_until(deadline) => {
                if let Err(error) =
                    send_h3_health_check(&sender, &authorization).await
                {
                    debug!("trusttunnel HTTP/3 health check failed: {error}");
                }
                deadline = Instant::now() + HEALTH_CHECK_INTERVAL;
            }
        }
    }
}

async fn send_h3_health_check(
    sender: &H3Sender,
    authorization: &str,
) -> io::Result<()> {
    let uri = Uri::builder()
        .scheme("https")
        .authority(HEALTH_CHECK_MAGIC_ADDRESS)
        .path_and_query("/")
        .build()
        .map_err(map_io_error)?;
    let request = Request::builder()
        .method(Method::CONNECT)
        .uri(uri)
        .version(Version::HTTP_3)
        .header("user-agent", std::env::consts::OS)
        .header("proxy-authorization", authorization)
        .body(())
        .map_err(map_io_error)?;
    let mut sender = sender.clone();
    let mut stream = sender
        .send_request(request)
        .await
        .map_err(io::Error::other)?;
    stream.finish().await.map_err(io::Error::other)?;
    let response = stream.recv_response().await.map_err(io::Error::other)?;
    if response.status() != StatusCode::OK {
        return Err(new_io_error(format!(
            "trusttunnel health check returned HTTP {}",
            response.status()
        )));
    }
    while stream
        .recv_data()
        .await
        .map_err(io::Error::other)?
        .is_some()
    {}
    Ok(())
}

struct StreamCounter(Arc<AtomicUsize>);

impl StreamCounter {
    fn new(active: Arc<AtomicUsize>) -> Self {
        active.fetch_add(1, Ordering::Relaxed);
        Self(active)
    }
}

impl Drop for StreamCounter {
    fn drop(&mut self) {
        self.0.fetch_sub(1, Ordering::Relaxed);
    }
}

struct CountedHttp2Stream {
    stream: Http2Stream,
    _counter: StreamCounter,
}

struct CountedHttp3Stream {
    stream: tokio::io::DuplexStream,
    _counter: StreamCounter,
}

impl AsyncRead for CountedHttp3Stream {
    fn poll_read(
        mut self: Pin<&mut Self>,
        context: &mut Context<'_>,
        buffer: &mut tokio::io::ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        Pin::new(&mut self.stream).poll_read(context, buffer)
    }
}

impl AsyncWrite for CountedHttp3Stream {
    fn poll_write(
        mut self: Pin<&mut Self>,
        context: &mut Context<'_>,
        buffer: &[u8],
    ) -> Poll<io::Result<usize>> {
        Pin::new(&mut self.stream).poll_write(context, buffer)
    }

    fn poll_flush(
        mut self: Pin<&mut Self>,
        context: &mut Context<'_>,
    ) -> Poll<io::Result<()>> {
        Pin::new(&mut self.stream).poll_flush(context)
    }

    fn poll_shutdown(
        mut self: Pin<&mut Self>,
        context: &mut Context<'_>,
    ) -> Poll<io::Result<()>> {
        Pin::new(&mut self.stream).poll_shutdown(context)
    }
}

impl AsyncRead for CountedHttp2Stream {
    fn poll_read(
        mut self: Pin<&mut Self>,
        context: &mut Context<'_>,
        buffer: &mut tokio::io::ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        Pin::new(&mut self.stream).poll_read(context, buffer)
    }
}

impl AsyncWrite for CountedHttp2Stream {
    fn poll_write(
        mut self: Pin<&mut Self>,
        context: &mut Context<'_>,
        buffer: &[u8],
    ) -> Poll<io::Result<usize>> {
        Pin::new(&mut self.stream).poll_write(context, buffer)
    }

    fn poll_flush(
        mut self: Pin<&mut Self>,
        context: &mut Context<'_>,
    ) -> Poll<io::Result<()>> {
        Pin::new(&mut self.stream).poll_flush(context)
    }

    fn poll_shutdown(
        mut self: Pin<&mut Self>,
        context: &mut Context<'_>,
    ) -> Poll<io::Result<()>> {
        Pin::new(&mut self.stream).poll_shutdown(context)
    }
}

impl_default_connector!(Handler);

impl Debug for Handler {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("TrustTunnel")
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
        OutboundType::TrustTunnel
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
        if self.opts.quic {
            ConnectorType::All
        } else {
            ConnectorType::Tcp
        }
    }

    async fn connect_stream_with_connector(
        &self,
        sess: &Session,
        resolver: ThreadSafeDNSResolver,
        connector: &dyn RemoteConnector,
    ) -> io::Result<BoxedChainedStream> {
        let authority = sess.destination.to_string();
        let stream = if self.opts.quic {
            self.open_h3_tunnel(connector, sess, resolver, &authority, false)
                .await?
        } else {
            self.open_h2_tunnel(connector, sess, resolver, &authority, false)
                .await?
        };
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
            return Err(new_io_error("trusttunnel UDP is disabled"));
        }
        let stream = if self.opts.quic {
            self.open_h3_tunnel(
                connector,
                sess,
                resolver.clone(),
                UDP_MAGIC_ADDRESS,
                true,
            )
            .await?
        } else {
            self.open_h2_tunnel(
                connector,
                sess,
                resolver.clone(),
                UDP_MAGIC_ADDRESS,
                true,
            )
            .await?
        };
        let datagram = TrustTunnelDatagram::new(stream, resolver, sess);
        let datagram = ChainedDatagramWrapper::new(datagram);
        datagram.append_to_chain(self.name()).await;
        Ok(Box::new(datagram))
    }

    fn try_as_plain_handler(&self) -> Option<&dyn PlainProxyAPIResponse> {
        Some(self)
    }
}

#[async_trait]
impl PlainProxyAPIResponse for Handler {
    async fn as_map(&self) -> HashMap<String, Box<dyn ErasedSerialize + Send>> {
        HashMap::from([
            ("server".to_owned(), Box::new(self.opts.server.clone()) as _),
            ("port".to_owned(), Box::new(self.opts.port) as _),
            ("udp".to_owned(), Box::new(self.opts.udp) as _),
            ("quic".to_owned(), Box::new(self.opts.quic) as _),
        ])
    }
}

struct TrustTunnelDatagram {
    send_tx: PollSender<UdpPacket>,
    recv_rx: tokio::sync::mpsc::Receiver<UdpPacket>,
    workers: Vec<tokio::task::JoinHandle<()>>,
}

impl TrustTunnelDatagram {
    fn new(
        stream: AnyStream,
        resolver: ThreadSafeDNSResolver,
        sess: &Session,
    ) -> Self {
        let (mut reader, mut writer) = tokio::io::split(stream);
        let (send_tx, mut send_rx) = tokio::sync::mpsc::channel::<UdpPacket>(32);
        let (recv_tx, recv_rx) = tokio::sync::mpsc::channel::<UdpPacket>(32);
        let local_source = SocksAddr::from(sess.source);
        let inbound_user = sess.inbound_user.clone();

        let write_worker = tokio::spawn(async move {
            while let Some(packet) = send_rx.recv().await {
                let destination =
                    match resolve_packet_destination(&packet.dst_addr, &resolver)
                        .await
                    {
                        Ok(destination) => destination,
                        Err(error) => {
                            debug!("trusttunnel UDP resolve failed: {error}");
                            continue;
                        }
                    };
                let frame = match encode_udp_request(destination, &packet.data) {
                    Ok(frame) => frame,
                    Err(error) => {
                        debug!("trusttunnel UDP encode failed: {error}");
                        continue;
                    }
                };
                if writer.write_all(&frame).await.is_err()
                    || writer.flush().await.is_err()
                {
                    break;
                }
            }
            let _ = writer.shutdown().await;
        });
        let read_worker = tokio::spawn(async move {
            loop {
                let mut header = [0u8; 4 + UDP_STATIC_HEADER_LENGTH];
                if reader.read_exact(&mut header).await.is_err() {
                    break;
                }
                let (source, payload_length) =
                    match decode_udp_response_header(&header) {
                        Ok(decoded) => decoded,
                        Err(error) => {
                            debug!("trusttunnel UDP decode failed: {error}");
                            break;
                        }
                    };
                let mut data = vec![0u8; payload_length];
                if reader.read_exact(&mut data).await.is_err() {
                    break;
                }
                if recv_tx
                    .send(UdpPacket {
                        data,
                        src_addr: source,
                        dst_addr: local_source.clone(),
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

impl Drop for TrustTunnelDatagram {
    fn drop(&mut self) {
        for worker in &self.workers {
            worker.abort();
        }
    }
}

impl Sink<UdpPacket> for TrustTunnelDatagram {
    type Error = io::Error;

    fn poll_ready(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<Result<(), Self::Error>> {
        self.send_tx
            .poll_ready_unpin(cx)
            .map_err(|_| new_io_error("trusttunnel UDP send channel closed"))
    }

    fn start_send(
        mut self: Pin<&mut Self>,
        item: UdpPacket,
    ) -> Result<(), Self::Error> {
        self.send_tx
            .start_send_unpin(item)
            .map_err(|_| new_io_error("trusttunnel UDP send channel closed"))
    }

    fn poll_flush(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<Result<(), Self::Error>> {
        self.send_tx
            .poll_flush_unpin(cx)
            .map_err(|_| new_io_error("trusttunnel UDP send channel flush failed"))
    }

    fn poll_close(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<Result<(), Self::Error>> {
        self.send_tx
            .poll_close_unpin(cx)
            .map_err(|_| new_io_error("trusttunnel UDP send channel close failed"))
    }
}

impl Stream for TrustTunnelDatagram {
    type Item = UdpPacket;

    fn poll_next(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<Option<Self::Item>> {
        self.recv_rx.poll_recv(cx)
    }
}

async fn resolve_packet_destination(
    destination: &SocksAddr,
    resolver: &ThreadSafeDNSResolver,
) -> io::Result<SocketAddr> {
    match destination {
        SocksAddr::Ip(address) => Ok(*address),
        SocksAddr::Domain(host, port) => resolver
            .resolve(host, false)
            .await
            .map_err(map_io_error)?
            .map(|ip| SocketAddr::new(ip, *port))
            .ok_or_else(|| {
                new_io_error(format!("trusttunnel could not resolve {host}"))
            }),
    }
}

fn encode_udp_request(
    destination: SocketAddr,
    payload: &[u8],
) -> io::Result<Vec<u8>> {
    if payload.len() > MAX_UDP_PAYLOAD {
        return Err(new_io_error("trusttunnel UDP payload is too large"));
    }
    let app_name = APP_NAME.as_bytes();
    let length = UDP_STATIC_HEADER_LENGTH + 1 + app_name.len() + payload.len();
    let mut output = Vec::with_capacity(4 + length);
    output.extend_from_slice(&(length as u32).to_be_bytes());
    output.extend_from_slice(&[0u8; 16]);
    output.extend_from_slice(&0u16.to_be_bytes());
    output.extend_from_slice(&padded_ip(destination.ip()));
    output.extend_from_slice(&destination.port().to_be_bytes());
    output.push(app_name.len() as u8);
    output.extend_from_slice(app_name);
    output.extend_from_slice(payload);
    Ok(output)
}

fn decode_udp_response_header(
    header: &[u8; 4 + UDP_STATIC_HEADER_LENGTH],
) -> io::Result<(SocksAddr, usize)> {
    let length = u32::from_be_bytes(header[..4].try_into().unwrap()) as usize;
    let payload_length = length
        .checked_sub(UDP_STATIC_HEADER_LENGTH)
        .ok_or_else(|| new_io_error("trusttunnel UDP response length is invalid"))?;
    if payload_length > MAX_UDP_PAYLOAD {
        return Err(new_io_error("trusttunnel UDP response is too large"));
    }
    let mut ip = [0u8; 16];
    ip.copy_from_slice(&header[4..20]);
    let port = u16::from_be_bytes([header[20], header[21]]);
    Ok((
        SocksAddr::Ip(SocketAddr::new(parse_padded_ip(ip), port)),
        payload_length,
    ))
}

fn padded_ip(ip: IpAddr) -> [u8; 16] {
    match ip {
        IpAddr::V4(ip) => {
            let mut output = [0u8; 16];
            output[12..].copy_from_slice(&ip.octets());
            output
        }
        IpAddr::V6(ip) => ip.octets(),
    }
}

fn parse_padded_ip(ip: [u8; 16]) -> IpAddr {
    let ipv4_padding = ip[..12].iter().all(|byte| *byte == 0);
    let loopback_v6 = ip[12..] == [0, 0, 0, 1];
    if ipv4_padding && !loopback_v6 {
        IpAddr::V4(Ipv4Addr::new(ip[12], ip[13], ip[14], ip[15]))
    } else {
        IpAddr::V6(Ipv6Addr::from(ip))
    }
}

#[cfg(test)]
mod tests {
    use super::{
        APP_NAME, Handler, HandlerOptions, QuicTlsOptions, UDP_STATIC_HEADER_LENGTH,
        decode_udp_response_header, encode_udp_request, send_health_check,
        should_create_client,
    };
    use crate::{
        app::dns::SystemResolver,
        common::tls::resolve_server_cert_and_key,
        proxy::{
            HandlerCommonOptions, transport::TlsClient, utils::DirectConnector,
        },
        session::{Session, SocksAddr},
    };
    use bytes::{Buf, Bytes};
    use http::{Method, Response, StatusCode};
    use std::{
        net::{IpAddr, Ipv4Addr, SocketAddr},
        sync::Arc,
        time::Duration,
    };
    use tokio::io::{AsyncReadExt, AsyncWriteExt, duplex};

    #[test]
    fn udp_request_matches_mihomo_layout() {
        let destination = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(8, 8, 8, 8)), 53);
        let frame = encode_udp_request(destination, b"dns").unwrap();
        assert_eq!(
            u32::from_be_bytes(frame[..4].try_into().unwrap()) as usize,
            UDP_STATIC_HEADER_LENGTH + 1 + APP_NAME.len() + 3
        );
        assert_eq!(&frame[4..22], &[0u8; 18]);
        assert_eq!(&frame[34..38], &[8, 8, 8, 8]);
        assert_eq!(&frame[38..40], &53u16.to_be_bytes());
        assert_eq!(frame[40] as usize, APP_NAME.len());
        assert_eq!(&frame[41 + APP_NAME.len()..], b"dns");
    }

    #[test]
    fn udp_response_header_decodes_padded_ipv4() {
        let mut header = [0u8; 4 + UDP_STATIC_HEADER_LENGTH];
        header[..4]
            .copy_from_slice(&(UDP_STATIC_HEADER_LENGTH as u32 + 3).to_be_bytes());
        header[16..20].copy_from_slice(&[1, 1, 1, 1]);
        header[20..22].copy_from_slice(&443u16.to_be_bytes());
        let (source, payload_length) = decode_udp_response_header(&header).unwrap();
        assert_eq!(source, SocksAddr::Ip(([1, 1, 1, 1], 443).into()));
        assert_eq!(payload_length, 3);
    }

    #[test]
    fn pool_selection_matches_mihomo_thresholds() {
        assert!(should_create_client(0, None, 8, 5, 0));
        assert!(!should_create_client(1, Some(0), 8, 5, 0));
        assert!(!should_create_client(1, Some(4), 8, 5, 0));
        assert!(should_create_client(1, Some(5), 8, 5, 0));
        assert!(!should_create_client(8, Some(9), 8, 5, 0));

        assert!(!should_create_client(1, Some(3), 0, 0, 4));
        assert!(should_create_client(1, Some(4), 0, 0, 4));
        assert!(should_create_client(1, Some(1), 0, 2, 0));
    }

    #[tokio::test]
    async fn health_check_matches_mihomo_connect_request() {
        let (client_io, server_io) = duplex(4096);
        let (client, client_connection) =
            h2::client::handshake(client_io).await.unwrap();
        tokio::spawn(async move {
            let _ = client_connection.await;
        });
        let server = tokio::spawn(async move {
            let mut connection = h2::server::handshake(server_io).await.unwrap();
            let (request, mut respond) =
                connection.accept().await.expect("health request").unwrap();
            assert_eq!(request.method(), Method::CONNECT);
            assert_eq!(request.uri().authority().unwrap().as_str(), "_check");
            assert_eq!(
                request.headers().get("user-agent").unwrap(),
                std::env::consts::OS
            );
            assert_eq!(
                request.headers().get("proxy-authorization").unwrap(),
                "Basic dXNlcjpwYXNz"
            );
            let response =
                Response::builder().status(StatusCode::OK).body(()).unwrap();
            respond.send_response(response, true).unwrap();
            connection.graceful_shutdown();
            while let Some(Ok(_)) = connection.accept().await {}
        });

        send_health_check(&client, "Basic dXNlcjpwYXNz")
            .await
            .unwrap();
        drop(client);
        server.await.unwrap();
    }

    #[tokio::test]
    async fn http3_connect_reuses_quic_connection_and_roundtrips_bytes() {
        crate::tests::initialize();
        let (certs, key) =
            resolve_server_cert_and_key(None, None, "trusttunnel-test").unwrap();
        let mut tls = rustls::ServerConfig::builder()
            .with_no_client_auth()
            .with_single_cert(certs, key)
            .unwrap();
        tls.alpn_protocols = vec![b"h3".to_vec()];
        let quic_tls =
            quinn::crypto::rustls::QuicServerConfig::try_from(tls).unwrap();
        let endpoint = quinn::Endpoint::server(
            quinn::ServerConfig::with_crypto(Arc::new(quic_tls)),
            (Ipv4Addr::LOCALHOST, 0).into(),
        )
        .unwrap();
        let server_addr = endpoint.local_addr().unwrap();
        let server = tokio::spawn(async move {
            let connection = endpoint.accept().await.unwrap().await.unwrap();
            let h3_connection = h3_quinn::Connection::new(connection);
            let mut server = h3::server::builder()
                .build::<_, Bytes>(h3_connection)
                .await
                .unwrap();
            use h3::server::RequestResolver;
            for _ in 0..2 {
                let resolver: RequestResolver<_, _> =
                    server.accept().await.unwrap().unwrap();
                let (request, mut stream) =
                    resolver.resolve_request().await.unwrap();
                assert_eq!(request.method(), Method::CONNECT);
                assert_eq!(request.version(), http::Version::HTTP_3);
                assert_eq!(
                    request.uri().authority().unwrap().as_str(),
                    "example.com:443"
                );
                assert_eq!(
                    request.headers()["proxy-authorization"],
                    "Basic dXNlcjpwYXNz"
                );
                assert!(
                    request.headers()["user-agent"]
                        .to_str()
                        .unwrap()
                        .contains("FlClash/")
                );
                stream
                    .send_response(
                        Response::builder().status(StatusCode::OK).body(()).unwrap(),
                    )
                    .await
                    .unwrap();
                while let Some(mut data) = stream.recv_data().await.unwrap() {
                    let length = data.remaining();
                    stream.send_data(data.copy_to_bytes(length)).await.unwrap();
                }
                let _ = stream.finish().await;
            }
        });

        let handler = Handler::new(HandlerOptions {
            name: "trust-h3".to_owned(),
            common_opts: HandlerCommonOptions::default(),
            server: "127.0.0.1".to_owned(),
            port: server_addr.port(),
            username: "user".to_owned(),
            password: "pass".to_owned(),
            udp: true,
            tls: Box::new(
                TlsClient::new(
                    true,
                    "localhost".to_owned(),
                    Some(vec!["h3".to_owned()]),
                    Some("h3".to_owned()),
                    None,
                    None,
                )
                .unwrap(),
            ),
            health_check: false,
            quic: true,
            quic_tls: Some(QuicTlsOptions::new(
                "localhost".to_owned(),
                true,
                None,
                None,
                None,
                None,
            )),
            congestion_controller: Some("bbr".to_owned()),
            cwnd: 32,
            bbr_profile: Some("mobile".to_owned()),
            max_connections: 8,
            min_streams: 5,
            max_streams: 0,
        })
        .unwrap();
        let resolver = Arc::new(SystemResolver::new(false).unwrap());
        for payload in [b"first".as_slice(), b"second".as_slice()] {
            let mut stream = tokio::time::timeout(
                Duration::from_secs(3),
                handler.open_h3_tunnel(
                    &DirectConnector::new(),
                    &Session::default(),
                    resolver.clone(),
                    "example.com:443",
                    false,
                ),
            )
            .await
            .expect("trusttunnel H3 handshake timed out")
            .unwrap();
            stream.write_all(payload).await.unwrap();
            stream.flush().await.unwrap();
            let mut response = vec![0u8; payload.len()];
            tokio::time::timeout(
                Duration::from_secs(2),
                stream.read_exact(&mut response),
            )
            .await
            .expect("trusttunnel H3 echo timed out")
            .unwrap();
            assert_eq!(response, payload);
            stream.shutdown().await.unwrap();
        }
        tokio::time::timeout(Duration::from_secs(2), server)
            .await
            .expect("trusttunnel H3 server timed out")
            .unwrap();
    }
}
