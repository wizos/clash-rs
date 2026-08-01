use std::{
    collections::HashMap,
    fmt::Debug,
    io,
    net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr},
    sync::Arc,
    time::Duration,
};

use async_trait::async_trait;
use base64::{Engine, engine::general_purpose::STANDARD as BASE64};
use bytes::{Buf, Bytes};
use erased_serde::Serialize as ErasedSerialize;
use h2::{RecvStream, SendStream};
use http::{Method, Request, StatusCode, Uri, Version};
use p256::pkcs8::EncodePrivateKey;
use rustls::{
    client::danger::{
        HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier,
    },
    pki_types::{
        CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer, ServerName, UnixTime,
    },
};
use tokio::{
    io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt},
    sync::{OnceCell, mpsc},
};
use tracing::{debug, warn};
use x509_parser::prelude::{FromDer, SubjectPublicKeyInfo, parse_x509_certificate};

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
        utils::{GLOBAL_DIRECT_CONNECTOR, QuinnDatagramSocket, RemoteConnector},
        wg::{device, events::PortProtocol},
    },
    session::{Session, SocksAddr},
};

const CAPSULE_DATAGRAM: u64 = 0;
const IPV4_HEADER_LENGTH: usize = 20;
const IPV6_HEADER_LENGTH: usize = 40;
const MAX_IP_PACKET_LENGTH: u64 = u16::MAX as u64;

#[derive(Clone)]
pub struct MasqueTlsClient {
    sni: String,
    config: Arc<rustls::ClientConfig>,
}

impl MasqueTlsClient {
    pub fn new(
        private_key: &str,
        public_key: &str,
        sni: String,
        skip_cert_verify: bool,
        network: MasqueNetwork,
    ) -> Result<Self, Error> {
        let private_key = BASE64.decode(private_key).map_err(|error| {
            Error::InvalidConfig(format!(
                "failed to decode MASQUE private-key: {error}"
            ))
        })?;
        let secret_key =
            p256::SecretKey::from_sec1_der(&private_key).map_err(|error| {
                Error::InvalidConfig(format!(
                    "failed to parse MASQUE EC private-key: {error}"
                ))
            })?;
        let pkcs8 = secret_key.to_pkcs8_der().map_err(|error| {
            Error::InvalidConfig(format!(
                "failed to convert MASQUE EC private-key: {error}"
            ))
        })?;
        let key_der = PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(
            pkcs8.as_bytes().to_vec(),
        ));
        let signing_key = rcgen::KeyPair::from_der_and_sign_algo(
            &key_der,
            &rcgen::PKCS_ECDSA_P256_SHA256,
        )
        .map_err(|error| {
            Error::InvalidConfig(format!(
                "failed to load MASQUE EC signing key: {error}"
            ))
        })?;
        let now = time::OffsetDateTime::now_utc();
        let mut params = rcgen::CertificateParams::default();
        params.not_before = now;
        params.not_after = now + time::Duration::days(1);
        params.serial_number = Some(0u64.into());
        params.distinguished_name = rcgen::DistinguishedName::new();
        let certificate = params.self_signed(&signing_key).map_err(|error| {
            Error::InvalidConfig(format!(
                "failed to generate MASQUE client certificate: {error}"
            ))
        })?;

        let public_key = BASE64.decode(public_key).map_err(|error| {
            Error::InvalidConfig(format!(
                "failed to decode MASQUE public-key: {error}"
            ))
        })?;
        let (remaining, spki) = SubjectPublicKeyInfo::from_der(&public_key)
            .map_err(|error| {
                Error::InvalidConfig(format!(
                    "failed to parse MASQUE endpoint public-key: {error}"
                ))
            })?;
        if !remaining.is_empty()
            || !matches!(
                spki.parsed(),
                Ok(x509_parser::public_key::PublicKey::EC(_))
            )
        {
            return Err(Error::InvalidConfig(
                "MASQUE public-key must be an ECDSA PKIX public key".to_owned(),
            ));
        }

        let verifier: Arc<dyn ServerCertVerifier> = Arc::new(
            PublicKeyVerifier::new((!skip_cert_verify).then_some(public_key)),
        );
        let mut tls_config = rustls::ClientConfig::builder()
            .dangerous()
            .with_custom_certificate_verifier(verifier)
            .with_client_auth_cert(
                vec![CertificateDer::from(certificate.der().to_vec())],
                key_der,
            )
            .map_err(|error| {
                Error::InvalidConfig(format!(
                    "failed to configure MASQUE client certificate: {error}"
                ))
            })?;
        tls_config.alpn_protocols = vec![network.alpn().to_vec()];
        let config = Arc::new(tls_config);

        Ok(Self { sni, config })
    }

    async fn connect(&self, stream: AnyStream) -> io::Result<AnyStream> {
        let server_name =
            ServerName::try_from(self.sni.clone()).map_err(map_io_error)?;
        tokio_rustls::TlsConnector::from(self.config.clone())
            .connect(server_name, stream)
            .await
            .and_then(|stream| {
                if stream.get_ref().1.alpn_protocol() != Some(b"h2") {
                    return Err(io::Error::other(
                        "MASQUE server did not negotiate HTTP/2",
                    ));
                }
                Ok(Box::new(stream) as AnyStream)
            })
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum MasqueNetwork {
    H2,
    H3,
}

impl MasqueNetwork {
    fn alpn(self) -> &'static [u8] {
        match self {
            Self::H2 => b"h2",
            Self::H3 => b"h3",
        }
    }
}

#[derive(Debug)]
struct PublicKeyVerifier {
    expected_spki: Option<Vec<u8>>,
    signatures: DefaultTlsVerifier,
}

impl PublicKeyVerifier {
    fn new(expected_spki: Option<Vec<u8>>) -> Self {
        Self {
            expected_spki,
            signatures: DefaultTlsVerifier::new(None, false),
        }
    }
}

impl ServerCertVerifier for PublicKeyVerifier {
    fn verify_server_cert(
        &self,
        end_entity: &CertificateDer<'_>,
        _intermediates: &[CertificateDer<'_>],
        _server_name: &ServerName<'_>,
        _ocsp_response: &[u8],
        _now: UnixTime,
    ) -> Result<ServerCertVerified, rustls::Error> {
        let Some(expected_spki) = self.expected_spki.as_ref() else {
            return Ok(ServerCertVerified::assertion());
        };
        let (_, certificate) =
            parse_x509_certificate(end_entity.as_ref()).map_err(|error| {
                rustls::Error::General(format!(
                    "invalid MASQUE endpoint certificate: {error}"
                ))
            })?;
        if certificate.public_key().raw != expected_spki {
            return Err(rustls::Error::General(
                "MASQUE endpoint public key does not match public-key".to_owned(),
            ));
        }
        Ok(ServerCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &rustls::DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        self.signatures.verify_tls12_signature(message, cert, dss)
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &rustls::DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        self.signatures.verify_tls13_signature(message, cert, dss)
    }

    fn supported_verify_schemes(&self) -> Vec<rustls::SignatureScheme> {
        self.signatures.supported_verify_schemes()
    }
}

pub struct HandlerOptions {
    pub name: String,
    pub common_opts: HandlerCommonOptions,
    pub server: String,
    pub port: u16,
    pub ip: Ipv4Addr,
    pub has_ipv4: bool,
    pub ipv6: Option<Ipv6Addr>,
    pub uri: String,
    pub mtu: u16,
    pub udp: bool,
    pub remote_dns_resolve: bool,
    pub dns: Option<Vec<String>>,
    pub network: MasqueNetwork,
    pub tls: MasqueTlsClient,
}

struct Inner {
    device_manager: Arc<device::DeviceManager>,
    #[allow(unused)]
    tunnel_handle: tokio::task::JoinHandle<()>,
    #[allow(unused)]
    device_handle: tokio::task::JoinHandle<()>,
}

pub struct Handler {
    opts: HandlerOptions,
    uri: Uri,
    inner: OnceCell<Inner>,
    connector: tokio::sync::RwLock<Option<Arc<dyn RemoteConnector>>>,
}

impl Handler {
    pub fn new(opts: HandlerOptions) -> Result<Self, Error> {
        if opts.name.is_empty() || opts.server.is_empty() || opts.port == 0 {
            return Err(Error::InvalidConfig(
                "MASQUE requires name, server and port".to_owned(),
            ));
        }
        if opts.mtu < 576 {
            return Err(Error::InvalidConfig(
                "MASQUE mtu must be at least 576".to_owned(),
            ));
        }
        if opts.uri.contains('{') || opts.uri.contains('}') {
            return Err(Error::InvalidConfig(
                "MASQUE URI templates with variables are not supported by Mihomo"
                    .to_owned(),
            ));
        }
        let uri = opts.uri.parse::<Uri>().map_err(|error| {
            Error::InvalidConfig(format!("invalid MASQUE uri: {error}"))
        })?;
        if uri.scheme_str() != Some("https") || uri.authority().is_none() {
            return Err(Error::InvalidConfig(
                "MASQUE uri must be an absolute https URI".to_owned(),
            ));
        }
        Ok(Self {
            opts,
            uri,
            inner: OnceCell::new(),
            connector: Default::default(),
        })
    }

    async fn initialize_inner(
        &self,
        resolver: ThreadSafeDNSResolver,
        sess: &Session,
    ) -> io::Result<&Inner> {
        self.inner
            .get_or_try_init(|| async {
                let (packet_sender, packet_receiver) = mpsc::channel(1024);
                let (incoming_sender, incoming_receiver) = mpsc::channel(1024);
                let (notifier_sender, notifier_receiver) = mpsc::channel(1024);

                let connector = self
                    .connector
                    .read()
                    .await
                    .clone()
                    .unwrap_or_else(|| GLOBAL_DIRECT_CONNECTOR.clone());
                let first_stream = open_tunnel(
                    connector.as_ref(),
                    resolver.clone(),
                    sess,
                    &self.opts.server,
                    self.opts.port,
                    &self.uri,
                    &self.opts.tls,
                    self.opts.network,
                )
                .await?;

                let device = device::VirtualIpDevice::new(
                    packet_sender,
                    incoming_receiver,
                    notifier_sender,
                    self.opts.mtu as usize,
                );
                let dns_servers = self
                    .opts
                    .dns
                    .as_ref()
                    .map(|servers| {
                        servers
                            .iter()
                            .map(|server| parse_dns_server(server))
                            .collect::<io::Result<Vec<_>>>()
                    })
                    .transpose()?
                    .unwrap_or_default();
                let device_manager = Arc::new(device::DeviceManager::new(
                    self.opts.has_ipv4.then_some(self.opts.ip),
                    self.opts.ipv6,
                    resolver.clone(),
                    if self.opts.remote_dns_resolve {
                        dns_servers
                    } else {
                        vec![]
                    },
                    notifier_receiver,
                ));

                let manager = device_manager.clone();
                let device_handle = tokio::spawn(async move {
                    manager.poll_sockets(device).await;
                });

                let session = sess.clone();
                let server = self.opts.server.clone();
                let port = self.opts.port;
                let uri = self.uri.clone();
                let tls = self.opts.tls.clone();
                let network = self.opts.network;
                let tunnel_handle = tokio::spawn(async move {
                    run_reconnecting_tunnel(
                        first_stream,
                        packet_receiver,
                        incoming_sender,
                        connector,
                        resolver,
                        session,
                        server,
                        port,
                        uri,
                        tls,
                        network,
                    )
                    .await;
                });

                Ok(Inner {
                    device_manager,
                    tunnel_handle,
                    device_handle,
                })
            })
            .await
    }

    async fn resolve_target(
        &self,
        resolver: &ThreadSafeDNSResolver,
        sess: &Session,
        inner: &Inner,
    ) -> io::Result<IpAddr> {
        if self.opts.remote_dns_resolve
            && sess.destination.is_domain()
            && self
                .opts
                .dns
                .as_ref()
                .is_some_and(|servers| !servers.is_empty())
        {
            let servers = self.opts.dns.as_ref().unwrap();
            let server = &servers[rand::random_range(0..servers.len())];
            return inner
                .device_manager
                .look_up_dns(&sess.destination.host(), parse_dns_server(server)?)
                .await
                .ok_or_else(|| new_io_error("invalid remote address"));
        }

        let host = sess.destination.host();
        let address = match (self.opts.has_ipv4, self.opts.ipv6.is_some()) {
            (true, false) => resolver
                .resolve_v4(&host, false)
                .await
                .map_err(map_io_error)?
                .map(IpAddr::V4),
            (false, true) => resolver
                .resolve_v6(&host, false)
                .await
                .map_err(map_io_error)?
                .map(IpAddr::V6),
            _ => resolver.resolve(&host, false).await.map_err(map_io_error)?,
        };
        address.ok_or_else(|| new_io_error("invalid remote address"))
    }
}

impl_default_connector!(Handler);

impl Debug for Handler {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("Masque")
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
        OutboundType::Masque
    }

    async fn support_udp(&self) -> bool {
        self.opts.udp
    }

    async fn connect_stream(
        &self,
        sess: &Session,
        resolver: ThreadSafeDNSResolver,
    ) -> io::Result<BoxedChainedStream> {
        let inner = self.initialize_inner(resolver.clone(), sess).await?;
        let target = self.resolve_target(&resolver, sess, inner).await?;
        let socket = inner
            .device_manager
            .new_tcp_socket(SocketAddr::new(target, sess.destination.port()))
            .await?;
        let chained = ChainedStreamWrapper::new(socket);
        chained.append_to_chain(self.name()).await;
        Ok(Box::new(chained))
    }

    async fn connect_datagram(
        &self,
        sess: &Session,
        resolver: ThreadSafeDNSResolver,
    ) -> io::Result<BoxedChainedDatagram> {
        let inner = self.initialize_inner(resolver, sess).await?;
        let socket = inner.device_manager.new_udp_socket().await;
        let chained = ChainedDatagramWrapper::new(socket);
        chained.append_to_chain(self.name()).await;
        Ok(Box::new(chained))
    }

    async fn support_connector(&self) -> ConnectorType {
        match self.opts.network {
            MasqueNetwork::H2 => ConnectorType::Tcp,
            MasqueNetwork::H3 => ConnectorType::All,
        }
    }

    fn try_as_plain_handler(&self) -> Option<&dyn PlainProxyAPIResponse> {
        Some(self)
    }
}

#[async_trait]
impl PlainProxyAPIResponse for Handler {
    async fn as_map(&self) -> HashMap<String, Box<dyn ErasedSerialize + Send>> {
        let mut values = HashMap::new();
        values.insert("server".to_owned(), Box::new(self.opts.server.clone()) as _);
        values.insert("port".to_owned(), Box::new(self.opts.port) as _);
        values.insert(
            "network".to_owned(),
            Box::new(match self.opts.network {
                MasqueNetwork::H2 => "h2",
                MasqueNetwork::H3 => "h3",
            }) as _,
        );
        values
    }
}

async fn open_h2_tunnel(
    connector: &dyn RemoteConnector,
    resolver: ThreadSafeDNSResolver,
    sess: &Session,
    server: &str,
    port: u16,
    uri: &Uri,
    tls: &MasqueTlsClient,
) -> io::Result<AnyStream> {
    let raw = connector
        .connect_stream(
            resolver,
            server,
            port,
            sess.iface.as_ref(),
            #[cfg(target_os = "linux")]
            sess.so_mark,
        )
        .await?;
    let tls = tls.connect(raw).await?;
    let (mut client, connection) = h2::client::Builder::new()
        .initial_connection_window_size(0x7fff_ffff)
        .initial_window_size(0x7fff_ffff)
        .enable_push(false)
        .handshake(tls)
        .await
        .map_err(map_io_error)?;
    client = client.ready().await.map_err(map_io_error)?;
    let request = Request::builder()
        .method(Method::CONNECT)
        .uri(uri.clone())
        .version(Version::HTTP_2)
        .header("user-agent", "")
        .header("cf-connect-proto", "cf-connect-ip")
        .header("pq-enabled", "false")
        .body(())
        .map_err(map_io_error)?;
    let (response, sender) =
        client.send_request(request, false).map_err(map_io_error)?;
    tokio::spawn(async move {
        if let Err(error) = connection.await {
            debug!("MASQUE HTTP/2 connection stopped: {error}");
        }
    });
    let response = response.await.map_err(map_io_error)?;
    if response.status() != StatusCode::OK {
        return Err(new_io_error(format!(
            "MASQUE server returned HTTP {}",
            response.status()
        )));
    }
    Ok(Box::new(CapsuleStream::new(response.into_body(), sender)))
}

#[allow(clippy::too_many_arguments)]
async fn open_tunnel(
    connector: &dyn RemoteConnector,
    resolver: ThreadSafeDNSResolver,
    sess: &Session,
    server: &str,
    port: u16,
    uri: &Uri,
    tls: &MasqueTlsClient,
    network: MasqueNetwork,
) -> io::Result<AnyStream> {
    match network {
        MasqueNetwork::H2 => {
            open_h2_tunnel(connector, resolver, sess, server, port, uri, tls).await
        }
        MasqueNetwork::H3 => {
            open_h3_tunnel(connector, resolver, sess, server, port, uri, tls).await
        }
    }
}

async fn open_h3_tunnel(
    connector: &dyn RemoteConnector,
    resolver: ThreadSafeDNSResolver,
    sess: &Session,
    server: &str,
    port: u16,
    uri: &Uri,
    tls: &MasqueTlsClient,
) -> io::Result<AnyStream> {
    let remote_ip = resolver
        .resolve(server, true)
        .await
        .map_err(map_io_error)?
        .ok_or_else(|| new_io_error("failed to resolve MASQUE HTTP/3 server"))?;
    let remote_addr = SocketAddr::new(remote_ip, port);
    let destination = SocksAddr::Domain(server.to_owned(), port);
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
    let socket = QuinnDatagramSocket::new(datagram, destination, remote_addr);
    let quic_tls =
        quinn::crypto::rustls::QuicClientConfig::try_from((*tls.config).clone())
            .map_err(io::Error::other)?;
    let mut client_config = quinn::ClientConfig::new(Arc::new(quic_tls));
    let mut transport = quinn::TransportConfig::default();
    transport.max_idle_timeout(Some(
        Duration::from_secs(300)
            .try_into()
            .map_err(io::Error::other)?,
    ));
    transport.keep_alive_interval(Some(Duration::from_secs(10)));
    client_config.transport_config(Arc::new(transport));
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
    let h3_connection = h3_quinn::Connection::new(connection);
    let mut builder = h3::client::builder();
    builder.enable_extended_connect(true);
    let (mut driver, mut sender) = builder
        .build::<_, _, Bytes>(h3_connection)
        .await
        .map_err(io::Error::other)?;
    tokio::spawn(async move {
        let error = driver.wait_idle().await;
        debug!("MASQUE HTTP/3 connection stopped: {error}");
        drop(endpoint);
    });
    let request = Request::builder()
        .method(Method::CONNECT)
        .uri(uri.clone())
        .version(Version::HTTP_3)
        .header("user-agent", "")
        .header("cf-connect-proto", "cf-connect-ip")
        .header("pq-enabled", "false")
        .body(())
        .map_err(map_io_error)?;
    let mut stream = sender
        .send_request(request)
        .await
        .map_err(io::Error::other)?;
    let response = stream.recv_response().await.map_err(io::Error::other)?;
    if response.status() != StatusCode::OK {
        return Err(new_io_error(format!(
            "MASQUE server returned HTTP {}",
            response.status()
        )));
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
        let _sender_guard = sender;
        loop {
            match download.recv_data().await {
                Ok(Some(mut data)) => {
                    let length = data.remaining();
                    if output.write_all(&data.copy_to_bytes(length)).await.is_err() {
                        break;
                    }
                }
                Ok(None) | Err(_) => break,
            }
        }
        let _ = output.shutdown().await;
    });
    Ok(Box::new(application))
}

#[allow(clippy::too_many_arguments)]
async fn run_reconnecting_tunnel(
    mut stream: AnyStream,
    mut packet_receiver: mpsc::Receiver<Bytes>,
    incoming_sender: mpsc::Sender<(PortProtocol, Bytes)>,
    connector: Arc<dyn RemoteConnector>,
    resolver: ThreadSafeDNSResolver,
    session: Session,
    server: String,
    port: u16,
    uri: Uri,
    tls: MasqueTlsClient,
    network: MasqueNetwork,
) {
    loop {
        let result =
            run_capsule_bridge(stream, &mut packet_receiver, &incoming_sender).await;
        if packet_receiver.is_closed() || incoming_sender.is_closed() {
            return;
        }
        warn!(
            "MASQUE {:?} tunnel stopped: {result:?}; reconnecting",
            network
        );
        loop {
            tokio::time::sleep(Duration::from_secs(1)).await;
            match open_tunnel(
                connector.as_ref(),
                resolver.clone(),
                &session,
                &server,
                port,
                &uri,
                &tls,
                network,
            )
            .await
            {
                Ok(next) => {
                    stream = next;
                    break;
                }
                Err(error) => {
                    warn!("MASQUE {:?} reconnect failed: {error}", network)
                }
            }
        }
    }
}

async fn run_capsule_bridge(
    stream: AnyStream,
    packet_receiver: &mut mpsc::Receiver<Bytes>,
    incoming_sender: &mpsc::Sender<(PortProtocol, Bytes)>,
) -> io::Result<()> {
    let (mut reader, mut writer) = tokio::io::split(stream);
    tokio::select! {
        result = send_ip_packets(packet_receiver, &mut writer) => result,
        result = receive_ip_packets(&mut reader, incoming_sender) => result,
    }
}

async fn send_ip_packets<W: AsyncWrite + Unpin>(
    packets: &mut mpsc::Receiver<Bytes>,
    writer: &mut W,
) -> io::Result<()> {
    while let Some(packet) = packets.recv().await {
        let mut packet = packet.to_vec();
        prepare_outgoing_packet(&mut packet)?;
        writer.write_all(&encode_varint(CAPSULE_DATAGRAM)?).await?;
        writer
            .write_all(&encode_varint(packet.len() as u64)?)
            .await?;
        writer.write_all(&packet).await?;
        writer.flush().await?;
    }
    Err(io::Error::new(
        io::ErrorKind::BrokenPipe,
        "MASQUE packet source closed",
    ))
}

async fn receive_ip_packets<R: AsyncRead + Unpin>(
    reader: &mut R,
    sender: &mpsc::Sender<(PortProtocol, Bytes)>,
) -> io::Result<()> {
    loop {
        let capsule_type = read_varint(reader).await?;
        let payload_length = read_varint(reader).await?;
        if payload_length > MAX_IP_PACKET_LENGTH {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                format!("MASQUE capsule payload is too large: {payload_length}"),
            ));
        }
        let mut packet = vec![0; payload_length as usize];
        reader.read_exact(&mut packet).await?;
        if capsule_type != CAPSULE_DATAGRAM {
            continue;
        }
        validate_incoming_packet(&packet)?;
        sender
            .send((packet_protocol(&packet), Bytes::from(packet)))
            .await
            .map_err(|_| {
                io::Error::new(
                    io::ErrorKind::BrokenPipe,
                    "MASQUE virtual IP stack stopped",
                )
            })?;
    }
}

fn prepare_outgoing_packet(packet: &mut [u8]) -> io::Result<()> {
    let version = packet.first().map(|byte| byte >> 4).unwrap_or_default();
    match version {
        4 if packet.len() >= IPV4_HEADER_LENGTH => {
            if packet[8] <= 1 {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "MASQUE IPv4 packet TTL is too small",
                ));
            }
            packet[8] -= 1;
            packet[10] = 0;
            packet[11] = 0;
            let checksum = ipv4_checksum(&packet[..IPV4_HEADER_LENGTH]);
            packet[10..12].copy_from_slice(&checksum.to_be_bytes());
            Ok(())
        }
        6 if packet.len() >= IPV6_HEADER_LENGTH => {
            if packet[7] <= 1 {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "MASQUE IPv6 packet hop limit is too small",
                ));
            }
            packet[7] -= 1;
            Ok(())
        }
        4 | 6 => Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "MASQUE IP packet is shorter than its fixed header",
        )),
        _ => Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!("MASQUE packet has unknown IP version {version}"),
        )),
    }
}

fn validate_incoming_packet(packet: &[u8]) -> io::Result<()> {
    match packet.first().map(|byte| byte >> 4).unwrap_or_default() {
        4 if packet.len() >= IPV4_HEADER_LENGTH => Ok(()),
        6 if packet.len() >= IPV6_HEADER_LENGTH => Ok(()),
        4 | 6 => Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "MASQUE IP packet is shorter than its fixed header",
        )),
        version => Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!("MASQUE packet has unknown IP version {version}"),
        )),
    }
}

fn packet_protocol(packet: &[u8]) -> PortProtocol {
    let next_header = match packet[0] >> 4 {
        4 => packet[9],
        6 => packet[6],
        _ => return PortProtocol::Tcp,
    };
    if next_header == 17 {
        PortProtocol::Udp
    } else {
        PortProtocol::Tcp
    }
}

fn ipv4_checksum(header: &[u8]) -> u16 {
    let mut sum = header
        .chunks_exact(2)
        .map(|word| u16::from_be_bytes([word[0], word[1]]) as u32)
        .sum::<u32>();
    while sum >> 16 != 0 {
        sum = (sum & 0xffff) + (sum >> 16);
    }
    !(sum as u16)
}

fn encode_varint(value: u64) -> io::Result<Vec<u8>> {
    match value {
        0..=63 => Ok(vec![value as u8]),
        64..=16_383 => Ok(((value as u16) | 0x4000).to_be_bytes().to_vec()),
        16_384..=1_073_741_823 => {
            Ok(((value as u32) | 0x8000_0000).to_be_bytes().to_vec())
        }
        1_073_741_824..=4_611_686_018_427_387_903 => {
            Ok((value | 0xc000_0000_0000_0000).to_be_bytes().to_vec())
        }
        _ => Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "QUIC variable-length integer is too large",
        )),
    }
}

async fn read_varint<R: AsyncRead + Unpin>(reader: &mut R) -> io::Result<u64> {
    let first = reader.read_u8().await?;
    let length = 1usize << (first >> 6);
    let mut value = (first & 0x3f) as u64;
    for _ in 1..length {
        value = (value << 8) | reader.read_u8().await? as u64;
    }
    Ok(value)
}

fn parse_dns_server(value: &str) -> io::Result<SocketAddr> {
    if let Ok(address) = value.parse::<SocketAddr>() {
        return Ok(address);
    }
    value
        .parse::<IpAddr>()
        .map(|address| SocketAddr::new(address, 53))
        .map_err(|error| {
            io::Error::new(
                io::ErrorKind::InvalidInput,
                format!(
                    "MASQUE remote DNS server `{value}` must be an IP address: \
                     {error}"
                ),
            )
        })
}

struct CapsuleStream {
    recv: RecvStream,
    send: SendStream<Bytes>,
    buffer: Bytes,
}

impl CapsuleStream {
    fn new(recv: RecvStream, send: SendStream<Bytes>) -> Self {
        Self {
            recv,
            send,
            buffer: Bytes::new(),
        }
    }
}

impl AsyncRead for CapsuleStream {
    fn poll_read(
        mut self: std::pin::Pin<&mut Self>,
        context: &mut std::task::Context<'_>,
        buffer: &mut tokio::io::ReadBuf<'_>,
    ) -> std::task::Poll<io::Result<()>> {
        use futures::ready;

        if !self.buffer.is_empty() {
            let length = self.buffer.len().min(buffer.remaining());
            buffer.put_slice(&self.buffer.split_to(length));
            return std::task::Poll::Ready(Ok(()));
        }
        match ready!(self.recv.poll_data(context)) {
            Some(Ok(data)) => {
                let length = data.len().min(buffer.remaining());
                buffer.put_slice(&data[..length]);
                if length < data.len() {
                    self.buffer = data.slice(length..);
                }
                self.recv
                    .flow_control()
                    .release_capacity(data.len())
                    .map_err(map_io_error)?;
                std::task::Poll::Ready(Ok(()))
            }
            Some(Err(error)) => std::task::Poll::Ready(Err(map_io_error(error))),
            None => std::task::Poll::Ready(Ok(())),
        }
    }
}

impl AsyncWrite for CapsuleStream {
    fn poll_write(
        mut self: std::pin::Pin<&mut Self>,
        context: &mut std::task::Context<'_>,
        buffer: &[u8],
    ) -> std::task::Poll<io::Result<usize>> {
        use futures::ready;

        self.send.reserve_capacity(buffer.len());
        match ready!(self.send.poll_capacity(context)) {
            Some(Ok(capacity)) => {
                let length = capacity.min(buffer.len());
                self.send
                    .send_data(Bytes::copy_from_slice(&buffer[..length]), false)
                    .map_err(map_io_error)?;
                std::task::Poll::Ready(Ok(length))
            }
            Some(Err(error)) => std::task::Poll::Ready(Err(map_io_error(error))),
            None => std::task::Poll::Ready(Err(io::Error::new(
                io::ErrorKind::BrokenPipe,
                "MASQUE HTTP/2 request body closed",
            ))),
        }
    }

    fn poll_flush(
        self: std::pin::Pin<&mut Self>,
        _context: &mut std::task::Context<'_>,
    ) -> std::task::Poll<io::Result<()>> {
        std::task::Poll::Ready(Ok(()))
    }

    fn poll_shutdown(
        mut self: std::pin::Pin<&mut Self>,
        context: &mut std::task::Context<'_>,
    ) -> std::task::Poll<io::Result<()>> {
        use futures::ready;

        self.send.reserve_capacity(0);
        match ready!(self.send.poll_capacity(context)) {
            Some(Ok(_)) => {
                self.send
                    .send_data(Bytes::new(), true)
                    .map_err(map_io_error)?;
                std::task::Poll::Ready(Ok(()))
            }
            Some(Err(error)) => std::task::Poll::Ready(Err(map_io_error(error))),
            None => std::task::Poll::Ready(Ok(())),
        }
    }
}

#[cfg(test)]
mod tests {
    use std::{net::Ipv4Addr, sync::Arc, time::Duration};

    use bytes::{Buf, Bytes};
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    use super::{
        MasqueNetwork, MasqueTlsClient, encode_varint, ipv4_checksum,
        open_h3_tunnel, prepare_outgoing_packet, read_varint,
        validate_incoming_packet,
    };
    use crate::{
        app::dns::SystemResolver, common::tls::resolve_server_cert_and_key,
        proxy::utils::DirectConnector, session::Session,
    };

    const PRIVATE_KEY: &str = "MHcCAQEEILI1eOtnbEIh89Fj4yNDuFR6UjayCKI3NdLl3DhetimWoAoGCCqGSM49AwEHoUQDQgAEgyXrE8v+hHsHy3ewSb3WcRjYgCrM9T9hiE0Uv6k2DZ1+4kefrDT9v1Q/8wdRigTf6t6gGNUV8W+IUMdrfUt+9g==";
    const PUBLIC_KEY: &str = "MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEIaU7MToJm9NKp8YfGxR6r+/\
         h4mcG7SxI8tsW8OR1A5tv/zCzVbCRRh2t87/kxnP6lAy0lkr7qYwu+ox+k3dr6w==";

    #[test]
    fn accepts_mihomo_cloudflare_access_key_format() {
        crate::tests::initialize();
        MasqueTlsClient::new(
            PRIVATE_KEY,
            PUBLIC_KEY,
            "consumer-masque.cloudflareclient.com".to_owned(),
            false,
            MasqueNetwork::H3,
        )
        .unwrap();
    }

    #[tokio::test]
    async fn http3_connect_ip_tunnel_roundtrips_capsule_bytes() {
        crate::tests::initialize();
        let (certs, key) =
            resolve_server_cert_and_key(None, None, "masque-test").unwrap();
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
            let mut builder = h3::server::builder();
            builder.enable_extended_connect(true);
            let mut server = builder.build::<_, Bytes>(h3_connection).await.unwrap();
            use h3::server::RequestResolver;
            let resolver: RequestResolver<_, _> =
                server.accept().await.unwrap().unwrap();
            let (request, mut stream) = resolver.resolve_request().await.unwrap();
            assert_eq!(request.method(), http::Method::CONNECT);
            assert_eq!(request.version(), http::Version::HTTP_3);
            assert_eq!(request.headers()["cf-connect-proto"], "cf-connect-ip");
            stream
                .send_response(
                    http::Response::builder().status(200).body(()).unwrap(),
                )
                .await
                .unwrap();
            while let Some(mut data) = stream.recv_data().await.unwrap() {
                let length = data.remaining();
                stream.send_data(data.copy_to_bytes(length)).await.unwrap();
            }
            let _ = stream.finish().await;
        });

        let tls = MasqueTlsClient::new(
            PRIVATE_KEY,
            PUBLIC_KEY,
            "localhost".to_owned(),
            true,
            MasqueNetwork::H3,
        )
        .unwrap();
        let resolver = Arc::new(SystemResolver::new(false).unwrap());
        let mut stream = tokio::time::timeout(
            Duration::from_secs(3),
            open_h3_tunnel(
                &DirectConnector::new(),
                resolver,
                &Session::default(),
                "127.0.0.1",
                server_addr.port(),
                &"https://cloudflareaccess.com".parse().unwrap(),
                &tls,
            ),
        )
        .await
        .expect("MASQUE H3 handshake timed out")
        .unwrap();
        stream.write_all(b"capsule").await.unwrap();
        let mut response = [0u8; 7];
        tokio::time::timeout(
            Duration::from_secs(2),
            stream.read_exact(&mut response),
        )
        .await
        .expect("MASQUE H3 echo timed out")
        .unwrap();
        assert_eq!(&response, b"capsule");
        drop(stream);
        tokio::time::timeout(Duration::from_secs(2), server)
            .await
            .expect("MASQUE H3 server timed out")
            .unwrap();
    }

    #[tokio::test]
    async fn quic_varint_round_trip_covers_all_lengths() {
        for value in [0, 63, 64, 16_383, 16_384, 1_073_741_823, 1_073_741_824] {
            let encoded = encode_varint(value).unwrap();
            let (mut writer, mut reader) = tokio::io::duplex(16);
            writer.write_all(&encoded).await.unwrap();
            assert_eq!(read_varint(&mut reader).await.unwrap(), value);
        }
    }

    #[test]
    fn outgoing_ipv4_packet_decrements_ttl_and_repairs_checksum() {
        let mut packet = vec![0u8; 20];
        packet[0] = 0x45;
        packet[2..4].copy_from_slice(&20u16.to_be_bytes());
        packet[8] = 64;
        packet[9] = 6;
        packet[12..16].copy_from_slice(&[10, 0, 0, 1]);
        packet[16..20].copy_from_slice(&[1, 1, 1, 1]);
        prepare_outgoing_packet(&mut packet).unwrap();
        assert_eq!(packet[8], 63);
        assert_eq!(ipv4_checksum(&packet), 0);
        validate_incoming_packet(&packet).unwrap();
    }

    #[test]
    fn malformed_ip_packets_are_rejected() {
        assert!(validate_incoming_packet(&[]).is_err());
        assert!(validate_incoming_packet(&[0x45; 19]).is_err());
        assert!(validate_incoming_packet(&[0x60; 39]).is_err());
    }
}
