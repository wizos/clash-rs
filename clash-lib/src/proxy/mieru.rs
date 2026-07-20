use std::{
    collections::{BTreeMap, HashMap},
    fmt::Debug,
    future::Future,
    io,
    net::IpAddr,
    pin::Pin,
    sync::{
        Arc, Weak,
        atomic::{AtomicBool, Ordering},
    },
    task::{Context, Poll},
    time::{Duration, Instant},
};

use ::mieru::{
    MieruOutbound, MieruTcpStream,
    crypto::{
        MieruCipher, NonceConfig, NoncePattern as MieruNoncePattern, derive_key,
    },
    metadata::{
        ACK_CLIENT_TO_SERVER, ACK_SERVER_TO_CLIENT, CLOSE_SESSION_REQUEST,
        CLOSE_SESSION_RESPONSE, DATA_CLIENT_TO_SERVER, DATA_SERVER_TO_CLIENT,
        DataMetadata, METADATA_LEN, OPEN_SESSION_REQUEST, OPEN_SESSION_RESPONSE,
        SessionMetadata,
    },
    segment::{
        MAX_FRAGMENT, build_data_segment, build_session_segment, parse_segment,
    },
    session::MieruSession as ProtocolSession,
    udp::MieruUdpFlowCodec,
};
use async_trait::async_trait;
use base64::{Engine as _, engine::general_purpose::STANDARD as BASE64};
use chacha20poly1305::{
    XChaCha20Poly1305, XNonce,
    aead::{Aead, KeyInit},
};
use erased_serde::Serialize as ErasedSerialize;
use futures::{Sink, SinkExt, Stream, StreamExt, ready};
use prost::Message;
use sha2::{Digest, Sha256};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, ReadBuf};
use tokio_util::sync::PollSender;
use tracing::debug;
use zero_core::{Address as MieruAddress, Error as MieruError};
use zero_traits::AsyncSocket;

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
        AnyOutboundDatagram, AnyStream, ConnectorType, DialWithConnector,
        HandlerCommonOptions, OutboundHandler, OutboundType, PlainProxyAPIResponse,
        datagram::UdpPacket,
        utils::{GLOBAL_DIRECT_CONNECTOR, RemoteConnector},
    },
    session::{Session, SocksAddr},
};

pub struct HandlerOptions {
    pub name: String,
    pub common_opts: HandlerCommonOptions,
    pub server: String,
    pub port: u16,
    pub port_range: Option<String>,
    pub transport: String,
    pub udp: bool,
    pub username: String,
    pub password: String,
    pub multiplexing: Option<String>,
    pub handshake_mode: Option<String>,
    pub traffic_pattern: Option<String>,
}

pub struct Handler {
    opts: HandlerOptions,
    port_range: Option<(u16, u16)>,
    transport: MieruTransport,
    multiplex_factor: u8,
    handshake_mode: MieruHandshakeMode,
    traffic_pattern: TrafficPattern,
    connector: tokio::sync::RwLock<Option<Arc<dyn RemoteConnector>>>,
    mux_pool: tokio::sync::Mutex<Vec<Weak<MieruMuxConnection>>>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum MieruHandshakeMode {
    Standard,
    NoWait,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum MieruTransport {
    Tcp,
    Udp,
}

#[derive(Clone, Debug, Default)]
struct TrafficPattern {
    tcp_fragment: Option<TcpFragment>,
    nonce: MieruNoncePattern,
    apply_nonce_to_all_udp_packets: bool,
}

#[derive(Clone, Copy, Debug)]
struct TcpFragment {
    max_sleep_ms: u64,
}

#[derive(Clone, PartialEq, Message)]
struct TrafficPatternProto {
    #[prost(int32, optional, tag = "1")]
    seed: Option<i32>,
    #[prost(bool, optional, tag = "2")]
    unlock_all: Option<bool>,
    #[prost(message, optional, tag = "3")]
    tcp_fragment: Option<TcpFragmentProto>,
    #[prost(message, optional, tag = "4")]
    nonce: Option<NoncePatternProto>,
}

#[derive(Clone, PartialEq, Message)]
struct TcpFragmentProto {
    #[prost(bool, optional, tag = "1")]
    enable: Option<bool>,
    #[prost(int32, optional, tag = "2")]
    max_sleep_ms: Option<i32>,
}

#[derive(Clone, PartialEq, Message)]
struct NoncePatternProto {
    #[prost(enumeration = "NonceTypeProto", optional, tag = "1")]
    kind: Option<i32>,
    #[prost(bool, optional, tag = "2")]
    apply_to_all_udp_packet: Option<bool>,
    #[prost(int32, optional, tag = "3")]
    min_len: Option<i32>,
    #[prost(int32, optional, tag = "4")]
    max_len: Option<i32>,
    #[prost(string, repeated, tag = "5")]
    custom_hex_strings: Vec<String>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, prost::Enumeration)]
#[repr(i32)]
enum NonceTypeProto {
    Random          = 0,
    Printable       = 1,
    PrintableSubset = 2,
    Fixed           = 3,
}

impl Handler {
    pub fn new(opts: HandlerOptions) -> Result<Self, Error> {
        if opts.name.is_empty()
            || opts.server.is_empty()
            || opts.username.is_empty()
            || opts.password.is_empty()
        {
            return Err(Error::InvalidConfig(
                "mieru requires name, server, username and password".to_owned(),
            ));
        }
        let port_range = match (opts.port, opts.port_range.as_deref()) {
            (0, None | Some("")) => {
                return Err(Error::InvalidConfig(
                    "mieru requires either port or port-range".to_owned(),
                ));
            }
            (port, Some(range)) if port != 0 && !range.is_empty() => {
                return Err(Error::InvalidConfig(
                    "mieru port and port-range cannot be set together".to_owned(),
                ));
            }
            (0, Some(range)) => Some(parse_port_range(range)?),
            _ => None,
        };
        let transport = parse_transport(&opts.transport)?;
        let multiplex_factor = parse_multiplexing(opts.multiplexing.as_deref())?;
        let handshake_mode = parse_handshake_mode(opts.handshake_mode.as_deref())?;
        let traffic_pattern =
            parse_traffic_pattern(opts.traffic_pattern.as_deref())?;

        Ok(Self {
            opts,
            port_range,
            transport,
            multiplex_factor,
            handshake_mode,
            traffic_pattern,
            connector: Default::default(),
            mux_pool: Default::default(),
        })
    }

    fn select_port(&self) -> u16 {
        self.port_range
            .map(|(start, end)| rand::random_range(start..=end))
            .unwrap_or(self.opts.port)
    }

    async fn open_raw_stream(
        &self,
        connector: &dyn RemoteConnector,
        sess: &Session,
        resolver: ThreadSafeDNSResolver,
    ) -> io::Result<MieruSocket> {
        connector
            .connect_stream(
                resolver,
                &self.opts.server,
                self.select_port(),
                sess.iface.as_ref(),
                #[cfg(target_os = "linux")]
                sess.so_mark,
            )
            .await
            .map(|stream| {
                MieruSocket::new(stream, self.traffic_pattern.tcp_fragment)
            })
    }

    async fn open_raw_datagram(
        &self,
        connector: &dyn RemoteConnector,
        sess: &Session,
        resolver: ThreadSafeDNSResolver,
    ) -> io::Result<(AnyOutboundDatagram, SocksAddr)> {
        let port = self.select_port();
        let destination = self
            .opts
            .server
            .parse::<IpAddr>()
            .map(|ip| SocksAddr::Ip((ip, port).into()))
            .unwrap_or_else(|_| SocksAddr::Domain(self.opts.server.clone(), port));
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
        Ok((datagram, destination))
    }

    async fn open_tcp_tunnel(
        &self,
        connector: &dyn RemoteConnector,
        sess: &Session,
        resolver: ThreadSafeDNSResolver,
    ) -> io::Result<AnyStream> {
        let mut stream = self
            .open_protocol_stream(connector, sess, resolver)
            .await
            .map_err(|error| {
                new_io_error(format!("mieru TCP handshake: {error}"))
            })?;
        write_socks_request(&mut stream, 0x01, &sess.destination).await?;
        match self.handshake_mode {
            MieruHandshakeMode::Standard => {
                read_socks_response(&mut stream).await?;
                Ok(stream)
            }
            MieruHandshakeMode::NoWait => Ok(spawn_no_wait_stream(stream)),
        }
    }

    async fn open_udp_tunnel(
        &self,
        connector: &dyn RemoteConnector,
        sess: &Session,
        resolver: ThreadSafeDNSResolver,
    ) -> io::Result<MieruDatagram> {
        let mut stream = self
            .open_protocol_stream(connector, sess, resolver)
            .await
            .map_err(|error| {
                new_io_error(format!("mieru UDP handshake: {error}"))
            })?;
        write_socks_request(
            &mut stream,
            0x03,
            &SocksAddr::Ip(std::net::SocketAddr::from(([0, 0, 0, 0], 0))),
        )
        .await?;
        let wait_for_socks_response = match self.handshake_mode {
            MieruHandshakeMode::Standard => {
                read_socks_response(&mut stream).await?;
                false
            }
            MieruHandshakeMode::NoWait => true,
        };
        Ok(MieruDatagram::new(stream, sess, wait_for_socks_response))
    }

    async fn open_protocol_stream(
        &self,
        connector: &dyn RemoteConnector,
        sess: &Session,
        resolver: ThreadSafeDNSResolver,
    ) -> io::Result<AnyStream> {
        if self.transport == MieruTransport::Tcp && self.multiplex_factor == 0 {
            let raw = self.open_raw_stream(connector, sess, resolver).await?;
            let (raw, outbound) = establish_mieru_session(
                raw,
                &self.opts.username,
                &self.opts.password,
                self.traffic_pattern.nonce,
            )
            .await
            .map_err(|error| new_io_error(format!("mieru handshake: {error}")))?;
            return Ok(Box::new(MieruTcpStream::new(raw, outbound)));
        }

        let existing = if self.multiplex_factor == 0 {
            None
        } else {
            let mut pool = self.mux_pool.lock().await;
            let mut active = Vec::new();
            pool.retain(|weak| {
                weak.upgrade().is_some_and(|connection| {
                    if connection.is_closed() {
                        false
                    } else {
                        active.push(connection);
                        true
                    }
                })
            });
            let reuse_factor = active.len() * self.multiplex_factor as usize;
            if reuse_factor == 0 {
                None
            } else {
                let selected = rand::random_range(0..=reuse_factor);
                (selected < reuse_factor).then(|| {
                    active[selected / self.multiplex_factor as usize].clone()
                })
            }
        };
        if let Some(connection) = existing {
            if let Ok(stream) = connection.open_stream().await {
                return Ok(Box::new(stream));
            }
        }

        let (connection, stream) = match self.transport {
            MieruTransport::Tcp => {
                let raw = self.open_raw_stream(connector, sess, resolver).await?;
                let (raw, outbound) = establish_mieru_session(
                    raw,
                    &self.opts.username,
                    &self.opts.password,
                    self.traffic_pattern.nonce,
                )
                .await
                .map_err(|error| {
                    new_io_error(format!("mieru handshake: {error}"))
                })?;
                MieruMuxConnection::spawn(raw, outbound)
            }
            MieruTransport::Udp => {
                let (raw, destination) =
                    self.open_raw_datagram(connector, sess, resolver).await?;
                let connection = MieruMuxConnection::spawn_packet(
                    raw,
                    destination,
                    mieru_key(&self.opts.username, &self.opts.password)?,
                    self.opts.username.clone(),
                    self.traffic_pattern.nonce,
                    self.traffic_pattern.apply_nonce_to_all_udp_packets,
                );
                let stream = connection.open_stream().await?;
                (connection, stream)
            }
        };
        if self.multiplex_factor > 0 {
            self.mux_pool.lock().await.push(Arc::downgrade(&connection));
        }
        Ok(Box::new(stream))
    }
}

fn parse_transport(value: &str) -> Result<MieruTransport, Error> {
    match value.trim().to_ascii_uppercase().as_str() {
        "TCP" => Ok(MieruTransport::Tcp),
        "UDP" => Ok(MieruTransport::Udp),
        value => Err(Error::InvalidConfig(format!(
            "invalid mieru transport `{value}`; expected TCP or UDP"
        ))),
    }
}

fn mieru_key(username: &str, password: &str) -> io::Result<[u8; 32]> {
    let unix_now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_err(|_| new_io_error("mieru system time is before Unix epoch"))?
        .as_secs();
    Ok(derive_key(username, password, unix_now))
}

fn parse_multiplexing(value: Option<&str>) -> Result<u8, Error> {
    match value.unwrap_or_default().trim() {
        "" | "MULTIPLEXING_DEFAULT" | "MULTIPLEXING_LOW" => Ok(1),
        "MULTIPLEXING_OFF" => Ok(0),
        "MULTIPLEXING_MIDDLE" => Ok(2),
        "MULTIPLEXING_HIGH" => Ok(3),
        value => Err(Error::InvalidConfig(format!(
            "invalid mieru multiplexing level `{value}`"
        ))),
    }
}

fn parse_handshake_mode(value: Option<&str>) -> Result<MieruHandshakeMode, Error> {
    match value.unwrap_or_default().trim() {
        "" | "HANDSHAKE_DEFAULT" | "HANDSHAKE_STANDARD" => {
            Ok(MieruHandshakeMode::Standard)
        }
        "HANDSHAKE_NO_WAIT" => Ok(MieruHandshakeMode::NoWait),
        value => Err(Error::InvalidConfig(format!(
            "invalid mieru handshake-mode `{value}`"
        ))),
    }
}

fn parse_traffic_pattern(value: Option<&str>) -> Result<TrafficPattern, Error> {
    let pattern = if let Some(value) = value.filter(|value| !value.trim().is_empty())
    {
        let bytes = BASE64.decode(value.trim()).map_err(|error| {
            Error::InvalidConfig(format!(
                "failed to decode mieru traffic-pattern: {error}"
            ))
        })?;
        TrafficPatternProto::decode(bytes.as_slice()).map_err(|error| {
            Error::InvalidConfig(format!(
                "failed to decode mieru traffic-pattern protobuf: {error}"
            ))
        })?
    } else {
        TrafficPatternProto::default()
    };
    // Upstream derives a host/version-specific seed when it is omitted. The
    // exact value is deliberately local to the client and does not affect
    // interoperability, so use a process-local random value here. Explicit
    // seeds use the exact upstream SHA-256 keyed derivation below.
    let seed = pattern.seed.unwrap_or_else(rand::random);
    let unlock_all = pattern.unlock_all.unwrap_or(false);
    let fragment = pattern.tcp_fragment.unwrap_or_default();
    let fragment_enabled = fragment.enable.unwrap_or_else(|| {
        unlock_all && fixed_int(2, &format!("{seed}:tcpFragment.enable")) == 1
    });
    let max_sleep_ms = fragment.max_sleep_ms.unwrap_or_else(|| {
        if unlock_all {
            fixed_int(100, &format!("{seed}:tcpFragment.maxSleepMs")) as i32 + 1
        } else {
            0
        }
    });
    if !(0..=100).contains(&max_sleep_ms) {
        return Err(Error::InvalidConfig(format!(
            "mieru TCPFragment maxSleepMs {max_sleep_ms} must be between 0 and 100"
        )));
    }
    let tcp_fragment = fragment_enabled.then_some(TcpFragment {
        max_sleep_ms: max_sleep_ms as u64,
    });

    let (nonce, apply_nonce_to_all_udp_packets) =
        parse_nonce_pattern(pattern.nonce.unwrap_or_default(), seed, unlock_all)?;
    Ok(TrafficPattern {
        tcp_fragment,
        nonce,
        apply_nonce_to_all_udp_packets,
    })
}

fn fixed_int(limit: usize, hint: &str) -> usize {
    if limit == 0 {
        return 0;
    }
    let mut digest = Sha256::digest(hint.as_bytes());
    digest[0] &= 0x7f;
    let value = u32::from_be_bytes(digest[..4].try_into().unwrap()) as usize;
    value % limit
}

fn implicit_nonce_kind(seed: i32, unlock_all: bool) -> NonceTypeProto {
    let offset = usize::from(!unlock_all);
    match fixed_int(
        if unlock_all { 3 } else { 2 },
        &format!("{seed}:nonce.type"),
    ) + offset
    {
        0 => NonceTypeProto::Random,
        1 => NonceTypeProto::Printable,
        _ => NonceTypeProto::PrintableSubset,
    }
}

fn parse_nonce_pattern(
    nonce: NoncePatternProto,
    seed: i32,
    unlock_all: bool,
) -> Result<(MieruNoncePattern, bool), Error> {
    let apply_to_all_udp_packets =
        nonce.apply_to_all_udp_packet.unwrap_or_else(|| {
            fixed_int(2, &format!("{seed}:nonce.applyToAllUDPPacket")) == 1
        });
    let min_len = nonce.min_len.unwrap_or_else(|| {
        if unlock_all {
            fixed_int(13, &format!("{seed}:nonce.minLen")) as i32
        } else {
            fixed_int(7, &format!("{seed}:nonce.minLen")) as i32 + 6
        }
    });
    let max_len = nonce.max_len.unwrap_or_else(|| {
        min_len
            + fixed_int((13 - min_len) as usize, &format!("{seed}:nonce.maxLen"))
                as i32
    });
    if !(0..=12).contains(&min_len)
        || !(0..=12).contains(&max_len)
        || min_len > max_len
    {
        return Err(Error::InvalidConfig(format!(
            "mieru NoncePattern length range {min_len}-{max_len} is invalid"
        )));
    }
    let kind = match nonce.kind {
        Some(kind) => NonceTypeProto::try_from(kind).map_err(|_| {
            Error::InvalidConfig(format!("invalid mieru NoncePattern type {kind}"))
        })?,
        None => implicit_nonce_kind(seed, unlock_all),
    };
    let pattern = match kind {
        NonceTypeProto::Random => MieruNoncePattern::Random,
        NonceTypeProto::Printable => MieruNoncePattern::Printable {
            min_len: min_len as usize,
            max_len: zero_nonce_exclusive_max(min_len, max_len),
        },
        NonceTypeProto::PrintableSubset => MieruNoncePattern::PrintableSubset {
            min_len: min_len as usize,
            max_len: zero_nonce_exclusive_max(min_len, max_len),
        },
        NonceTypeProto::Fixed => {
            let mut values = Vec::with_capacity(nonce.custom_hex_strings.len());
            for value in nonce.custom_hex_strings {
                let decoded = hex::decode(&value).map_err(|error| {
                    Error::InvalidConfig(format!(
                        "invalid mieru fixed nonce `{value}`: {error}"
                    ))
                })?;
                if decoded.len() > 12 {
                    return Err(Error::InvalidConfig(format!(
                        "mieru fixed nonce `{value}` exceeds 12 bytes"
                    )));
                }
                values.push(Box::leak(value.into_boxed_str()) as &'static str);
            }
            let values = Box::leak(values.into_boxed_slice());
            MieruNoncePattern::Fixed {
                hex_strings: values,
            }
        }
    };
    Ok((pattern, apply_to_all_udp_packets))
}

fn zero_nonce_exclusive_max(min_len: i32, max_len: i32) -> usize {
    // Mieru specifies an inclusive [min,max] range. The pinned zero codec
    // samples `[min,max)` unless both ends are equal, so compensate at the
    // integration boundary without forking its entire protocol crate.
    (max_len + i32::from(max_len > min_len)) as usize
}

async fn establish_mieru_session(
    mut stream: MieruSocket,
    username: &str,
    password: &str,
    nonce_pattern: MieruNoncePattern,
) -> Result<(MieruSocket, MieruOutbound), MieruError> {
    let unix_now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_err(|_| MieruError::Protocol("mieru: time"))?
        .as_secs();
    let key = derive_key(username, password, unix_now);
    let client_nonce = NonceConfig {
        pattern: nonce_pattern,
        username: Some(username.to_owned()),
    };
    let server_nonce = NonceConfig {
        username: Some(username.to_owned()),
        ..Default::default()
    };
    let mut client_cipher = MieruCipher::with_config(&key, &client_nonce);
    let mut server_cipher = MieruCipher::with_config(&key, &server_nonce);
    let session = ProtocolSession::new();
    let open_meta = SessionMetadata {
        protocol_type: OPEN_SESSION_REQUEST,
        timestamp: ProtocolSession::timestamp_minutes(),
        session_id: session.session_id,
        sequence_number: 0,
        status_code: 0,
        payload_length: 0,
        suffix_length: 0,
    };
    let open = build_session_segment(&open_meta, &[], &mut client_cipher, true)?;
    AsyncSocket::write_all(&mut stream, &open)
        .await
        .map_err(|_| MieruError::Io("mieru: send open"))?;

    const CORE_LEN: usize = 24 + METADATA_LEN + 16;
    let mut response = vec![0u8; CORE_LEN];
    read_mieru_exact(&mut stream, &mut response).await?;
    let (segment, _) = parse_segment(&response, &mut server_cipher, true, true)?;
    let metadata = segment
        .session_meta
        .ok_or(MieruError::Protocol("mieru: expected session meta"))?;
    if metadata.protocol_type != OPEN_SESSION_RESPONSE {
        return Err(MieruError::Protocol("mieru: unexpected response"));
    }
    if metadata.suffix_length > 0 {
        let mut suffix = vec![0u8; metadata.suffix_length as usize];
        read_mieru_exact(&mut stream, &mut suffix).await?;
    }
    Ok((
        stream,
        MieruOutbound {
            mieru_session: session,
            client_cipher,
            server_cipher,
            c2s_nonce_sent: true,
            s2c_nonce_recv: true,
        },
    ))
}

async fn read_mieru_exact<S: AsyncSocket>(
    stream: &mut S,
    buffer: &mut [u8],
) -> Result<(), MieruError> {
    let mut offset = 0;
    while offset < buffer.len() {
        let size = stream
            .read(&mut buffer[offset..])
            .await
            .map_err(|_| MieruError::Io("mieru: read"))?;
        if size == 0 {
            return Err(MieruError::Protocol("mieru: connection closed"));
        }
        offset += size;
    }
    Ok(())
}

async fn write_socks_request<S>(
    stream: &mut S,
    command: u8,
    destination: &SocksAddr,
) -> io::Result<()>
where
    S: AsyncWrite + Unpin,
{
    let mut request = vec![0x05, command, 0x00];
    match destination {
        SocksAddr::Ip(address) => match address.ip() {
            IpAddr::V4(ip) => {
                request.push(0x01);
                request.extend_from_slice(&ip.octets());
            }
            IpAddr::V6(ip) => {
                request.push(0x04);
                request.extend_from_slice(&ip.octets());
            }
        },
        SocksAddr::Domain(host, _) => {
            let length = u8::try_from(host.len()).map_err(|_| {
                new_io_error("mieru SOCKS5 domain exceeds 255 bytes")
            })?;
            request.extend_from_slice(&[0x03, length]);
            request.extend_from_slice(host.as_bytes());
        }
    }
    request.extend_from_slice(&destination.port().to_be_bytes());
    stream.write_all(&request).await?;
    stream.flush().await
}

async fn read_socks_response<S>(stream: &mut S) -> io::Result<()>
where
    S: AsyncRead + Unpin,
{
    let mut header = [0u8; 4];
    stream.read_exact(&mut header).await?;
    if header[0] != 0x05 || header[1] != 0x00 {
        return Err(new_io_error(format!(
            "mieru SOCKS5 CONNECT failed with reply {}",
            header[1]
        )));
    }
    let length = match header[3] {
        0x01 => 4,
        0x04 => 16,
        0x03 => {
            let mut length = [0u8; 1];
            stream.read_exact(&mut length).await?;
            length[0] as usize
        }
        value => {
            return Err(new_io_error(format!(
                "mieru SOCKS5 returned invalid address type {value}"
            )));
        }
    };
    let mut address_and_port = vec![0u8; length + 2];
    stream.read_exact(&mut address_and_port).await?;
    Ok(())
}

fn spawn_no_wait_stream<S>(stream: S) -> AnyStream
where
    S: AsyncRead + AsyncWrite + Send + Unpin + 'static,
{
    let (application, worker) = tokio::io::duplex(64 * 1024);
    let (mut application_reader, mut application_writer) = tokio::io::split(worker);
    let (mut remote_reader, mut remote_writer) = tokio::io::split(stream);
    tokio::spawn(async move {
        if let Err(error) =
            tokio::io::copy(&mut application_reader, &mut remote_writer).await
        {
            debug!("mieru HANDSHAKE_NO_WAIT upload stopped: {error}");
        }
        let _ = remote_writer.shutdown().await;
    });
    tokio::spawn(async move {
        let result = async {
            read_socks_response(&mut remote_reader).await?;
            tokio::io::copy(&mut remote_reader, &mut application_writer).await?;
            Ok::<_, io::Error>(())
        }
        .await;
        if let Err(error) = result {
            debug!("mieru HANDSHAKE_NO_WAIT download stopped: {error}");
        }
        let _ = application_writer.shutdown().await;
    });
    Box::new(application)
}

fn parse_port_range(value: &str) -> Result<(u16, u16), Error> {
    let (start, end) = value.split_once('-').ok_or_else(|| {
        Error::InvalidConfig(format!("invalid mieru port-range `{value}`"))
    })?;
    if end.contains('-') {
        return Err(Error::InvalidConfig(format!(
            "invalid mieru port-range `{value}`"
        )));
    }
    let start = start.parse::<u16>().map_err(|_| {
        Error::InvalidConfig(format!("invalid mieru port-range `{value}`"))
    })?;
    let end = end.parse::<u16>().map_err(|_| {
        Error::InvalidConfig(format!("invalid mieru port-range `{value}`"))
    })?;
    if start == 0 || end == 0 || start > end {
        return Err(Error::InvalidConfig(format!(
            "invalid mieru port-range `{value}`"
        )));
    }
    Ok((start, end))
}

impl_default_connector!(Handler);

impl Debug for Handler {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("Mieru")
            .field("name", &self.opts.name)
            .field("transport", &self.opts.transport)
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
        OutboundType::Mieru
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
        match self.transport {
            MieruTransport::Tcp => ConnectorType::Tcp,
            MieruTransport::Udp => ConnectorType::All,
        }
    }

    async fn connect_stream_with_connector(
        &self,
        sess: &Session,
        resolver: ThreadSafeDNSResolver,
        connector: &dyn RemoteConnector,
    ) -> io::Result<BoxedChainedStream> {
        let stream = self.open_tcp_tunnel(connector, sess, resolver).await?;
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
            return Err(new_io_error("mieru UDP is disabled"));
        }
        let datagram = self.open_udp_tunnel(connector, sess, resolver).await?;
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
            (
                "port-range".to_owned(),
                Box::new(self.opts.port_range.clone()) as _,
            ),
            ("udp".to_owned(), Box::new(self.opts.udp) as _),
            (
                "multiplexing".to_owned(),
                Box::new(self.opts.multiplexing.clone()) as _,
            ),
            (
                "multiplexing-factor".to_owned(),
                Box::new(self.multiplex_factor) as _,
            ),
            (
                "handshake-mode".to_owned(),
                Box::new(self.opts.handshake_mode.clone()) as _,
            ),
            (
                "traffic-pattern".to_owned(),
                Box::new(self.opts.traffic_pattern.clone()) as _,
            ),
        ])
    }
}

struct MieruMuxConnection {
    commands: tokio::sync::mpsc::Sender<MieruMuxCommand>,
    closed: Arc<AtomicBool>,
}

impl MieruMuxConnection {
    fn spawn(
        raw: MieruSocket,
        outbound: MieruOutbound,
    ) -> (Arc<Self>, MieruMuxStream) {
        let initial_session_id = outbound.mieru_session.session_id;
        let (commands, command_rx) = tokio::sync::mpsc::channel(64);
        let (payload_tx, payload_rx) = tokio::sync::mpsc::channel(32);
        let closed = Arc::new(AtomicBool::new(false));
        let connection = Arc::new(Self {
            commands,
            closed: closed.clone(),
        });
        tokio::spawn(run_mieru_mux_driver(
            raw,
            outbound,
            command_rx,
            initial_session_id,
            payload_tx,
            closed,
        ));
        let stream =
            MieruMuxStream::new(connection.clone(), initial_session_id, payload_rx);
        (connection, stream)
    }

    fn spawn_packet(
        raw: AnyOutboundDatagram,
        destination: SocksAddr,
        key: [u8; 32],
        username: String,
        nonce_pattern: MieruNoncePattern,
        apply_nonce_to_all_packets: bool,
    ) -> Arc<Self> {
        Self::spawn_packet_with_config(
            raw,
            destination,
            key,
            username,
            nonce_pattern,
            apply_nonce_to_all_packets,
            MieruPacketDriverConfig::default(),
        )
    }

    fn spawn_packet_with_config(
        raw: AnyOutboundDatagram,
        destination: SocksAddr,
        key: [u8; 32],
        username: String,
        nonce_pattern: MieruNoncePattern,
        apply_nonce_to_all_packets: bool,
        config: MieruPacketDriverConfig,
    ) -> Arc<Self> {
        let (commands, command_rx) = tokio::sync::mpsc::channel(64);
        let closed = Arc::new(AtomicBool::new(false));
        let connection = Arc::new(Self {
            commands,
            closed: closed.clone(),
        });
        tokio::spawn(run_mieru_packet_driver(
            raw,
            destination,
            MieruPacketCipher::new(
                key,
                username,
                nonce_pattern,
                apply_nonce_to_all_packets,
            ),
            command_rx,
            closed,
            config,
        ));
        connection
    }

    fn is_closed(&self) -> bool {
        self.closed.load(Ordering::Acquire)
    }

    async fn open_stream(self: &Arc<Self>) -> io::Result<MieruMuxStream> {
        if self.is_closed() {
            return Err(new_io_error("mieru multiplexed connection is closed"));
        }
        let (payload_tx, payload_rx) = tokio::sync::mpsc::channel(32);
        let (response_tx, response_rx) = tokio::sync::oneshot::channel();
        self.commands
            .send(MieruMuxCommand::Open {
                payload_tx,
                response: response_tx,
            })
            .await
            .map_err(|_| new_io_error("mieru multiplexed connection is closed"))?;
        let session_id = response_rx
            .await
            .map_err(|_| new_io_error("mieru multiplexed open was cancelled"))??;
        Ok(MieruMuxStream::new(self.clone(), session_id, payload_rx))
    }
}

enum MieruMuxCommand {
    Open {
        payload_tx: tokio::sync::mpsc::Sender<Vec<u8>>,
        response: tokio::sync::oneshot::Sender<io::Result<u32>>,
    },
    Data {
        session_id: u32,
        payload: Vec<u8>,
        written: tokio::sync::oneshot::Sender<io::Result<()>>,
    },
    Close {
        session_id: u32,
    },
}

struct MieruMuxSession {
    payload_tx: tokio::sync::mpsc::Sender<Vec<u8>>,
    open_response: Option<tokio::sync::oneshot::Sender<io::Result<u32>>>,
    send_sequence: u32,
}

async fn run_mieru_mux_driver(
    mut raw: MieruSocket,
    mut outbound: MieruOutbound,
    mut commands: tokio::sync::mpsc::Receiver<MieruMuxCommand>,
    initial_session_id: u32,
    initial_payload_tx: tokio::sync::mpsc::Sender<Vec<u8>>,
    closed: Arc<AtomicBool>,
) {
    let mut sessions = HashMap::from([(
        initial_session_id,
        MieruMuxSession {
            payload_tx: initial_payload_tx,
            open_response: None,
            send_sequence: 0,
        },
    )]);
    let mut read_buffer = Vec::new();
    let mut scratch = [0u8; 16 * 1024];

    loop {
        let result: io::Result<()> = tokio::select! {
            command = commands.recv() => {
                let Some(command) = command else {
                    break;
                };
                handle_mieru_mux_command(
                    command,
                    &mut raw,
                    &mut outbound,
                    &mut sessions,
                ).await
            }
            read = AsyncReadExt::read(&mut raw, &mut scratch) => {
                match read {
                    Ok(0) => Err(io::Error::from(io::ErrorKind::UnexpectedEof)),
                    Ok(length) => {
                        read_buffer.extend_from_slice(&scratch[..length]);
                        dispatch_mieru_mux_segments(
                            &mut read_buffer,
                            &mut outbound,
                            &mut sessions,
                        ).await
                    }
                    Err(error) => Err(error),
                }
            }
        };
        if let Err(error) = result {
            debug!("mieru multiplexed connection stopped: {error}");
            break;
        }
    }

    closed.store(true, Ordering::Release);
    for (_, mut session) in sessions {
        if let Some(response) = session.open_response.take() {
            let _ = response.send(Err(new_io_error(
                "mieru multiplexed connection closed during open",
            )));
        }
    }
}

async fn handle_mieru_mux_command(
    command: MieruMuxCommand,
    raw: &mut MieruSocket,
    outbound: &mut MieruOutbound,
    sessions: &mut HashMap<u32, MieruMuxSession>,
) -> io::Result<()> {
    match command {
        MieruMuxCommand::Open {
            payload_tx,
            response,
        } => {
            let session_id = unique_mieru_session_id(sessions);
            let metadata = SessionMetadata {
                protocol_type: OPEN_SESSION_REQUEST,
                timestamp: ProtocolSession::timestamp_minutes(),
                session_id,
                sequence_number: 0,
                status_code: 0,
                payload_length: 0,
                suffix_length: 0,
            };
            let wire = build_session_segment(
                &metadata,
                &[],
                &mut outbound.client_cipher,
                false,
            )
            .map_err(|error| new_io_error(format!("mieru mux open: {error}")))?;
            if let Err(error) = AsyncWriteExt::write_all(raw, &wire).await {
                let _ = response.send(Err(copy_io_error(&error)));
                return Err(error);
            }
            raw.flush().await?;
            sessions.insert(
                session_id,
                MieruMuxSession {
                    payload_tx,
                    open_response: Some(response),
                    send_sequence: 0,
                },
            );
        }
        MieruMuxCommand::Data {
            session_id,
            payload,
            written,
        } => {
            let Some(session) = sessions.get_mut(&session_id) else {
                let _ = written
                    .send(Err(new_io_error("mieru multiplexed session is closed")));
                return Ok(());
            };
            for fragment in payload.chunks(MAX_FRAGMENT) {
                let metadata = DataMetadata {
                    protocol_type: DATA_CLIENT_TO_SERVER,
                    timestamp: ProtocolSession::timestamp_minutes(),
                    session_id,
                    sequence_number: session.send_sequence,
                    unack_sequence: 0,
                    window_size: 1024,
                    fragment_number: 0,
                    prefix_length: 0,
                    payload_length: fragment.len() as u16,
                    suffix_length: 0,
                };
                session.send_sequence = session.send_sequence.wrapping_add(1);
                let wire = build_data_segment(
                    &metadata,
                    fragment,
                    &mut outbound.client_cipher,
                    false,
                )
                .map_err(|error| new_io_error(format!("mieru mux data: {error}")))?;
                if let Err(error) = AsyncWriteExt::write_all(raw, &wire).await {
                    let _ = written.send(Err(copy_io_error(&error)));
                    return Err(error);
                }
            }
            if let Err(error) = raw.flush().await {
                let _ = written.send(Err(copy_io_error(&error)));
                return Err(error);
            }
            let _ = written.send(Ok(()));
        }
        MieruMuxCommand::Close { session_id } => {
            let Some(session) = sessions.remove(&session_id) else {
                return Ok(());
            };
            let metadata = SessionMetadata {
                protocol_type: CLOSE_SESSION_REQUEST,
                timestamp: ProtocolSession::timestamp_minutes(),
                session_id,
                sequence_number: session.send_sequence,
                status_code: 0,
                payload_length: 0,
                suffix_length: 0,
            };
            let wire = build_session_segment(
                &metadata,
                &[],
                &mut outbound.client_cipher,
                false,
            )
            .map_err(|error| new_io_error(format!("mieru mux close: {error}")))?;
            AsyncWriteExt::write_all(raw, &wire).await?;
            raw.flush().await?;
        }
    }
    Ok(())
}

async fn dispatch_mieru_mux_segments(
    read_buffer: &mut Vec<u8>,
    outbound: &mut MieruOutbound,
    sessions: &mut HashMap<u32, MieruMuxSession>,
) -> io::Result<()> {
    loop {
        let mut server_cipher = outbound.server_cipher.clone();
        let parsed = parse_segment(read_buffer, &mut server_cipher, false, false);
        let (segment, consumed) = match parsed {
            Ok(value) => value,
            Err(MieruError::Protocol("mieru: need more data")) => return Ok(()),
            Err(error) => {
                return Err(new_io_error(format!("mieru mux decrypt: {error}")));
            }
        };
        outbound.server_cipher = server_cipher;
        read_buffer.drain(..consumed);

        if let Some(metadata) = segment.session_meta {
            if metadata.protocol_type == OPEN_SESSION_RESPONSE {
                let Some(session) = sessions.get_mut(&metadata.session_id) else {
                    continue;
                };
                if let Some(response) = session.open_response.take() {
                    let result = if metadata.status_code == 0 {
                        Ok(metadata.session_id)
                    } else {
                        Err(new_io_error(format!(
                            "mieru multiplexed open failed with status {}",
                            metadata.status_code,
                        )))
                    };
                    let _ = response.send(result);
                }
                if metadata.status_code != 0 {
                    sessions.remove(&metadata.session_id);
                }
            } else if metadata.protocol_type
                == ::mieru::metadata::CLOSE_SESSION_RESPONSE
                || metadata.protocol_type == ::mieru::metadata::CLOSE_SESSION_REQUEST
            {
                sessions.remove(&metadata.session_id);
            }
            continue;
        }
        let Some(metadata) = segment.data_meta else {
            continue;
        };
        if segment.payload.is_empty() {
            continue;
        }
        let Some(payload_tx) = sessions
            .get(&metadata.session_id)
            .map(|session| session.payload_tx.clone())
        else {
            continue;
        };
        if payload_tx.send(segment.payload).await.is_err() {
            sessions.remove(&metadata.session_id);
        }
    }
}

fn unique_mieru_session_id(sessions: &HashMap<u32, MieruMuxSession>) -> u32 {
    loop {
        let session_id = rand::random::<u32>();
        if session_id != 0 && !sessions.contains_key(&session_id) {
            return session_id;
        }
    }
}

fn copy_io_error(error: &io::Error) -> io::Error {
    io::Error::new(error.kind(), error.to_string())
}

const MIERU_PACKET_MTU: usize = 1400;
const MIERU_PACKET_OVERHEAD: usize = 24 + METADATA_LEN + 16 * 2;
const MIERU_PACKET_MAX_PAYLOAD: usize = MIERU_PACKET_MTU - MIERU_PACKET_OVERHEAD;

#[derive(Clone, Copy)]
struct MieruPacketDriverConfig {
    tick_interval: Duration,
    initial_rto: Duration,
    open_timeout: Duration,
    heartbeat_interval: Duration,
    max_retransmissions: u8,
}

impl Default for MieruPacketDriverConfig {
    fn default() -> Self {
        Self {
            tick_interval: Duration::from_millis(10),
            initial_rto: Duration::from_secs(2),
            open_timeout: Duration::from_secs(10),
            heartbeat_interval: Duration::from_secs(5),
            max_retransmissions: 20,
        }
    }
}

#[derive(Clone)]
enum MieruPacketSegment {
    Session {
        metadata: SessionMetadata,
        payload: Vec<u8>,
    },
    Data {
        metadata: DataMetadata,
        payload: Vec<u8>,
    },
}

impl MieruPacketSegment {
    fn session_id(&self) -> u32 {
        match self {
            Self::Session { metadata, .. } => metadata.session_id,
            Self::Data { metadata, .. } => metadata.session_id,
        }
    }

    fn sequence_number(&self) -> u32 {
        match self {
            Self::Session { metadata, .. } => metadata.sequence_number,
            Self::Data { metadata, .. } => metadata.sequence_number,
        }
    }

    fn set_unack_sequence(&mut self, sequence: u32) {
        if let Self::Data { metadata, .. } = self {
            metadata.unack_sequence = sequence;
        }
    }
}

struct MieruPacketCipher {
    key: [u8; 32],
    username: String,
    nonce_pattern: MieruNoncePattern,
    apply_nonce_to_all_packets: bool,
    nonce_pattern_applied: bool,
}

impl MieruPacketCipher {
    fn new(
        key: [u8; 32],
        username: String,
        nonce_pattern: MieruNoncePattern,
        apply_nonce_to_all_packets: bool,
    ) -> Self {
        Self {
            key,
            username,
            nonce_pattern,
            apply_nonce_to_all_packets,
            nonce_pattern_applied: false,
        }
    }

    fn encrypt(&mut self, segment: &MieruPacketSegment) -> io::Result<Vec<u8>> {
        let pattern =
            if self.nonce_pattern_applied && !self.apply_nonce_to_all_packets {
                MieruNoncePattern::Random
            } else {
                self.nonce_pattern
            };
        let generator = MieruCipher::with_config(
            &self.key,
            &NonceConfig {
                pattern,
                username: Some(self.username.clone()),
            },
        );
        let nonce = *generator.current_nonce();
        self.nonce_pattern_applied = true;

        let (metadata, payload, prefix_length, suffix_length) = match segment {
            MieruPacketSegment::Session { metadata, payload } => (
                metadata.encode(),
                payload.as_slice(),
                0usize,
                metadata.suffix_length as usize,
            ),
            MieruPacketSegment::Data { metadata, payload } => (
                metadata.encode(),
                payload.as_slice(),
                metadata.prefix_length as usize,
                metadata.suffix_length as usize,
            ),
        };
        let cipher = XChaCha20Poly1305::new_from_slice(&self.key)
            .map_err(|_| new_io_error("mieru packet key has invalid length"))?;
        let xnonce = XNonce::from_slice(&nonce);
        let encrypted_metadata = cipher
            .encrypt(xnonce, metadata.as_slice())
            .map_err(|_| new_io_error("mieru packet metadata encryption failed"))?;
        let encrypted_payload = if payload.is_empty() {
            Vec::new()
        } else {
            cipher.encrypt(xnonce, payload).map_err(|_| {
                new_io_error("mieru packet payload encryption failed")
            })?
        };
        let mut wire = Vec::with_capacity(
            24 + encrypted_metadata.len()
                + prefix_length
                + encrypted_payload.len()
                + suffix_length,
        );
        wire.extend_from_slice(&nonce);
        wire.extend_from_slice(&encrypted_metadata);
        wire.resize(wire.len() + prefix_length, 0);
        wire.extend_from_slice(&encrypted_payload);
        wire.resize(wire.len() + suffix_length, 0);
        Ok(wire)
    }

    fn decrypt(&self, wire: &[u8]) -> io::Result<MieruPacketSegment> {
        const HEADER_LENGTH: usize = 24 + METADATA_LEN + 16;
        if wire.len() < HEADER_LENGTH {
            return Err(new_io_error("mieru packet is shorter than its header"));
        }
        let nonce = XNonce::from_slice(&wire[..24]);
        let cipher = XChaCha20Poly1305::new_from_slice(&self.key)
            .map_err(|_| new_io_error("mieru packet key has invalid length"))?;
        let metadata =
            cipher
                .decrypt(nonce, &wire[24..HEADER_LENGTH])
                .map_err(|_| {
                    new_io_error("mieru packet metadata authentication failed")
                })?;
        if metadata.len() != METADATA_LEN {
            return Err(new_io_error("mieru packet metadata has invalid length"));
        }

        match metadata[0] {
            OPEN_SESSION_REQUEST
            | OPEN_SESSION_RESPONSE
            | CLOSE_SESSION_REQUEST
            | CLOSE_SESSION_RESPONSE => {
                let metadata = SessionMetadata::decode(&metadata);
                let payload = decrypt_mieru_packet_payload(
                    &cipher,
                    nonce,
                    wire,
                    HEADER_LENGTH,
                    metadata.payload_length as usize,
                    metadata.suffix_length as usize,
                )?;
                Ok(MieruPacketSegment::Session { metadata, payload })
            }
            DATA_CLIENT_TO_SERVER
            | DATA_SERVER_TO_CLIENT
            | ACK_CLIENT_TO_SERVER
            | ACK_SERVER_TO_CLIENT => {
                let metadata = DataMetadata::decode(&metadata);
                let payload_offset = HEADER_LENGTH
                    .checked_add(metadata.prefix_length as usize)
                    .ok_or_else(|| new_io_error("mieru packet length overflow"))?;
                let payload = decrypt_mieru_packet_payload(
                    &cipher,
                    nonce,
                    wire,
                    payload_offset,
                    metadata.payload_length as usize,
                    metadata.suffix_length as usize,
                )?;
                Ok(MieruPacketSegment::Data { metadata, payload })
            }
            protocol => Err(new_io_error(format!(
                "mieru packet has unknown protocol type {protocol}"
            ))),
        }
    }
}

fn decrypt_mieru_packet_payload(
    cipher: &XChaCha20Poly1305,
    nonce: &XNonce,
    wire: &[u8],
    payload_offset: usize,
    payload_length: usize,
    suffix_length: usize,
) -> io::Result<Vec<u8>> {
    let encrypted_length = if payload_length == 0 {
        0
    } else {
        payload_length + 16
    };
    let expected_length = payload_offset
        .checked_add(encrypted_length)
        .and_then(|length| length.checked_add(suffix_length))
        .ok_or_else(|| new_io_error("mieru packet length overflow"))?;
    if wire.len() != expected_length {
        return Err(new_io_error(format!(
            "mieru packet length {} does not match metadata {expected_length}",
            wire.len(),
        )));
    }
    if encrypted_length == 0 {
        return Ok(Vec::new());
    }
    cipher
        .decrypt(
            nonce,
            &wire[payload_offset..payload_offset + encrypted_length],
        )
        .map_err(|_| new_io_error("mieru packet payload authentication failed"))
}

#[derive(Clone)]
struct MieruPendingPacket {
    segment: MieruPacketSegment,
    last_sent: Instant,
    retransmission_timeout: Duration,
    transmission_count: u8,
}

struct MieruPacketSession {
    payload_tx: tokio::sync::mpsc::Sender<Vec<u8>>,
    open_response: Option<tokio::sync::oneshot::Sender<io::Result<u32>>>,
    send_sequence: u32,
    next_receive_sequence: u32,
    receive_buffer: BTreeMap<u32, Vec<u8>>,
    pending: BTreeMap<u32, MieruPendingPacket>,
    opened_at: Instant,
    last_sent: Instant,
    closing: bool,
}

impl MieruPacketSession {
    fn receive_window(&self) -> u16 {
        let available = 4096usize.saturating_sub(self.receive_buffer.len());
        available.clamp(16, u16::MAX as usize) as u16
    }
}

async fn run_mieru_packet_driver(
    mut raw: AnyOutboundDatagram,
    destination: SocksAddr,
    mut cipher: MieruPacketCipher,
    mut commands: tokio::sync::mpsc::Receiver<MieruMuxCommand>,
    closed: Arc<AtomicBool>,
    config: MieruPacketDriverConfig,
) {
    let mut sessions = HashMap::<u32, MieruPacketSession>::new();
    let mut ticker = tokio::time::interval(config.tick_interval);
    ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);

    loop {
        let result = tokio::select! {
            command = commands.recv() => {
                let Some(command) = command else {
                    break;
                };
                handle_mieru_packet_command(
                    command,
                    &mut raw,
                    &destination,
                    &mut cipher,
                    &mut sessions,
                    config,
                ).await
            }
            packet = raw.next() => {
                match packet {
                    Some(packet) => match cipher.decrypt(&packet.data) {
                        Ok(segment) => handle_mieru_packet_input(
                            segment,
                            &mut raw,
                            &destination,
                            &mut cipher,
                            &mut sessions,
                        ).await,
                        Err(error) => {
                            debug!("ignored invalid mieru UDP packet: {error}");
                            Ok(())
                        }
                    },
                    None => Err(new_io_error("mieru UDP underlay closed")),
                }
            }
            _ = ticker.tick() => {
                maintain_mieru_packet_sessions(
                    &mut raw,
                    &destination,
                    &mut cipher,
                    &mut sessions,
                    config,
                ).await
            }
        };
        if let Err(error) = result {
            debug!("mieru UDP underlay stopped: {error}");
            break;
        }
    }

    closed.store(true, Ordering::Release);
    for (_, mut session) in sessions {
        if let Some(response) = session.open_response.take() {
            let _ = response.send(Err(new_io_error(
                "mieru UDP underlay closed during session open",
            )));
        }
    }
}

async fn handle_mieru_packet_command(
    command: MieruMuxCommand,
    raw: &mut AnyOutboundDatagram,
    destination: &SocksAddr,
    cipher: &mut MieruPacketCipher,
    sessions: &mut HashMap<u32, MieruPacketSession>,
    config: MieruPacketDriverConfig,
) -> io::Result<()> {
    match command {
        MieruMuxCommand::Open {
            payload_tx,
            response,
        } => {
            let session_id = unique_mieru_packet_session_id(sessions);
            let segment = MieruPacketSegment::Session {
                metadata: SessionMetadata {
                    protocol_type: OPEN_SESSION_REQUEST,
                    timestamp: ProtocolSession::timestamp_minutes(),
                    session_id,
                    sequence_number: 0,
                    status_code: 0,
                    payload_length: 0,
                    suffix_length: 0,
                },
                payload: Vec::new(),
            };
            let now = Instant::now();
            sessions.insert(
                session_id,
                MieruPacketSession {
                    payload_tx,
                    open_response: Some(response),
                    send_sequence: 1,
                    next_receive_sequence: 0,
                    receive_buffer: BTreeMap::new(),
                    pending: BTreeMap::from([(
                        0,
                        MieruPendingPacket {
                            segment: segment.clone(),
                            last_sent: now,
                            retransmission_timeout: config.initial_rto,
                            transmission_count: 1,
                        },
                    )]),
                    opened_at: now,
                    last_sent: now,
                    closing: false,
                },
            );
            send_mieru_packet(raw, destination, cipher, &segment).await?;
        }
        MieruMuxCommand::Data {
            session_id,
            payload,
            written,
        } => {
            let Some(session) = sessions.get_mut(&session_id) else {
                let _ =
                    written.send(Err(new_io_error("mieru UDP session is closed")));
                return Ok(());
            };
            if session.closing {
                let _ =
                    written.send(Err(new_io_error("mieru UDP session is closing")));
                return Ok(());
            }
            let mut segments = Vec::new();
            for chunk in payload.chunks(MAX_FRAGMENT) {
                let fragment_count = chunk.len().div_ceil(MIERU_PACKET_MAX_PAYLOAD);
                for (index, fragment) in
                    chunk.chunks(MIERU_PACKET_MAX_PAYLOAD).enumerate()
                {
                    let sequence_number = session.send_sequence;
                    session.send_sequence = session.send_sequence.wrapping_add(1);
                    segments.push(MieruPacketSegment::Data {
                        metadata: DataMetadata {
                            protocol_type: DATA_CLIENT_TO_SERVER,
                            timestamp: ProtocolSession::timestamp_minutes(),
                            session_id,
                            sequence_number,
                            unack_sequence: session.next_receive_sequence,
                            window_size: session.receive_window(),
                            fragment_number: (fragment_count - index - 1) as u8,
                            prefix_length: 0,
                            payload_length: fragment.len() as u16,
                            suffix_length: 0,
                        },
                        payload: fragment.to_vec(),
                    });
                }
            }
            let now = Instant::now();
            for segment in segments {
                if let Err(error) =
                    send_mieru_packet(raw, destination, cipher, &segment).await
                {
                    let _ = written.send(Err(copy_io_error(&error)));
                    return Err(error);
                }
                session.pending.insert(
                    segment.sequence_number(),
                    MieruPendingPacket {
                        segment,
                        last_sent: now,
                        retransmission_timeout: config.initial_rto,
                        transmission_count: 1,
                    },
                );
            }
            session.last_sent = now;
            let _ = written.send(Ok(()));
        }
        MieruMuxCommand::Close { session_id } => {
            let Some(session) = sessions.get_mut(&session_id) else {
                return Ok(());
            };
            if session.closing {
                return Ok(());
            }
            session.closing = true;
            let sequence_number = session.send_sequence;
            session.send_sequence = session.send_sequence.wrapping_add(1);
            let segment = MieruPacketSegment::Session {
                metadata: SessionMetadata {
                    protocol_type: CLOSE_SESSION_REQUEST,
                    timestamp: ProtocolSession::timestamp_minutes(),
                    session_id,
                    sequence_number,
                    status_code: 0,
                    payload_length: 0,
                    suffix_length: 0,
                },
                payload: Vec::new(),
            };
            send_mieru_packet(raw, destination, cipher, &segment).await?;
            let now = Instant::now();
            session.pending.insert(
                sequence_number,
                MieruPendingPacket {
                    segment,
                    last_sent: now,
                    retransmission_timeout: config.initial_rto,
                    transmission_count: 1,
                },
            );
            session.last_sent = now;
        }
    }
    Ok(())
}

async fn handle_mieru_packet_input(
    segment: MieruPacketSegment,
    raw: &mut AnyOutboundDatagram,
    destination: &SocksAddr,
    cipher: &mut MieruPacketCipher,
    sessions: &mut HashMap<u32, MieruPacketSession>,
) -> io::Result<()> {
    let session_id = segment.session_id();
    match segment {
        MieruPacketSegment::Session { metadata, payload }
            if metadata.protocol_type == OPEN_SESSION_RESPONSE =>
        {
            let Some(session) = sessions.get_mut(&session_id) else {
                return Ok(());
            };
            let is_new = metadata.sequence_number == session.next_receive_sequence;
            if metadata.sequence_number > session.next_receive_sequence {
                return Ok(());
            }
            if is_new {
                session.next_receive_sequence =
                    session.next_receive_sequence.wrapping_add(1);
                session.pending.remove(&0);
            }
            let response = is_new.then(|| session.open_response.take()).flatten();
            let payload_tx = session.payload_tx.clone();
            let ack = packet_ack(session_id, session);
            let failed = metadata.status_code != 0;
            if let Some(response) = response {
                let result = if failed {
                    Err(new_io_error(format!(
                        "mieru UDP open failed with status {}",
                        metadata.status_code,
                    )))
                } else {
                    Ok(session_id)
                };
                let _ = response.send(result);
            }
            if is_new
                && !payload.is_empty()
                && payload_tx.send(payload).await.is_err()
            {
                sessions.remove(&session_id);
                return Ok(());
            }
            send_mieru_packet(raw, destination, cipher, &ack).await?;
            if failed {
                sessions.remove(&session_id);
            }
        }
        MieruPacketSegment::Session { metadata, .. }
            if metadata.protocol_type == CLOSE_SESSION_REQUEST =>
        {
            let Some(session) = sessions.get(&session_id) else {
                return Ok(());
            };
            let response = MieruPacketSegment::Session {
                metadata: SessionMetadata {
                    protocol_type: CLOSE_SESSION_RESPONSE,
                    timestamp: ProtocolSession::timestamp_minutes(),
                    session_id,
                    sequence_number: session.send_sequence,
                    status_code: 0,
                    payload_length: 0,
                    suffix_length: 0,
                },
                payload: Vec::new(),
            };
            send_mieru_packet(raw, destination, cipher, &response).await?;
            sessions.remove(&session_id);
        }
        MieruPacketSegment::Session { metadata, .. }
            if metadata.protocol_type == CLOSE_SESSION_RESPONSE =>
        {
            sessions.remove(&session_id);
        }
        MieruPacketSegment::Data { metadata, payload }
            if metadata.protocol_type == DATA_SERVER_TO_CLIENT
                || metadata.protocol_type == ACK_SERVER_TO_CLIENT =>
        {
            let Some(session) = sessions.get_mut(&session_id) else {
                return Ok(());
            };
            session
                .pending
                .retain(|sequence, _| *sequence >= metadata.unack_sequence);
            if metadata.protocol_type == ACK_SERVER_TO_CLIENT {
                return Ok(());
            }
            if metadata.sequence_number >= session.next_receive_sequence {
                session
                    .receive_buffer
                    .entry(metadata.sequence_number)
                    .or_insert(payload);
            }
            let payload_tx = session.payload_tx.clone();
            let mut ready_payloads = Vec::new();
            while let Some(payload) = session
                .receive_buffer
                .remove(&session.next_receive_sequence)
            {
                session.next_receive_sequence =
                    session.next_receive_sequence.wrapping_add(1);
                if !payload.is_empty() {
                    ready_payloads.push(payload);
                }
            }
            let ack = packet_ack(session_id, session);
            for payload in ready_payloads {
                if payload_tx.send(payload).await.is_err() {
                    sessions.remove(&session_id);
                    return Ok(());
                }
            }
            send_mieru_packet(raw, destination, cipher, &ack).await?;
        }
        _ => {}
    }
    Ok(())
}

async fn maintain_mieru_packet_sessions(
    raw: &mut AnyOutboundDatagram,
    destination: &SocksAddr,
    cipher: &mut MieruPacketCipher,
    sessions: &mut HashMap<u32, MieruPacketSession>,
    config: MieruPacketDriverConfig,
) -> io::Result<()> {
    let now = Instant::now();
    let mut expired = Vec::new();
    let mut to_send = Vec::new();
    for (&session_id, session) in sessions.iter_mut() {
        if session.open_response.is_some()
            && now.duration_since(session.opened_at) >= config.open_timeout
        {
            expired.push(session_id);
            continue;
        }
        for pending in session.pending.values_mut() {
            if now.duration_since(pending.last_sent) < pending.retransmission_timeout
            {
                continue;
            }
            if pending.transmission_count >= config.max_retransmissions {
                expired.push(session_id);
                break;
            }
            pending
                .segment
                .set_unack_sequence(session.next_receive_sequence);
            pending.last_sent = now;
            pending.transmission_count += 1;
            pending.retransmission_timeout = Duration::from_secs_f64(
                (pending.retransmission_timeout.as_secs_f64() * 1.5).min(10.0),
            );
            to_send.push((session_id, pending.segment.clone()));
        }
        if now.duration_since(session.last_sent) >= config.heartbeat_interval {
            to_send.push((session_id, packet_ack(session_id, session)));
        }
    }
    expired.sort_unstable();
    expired.dedup();
    for session_id in expired {
        if let Some(mut session) = sessions.remove(&session_id) {
            if let Some(response) = session.open_response.take() {
                let _ = response.send(Err(new_io_error(
                    "mieru UDP session establishment timed out",
                )));
            }
        }
    }
    for (session_id, segment) in to_send {
        if !sessions.contains_key(&session_id) {
            continue;
        }
        send_mieru_packet(raw, destination, cipher, &segment).await?;
        if let Some(session) = sessions.get_mut(&session_id) {
            session.last_sent = now;
        }
    }
    Ok(())
}

fn packet_ack(session_id: u32, session: &MieruPacketSession) -> MieruPacketSegment {
    MieruPacketSegment::Data {
        metadata: DataMetadata {
            protocol_type: ACK_CLIENT_TO_SERVER,
            timestamp: ProtocolSession::timestamp_minutes(),
            session_id,
            sequence_number: session.send_sequence.saturating_sub(1),
            unack_sequence: session.next_receive_sequence,
            window_size: session.receive_window(),
            fragment_number: 0,
            prefix_length: 0,
            payload_length: 0,
            suffix_length: 0,
        },
        payload: Vec::new(),
    }
}

async fn send_mieru_packet(
    raw: &mut AnyOutboundDatagram,
    destination: &SocksAddr,
    cipher: &mut MieruPacketCipher,
    segment: &MieruPacketSegment,
) -> io::Result<()> {
    raw.send(UdpPacket {
        data: cipher.encrypt(segment)?,
        src_addr: SocksAddr::any_ipv4(),
        dst_addr: destination.clone(),
        inbound_user: None,
    })
    .await
}

fn unique_mieru_packet_session_id(
    sessions: &HashMap<u32, MieruPacketSession>,
) -> u32 {
    loop {
        let session_id = rand::random::<u32>();
        if session_id != 0 && !sessions.contains_key(&session_id) {
            return session_id;
        }
    }
}

struct MieruMuxStream {
    connection: Arc<MieruMuxConnection>,
    session_id: u32,
    send_tx: PollSender<MieruMuxCommand>,
    recv_rx: tokio::sync::mpsc::Receiver<Vec<u8>>,
    read_buffer: Vec<u8>,
    read_position: usize,
    pending_write: Option<(usize, tokio::sync::oneshot::Receiver<io::Result<()>>)>,
    close_sent: bool,
}

impl MieruMuxStream {
    fn new(
        connection: Arc<MieruMuxConnection>,
        session_id: u32,
        recv_rx: tokio::sync::mpsc::Receiver<Vec<u8>>,
    ) -> Self {
        Self {
            send_tx: PollSender::new(connection.commands.clone()),
            connection,
            session_id,
            recv_rx,
            read_buffer: Vec::new(),
            read_position: 0,
            pending_write: None,
            close_sent: false,
        }
    }

    fn poll_pending_write(
        &mut self,
        cx: &mut Context<'_>,
    ) -> Poll<io::Result<Option<usize>>> {
        let Some((length, response)) = self.pending_write.as_mut() else {
            return Poll::Ready(Ok(None));
        };
        match Pin::new(response).poll(cx) {
            Poll::Pending => Poll::Pending,
            Poll::Ready(Ok(Ok(()))) => {
                let length = *length;
                self.pending_write = None;
                Poll::Ready(Ok(Some(length)))
            }
            Poll::Ready(Ok(Err(error))) => {
                self.pending_write = None;
                Poll::Ready(Err(error))
            }
            Poll::Ready(Err(_)) => {
                self.pending_write = None;
                Poll::Ready(Err(new_io_error(
                    "mieru multiplexed write was cancelled",
                )))
            }
        }
    }
}

impl AsyncRead for MieruMuxStream {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        output: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        loop {
            if this.read_position < this.read_buffer.len() {
                let length = (this.read_buffer.len() - this.read_position)
                    .min(output.remaining());
                output.put_slice(
                    &this.read_buffer
                        [this.read_position..this.read_position + length],
                );
                this.read_position += length;
                if this.read_position == this.read_buffer.len() {
                    this.read_buffer.clear();
                    this.read_position = 0;
                }
                return Poll::Ready(Ok(()));
            }
            match this.recv_rx.poll_recv(cx) {
                Poll::Ready(Some(payload)) if payload.is_empty() => continue,
                Poll::Ready(Some(payload)) => this.read_buffer = payload,
                Poll::Ready(None) => return Poll::Ready(Ok(())),
                Poll::Pending => return Poll::Pending,
            }
        }
    }
}

impl AsyncWrite for MieruMuxStream {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buffer: &[u8],
    ) -> Poll<io::Result<usize>> {
        let this = self.get_mut();
        match this.poll_pending_write(cx) {
            Poll::Ready(Ok(Some(length))) => return Poll::Ready(Ok(length)),
            Poll::Ready(Ok(None)) => {}
            Poll::Ready(Err(error)) => return Poll::Ready(Err(error)),
            Poll::Pending => return Poll::Pending,
        }
        if buffer.is_empty() {
            return Poll::Ready(Ok(0));
        }
        ready!(this.send_tx.poll_ready_unpin(cx))
            .map_err(|_| new_io_error("mieru multiplexed command channel closed"))?;
        let (written, response) = tokio::sync::oneshot::channel();
        this.send_tx
            .start_send_unpin(MieruMuxCommand::Data {
                session_id: this.session_id,
                payload: buffer.to_vec(),
                written,
            })
            .map_err(|_| new_io_error("mieru multiplexed command channel closed"))?;
        this.pending_write = Some((buffer.len(), response));
        match this.poll_pending_write(cx) {
            Poll::Ready(Ok(Some(length))) => Poll::Ready(Ok(length)),
            Poll::Ready(Ok(None)) => unreachable!("pending write was just set"),
            Poll::Ready(Err(error)) => Poll::Ready(Err(error)),
            Poll::Pending => Poll::Pending,
        }
    }

    fn poll_flush(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        match this.poll_pending_write(cx) {
            Poll::Ready(Ok(_)) => {}
            Poll::Ready(Err(error)) => return Poll::Ready(Err(error)),
            Poll::Pending => return Poll::Pending,
        }
        this.send_tx
            .poll_flush_unpin(cx)
            .map_err(|_| new_io_error("mieru multiplexed flush failed"))
    }

    fn poll_shutdown(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        ready!(Pin::new(&mut *this).poll_flush(cx))?;
        if !this.close_sent {
            ready!(this.send_tx.poll_ready_unpin(cx)).map_err(|_| {
                new_io_error("mieru multiplexed command channel closed")
            })?;
            this.send_tx
                .start_send_unpin(MieruMuxCommand::Close {
                    session_id: this.session_id,
                })
                .map_err(|_| new_io_error("mieru multiplexed close failed"))?;
            this.close_sent = true;
        }
        this.send_tx
            .poll_flush_unpin(cx)
            .map_err(|_| new_io_error("mieru multiplexed close failed"))
    }
}

impl Drop for MieruMuxStream {
    fn drop(&mut self) {
        if !self.close_sent {
            let _ = self.connection.commands.try_send(MieruMuxCommand::Close {
                session_id: self.session_id,
            });
        }
    }
}

struct MieruSocket {
    inner: AnyStream,
    fragment: Option<TcpFragment>,
    delay: Option<Pin<Box<tokio::time::Sleep>>>,
}

impl MieruSocket {
    fn new(inner: AnyStream, fragment: Option<TcpFragment>) -> Self {
        Self {
            inner,
            fragment,
            delay: None,
        }
    }
}

impl AsyncRead for MieruSocket {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buffer: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        Pin::new(&mut self.get_mut().inner).poll_read(cx, buffer)
    }
}

impl AsyncWrite for MieruSocket {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buffer: &[u8],
    ) -> Poll<Result<usize, io::Error>> {
        let this = self.get_mut();
        if let Some(delay) = this.delay.as_mut() {
            match delay.as_mut().poll(cx) {
                Poll::Ready(_) => this.delay = None,
                Poll::Pending => return Poll::Pending,
            }
        }
        let Some(fragment) = this.fragment else {
            return Pin::new(&mut this.inner).poll_write(cx, buffer);
        };
        if buffer.is_empty() {
            return Poll::Ready(Ok(0));
        }
        let minimum = (buffer.len() as f64).sqrt() as usize + 1;
        let maximum = minimum.max(buffer.len() / 2);
        let length = rand::random_range(minimum..=maximum).min(buffer.len());
        match Pin::new(&mut this.inner).poll_write(cx, &buffer[..length]) {
            Poll::Ready(Ok(size)) => {
                if size > 0 && size < buffer.len() && fragment.max_sleep_ms > 0 {
                    let millis = rand::random_range(0..=fragment.max_sleep_ms);
                    this.delay = Some(Box::pin(tokio::time::sleep(
                        std::time::Duration::from_millis(millis),
                    )));
                }
                Poll::Ready(Ok(size))
            }
            other => other,
        }
    }

    fn poll_flush(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<Result<(), io::Error>> {
        Pin::new(&mut self.get_mut().inner).poll_flush(cx)
    }

    fn poll_shutdown(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<Result<(), io::Error>> {
        Pin::new(&mut self.get_mut().inner).poll_shutdown(cx)
    }
}

impl AsyncSocket for MieruSocket {
    type Error = io::Error;

    async fn read(&mut self, buffer: &mut [u8]) -> Result<usize, Self::Error> {
        AsyncReadExt::read(&mut self.inner, buffer).await
    }

    async fn write_all(&mut self, buffer: &[u8]) -> Result<(), Self::Error> {
        AsyncWriteExt::write_all(self, buffer).await
    }

    async fn shutdown(&mut self) -> Result<(), Self::Error> {
        AsyncWriteExt::shutdown(self).await
    }
}

struct MieruDatagram {
    send_tx: PollSender<UdpPacket>,
    recv_rx: tokio::sync::mpsc::Receiver<UdpPacket>,
    workers: Vec<tokio::task::JoinHandle<()>>,
}

impl MieruDatagram {
    fn new<S>(stream: S, sess: &Session, wait_for_socks_response: bool) -> Self
    where
        S: AsyncRead + AsyncWrite + Send + Unpin + 'static,
    {
        let (send_tx, mut send_rx) = tokio::sync::mpsc::channel::<UdpPacket>(32);
        let (recv_tx, recv_rx) = tokio::sync::mpsc::channel::<UdpPacket>(32);
        let local_source = SocksAddr::from(sess.source);
        let inbound_user = sess.inbound_user.clone();
        let (mut reader, mut writer) = tokio::io::split(stream);

        let write_worker = tokio::spawn(async move {
            let codec = MieruUdpFlowCodec;
            while let Some(packet) = send_rx.recv().await {
                let target = to_mieru_address(&packet.dst_addr);
                let frame = match codec.encode_packet(
                    &target,
                    packet.dst_addr.port(),
                    &packet.data,
                ) {
                    Ok(frame) => frame,
                    Err(_) => break,
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
            if wait_for_socks_response
                && read_socks_response(&mut reader).await.is_err()
            {
                return;
            }
            let codec = MieruUdpFlowCodec;
            loop {
                let frame = match read_mieru_udp_frame(&mut reader).await {
                    Ok(Some(frame)) => frame,
                    Ok(None) | Err(_) => break,
                };
                let packet = match codec.decode_packet(&frame) {
                    Ok(packet) => packet,
                    Err(_) => break,
                };
                let (source, port, data) = packet.into_parts();
                if recv_tx
                    .send(UdpPacket {
                        data,
                        src_addr: from_mieru_address(source, port),
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

async fn read_mieru_udp_frame<R>(reader: &mut R) -> io::Result<Option<Vec<u8>>>
where
    R: AsyncRead + Unpin,
{
    let mut header = [0u8; 3];
    match reader.read_exact(&mut header).await {
        Ok(_) => {}
        Err(error) if error.kind() == io::ErrorKind::UnexpectedEof => {
            return Ok(None);
        }
        Err(error) => return Err(error),
    }
    if header[0] != 0x00 {
        return Err(new_io_error("mieru UDP frame is missing the start marker"));
    }
    let payload_length = u16::from_be_bytes([header[1], header[2]]) as usize;
    let mut tail = vec![0u8; payload_length + 1];
    reader.read_exact(&mut tail).await?;
    if tail[payload_length] != 0xff {
        return Err(new_io_error("mieru UDP frame is missing the end marker"));
    }
    let mut frame = Vec::with_capacity(header.len() + tail.len());
    frame.extend_from_slice(&header);
    frame.extend_from_slice(&tail);
    Ok(Some(frame))
}

impl Drop for MieruDatagram {
    fn drop(&mut self) {
        for worker in &self.workers {
            worker.abort();
        }
    }
}

impl Sink<UdpPacket> for MieruDatagram {
    type Error = io::Error;

    fn poll_ready(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<Result<(), Self::Error>> {
        self.send_tx
            .poll_ready_unpin(cx)
            .map_err(|_| new_io_error("mieru UDP send channel closed"))
    }

    fn start_send(
        mut self: Pin<&mut Self>,
        item: UdpPacket,
    ) -> Result<(), Self::Error> {
        self.send_tx
            .start_send_unpin(item)
            .map_err(|_| new_io_error("mieru UDP send channel closed"))
    }

    fn poll_flush(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<Result<(), Self::Error>> {
        self.send_tx
            .poll_flush_unpin(cx)
            .map_err(|_| new_io_error("mieru UDP send channel flush failed"))
    }

    fn poll_close(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<Result<(), Self::Error>> {
        self.send_tx
            .poll_close_unpin(cx)
            .map_err(|_| new_io_error("mieru UDP send channel close failed"))
    }
}

impl Stream for MieruDatagram {
    type Item = UdpPacket;

    fn poll_next(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<Option<Self::Item>> {
        self.recv_rx.poll_recv(cx)
    }
}

fn to_mieru_address(address: &SocksAddr) -> MieruAddress {
    match address {
        SocksAddr::Domain(host, _) => MieruAddress::Domain(host.clone()),
        SocksAddr::Ip(address) => match address.ip() {
            IpAddr::V4(ip) => MieruAddress::Ipv4(ip.octets()),
            IpAddr::V6(ip) => MieruAddress::Ipv6(ip.octets()),
        },
    }
}

fn from_mieru_address(address: MieruAddress, port: u16) -> SocksAddr {
    match address {
        MieruAddress::Domain(host) => SocksAddr::Domain(host, port),
        MieruAddress::Ipv4(ip) => SocksAddr::Ip((ip, port).into()),
        MieruAddress::Ipv6(ip) => SocksAddr::Ip((ip, port).into()),
    }
}

#[cfg(test)]
mod tests {
    use super::{
        Handler, HandlerOptions, MieruDatagram, MieruHandshakeMode,
        MieruMuxConnection, MieruPacketCipher, MieruPacketDriverConfig,
        MieruPacketSegment, MieruSocket, MieruTransport, NonceTypeProto,
        TrafficPatternProto, establish_mieru_session, fixed_int, parse_port_range,
        parse_traffic_pattern, read_mieru_udp_frame, spawn_no_wait_stream,
        write_socks_request,
    };
    use crate::{
        proxy::{AnyOutboundDatagram, HandlerCommonOptions, datagram::UdpPacket},
        session::SocksAddr,
    };
    use ::mieru::{
        MieruTcpStream,
        crypto::{MieruCipher, NoncePattern as MieruNoncePattern, derive_key},
        inbound::{
            MieruInboundAcceptedSession, MieruInboundProfile, MieruInboundStream,
        },
        metadata::{
            ACK_CLIENT_TO_SERVER, DATA_CLIENT_TO_SERVER, DATA_SERVER_TO_CLIENT,
            DataMetadata, OPEN_SESSION_REQUEST, OPEN_SESSION_RESPONSE,
            SessionMetadata,
        },
        segment::{build_data_segment, build_session_segment, parse_segment},
        session::MieruSession as ProtocolSession,
        udp::MieruUdpFlowCodec,
    };
    use base64::{Engine as _, engine::general_purpose::STANDARD as BASE64};
    use futures::{Sink, SinkExt, Stream, StreamExt};
    use prost::Message;
    use std::{
        io,
        pin::Pin,
        task::{Context, Poll},
        time::Duration,
    };
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio_util::sync::PollSender;

    struct TestPacketDatagram {
        send_tx: PollSender<UdpPacket>,
        recv_rx: tokio::sync::mpsc::Receiver<UdpPacket>,
    }

    impl Sink<UdpPacket> for TestPacketDatagram {
        type Error = io::Error;

        fn poll_ready(
            mut self: Pin<&mut Self>,
            cx: &mut Context<'_>,
        ) -> Poll<Result<(), Self::Error>> {
            self.send_tx.poll_ready_unpin(cx).map_err(|_| {
                io::Error::new(io::ErrorKind::BrokenPipe, "test datagram closed")
            })
        }

        fn start_send(
            mut self: Pin<&mut Self>,
            packet: UdpPacket,
        ) -> Result<(), Self::Error> {
            self.send_tx.start_send_unpin(packet).map_err(|_| {
                io::Error::new(io::ErrorKind::BrokenPipe, "test datagram closed")
            })
        }

        fn poll_flush(
            mut self: Pin<&mut Self>,
            cx: &mut Context<'_>,
        ) -> Poll<Result<(), Self::Error>> {
            self.send_tx.poll_flush_unpin(cx).map_err(|_| {
                io::Error::new(io::ErrorKind::BrokenPipe, "test datagram closed")
            })
        }

        fn poll_close(
            mut self: Pin<&mut Self>,
            cx: &mut Context<'_>,
        ) -> Poll<Result<(), Self::Error>> {
            self.send_tx.poll_close_unpin(cx).map_err(|_| {
                io::Error::new(io::ErrorKind::BrokenPipe, "test datagram closed")
            })
        }
    }

    impl Stream for TestPacketDatagram {
        type Item = UdpPacket;

        fn poll_next(
            mut self: Pin<&mut Self>,
            cx: &mut Context<'_>,
        ) -> Poll<Option<Self::Item>> {
            self.recv_rx.poll_recv(cx)
        }
    }

    fn test_packet_datagram() -> (
        AnyOutboundDatagram,
        tokio::sync::mpsc::Receiver<UdpPacket>,
        tokio::sync::mpsc::Sender<UdpPacket>,
    ) {
        let (client_tx, server_rx) = tokio::sync::mpsc::channel(64);
        let (server_tx, client_rx) = tokio::sync::mpsc::channel(64);
        (
            Box::new(TestPacketDatagram {
                send_tx: PollSender::new(client_tx),
                recv_rx: client_rx,
            }),
            server_rx,
            server_tx,
        )
    }

    async fn run_mieru_mux_echo_server(server_io: tokio::io::DuplexStream) {
        let mut raw = MieruSocket::new(Box::new(server_io), None);
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs();
        let key = derive_key("user", "password", now);
        let mut client_cipher = MieruCipher::new(&key);
        let mut server_cipher = MieruCipher::new(&key);

        let mut first = vec![0u8; 24 + 32 + 16];
        tokio::io::AsyncReadExt::read_exact(&mut raw, &mut first)
            .await
            .unwrap();
        let (segment, _) =
            parse_segment(&first, &mut client_cipher, true, true).unwrap();
        let open = segment.session_meta.unwrap();
        assert_eq!(open.protocol_type, OPEN_SESSION_REQUEST);
        let response = SessionMetadata {
            protocol_type: OPEN_SESSION_RESPONSE,
            timestamp: ProtocolSession::timestamp_minutes(),
            session_id: open.session_id,
            sequence_number: 0,
            status_code: 0,
            payload_length: 0,
            suffix_length: 0,
        };
        let wire =
            build_session_segment(&response, &[], &mut server_cipher, true).unwrap();
        tokio::io::AsyncWriteExt::write_all(&mut raw, &wire)
            .await
            .unwrap();
        tokio::io::AsyncWriteExt::flush(&mut raw).await.unwrap();

        let mut read_buffer = Vec::new();
        let mut scratch = [0u8; 8192];
        let mut send_sequences = std::collections::HashMap::<u32, u32>::new();
        loop {
            let length = tokio::io::AsyncReadExt::read(&mut raw, &mut scratch)
                .await
                .unwrap();
            if length == 0 {
                break;
            }
            read_buffer.extend_from_slice(&scratch[..length]);
            loop {
                let mut candidate = client_cipher.clone();
                let (segment, consumed) = match parse_segment(
                    &read_buffer,
                    &mut candidate,
                    false,
                    false,
                ) {
                    Ok(value) => value,
                    Err(zero_core::Error::Protocol("mieru: need more data")) => {
                        break;
                    }
                    Err(error) => panic!("failed to parse mux segment: {error}"),
                };
                client_cipher = candidate;
                read_buffer.drain(..consumed);
                if let Some(metadata) = segment.session_meta {
                    if metadata.protocol_type == OPEN_SESSION_REQUEST {
                        let response = SessionMetadata {
                            protocol_type: OPEN_SESSION_RESPONSE,
                            timestamp: ProtocolSession::timestamp_minutes(),
                            session_id: metadata.session_id,
                            sequence_number: 0,
                            status_code: 0,
                            payload_length: 0,
                            suffix_length: 0,
                        };
                        let wire = build_session_segment(
                            &response,
                            &[],
                            &mut server_cipher,
                            false,
                        )
                        .unwrap();
                        tokio::io::AsyncWriteExt::write_all(&mut raw, &wire)
                            .await
                            .unwrap();
                        tokio::io::AsyncWriteExt::flush(&mut raw).await.unwrap();
                    }
                    continue;
                }
                let Some(metadata) = segment.data_meta else {
                    continue;
                };
                let sequence =
                    send_sequences.entry(metadata.session_id).or_default();
                let response = DataMetadata {
                    protocol_type: DATA_SERVER_TO_CLIENT,
                    timestamp: ProtocolSession::timestamp_minutes(),
                    session_id: metadata.session_id,
                    sequence_number: *sequence,
                    unack_sequence: 0,
                    window_size: 1024,
                    fragment_number: 0,
                    prefix_length: 0,
                    payload_length: segment.payload.len() as u16,
                    suffix_length: 0,
                };
                *sequence = sequence.wrapping_add(1);
                let wire = build_data_segment(
                    &response,
                    &segment.payload,
                    &mut server_cipher,
                    false,
                )
                .unwrap();
                tokio::io::AsyncWriteExt::write_all(&mut raw, &wire)
                    .await
                    .unwrap();
                tokio::io::AsyncWriteExt::flush(&mut raw).await.unwrap();
            }
        }
    }

    fn options() -> HandlerOptions {
        HandlerOptions {
            name: "mieru-test".to_owned(),
            common_opts: HandlerCommonOptions::default(),
            server: "example.com".to_owned(),
            port: 443,
            port_range: None,
            transport: "TCP".to_owned(),
            udp: true,
            username: "user".to_owned(),
            password: "password".to_owned(),
            multiplexing: None,
            handshake_mode: None,
            traffic_pattern: None,
        }
    }

    #[tokio::test]
    async fn multiplexes_two_logical_streams_on_one_physical_connection() {
        crate::tests::initialize();
        let (client_io, server_io) = tokio::io::duplex(256 * 1024);
        let server = tokio::spawn(run_mieru_mux_echo_server(server_io));
        let (raw, outbound) = establish_mieru_session(
            MieruSocket::new(Box::new(client_io), None),
            "user",
            "password",
            MieruNoncePattern::Random,
        )
        .await
        .unwrap();
        let (connection, mut first) = MieruMuxConnection::spawn(raw, outbound);
        let mut second = connection.open_stream().await.unwrap();

        let first_flow = async {
            first.write_all(b"first-session").await.unwrap();
            let mut response = [0u8; 13];
            first.read_exact(&mut response).await.unwrap();
            assert_eq!(&response, b"first-session");
        };
        let second_flow = async {
            second.write_all(b"second-session").await.unwrap();
            let mut response = [0u8; 14];
            second.read_exact(&mut response).await.unwrap();
            assert_eq!(&response, b"second-session");
        };
        tokio::join!(first_flow, second_flow);
        drop(first);
        drop(second);
        drop(connection);
        server.await.unwrap();
    }

    #[test]
    fn packet_codec_uses_one_nonce_for_metadata_and_payload() {
        let key = [0x42; 32];
        let mut sender = MieruPacketCipher::new(
            key,
            "user".to_owned(),
            MieruNoncePattern::Random,
            true,
        );
        let receiver = MieruPacketCipher::new(
            key,
            "user".to_owned(),
            MieruNoncePattern::Random,
            true,
        );
        let segment = MieruPacketSegment::Data {
            metadata: DataMetadata {
                protocol_type: DATA_CLIENT_TO_SERVER,
                timestamp: ProtocolSession::timestamp_minutes(),
                session_id: 77,
                sequence_number: 9,
                unack_sequence: 4,
                window_size: 128,
                fragment_number: 0,
                prefix_length: 3,
                payload_length: 13,
                suffix_length: 5,
            },
            payload: b"same-nonce-ok".to_vec(),
        };
        let wire = sender.encrypt(&segment).unwrap();
        let decoded = receiver.decrypt(&wire).unwrap();
        let MieruPacketSegment::Data { metadata, payload } = decoded else {
            panic!("expected data packet");
        };
        assert_eq!(metadata.session_id, 77);
        assert_eq!(metadata.sequence_number, 9);
        assert_eq!(metadata.prefix_length, 3);
        assert_eq!(metadata.suffix_length, 5);
        assert_eq!(payload, b"same-nonce-ok");
    }

    #[tokio::test]
    async fn packet_underlay_retransmits_open_and_reorders_server_data() {
        crate::tests::initialize();
        let (raw, mut from_client, to_client) = test_packet_datagram();
        let destination = SocksAddr::Domain("server.test".to_owned(), 443);
        let unix_now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs();
        let key = derive_key("user", "password", unix_now);
        let server = tokio::spawn(async move {
            let mut codec = MieruPacketCipher::new(
                key,
                "user".to_owned(),
                MieruNoncePattern::Random,
                true,
            );

            let first_open = from_client.recv().await.unwrap();
            let MieruPacketSegment::Session {
                metadata: first_metadata,
                ..
            } = codec.decrypt(&first_open.data).unwrap()
            else {
                panic!("expected first open request");
            };
            assert_eq!(first_metadata.protocol_type, OPEN_SESSION_REQUEST);

            let retransmitted_open = from_client.recv().await.unwrap();
            assert_ne!(first_open.data, retransmitted_open.data);
            let MieruPacketSegment::Session { metadata, .. } =
                codec.decrypt(&retransmitted_open.data).unwrap()
            else {
                panic!("expected retransmitted open request");
            };
            assert_eq!(metadata.protocol_type, OPEN_SESSION_REQUEST);
            assert_eq!(metadata.session_id, first_metadata.session_id);
            let session_id = metadata.session_id;

            let open_response = MieruPacketSegment::Session {
                metadata: SessionMetadata {
                    protocol_type: OPEN_SESSION_RESPONSE,
                    timestamp: ProtocolSession::timestamp_minutes(),
                    session_id,
                    sequence_number: 0,
                    status_code: 0,
                    payload_length: 0,
                    suffix_length: 0,
                },
                payload: Vec::new(),
            };
            to_client
                .send(UdpPacket {
                    data: codec.encrypt(&open_response).unwrap(),
                    ..Default::default()
                })
                .await
                .unwrap();

            let client_data = loop {
                let packet = from_client.recv().await.unwrap();
                let segment = codec.decrypt(&packet.data).unwrap();
                match segment {
                    MieruPacketSegment::Data { metadata, payload }
                        if metadata.protocol_type == DATA_CLIENT_TO_SERVER =>
                    {
                        break (metadata, payload);
                    }
                    MieruPacketSegment::Data { metadata, .. } => {
                        assert_eq!(metadata.protocol_type, ACK_CLIENT_TO_SERVER);
                    }
                    _ => {}
                }
            };
            assert_eq!(client_data.1, b"client-payload");

            for (sequence_number, payload) in
                [(2, b"second".as_slice()), (1, b"first".as_slice())]
            {
                let response = MieruPacketSegment::Data {
                    metadata: DataMetadata {
                        protocol_type: DATA_SERVER_TO_CLIENT,
                        timestamp: ProtocolSession::timestamp_minutes(),
                        session_id,
                        sequence_number,
                        unack_sequence: client_data.0.sequence_number + 1,
                        window_size: 1024,
                        fragment_number: 0,
                        prefix_length: 0,
                        payload_length: payload.len() as u16,
                        suffix_length: 0,
                    },
                    payload: payload.to_vec(),
                };
                to_client
                    .send(UdpPacket {
                        data: codec.encrypt(&response).unwrap(),
                        ..Default::default()
                    })
                    .await
                    .unwrap();
            }
            loop {
                let packet = from_client.recv().await.unwrap();
                let MieruPacketSegment::Data { metadata, .. } =
                    codec.decrypt(&packet.data).unwrap()
                else {
                    continue;
                };
                if metadata.protocol_type == ACK_CLIENT_TO_SERVER
                    && metadata.unack_sequence == 3
                {
                    break;
                }
            }
        });

        let connection = MieruMuxConnection::spawn_packet_with_config(
            raw,
            destination,
            key,
            "user".to_owned(),
            MieruNoncePattern::Random,
            true,
            MieruPacketDriverConfig {
                tick_interval: Duration::from_millis(2),
                initial_rto: Duration::from_millis(20),
                open_timeout: Duration::from_secs(1),
                heartbeat_interval: Duration::from_secs(1),
                max_retransmissions: 5,
            },
        );
        let mut stream =
            tokio::time::timeout(Duration::from_secs(1), connection.open_stream())
                .await
                .unwrap()
                .unwrap();
        stream.write_all(b"client-payload").await.unwrap();
        let mut response = [0u8; 11];
        tokio::time::timeout(
            Duration::from_secs(1),
            stream.read_exact(&mut response),
        )
        .await
        .unwrap()
        .unwrap();
        assert_eq!(&response, b"firstsecond");
        server.await.unwrap();
    }

    #[test]
    fn accepts_mihomo_udp_packet_transport() {
        let mut opts = options();
        opts.transport = "UDP".to_owned();
        let handler = Handler::new(opts).unwrap();
        assert_eq!(handler.transport, MieruTransport::Udp);
    }

    #[test]
    fn validates_mihomo_port_range() {
        assert_eq!(parse_port_range("4000-5000").unwrap(), (4000, 5000));
        assert!(parse_port_range("0-5000").is_err());
        assert!(parse_port_range("5000-4000").is_err());
        assert!(parse_port_range("4000-5000-6000").is_err());
    }

    #[test]
    fn accepts_and_applies_mihomo_extensions() {
        let mut opts = options();
        opts.multiplexing = Some("MULTIPLEXING_HIGH".to_owned());
        opts.handshake_mode = Some("HANDSHAKE_NO_WAIT".to_owned());
        opts.traffic_pattern = Some("GgQIARAK".to_owned());
        let handler = Handler::new(opts).unwrap();
        assert_eq!(handler.multiplex_factor, 3);
        assert_eq!(handler.handshake_mode, MieruHandshakeMode::NoWait);
        assert_eq!(
            handler.traffic_pattern.tcp_fragment.unwrap().max_sleep_ms,
            10
        );
    }

    #[test]
    fn rejects_invalid_mihomo_extension_values() {
        let mut opts = options();
        opts.multiplexing = Some("MULTIPLEXING_EXTREME".to_owned());
        assert!(
            Handler::new(opts)
                .err()
                .unwrap()
                .to_string()
                .contains("multiplexing")
        );

        let mut opts = options();
        opts.handshake_mode = Some("HANDSHAKE_FAST".to_owned());
        assert!(
            Handler::new(opts)
                .err()
                .unwrap()
                .to_string()
                .contains("handshake-mode")
        );

        let mut opts = options();
        opts.traffic_pattern = Some("not-base64".to_owned());
        assert!(
            Handler::new(opts)
                .err()
                .unwrap()
                .to_string()
                .contains("traffic-pattern")
        );
    }

    #[test]
    fn traffic_pattern_uses_upstream_fixed_derivation() {
        assert_eq!(fixed_int(2, "42:tcpFragment.enable"), 1);
        assert_eq!(fixed_int(100, "42:tcpFragment.maxSleepMs"), 54);
        assert_eq!(fixed_int(3, "42:nonce.type"), 2);
        assert_eq!(fixed_int(13, "42:nonce.minLen"), 9);
        assert_eq!(fixed_int(4, "42:nonce.maxLen"), 3);

        let encoded = BASE64.encode(
            TrafficPatternProto {
                seed: Some(42),
                unlock_all: Some(true),
                tcp_fragment: None,
                nonce: None,
            }
            .encode_to_vec(),
        );
        let pattern = parse_traffic_pattern(Some(&encoded)).unwrap();
        assert_eq!(pattern.tcp_fragment.unwrap().max_sleep_ms, 55);
        assert_eq!(
            pattern.nonce,
            ::mieru::crypto::NoncePattern::PrintableSubset {
                min_len: 9,
                max_len: 13,
            }
        );
        assert!(!pattern.apply_nonce_to_all_udp_packets);
    }

    #[test]
    fn traffic_pattern_preserves_explicit_udp_nonce_scope() {
        let encoded = BASE64.encode(
            TrafficPatternProto {
                seed: Some(7),
                unlock_all: Some(false),
                tcp_fragment: None,
                nonce: Some(super::NoncePatternProto {
                    kind: Some(NonceTypeProto::Printable as i32),
                    apply_to_all_udp_packet: Some(true),
                    min_len: Some(3),
                    max_len: Some(7),
                    custom_hex_strings: Vec::new(),
                }),
            }
            .encode_to_vec(),
        );
        let pattern = parse_traffic_pattern(Some(&encoded)).unwrap();
        assert_eq!(
            pattern.nonce,
            ::mieru::crypto::NoncePattern::Printable {
                min_len: 3,
                max_len: 8,
            }
        );
        assert!(pattern.apply_nonce_to_all_udp_packets);
    }

    #[tokio::test]
    async fn no_wait_sends_payload_before_socks_response() {
        crate::tests::initialize();
        let (client_io, server_io) = tokio::io::duplex(128 * 1024);
        let server = tokio::spawn(async move {
            let profile = MieruInboundProfile::from_config_parts(vec![(
                "user".to_owned(),
                "password".to_owned(),
            )]);
            let accepted = profile
                .accept_client(MieruSocket::new(Box::new(server_io), None))
                .await
                .unwrap();
            let MieruInboundAcceptedSession::Tcp {
                session,
                mut stream,
            } = accepted
            else {
                panic!("expected TCP session");
            };
            assert_eq!(session.port, 443);
            let mut payload = [0u8; 10];
            stream.read_exact(&mut payload).await.unwrap();
            assert_eq!(&payload, b"early-data");
            stream.write_all(&payload).await.unwrap();
            stream.flush().await.unwrap();
        });

        let (socket, outbound) = establish_mieru_session(
            MieruSocket::new(Box::new(client_io), None),
            "user",
            "password",
            MieruNoncePattern::PrintableSubset {
                min_len: 6,
                max_len: 12,
            },
        )
        .await
        .unwrap();
        let mut encrypted = MieruTcpStream::new(socket, outbound);
        write_socks_request(
            &mut encrypted,
            0x01,
            &SocksAddr::Domain("example.com".to_owned(), 443),
        )
        .await
        .unwrap();
        let mut stream = spawn_no_wait_stream(encrypted);
        stream.write_all(b"early-data").await.unwrap();
        stream.flush().await.unwrap();
        let mut response = [0u8; 10];
        stream.read_exact(&mut response).await.unwrap();
        assert_eq!(&response, b"early-data");
        server.await.unwrap();
    }

    #[tokio::test]
    async fn udp_no_wait_sends_packet_before_socks_response() {
        crate::tests::initialize();
        let (client_io, server_io) = tokio::io::duplex(128 * 1024);
        let server = tokio::spawn(async move {
            let profile = MieruInboundProfile::from_config_parts(vec![(
                "user".to_owned(),
                "password".to_owned(),
            )]);
            let mut raw = MieruSocket::new(Box::new(server_io), None);
            let accepted = profile.accept_request(&mut raw).await.unwrap();
            let mut stream = MieruInboundStream::new(raw, accepted);

            let mut request = [0u8; 10];
            stream.read_exact(&mut request).await.unwrap();
            assert_eq!(request, [5, 3, 0, 1, 0, 0, 0, 0, 0, 0]);

            // Read the first UDP frame before acknowledging UDP ASSOCIATE.
            // This proves HANDSHAKE_NO_WAIT affects UDP as it does upstream.
            let codec = MieruUdpFlowCodec;
            let frame = read_mieru_udp_frame(&mut stream).await.unwrap().unwrap();
            let packet = codec.decode_packet(&frame).unwrap();
            assert_eq!(
                packet.target(),
                &zero_core::Address::Domain("dns.example".to_owned())
            );
            assert_eq!(packet.port(), 53);
            assert_eq!(packet.payload(), b"query");

            stream
                .write_all(&[5, 0, 0, 1, 0, 0, 0, 0, 0, 0])
                .await
                .unwrap();
            let response = codec
                .encode_packet(packet.target(), packet.port(), b"answer")
                .unwrap();
            stream.write_all(&response).await.unwrap();
            stream.flush().await.unwrap();
        });

        let (socket, outbound) = establish_mieru_session(
            MieruSocket::new(Box::new(client_io), None),
            "user",
            "password",
            MieruNoncePattern::PrintableSubset {
                min_len: 6,
                max_len: 12,
            },
        )
        .await
        .unwrap();
        let mut encrypted = MieruTcpStream::new(socket, outbound);
        write_socks_request(&mut encrypted, 0x03, &SocksAddr::any_ipv4())
            .await
            .unwrap();
        let session = crate::session::Session {
            network: crate::session::Network::Udp,
            source: "127.0.0.1:54321".parse().unwrap(),
            ..Default::default()
        };
        let mut datagram = MieruDatagram::new(encrypted, &session, true);
        datagram
            .send(crate::proxy::datagram::UdpPacket {
                data: b"query".to_vec(),
                src_addr: SocksAddr::from(session.source),
                dst_addr: SocksAddr::Domain("dns.example".to_owned(), 53),
                inbound_user: None,
            })
            .await
            .unwrap();
        let response =
            tokio::time::timeout(std::time::Duration::from_secs(2), datagram.next())
                .await
                .unwrap()
                .unwrap();
        assert_eq!(response.data, b"answer");
        assert_eq!(
            response.src_addr,
            SocksAddr::Domain("dns.example".to_owned(), 53)
        );
        server.await.unwrap();
    }
}
