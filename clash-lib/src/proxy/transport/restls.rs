//! Restls client transport.
//!
//! Restls performs a genuine TLS handshake through a cover server,
//! authenticates the client in the legacy session ID, authenticates the server
//! by masking its first encrypted handshake record, and then replaces TLS
//! application records with lightweight BLAKE3-authenticated records. The wire
//! constants and record construction follow the BSD-3-Clause Restls reference
//! implementation.

use async_trait::async_trait;
use bytes::BytesMut;
use rand::RngExt as _;
use std::{
    collections::VecDeque,
    fmt, io,
    pin::Pin,
    sync::{Arc, LazyLock, Mutex, OnceLock},
    task::{Context, Poll},
};
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
use tokio_rustls::TlsConnector;

use super::Transport;
use crate::{
    common::{
        errors::map_io_error,
        tls::{DefaultTlsVerifier, build_tls_client_config_with_protocol_versions},
    },
    proxy::AnyStream,
};

const TLS_HEADER_LEN: usize = 5;
const RESTLS_AUTH_LEN: usize = 8;
const RESTLS_MASK_LEN: usize = 4;
const RESTLS_DATA_OFFSET: usize = RESTLS_AUTH_LEN + RESTLS_MASK_LEN;
const RESTLS_HANDSHAKE_AUTH_LEN: usize = 16;
const MAX_TLS_RECORD_LEN: usize = 18_432;
const DEFAULT_SCRIPT: &str = "250?100<1,350~100<1,600~100,300~200,300~100";

const RECORD_CCS: u8 = 0x14;
const RECORD_ALERT: u8 = 0x15;
const RECORD_HANDSHAKE: u8 = 0x16;
const RECORD_APPLICATION_DATA: u8 = 0x17;
const HANDSHAKE_SERVER_HELLO: u8 = 0x02;

const EXT_SESSION_TICKET: u16 = 0x0023;
const EXT_PRE_SHARED_KEY: u16 = 0x0029;
const EXT_KEY_SHARE: u16 = 0x0033;

const TO_CLIENT_MAGIC: &[u8] = b"server-to-client";
const TO_SERVER_MAGIC: &[u8] = b"client-to-server";

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum VersionHint {
    Tls12,
    Tls13,
}

static TLS12_HANDSHAKE_LOCK: LazyLock<tokio::sync::Mutex<()>> =
    LazyLock::new(|| tokio::sync::Mutex::new(()));
static TLS12_KX_GROUPS: OnceLock<[&'static RestlsKxGroup; 3]> = OnceLock::new();

struct RestlsKxGroup {
    inner: &'static dyn rustls::crypto::SupportedKxGroup,
    prepared: Mutex<Option<Box<dyn rustls::crypto::ActiveKeyExchange>>>,
}

impl fmt::Debug for RestlsKxGroup {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("RestlsKxGroup")
            .field("name", &self.inner.name())
            .finish_non_exhaustive()
    }
}

impl RestlsKxGroup {
    fn prepare(&self) -> Result<Vec<u8>, rustls::Error> {
        let exchange = self.inner.start()?;
        let public_key = exchange.pub_key().to_vec();
        *self.prepared.lock().map_err(|_| {
            rustls::Error::General("Restls ECDHE state poisoned".to_owned())
        })? = Some(exchange);
        Ok(public_key)
    }
}

impl rustls::crypto::SupportedKxGroup for RestlsKxGroup {
    fn start(
        &self,
    ) -> Result<Box<dyn rustls::crypto::ActiveKeyExchange>, rustls::Error> {
        if let Some(exchange) = self
            .prepared
            .lock()
            .map_err(|_| {
                rustls::Error::General("Restls ECDHE state poisoned".to_owned())
            })?
            .take()
        {
            Ok(exchange)
        } else {
            self.inner.start()
        }
    }

    fn name(&self) -> rustls::NamedGroup {
        self.inner.name()
    }

    fn fips(&self) -> bool {
        self.inner.fips()
    }

    fn usable_for_version(&self, version: rustls::ProtocolVersion) -> bool {
        self.inner.usable_for_version(version)
    }
}

fn tls12_kx_groups() -> io::Result<&'static [&'static RestlsKxGroup; 3]> {
    if let Some(groups) = TLS12_KX_GROUPS.get() {
        return Ok(groups);
    }
    let provider =
        rustls::crypto::CryptoProvider::get_default().ok_or_else(|| {
            io::Error::other("no default rustls CryptoProvider is installed")
        })?;
    let find = |name| {
        provider
            .kx_groups
            .iter()
            .copied()
            .find(|group| group.name() == name)
            .ok_or_else(|| {
                io::Error::new(
                    io::ErrorKind::Unsupported,
                    format!(
                        "rustls provider does not support Restls ECDHE group \
                         {name:?}"
                    ),
                )
            })
    };
    let create = |inner| {
        Box::leak(Box::new(RestlsKxGroup {
            inner,
            prepared: Mutex::new(None),
        })) as &'static RestlsKxGroup
    };
    let groups = [
        create(find(rustls::NamedGroup::X25519)?),
        create(find(rustls::NamedGroup::secp256r1)?),
        create(find(rustls::NamedGroup::secp384r1)?),
    ];
    let _ = TLS12_KX_GROUPS.set(groups);
    Ok(TLS12_KX_GROUPS.get().unwrap())
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum Command {
    Noop,
    Response(u8),
}

impl Command {
    fn to_bytes(self) -> [u8; 2] {
        match self {
            Self::Noop => [0, 0],
            Self::Response(count) => [1, count],
        }
    }

    fn from_bytes(value: &[u8]) -> io::Result<Self> {
        match value {
            [0, _] => Ok(Self::Noop),
            [1, count] => Ok(Self::Response(*count)),
            _ => Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "unsupported Restls record command",
            )),
        }
    }

    fn interrupts(self) -> bool {
        matches!(self, Self::Response(_))
    }
}

#[derive(Clone, Debug)]
enum TargetLength {
    Fixed(usize),
    RandomEach { base: usize, range: usize },
}

impl TargetLength {
    fn resolve(&self) -> usize {
        match *self {
            Self::Fixed(value) => value,
            Self::RandomEach { base, range: 0 } => base,
            Self::RandomEach { base, range } => {
                base + rand::rng().random_range(0..range)
            }
        }
    }
}

#[derive(Clone, Debug)]
struct ScriptLine {
    target: TargetLength,
    command: Command,
}

fn parse_number(input: &str, position: &mut usize) -> io::Result<usize> {
    let start = *position;
    let bytes = input.as_bytes();
    while *position < bytes.len() && bytes[*position].is_ascii_digit() {
        *position += 1;
    }
    if start == *position {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            format!("invalid Restls script line `{input}`"),
        ));
    }
    let value = input[start..*position].parse::<usize>().map_err(|error| {
        io::Error::new(
            io::ErrorKind::InvalidInput,
            format!("invalid Restls script number: {error}"),
        )
    })?;
    if value > 32_768 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "Restls script record length exceeds 32768",
        ));
    }
    Ok(value)
}

fn parse_script(script: &str) -> io::Result<Vec<ScriptLine>> {
    let script = if script.trim().is_empty() {
        DEFAULT_SCRIPT
    } else {
        script
    };
    script
        .replace(' ', "")
        .split(',')
        .filter(|line| !line.is_empty())
        .map(|line| {
            let mut position = 0;
            let base = parse_number(line, &mut position)?;
            let mut target = TargetLength::Fixed(base);
            if let Some(kind @ (b'?' | b'~')) =
                line.as_bytes().get(position).copied()
            {
                position += 1;
                let range = parse_number(line, &mut position)?;
                if base + range > 32_768 {
                    return Err(io::Error::new(
                        io::ErrorKind::InvalidInput,
                        "Restls randomized record length exceeds 32768",
                    ));
                }
                target = if kind == b'?' {
                    let value = if range == 0 {
                        base
                    } else {
                        base + rand::rng().random_range(0..range)
                    };
                    TargetLength::Fixed(value)
                } else {
                    TargetLength::RandomEach { base, range }
                };
            }

            let command = if line.as_bytes().get(position) == Some(&b'<') {
                position += 1;
                let count = parse_number(line, &mut position)?;
                let count = u8::try_from(count).map_err(|_| {
                    io::Error::new(
                        io::ErrorKind::InvalidInput,
                        "Restls response count exceeds 255",
                    )
                })?;
                Command::Response(count)
            } else {
                Command::Noop
            };
            if position != line.len() {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidInput,
                    format!("invalid Restls script suffix in `{line}`"),
                ));
            }
            Ok(ScriptLine { target, command })
        })
        .collect()
}

pub struct Client {
    host: String,
    secret: [u8; 32],
    script: Vec<ScriptLine>,
    client_fingerprint: Option<String>,
    version_hint: VersionHint,
    session_store: Arc<rustls::client::ClientSessionMemoryCache>,
}

impl Client {
    pub fn new(
        host: String,
        password: String,
        version_hint: String,
        script: Option<String>,
        client_fingerprint: Option<String>,
    ) -> io::Result<Self> {
        let version_hint = match version_hint.to_ascii_lowercase().as_str() {
            "tls13" => VersionHint::Tls13,
            "tls12" => VersionHint::Tls12,
            _ => {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidInput,
                    "Restls version-hint must be either tls12 or tls13",
                ));
            }
        };
        if host.trim().is_empty() {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "Restls host is required",
            ));
        }
        if password.is_empty() {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "Restls password is required",
            ));
        }
        let script = parse_script(script.as_deref().unwrap_or_default())?;
        Ok(Self {
            host,
            secret: blake3::derive_key("restls-traffic-key", password.as_bytes()),
            script,
            client_fingerprint,
            version_hint,
            session_store: Arc::new(rustls::client::ClientSessionMemoryCache::new(
                100,
            )),
        })
    }

    async fn wrap_stream(&self, stream: AnyStream) -> io::Result<AnyStream> {
        self.wrap_stream_with_verification(stream, false).await
    }

    async fn wrap_stream_with_verification(
        &self,
        stream: AnyStream,
        skip_cert_verify: bool,
    ) -> io::Result<AnyStream> {
        if let Some(fingerprint) = self.client_fingerprint.as_deref() {
            match fingerprint.to_ascii_lowercase().as_str() {
                "chrome" | "firefox" | "safari" | "ios" => {}
                value => tracing::warn!(
                    "unknown Restls client-fingerprint `{value}`, using the Rust \
                     TLS fingerprint"
                ),
            }
        }

        let verifier =
            Arc::new(DefaultTlsVerifier::try_new(None, skip_cert_verify)?);
        match self.version_hint {
            VersionHint::Tls12 => self.wrap_tls12(stream, verifier).await,
            VersionHint::Tls13 => self.wrap_tls13(stream, verifier).await,
        }
    }

    async fn wrap_tls13(
        &self,
        stream: AnyStream,
        verifier: Arc<DefaultTlsVerifier>,
    ) -> io::Result<AnyStream> {
        let mut config = build_tls_client_config_with_protocol_versions(
            verifier,
            None,
            None,
            &[&rustls::version::TLS13],
        )?;
        // Mihomo's Restls TLS 1.3 mode disables session tickets. Besides
        // matching its ClientHello, this keeps PSK identities out of future
        // authenticated handshakes.
        config.resumption = rustls::client::Resumption::disabled();
        let connector = TlsConnector::from(Arc::new(config));
        let server_name = rustls::pki_types::ServerName::try_from(self.host.clone())
            .map_err(map_io_error)?;
        let secret = self.secret;
        let generator = move |client_hello: &[u8]| {
            restls_tls13_session_id(&secret, client_hello).unwrap_or([0; 32])
        };
        let capture = HandshakeCapture::new(stream, self.secret, VersionHint::Tls13);
        let tls = connector
            .connect_with_session_id_generator(
                server_name,
                capture,
                Some(generator),
                |_| {},
            )
            .await?;
        self.finish_handshake(tls, rustls::ProtocolVersion::TLSv1_3)
    }

    async fn wrap_tls12(
        &self,
        stream: AnyStream,
        verifier: Arc<DefaultTlsVerifier>,
    ) -> io::Result<AnyStream> {
        let _handshake_guard = TLS12_HANDSHAKE_LOCK.lock().await;
        let groups = tls12_kx_groups()?;
        let public_keys = [
            groups[0].prepare(),
            groups[1].prepare(),
            groups[2].prepare(),
        ]
        .into_iter()
        .collect::<Result<Vec<_>, _>>()
        .map_err(map_io_error)?;

        let default_provider = rustls::crypto::CryptoProvider::get_default()
            .ok_or_else(|| {
                io::Error::other("no default rustls CryptoProvider is installed")
            })?;
        let mut provider = default_provider.as_ref().clone();
        for configured in &mut provider.kx_groups {
            if let Some(group) = groups
                .iter()
                .find(|group| group.inner.name() == configured.name())
            {
                *configured =
                    *group as &'static dyn rustls::crypto::SupportedKxGroup;
            }
        }
        let mut config =
            rustls::ClientConfig::builder_with_provider(Arc::new(provider))
                .with_protocol_versions(&[&rustls::version::TLS12])
                .map_err(map_io_error)?
                .dangerous()
                .with_custom_certificate_verifier(verifier)
                .with_no_client_auth();
        config.resumption =
            rustls::client::Resumption::store(self.session_store.clone());
        let connector = TlsConnector::from(Arc::new(config));
        let server_name = rustls::pki_types::ServerName::try_from(self.host.clone())
            .map_err(map_io_error)?;
        let secret = self.secret;
        let generator = move |client_hello: &[u8]| {
            restls_tls12_session_id(&secret, &public_keys, client_hello)
                .unwrap_or([0; 32])
        };
        let capture = HandshakeCapture::new(stream, self.secret, VersionHint::Tls12);
        let tls = connector
            .connect_with_session_id_generator(
                server_name,
                capture,
                Some(generator),
                |_| {},
            )
            .await?;
        self.finish_handshake(tls, rustls::ProtocolVersion::TLSv1_2)
    }

    fn finish_handshake(
        &self,
        tls: tokio_rustls::client::TlsStream<HandshakeCapture>,
        expected_version: rustls::ProtocolVersion,
    ) -> io::Result<AnyStream> {
        if tls.get_ref().1.protocol_version() != Some(expected_version) {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                format!(
                    "Restls cover server did not negotiate {expected_version:?}"
                ),
            ));
        }
        let (capture, _) = tls.into_inner();
        let parts = capture.into_parts()?;
        Ok(Box::new(RestlsStream::new(
            parts.raw,
            self.secret,
            parts.server_random,
            parts.client_finished,
            self.script.clone(),
            parts.prefetched,
            parts.cover_records,
            parts.tls12_gcm,
            parts.server_gcm_nonce,
        )))
    }
}

#[async_trait]
impl Transport for Client {
    async fn proxy_stream(&self, stream: AnyStream) -> io::Result<AnyStream> {
        self.wrap_stream(stream).await
    }
}

fn take_u8(data: &[u8], position: &mut usize) -> Option<u8> {
    let value = *data.get(*position)?;
    *position += 1;
    Some(value)
}

fn take_u16(data: &[u8], position: &mut usize) -> Option<u16> {
    let value =
        u16::from_be_bytes([*data.get(*position)?, *data.get(*position + 1)?]);
    *position += 2;
    Some(value)
}

fn take_slice<'a>(
    data: &'a [u8],
    position: &mut usize,
    length: usize,
) -> Option<&'a [u8]> {
    let result = data.get(*position..position.checked_add(length)?)?;
    *position += length;
    Some(result)
}

fn find_client_hello_extension<'a>(
    client_hello: &'a [u8],
    expected_kind: u16,
) -> io::Result<Option<&'a [u8]>> {
    let mut position = 0;
    if take_u8(client_hello, &mut position) != Some(0x01) {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "Restls session generator did not receive a ClientHello",
        ));
    }
    take_slice(client_hello, &mut position, 3 + 2 + 32).ok_or_else(|| {
        io::Error::new(io::ErrorKind::InvalidData, "truncated ClientHello prefix")
    })?;
    let session_len = take_u8(client_hello, &mut position).ok_or_else(|| {
        io::Error::new(io::ErrorKind::InvalidData, "missing ClientHello session ID")
    })? as usize;
    take_slice(client_hello, &mut position, session_len).ok_or_else(|| {
        io::Error::new(
            io::ErrorKind::InvalidData,
            "truncated ClientHello session ID",
        )
    })?;
    let cipher_len = take_u16(client_hello, &mut position).ok_or_else(|| {
        io::Error::new(io::ErrorKind::InvalidData, "missing ClientHello ciphers")
    })? as usize;
    take_slice(client_hello, &mut position, cipher_len).ok_or_else(|| {
        io::Error::new(io::ErrorKind::InvalidData, "truncated ClientHello ciphers")
    })?;
    let compression_len = take_u8(client_hello, &mut position).ok_or_else(|| {
        io::Error::new(
            io::ErrorKind::InvalidData,
            "missing ClientHello compression",
        )
    })? as usize;
    take_slice(client_hello, &mut position, compression_len).ok_or_else(|| {
        io::Error::new(
            io::ErrorKind::InvalidData,
            "truncated ClientHello compression",
        )
    })?;
    let extensions_len = take_u16(client_hello, &mut position).ok_or_else(|| {
        io::Error::new(io::ErrorKind::InvalidData, "missing ClientHello extensions")
    })? as usize;
    let extensions = take_slice(client_hello, &mut position, extensions_len)
        .ok_or_else(|| {
            io::Error::new(
                io::ErrorKind::InvalidData,
                "truncated ClientHello extensions",
            )
        })?;
    let mut position = 0;
    while position < extensions.len() {
        let kind = take_u16(extensions, &mut position).ok_or_else(|| {
            io::Error::new(io::ErrorKind::InvalidData, "truncated TLS extension")
        })?;
        let length = take_u16(extensions, &mut position).ok_or_else(|| {
            io::Error::new(
                io::ErrorKind::InvalidData,
                "truncated TLS extension length",
            )
        })? as usize;
        let extension =
            take_slice(extensions, &mut position, length).ok_or_else(|| {
                io::Error::new(
                    io::ErrorKind::InvalidData,
                    "truncated TLS extension body",
                )
            })?;
        if kind == expected_kind {
            return Ok(Some(extension));
        }
    }
    Ok(None)
}

fn restls_tls12_session_id(
    secret: &[u8; 32],
    public_keys: &[Vec<u8>],
    client_hello: &[u8],
) -> io::Result<[u8; 32]> {
    if public_keys.len() != 3 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "Restls TLS 1.2 requires X25519, P-256, and P-384 keys",
        ));
    }
    let ticket = find_client_hello_extension(client_hello, EXT_SESSION_TICKET)?
        .filter(|ticket| !ticket.is_empty());
    let layout: &[usize] = if ticket.is_some() {
        &[0, 8, 16, 24, 32]
    } else {
        &[0, 11, 22, 32]
    };
    let mut session_id = [0u8; 32];
    for (index, material) in public_keys
        .iter()
        .map(Vec::as_slice)
        .chain(ticket)
        .enumerate()
    {
        let digest = blake3::keyed_hash(secret, material);
        let output = &mut session_id[layout[index]..layout[index + 1]];
        output.copy_from_slice(&digest.as_bytes()[..output.len()]);
    }
    Ok(session_id)
}

fn restls_tls13_session_id(
    secret: &[u8; 32],
    client_hello: &[u8],
) -> io::Result<[u8; 32]> {
    let mut position = 0;
    if take_u8(client_hello, &mut position) != Some(0x01) {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "Restls session generator did not receive a ClientHello",
        ));
    }
    let handshake_len = {
        let bytes = take_slice(client_hello, &mut position, 3).ok_or_else(|| {
            io::Error::new(io::ErrorKind::InvalidData, "truncated ClientHello")
        })?;
        ((bytes[0] as usize) << 16) | ((bytes[1] as usize) << 8) | bytes[2] as usize
    };
    if handshake_len != client_hello.len().saturating_sub(4) {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "invalid ClientHello handshake length",
        ));
    }
    take_slice(client_hello, &mut position, 2 + 32).ok_or_else(|| {
        io::Error::new(io::ErrorKind::InvalidData, "truncated ClientHello prefix")
    })?;
    let session_len = take_u8(client_hello, &mut position).ok_or_else(|| {
        io::Error::new(io::ErrorKind::InvalidData, "missing ClientHello session ID")
    })? as usize;
    take_slice(client_hello, &mut position, session_len).ok_or_else(|| {
        io::Error::new(
            io::ErrorKind::InvalidData,
            "truncated ClientHello session ID",
        )
    })?;
    let cipher_len = take_u16(client_hello, &mut position).ok_or_else(|| {
        io::Error::new(io::ErrorKind::InvalidData, "missing ClientHello ciphers")
    })? as usize;
    take_slice(client_hello, &mut position, cipher_len).ok_or_else(|| {
        io::Error::new(io::ErrorKind::InvalidData, "truncated ClientHello ciphers")
    })?;
    let compression_len = take_u8(client_hello, &mut position).ok_or_else(|| {
        io::Error::new(
            io::ErrorKind::InvalidData,
            "missing ClientHello compression",
        )
    })? as usize;
    take_slice(client_hello, &mut position, compression_len).ok_or_else(|| {
        io::Error::new(
            io::ErrorKind::InvalidData,
            "truncated ClientHello compression",
        )
    })?;
    let extensions_len = take_u16(client_hello, &mut position).ok_or_else(|| {
        io::Error::new(io::ErrorKind::InvalidData, "missing ClientHello extensions")
    })? as usize;
    let extensions = take_slice(client_hello, &mut position, extensions_len)
        .ok_or_else(|| {
            io::Error::new(
                io::ErrorKind::InvalidData,
                "truncated ClientHello extensions",
            )
        })?;

    let mut material = Vec::new();
    let mut ext_position = 0;
    while ext_position < extensions.len() {
        let kind = take_u16(extensions, &mut ext_position).ok_or_else(|| {
            io::Error::new(io::ErrorKind::InvalidData, "truncated TLS extension")
        })?;
        let length = take_u16(extensions, &mut ext_position).ok_or_else(|| {
            io::Error::new(
                io::ErrorKind::InvalidData,
                "truncated TLS extension length",
            )
        })? as usize;
        let extension = take_slice(extensions, &mut ext_position, length)
            .ok_or_else(|| {
                io::Error::new(
                    io::ErrorKind::InvalidData,
                    "truncated TLS extension body",
                )
            })?;
        match kind {
            EXT_KEY_SHARE => {
                let mut share_position = 0;
                let share_len =
                    take_u16(extension, &mut share_position).ok_or_else(|| {
                        io::Error::new(
                            io::ErrorKind::InvalidData,
                            "invalid key_share extension",
                        )
                    })? as usize;
                let shares = take_slice(extension, &mut share_position, share_len)
                    .ok_or_else(|| {
                    io::Error::new(
                        io::ErrorKind::InvalidData,
                        "truncated key_share extension",
                    )
                })?;
                let mut position = 0;
                while position < shares.len() {
                    let group =
                        take_u16(shares, &mut position).ok_or_else(|| {
                            io::Error::new(
                                io::ErrorKind::InvalidData,
                                "truncated key_share group",
                            )
                        })?;
                    let key_len =
                        take_u16(shares, &mut position).ok_or_else(|| {
                            io::Error::new(
                                io::ErrorKind::InvalidData,
                                "truncated key_share length",
                            )
                        })? as usize;
                    let key = take_slice(shares, &mut position, key_len)
                        .ok_or_else(|| {
                            io::Error::new(
                                io::ErrorKind::InvalidData,
                                "truncated key_share key",
                            )
                        })?;
                    material.extend_from_slice(&group.to_be_bytes());
                    material.extend_from_slice(key);
                }
            }
            EXT_PRE_SHARED_KEY => {
                let mut psk_position = 0;
                let identities_len = take_u16(extension, &mut psk_position)
                    .ok_or_else(|| {
                        io::Error::new(
                            io::ErrorKind::InvalidData,
                            "invalid PSK extension",
                        )
                    })? as usize;
                let identities =
                    take_slice(extension, &mut psk_position, identities_len)
                        .ok_or_else(|| {
                            io::Error::new(
                                io::ErrorKind::InvalidData,
                                "truncated PSK identities",
                            )
                        })?;
                let mut position = 0;
                while position < identities.len() {
                    let identity_len = take_u16(identities, &mut position)
                        .ok_or_else(|| {
                            io::Error::new(
                                io::ErrorKind::InvalidData,
                                "truncated PSK identity length",
                            )
                        })? as usize;
                    let identity =
                        take_slice(identities, &mut position, identity_len)
                            .ok_or_else(|| {
                                io::Error::new(
                                    io::ErrorKind::InvalidData,
                                    "truncated PSK identity",
                                )
                            })?;
                    material.extend_from_slice(identity);
                    take_slice(identities, &mut position, 4).ok_or_else(|| {
                        io::Error::new(
                            io::ErrorKind::InvalidData,
                            "truncated PSK ticket age",
                        )
                    })?;
                }
            }
            _ => {}
        }
    }
    if material.is_empty() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "Restls ClientHello has no TLS 1.3 key share",
        ));
    }
    let digest = blake3::keyed_hash(secret, &material);
    let mut session_id = [0u8; 32];
    rand::fill(&mut session_id[RESTLS_HANDSHAKE_AUTH_LEN..]);
    session_id[..RESTLS_HANDSHAKE_AUTH_LEN]
        .copy_from_slice(&digest.as_bytes()[..RESTLS_HANDSHAKE_AUTH_LEN]);
    Ok(session_id)
}

struct HandshakeParts {
    raw: AnyStream,
    server_random: [u8; 32],
    client_finished: Vec<u8>,
    prefetched: BytesMut,
    cover_records: u64,
    tls12_gcm: bool,
    server_gcm_nonce: bool,
}

struct HandshakeCapture {
    raw: AnyStream,
    secret: [u8; 32],
    version_hint: VersionHint,
    read_pending: BytesMut,
    read_output: BytesMut,
    write_pending: BytesMut,
    server_random: Option<[u8; 32]>,
    server_ccs: bool,
    server_auth_unmasked: bool,
    client_ccs: bool,
    client_finished: Option<Vec<u8>>,
    cover_records: u64,
    tls12_gcm: bool,
    server_gcm_nonce: bool,
}

impl HandshakeCapture {
    fn new(raw: AnyStream, secret: [u8; 32], version_hint: VersionHint) -> Self {
        Self {
            raw,
            secret,
            version_hint,
            read_pending: BytesMut::new(),
            read_output: BytesMut::new(),
            write_pending: BytesMut::new(),
            server_random: None,
            server_ccs: false,
            server_auth_unmasked: false,
            client_ccs: false,
            client_finished: None,
            cover_records: 0,
            tls12_gcm: false,
            server_gcm_nonce: false,
        }
    }

    fn record_length(buffer: &[u8]) -> io::Result<Option<usize>> {
        if buffer.len() < TLS_HEADER_LEN {
            return Ok(None);
        }
        let payload_len = u16::from_be_bytes([buffer[3], buffer[4]]) as usize;
        let record_len = TLS_HEADER_LEN + payload_len;
        if record_len > MAX_TLS_RECORD_LEN {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "oversized TLS record during Restls handshake",
            ));
        }
        Ok((buffer.len() >= record_len).then_some(record_len))
    }

    fn process_server_record(&mut self, record: &mut [u8]) -> io::Result<()> {
        match record.first().copied() {
            Some(RECORD_HANDSHAKE)
                if self.server_random.is_none()
                    && record.get(TLS_HEADER_LEN)
                        == Some(&HANDSHAKE_SERVER_HELLO) =>
            {
                let random = record.get(11..43).ok_or_else(|| {
                    io::Error::new(
                        io::ErrorKind::InvalidData,
                        "truncated TLS ServerHello",
                    )
                })?;
                self.server_random = Some(random.try_into().unwrap());
                if self.version_hint == VersionHint::Tls12 {
                    let session_len = *record.get(43).ok_or_else(|| {
                        io::Error::new(
                            io::ErrorKind::InvalidData,
                            "truncated TLS 1.2 ServerHello session ID",
                        )
                    })? as usize;
                    let cipher_offset = 44 + session_len;
                    let cipher = u16::from_be_bytes([
                        *record.get(cipher_offset).ok_or_else(|| {
                            io::Error::new(
                                io::ErrorKind::InvalidData,
                                "truncated TLS 1.2 ServerHello cipher",
                            )
                        })?,
                        *record.get(cipher_offset + 1).ok_or_else(|| {
                            io::Error::new(
                                io::ErrorKind::InvalidData,
                                "truncated TLS 1.2 ServerHello cipher",
                            )
                        })?,
                    ]);
                    self.tls12_gcm =
                        matches!(cipher, 0xc02f | 0xc02b | 0xc030 | 0xc02c);
                }
            }
            Some(RECORD_CCS) => self.server_ccs = true,
            Some(record_type)
                if self.server_ccs
                    && !self.server_auth_unmasked
                    && ((self.version_hint == VersionHint::Tls13
                        && record_type == RECORD_APPLICATION_DATA)
                        || (self.version_hint == VersionHint::Tls12
                            && record_type == RECORD_HANDSHAKE)) =>
            {
                let server_random = self.server_random.ok_or_else(|| {
                    io::Error::new(
                        io::ErrorKind::InvalidData,
                        "Restls server auth arrived before ServerHello",
                    )
                })?;
                let digest = blake3::keyed_hash(&self.secret, &server_random);
                let mask_offset = if self.tls12_gcm
                    && record.get(TLS_HEADER_LEN..TLS_HEADER_LEN + 8)
                        == Some(&[0u8; 8])
                {
                    self.server_gcm_nonce = true;
                    TLS_HEADER_LEN + 8
                } else {
                    TLS_HEADER_LEN
                };
                let body = record.get_mut(mask_offset..).ok_or_else(|| {
                    io::Error::new(
                        io::ErrorKind::InvalidData,
                        "empty Restls server auth",
                    )
                })?;
                for (byte, mask) in body
                    .iter_mut()
                    .zip(digest.as_bytes()[..RESTLS_HANDSHAKE_AUTH_LEN].iter())
                {
                    *byte ^= mask;
                }
                self.server_auth_unmasked = true;
            }
            Some(RECORD_APPLICATION_DATA) if self.server_auth_unmasked => {
                self.cover_records += 1;
            }
            _ => {}
        }
        Ok(())
    }

    fn process_client_records(&mut self) -> io::Result<()> {
        while let Some(length) = Self::record_length(&self.write_pending)? {
            let record = self.write_pending.split_to(length);
            match record.first().copied() {
                Some(RECORD_CCS) => self.client_ccs = true,
                Some(record_type)
                    if record_type != RECORD_CCS
                        && self.client_ccs
                        && self.client_finished.is_none() =>
                {
                    self.client_finished = Some(record.to_vec());
                }
                _ => {}
            }
        }
        Ok(())
    }

    fn into_parts(self) -> io::Result<HandshakeParts> {
        let server_random = self.server_random.ok_or_else(|| {
            io::Error::new(
                io::ErrorKind::InvalidData,
                "Restls handshake did not expose a ServerHello random",
            )
        })?;
        if !self.server_auth_unmasked {
            return Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                "Restls server authentication record was not received",
            ));
        }
        let client_finished = self.client_finished.ok_or_else(|| {
            io::Error::new(
                io::ErrorKind::InvalidData,
                "Restls handshake did not capture Client Finished",
            )
        })?;
        let mut prefetched = self.read_output;
        prefetched.extend_from_slice(&self.read_pending);
        Ok(HandshakeParts {
            raw: self.raw,
            server_random,
            client_finished,
            prefetched,
            cover_records: self.cover_records,
            tls12_gcm: self.tls12_gcm,
            server_gcm_nonce: self.server_gcm_nonce,
        })
    }
}

impl AsyncRead for HandshakeCapture {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buffer: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        loop {
            if !self.read_output.is_empty() {
                let count = buffer.remaining().min(self.read_output.len());
                buffer.put_slice(&self.read_output.split_to(count));
                return Poll::Ready(Ok(()));
            }

            match Self::record_length(&self.read_pending) {
                Ok(Some(length)) => {
                    let mut record = self.read_pending.split_to(length);
                    if let Err(error) = self.process_server_record(&mut record) {
                        return Poll::Ready(Err(error));
                    }
                    self.read_output.extend_from_slice(&record);
                    continue;
                }
                Ok(None) => {}
                Err(error) => return Poll::Ready(Err(error)),
            }

            let mut temporary = [0u8; 16_384];
            let mut read = ReadBuf::new(&mut temporary);
            match Pin::new(&mut self.raw).poll_read(cx, &mut read) {
                Poll::Ready(Ok(())) if read.filled().is_empty() => {
                    if self.read_pending.is_empty() {
                        return Poll::Ready(Ok(()));
                    }
                    return Poll::Ready(Err(io::Error::new(
                        io::ErrorKind::UnexpectedEof,
                        "truncated TLS record during Restls handshake",
                    )));
                }
                Poll::Ready(Ok(())) => {
                    self.read_pending.extend_from_slice(read.filled());
                }
                Poll::Ready(Err(error)) => return Poll::Ready(Err(error)),
                Poll::Pending => return Poll::Pending,
            }
        }
    }
}

impl AsyncWrite for HandshakeCapture {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buffer: &[u8],
    ) -> Poll<io::Result<usize>> {
        match Pin::new(&mut self.raw).poll_write(cx, buffer) {
            Poll::Ready(Ok(count)) => {
                self.write_pending.extend_from_slice(&buffer[..count]);
                if let Err(error) = self.process_client_records() {
                    return Poll::Ready(Err(error));
                }
                Poll::Ready(Ok(count))
            }
            other => other,
        }
    }

    fn poll_flush(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<io::Result<()>> {
        Pin::new(&mut self.raw).poll_flush(cx)
    }

    fn poll_shutdown(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<io::Result<()>> {
        Pin::new(&mut self.raw).poll_shutdown(cx)
    }
}

struct RestlsStream {
    raw: AnyStream,
    secret: [u8; 32],
    server_random: [u8; 32],
    client_finished: Option<Vec<u8>>,
    script: Vec<ScriptLine>,
    to_server_counter: u64,
    to_client_counter: u64,
    awaiting_response: bool,
    pending_plain: VecDeque<u8>,
    pending_write: BytesMut,
    pending_write_position: usize,
    pending_read: BytesMut,
    plain_read: VecDeque<u8>,
    eof: bool,
    tls12_gcm: bool,
    server_gcm_nonce: bool,
}

impl RestlsStream {
    #[allow(clippy::too_many_arguments)]
    fn new(
        raw: AnyStream,
        secret: [u8; 32],
        server_random: [u8; 32],
        client_finished: Vec<u8>,
        script: Vec<ScriptLine>,
        prefetched: BytesMut,
        cover_records: u64,
        tls12_gcm: bool,
        server_gcm_nonce: bool,
    ) -> Self {
        Self {
            raw,
            secret,
            server_random,
            client_finished: Some(client_finished),
            script,
            to_server_counter: 0,
            to_client_counter: cover_records,
            awaiting_response: false,
            pending_plain: VecDeque::new(),
            pending_write: BytesMut::new(),
            pending_write_position: 0,
            pending_read: prefetched,
            plain_read: VecDeque::new(),
            eof: false,
            tls12_gcm,
            server_gcm_nonce,
        }
    }

    fn auth_hasher(&self, to_client: bool, counter: u64) -> blake3::Hasher {
        let mut hasher = blake3::Hasher::new_keyed(&self.secret);
        hasher.update(&self.server_random);
        hasher.update(if to_client {
            TO_CLIENT_MAGIC
        } else {
            TO_SERVER_MAGIC
        });
        hasher.update(&counter.to_be_bytes());
        hasher
    }

    fn encode_record(&mut self, fake_response: bool) -> io::Result<bool> {
        let wire_prefix_len = TLS_HEADER_LEN + if self.tls12_gcm { 8 } else { 0 };
        let data_offset = wire_prefix_len + RESTLS_DATA_OFFSET;
        let max_plaintext = 16_384 - RESTLS_DATA_OFFSET - (wire_prefix_len - 5);
        let line = self.script.get(self.to_server_counter as usize);
        let available = self.pending_plain.len();
        let (data_len, padding_len, command) = if let Some(line) = line {
            let target = line.target.resolve();
            let data_len = available.min(target).min(max_plaintext);
            let padding_len = target
                .saturating_sub(data_len)
                .min(max_plaintext - data_len);
            (data_len, padding_len, line.command)
        } else if fake_response && available == 0 {
            (0, 19 + rand::rng().random_range(0..100), Command::Noop)
        } else {
            (available.min(max_plaintext), 0, Command::Noop)
        };
        if data_len == 0 && padding_len == 0 && !fake_response {
            return Ok(false);
        }

        let payload_len = wire_prefix_len - TLS_HEADER_LEN
            + RESTLS_DATA_OFFSET
            + data_len
            + padding_len;
        let mut record = vec![0u8; TLS_HEADER_LEN + payload_len];
        record[0..3].copy_from_slice(&[RECORD_APPLICATION_DATA, 0x03, 0x03]);
        record[3..5].copy_from_slice(&(payload_len as u16).to_be_bytes());
        if self.tls12_gcm {
            record[TLS_HEADER_LEN..wire_prefix_len]
                .copy_from_slice(&(self.to_server_counter + 1).to_be_bytes());
        }
        for destination in &mut record[data_offset..data_offset + data_len] {
            *destination = self.pending_plain.pop_front().unwrap();
        }
        rand::fill(&mut record[data_offset + data_len..]);

        let mut mask_hasher = self.auth_hasher(false, self.to_server_counter);
        let sample_end = (data_offset + 32).min(record.len());
        mask_hasher.update(&record[data_offset..sample_end]);
        let mask = mask_hasher.finalize();
        let mut masked = [0u8; RESTLS_MASK_LEN];
        masked[..2].copy_from_slice(&(data_len as u16).to_be_bytes());
        masked[2..].copy_from_slice(&command.to_bytes());
        for (value, mask) in masked.iter_mut().zip(mask.as_bytes()) {
            *value ^= mask;
        }
        record[wire_prefix_len + RESTLS_AUTH_LEN
            ..wire_prefix_len + RESTLS_DATA_OFFSET]
            .copy_from_slice(&masked);

        let mut auth = self.auth_hasher(false, self.to_server_counter);
        if let Some(client_finished) = self.client_finished.take() {
            auth.update(&client_finished);
        }
        auth.update(&record[..wire_prefix_len]);
        auth.update(&record[wire_prefix_len + RESTLS_AUTH_LEN..]);
        let auth = auth.finalize();
        record[wire_prefix_len..wire_prefix_len + RESTLS_AUTH_LEN]
            .copy_from_slice(&auth.as_bytes()[..RESTLS_AUTH_LEN]);

        self.pending_write.extend_from_slice(&record);
        self.to_server_counter += 1;
        if command.interrupts() && !fake_response {
            self.awaiting_response = true;
        }
        Ok(true)
    }

    fn encode_available(&mut self) -> io::Result<usize> {
        let mut records = 0;
        while !self.awaiting_response && !self.pending_plain.is_empty() {
            if !self.encode_record(false)? {
                break;
            }
            records += 1;
        }
        Ok(records)
    }

    fn drain_writes(&mut self, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        while self.pending_write_position < self.pending_write.len() {
            match Pin::new(&mut self.raw)
                .poll_write(cx, &self.pending_write[self.pending_write_position..])
            {
                Poll::Ready(Ok(0)) => {
                    return Poll::Ready(Err(io::Error::new(
                        io::ErrorKind::WriteZero,
                        "failed to write Restls record",
                    )));
                }
                Poll::Ready(Ok(count)) => self.pending_write_position += count,
                Poll::Ready(Err(error)) => return Poll::Ready(Err(error)),
                Poll::Pending => return Poll::Pending,
            }
        }
        self.pending_write.clear();
        self.pending_write_position = 0;
        Poll::Ready(Ok(()))
    }

    fn parse_server_record(&mut self, mut record: BytesMut) -> io::Result<()> {
        match record.first().copied() {
            Some(RECORD_ALERT) => {
                self.eof = true;
                return Ok(());
            }
            Some(RECORD_APPLICATION_DATA) => {}
            _ => return Ok(()),
        }
        let wire_prefix_len = TLS_HEADER_LEN
            + if self.tls12_gcm && self.server_gcm_nonce {
                8
            } else {
                0
            };
        let data_offset = wire_prefix_len + RESTLS_DATA_OFFSET;
        if record.len() < data_offset {
            self.to_client_counter += 1;
            return Ok(());
        }
        if wire_prefix_len > TLS_HEADER_LEN {
            let nonce = u64::from_be_bytes(
                record[TLS_HEADER_LEN..wire_prefix_len].try_into().unwrap(),
            );
            if nonce != self.to_client_counter + 1 {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "invalid Restls TLS 1.2 GCM server record counter",
                ));
            }
        }

        let mut auth = self.auth_hasher(true, self.to_client_counter);
        auth.update(&record[..wire_prefix_len]);
        auth.update(&record[wire_prefix_len + RESTLS_AUTH_LEN..]);
        let expected = auth.finalize();
        if record[wire_prefix_len..wire_prefix_len + RESTLS_AUTH_LEN]
            != expected.as_bytes()[..RESTLS_AUTH_LEN]
        {
            // Genuine post-handshake traffic from the cover TLS connection is
            // intentionally ignored but still consumes a Restls receive counter.
            self.to_client_counter += 1;
            return Ok(());
        }

        let sample_end = (data_offset + 32).min(record.len());
        let mut mask = self.auth_hasher(true, self.to_client_counter);
        mask.update(&record[data_offset..sample_end]);
        let mask = mask.finalize();
        let masked = &mut record[wire_prefix_len + RESTLS_AUTH_LEN
            ..wire_prefix_len + RESTLS_DATA_OFFSET];
        for (value, mask) in masked.iter_mut().zip(mask.as_bytes()) {
            *value ^= mask;
        }
        let data_len = u16::from_be_bytes([masked[0], masked[1]]) as usize;
        let command = Command::from_bytes(&masked[2..])?;
        if data_len > record.len() - data_offset {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "Restls record data length exceeds its payload",
            ));
        }
        self.plain_read
            .extend(&record[data_offset..data_offset + data_len]);
        self.to_client_counter += 1;

        let sent = if self.awaiting_response {
            self.awaiting_response = false;
            self.encode_available()?
        } else {
            0
        };
        if let Command::Response(mut count) = command {
            if sent > 0 {
                count = count.saturating_sub(1);
            }
            for _ in 0..count {
                self.encode_record(true)?;
            }
        }
        Ok(())
    }

    fn parse_pending_records(&mut self) -> io::Result<()> {
        while let Some(length) = HandshakeCapture::record_length(&self.pending_read)?
        {
            let record = self.pending_read.split_to(length);
            self.parse_server_record(record)?;
            if !self.plain_read.is_empty() || self.eof {
                break;
            }
        }
        Ok(())
    }
}

impl AsyncRead for RestlsStream {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buffer: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        loop {
            match self.drain_writes(cx) {
                Poll::Ready(Ok(())) => {}
                Poll::Ready(Err(error)) => return Poll::Ready(Err(error)),
                Poll::Pending => return Poll::Pending,
            }
            if let Err(error) = self.parse_pending_records() {
                return Poll::Ready(Err(error));
            }
            if !self.plain_read.is_empty() {
                let count = buffer.remaining().min(self.plain_read.len());
                let (front, back) = self.plain_read.as_slices();
                if count <= front.len() {
                    buffer.put_slice(&front[..count]);
                } else {
                    buffer.put_slice(front);
                    buffer.put_slice(&back[..count - front.len()]);
                }
                self.plain_read.drain(..count);
                return Poll::Ready(Ok(()));
            }
            if self.eof {
                return Poll::Ready(Ok(()));
            }

            let mut temporary = [0u8; 16_384];
            let mut read = ReadBuf::new(&mut temporary);
            match Pin::new(&mut self.raw).poll_read(cx, &mut read) {
                Poll::Ready(Ok(())) if read.filled().is_empty() => {
                    self.eof = true;
                    return Poll::Ready(Ok(()));
                }
                Poll::Ready(Ok(())) => {
                    self.pending_read.extend_from_slice(read.filled());
                }
                Poll::Ready(Err(error)) => return Poll::Ready(Err(error)),
                Poll::Pending => return Poll::Pending,
            }
        }
    }
}

impl AsyncWrite for RestlsStream {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buffer: &[u8],
    ) -> Poll<io::Result<usize>> {
        if self
            .pending_write
            .len()
            .saturating_sub(self.pending_write_position)
            > 1024 * 1024
        {
            match self.drain_writes(cx) {
                Poll::Ready(Ok(())) => {}
                Poll::Ready(Err(error)) => return Poll::Ready(Err(error)),
                Poll::Pending => return Poll::Pending,
            }
        }
        self.pending_plain.extend(buffer);
        if let Err(error) = self.encode_available() {
            return Poll::Ready(Err(error));
        }
        match self.drain_writes(cx) {
            Poll::Ready(Err(error)) => Poll::Ready(Err(error)),
            Poll::Ready(Ok(())) | Poll::Pending => Poll::Ready(Ok(buffer.len())),
        }
    }

    fn poll_flush(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<io::Result<()>> {
        if let Err(error) = self.encode_available() {
            return Poll::Ready(Err(error));
        }
        match self.drain_writes(cx) {
            Poll::Ready(Ok(())) => Pin::new(&mut self.raw).poll_flush(cx),
            other => other,
        }
    }

    fn poll_shutdown(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<io::Result<()>> {
        match self.as_mut().poll_flush(cx) {
            Poll::Ready(Ok(())) => Pin::new(&mut self.raw).poll_shutdown(cx),
            other => other,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::io::{AsyncReadExt, AsyncWriteExt, DuplexStream};
    use tokio_rustls::TlsAcceptor;

    struct ServerHandshakeCapture {
        raw: DuplexStream,
        secret: [u8; 32],
        read_pending: BytesMut,
        read_output: BytesMut,
        version_hint: VersionHint,
        client_hello: Option<Vec<u8>>,
        client_key_exchange: Option<Vec<u8>>,
        client_ccs: bool,
        client_finished: Option<Vec<u8>>,
        server_random: Option<[u8; 32]>,
        server_ccs: bool,
        server_auth_masked: bool,
        selected_group: Option<u16>,
        tls12_gcm: bool,
        server_gcm_nonce: bool,
    }

    impl ServerHandshakeCapture {
        fn new(
            raw: DuplexStream,
            secret: [u8; 32],
            version_hint: VersionHint,
        ) -> Self {
            Self {
                raw,
                secret,
                read_pending: BytesMut::new(),
                read_output: BytesMut::new(),
                version_hint,
                client_hello: None,
                client_key_exchange: None,
                client_ccs: false,
                client_finished: None,
                server_random: None,
                server_ccs: false,
                server_auth_masked: false,
                selected_group: None,
                tls12_gcm: false,
                server_gcm_nonce: false,
            }
        }

        fn inspect_client_record(&mut self, record: &[u8]) {
            match record.first().copied() {
                Some(RECORD_HANDSHAKE)
                    if record.get(TLS_HEADER_LEN) == Some(&0x01)
                        && self.client_hello.is_none() =>
                {
                    self.client_hello = Some(record.to_vec());
                }
                Some(RECORD_HANDSHAKE)
                    if record.get(TLS_HEADER_LEN) == Some(&0x10)
                        && self.client_key_exchange.is_none() =>
                {
                    self.client_key_exchange = Some(record.to_vec());
                }
                Some(RECORD_CCS) => self.client_ccs = true,
                Some(record_type)
                    if record_type != RECORD_CCS
                        && self.client_ccs
                        && self.client_finished.is_none() =>
                {
                    self.client_finished = Some(record.to_vec());
                }
                _ => {}
            }
        }

        fn transform_server_records(
            &mut self,
            buffer: &[u8],
        ) -> io::Result<Vec<u8>> {
            let mut output = buffer.to_vec();
            let mut position = 0;
            while position < output.len() {
                let length = HandshakeCapture::record_length(&output[position..])?
                    .ok_or_else(|| {
                    io::Error::new(
                        io::ErrorKind::InvalidData,
                        "test TLS server emitted a partial record",
                    )
                })?;
                let record = &mut output[position..position + length];
                match record.first().copied() {
                    Some(RECORD_HANDSHAKE)
                        if self.server_random.is_none()
                            && record.get(TLS_HEADER_LEN)
                                == Some(&HANDSHAKE_SERVER_HELLO) =>
                    {
                        self.server_random =
                            Some(record[11..43].try_into().unwrap());
                        if self.version_hint == VersionHint::Tls12 {
                            let session_len = record[43] as usize;
                            let cipher_offset = 44 + session_len;
                            let cipher = u16::from_be_bytes([
                                record[cipher_offset],
                                record[cipher_offset + 1],
                            ]);
                            self.tls12_gcm =
                                matches!(cipher, 0xc02f | 0xc02b | 0xc030 | 0xc02c);
                        }
                    }
                    Some(RECORD_HANDSHAKE)
                        if self.version_hint == VersionHint::Tls12
                            && record.get(TLS_HEADER_LEN) == Some(&0x0c) =>
                    {
                        self.selected_group = Some(u16::from_be_bytes([
                            record[TLS_HEADER_LEN + 5],
                            record[TLS_HEADER_LEN + 6],
                        ]));
                    }
                    Some(RECORD_CCS) => self.server_ccs = true,
                    Some(record_type)
                        if self.server_ccs
                            && !self.server_auth_masked
                            && ((self.version_hint == VersionHint::Tls13
                                && record_type == RECORD_APPLICATION_DATA)
                                || (self.version_hint == VersionHint::Tls12
                                    && record_type == RECORD_HANDSHAKE)) =>
                    {
                        let random = self.server_random.unwrap();
                        let mask = blake3::keyed_hash(&self.secret, &random);
                        let mask_offset = if self.tls12_gcm
                            && record[TLS_HEADER_LEN..TLS_HEADER_LEN + 8] == [0u8; 8]
                        {
                            self.server_gcm_nonce = true;
                            TLS_HEADER_LEN + 8
                        } else {
                            TLS_HEADER_LEN
                        };
                        for (byte, mask) in record[mask_offset..]
                            .iter_mut()
                            .zip(mask.as_bytes()[..RESTLS_HANDSHAKE_AUTH_LEN].iter())
                        {
                            *byte ^= mask;
                        }
                        self.server_auth_masked = true;
                    }
                    _ => {}
                }
                position += length;
            }
            Ok(output)
        }
    }

    impl AsyncRead for ServerHandshakeCapture {
        fn poll_read(
            mut self: Pin<&mut Self>,
            cx: &mut Context<'_>,
            buffer: &mut ReadBuf<'_>,
        ) -> Poll<io::Result<()>> {
            loop {
                if !self.read_output.is_empty() {
                    let count = buffer.remaining().min(self.read_output.len());
                    buffer.put_slice(&self.read_output.split_to(count));
                    return Poll::Ready(Ok(()));
                }
                // The next 0x17 is already a Restls application record. Keep it
                // away from rustls after delivering Client Finished; the real
                // Restls server makes the same protocol-layer transition here.
                if self.client_finished.is_some() {
                    return Poll::Pending;
                }
                match HandshakeCapture::record_length(&self.read_pending) {
                    Ok(Some(length)) => {
                        let record = self.read_pending.split_to(length);
                        self.inspect_client_record(&record);
                        self.read_output.extend_from_slice(&record);
                        continue;
                    }
                    Ok(None) => {}
                    Err(error) => return Poll::Ready(Err(error)),
                }

                let mut temporary = [0u8; 16_384];
                let mut read = ReadBuf::new(&mut temporary);
                match Pin::new(&mut self.raw).poll_read(cx, &mut read) {
                    Poll::Ready(Ok(())) if read.filled().is_empty() => {
                        return Poll::Ready(Ok(()));
                    }
                    Poll::Ready(Ok(())) => {
                        self.read_pending.extend_from_slice(read.filled());
                    }
                    Poll::Ready(Err(error)) => return Poll::Ready(Err(error)),
                    Poll::Pending => return Poll::Pending,
                }
            }
        }
    }

    impl AsyncWrite for ServerHandshakeCapture {
        fn poll_write(
            mut self: Pin<&mut Self>,
            cx: &mut Context<'_>,
            buffer: &[u8],
        ) -> Poll<io::Result<usize>> {
            let output = match self.transform_server_records(buffer) {
                Ok(output) => output,
                Err(error) => return Poll::Ready(Err(error)),
            };
            Pin::new(&mut self.raw).poll_write(cx, &output)
        }

        fn poll_flush(
            mut self: Pin<&mut Self>,
            cx: &mut Context<'_>,
        ) -> Poll<io::Result<()>> {
            Pin::new(&mut self.raw).poll_flush(cx)
        }

        fn poll_shutdown(
            mut self: Pin<&mut Self>,
            cx: &mut Context<'_>,
        ) -> Poll<io::Result<()>> {
            Pin::new(&mut self.raw).poll_shutdown(cx)
        }
    }

    fn verify_client_hello_auth(secret: &[u8; 32], record: &[u8]) -> io::Result<()> {
        let mut hello = record
            .get(TLS_HEADER_LEN..)
            .ok_or_else(|| {
                io::Error::new(io::ErrorKind::InvalidData, "missing ClientHello")
            })?
            .to_vec();
        let session_offset = 4 + 2 + 32 + 1;
        if hello.get(session_offset - 1) != Some(&32) {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "Restls ClientHello session ID is not 32 bytes",
            ));
        }
        let actual = hello
            [session_offset..session_offset + RESTLS_HANDSHAKE_AUTH_LEN]
            .to_vec();
        hello[session_offset..session_offset + 32].fill(0);
        let expected = restls_tls13_session_id(secret, &hello)?;
        if actual != expected[..RESTLS_HANDSHAKE_AUTH_LEN] {
            return Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                "invalid Restls TLS 1.3 ClientHello authentication",
            ));
        }
        Ok(())
    }

    fn verify_tls12_client_auth(
        secret: &[u8; 32],
        client_hello_record: &[u8],
        client_key_exchange_record: &[u8],
        selected_group: u16,
    ) -> io::Result<()> {
        let hello = client_hello_record.get(TLS_HEADER_LEN..).ok_or_else(|| {
            io::Error::new(io::ErrorKind::InvalidData, "missing TLS 1.2 ClientHello")
        })?;
        let session_offset = 4 + 2 + 32 + 1;
        if hello.get(session_offset - 1) != Some(&32) {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "Restls TLS 1.2 session ID is not 32 bytes",
            ));
        }
        let ticket = find_client_hello_extension(hello, EXT_SESSION_TICKET)?
            .filter(|ticket| !ticket.is_empty());
        let layout: &[usize] = if ticket.is_some() {
            &[0, 8, 16, 24, 32]
        } else {
            &[0, 11, 22, 32]
        };
        let group_index = match selected_group {
            29 => 0,
            23 => 1,
            24 => 2,
            _ => {
                return Err(io::Error::new(
                    io::ErrorKind::Unsupported,
                    format!(
                        "unsupported Restls TLS 1.2 ECDHE group {selected_group}"
                    ),
                ));
            }
        };
        let key_exchange = client_key_exchange_record
            .get(TLS_HEADER_LEN..)
            .ok_or_else(|| {
                io::Error::new(
                    io::ErrorKind::InvalidData,
                    "missing ClientKeyExchange",
                )
            })?;
        if key_exchange.first() != Some(&0x10) {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "invalid ClientKeyExchange handshake type",
            ));
        }
        let public_key_len = *key_exchange.get(4).ok_or_else(|| {
            io::Error::new(io::ErrorKind::InvalidData, "truncated ClientKeyExchange")
        })? as usize;
        let public_key =
            key_exchange.get(5..5 + public_key_len).ok_or_else(|| {
                io::Error::new(
                    io::ErrorKind::InvalidData,
                    "truncated ClientKeyExchange public key",
                )
            })?;
        let digest = blake3::keyed_hash(secret, public_key);
        let expected =
            &digest.as_bytes()[..layout[group_index + 1] - layout[group_index]];
        let actual = &hello[session_offset + layout[group_index]
            ..session_offset + layout[group_index + 1]];
        if actual != expected {
            return Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                "invalid Restls TLS 1.2 ClientKeyExchange authentication",
            ));
        }
        Ok(())
    }

    async fn read_raw_record(
        stream: &mut DuplexStream,
        prefetched: &mut BytesMut,
    ) -> io::Result<Vec<u8>> {
        while prefetched.len() < TLS_HEADER_LEN {
            if stream.read_buf(prefetched).await? == 0 {
                return Err(io::Error::new(
                    io::ErrorKind::UnexpectedEof,
                    "truncated Restls test record header",
                ));
            }
        }
        let payload_len =
            u16::from_be_bytes([prefetched[3], prefetched[4]]) as usize;
        let record_len = TLS_HEADER_LEN + payload_len;
        while prefetched.len() < record_len {
            if stream.read_buf(prefetched).await? == 0 {
                return Err(io::Error::new(
                    io::ErrorKind::UnexpectedEof,
                    "truncated Restls test record body",
                ));
            }
        }
        Ok(prefetched.split_to(record_len).to_vec())
    }

    fn decode_client_record(
        secret: &[u8; 32],
        server_random: &[u8; 32],
        client_finished: &[u8],
        counter: u64,
        tls12_gcm: bool,
        mut record: Vec<u8>,
    ) -> io::Result<(Vec<u8>, Command)> {
        let wire_prefix_len = TLS_HEADER_LEN + if tls12_gcm { 8 } else { 0 };
        let data_offset = wire_prefix_len + RESTLS_DATA_OFFSET;
        if tls12_gcm
            && u64::from_be_bytes(
                record[TLS_HEADER_LEN..wire_prefix_len].try_into().unwrap(),
            ) != counter + 1
        {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "invalid client Restls TLS 1.2 GCM counter",
            ));
        }
        let mut auth = blake3::Hasher::new_keyed(secret);
        auth.update(server_random);
        auth.update(TO_SERVER_MAGIC);
        auth.update(&counter.to_be_bytes());
        auth.update(client_finished);
        auth.update(&record[..wire_prefix_len]);
        auth.update(&record[wire_prefix_len + RESTLS_AUTH_LEN..]);
        let expected = auth.finalize();
        if record[wire_prefix_len..wire_prefix_len + RESTLS_AUTH_LEN]
            != expected.as_bytes()[..RESTLS_AUTH_LEN]
        {
            return Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                "invalid client Restls application record",
            ));
        }
        let mut mask = blake3::Hasher::new_keyed(secret);
        mask.update(server_random);
        mask.update(TO_SERVER_MAGIC);
        mask.update(&counter.to_be_bytes());
        let sample_end = (data_offset + 32).min(record.len());
        mask.update(&record[data_offset..sample_end]);
        let mask = mask.finalize();
        let masked = &mut record[wire_prefix_len + RESTLS_AUTH_LEN
            ..wire_prefix_len + RESTLS_DATA_OFFSET];
        for (value, mask) in masked.iter_mut().zip(mask.as_bytes()) {
            *value ^= mask;
        }
        let length = u16::from_be_bytes([masked[0], masked[1]]) as usize;
        let command = Command::from_bytes(&masked[2..])?;
        Ok((record[data_offset..data_offset + length].to_vec(), command))
    }

    fn encode_server_record(
        secret: &[u8; 32],
        server_random: &[u8; 32],
        counter: u64,
        tls12_gcm: bool,
        data: &[u8],
        command: Command,
    ) -> Vec<u8> {
        let wire_prefix_len = TLS_HEADER_LEN + if tls12_gcm { 8 } else { 0 };
        let data_offset = wire_prefix_len + RESTLS_DATA_OFFSET;
        let payload_len =
            wire_prefix_len - TLS_HEADER_LEN + RESTLS_DATA_OFFSET + data.len();
        let mut record = vec![0u8; TLS_HEADER_LEN + payload_len];
        record[..3].copy_from_slice(&[RECORD_APPLICATION_DATA, 3, 3]);
        record[3..5].copy_from_slice(&(payload_len as u16).to_be_bytes());
        if tls12_gcm {
            record[TLS_HEADER_LEN..wire_prefix_len]
                .copy_from_slice(&(counter + 1).to_be_bytes());
        }
        record[data_offset..].copy_from_slice(data);

        let mut mask = blake3::Hasher::new_keyed(secret);
        mask.update(server_random);
        mask.update(TO_CLIENT_MAGIC);
        mask.update(&counter.to_be_bytes());
        let sample_end = (data_offset + 32).min(record.len());
        mask.update(&record[data_offset..sample_end]);
        let mask = mask.finalize();
        let mut masked = [0u8; RESTLS_MASK_LEN];
        masked[..2].copy_from_slice(&(data.len() as u16).to_be_bytes());
        masked[2..].copy_from_slice(&command.to_bytes());
        for (value, mask) in masked.iter_mut().zip(mask.as_bytes()) {
            *value ^= mask;
        }
        record[wire_prefix_len + RESTLS_AUTH_LEN
            ..wire_prefix_len + RESTLS_DATA_OFFSET]
            .copy_from_slice(&masked);

        let mut auth = blake3::Hasher::new_keyed(secret);
        auth.update(server_random);
        auth.update(TO_CLIENT_MAGIC);
        auth.update(&counter.to_be_bytes());
        auth.update(&record[..wire_prefix_len]);
        auth.update(&record[wire_prefix_len + RESTLS_AUTH_LEN..]);
        let auth = auth.finalize();
        record[wire_prefix_len..wire_prefix_len + RESTLS_AUTH_LEN]
            .copy_from_slice(&auth.as_bytes()[..RESTLS_AUTH_LEN]);
        record
    }

    #[test]
    fn script_parser_matches_restls_once_and_per_record_randomness() {
        let script = parse_script("300?100<1,400~100,350").unwrap();
        assert_eq!(script.len(), 3);
        assert!(matches!(script[0].target, TargetLength::Fixed(300..=399)));
        assert_eq!(script[0].command, Command::Response(1));
        assert!(matches!(
            script[1].target,
            TargetLength::RandomEach {
                base: 400,
                range: 100
            }
        ));
        assert_eq!(script[2].target.resolve(), 350);
    }

    #[test]
    fn invalid_script_is_rejected_without_panicking() {
        for script in ["", "abc", "40000", "300~40000", "300!1", "300<256"] {
            if script.is_empty() {
                assert!(parse_script(script).is_ok());
            } else {
                assert!(parse_script(script).is_err(), "{script}");
            }
        }
    }

    #[test]
    fn tls13_session_id_hashes_key_share_group_and_key() {
        let secret = [0x42; 32];
        let key = [0x23; 32];
        let mut extensions = Vec::new();
        extensions.extend_from_slice(&EXT_KEY_SHARE.to_be_bytes());
        extensions
            .extend_from_slice(&(2u16 + 2 + 2 + key.len() as u16).to_be_bytes());
        extensions.extend_from_slice(&(2u16 + 2 + key.len() as u16).to_be_bytes());
        extensions.extend_from_slice(&29u16.to_be_bytes());
        extensions.extend_from_slice(&(key.len() as u16).to_be_bytes());
        extensions.extend_from_slice(&key);

        let mut body = Vec::new();
        body.extend_from_slice(&0x0303u16.to_be_bytes());
        body.extend_from_slice(&[0x11; 32]);
        body.push(32);
        body.extend_from_slice(&[0; 32]);
        body.extend_from_slice(&2u16.to_be_bytes());
        body.extend_from_slice(&0x1301u16.to_be_bytes());
        body.push(1);
        body.push(0);
        body.extend_from_slice(&(extensions.len() as u16).to_be_bytes());
        body.extend_from_slice(&extensions);
        let mut hello = vec![1, 0, 0, body.len() as u8];
        hello.extend_from_slice(&body);

        let session_id = restls_tls13_session_id(&secret, &hello).unwrap();
        let mut material = Vec::from(29u16.to_be_bytes());
        material.extend_from_slice(&key);
        let expected = blake3::keyed_hash(&secret, &material);
        assert_eq!(
            &session_id[..RESTLS_HANDSHAKE_AUTH_LEN],
            &expected.as_bytes()[..RESTLS_HANDSHAKE_AUTH_LEN],
        );
    }

    #[tokio::test]
    async fn full_tls13_handshake_and_bidirectional_restls_records() {
        crate::setup_default_crypto_provider();
        let password = "restls-integration-password";
        let secret = blake3::derive_key("restls-traffic-key", password.as_bytes());
        let (certificates, private_key) =
            crate::common::tls::resolve_server_cert_and_key(
                None,
                None,
                "restls-test",
            )
            .unwrap();
        let mut server_config =
            rustls::ServerConfig::builder_with_protocol_versions(&[
                &rustls::version::TLS13,
            ])
            .with_no_client_auth()
            .with_single_cert(certificates, private_key)
            .unwrap();
        server_config.send_tls13_tickets = 0;
        let acceptor = TlsAcceptor::from(Arc::new(server_config));
        let (client_io, server_io) = tokio::io::duplex(1024 * 1024);

        let server = tokio::spawn(async move {
            let tls = acceptor
                .accept(ServerHandshakeCapture::new(
                    server_io,
                    secret,
                    VersionHint::Tls13,
                ))
                .await
                .unwrap();
            let (capture, _) = tls.into_inner();
            assert!(capture.server_auth_masked);
            let server_random = capture.server_random.unwrap();
            let client_finished = capture.client_finished.clone().unwrap();
            verify_client_hello_auth(
                &secret,
                capture.client_hello.as_deref().unwrap(),
            )
            .unwrap();
            let mut prefetched = capture.read_output;
            prefetched.extend_from_slice(&capture.read_pending);
            let mut raw = capture.raw;
            let record = read_raw_record(&mut raw, &mut prefetched).await.unwrap();
            let (request, command) = decode_client_record(
                &secret,
                &server_random,
                &client_finished,
                0,
                false,
                record,
            )
            .unwrap();
            assert_eq!(command, Command::Response(1));
            let response = encode_server_record(
                &secret,
                &server_random,
                0,
                false,
                b"restls-response",
                Command::Noop,
            );
            raw.write_all(&response).await.unwrap();
            raw.flush().await.unwrap();
            request
        });

        let client = Client::new(
            "localhost".to_owned(),
            password.to_owned(),
            "tls13".to_owned(),
            Some("64<1,64".to_owned()),
            Some("chrome".to_owned()),
        )
        .unwrap();
        let mut stream = client
            .wrap_stream_with_verification(Box::new(client_io), true)
            .await
            .unwrap();
        stream.write_all(b"restls-request").await.unwrap();
        stream.flush().await.unwrap();
        let request = server.await.unwrap();
        let mut response = vec![0u8; b"restls-response".len()];
        stream.read_exact(&mut response).await.unwrap();
        assert_eq!(response, b"restls-response");
        assert_eq!(request, b"restls-request");
    }

    #[tokio::test]
    async fn full_tls12_handshake_reuses_authenticated_ecdhe_key() {
        crate::setup_default_crypto_provider();
        let password = "restls-tls12-integration-password";
        let secret = blake3::derive_key("restls-traffic-key", password.as_bytes());
        let (certificates, private_key) =
            crate::common::tls::resolve_server_cert_and_key(
                None,
                None,
                "restls-test",
            )
            .unwrap();
        let server_config = rustls::ServerConfig::builder_with_protocol_versions(&[
            &rustls::version::TLS12,
        ])
        .with_no_client_auth()
        .with_single_cert(certificates, private_key)
        .unwrap();
        let acceptor = TlsAcceptor::from(Arc::new(server_config));
        let (client_io, server_io) = tokio::io::duplex(1024 * 1024);

        let server =
            tokio::spawn(async move {
                let tls = acceptor
                    .accept(ServerHandshakeCapture::new(
                        server_io,
                        secret,
                        VersionHint::Tls12,
                    ))
                    .await
                    .unwrap();
                let (capture, _) = tls.into_inner();
                assert!(capture.server_auth_masked);
                let server_random = capture.server_random.unwrap();
                let client_finished = capture.client_finished.clone().unwrap();
                let client_key_exchange =
                    capture.client_key_exchange.as_deref().unwrap();
                let selected_group = capture.selected_group.unwrap_or_else(|| {
                    match client_key_exchange[TLS_HEADER_LEN + 4] {
                        32 => 29,
                        65 => 23,
                        97 => 24,
                        length => {
                            panic!("unexpected ECDHE public key length {length}")
                        }
                    }
                });
                verify_tls12_client_auth(
                    &secret,
                    capture.client_hello.as_deref().unwrap(),
                    client_key_exchange,
                    selected_group,
                )
                .unwrap();
                let tls12_gcm = capture.tls12_gcm;
                let server_gcm_nonce = capture.server_gcm_nonce;
                let mut prefetched = capture.read_output;
                prefetched.extend_from_slice(&capture.read_pending);
                let mut raw = capture.raw;
                let record =
                    read_raw_record(&mut raw, &mut prefetched).await.unwrap();
                let (request, command) = decode_client_record(
                    &secret,
                    &server_random,
                    &client_finished,
                    0,
                    tls12_gcm,
                    record,
                )
                .unwrap();
                assert_eq!(command, Command::Response(1));
                let response = encode_server_record(
                    &secret,
                    &server_random,
                    0,
                    server_gcm_nonce,
                    b"restls-tls12-response",
                    Command::Noop,
                );
                raw.write_all(&response).await.unwrap();
                raw.flush().await.unwrap();
                request
            });

        let client = Client::new(
            "localhost".to_owned(),
            password.to_owned(),
            "tls12".to_owned(),
            Some("64<1,64".to_owned()),
            Some("chrome".to_owned()),
        )
        .unwrap();
        let mut stream = client
            .wrap_stream_with_verification(Box::new(client_io), true)
            .await
            .unwrap();
        stream.write_all(b"restls-tls12-request").await.unwrap();
        stream.flush().await.unwrap();
        let request = server.await.unwrap();
        let mut response = vec![0u8; b"restls-tls12-response".len()];
        stream.read_exact(&mut response).await.unwrap();
        assert_eq!(response, b"restls-tls12-response");
        assert_eq!(request, b"restls-tls12-request");
    }
}
