//! Sudoku outbound protocol support.
//!
//! The protocol engine in this directory is derived from the GPL-3.0-only
//! H-gripe Sudoku implementation and adapted for the FlClash GPL distribution.
//! See `NOTICE` and `LICENSE` in this directory. It is intentionally isolated
//! from the Apache-2.0 portions of the upstream clash-rs project.

mod grid;
mod http_tunnel;
mod kip;
mod layout;
mod mask;
mod mux;
mod obfs;
mod record;
mod rng;
mod rng_cooked;
mod table;
mod uot;

#[cfg(test)]
mod interop_tests;

use std::{
    collections::HashMap,
    fmt::Debug,
    io,
    pin::Pin,
    sync::Arc,
    task::{Context as TaskContext, Poll},
    time::Duration,
};

use anyhow::{Context, Result, bail};
use async_trait::async_trait;
use curve25519_dalek::{
    edwards::{CompressedEdwardsY, EdwardsPoint},
    scalar::Scalar,
};
use erased_serde::Serialize as ErasedSerialize;
use futures::{Sink, SinkExt, Stream};
use tokio::io::AsyncWriteExt;
use tokio_util::sync::PollSender;

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
        utils::{GLOBAL_DIRECT_CONNECTOR, RemoteConnector},
    },
    session::{Session, SocksAddr},
};

use self::{
    obfs::ObfsStream,
    record::{AeadMethod, RecordStream},
};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum HttpMaskMode {
    Disabled,
    Legacy,
    Stream,
    Poll,
    Auto,
    WebSocket,
}

impl HttpMaskMode {
    pub(crate) fn parse(enabled: bool, mode: &str) -> Result<Self> {
        if !enabled {
            return Ok(Self::Disabled);
        }
        match mode.trim().to_ascii_lowercase().as_str() {
            "" | "legacy" => Ok(Self::Legacy),
            "stream" => Ok(Self::Stream),
            "poll" => Ok(Self::Poll),
            "auto" => Ok(Self::Auto),
            "ws" => Ok(Self::WebSocket),
            other => bail!("sudoku: invalid http-mask-mode `{other}`"),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SudokuOutboundConfig {
    pub(crate) server: String,
    pub(crate) port: u16,
    pub(crate) key: String,
    pub(crate) aead_method: AeadMethod,
    pub(crate) table_type: String,
    pub(crate) custom_patterns: Vec<String>,
    pub(crate) padding_min: u32,
    pub(crate) padding_max: u32,
    pub(crate) pure_downlink: bool,
    pub(crate) session_mux: bool,
    pub(crate) http_mask_mode: HttpMaskMode,
    pub(crate) http_mask_tls: bool,
    pub(crate) http_mask_host: String,
    pub(crate) http_mask_path_root: String,
    pub(crate) http_mask_multiplex: String,
}

impl SudokuOutboundConfig {
    #[allow(clippy::too_many_arguments)]
    pub(crate) fn new(
        server: String,
        port: u16,
        key: String,
        aead_method: String,
        table_type: String,
        custom_table: Option<String>,
        custom_tables: Vec<String>,
        padding_min: Option<u32>,
        padding_max: Option<u32>,
        pure_downlink: Option<bool>,
        http_mask_enabled: bool,
        http_mask_mode: String,
        http_mask_tls: bool,
        http_mask_host: String,
        http_mask_path_root: String,
        http_mask_multiplex: String,
    ) -> Result<Self> {
        if server.trim().is_empty() || port == 0 || key.trim().is_empty() {
            bail!("sudoku requires server, port and key");
        }
        let key = key.trim().to_owned();
        let aead_seed = client_aead_seed(&key);
        let aead_method = AeadMethod::parse(aead_method.trim())?;
        let table_type = if table_type.trim().is_empty() {
            "prefer_entropy".to_owned()
        } else {
            table_type.trim().to_owned()
        };
        let mut custom_patterns = if custom_tables.is_empty() {
            custom_table.into_iter().collect::<Vec<_>>()
        } else {
            custom_tables
        };
        if custom_patterns.is_empty() {
            custom_patterns.push(String::new());
        }
        for pattern in &mut custom_patterns {
            *pattern = pattern.trim().to_owned();
            table::new_directional_table(&aead_seed, &table_type, pattern)
                .context("sudoku: invalid table-type/custom-table")?;
        }
        let padding_min_provided = padding_min.is_some();
        let padding_max_provided = padding_max.is_some();
        let mut padding_min = padding_min.unwrap_or(10);
        let mut padding_max = padding_max.unwrap_or(30);
        if padding_min > 100 || padding_max > 100 {
            bail!("sudoku padding-min/padding-max must be between 0 and 100");
        }
        if padding_max < padding_min {
            match (padding_min_provided, padding_max_provided) {
                (false, true) => padding_min = padding_max,
                (true, false) => padding_max = padding_min,
                _ => bail!("sudoku padding-max must be >= padding-min"),
            }
        }
        let http_mask_mode =
            HttpMaskMode::parse(http_mask_enabled, &http_mask_mode)?;
        let http_mask_path_root = normalize_path_root(&http_mask_path_root)?;
        let http_mask_multiplex =
            match http_mask_multiplex.trim().to_ascii_lowercase().as_str() {
                "" | "off" => "off".to_owned(),
                "auto" => "auto".to_owned(),
                "on" => "on".to_owned(),
                other => bail!("sudoku: invalid http-mask-multiplex `{other}`"),
            };
        let session_mux = http_mask_multiplex == "on";
        Ok(Self {
            server,
            port,
            key,
            aead_method,
            table_type,
            custom_patterns,
            padding_min,
            padding_max,
            pure_downlink: pure_downlink.unwrap_or(true),
            session_mux,
            http_mask_mode,
            http_mask_tls,
            http_mask_host,
            http_mask_path_root,
            http_mask_multiplex,
        })
    }
}

/// Mirrors Mihomo's `ClientAEADSeed`: a valid 32-byte public point wins over
/// the ambiguous scalar form; canonical master/split scalars are converted to
/// their compressed Ed25519 public point.
fn client_aead_seed(key: &str) -> String {
    let key = key.trim();
    let Ok(bytes) = hex::decode(key) else {
        return key.to_owned();
    };
    if bytes.len() == 32 {
        let encoded: [u8; 32] = bytes.as_slice().try_into().expect("length checked");
        if let Some(point) = CompressedEdwardsY(encoded).decompress() {
            return hex::encode(point.compress().to_bytes());
        }
    }
    let scalar = match bytes.len() {
        32 => {
            let encoded: [u8; 32] =
                bytes.as_slice().try_into().expect("length checked");
            Option::<Scalar>::from(Scalar::from_canonical_bytes(encoded))
        }
        64 => {
            let left: [u8; 32] = bytes[..32].try_into().expect("length checked");
            let right: [u8; 32] = bytes[32..].try_into().expect("length checked");
            Option::<Scalar>::from(Scalar::from_canonical_bytes(left))
                .zip(Option::<Scalar>::from(Scalar::from_canonical_bytes(right)))
                .map(|(left, right)| left + right)
        }
        _ => None,
    };
    scalar
        .map(|scalar| {
            hex::encode(EdwardsPoint::mul_base(&scalar).compress().to_bytes())
        })
        .unwrap_or_else(|| key.to_owned())
}

fn normalize_path_root(value: &str) -> Result<String> {
    let value = value.trim().trim_matches('/');
    if value.is_empty() {
        return Ok(String::new());
    }
    if value.contains('/')
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || byte == b'_' || byte == b'-')
    {
        bail!("sudoku: http-mask path-root must be one [A-Za-z0-9_-] segment");
    }
    Ok(value.to_owned())
}

fn choose_table(
    config: &SudokuOutboundConfig,
) -> Result<(table::DirectionalTable, Option<u32>)> {
    let index = if config.custom_patterns.len() == 1 {
        0
    } else {
        let mut bytes = [0u8; 8];
        getrandom::fill(&mut bytes).context("sudoku: table choice RNG")?;
        (u64::from_be_bytes(bytes) as usize) % config.custom_patterns.len()
    };
    let table = table::new_directional_table(
        &client_aead_seed(&config.key),
        &config.table_type,
        &config.custom_patterns[index],
    )?;
    let hint = (config.custom_patterns.len() > 1).then(|| table.uplink.hint());
    Ok((table, hint))
}

pub(crate) async fn establish_session(
    config: &SudokuOutboundConfig,
    mut raw: AnyStream,
) -> Result<AnyStream> {
    if config.http_mask_mode == HttpMaskMode::Legacy {
        let host = if config.http_mask_host.trim().is_empty() {
            format!("{}:{}", config.server, config.port)
        } else {
            config.http_mask_host.clone()
        };
        mask::write_request_header(
            &mut raw,
            &mask::HttpMaskConfig {
                host,
                path_root: config.http_mask_path_root.clone(),
            },
        )
        .await
        .context("sudoku: write legacy HTTP mask")?;
    }

    let (tables, table_hint) = choose_table(config)?;
    let obfs = ObfsStream::new(
        raw,
        tables.uplink,
        tables.downlink,
        config.padding_min as i32,
        config.padding_max as i32,
        false,
        !config.pure_downlink,
    );
    let aead_seed = client_aead_seed(&config.key);
    let (psk_c2s, psk_s2c) = kip::derive_psk_bases(&aead_seed);
    let mut record =
        RecordStream::new(obfs, config.aead_method, &psk_c2s, &psk_s2c)?;
    let private_key = hex::decode(config.key.trim()).unwrap_or_default();
    let outcome =
        kip::client_handshake(&mut record, &aead_seed, &private_key, table_hint)
            .await
            .context("sudoku: KIP handshake")?;
    record.rekey(&outcome.session_c2s, &outcome.session_s2c)?;
    Ok(Box::new(record))
}

async fn connect(
    config: &SudokuOutboundConfig,
    target: &SocksAddr,
    raw: AnyStream,
) -> Result<AnyStream> {
    if config.session_mux {
        return mux::connect(config, target, raw).await;
    }
    let mut stream = establish_session(config, raw).await?;
    kip::write_open_tcp(&mut stream, target).await?;
    Ok(stream)
}

pub struct HandlerOptions {
    pub name: String,
    pub common_opts: HandlerCommonOptions,
    pub config: SudokuOutboundConfig,
}

pub struct Handler {
    pub(crate) opts: HandlerOptions,
    connector: tokio::sync::RwLock<Option<Arc<dyn RemoteConnector>>>,
}

impl Handler {
    pub fn new(opts: HandlerOptions) -> Result<Self, Error> {
        Ok(Self {
            opts,
            connector: Default::default(),
        })
    }

    async fn open_raw_stream(
        &self,
        connector: &dyn RemoteConnector,
        sess: &Session,
        resolver: ThreadSafeDNSResolver,
    ) -> io::Result<AnyStream> {
        connector
            .connect_stream(
                resolver,
                &self.opts.config.server,
                self.opts.config.port,
                sess.iface.as_ref(),
                #[cfg(target_os = "linux")]
                sess.so_mark,
            )
            .await
    }

    async fn open_transport_stream_for(
        &self,
        config: &SudokuOutboundConfig,
        connector: &dyn RemoteConnector,
        sess: &Session,
        resolver: ThreadSafeDNSResolver,
    ) -> Result<AnyStream> {
        if matches!(
            config.http_mask_mode,
            HttpMaskMode::Stream
                | HttpMaskMode::Poll
                | HttpMaskMode::Auto
                | HttpMaskMode::WebSocket
        ) {
            let dialer = http_tunnel::Dialer::new(
                connector.clone_connector(),
                resolver,
                config,
                sess.iface.clone(),
                #[cfg(target_os = "linux")]
                sess.so_mark,
            )?;
            http_tunnel::connect(dialer, config).await
        } else {
            Ok(self.open_raw_stream(connector, sess, resolver).await?)
        }
    }
}

impl_default_connector!(Handler);

impl Debug for Handler {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("Sudoku")
            .field("name", &self.opts.name)
            .field("server", &self.opts.config.server)
            .field("port", &self.opts.config.port)
            .finish()
    }
}

#[async_trait]
impl OutboundHandler for Handler {
    fn name(&self) -> &str {
        &self.opts.name
    }

    fn server_name(&self) -> Option<&str> {
        Some(&self.opts.config.server)
    }

    fn proto(&self) -> OutboundType {
        OutboundType::Sudoku
    }

    async fn support_udp(&self) -> bool {
        true
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
        let stream = if self.opts.config.http_mask_mode == HttpMaskMode::Auto {
            let mut stream_config = self.opts.config.clone();
            stream_config.http_mask_mode = HttpMaskMode::Stream;
            let attempt = async {
                let raw = self
                    .open_transport_stream_for(
                        &stream_config,
                        connector,
                        sess,
                        resolver.clone(),
                    )
                    .await?;
                connect(&stream_config, &sess.destination, raw).await
            };
            match tokio::time::timeout(Duration::from_secs(3), attempt).await {
                Ok(Ok(stream)) => stream,
                stream_error => {
                    let stream_error = match stream_error {
                        Ok(Err(error)) => error.to_string(),
                        Err(error) => error.to_string(),
                        Ok(Ok(_)) => unreachable!("matched above"),
                    };
                    let mut poll_config = self.opts.config.clone();
                    poll_config.http_mask_mode = HttpMaskMode::Poll;
                    let raw = self
                        .open_transport_stream_for(
                            &poll_config,
                            connector,
                            sess,
                            resolver,
                        )
                        .await
                        .map_err(new_io_error)?;
                    connect(&poll_config, &sess.destination, raw)
                        .await
                        .with_context(|| {
                            format!(
                                "sudoku auto stream attempt failed: {stream_error}"
                            )
                        })
                        .map_err(new_io_error)?
                }
            }
        } else {
            let raw = self
                .open_transport_stream_for(
                    &self.opts.config,
                    connector,
                    sess,
                    resolver,
                )
                .await
                .map_err(new_io_error)?;
            connect(&self.opts.config, &sess.destination, raw)
                .await
                .map_err(new_io_error)?
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
        let stream = if self.opts.config.http_mask_mode == HttpMaskMode::Auto {
            let mut stream_config = self.opts.config.clone();
            stream_config.http_mask_mode = HttpMaskMode::Stream;
            let attempt = async {
                let raw = self
                    .open_transport_stream_for(
                        &stream_config,
                        connector,
                        sess,
                        resolver.clone(),
                    )
                    .await?;
                uot::start(&stream_config, raw).await
            };
            match tokio::time::timeout(Duration::from_secs(3), attempt).await {
                Ok(Ok(stream)) => stream,
                stream_error => {
                    let stream_error = match stream_error {
                        Ok(Err(error)) => error.to_string(),
                        Err(error) => error.to_string(),
                        Ok(Ok(_)) => unreachable!("matched above"),
                    };
                    let mut poll_config = self.opts.config.clone();
                    poll_config.http_mask_mode = HttpMaskMode::Poll;
                    let raw = self
                        .open_transport_stream_for(
                            &poll_config,
                            connector,
                            sess,
                            resolver,
                        )
                        .await
                        .map_err(new_io_error)?;
                    uot::start(&poll_config, raw)
                        .await
                        .with_context(|| {
                            format!(
                                "sudoku auto stream attempt failed: {stream_error}"
                            )
                        })
                        .map_err(new_io_error)?
                }
            }
        } else {
            let raw = self
                .open_transport_stream_for(
                    &self.opts.config,
                    connector,
                    sess,
                    resolver,
                )
                .await
                .map_err(new_io_error)?;
            uot::start(&self.opts.config, raw)
                .await
                .map_err(new_io_error)?
        };
        let datagram = SudokuDatagram::new(stream, sess);
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
            (
                "server".to_owned(),
                Box::new(self.opts.config.server.clone()) as _,
            ),
            ("port".to_owned(), Box::new(self.opts.config.port) as _),
            ("udp".to_owned(), Box::new(true) as _),
        ])
    }
}

struct SudokuDatagram {
    send_tx: PollSender<UdpPacket>,
    recv_rx: tokio::sync::mpsc::Receiver<UdpPacket>,
    workers: Vec<tokio::task::JoinHandle<()>>,
}

impl SudokuDatagram {
    fn new(stream: AnyStream, sess: &Session) -> Self {
        let (mut reader, mut writer) = tokio::io::split(stream);
        let (send_tx, mut send_rx) = tokio::sync::mpsc::channel::<UdpPacket>(32);
        let (recv_tx, recv_rx) = tokio::sync::mpsc::channel::<UdpPacket>(32);
        let local_source = SocksAddr::from(sess.source);
        let inbound_user = sess.inbound_user.clone();

        let write_worker = tokio::spawn(async move {
            while let Some(packet) = send_rx.recv().await {
                if uot::write_packet(&mut writer, &packet.dst_addr, &packet.data)
                    .await
                    .is_err()
                {
                    break;
                }
            }
            let _ = writer.shutdown().await;
        });
        let read_worker = tokio::spawn(async move {
            while let Ok((source, data)) = uot::read_packet(&mut reader).await {
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

impl Drop for SudokuDatagram {
    fn drop(&mut self) {
        for worker in &self.workers {
            worker.abort();
        }
    }
}

impl Sink<UdpPacket> for SudokuDatagram {
    type Error = io::Error;

    fn poll_ready(
        mut self: Pin<&mut Self>,
        cx: &mut TaskContext<'_>,
    ) -> Poll<Result<(), Self::Error>> {
        self.send_tx
            .poll_ready_unpin(cx)
            .map_err(|_| new_io_error("sudoku UDP send channel closed"))
    }

    fn start_send(
        mut self: Pin<&mut Self>,
        item: UdpPacket,
    ) -> Result<(), Self::Error> {
        self.send_tx
            .start_send_unpin(item)
            .map_err(|_| new_io_error("sudoku UDP send channel closed"))
    }

    fn poll_flush(
        mut self: Pin<&mut Self>,
        cx: &mut TaskContext<'_>,
    ) -> Poll<Result<(), Self::Error>> {
        self.send_tx
            .poll_flush_unpin(cx)
            .map_err(|_| new_io_error("sudoku UDP send channel flush failed"))
    }

    fn poll_close(
        mut self: Pin<&mut Self>,
        cx: &mut TaskContext<'_>,
    ) -> Poll<Result<(), Self::Error>> {
        self.send_tx
            .poll_close_unpin(cx)
            .map_err(|_| new_io_error("sudoku UDP send channel close failed"))
    }
}

impl Stream for SudokuDatagram {
    type Item = UdpPacket;

    fn poll_next(
        mut self: Pin<&mut Self>,
        cx: &mut TaskContext<'_>,
    ) -> Poll<Option<Self::Item>> {
        self.recv_rx.poll_recv(cx)
    }
}

#[cfg(test)]
mod config_tests {
    use curve25519_dalek::{
        edwards::{CompressedEdwardsY, EdwardsPoint},
        scalar::Scalar,
    };

    use super::{SudokuOutboundConfig, client_aead_seed};

    #[test]
    fn aead_seed_preserves_public_point_and_psk() {
        let public = EdwardsPoint::mul_base(&Scalar::from(42u64))
            .compress()
            .to_bytes();
        assert_eq!(client_aead_seed(&hex::encode(public)), hex::encode(public));
        assert_eq!(client_aead_seed("  ordinary psk  "), "ordinary psk");
        assert_eq!(client_aead_seed("abcd"), "abcd");
    }

    #[test]
    fn aead_seed_recovers_master_and_split_private_scalars() {
        let master = (1u64..10_000)
            .map(Scalar::from)
            .find(|scalar| {
                CompressedEdwardsY(scalar.to_bytes()).decompress().is_none()
            })
            .expect("find an unambiguous master scalar");
        let expected =
            hex::encode(EdwardsPoint::mul_base(&master).compress().to_bytes());
        assert_eq!(client_aead_seed(&hex::encode(master.to_bytes())), expected);

        let left = Scalar::from(17u64);
        let right = Scalar::from(25u64);
        let split = [left.to_bytes(), right.to_bytes()].concat();
        let split_expected = hex::encode(
            EdwardsPoint::mul_base(&(left + right))
                .compress()
                .to_bytes(),
        );
        assert_eq!(client_aead_seed(&hex::encode(split)), split_expected);
    }

    #[test]
    fn padding_resolution_matches_mihomo_presence_rules() {
        let build = |min, max| {
            SudokuOutboundConfig::new(
                "127.0.0.1".to_owned(),
                1,
                "key".to_owned(),
                "aes-128-gcm".to_owned(),
                "prefer_entropy".to_owned(),
                None,
                Vec::new(),
                min,
                max,
                None,
                false,
                "legacy".to_owned(),
                false,
                String::new(),
                String::new(),
                "off".to_owned(),
            )
        };
        let only_max = build(None, Some(5)).unwrap();
        assert_eq!((only_max.padding_min, only_max.padding_max), (5, 5));
        let only_min = build(Some(40), None).unwrap();
        assert_eq!((only_min.padding_min, only_min.padding_max), (40, 40));
        assert!(build(Some(10), Some(5)).is_err());
    }
}
