use std::{
    collections::HashMap,
    io,
    net::SocketAddr,
    pin::Pin,
    sync::{
        Arc, Mutex,
        atomic::{AtomicBool, AtomicUsize, Ordering},
    },
    task::{Context, Poll},
    time::{Duration, Instant},
};

use async_trait::async_trait;
use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use bytes::{Buf, Bytes};
use h2::{RecvStream, SendStream, client::SendRequest};
use http::{
    HeaderMap, HeaderName, HeaderValue, Method, Request, StatusCode, Uri, Version,
};
use http_body_util::{
    BodyExt, Empty, Full, channel::Channel, combinators::UnsyncBoxBody,
};
use hyper_util::rt::TokioIo;
use rand::Rng;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, ReadBuf};
use tracing::{debug, error};
use url::Url;

use super::{
    TlsEchOptions as EchOptions, Transport,
    build_rustls_client_config_with_optional_ech,
};
use crate::{
    common::{errors::map_io_error, tls::DefaultTlsVerifier},
    proxy::{AnyOutboundDatagram, AnyStream, utils::QuinnDatagramSocket},
    session::SocksAddr,
};

/// Log xhttp errors, downgrading benign stream closures to debug level.
/// Benign closures include: NO_ERROR RST_STREAM ("not a result of an error"),
/// broken pipe, and inactive stream — the remote peer closed normally.
macro_rules! xhttp_err {
    ($($arg:tt)*) => {{
        let msg = format!($($arg)*);
        if msg.contains("not a result of an error")
            || msg.contains("broken pipe")
            || msg.contains("inactive stream")
        {
            debug!("{msg}");
        } else {
            error!("{msg}");
        }
    }};
}

const DEFAULT_MAX_EACH_POST_BYTES: usize = 1_000_000;
const DEFAULT_MIN_POSTS_INTERVAL_MS: usize = 30;
type H3Sender = h3::client::SendRequest<h3_quinn::OpenStreams, Bytes>;
type Http1Body = UnsyncBoxBody<Bytes, io::Error>;
type Http1Sender =
    Arc<tokio::sync::Mutex<hyper::client::conn::http1::SendRequest<Http1Body>>>;

enum IndependentDownload {
    Http1(Http1Sender),
    Http2(SendRequest<Bytes>),
    Http3(H3Sender),
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum Mode {
    StreamOne,
    StreamUp,
    PacketUp,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum HttpVersion {
    Http1,
    Http2,
    Http3,
}

impl HttpVersion {
    fn parse(value: Option<&str>) -> io::Result<Self> {
        match value.filter(|value| !value.trim().is_empty()) {
            None | Some("h2") => Ok(Self::Http2),
            Some("http/1.1") => Ok(Self::Http1),
            Some("h3") => Ok(Self::Http3),
            Some(value) => Err(invalid_input(format!(
                "unsupported xhttp HTTP version: {value}"
            ))),
        }
    }
}

impl Mode {
    fn parse(value: &str) -> io::Result<Self> {
        match value {
            "stream-one" => Ok(Self::StreamOne),
            "stream-up" => Ok(Self::StreamUp),
            "packet-up" => Ok(Self::PacketUp),
            value => Err(invalid_input(format!("unsupported xhttp mode: {value}"))),
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum Placement {
    Path,
    Query,
    Header,
    Cookie,
    Body,
    QueryInHeader,
    Auto,
}

impl Placement {
    fn parse(value: Option<&str>, fallback: Self) -> io::Result<Self> {
        match value.filter(|value| !value.trim().is_empty()) {
            None => Ok(fallback),
            Some("path") => Ok(Self::Path),
            Some("query") => Ok(Self::Query),
            Some("header") => Ok(Self::Header),
            Some("cookie") => Ok(Self::Cookie),
            Some("body") => Ok(Self::Body),
            Some("queryInHeader") => Ok(Self::QueryInHeader),
            Some("auto") => Ok(Self::Auto),
            Some(value) => Err(invalid_input(format!(
                "unsupported xhttp placement: {value}"
            ))),
        }
    }
}

#[derive(Clone, Copy, Debug)]
struct ValueRange {
    min: usize,
    max: usize,
}

impl ValueRange {
    fn parse(value: Option<&str>, fallback: &str, field: &str) -> io::Result<Self> {
        let value = value
            .filter(|value| !value.trim().is_empty())
            .unwrap_or(fallback)
            .trim();
        let parts = value.split('-').map(str::trim).collect::<Vec<_>>();
        let (min, max) = match parts.as_slice() {
            [value] => {
                let value = value.parse::<usize>().map_err(|error| {
                    invalid_input(format!("invalid {field}: {error}"))
                })?;
                (value, value)
            }
            [min, max] => {
                let min = min.parse::<usize>().map_err(|error| {
                    invalid_input(format!("invalid {field}: {error}"))
                })?;
                let max = max.parse::<usize>().map_err(|error| {
                    invalid_input(format!("invalid {field}: {error}"))
                })?;
                if max < min {
                    return Err(invalid_input(format!(
                        "invalid {field}: maximum is less than minimum"
                    )));
                }
                (min, max)
            }
            _ => return Err(invalid_input(format!("invalid {field}: {value}"))),
        };
        Ok(Self { min, max })
    }

    fn non_zero(self, field: &str) -> io::Result<Self> {
        if self.max == 0 {
            return Err(invalid_input(format!(
                "invalid {field}: must be greater than zero"
            )));
        }
        Ok(self)
    }

    fn random(self) -> usize {
        if self.min == self.max {
            self.min
        } else {
            rand::random_range(self.min..=self.max)
        }
    }
}

#[derive(Debug, Default)]
pub struct ClientConfig {
    pub host: String,
    pub path: String,
    pub mode: String,
    pub http_version: Option<String>,
    pub method: Option<String>,
    pub headers: HashMap<String, String>,
    pub no_grpc_header: bool,
    pub x_padding_bytes: Option<String>,
    pub x_padding_obfs_mode: bool,
    pub x_padding_key: Option<String>,
    pub x_padding_header: Option<String>,
    pub x_padding_placement: Option<String>,
    pub x_padding_method: Option<String>,
    pub session_placement: Option<String>,
    pub session_key: Option<String>,
    pub seq_placement: Option<String>,
    pub seq_key: Option<String>,
    pub uplink_data_placement: Option<String>,
    pub uplink_data_key: Option<String>,
    pub uplink_chunk_size: Option<String>,
    pub sc_max_each_post_bytes: Option<String>,
    pub sc_min_posts_interval_ms: Option<String>,
    pub download: Option<DownloadConfig>,
    pub h3_tls: Option<H3TlsConfig>,
    pub reuse: Option<ReuseConfig>,
}

#[derive(Clone, Debug, Default)]
pub struct ReuseConfig {
    pub max_concurrency: Option<String>,
    pub max_connections: Option<String>,
    pub c_max_reuse_times: Option<String>,
    pub h_max_request_times: Option<String>,
    pub h_max_reusable_secs: Option<String>,
    pub h_keep_alive_period: Option<i64>,
}

#[derive(Clone, Debug)]
pub struct H3TlsConfig {
    pub sni: String,
    pub skip_cert_verify: bool,
    pub certificate_fingerprint: Option<String>,
    pub ech: Option<EchOptions>,
    pub tls_cert: Option<String>,
    pub tls_key: Option<String>,
}

#[derive(Debug)]
pub struct DownloadConfig {
    pub host: String,
    pub path: String,
    pub http_version: Option<String>,
    pub headers: HashMap<String, String>,
    pub h3_tls: Option<H3TlsConfig>,
    pub reuse: Option<ReuseConfig>,
}

#[derive(Clone)]
struct DownloadRequest {
    host: String,
    path: String,
    http_version: HttpVersion,
    headers: HeaderMap,
    h3_tls: Option<H3TlsConfig>,
    reuse: Option<Arc<ReuseManager>>,
    keep_alive_period: Option<i64>,
}

pub struct Client {
    host: String,
    path: String,
    mode: Mode,
    http_version: HttpVersion,
    method: Method,
    headers: HeaderMap,
    no_grpc_header: bool,
    padding: ValueRange,
    padding_obfs_mode: bool,
    padding_key: String,
    padding_header: String,
    padding_placement: Placement,
    padding_method: String,
    session_placement: Placement,
    session_key: String,
    seq_placement: Placement,
    seq_key: String,
    uplink_data_placement: Placement,
    uplink_data_key: String,
    uplink_chunk_size: ValueRange,
    max_each_post_bytes: ValueRange,
    min_posts_interval_ms: ValueRange,
    download: Option<DownloadRequest>,
    h3_tls: Option<H3TlsConfig>,
    upload_reuse: Option<Arc<ReuseManager>>,
    keep_alive_period: Option<i64>,
}

#[derive(Clone)]
enum ReusableSender {
    Http1(Http1Sender),
    Http2(SendRequest<Bytes>),
    Http3(H3Sender),
}

struct ReuseEntry {
    sender: ReusableSender,
    open_usage: AtomicUsize,
    left_requests: AtomicUsize,
    reuse_count: AtomicUsize,
    max_reuse_times: usize,
    max_concurrency: usize,
    unreusable_at: Option<Instant>,
    closed: AtomicBool,
}

struct ReuseManager {
    max_concurrency: usize,
    max_connections: usize,
    c_max_reuse_times: ValueRange,
    h_max_request_times: ValueRange,
    h_max_reusable_secs: ValueRange,
    entries: Mutex<Vec<Arc<ReuseEntry>>>,
}

impl ReuseManager {
    fn new(config: ReuseConfig) -> io::Result<Arc<Self>> {
        Ok(Arc::new(Self {
            max_concurrency: ValueRange::parse(
                config.max_concurrency.as_deref(),
                "0",
                "max-concurrency",
            )?
            .random(),
            max_connections: ValueRange::parse(
                config.max_connections.as_deref(),
                "0",
                "max-connections",
            )?
            .random(),
            c_max_reuse_times: ValueRange::parse(
                config.c_max_reuse_times.as_deref(),
                "0",
                "c-max-reuse-times",
            )?,
            h_max_request_times: ValueRange::parse(
                config.h_max_request_times.as_deref(),
                "0",
                "h-max-request-times",
            )?,
            h_max_reusable_secs: ValueRange::parse(
                config.h_max_reusable_secs.as_deref(),
                "0",
                "h-max-reusable-secs",
            )?,
            entries: Mutex::new(Vec::new()),
        }))
    }

    fn cleanup_locked(entries: &mut Vec<Arc<ReuseEntry>>, now: Instant) {
        entries.retain(|entry| {
            if entry.closed.load(Ordering::Acquire) {
                return false;
            }
            let idle = entry.open_usage.load(Ordering::Acquire) == 0;
            if idle
                && (entry.left_requests.load(Ordering::Acquire) == 0
                    || entry.unreusable_at.is_some_and(|deadline| now > deadline))
            {
                entry.closed.store(true, Ordering::Release);
                return false;
            }
            true
        });
    }

    fn acquire_existing(self: &Arc<Self>) -> Option<(ReusableSender, ReuseLease)> {
        let now = Instant::now();
        let mut entries = self.entries.lock().ok()?;
        Self::cleanup_locked(&mut entries, now);
        if entries.is_empty()
            || (self.max_connections > 0 && entries.len() < self.max_connections)
        {
            return None;
        }
        let entry = entries
            .iter()
            .filter(|entry| {
                !entry.closed.load(Ordering::Acquire)
                    && entry.left_requests.load(Ordering::Acquire) > 0
                    && (entry.max_reuse_times == 0
                        || entry.reuse_count.load(Ordering::Acquire)
                            < entry.max_reuse_times)
                    && (entry.max_concurrency == 0
                        || entry.open_usage.load(Ordering::Acquire)
                            < entry.max_concurrency)
            })
            .min_by_key(|entry| entry.open_usage.load(Ordering::Acquire))?
            .clone();
        entry.reuse_count.fetch_add(1, Ordering::AcqRel);
        entry.open_usage.fetch_add(1, Ordering::AcqRel);
        entry
            .left_requests
            .fetch_update(Ordering::AcqRel, Ordering::Acquire, |value| {
                Some(value.saturating_sub(1))
            })
            .ok();
        Some((entry.sender.clone(), ReuseLease { entry }))
    }

    fn insert(
        self: &Arc<Self>,
        sender: ReusableSender,
    ) -> (ReusableSender, ReuseLease) {
        let request_limit = self.h_max_request_times.random();
        let reusable_secs = self.h_max_reusable_secs.random();
        let max_concurrency = match &sender {
            ReusableSender::Http1(_) => 1,
            _ => self.max_concurrency,
        };
        let entry = Arc::new(ReuseEntry {
            sender: sender.clone(),
            open_usage: AtomicUsize::new(1),
            left_requests: AtomicUsize::new(if request_limit == 0 {
                usize::MAX
            } else {
                request_limit.saturating_sub(1)
            }),
            reuse_count: AtomicUsize::new(0),
            max_reuse_times: self.c_max_reuse_times.random(),
            max_concurrency,
            unreusable_at: (reusable_secs > 0)
                .then(|| Instant::now() + Duration::from_secs(reusable_secs as u64)),
            closed: AtomicBool::new(false),
        });
        if let Ok(mut entries) = self.entries.lock() {
            Self::cleanup_locked(&mut entries, Instant::now());
            entries.push(entry.clone());
        }
        (sender, ReuseLease { entry })
    }
}

struct ReuseLease {
    entry: Arc<ReuseEntry>,
}

impl Drop for ReuseLease {
    fn drop(&mut self) {
        let previous = self.entry.open_usage.fetch_sub(1, Ordering::AcqRel);
        if previous <= 1 {
            self.entry.open_usage.store(0, Ordering::Release);
            let expired = self
                .entry
                .unreusable_at
                .is_some_and(|deadline| Instant::now() > deadline);
            if self.entry.left_requests.load(Ordering::Acquire) == 0
                || (self.entry.max_reuse_times > 0
                    && self.entry.reuse_count.load(Ordering::Acquire)
                        >= self.entry.max_reuse_times)
                || expired
            {
                self.entry.closed.store(true, Ordering::Release);
            }
        }
    }
}

struct ReuseGuardStream {
    inner: AnyStream,
    _leases: Vec<ReuseLease>,
}

impl AsyncRead for ReuseGuardStream {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        Pin::new(&mut self.inner).poll_read(cx, buf)
    }
}

impl AsyncWrite for ReuseGuardStream {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<Result<usize, io::Error>> {
        Pin::new(&mut self.inner).poll_write(cx, buf)
    }

    fn poll_flush(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<Result<(), io::Error>> {
        Pin::new(&mut self.inner).poll_flush(cx)
    }

    fn poll_shutdown(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<Result<(), io::Error>> {
        Pin::new(&mut self.inner).poll_shutdown(cx)
    }
}

fn guard_reuse(stream: AnyStream, leases: Vec<ReuseLease>) -> AnyStream {
    if leases.is_empty() {
        stream
    } else {
        Box::new(ReuseGuardStream {
            inner: stream,
            _leases: leases,
        })
    }
}

impl Client {
    pub fn new(config: ClientConfig) -> io::Result<Self> {
        let mode = Mode::parse(&config.mode)?;
        let http_version = HttpVersion::parse(config.http_version.as_deref())?;
        if http_version == HttpVersion::Http3 && config.h3_tls.is_none() {
            return Err(invalid_input("xhttp HTTP/3 requires TLS settings"));
        }
        let path = normalize_path(config.path);
        let method = config
            .method
            .as_deref()
            .filter(|value| !value.trim().is_empty())
            .unwrap_or("POST")
            .parse()
            .map_err(|error| {
                invalid_input(format!("invalid xhttp uplink HTTP method: {error}"))
            })?;
        let headers = parse_headers(config.headers)?;
        let upload_reuse =
            config.reuse.clone().map(ReuseManager::new).transpose()?;
        let keep_alive_period = config
            .reuse
            .as_ref()
            .and_then(|reuse| reuse.h_keep_alive_period);
        let download = config
            .download
            .map(|download| {
                let download_http_version = match download.http_version.as_deref() {
                    Some(value) => HttpVersion::parse(Some(value))?,
                    None => http_version,
                };
                if download_http_version == HttpVersion::Http3
                    && download.h3_tls.is_none()
                {
                    return Err(invalid_input(
                        "xhttp HTTP/3 download-settings require TLS settings",
                    ));
                }
                let keep_alive_period = download
                    .reuse
                    .as_ref()
                    .and_then(|reuse| reuse.h_keep_alive_period);
                Ok::<_, io::Error>(DownloadRequest {
                    host: download.host,
                    path: normalize_path(download.path),
                    http_version: download_http_version,
                    headers: parse_headers(download.headers)?,
                    h3_tls: download.h3_tls,
                    reuse: download.reuse.map(ReuseManager::new).transpose()?,
                    keep_alive_period,
                })
            })
            .transpose()?;

        let max_each_post_bytes = ValueRange::parse(
            config.sc_max_each_post_bytes.as_deref(),
            &DEFAULT_MAX_EACH_POST_BYTES.to_string(),
            "sc-max-each-post-bytes",
        )?
        .non_zero("sc-max-each-post-bytes")?;
        let min_posts_interval_ms = ValueRange::parse(
            config.sc_min_posts_interval_ms.as_deref(),
            &DEFAULT_MIN_POSTS_INTERVAL_MS.to_string(),
            "sc-min-posts-interval-ms",
        )?
        .non_zero("sc-min-posts-interval-ms")?;
        let uplink_data_placement = Placement::parse(
            config.uplink_data_placement.as_deref(),
            Placement::Body,
        )?;
        if !matches!(
            uplink_data_placement,
            Placement::Body
                | Placement::Header
                | Placement::Cookie
                | Placement::Auto
        ) {
            return Err(invalid_input(
                "xhttp uplink-data-placement must be body, header, cookie, or auto",
            ));
        }
        let uplink_chunk_size = match config.uplink_chunk_size.as_deref() {
            Some(value) if !value.trim().is_empty() => {
                let mut range =
                    ValueRange::parse(Some(value), "0", "uplink-chunk-size")?;
                if range.min < 64 {
                    range.min = 64;
                    range.max = range.max.max(64);
                }
                range
            }
            _ => match uplink_data_placement {
                Placement::Cookie => ValueRange {
                    min: 2 * 1024,
                    max: 3 * 1024,
                },
                Placement::Header => ValueRange {
                    min: 3 * 1024,
                    max: 4 * 1024,
                },
                _ => max_each_post_bytes,
            },
        };
        let padding_obfs_mode = config.x_padding_obfs_mode;
        let padding_placement = if padding_obfs_mode {
            Placement::parse(
                config.x_padding_placement.as_deref(),
                Placement::QueryInHeader,
            )?
        } else {
            Placement::QueryInHeader
        };
        if !matches!(
            padding_placement,
            Placement::Header
                | Placement::Cookie
                | Placement::Query
                | Placement::QueryInHeader
        ) {
            return Err(invalid_input(
                "xhttp x-padding-placement must be queryInHeader, query, header, \
                 or cookie",
            ));
        }

        let session_placement =
            Placement::parse(config.session_placement.as_deref(), Placement::Path)?;
        let seq_placement =
            Placement::parse(config.seq_placement.as_deref(), Placement::Path)?;
        if !matches!(
            session_placement,
            Placement::Path
                | Placement::Query
                | Placement::Header
                | Placement::Cookie
        ) || !matches!(
            seq_placement,
            Placement::Path
                | Placement::Query
                | Placement::Header
                | Placement::Cookie
        ) {
            return Err(invalid_input(
                "xhttp session/seq placement must be path, query, header, or cookie",
            ));
        }
        let session_key =
            config
                .session_key
                .unwrap_or_else(|| match session_placement {
                    Placement::Header => "X-Session".to_owned(),
                    Placement::Cookie | Placement::Query => "x_session".to_owned(),
                    _ => String::new(),
                });
        let seq_key = config.seq_key.unwrap_or_else(|| match seq_placement {
            Placement::Header => "X-Seq".to_owned(),
            Placement::Cookie | Placement::Query => "x_seq".to_owned(),
            _ => String::new(),
        });

        Ok(Self {
            host: config.host,
            path,
            mode,
            http_version,
            method,
            headers,
            no_grpc_header: config.no_grpc_header,
            padding: ValueRange::parse(
                config.x_padding_bytes.as_deref(),
                "100-1000",
                "x-padding-bytes",
            )?,
            padding_obfs_mode,
            padding_key: if padding_obfs_mode {
                config.x_padding_key.unwrap_or_default()
            } else {
                "x_padding".to_owned()
            },
            padding_header: if padding_obfs_mode {
                config.x_padding_header.unwrap_or_default()
            } else {
                "Referer".to_owned()
            },
            padding_placement,
            padding_method: config.x_padding_method.unwrap_or_default(),
            session_placement,
            session_key,
            seq_placement,
            seq_key,
            uplink_data_placement,
            uplink_data_key: config.uplink_data_key.unwrap_or_default(),
            uplink_chunk_size,
            max_each_post_bytes,
            min_posts_interval_ms,
            download,
            h3_tls: config.h3_tls,
            upload_reuse,
            keep_alive_period,
        })
    }

    fn request(
        &self,
        method: Method,
        session: Option<&str>,
        seq: Option<u64>,
        payload: Option<&[u8]>,
        stream_body: bool,
    ) -> io::Result<(Request<()>, Option<Bytes>)> {
        self.request_with_base(method, session, seq, payload, stream_body, false)
    }

    fn request_with_base(
        &self,
        method: Method,
        session: Option<&str>,
        seq: Option<u64>,
        payload: Option<&[u8]>,
        stream_body: bool,
        download: bool,
    ) -> io::Result<(Request<()>, Option<Bytes>)> {
        let (host, path, base_headers) = match (download, self.download.as_ref()) {
            (true, Some(download)) => (
                download.host.as_str(),
                download.path.as_str(),
                &download.headers,
            ),
            _ => (self.host.as_str(), self.path.as_str(), &self.headers),
        };
        let mut url = Url::parse(&format!("https://{host}{path}"))
            .map_err(|error| invalid_input(format!("invalid xhttp URL: {error}")))?;
        let mut headers = base_headers.clone();
        let body = if let Some(payload) = payload {
            self.apply_payload(&mut headers, payload)?
        } else {
            None
        };
        self.apply_padding(&url, &mut headers)?;
        self.apply_metadata(&mut url, &mut headers, session, seq)?;
        if stream_body && !self.no_grpc_header {
            headers.insert(
                http::header::CONTENT_TYPE,
                HeaderValue::from_static("application/grpc"),
            );
        }
        if let Some(body) = body.as_ref() {
            headers.insert(
                http::header::CONTENT_LENGTH,
                HeaderValue::from_str(&body.len().to_string())
                    .map_err(invalid_input)?,
            );
        }
        let uri = url
            .as_str()
            .parse::<Uri>()
            .map_err(|error| invalid_input(format!("invalid xhttp URI: {error}")))?;
        let mut request = Request::builder()
            .method(method)
            .uri(uri)
            .version(Version::HTTP_2)
            .body(())
            .map_err(invalid_input)?;
        for (name, value) in headers {
            if let Some(name) = name
                && !name.as_str().eq_ignore_ascii_case("host")
            {
                request.headers_mut().append(name, value);
            }
        }
        Ok((request, body))
    }

    fn apply_payload(
        &self,
        headers: &mut HeaderMap,
        payload: &[u8],
    ) -> io::Result<Option<Bytes>> {
        match self.uplink_data_placement {
            Placement::Body | Placement::Auto => {
                Ok(Some(Bytes::copy_from_slice(payload)))
            }
            Placement::Header => {
                let encoded = URL_SAFE_NO_PAD.encode(payload);
                for (index, chunk) in
                    split_random(&encoded, self.uplink_chunk_size).enumerate()
                {
                    let name = format!("{}-{index}", self.uplink_data_key)
                        .parse::<HeaderName>()
                        .map_err(|error| {
                            invalid_input(format!(
                                "invalid xhttp uplink header name: {error}"
                            ))
                        })?;
                    let value =
                        HeaderValue::from_str(chunk).map_err(invalid_input)?;
                    headers.insert(name, value);
                }
                Ok(None)
            }
            Placement::Cookie => {
                let encoded = URL_SAFE_NO_PAD.encode(payload);
                for (index, chunk) in
                    split_random(&encoded, self.uplink_chunk_size).enumerate()
                {
                    add_cookie(
                        headers,
                        &format!("{}_{index}", self.uplink_data_key),
                        chunk,
                    )?;
                }
                Ok(None)
            }
            _ => unreachable!("uplink placement validated by Client::new"),
        }
    }

    fn apply_padding(&self, url: &Url, headers: &mut HeaderMap) -> io::Result<()> {
        let padding = match self.padding_method.as_str() {
            "" | "repeat-x" => "X".repeat(self.padding.random()),
            "tokenish" => tokenish_padding(self.padding.random()),
            value => {
                return Err(invalid_input(format!(
                    "unsupported xhttp padding method: {value}"
                )));
            }
        };
        match self.padding_placement {
            Placement::Header => {
                let name =
                    required_header_name(&self.padding_header, "x-padding-header")?;
                headers.insert(
                    name,
                    HeaderValue::from_str(&padding).map_err(invalid_input)?,
                );
            }
            Placement::Cookie => {
                add_cookie(headers, &self.padding_key, &padding)?;
            }
            Placement::Query => {
                // Query padding is applied to the actual request URL below by
                // apply_metadata, so keep it in a private marker header first.
                let marker =
                    HeaderValue::from_str(&padding).map_err(invalid_input)?;
                headers
                    .insert(HeaderName::from_static("x-clash-rs-xpadding"), marker);
            }
            Placement::QueryInHeader => {
                let name =
                    required_header_name(&self.padding_header, "x-padding-header")?;
                let mut referer = url.clone();
                referer.set_query(Some(&format!("{}={padding}", self.padding_key)));
                headers.insert(
                    name,
                    HeaderValue::from_str(referer.as_str())
                        .map_err(invalid_input)?,
                );
            }
            _ => unreachable!("padding placement validated by Client::new"),
        }
        Ok(())
    }

    fn apply_metadata(
        &self,
        url: &mut Url,
        headers: &mut HeaderMap,
        session: Option<&str>,
        seq: Option<u64>,
    ) -> io::Result<()> {
        if self.padding_placement == Placement::Query {
            if let Some(value) = headers.remove("x-clash-rs-xpadding") {
                url.query_pairs_mut().append_pair(
                    &self.padding_key,
                    value.to_str().map_err(invalid_input)?,
                );
            }
        }
        if let Some(session) = session {
            apply_metadata_value(
                url,
                headers,
                self.session_placement,
                &self.session_key,
                session,
            )?;
        }
        if let Some(seq) = seq {
            apply_metadata_value(
                url,
                headers,
                self.seq_placement,
                &self.seq_key,
                &seq.to_string(),
            )?;
        }
        Ok(())
    }

    async fn proxy_stream_one(
        &self,
        sender: SendRequest<Bytes>,
    ) -> io::Result<AnyStream> {
        let (request, _) =
            self.request(self.method.clone(), None, None, None, true)?;
        let mut sender = sender.ready().await.map_err(map_io_error)?;
        let (response, upload) =
            sender.send_request(request, false).map_err(map_io_error)?;
        Ok(spawn_stream(response, upload, "stream-one"))
    }

    async fn start_independent_download(
        &self,
        session: &str,
        download: IndependentDownload,
        mut output: tokio::io::WriteHalf<tokio::io::DuplexStream>,
    ) -> io::Result<()> {
        let (request, _) = self.request_with_base(
            Method::GET,
            Some(session),
            None,
            None,
            false,
            true,
        )?;
        match download {
            IndependentDownload::Http1(sender) => {
                let mut request = request.map(|_| empty_http1_body());
                *request.version_mut() = Version::HTTP_11;
                tokio::spawn(async move {
                    let result = async {
                        let mut sender = sender.lock().await;
                        let mut response = sender
                            .send_request(request)
                            .await
                            .map_err(map_io_error)?;
                        if response.status() != StatusCode::OK {
                            return Err(io::Error::new(
                                io::ErrorKind::ConnectionRefused,
                                format!(
                                    "xhttp HTTP/1.1 download bad status: {}",
                                    response.status()
                                ),
                            ));
                        }
                        copy_http1_response(&mut response, &mut output).await
                    }
                    .await;
                    if let Err(error_value) = result {
                        xhttp_err!("xhttp HTTP/1.1 download error: {error_value}");
                    }
                    let _ = output.shutdown().await;
                });
            }
            IndependentDownload::Http2(sender) => {
                let mut sender = sender.ready().await.map_err(map_io_error)?;
                let (response, _) =
                    sender.send_request(request, true).map_err(map_io_error)?;
                spawn_download(response, output, "independent HTTP/2 download");
            }
            IndependentDownload::Http3(mut sender) => {
                let mut request = request;
                *request.version_mut() = Version::HTTP_3;
                let mut stream = sender
                    .send_request(request)
                    .await
                    .map_err(io::Error::other)?;
                stream.finish().await.map_err(io::Error::other)?;
                tokio::spawn(async move {
                    let _sender_guard = sender;
                    if let Err(error_value) = copy_h3_response(
                        &mut stream,
                        &mut output,
                        "independent HTTP/3 download",
                    )
                    .await
                    {
                        error!("{error_value}");
                    }
                    let _ = output.shutdown().await;
                });
            }
        }
        Ok(())
    }

    async fn proxy_http1_stream_one(
        &self,
        sender: Http1Sender,
    ) -> io::Result<AnyStream> {
        let (body_sender, body) = Channel::<Bytes, io::Error>::new(16);
        let (request, _) =
            self.request(self.method.clone(), None, None, None, true)?;
        let mut request = request.map(|_| body.boxed_unsync());
        *request.version_mut() = Version::HTTP_11;

        let (application, worker) = tokio::io::duplex(64 * 1024);
        let (upload_reader, mut download_writer) = tokio::io::split(worker);
        tokio::spawn(async move {
            if let Err(error_value) =
                copy_http1_upload(upload_reader, body_sender).await
            {
                xhttp_err!("xhttp HTTP/1.1 stream-one upload error: {error_value}");
            }
        });
        tokio::spawn(async move {
            let result = async {
                let mut sender = sender.lock().await;
                let mut response =
                    sender.send_request(request).await.map_err(map_io_error)?;
                if !response.status().is_success() {
                    return Err(io::Error::new(
                        io::ErrorKind::ConnectionRefused,
                        format!(
                            "xhttp HTTP/1.1 stream-one bad status: {}",
                            response.status()
                        ),
                    ));
                }
                while let Some(frame) = response.body_mut().frame().await {
                    let frame = frame.map_err(map_io_error)?;
                    if let Ok(data) = frame.into_data() {
                        download_writer.write_all(&data).await?;
                    }
                }
                Ok::<_, io::Error>(())
            }
            .await;
            if let Err(error_value) = result {
                xhttp_err!(
                    "xhttp HTTP/1.1 stream-one download error: {error_value}"
                );
            }
            let _ = download_writer.shutdown().await;
        });
        Ok(Box::new(application))
    }

    async fn proxy_http1_multi(
        &self,
        upload_stream: AnyStream,
        mut additional: Vec<AnyStream>,
    ) -> io::Result<AnyStream> {
        if additional.len() != 1 {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                format!(
                    "xhttp HTTP/1.1 {} requires exactly one additional stream",
                    match self.mode {
                        Mode::StreamUp => "stream-up",
                        Mode::PacketUp => "packet-up",
                        Mode::StreamOne => "stream-one",
                    }
                ),
            ));
        }
        let download_stream = additional.pop().expect("length checked");
        let (upload_sender, upload_lease) = self
            .reusable_h1_sender(upload_stream, self.upload_reuse.as_ref(), "upload")
            .await?;
        let download_manager = self
            .download
            .as_ref()
            .and_then(|download| download.reuse.as_ref())
            .or(self.upload_reuse.as_ref());
        let (download_sender, download_lease) = self
            .reusable_h1_sender(download_stream, download_manager, "download")
            .await?;
        let result = self
            .proxy_http1_upload_with_download(
                upload_sender,
                IndependentDownload::Http1(download_sender),
            )
            .await?;
        Ok(guard_reuse(
            result,
            upload_lease.into_iter().chain(download_lease).collect(),
        ))
    }

    async fn proxy_http1_upload_with_download(
        &self,
        upload_sender: Http1Sender,
        download: IndependentDownload,
    ) -> io::Result<AnyStream> {
        let session = new_session_id();
        let (application, worker) = tokio::io::duplex(64 * 1024);
        let (upload_reader, download_writer) = tokio::io::split(worker);
        self.start_independent_download(&session, download, download_writer)
            .await?;

        match self.mode {
            Mode::StreamUp => {
                let (body_sender, body) = Channel::<Bytes, io::Error>::new(16);
                let (request, _) = self.request(
                    self.method.clone(),
                    Some(&session),
                    None,
                    None,
                    true,
                )?;
                let mut request = request.map(|_| body.boxed_unsync());
                *request.version_mut() = Version::HTTP_11;
                tokio::spawn(async move {
                    if let Err(error_value) =
                        copy_http1_upload(upload_reader, body_sender).await
                    {
                        xhttp_err!(
                            "xhttp HTTP/1.1 stream-up body error: {error_value}"
                        );
                    }
                });
                tokio::spawn(async move {
                    let mut sender = upload_sender.lock().await;
                    match sender.send_request(request).await {
                        Ok(mut response) if response.status().is_success() => {
                            while let Some(frame) = response.body_mut().frame().await
                            {
                                if frame.is_err() {
                                    break;
                                }
                            }
                        }
                        Ok(response) => error!(
                            "xhttp HTTP/1.1 stream-up bad status: {}",
                            response.status()
                        ),
                        Err(error_value) => {
                            xhttp_err!(
                                "xhttp HTTP/1.1 stream-up error: {error_value}"
                            )
                        }
                    }
                });
            }
            Mode::PacketUp => {
                let requests = self.packet_request_builder(session);
                let method = self.method.clone();
                let max_each_post_bytes = self.max_each_post_bytes.random();
                let min_posts_interval_ms = self.min_posts_interval_ms;
                tokio::spawn(async move {
                    let mut upload_reader = upload_reader;
                    let mut sender = upload_sender.lock().await;
                    let result = async {
                        let mut sequence = 0u64;
                        loop {
                            let Some(payload) = read_packet(
                                &mut upload_reader,
                                max_each_post_bytes,
                                Duration::from_millis(
                                    min_posts_interval_ms.random() as u64,
                                ),
                            )
                            .await?
                            else {
                                return Ok::<_, io::Error>(());
                            };
                            let (request, body) =
                                requests(method.clone(), sequence, &payload)?;
                            let mut request = request
                                .map(|_| full_http1_body(body.unwrap_or_default()));
                            *request.version_mut() = Version::HTTP_11;
                            let mut response = sender
                                .send_request(request)
                                .await
                                .map_err(map_io_error)?;
                            if response.status() != StatusCode::OK {
                                return Err(io::Error::new(
                                    io::ErrorKind::ConnectionRefused,
                                    format!(
                                        "xhttp HTTP/1.1 packet-up bad status: {}",
                                        response.status()
                                    ),
                                ));
                            }
                            while let Some(frame) = response.body_mut().frame().await
                            {
                                frame.map_err(map_io_error)?;
                            }
                            sequence += 1;
                        }
                    }
                    .await;
                    if let Err(error_value) = result {
                        xhttp_err!("xhttp HTTP/1.1 packet-up error: {error_value}");
                    }
                });
            }
            Mode::StreamOne => unreachable!("handled by proxy_http1_stream_one"),
        }
        Ok(Box::new(application))
    }

    async fn proxy_stream_up(
        &self,
        sender: SendRequest<Bytes>,
        download_sender: Option<SendRequest<Bytes>>,
    ) -> io::Result<AnyStream> {
        let session = new_session_id();
        let (download_request, _) = self.request_with_base(
            Method::GET,
            Some(&session),
            None,
            None,
            false,
            true,
        )?;
        let mut download_sender = download_sender
            .unwrap_or_else(|| sender.clone())
            .ready()
            .await
            .map_err(map_io_error)?;
        let (download_response, _) = download_sender
            .send_request(download_request, true)
            .map_err(map_io_error)?;

        let (upload_request, _) =
            self.request(self.method.clone(), Some(&session), None, None, true)?;
        let mut upload_sender = sender.ready().await.map_err(map_io_error)?;
        let (upload_response, upload) = upload_sender
            .send_request(upload_request, false)
            .map_err(map_io_error)?;
        tokio::spawn(async move {
            if let Err(error_value) =
                drain_response(upload_response, "stream-up upload").await
            {
                error!("{error_value}");
            }
        });
        Ok(spawn_stream(
            download_response,
            upload,
            "stream-up download",
        ))
    }

    async fn proxy_packet_up(
        &self,
        sender: SendRequest<Bytes>,
        download_sender: Option<SendRequest<Bytes>>,
    ) -> io::Result<AnyStream> {
        let session = new_session_id();
        let (download_request, _) = self.request_with_base(
            Method::GET,
            Some(&session),
            None,
            None,
            false,
            true,
        )?;
        let mut download_sender = download_sender
            .unwrap_or_else(|| sender.clone())
            .ready()
            .await
            .map_err(map_io_error)?;
        let (download_response, _) = download_sender
            .send_request(download_request, true)
            .map_err(map_io_error)?;

        let (application, worker) = tokio::io::duplex(64 * 1024);
        let (mut upload_reader, download_writer) = tokio::io::split(worker);
        spawn_download(download_response, download_writer, "packet-up download");
        let method = self.method.clone();
        let max_each_post_bytes = self.max_each_post_bytes.random();
        let min_posts_interval_ms = self.min_posts_interval_ms;
        let requests = self.packet_request_builder(session);
        tokio::spawn(async move {
            let mut sequence = 0u64;
            let result = async {
                loop {
                    let Some(payload) = read_packet(
                        &mut upload_reader,
                        max_each_post_bytes,
                        Duration::from_millis(min_posts_interval_ms.random() as u64),
                    )
                    .await?
                    else {
                        return Ok::<_, io::Error>(());
                    };
                    let (request, body) =
                        requests(method.clone(), sequence, &payload)?;
                    send_packet(&sender, request, body).await?;
                    sequence += 1;
                }
            }
            .await;
            if let Err(error_value) = result {
                xhttp_err!("xhttp packet-up upload error: {error_value}");
            }
        });
        Ok(Box::new(application))
    }

    async fn h3_sender(
        &self,
        datagram: AnyOutboundDatagram,
        destination: SocksAddr,
        remote_addr: SocketAddr,
        tls: &H3TlsConfig,
        keep_alive_period: Option<i64>,
    ) -> io::Result<H3Sender> {
        let verifier = Arc::new(DefaultTlsVerifier::try_new(
            tls.certificate_fingerprint.clone(),
            tls.skip_cert_verify,
        )?);
        let mut tls_config = build_rustls_client_config_with_optional_ech(
            verifier,
            tls.tls_cert.as_deref(),
            tls.tls_key.as_deref(),
            tls.ech.as_ref(),
            &tls.sni,
        )
        .await?;
        tls_config.alpn_protocols = vec![b"h3".to_vec()];
        if std::env::var("SSLKEYLOGFILE").is_ok() {
            tls_config.key_log = Arc::new(rustls::KeyLogFile::new());
        }
        let quic_crypto =
            quinn::crypto::rustls::QuicClientConfig::try_from(tls_config)
                .map_err(io::Error::other)?;
        let mut client_config = quinn::ClientConfig::new(Arc::new(quic_crypto));
        let mut transport_config = quinn::TransportConfig::default();
        transport_config.max_idle_timeout(Some(
            Duration::from_secs(300)
                .try_into()
                .map_err(io::Error::other)?,
        ));
        transport_config.keep_alive_interval(keep_alive_interval(
            keep_alive_period,
            Duration::from_secs(10),
        ));
        client_config.transport_config(Arc::new(transport_config));

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
        let h3_connection = h3_quinn::Connection::new(connection);
        let (mut driver, sender) = h3::client::builder()
            .build::<_, _, Bytes>(h3_connection)
            .await
            .map_err(io::Error::other)?;
        tokio::spawn(async move {
            let error_value = driver.wait_idle().await;
            if error_value.is_h3_no_error() {
                debug!("xhttp HTTP/3 connection closed: {error_value}");
            } else {
                xhttp_err!("xhttp HTTP/3 connection failed: {error_value}");
            }
            drop(endpoint);
        });
        Ok(sender)
    }

    async fn reusable_h1_sender(
        &self,
        stream: AnyStream,
        manager: Option<&Arc<ReuseManager>>,
        label: &'static str,
    ) -> io::Result<(Http1Sender, Option<ReuseLease>)> {
        if let Some(manager) = manager
            && let Some((sender, lease)) = manager.acquire_existing()
        {
            return match sender {
                ReusableSender::Http1(sender) => Ok((sender, Some(lease))),
                ReusableSender::Http2(_) | ReusableSender::Http3(_) => {
                    Err(io::Error::other(
                        "xhttp reuse pool protocol mismatch: expected HTTP/1.1",
                    ))
                }
            };
        }
        let (sender, connection) = hyper::client::conn::http1::handshake::<
            _,
            Http1Body,
        >(TokioIo::new(stream))
        .await
        .map_err(map_io_error)?;
        tokio::spawn(async move {
            if let Err(error_value) = connection.await {
                xhttp_err!("xhttp HTTP/1.1 {label} connection error: {error_value}");
            }
        });
        let sender = Arc::new(tokio::sync::Mutex::new(sender));
        if let Some(manager) = manager {
            let (sender, lease) = manager.insert(ReusableSender::Http1(sender));
            match sender {
                ReusableSender::Http1(sender) => Ok((sender, Some(lease))),
                ReusableSender::Http2(_) | ReusableSender::Http3(_) => {
                    unreachable!("inserted HTTP/1.1 sender")
                }
            }
        } else {
            Ok((sender, None))
        }
    }

    async fn reusable_h2_sender(
        &self,
        stream: AnyStream,
        manager: Option<&Arc<ReuseManager>>,
        keep_alive_period: Option<i64>,
        label: &'static str,
    ) -> io::Result<(SendRequest<Bytes>, Option<ReuseLease>)> {
        if let Some(manager) = manager
            && let Some((sender, lease)) = manager.acquire_existing()
        {
            return match sender {
                ReusableSender::Http2(sender) => Ok((sender, Some(lease))),
                ReusableSender::Http1(_) | ReusableSender::Http3(_) => {
                    Err(io::Error::other(
                        "xhttp reuse pool protocol mismatch: expected HTTP/2",
                    ))
                }
            };
        }
        let (sender, mut connection) =
            h2::client::handshake(stream).await.map_err(map_io_error)?;
        let mut ping_pong = connection.ping_pong();
        tokio::spawn(async move {
            if let Err(error_value) = connection.await {
                xhttp_err!("xhttp HTTP/2 {label} connection error: {error_value}");
            }
        });
        if let Some(interval) =
            keep_alive_interval(keep_alive_period, Duration::from_secs(45))
            && let Some(mut ping_pong) = ping_pong.take()
        {
            tokio::spawn(async move {
                loop {
                    tokio::time::sleep(interval).await;
                    if ping_pong.ping(h2::Ping::opaque()).await.is_err() {
                        break;
                    }
                }
            });
        }
        if let Some(manager) = manager {
            let (sender, lease) = manager.insert(ReusableSender::Http2(sender));
            match sender {
                ReusableSender::Http2(sender) => Ok((sender, Some(lease))),
                ReusableSender::Http1(_) | ReusableSender::Http3(_) => {
                    unreachable!("inserted HTTP/2 sender")
                }
            }
        } else {
            Ok((sender, None))
        }
    }

    async fn reusable_h3_sender(
        &self,
        datagram: AnyOutboundDatagram,
        destination: SocksAddr,
        remote_addr: SocketAddr,
        tls: &H3TlsConfig,
        manager: Option<&Arc<ReuseManager>>,
        keep_alive_period: Option<i64>,
    ) -> io::Result<(H3Sender, Option<ReuseLease>)> {
        if let Some(manager) = manager
            && let Some((sender, lease)) = manager.acquire_existing()
        {
            return match sender {
                ReusableSender::Http3(sender) => Ok((sender, Some(lease))),
                ReusableSender::Http1(_) | ReusableSender::Http2(_) => {
                    Err(io::Error::other(
                        "xhttp reuse pool protocol mismatch: expected HTTP/3",
                    ))
                }
            };
        }
        let sender = self
            .h3_sender(datagram, destination, remote_addr, tls, keep_alive_period)
            .await?;
        if let Some(manager) = manager {
            let (sender, lease) = manager.insert(ReusableSender::Http3(sender));
            match sender {
                ReusableSender::Http3(sender) => Ok((sender, Some(lease))),
                ReusableSender::Http1(_) | ReusableSender::Http2(_) => {
                    unreachable!("inserted HTTP/3 sender")
                }
            }
        } else {
            Ok((sender, None))
        }
    }

    async fn proxy_h3_stream_one(
        &self,
        mut sender: H3Sender,
    ) -> io::Result<AnyStream> {
        let (mut request, _) =
            self.request(self.method.clone(), None, None, None, true)?;
        *request.version_mut() = Version::HTTP_3;
        let stream = sender
            .send_request(request)
            .await
            .map_err(io::Error::other)?;
        Ok(spawn_h3_stream(stream, sender, "stream-one"))
    }

    async fn proxy_h3_stream_up(
        &self,
        mut sender: H3Sender,
        download_sender: Option<H3Sender>,
    ) -> io::Result<AnyStream> {
        let session = new_session_id();
        let (mut download_request, _) = self.request_with_base(
            Method::GET,
            Some(&session),
            None,
            None,
            false,
            true,
        )?;
        *download_request.version_mut() = Version::HTTP_3;
        let mut download_sender = download_sender.unwrap_or_else(|| sender.clone());
        let mut download = download_sender
            .send_request(download_request)
            .await
            .map_err(io::Error::other)?;
        download.finish().await.map_err(io::Error::other)?;

        let (mut upload_request, _) =
            self.request(self.method.clone(), Some(&session), None, None, true)?;
        *upload_request.version_mut() = Version::HTTP_3;
        let upload = sender
            .send_request(upload_request)
            .await
            .map_err(io::Error::other)?;
        let (upload_send, upload_recv) = upload.split();

        let (application, worker) = tokio::io::duplex(64 * 1024);
        let (upload_reader, mut download_writer) = tokio::io::split(worker);
        tokio::spawn(async move {
            if let Err(error_value) =
                copy_h3_upload(upload_reader, upload_send).await
            {
                xhttp_err!("xhttp HTTP/3 stream-up upload error: {error_value}");
            }
        });
        tokio::spawn(async move {
            if let Err(error_value) =
                drain_h3_response(upload_recv, "stream-up upload").await
            {
                error!("{error_value}");
            }
        });
        tokio::spawn(async move {
            let _sender_guard = (sender, download_sender);
            if let Err(error_value) = copy_h3_response(
                &mut download,
                &mut download_writer,
                "stream-up download",
            )
            .await
            {
                error!("{error_value}");
            }
            let _ = download_writer.shutdown().await;
        });
        Ok(Box::new(application))
    }

    async fn proxy_h3_packet_up(
        &self,
        mut sender: H3Sender,
        download_sender: Option<H3Sender>,
    ) -> io::Result<AnyStream> {
        let session = new_session_id();
        let (mut download_request, _) = self.request_with_base(
            Method::GET,
            Some(&session),
            None,
            None,
            false,
            true,
        )?;
        *download_request.version_mut() = Version::HTTP_3;
        let mut download_sender = download_sender.unwrap_or_else(|| sender.clone());
        let mut download = download_sender
            .send_request(download_request)
            .await
            .map_err(io::Error::other)?;
        download.finish().await.map_err(io::Error::other)?;

        let (application, worker) = tokio::io::duplex(64 * 1024);
        let (mut upload_reader, mut download_writer) = tokio::io::split(worker);
        tokio::spawn(async move {
            let _download_sender_guard = download_sender;
            if let Err(error_value) = copy_h3_response(
                &mut download,
                &mut download_writer,
                "packet-up download",
            )
            .await
            {
                error!("{error_value}");
            }
            let _ = download_writer.shutdown().await;
        });
        let method = self.method.clone();
        let max_each_post_bytes = self.max_each_post_bytes.random();
        let min_posts_interval_ms = self.min_posts_interval_ms;
        let requests = self.packet_request_builder(session);
        tokio::spawn(async move {
            let mut sequence = 0u64;
            let result = async {
                loop {
                    let Some(payload) = read_packet(
                        &mut upload_reader,
                        max_each_post_bytes,
                        Duration::from_millis(min_posts_interval_ms.random() as u64),
                    )
                    .await?
                    else {
                        return Ok::<_, io::Error>(());
                    };
                    let (mut request, body) =
                        requests(method.clone(), sequence, &payload)?;
                    *request.version_mut() = Version::HTTP_3;
                    send_h3_packet(&mut sender, request, body).await?;
                    sequence += 1;
                }
            }
            .await;
            if let Err(error_value) = result {
                xhttp_err!("xhttp HTTP/3 packet-up upload error: {error_value}");
            }
        });
        Ok(Box::new(application))
    }

    async fn proxy_h2_upload_with_download(
        &self,
        sender: SendRequest<Bytes>,
        download: IndependentDownload,
    ) -> io::Result<AnyStream> {
        let session = new_session_id();
        let (application, worker) = tokio::io::duplex(64 * 1024);
        let (mut upload_reader, download_writer) = tokio::io::split(worker);
        self.start_independent_download(&session, download, download_writer)
            .await?;

        match self.mode {
            Mode::StreamUp => {
                let (upload_request, _) = self.request(
                    self.method.clone(),
                    Some(&session),
                    None,
                    None,
                    true,
                )?;
                let mut upload_sender =
                    sender.ready().await.map_err(map_io_error)?;
                let (upload_response, upload) = upload_sender
                    .send_request(upload_request, false)
                    .map_err(map_io_error)?;
                tokio::spawn(async move {
                    if let Err(error_value) =
                        drain_response(upload_response, "mixed HTTP/2 upload").await
                    {
                        error!("{error_value}");
                    }
                });
                tokio::spawn(async move {
                    if let Err(error_value) =
                        copy_upload(upload_reader, upload).await
                    {
                        error!(
                            "xhttp mixed HTTP/2 stream-up upload error: \
                             {error_value}"
                        );
                    }
                });
            }
            Mode::PacketUp => {
                let method = self.method.clone();
                let max_each_post_bytes = self.max_each_post_bytes.random();
                let min_posts_interval_ms = self.min_posts_interval_ms;
                let requests = self.packet_request_builder(session);
                tokio::spawn(async move {
                    let mut sequence = 0u64;
                    let result = async {
                        loop {
                            let Some(payload) = read_packet(
                                &mut upload_reader,
                                max_each_post_bytes,
                                Duration::from_millis(
                                    min_posts_interval_ms.random() as u64,
                                ),
                            )
                            .await?
                            else {
                                return Ok::<_, io::Error>(());
                            };
                            let (request, body) =
                                requests(method.clone(), sequence, &payload)?;
                            send_packet(&sender, request, body).await?;
                            sequence += 1;
                        }
                    }
                    .await;
                    if let Err(error_value) = result {
                        error!(
                            "xhttp mixed HTTP/2 packet-up upload error: \
                             {error_value}"
                        );
                    }
                });
            }
            Mode::StreamOne => {
                return Err(invalid_input(
                    "xhttp stream-one cannot use download-settings",
                ));
            }
        }
        Ok(Box::new(application))
    }

    async fn proxy_h3_upload_with_download(
        &self,
        mut sender: H3Sender,
        download: IndependentDownload,
    ) -> io::Result<AnyStream> {
        let session = new_session_id();
        let (application, worker) = tokio::io::duplex(64 * 1024);
        let (mut upload_reader, download_writer) = tokio::io::split(worker);
        self.start_independent_download(&session, download, download_writer)
            .await?;

        match self.mode {
            Mode::StreamUp => {
                let (mut upload_request, _) = self.request(
                    self.method.clone(),
                    Some(&session),
                    None,
                    None,
                    true,
                )?;
                *upload_request.version_mut() = Version::HTTP_3;
                let upload = sender
                    .send_request(upload_request)
                    .await
                    .map_err(io::Error::other)?;
                let (upload_send, upload_recv) = upload.split();
                tokio::spawn(async move {
                    if let Err(error_value) =
                        copy_h3_upload(upload_reader, upload_send).await
                    {
                        error!(
                            "xhttp mixed HTTP/3 stream-up upload error: \
                             {error_value}"
                        );
                    }
                });
                tokio::spawn(async move {
                    let _sender_guard = sender;
                    if let Err(error_value) =
                        drain_h3_response(upload_recv, "mixed HTTP/3 upload").await
                    {
                        error!("{error_value}");
                    }
                });
            }
            Mode::PacketUp => {
                let method = self.method.clone();
                let max_each_post_bytes = self.max_each_post_bytes.random();
                let min_posts_interval_ms = self.min_posts_interval_ms;
                let requests = self.packet_request_builder(session);
                tokio::spawn(async move {
                    let mut sequence = 0u64;
                    let result = async {
                        loop {
                            let Some(payload) = read_packet(
                                &mut upload_reader,
                                max_each_post_bytes,
                                Duration::from_millis(
                                    min_posts_interval_ms.random() as u64,
                                ),
                            )
                            .await?
                            else {
                                return Ok::<_, io::Error>(());
                            };
                            let (mut request, body) =
                                requests(method.clone(), sequence, &payload)?;
                            *request.version_mut() = Version::HTTP_3;
                            send_h3_packet(&mut sender, request, body).await?;
                            sequence += 1;
                        }
                    }
                    .await;
                    if let Err(error_value) = result {
                        error!(
                            "xhttp mixed HTTP/3 packet-up upload error: \
                             {error_value}"
                        );
                    }
                });
            }
            Mode::StreamOne => {
                return Err(invalid_input(
                    "xhttp stream-one cannot use download-settings",
                ));
            }
        }
        Ok(Box::new(application))
    }

    fn packet_request_builder(
        &self,
        session: String,
    ) -> impl Fn(Method, u64, &[u8]) -> io::Result<(Request<()>, Option<Bytes>)>
    + Send
    + Sync
    + 'static {
        let client = self.clone_for_requests();
        move |method, seq, payload| {
            client.request(method, Some(&session), Some(seq), Some(payload), false)
        }
    }

    fn clone_for_requests(&self) -> Self {
        Self {
            host: self.host.clone(),
            path: self.path.clone(),
            mode: self.mode,
            http_version: self.http_version,
            method: self.method.clone(),
            headers: self.headers.clone(),
            no_grpc_header: self.no_grpc_header,
            padding: self.padding,
            padding_obfs_mode: self.padding_obfs_mode,
            padding_key: self.padding_key.clone(),
            padding_header: self.padding_header.clone(),
            padding_placement: self.padding_placement,
            padding_method: self.padding_method.clone(),
            session_placement: self.session_placement,
            session_key: self.session_key.clone(),
            seq_placement: self.seq_placement,
            seq_key: self.seq_key.clone(),
            uplink_data_placement: self.uplink_data_placement,
            uplink_data_key: self.uplink_data_key.clone(),
            uplink_chunk_size: self.uplink_chunk_size,
            max_each_post_bytes: self.max_each_post_bytes,
            min_posts_interval_ms: self.min_posts_interval_ms,
            download: self.download.clone(),
            h3_tls: self.h3_tls.clone(),
            upload_reuse: self.upload_reuse.clone(),
            keep_alive_period: self.keep_alive_period,
        }
    }
}

#[async_trait]
impl Transport for Client {
    fn uses_datagram(&self) -> bool {
        self.http_version == HttpVersion::Http3
    }

    fn additional_datagrams(&self) -> usize {
        usize::from(
            self.mode != Mode::StreamOne
                && self.download.as_ref().is_some_and(|download| {
                    download.http_version == HttpVersion::Http3
                }),
        )
    }

    fn additional_streams(&self) -> usize {
        if self.mode == Mode::StreamOne {
            return 0;
        }
        match self.download.as_ref() {
            Some(download) => usize::from(matches!(
                download.http_version,
                HttpVersion::Http1 | HttpVersion::Http2
            )),
            None => usize::from(self.http_version == HttpVersion::Http1),
        }
    }

    async fn proxy_stream(&self, stream: AnyStream) -> io::Result<AnyStream> {
        if self.http_version == HttpVersion::Http3 {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "xhttp HTTP/3 requires a datagram socket",
            ));
        }
        if self.http_version == HttpVersion::Http1 {
            if self.mode != Mode::StreamOne {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidInput,
                    "xhttp HTTP/1.1 stream-up/packet-up require one additional \
                     stream",
                ));
            }
            let (sender, lease) = self
                .reusable_h1_sender(stream, self.upload_reuse.as_ref(), "stream-one")
                .await?;
            let result = self.proxy_http1_stream_one(sender).await?;
            return Ok(guard_reuse(result, lease.into_iter().collect()));
        }
        let (sender, lease) = self
            .reusable_h2_sender(
                stream,
                self.upload_reuse.as_ref(),
                self.keep_alive_period,
                "upload",
            )
            .await?;
        let result = match self.mode {
            Mode::StreamOne => self.proxy_stream_one(sender).await,
            Mode::StreamUp => self.proxy_stream_up(sender, None).await,
            Mode::PacketUp => self.proxy_packet_up(sender, None).await,
        }?;
        Ok(guard_reuse(result, lease.into_iter().collect()))
    }

    async fn proxy_stream_with_additional(
        &self,
        stream: AnyStream,
        additional: Vec<AnyStream>,
    ) -> io::Result<AnyStream> {
        if self.http_version == HttpVersion::Http1 && self.mode != Mode::StreamOne {
            self.proxy_http1_multi(stream, additional).await
        } else if self.http_version == HttpVersion::Http2
            && self.mode != Mode::StreamOne
            && self
                .download
                .as_ref()
                .is_some_and(|download| download.http_version == HttpVersion::Http2)
        {
            if additional.len() != 1 {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidInput,
                    "xhttp HTTP/2 download-settings require exactly one \
                     independent stream",
                ));
            }
            let download_stream =
                additional.into_iter().next().expect("length checked");
            let (sender, upload_lease) = self
                .reusable_h2_sender(
                    stream,
                    self.upload_reuse.as_ref(),
                    self.keep_alive_period,
                    "upload",
                )
                .await?;
            let download_manager = self
                .download
                .as_ref()
                .and_then(|download| download.reuse.as_ref());
            let download_keep_alive = self
                .download
                .as_ref()
                .and_then(|download| download.keep_alive_period);
            let (download_sender, download_lease) = self
                .reusable_h2_sender(
                    download_stream,
                    download_manager,
                    download_keep_alive,
                    "download",
                )
                .await?;
            let result = match self.mode {
                Mode::StreamUp => {
                    self.proxy_stream_up(sender, Some(download_sender)).await
                }
                Mode::PacketUp => {
                    self.proxy_packet_up(sender, Some(download_sender)).await
                }
                Mode::StreamOne => unreachable!("validated above"),
            }?;
            Ok(guard_reuse(
                result,
                upload_lease.into_iter().chain(download_lease).collect(),
            ))
        } else {
            debug_assert!(additional.is_empty());
            self.proxy_stream(stream).await
        }
    }

    async fn proxy_stream_with_additional_mixed(
        &self,
        stream: AnyStream,
        mut additional_streams: Vec<AnyStream>,
        mut additional_datagrams: Vec<(AnyOutboundDatagram, SocksAddr, SocketAddr)>,
    ) -> io::Result<AnyStream> {
        let Some(download) = self.download.as_ref() else {
            if !additional_datagrams.is_empty() {
                return Err(invalid_input(
                    "xhttp stream-primary transport received unexpected datagram \
                     resources",
                ));
            }
            return self
                .proxy_stream_with_additional(stream, additional_streams)
                .await;
        };
        if self.mode == Mode::StreamOne || download.http_version == self.http_version
        {
            if !additional_datagrams.is_empty() {
                return Err(invalid_input(
                    "xhttp stream-primary transport received unexpected datagram \
                     resources",
                ));
            }
            return self
                .proxy_stream_with_additional(stream, additional_streams)
                .await;
        }

        match (self.http_version, download.http_version) {
            (HttpVersion::Http1, HttpVersion::Http2) => {
                if additional_streams.len() != 1 || !additional_datagrams.is_empty()
                {
                    return Err(invalid_input(
                        "xhttp HTTP/1.1 upload with HTTP/2 download requires \
                         exactly one independent stream",
                    ));
                }
                let download_stream = additional_streams.pop().expect("checked");
                let (download_sender, download_lease) = self
                    .reusable_h2_sender(
                        download_stream,
                        download.reuse.as_ref(),
                        download.keep_alive_period,
                        "download",
                    )
                    .await?;
                let (upload_sender, upload_lease) = self
                    .reusable_h1_sender(stream, self.upload_reuse.as_ref(), "upload")
                    .await?;
                let result = self
                    .proxy_http1_upload_with_download(
                        upload_sender,
                        IndependentDownload::Http2(download_sender),
                    )
                    .await?;
                Ok(guard_reuse(
                    result,
                    upload_lease.into_iter().chain(download_lease).collect(),
                ))
            }
            (HttpVersion::Http1, HttpVersion::Http3)
            | (HttpVersion::Http2, HttpVersion::Http3) => {
                if !additional_streams.is_empty() || additional_datagrams.len() != 1
                {
                    return Err(invalid_input(
                        "xhttp stream upload with HTTP/3 download requires exactly \
                         one independent datagram",
                    ));
                }
                let download_tls = download.h3_tls.as_ref().ok_or_else(|| {
                    invalid_input(
                        "xhttp HTTP/3 download-settings require download TLS \
                         settings",
                    )
                })?;
                let (download_datagram, destination, remote_addr) =
                    additional_datagrams.pop().expect("checked");
                let (download_sender, download_lease) = self
                    .reusable_h3_sender(
                        download_datagram,
                        destination,
                        remote_addr,
                        download_tls,
                        download.reuse.as_ref(),
                        download.keep_alive_period,
                    )
                    .await?;
                let independent = IndependentDownload::Http3(download_sender);
                if self.http_version == HttpVersion::Http1 {
                    let (upload_sender, upload_lease) = self
                        .reusable_h1_sender(
                            stream,
                            self.upload_reuse.as_ref(),
                            "upload",
                        )
                        .await?;
                    let result = self
                        .proxy_http1_upload_with_download(upload_sender, independent)
                        .await?;
                    Ok(guard_reuse(
                        result,
                        upload_lease.into_iter().chain(download_lease).collect(),
                    ))
                } else {
                    let (sender, upload_lease) = self
                        .reusable_h2_sender(
                            stream,
                            self.upload_reuse.as_ref(),
                            self.keep_alive_period,
                            "upload",
                        )
                        .await?;
                    let result = self
                        .proxy_h2_upload_with_download(sender, independent)
                        .await?;
                    Ok(guard_reuse(
                        result,
                        upload_lease.into_iter().chain(download_lease).collect(),
                    ))
                }
            }
            (HttpVersion::Http2, HttpVersion::Http1) => {
                if additional_streams.len() != 1 || !additional_datagrams.is_empty()
                {
                    return Err(invalid_input(
                        "xhttp HTTP/2 upload with HTTP/1.1 download requires \
                         exactly one independent stream",
                    ));
                }
                let download_stream = additional_streams.pop().expect("checked");
                let (download_sender, download_lease) = self
                    .reusable_h1_sender(
                        download_stream,
                        download.reuse.as_ref(),
                        "download",
                    )
                    .await?;
                let (sender, upload_lease) = self
                    .reusable_h2_sender(
                        stream,
                        self.upload_reuse.as_ref(),
                        self.keep_alive_period,
                        "upload",
                    )
                    .await?;
                let result = self
                    .proxy_h2_upload_with_download(
                        sender,
                        IndependentDownload::Http1(download_sender),
                    )
                    .await?;
                Ok(guard_reuse(
                    result,
                    upload_lease.into_iter().chain(download_lease).collect(),
                ))
            }
            _ => Err(invalid_input(
                "invalid xhttp stream-primary HTTP version combination",
            )),
        }
    }

    async fn proxy_datagram(
        &self,
        datagram: AnyOutboundDatagram,
        destination: SocksAddr,
        remote_addr: SocketAddr,
    ) -> io::Result<AnyStream> {
        if self.http_version != HttpVersion::Http3 {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "xhttp HTTP/1.1 and HTTP/2 require a stream socket",
            ));
        }
        let tls = self
            .h3_tls
            .as_ref()
            .ok_or_else(|| invalid_input("xhttp HTTP/3 requires TLS settings"))?;
        let (sender, lease) = self
            .reusable_h3_sender(
                datagram,
                destination,
                remote_addr,
                tls,
                self.upload_reuse.as_ref(),
                self.keep_alive_period,
            )
            .await?;
        let result = match self.mode {
            Mode::StreamOne => self.proxy_h3_stream_one(sender).await,
            Mode::StreamUp => self.proxy_h3_stream_up(sender, None).await,
            Mode::PacketUp => self.proxy_h3_packet_up(sender, None).await,
        }?;
        Ok(guard_reuse(result, lease.into_iter().collect()))
    }

    async fn proxy_datagram_with_additional(
        &self,
        datagram: AnyOutboundDatagram,
        destination: SocksAddr,
        remote_addr: SocketAddr,
        additional: Vec<(AnyOutboundDatagram, SocksAddr, SocketAddr)>,
    ) -> io::Result<AnyStream> {
        if self.http_version != HttpVersion::Http3
            || !self
                .download
                .as_ref()
                .is_some_and(|download| download.http_version == HttpVersion::Http3)
        {
            debug_assert!(additional.is_empty());
            return self
                .proxy_datagram(datagram, destination, remote_addr)
                .await;
        }
        if additional.len() != 1 {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "xhttp HTTP/3 download-settings require exactly one independent \
                 datagram",
            ));
        }
        let primary_tls = self
            .h3_tls
            .as_ref()
            .ok_or_else(|| invalid_input("xhttp HTTP/3 requires TLS settings"))?;
        let download_tls = self
            .download
            .as_ref()
            .and_then(|download| download.h3_tls.as_ref())
            .ok_or_else(|| {
                invalid_input(
                    "xhttp HTTP/3 download-settings require download TLS settings",
                )
            })?;
        let (sender, upload_lease) = self
            .reusable_h3_sender(
                datagram,
                destination,
                remote_addr,
                primary_tls,
                self.upload_reuse.as_ref(),
                self.keep_alive_period,
            )
            .await?;
        let (download_datagram, download_destination, download_remote_addr) =
            additional.into_iter().next().expect("length checked");
        let download_manager = self
            .download
            .as_ref()
            .and_then(|download| download.reuse.as_ref());
        let download_keep_alive = self
            .download
            .as_ref()
            .and_then(|download| download.keep_alive_period);
        let (download_sender, download_lease) = self
            .reusable_h3_sender(
                download_datagram,
                download_destination,
                download_remote_addr,
                download_tls,
                download_manager,
                download_keep_alive,
            )
            .await?;
        let result = match self.mode {
            Mode::StreamUp => {
                self.proxy_h3_stream_up(sender, Some(download_sender)).await
            }
            Mode::PacketUp => {
                self.proxy_h3_packet_up(sender, Some(download_sender)).await
            }
            Mode::StreamOne => Err(invalid_input(
                "xhttp stream-one cannot use download-settings",
            )),
        }?;
        Ok(guard_reuse(
            result,
            upload_lease.into_iter().chain(download_lease).collect(),
        ))
    }

    async fn proxy_datagram_with_additional_mixed(
        &self,
        datagram: AnyOutboundDatagram,
        destination: SocksAddr,
        remote_addr: SocketAddr,
        mut additional_streams: Vec<AnyStream>,
        additional_datagrams: Vec<(AnyOutboundDatagram, SocksAddr, SocketAddr)>,
    ) -> io::Result<AnyStream> {
        let Some(download) = self.download.as_ref() else {
            if !additional_streams.is_empty() {
                return Err(invalid_input(
                    "xhttp datagram-primary transport received unexpected stream \
                     resources",
                ));
            }
            return self
                .proxy_datagram_with_additional(
                    datagram,
                    destination,
                    remote_addr,
                    additional_datagrams,
                )
                .await;
        };
        if self.mode == Mode::StreamOne
            || download.http_version == HttpVersion::Http3
        {
            if !additional_streams.is_empty() {
                return Err(invalid_input(
                    "xhttp datagram-primary transport received unexpected stream \
                     resources",
                ));
            }
            return self
                .proxy_datagram_with_additional(
                    datagram,
                    destination,
                    remote_addr,
                    additional_datagrams,
                )
                .await;
        }
        if additional_streams.len() != 1 || !additional_datagrams.is_empty() {
            return Err(invalid_input(
                "xhttp HTTP/3 upload with stream-based download requires exactly \
                 one independent stream",
            ));
        }
        let primary_tls = self
            .h3_tls
            .as_ref()
            .ok_or_else(|| invalid_input("xhttp HTTP/3 requires TLS settings"))?;
        let (sender, upload_lease) = self
            .reusable_h3_sender(
                datagram,
                destination,
                remote_addr,
                primary_tls,
                self.upload_reuse.as_ref(),
                self.keep_alive_period,
            )
            .await?;
        let download = self.download.as_ref().expect("mixed mode checked");
        let download_stream = additional_streams.pop().expect("length checked");
        let (independent, download_lease) =
            if download.http_version == HttpVersion::Http2 {
                let (download_sender, lease) = self
                    .reusable_h2_sender(
                        download_stream,
                        download.reuse.as_ref(),
                        download.keep_alive_period,
                        "download",
                    )
                    .await?;
                (IndependentDownload::Http2(download_sender), lease)
            } else {
                let (download_sender, lease) = self
                    .reusable_h1_sender(
                        download_stream,
                        download.reuse.as_ref(),
                        "download",
                    )
                    .await?;
                (IndependentDownload::Http1(download_sender), lease)
            };
        let result = self
            .proxy_h3_upload_with_download(sender, independent)
            .await?;
        Ok(guard_reuse(
            result,
            upload_lease.into_iter().chain(download_lease).collect(),
        ))
    }
}

async fn copy_http1_upload(
    mut input: tokio::io::ReadHalf<tokio::io::DuplexStream>,
    mut sender: http_body_util::channel::Sender<Bytes, io::Error>,
) -> io::Result<()> {
    let mut buffer = vec![0u8; 64 * 1024];
    loop {
        let size = input.read(&mut buffer).await?;
        if size == 0 {
            return Ok(());
        }
        sender
            .send_data(Bytes::copy_from_slice(&buffer[..size]))
            .await
            .map_err(io::Error::other)?;
    }
}

fn empty_http1_body() -> Http1Body {
    Empty::<Bytes>::new()
        .map_err(|never| match never {})
        .boxed_unsync()
}

fn full_http1_body(body: Bytes) -> Http1Body {
    Full::new(body)
        .map_err(|never| match never {})
        .boxed_unsync()
}

async fn copy_http1_response<B>(
    response: &mut http::Response<B>,
    output: &mut tokio::io::WriteHalf<tokio::io::DuplexStream>,
) -> io::Result<()>
where
    B: hyper::body::Body<Data = Bytes> + Unpin,
    B::Error: std::error::Error + Send + Sync + 'static,
{
    while let Some(frame) = response.body_mut().frame().await {
        let frame = frame.map_err(io::Error::other)?;
        if let Ok(data) = frame.into_data() {
            output.write_all(&data).await?;
        }
    }
    Ok(())
}

fn invalid_input(error: impl std::fmt::Display) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidInput, error.to_string())
}

fn keep_alive_interval(value: Option<i64>, fallback: Duration) -> Option<Duration> {
    match value {
        Some(value) if value < 0 => None,
        Some(0) | None => Some(fallback),
        Some(value) => Some(Duration::from_secs(value as u64)),
    }
}

fn normalize_path(mut path: String) -> String {
    if path.trim().is_empty() {
        path = "/".to_owned();
    }
    if !path.starts_with('/') {
        path.insert(0, '/');
    }
    if !path.ends_with('/') {
        path.push('/');
    }
    path
}

fn parse_headers(values: HashMap<String, String>) -> io::Result<HeaderMap> {
    let mut headers = HeaderMap::new();
    for (name, value) in values {
        let name = name.parse::<HeaderName>().map_err(|error| {
            invalid_input(format!("invalid xhttp header name: {error}"))
        })?;
        let value = value.parse::<HeaderValue>().map_err(|error| {
            invalid_input(format!("invalid xhttp header value: {error}"))
        })?;
        headers.insert(name, value);
    }
    apply_default_fetch_headers(&mut headers)?;
    Ok(headers)
}

fn required_header_name(value: &str, field: &str) -> io::Result<HeaderName> {
    if value.is_empty() {
        return Err(invalid_input(format!("{field} must not be empty")));
    }
    value
        .parse()
        .map_err(|error| invalid_input(format!("invalid {field}: {error}")))
}

fn apply_default_fetch_headers(headers: &mut HeaderMap) -> io::Result<()> {
    let browser = headers
        .get(http::header::USER_AGENT)
        .and_then(|value| value.to_str().ok());
    let user_agent = match browser {
        None | Some("chrome") => Some(
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, \
             like Gecko) Chrome/144.0.0.0 Safari/537.36",
        ),
        Some("edge") => Some(
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, \
             like Gecko) Chrome/144.0.0.0 Safari/537.36 Edg/144.0.0.0",
        ),
        Some("firefox") => Some(
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:147.0) Gecko/20100101 \
             Firefox/147.0",
        ),
        Some("safari") => Some(
            "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 \
             (KHTML, like Gecko) Version/26.0 Safari/605.1.15",
        ),
        Some("curl") => Some("curl/8.16.0"),
        Some("golang") => {
            headers.remove(http::header::USER_AGENT);
            None
        }
        Some(_) => None,
    };
    if let Some(user_agent) = user_agent {
        headers.insert(
            http::header::USER_AGENT,
            HeaderValue::from_static(user_agent),
        );
        headers
            .entry(http::header::ACCEPT_LANGUAGE)
            .or_insert(HeaderValue::from_static("en-US,en;q=0.9"));
    }
    for (name, value) in [
        ("sec-fetch-mode", "cors"),
        ("sec-fetch-dest", "empty"),
        ("sec-fetch-site", "same-origin"),
        ("priority", "u=1, i"),
        ("cache-control", "no-cache"),
        ("pragma", "no-cache"),
        ("accept", "*/*"),
    ] {
        let name = HeaderName::from_static(name);
        headers
            .entry(name)
            .or_insert(HeaderValue::from_static(value));
    }
    Ok(())
}

fn apply_metadata_value(
    url: &mut Url,
    headers: &mut HeaderMap,
    placement: Placement,
    key: &str,
    value: &str,
) -> io::Result<()> {
    match placement {
        Placement::Path => {
            let mut path = url.path().trim_end_matches('/').to_owned();
            path.push('/');
            path.push_str(value);
            url.set_path(&path);
        }
        Placement::Query => {
            url.query_pairs_mut().append_pair(key, value);
        }
        Placement::Header => {
            let name = required_header_name(key, "xhttp metadata key")?;
            headers
                .insert(name, HeaderValue::from_str(value).map_err(invalid_input)?);
        }
        Placement::Cookie => add_cookie(headers, key, value)?,
        _ => unreachable!("metadata placement validated by Client::new"),
    }
    Ok(())
}

fn add_cookie(headers: &mut HeaderMap, key: &str, value: &str) -> io::Result<()> {
    if key.is_empty() {
        return Err(invalid_input("xhttp cookie key must not be empty"));
    }
    let cookie = format!("{key}={value}");
    let combined = match headers.get(http::header::COOKIE) {
        Some(existing) => {
            format!("{}; {cookie}", existing.to_str().map_err(invalid_input)?)
        }
        None => cookie,
    };
    headers.insert(
        http::header::COOKIE,
        HeaderValue::from_str(&combined).map_err(invalid_input)?,
    );
    Ok(())
}

fn random_base62(length: usize) -> String {
    const BASE62: &[u8] =
        b"0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz";
    (0..length)
        .map(|_| BASE62[rand::random_range(0..BASE62.len())] as char)
        .collect()
}

fn tokenish_padding(target_huffman_bytes: usize) -> String {
    if target_huffman_bytes == 0 {
        return String::new();
    }
    let initial_length = (target_huffman_bytes * 5).div_ceil(4).max(1);
    let mut padding = random_base62(initial_length);
    let mut adjustment = 'X';
    for _ in 0..150 {
        let current = hpack_huffman_bytes(&padding);
        if current.abs_diff(target_huffman_bytes) <= 2 {
            return padding;
        }
        if current < target_huffman_bytes {
            padding.push(adjustment);
            adjustment = if adjustment == 'X' { 'Z' } else { 'X' };
        } else if padding.pop().is_none() {
            break;
        }
    }
    padding
}

fn hpack_huffman_bytes(value: &str) -> usize {
    let bits = value
        .bytes()
        .map(|value| match value {
            b'0'..=b'2' => 5,
            b'3'..=b'9' => 6,
            b'A' => 6,
            b'B'..=b'W' | b'Y' => 7,
            b'X' | b'Z' => 8,
            b'a' | b'c' | b'e' | b'i' | b'o' | b's' | b't' => 5,
            b'b' | b'd' | b'f'..=b'h' | b'l'..=b'n' | b'p' | b'r' | b'u' => 6,
            b'j' | b'k' | b'q' | b'v'..=b'z' => 7,
            _ => 8,
        })
        .sum::<usize>();
    bits.div_ceil(8)
}

fn new_session_id() -> String {
    let mut bytes = [0u8; 16];
    rand::rng().fill_bytes(&mut bytes);
    bytes.iter().map(|value| format!("{value:02x}")).collect()
}

fn split_random(value: &str, range: ValueRange) -> impl Iterator<Item = &str> {
    let mut rest = value;
    std::iter::from_fn(move || {
        if rest.is_empty() {
            return None;
        }
        let size = range.random().min(rest.len());
        let (chunk, remaining) = rest.split_at(size);
        rest = remaining;
        Some(chunk)
    })
}

fn spawn_stream(
    response: h2::client::ResponseFuture,
    upload: SendStream<Bytes>,
    label: &'static str,
) -> AnyStream {
    let (application, worker) = tokio::io::duplex(64 * 1024);
    let (upload_reader, download_writer) = tokio::io::split(worker);
    spawn_download(response, download_writer, label);
    tokio::spawn(async move {
        if let Err(error_value) = copy_upload(upload_reader, upload).await {
            xhttp_err!("xhttp {label} upload error: {error_value}");
        }
    });
    Box::new(application)
}

fn spawn_h3_stream(
    stream: h3::client::RequestStream<h3_quinn::BidiStream<Bytes>, Bytes>,
    sender: H3Sender,
    label: &'static str,
) -> AnyStream {
    let (upload, download) = stream.split();
    let (application, worker) = tokio::io::duplex(64 * 1024);
    let (upload_reader, mut download_writer) = tokio::io::split(worker);
    tokio::spawn(async move {
        if let Err(error_value) = copy_h3_upload(upload_reader, upload).await {
            xhttp_err!("xhttp HTTP/3 {label} upload error: {error_value}");
        }
    });
    tokio::spawn(async move {
        let _sender_guard = sender;
        let mut download = download;
        if let Err(error_value) =
            copy_h3_response(&mut download, &mut download_writer, label).await
        {
            error!("{error_value}");
        }
        let _ = download_writer.shutdown().await;
    });
    Box::new(application)
}

async fn copy_h3_upload<S>(
    mut input: tokio::io::ReadHalf<tokio::io::DuplexStream>,
    mut stream: h3::client::RequestStream<S, Bytes>,
) -> io::Result<()>
where
    S: h3::quic::SendStream<Bytes>,
{
    let mut buffer = vec![0u8; 64 * 1024];
    loop {
        let size = input.read(&mut buffer).await?;
        if size == 0 {
            stream.finish().await.map_err(io::Error::other)?;
            return Ok(());
        }
        stream
            .send_data(Bytes::copy_from_slice(&buffer[..size]))
            .await
            .map_err(io::Error::other)?;
    }
}

async fn copy_h3_response<S>(
    stream: &mut h3::client::RequestStream<S, Bytes>,
    output: &mut tokio::io::WriteHalf<tokio::io::DuplexStream>,
    label: &str,
) -> io::Result<()>
where
    S: h3::quic::RecvStream,
{
    let response = stream.recv_response().await.map_err(io::Error::other)?;
    if !response.status().is_success() {
        return Err(io::Error::new(
            io::ErrorKind::ConnectionRefused,
            format!("xhttp HTTP/3 {label} bad status: {}", response.status()),
        ));
    }
    while let Some(mut data) = stream.recv_data().await.map_err(io::Error::other)? {
        let length = data.remaining();
        output.write_all(&data.copy_to_bytes(length)).await?;
    }
    Ok(())
}

async fn drain_h3_response<S>(
    mut stream: h3::client::RequestStream<S, Bytes>,
    label: &str,
) -> io::Result<()>
where
    S: h3::quic::RecvStream,
{
    let response = stream.recv_response().await.map_err(io::Error::other)?;
    if !response.status().is_success() {
        return Err(io::Error::new(
            io::ErrorKind::ConnectionRefused,
            format!("xhttp HTTP/3 {label} bad status: {}", response.status()),
        ));
    }
    while stream
        .recv_data()
        .await
        .map_err(io::Error::other)?
        .is_some()
    {}
    Ok(())
}

fn spawn_download(
    response: h2::client::ResponseFuture,
    mut output: tokio::io::WriteHalf<tokio::io::DuplexStream>,
    label: &'static str,
) {
    tokio::spawn(async move {
        let result = async {
            let response = response.await.map_err(map_io_error)?;
            if !response.status().is_success() {
                return Err(io::Error::new(
                    io::ErrorKind::ConnectionRefused,
                    format!("xhttp {label} bad status: {}", response.status()),
                ));
            }
            copy_download(response.into_body(), &mut output).await
        }
        .await;
        if let Err(error_value) = result {
            xhttp_err!("xhttp {label} error: {error_value}");
        }
        let _ = output.shutdown().await;
    });
}

async fn copy_download(
    mut body: RecvStream,
    output: &mut tokio::io::WriteHalf<tokio::io::DuplexStream>,
) -> io::Result<()> {
    while let Some(data) = body.data().await {
        let data = data.map_err(map_io_error)?;
        body.flow_control()
            .release_capacity(data.len())
            .map_err(map_io_error)?;
        output.write_all(&data).await?;
    }
    Ok(())
}

async fn copy_upload(
    mut input: tokio::io::ReadHalf<tokio::io::DuplexStream>,
    mut stream: SendStream<Bytes>,
) -> io::Result<()> {
    let mut buffer = vec![0u8; 64 * 1024];
    loop {
        let size = input.read(&mut buffer).await?;
        if size == 0 {
            stream.send_data(Bytes::new(), true).map_err(map_io_error)?;
            return Ok(());
        }
        send_data(&mut stream, Bytes::copy_from_slice(&buffer[..size]), false)
            .await?;
    }
}

async fn send_data(
    stream: &mut SendStream<Bytes>,
    data: Bytes,
    end_stream: bool,
) -> io::Result<()> {
    stream.send_data(data, end_stream).map_err(map_io_error)
}

async fn drain_response(
    response: h2::client::ResponseFuture,
    label: &str,
) -> io::Result<()> {
    let response = response.await.map_err(map_io_error)?;
    if !response.status().is_success() {
        return Err(io::Error::new(
            io::ErrorKind::ConnectionRefused,
            format!("xhttp {label} bad status: {}", response.status()),
        ));
    }
    let mut body = response.into_body();
    while let Some(data) = body.data().await {
        let data = data.map_err(map_io_error)?;
        body.flow_control()
            .release_capacity(data.len())
            .map_err(map_io_error)?;
    }
    Ok(())
}

async fn read_packet(
    input: &mut tokio::io::ReadHalf<tokio::io::DuplexStream>,
    max_size: usize,
    interval: Duration,
) -> io::Result<Option<Vec<u8>>> {
    let mut payload = Vec::with_capacity(max_size.min(64 * 1024));
    let mut buffer = vec![0u8; max_size.min(64 * 1024)];
    let size = input.read(&mut buffer).await?;
    if size == 0 {
        return Ok(None);
    }
    payload.extend_from_slice(&buffer[..size]);
    let deadline = tokio::time::sleep(interval);
    tokio::pin!(deadline);
    while payload.len() < max_size {
        let limit = (max_size - payload.len()).min(buffer.len());
        tokio::select! {
            _ = &mut deadline => break,
            result = input.read(&mut buffer[..limit]) => {
                let size = result?;
                if size == 0 {
                    break;
                }
                payload.extend_from_slice(&buffer[..size]);
            }
        }
    }
    Ok(Some(payload))
}

async fn send_packet(
    sender: &SendRequest<Bytes>,
    request: Request<()>,
    body: Option<Bytes>,
) -> io::Result<()> {
    let mut sender = sender.clone().ready().await.map_err(map_io_error)?;
    let end_stream = body.is_none();
    let (response, mut stream) = sender
        .send_request(request, end_stream)
        .map_err(map_io_error)?;
    if let Some(body) = body {
        send_data(&mut stream, body, true).await?;
    }
    let response = response.await.map_err(map_io_error)?;
    if response.status() != StatusCode::OK {
        return Err(io::Error::new(
            io::ErrorKind::ConnectionRefused,
            format!("xhttp packet-up bad status: {}", response.status()),
        ));
    }
    let mut body = response.into_body();
    while let Some(data) = body.data().await {
        let data = data.map_err(map_io_error)?;
        body.flow_control()
            .release_capacity(data.len())
            .map_err(map_io_error)?;
    }
    Ok(())
}

async fn send_h3_packet(
    sender: &mut H3Sender,
    request: Request<()>,
    body: Option<Bytes>,
) -> io::Result<()> {
    let mut stream = sender
        .send_request(request)
        .await
        .map_err(io::Error::other)?;
    if let Some(body) = body {
        stream.send_data(body).await.map_err(io::Error::other)?;
    }
    stream.finish().await.map_err(io::Error::other)?;
    let response = stream.recv_response().await.map_err(io::Error::other)?;
    if response.status() != StatusCode::OK {
        return Err(io::Error::new(
            io::ErrorKind::ConnectionRefused,
            format!("xhttp HTTP/3 packet-up bad status: {}", response.status()),
        ));
    }
    while stream
        .recv_data()
        .await
        .map_err(io::Error::other)?
        .is_some()
    {}
    Ok(())
}

#[cfg(test)]
mod tests {
    use std::{
        collections::HashMap,
        convert::Infallible,
        io,
        net::{Ipv4Addr, SocketAddr},
        sync::{Arc, Mutex},
        time::Duration,
    };

    use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
    use bytes::{Buf, Bytes};
    use http::{Method, StatusCode, Version};
    use http_body_util::{BodyExt, Full, channel::Channel};
    use hyper_util::rt::TokioIo;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    use super::{Client, ClientConfig, DownloadConfig, H3TlsConfig, ReuseConfig};
    use crate::{
        app::dns::SystemResolver,
        common::tls::resolve_server_cert_and_key,
        proxy::{direct::datagram::OutboundDatagramImpl, transport::Transport},
        session::SocksAddr,
    };

    fn config(mode: &str) -> ClientConfig {
        ClientConfig {
            host: "cdn.example.com".to_owned(),
            path: "xhttp".to_owned(),
            mode: mode.to_owned(),
            headers: [("X-Test".to_owned(), "flclash".to_owned())]
                .into_iter()
                .collect(),
            ..Default::default()
        }
    }

    async fn serve_h2_echo_once(stream: tokio::io::DuplexStream) {
        let mut connection = h2::server::handshake(stream).await.unwrap();
        let (request, mut response) = connection.accept().await.unwrap().unwrap();
        let handler = tokio::spawn(async move {
            let mut body = request.into_body();
            let reply = http::Response::builder().status(200).body(()).unwrap();
            let mut output = response.send_response(reply, false).unwrap();
            let data = body.data().await.unwrap().unwrap();
            body.flow_control().release_capacity(data.len()).unwrap();
            output.send_data(data, true).unwrap();
        });
        while let Some(request) = connection.accept().await {
            request.unwrap();
            panic!("unexpected reused request on rotated H2 connection");
        }
        handler.await.unwrap();
    }

    async fn serve_h3_stream_one_echo() -> SocketAddr {
        let (certs, key) =
            resolve_server_cert_and_key(None, None, "xhttp-test").unwrap();
        let mut tls = rustls::ServerConfig::builder()
            .with_no_client_auth()
            .with_single_cert(certs, key)
            .unwrap();
        tls.alpn_protocols = vec![b"h3".to_vec()];
        let quic_tls =
            quinn::crypto::rustls::QuicServerConfig::try_from(tls).unwrap();
        let server_config = quinn::ServerConfig::with_crypto(Arc::new(quic_tls));
        let endpoint = quinn::Endpoint::server(
            server_config,
            SocketAddr::new(Ipv4Addr::LOCALHOST.into(), 0),
        )
        .unwrap();
        let address = endpoint.local_addr().unwrap();
        tokio::spawn(async move {
            let incoming = endpoint.accept().await.unwrap();
            let connection = incoming.await.unwrap();
            let h3_connection = h3_quinn::Connection::new(connection);
            let mut server = h3::server::builder()
                .build::<_, Bytes>(h3_connection)
                .await
                .unwrap();
            use h3::server::RequestResolver;
            let resolver: RequestResolver<_, _> =
                server.accept().await.unwrap().unwrap();
            let (request, mut stream) = resolver.resolve_request().await.unwrap();
            assert_eq!(request.method(), Method::POST);
            assert_eq!(request.version(), Version::HTTP_3);
            assert_eq!(request.uri().path(), "/xhttp/");
            stream
                .send_response(
                    http::Response::builder()
                        .status(StatusCode::OK)
                        .body(())
                        .unwrap(),
                )
                .await
                .unwrap();
            while let Some(mut data) = stream.recv_data().await.unwrap() {
                let length = data.remaining();
                stream.send_data(data.copy_to_bytes(length)).await.unwrap();
            }
            stream.finish().await.unwrap();
        });
        address
    }

    async fn serve_h3_reuse_echo() -> SocketAddr {
        let (certs, key) =
            resolve_server_cert_and_key(None, None, "xhttp-test").unwrap();
        let mut tls = rustls::ServerConfig::builder()
            .with_no_client_auth()
            .with_single_cert(certs, key)
            .unwrap();
        tls.alpn_protocols = vec![b"h3".to_vec()];
        let quic_tls =
            quinn::crypto::rustls::QuicServerConfig::try_from(tls).unwrap();
        let server_config = quinn::ServerConfig::with_crypto(Arc::new(quic_tls));
        let endpoint = quinn::Endpoint::server(
            server_config,
            SocketAddr::new(Ipv4Addr::LOCALHOST.into(), 0),
        )
        .unwrap();
        let address = endpoint.local_addr().unwrap();
        tokio::spawn(async move {
            let incoming = endpoint.accept().await.unwrap();
            let connection = incoming.await.unwrap();
            let h3_connection = h3_quinn::Connection::new(connection);
            let mut server = h3::server::builder()
                .build::<_, Bytes>(h3_connection)
                .await
                .unwrap();
            use h3::server::RequestResolver;
            let mut handlers = Vec::new();
            for _ in 0..2 {
                let resolver: RequestResolver<_, _> =
                    server.accept().await.unwrap().unwrap();
                let (request, mut stream) =
                    resolver.resolve_request().await.unwrap();
                assert_eq!(request.method(), Method::POST);
                handlers.push(tokio::spawn(async move {
                    stream
                        .send_response(
                            http::Response::builder()
                                .status(StatusCode::OK)
                                .body(())
                                .unwrap(),
                        )
                        .await
                        .unwrap();
                    if let Some(mut data) = stream.recv_data().await.unwrap() {
                        let length = data.remaining();
                        stream.send_data(data.copy_to_bytes(length)).await.unwrap();
                    }
                    let _ = stream.finish().await;
                }));
            }
            let _ = server.accept().await;
            for handler in handlers {
                handler.await.unwrap();
            }
        });
        address
    }

    async fn serve_h3_multi_echo() -> SocketAddr {
        let (certs, key) =
            resolve_server_cert_and_key(None, None, "xhttp-test").unwrap();
        let mut tls = rustls::ServerConfig::builder()
            .with_no_client_auth()
            .with_single_cert(certs, key)
            .unwrap();
        tls.alpn_protocols = vec![b"h3".to_vec()];
        let quic_tls =
            quinn::crypto::rustls::QuicServerConfig::try_from(tls).unwrap();
        let server_config = quinn::ServerConfig::with_crypto(Arc::new(quic_tls));
        let endpoint = quinn::Endpoint::server(
            server_config,
            SocketAddr::new(Ipv4Addr::LOCALHOST.into(), 0),
        )
        .unwrap();
        let address = endpoint.local_addr().unwrap();
        tokio::spawn(async move {
            let incoming = endpoint.accept().await.unwrap();
            let connection = incoming.await.unwrap();
            let h3_connection = h3_quinn::Connection::new(connection);
            let mut server = h3::server::builder()
                .build::<_, Bytes>(h3_connection)
                .await
                .unwrap();
            let (payload_tx, payload_rx) =
                tokio::sync::mpsc::unbounded_channel::<Bytes>();
            let payload_rx = Arc::new(Mutex::new(Some(payload_rx)));
            use h3::server::RequestResolver;
            while let Some(resolver) = server.accept().await.unwrap() {
                let resolver: RequestResolver<_, _> = resolver;
                let (request, mut stream) =
                    resolver.resolve_request().await.unwrap();
                assert_eq!(request.version(), Version::HTTP_3);
                assert!(request.uri().path().starts_with("/xhttp/"));
                if request.method() == Method::GET {
                    let mut payload_rx = payload_rx
                        .lock()
                        .unwrap()
                        .take()
                        .expect("one H3 download request expected");
                    tokio::spawn(async move {
                        stream
                            .send_response(
                                http::Response::builder()
                                    .status(StatusCode::OK)
                                    .body(())
                                    .unwrap(),
                            )
                            .await
                            .unwrap();
                        while let Some(payload) = payload_rx.recv().await {
                            stream.send_data(payload).await.unwrap();
                        }
                        let _ = stream.finish().await;
                    });
                } else {
                    assert_eq!(request.method(), Method::POST);
                    let payload_tx = payload_tx.clone();
                    tokio::spawn(async move {
                        stream
                            .send_response(
                                http::Response::builder()
                                    .status(StatusCode::OK)
                                    .body(())
                                    .unwrap(),
                            )
                            .await
                            .unwrap();
                        while let Some(mut data) = stream.recv_data().await.unwrap()
                        {
                            let length = data.remaining();
                            payload_tx.send(data.copy_to_bytes(length)).unwrap();
                        }
                        let _ = stream.finish().await;
                    });
                }
            }
        });
        address
    }

    async fn serve_h3_split_echo() -> SocketAddr {
        let (certs, key) =
            resolve_server_cert_and_key(None, None, "xhttp-test").unwrap();
        let mut tls = rustls::ServerConfig::builder()
            .with_no_client_auth()
            .with_single_cert(certs, key)
            .unwrap();
        tls.alpn_protocols = vec![b"h3".to_vec()];
        let quic_tls =
            quinn::crypto::rustls::QuicServerConfig::try_from(tls).unwrap();
        let server_config = quinn::ServerConfig::with_crypto(Arc::new(quic_tls));
        let endpoint = quinn::Endpoint::server(
            server_config,
            SocketAddr::new(Ipv4Addr::LOCALHOST.into(), 0),
        )
        .unwrap();
        let address = endpoint.local_addr().unwrap();
        tokio::spawn(async move {
            let (payload_tx, payload_rx) =
                tokio::sync::mpsc::unbounded_channel::<Bytes>();
            let payload_rx = Arc::new(Mutex::new(Some(payload_rx)));
            for _ in 0..2 {
                let incoming = endpoint.accept().await.unwrap();
                let payload_tx = payload_tx.clone();
                let payload_rx = payload_rx.clone();
                tokio::spawn(async move {
                    let connection = incoming.await.unwrap();
                    let h3_connection = h3_quinn::Connection::new(connection);
                    let mut server = h3::server::builder()
                        .build::<_, Bytes>(h3_connection)
                        .await
                        .unwrap();
                    use h3::server::RequestResolver;
                    while let Some(resolver) = server.accept().await.unwrap() {
                        let resolver: RequestResolver<_, _> = resolver;
                        let (request, mut stream) =
                            resolver.resolve_request().await.unwrap();
                        assert_eq!(request.version(), Version::HTTP_3);
                        if request.method() == Method::GET {
                            let mut payload_rx = payload_rx
                                .lock()
                                .unwrap()
                                .take()
                                .expect("one independent H3 download expected");
                            tokio::spawn(async move {
                                stream
                                    .send_response(
                                        http::Response::builder()
                                            .status(StatusCode::OK)
                                            .body(())
                                            .unwrap(),
                                    )
                                    .await
                                    .unwrap();
                                while let Some(payload) = payload_rx.recv().await {
                                    stream.send_data(payload).await.unwrap();
                                }
                                let _ = stream.finish().await;
                            });
                        } else {
                            let payload_tx = payload_tx.clone();
                            tokio::spawn(async move {
                                stream
                                    .send_response(
                                        http::Response::builder()
                                            .status(StatusCode::OK)
                                            .body(())
                                            .unwrap(),
                                    )
                                    .await
                                    .unwrap();
                                while let Some(mut data) =
                                    stream.recv_data().await.unwrap()
                                {
                                    let length = data.remaining();
                                    payload_tx
                                        .send(data.copy_to_bytes(length))
                                        .unwrap();
                                }
                                let _ = stream.finish().await;
                            });
                        }
                    }
                });
            }
        });
        address
    }

    async fn serve_h3_download_once(
        mut payload_rx: tokio::sync::mpsc::UnboundedReceiver<Bytes>,
    ) -> SocketAddr {
        let (certs, key) =
            resolve_server_cert_and_key(None, None, "xhttp-test").unwrap();
        let mut tls = rustls::ServerConfig::builder()
            .with_no_client_auth()
            .with_single_cert(certs, key)
            .unwrap();
        tls.alpn_protocols = vec![b"h3".to_vec()];
        let quic_tls =
            quinn::crypto::rustls::QuicServerConfig::try_from(tls).unwrap();
        let endpoint = quinn::Endpoint::server(
            quinn::ServerConfig::with_crypto(Arc::new(quic_tls)),
            SocketAddr::new(Ipv4Addr::LOCALHOST.into(), 0),
        )
        .unwrap();
        let address = endpoint.local_addr().unwrap();
        tokio::spawn(async move {
            let connection = endpoint.accept().await.unwrap().await.unwrap();
            let mut server = h3::server::builder()
                .build::<_, Bytes>(h3_quinn::Connection::new(connection))
                .await
                .unwrap();
            use h3::server::RequestResolver;
            let resolver: RequestResolver<_, _> =
                server.accept().await.unwrap().unwrap();
            let (request, mut stream) = resolver.resolve_request().await.unwrap();
            assert_eq!(request.method(), Method::GET);
            assert_eq!(request.version(), Version::HTTP_3);
            stream
                .send_response(
                    http::Response::builder()
                        .status(StatusCode::OK)
                        .body(())
                        .unwrap(),
                )
                .await
                .unwrap();
            while let Some(payload) = payload_rx.recv().await {
                stream.send_data(payload).await.unwrap();
            }
            let _ = stream.finish().await;
        });
        address
    }

    async fn serve_h3_upload_once(
        payload_tx: tokio::sync::mpsc::UnboundedSender<Bytes>,
    ) -> SocketAddr {
        let (certs, key) =
            resolve_server_cert_and_key(None, None, "xhttp-test").unwrap();
        let mut tls = rustls::ServerConfig::builder()
            .with_no_client_auth()
            .with_single_cert(certs, key)
            .unwrap();
        tls.alpn_protocols = vec![b"h3".to_vec()];
        let quic_tls =
            quinn::crypto::rustls::QuicServerConfig::try_from(tls).unwrap();
        let endpoint = quinn::Endpoint::server(
            quinn::ServerConfig::with_crypto(Arc::new(quic_tls)),
            SocketAddr::new(Ipv4Addr::LOCALHOST.into(), 0),
        )
        .unwrap();
        let address = endpoint.local_addr().unwrap();
        tokio::spawn(async move {
            let connection = endpoint.accept().await.unwrap().await.unwrap();
            let mut server = h3::server::builder()
                .build::<_, Bytes>(h3_quinn::Connection::new(connection))
                .await
                .unwrap();
            use h3::server::RequestResolver;
            let resolver: RequestResolver<_, _> =
                server.accept().await.unwrap().unwrap();
            let (request, mut stream) = resolver.resolve_request().await.unwrap();
            assert_eq!(request.method(), Method::POST);
            assert_eq!(request.version(), Version::HTTP_3);
            stream
                .send_response(
                    http::Response::builder()
                        .status(StatusCode::OK)
                        .body(())
                        .unwrap(),
                )
                .await
                .unwrap();
            while let Some(mut data) = stream.recv_data().await.unwrap() {
                let length = data.remaining();
                payload_tx.send(data.copy_to_bytes(length)).unwrap();
            }
            let _ = stream.finish().await;
        });
        address
    }

    async fn mixed_h2_upload_h3_download_roundtrip(mode: &str) {
        crate::setup_default_crypto_provider();
        let (payload_tx, payload_rx) = tokio::sync::mpsc::unbounded_channel();
        let payload_keepalive = payload_tx.clone();
        let download_addr = serve_h3_download_once(payload_rx).await;
        let (upload_client, upload_server) = tokio::io::duplex(64 * 1024);
        tokio::spawn(async move {
            let mut connection = h2::server::handshake(upload_server).await.unwrap();
            let (request, mut response) =
                connection.accept().await.unwrap().unwrap();
            assert_eq!(request.method(), Method::POST);
            tokio::spawn(async move {
                response
                    .send_response(
                        http::Response::builder()
                            .status(StatusCode::OK)
                            .body(())
                            .unwrap(),
                        true,
                    )
                    .unwrap();
                let mut body = request.into_body();
                while let Some(data) = body.data().await {
                    let data = data.unwrap();
                    body.flow_control().release_capacity(data.len()).unwrap();
                    payload_tx.send(data).unwrap();
                }
            });
            while let Some(request) = connection.accept().await {
                request.unwrap();
            }
        });

        let resolver = Arc::new(SystemResolver::new(false).unwrap());
        let socket = tokio::net::UdpSocket::bind((Ipv4Addr::LOCALHOST, 0))
            .await
            .unwrap();
        let datagram = OutboundDatagramImpl::new(socket, resolver);
        let mut options = config(mode);
        if mode == "packet-up" {
            options.sc_max_each_post_bytes = Some("4".to_owned());
            options.sc_min_posts_interval_ms = Some("1".to_owned());
        }
        options.download = Some(DownloadConfig {
            host: "download.example.com".to_owned(),
            path: "/download".to_owned(),
            http_version: Some("h3".to_owned()),
            headers: HashMap::new(),
            h3_tls: Some(H3TlsConfig {
                sni: "localhost".to_owned(),
                skip_cert_verify: true,
                certificate_fingerprint: None,
                ech: None,
                tls_cert: None,
                tls_key: None,
            }),
            reuse: None,
        });
        let client = Client::new(options).unwrap();
        assert_eq!(client.additional_streams(), 0);
        assert_eq!(client.additional_datagrams(), 1);
        let mut stream = client
            .proxy_stream_with_additional_mixed(
                Box::new(upload_client),
                Vec::new(),
                vec![(
                    Box::new(datagram),
                    SocksAddr::Ip(download_addr),
                    download_addr,
                )],
            )
            .await
            .unwrap();
        stream.write_all(b"ping").await.unwrap();
        let mut response = [0u8; 4];
        tokio::time::timeout(
            Duration::from_secs(3),
            stream.read_exact(&mut response),
        )
        .await
        .expect("mixed H2 upload/H3 download timed out")
        .unwrap();
        assert_eq!(&response, b"ping");
        drop(payload_keepalive);
    }

    async fn mixed_h3_upload_h2_download_roundtrip(mode: &str) {
        crate::setup_default_crypto_provider();
        let (payload_tx, mut payload_rx) = tokio::sync::mpsc::unbounded_channel();
        let upload_addr = serve_h3_upload_once(payload_tx).await;
        let (download_client, download_server) = tokio::io::duplex(64 * 1024);
        tokio::spawn(async move {
            let mut connection =
                h2::server::handshake(download_server).await.unwrap();
            let (request, mut response) =
                connection.accept().await.unwrap().unwrap();
            assert_eq!(request.method(), Method::GET);
            tokio::spawn(async move {
                let reply = http::Response::builder()
                    .status(StatusCode::OK)
                    .body(())
                    .unwrap();
                let mut output = response.send_response(reply, false).unwrap();
                while let Some(payload) = payload_rx.recv().await {
                    output.send_data(payload, false).unwrap();
                }
                let _ = output.send_data(Bytes::new(), true);
            });
            while let Some(request) = connection.accept().await {
                request.unwrap();
            }
        });

        let resolver = Arc::new(SystemResolver::new(false).unwrap());
        let socket = tokio::net::UdpSocket::bind((Ipv4Addr::LOCALHOST, 0))
            .await
            .unwrap();
        let datagram = OutboundDatagramImpl::new(socket, resolver);
        let mut options = config(mode);
        options.http_version = Some("h3".to_owned());
        options.h3_tls = Some(H3TlsConfig {
            sni: "localhost".to_owned(),
            skip_cert_verify: true,
            certificate_fingerprint: None,
            ech: None,
            tls_cert: None,
            tls_key: None,
        });
        if mode == "packet-up" {
            options.sc_max_each_post_bytes = Some("4".to_owned());
            options.sc_min_posts_interval_ms = Some("1".to_owned());
        }
        options.download = Some(DownloadConfig {
            host: "download.example.com".to_owned(),
            path: "/download".to_owned(),
            http_version: Some("h2".to_owned()),
            headers: HashMap::new(),
            h3_tls: None,
            reuse: None,
        });
        let client = Client::new(options).unwrap();
        assert_eq!(client.additional_streams(), 1);
        assert_eq!(client.additional_datagrams(), 0);
        let mut stream = client
            .proxy_datagram_with_additional_mixed(
                Box::new(datagram),
                SocksAddr::Ip(upload_addr),
                upload_addr,
                vec![Box::new(download_client)],
                Vec::new(),
            )
            .await
            .unwrap();
        stream.write_all(b"ping").await.unwrap();
        let mut response = [0u8; 4];
        tokio::time::timeout(
            Duration::from_secs(3),
            stream.read_exact(&mut response),
        )
        .await
        .expect("mixed H3 upload/H2 download timed out")
        .unwrap();
        assert_eq!(&response, b"ping");
    }

    async fn h3_multi_roundtrip(mode: &str) {
        crate::setup_default_crypto_provider();
        let server_addr = serve_h3_multi_echo().await;
        let resolver = Arc::new(SystemResolver::new(false).unwrap());
        let socket = tokio::net::UdpSocket::bind((Ipv4Addr::LOCALHOST, 0))
            .await
            .unwrap();
        let datagram = OutboundDatagramImpl::new(socket, resolver);
        let mut options = config(mode);
        options.http_version = Some("h3".to_owned());
        options.h3_tls = Some(H3TlsConfig {
            sni: "localhost".to_owned(),
            skip_cert_verify: true,
            certificate_fingerprint: None,
            ech: None,
            tls_cert: None,
            tls_key: None,
        });
        let client = Client::new(options).unwrap();
        let mut stream = tokio::time::timeout(
            Duration::from_secs(3),
            client.proxy_datagram(
                Box::new(datagram),
                SocksAddr::Ip(server_addr),
                server_addr,
            ),
        )
        .await
        .expect("xhttp HTTP/3 client handshake timed out")
        .unwrap();
        tokio::time::timeout(Duration::from_secs(2), stream.write_all(b"ping"))
            .await
            .expect("xhttp HTTP/3 upload timed out")
            .unwrap();
        let mut response = [0u8; 4];
        tokio::time::timeout(
            Duration::from_secs(3),
            stream.read_exact(&mut response),
        )
        .await
        .expect("xhttp HTTP/3 download timed out")
        .unwrap();
        assert_eq!(&response, b"ping");
    }

    async fn serve_http1_multi_echo(
        upload_stream: tokio::io::DuplexStream,
        download_stream: tokio::io::DuplexStream,
        stream_up: bool,
    ) {
        use hyper::service::service_fn;

        let (payload_sender, mut payload_receiver) =
            tokio::sync::mpsc::unbounded_channel::<Bytes>();
        let (mut download_output, download_body) =
            Channel::<Bytes, io::Error>::new(4);
        let download_body = Arc::new(Mutex::new(Some(download_body)));
        let forward = tokio::spawn(async move {
            while let Some(payload) = payload_receiver.recv().await {
                if download_output.send_data(payload).await.is_err() {
                    break;
                }
            }
        });

        let download_service = service_fn(move |request| {
            let body = download_body
                .lock()
                .unwrap()
                .take()
                .expect("one download request expected");
            async move {
                assert_eq!(request.method(), http::Method::GET);
                assert!(request.uri().path().starts_with("/xhttp/"));
                Ok::<_, Infallible>(http::Response::new(body))
            }
        });
        let upload_service =
            service_fn(move |mut request: hyper::Request<hyper::body::Incoming>| {
                let payload_sender = payload_sender.clone();
                async move {
                    assert_eq!(request.method(), http::Method::POST);
                    if stream_up {
                        assert_eq!(
                            request.headers()["content-type"],
                            "application/grpc"
                        );
                        assert_eq!(request.uri().path().split('/').count(), 3);
                        tokio::spawn(async move {
                            while let Some(frame) = request.body_mut().frame().await
                            {
                                if let Ok(data) = frame.unwrap().into_data() {
                                    let _ = payload_sender.send(data);
                                }
                            }
                        });
                    } else {
                        assert!(request.uri().path().ends_with("/0"));
                        while let Some(frame) = request.body_mut().frame().await {
                            if let Ok(data) = frame.unwrap().into_data() {
                                let _ = payload_sender.send(data);
                            }
                        }
                    }
                    Ok::<_, Infallible>(http::Response::new(Full::new(Bytes::new())))
                }
            });
        let download_connection = hyper::server::conn::http1::Builder::new()
            .serve_connection(TokioIo::new(download_stream), download_service);
        let upload_connection = hyper::server::conn::http1::Builder::new()
            .serve_connection(TokioIo::new(upload_stream), upload_service);
        let (download_result, upload_result) =
            tokio::join!(download_connection, upload_connection);
        download_result.unwrap();
        upload_result.unwrap();
        forward.await.unwrap();
    }

    async fn serve_http1_upload_once(
        stream: tokio::io::DuplexStream,
        payload_tx: tokio::sync::mpsc::UnboundedSender<Bytes>,
    ) {
        use hyper::service::service_fn;

        let service =
            service_fn(move |mut request: hyper::Request<hyper::body::Incoming>| {
                let payload_tx = payload_tx.clone();
                async move {
                    assert_eq!(request.method(), Method::POST);
                    tokio::spawn(async move {
                        while let Some(frame) = request.body_mut().frame().await {
                            let frame = frame.unwrap();
                            if let Ok(data) = frame.into_data() {
                                payload_tx.send(data).unwrap();
                            }
                        }
                    });
                    Ok::<_, Infallible>(http::Response::new(Full::new(Bytes::new())))
                }
            });
        hyper::server::conn::http1::Builder::new()
            .serve_connection(TokioIo::new(stream), service)
            .await
            .unwrap();
    }

    async fn serve_http1_download_once(
        stream: tokio::io::DuplexStream,
        mut payload_rx: tokio::sync::mpsc::UnboundedReceiver<Bytes>,
    ) {
        use hyper::service::service_fn;

        let body = Arc::new(Mutex::new(Some({
            let (mut output, body) = Channel::<Bytes, io::Error>::new(4);
            tokio::spawn(async move {
                while let Some(payload) = payload_rx.recv().await {
                    if output.send_data(payload).await.is_err() {
                        break;
                    }
                }
            });
            body
        })));
        let service = service_fn(move |request| {
            assert_eq!(request.method(), Method::GET);
            let body = body
                .lock()
                .unwrap()
                .take()
                .expect("one HTTP/1.1 download request expected");
            async move { Ok::<_, Infallible>(http::Response::new(body)) }
        });
        hyper::server::conn::http1::Builder::new()
            .serve_connection(TokioIo::new(stream), service)
            .await
            .unwrap();
    }

    async fn serve_h2_upload_once(
        stream: tokio::io::DuplexStream,
        payload_tx: tokio::sync::mpsc::UnboundedSender<Bytes>,
    ) {
        let mut connection = h2::server::handshake(stream).await.unwrap();
        let (request, mut response) = connection.accept().await.unwrap().unwrap();
        assert_eq!(request.method(), Method::POST);
        tokio::spawn(async move {
            response
                .send_response(
                    http::Response::builder()
                        .status(StatusCode::OK)
                        .body(())
                        .unwrap(),
                    true,
                )
                .unwrap();
            let mut body = request.into_body();
            while let Some(data) = body.data().await {
                let data = data.unwrap();
                body.flow_control().release_capacity(data.len()).unwrap();
                payload_tx.send(data).unwrap();
            }
        });
        while let Some(request) = connection.accept().await {
            request.unwrap();
        }
    }

    async fn serve_h2_download_once(
        stream: tokio::io::DuplexStream,
        mut payload_rx: tokio::sync::mpsc::UnboundedReceiver<Bytes>,
    ) {
        let mut connection = h2::server::handshake(stream).await.unwrap();
        let (request, mut response) = connection.accept().await.unwrap().unwrap();
        assert_eq!(request.method(), Method::GET);
        tokio::spawn(async move {
            let mut output = response
                .send_response(
                    http::Response::builder()
                        .status(StatusCode::OK)
                        .body(())
                        .unwrap(),
                    false,
                )
                .unwrap();
            while let Some(payload) = payload_rx.recv().await {
                output.send_data(payload, false).unwrap();
            }
            let _ = output.send_data(Bytes::new(), true);
        });
        while let Some(request) = connection.accept().await {
            request.unwrap();
        }
    }

    async fn mixed_http1_h2_roundtrip(http1_upload: bool) {
        let (payload_tx, payload_rx) = tokio::sync::mpsc::unbounded_channel();
        let payload_keepalive = payload_tx.clone();
        let (http1_client, http1_server) = tokio::io::duplex(64 * 1024);
        let (h2_client, h2_server) = tokio::io::duplex(64 * 1024);
        let mut stream = if http1_upload {
            tokio::spawn(serve_http1_upload_once(http1_server, payload_tx));
            tokio::spawn(serve_h2_download_once(h2_server, payload_rx));
            let mut options = config("stream-up");
            options.http_version = Some("http/1.1".to_owned());
            options.download = Some(DownloadConfig {
                host: "download.example.com".to_owned(),
                path: "/download".to_owned(),
                http_version: Some("h2".to_owned()),
                headers: HashMap::new(),
                h3_tls: None,
                reuse: None,
            });
            let client = Client::new(options).unwrap();
            client
                .proxy_stream_with_additional_mixed(
                    Box::new(http1_client),
                    vec![Box::new(h2_client)],
                    Vec::new(),
                )
                .await
                .unwrap()
        } else {
            tokio::spawn(serve_h2_upload_once(h2_server, payload_tx));
            tokio::spawn(serve_http1_download_once(http1_server, payload_rx));
            let mut options = config("stream-up");
            options.download = Some(DownloadConfig {
                host: "download.example.com".to_owned(),
                path: "/download".to_owned(),
                http_version: Some("http/1.1".to_owned()),
                headers: HashMap::new(),
                h3_tls: None,
                reuse: None,
            });
            let client = Client::new(options).unwrap();
            client
                .proxy_stream_with_additional_mixed(
                    Box::new(h2_client),
                    vec![Box::new(http1_client)],
                    Vec::new(),
                )
                .await
                .unwrap()
        };
        stream.write_all(b"ping").await.unwrap();
        let mut response = [0u8; 4];
        tokio::time::timeout(
            Duration::from_secs(2),
            stream.read_exact(&mut response),
        )
        .await
        .expect("mixed HTTP/1.1 and HTTP/2 roundtrip timed out")
        .unwrap();
        assert_eq!(&response, b"ping");
        drop(payload_keepalive);
    }

    async fn mixed_http1_h3_roundtrip(http1_upload: bool) {
        crate::setup_default_crypto_provider();
        let (payload_tx, payload_rx) = tokio::sync::mpsc::unbounded_channel();
        let payload_keepalive = payload_tx.clone();
        let (http1_client, http1_server) = tokio::io::duplex(64 * 1024);
        let resolver = Arc::new(SystemResolver::new(false).unwrap());
        let socket = tokio::net::UdpSocket::bind((Ipv4Addr::LOCALHOST, 0))
            .await
            .unwrap();
        let datagram = OutboundDatagramImpl::new(socket, resolver);
        let tls = H3TlsConfig {
            sni: "localhost".to_owned(),
            skip_cert_verify: true,
            certificate_fingerprint: None,
            ech: None,
            tls_cert: None,
            tls_key: None,
        };
        let mut stream = if http1_upload {
            tokio::spawn(serve_http1_upload_once(http1_server, payload_tx));
            let h3_addr = serve_h3_download_once(payload_rx).await;
            let mut options = config("stream-up");
            options.http_version = Some("http/1.1".to_owned());
            options.download = Some(DownloadConfig {
                host: "download.example.com".to_owned(),
                path: "/download".to_owned(),
                http_version: Some("h3".to_owned()),
                headers: HashMap::new(),
                h3_tls: Some(tls),
                reuse: None,
            });
            let client = Client::new(options).unwrap();
            client
                .proxy_stream_with_additional_mixed(
                    Box::new(http1_client),
                    Vec::new(),
                    vec![(Box::new(datagram), SocksAddr::Ip(h3_addr), h3_addr)],
                )
                .await
                .unwrap()
        } else {
            tokio::spawn(serve_http1_download_once(http1_server, payload_rx));
            let h3_addr = serve_h3_upload_once(payload_tx).await;
            let mut options = config("stream-up");
            options.http_version = Some("h3".to_owned());
            options.h3_tls = Some(tls);
            options.download = Some(DownloadConfig {
                host: "download.example.com".to_owned(),
                path: "/download".to_owned(),
                http_version: Some("http/1.1".to_owned()),
                headers: HashMap::new(),
                h3_tls: None,
                reuse: None,
            });
            let client = Client::new(options).unwrap();
            client
                .proxy_datagram_with_additional_mixed(
                    Box::new(datagram),
                    SocksAddr::Ip(h3_addr),
                    h3_addr,
                    vec![Box::new(http1_client)],
                    Vec::new(),
                )
                .await
                .unwrap()
        };
        stream.write_all(b"ping").await.unwrap();
        let mut response = [0u8; 4];
        tokio::time::timeout(
            Duration::from_secs(3),
            stream.read_exact(&mut response),
        )
        .await
        .expect("mixed HTTP/1.1 and HTTP/3 roundtrip timed out")
        .unwrap();
        assert_eq!(&response, b"ping");
        drop(payload_keepalive);
    }

    #[test]
    fn normalizes_mihomo_stream_one_request() {
        let client = Client::new(config("stream-one")).unwrap();
        let (request, _) = client
            .request(http::Method::POST, None, None, None, true)
            .unwrap();
        assert_eq!(request.uri().path(), "/xhttp/");
        assert_eq!(request.method(), http::Method::POST);
        assert_eq!(request.headers()["content-type"], "application/grpc");
        let referer = request.headers()["referer"].to_str().unwrap();
        let padding = url::Url::parse(referer)
            .unwrap()
            .query_pairs()
            .find(|(key, _)| key == "x_padding")
            .unwrap()
            .1
            .len();
        assert!((100..=1000).contains(&padding));
    }

    #[test]
    fn tokenish_padding_targets_hpack_encoded_length() {
        for target in [1, 10, 100, 1_000] {
            let padding = super::tokenish_padding(target);
            assert!(
                super::hpack_huffman_bytes(&padding).abs_diff(target) <= 2,
                "target={target}, actual={}",
                super::hpack_huffman_bytes(&padding),
            );
        }
    }

    #[test]
    fn applies_advanced_mihomo_packet_metadata_and_payload() {
        let client = Client::new(ClientConfig {
            host: "cdn.example.com".to_owned(),
            path: "/advanced".to_owned(),
            mode: "packet-up".to_owned(),
            session_placement: Some("query".to_owned()),
            session_key: Some("sid".to_owned()),
            seq_placement: Some("header".to_owned()),
            seq_key: Some("X-Sequence".to_owned()),
            uplink_data_placement: Some("header".to_owned()),
            uplink_data_key: Some("X-Payload".to_owned()),
            uplink_chunk_size: Some("64".to_owned()),
            x_padding_obfs_mode: true,
            x_padding_bytes: Some("100".to_owned()),
            x_padding_placement: Some("cookie".to_owned()),
            x_padding_key: Some("padding".to_owned()),
            x_padding_method: Some("tokenish".to_owned()),
            ..Default::default()
        })
        .unwrap();
        let (request, body) = client
            .request(
                http::Method::POST,
                Some("session"),
                Some(7),
                Some(b"payload"),
                false,
            )
            .unwrap();
        assert!(body.is_none());
        assert_eq!(request.uri().query(), Some("sid=session"));
        assert_eq!(request.headers()["x-sequence"], "7");
        assert!(
            request.headers()["cookie"]
                .to_str()
                .unwrap()
                .starts_with("padding=")
        );
        let encoded = request.headers()["x-payload-0"].to_str().unwrap();
        assert_eq!(URL_SAFE_NO_PAD.decode(encoded).unwrap(), b"payload");
    }

    #[tokio::test]
    async fn stream_one_roundtrips_over_http2() {
        let (client_side, server_side) = tokio::io::duplex(64 * 1024);
        let server = tokio::spawn(async move {
            let mut connection = h2::server::handshake(server_side).await.unwrap();
            let (request, mut response) =
                tokio::time::timeout(Duration::from_secs(1), connection.accept())
                    .await
                    .expect("xhttp server accept timed out")
                    .unwrap()
                    .unwrap();
            assert_eq!(request.method(), http::Method::POST);
            assert_eq!(request.uri().path(), "/xhttp/");
            assert_eq!(request.headers()["x-test"], "flclash");
            let mut body = request.into_body();
            let reply = http::Response::builder().status(200).body(()).unwrap();
            let mut output = response.send_response(reply, false).unwrap();
            let request_task = tokio::spawn(async move {
                let data = body.data().await.unwrap().unwrap();
                body.flow_control().release_capacity(data.len()).unwrap();
                output.send_data(data, true).unwrap();
            });
            while let Some(request) = connection.accept().await {
                request.unwrap();
            }
            request_task.await.unwrap();
        });

        let client = Client::new(config("stream-one")).unwrap();
        let mut stream = tokio::time::timeout(
            Duration::from_secs(2),
            client.proxy_stream(Box::new(client_side)),
        )
        .await
        .expect("xhttp client handshake timed out")
        .unwrap();
        tokio::time::timeout(Duration::from_secs(2), stream.write_all(b"ping"))
            .await
            .expect("xhttp stream-one upload timed out")
            .unwrap();
        let mut response = [0u8; 4];
        tokio::time::timeout(
            Duration::from_secs(2),
            stream.read_exact(&mut response),
        )
        .await
        .expect("xhttp stream-one download timed out")
        .unwrap();
        assert_eq!(&response, b"ping");
        drop(stream);
        tokio::time::timeout(Duration::from_secs(2), server)
            .await
            .expect("xhttp server timed out")
            .unwrap();
    }

    #[tokio::test]
    async fn xmux_reuses_one_http2_connection_across_concurrent_sessions() {
        let (first_client, first_server) = tokio::io::duplex(64 * 1024);
        let (second_client, mut unused_second_server) = tokio::io::duplex(64 * 1024);
        let server = tokio::spawn(async move {
            let mut connection = h2::server::handshake(first_server).await.unwrap();
            let mut handlers = Vec::new();
            for _ in 0..2 {
                let (request, mut response) =
                    connection.accept().await.unwrap().unwrap();
                handlers.push(tokio::spawn(async move {
                    let mut body = request.into_body();
                    let reply =
                        http::Response::builder().status(200).body(()).unwrap();
                    let mut output = response.send_response(reply, false).unwrap();
                    let data = body.data().await.unwrap().unwrap();
                    body.flow_control().release_capacity(data.len()).unwrap();
                    output.send_data(data, true).unwrap();
                }));
            }
            while let Some(request) = connection.accept().await {
                request.unwrap();
                panic!("unexpected third XMUX request");
            }
            for handler in handlers {
                handler.await.unwrap();
            }
        });

        let mut options = config("stream-one");
        options.reuse = Some(ReuseConfig {
            max_concurrency: Some("2".to_owned()),
            max_connections: Some("1".to_owned()),
            h_max_request_times: Some("10".to_owned()),
            ..Default::default()
        });
        let client = Client::new(options).unwrap();
        let mut first = client.proxy_stream(Box::new(first_client)).await.unwrap();
        let mut second = client.proxy_stream(Box::new(second_client)).await.unwrap();
        let mut unused = [0u8; 1];
        assert_eq!(
            tokio::time::timeout(
                Duration::from_secs(1),
                unused_second_server.read(&mut unused),
            )
            .await
            .unwrap()
            .unwrap(),
            0,
            "the second physical stream must be discarded when XMUX reuses H2",
        );
        first.write_all(b"one").await.unwrap();
        second.write_all(b"two").await.unwrap();
        let mut first_reply = [0u8; 3];
        let mut second_reply = [0u8; 3];
        first.read_exact(&mut first_reply).await.unwrap();
        second.read_exact(&mut second_reply).await.unwrap();
        assert_eq!(&first_reply, b"one");
        assert_eq!(&second_reply, b"two");
        drop(first);
        drop(second);
        drop(client);
        tokio::time::timeout(Duration::from_secs(2), server)
            .await
            .expect("XMUX H2 server timed out")
            .unwrap();
    }

    #[tokio::test]
    async fn xmux_rotates_http2_after_request_limit() {
        let (first_client, first_server) = tokio::io::duplex(64 * 1024);
        let (second_client, second_server) = tokio::io::duplex(64 * 1024);
        let first_server = tokio::spawn(serve_h2_echo_once(first_server));
        let second_server = tokio::spawn(serve_h2_echo_once(second_server));
        let mut options = config("stream-one");
        options.reuse = Some(ReuseConfig {
            max_concurrency: Some("1".to_owned()),
            max_connections: Some("1".to_owned()),
            h_max_request_times: Some("1".to_owned()),
            ..Default::default()
        });
        let client = Client::new(options).unwrap();

        let mut first = client.proxy_stream(Box::new(first_client)).await.unwrap();
        first.write_all(b"one").await.unwrap();
        let mut first_reply = [0u8; 3];
        first.read_exact(&mut first_reply).await.unwrap();
        assert_eq!(&first_reply, b"one");
        drop(first);

        let mut second = client.proxy_stream(Box::new(second_client)).await.unwrap();
        second.write_all(b"two").await.unwrap();
        let mut second_reply = [0u8; 3];
        second.read_exact(&mut second_reply).await.unwrap();
        assert_eq!(&second_reply, b"two");
        drop(second);
        drop(client);

        tokio::time::timeout(Duration::from_secs(2), first_server)
            .await
            .expect("first rotated H2 server timed out")
            .unwrap();
        tokio::time::timeout(Duration::from_secs(2), second_server)
            .await
            .expect("second rotated H2 server timed out")
            .unwrap();
    }

    #[tokio::test]
    async fn xmux_reuses_one_http1_connection_across_sequential_sessions() {
        use hyper::service::service_fn;

        let (first_client, first_server) = tokio::io::duplex(64 * 1024);
        let (second_client, mut unused_second_server) = tokio::io::duplex(64 * 1024);
        let server = tokio::spawn(async move {
            let service = service_fn(
                |mut request: hyper::Request<hyper::body::Incoming>| async move {
                    let (mut output, body) = Channel::<Bytes, io::Error>::new(4);
                    tokio::spawn(async move {
                        while let Some(frame) = request.body_mut().frame().await {
                            let frame = frame.unwrap();
                            if let Ok(data) = frame.into_data() {
                                output.send_data(data).await.unwrap();
                            }
                        }
                    });
                    Ok::<_, Infallible>(http::Response::new(body))
                },
            );
            hyper::server::conn::http1::Builder::new()
                .keep_alive(true)
                .serve_connection(TokioIo::new(first_server), service)
                .await
                .unwrap();
        });

        let mut options = config("stream-one");
        options.http_version = Some("http/1.1".to_owned());
        options.reuse = Some(ReuseConfig {
            max_concurrency: Some("8".to_owned()),
            max_connections: Some("1".to_owned()),
            h_max_request_times: Some("10".to_owned()),
            ..Default::default()
        });
        let client = Client::new(options).unwrap();

        let mut first = client.proxy_stream(Box::new(first_client)).await.unwrap();
        first.write_all(b"one").await.unwrap();
        let mut first_reply = [0u8; 3];
        first.read_exact(&mut first_reply).await.unwrap();
        assert_eq!(&first_reply, b"one");
        drop(first);
        tokio::task::yield_now().await;

        let mut second = client.proxy_stream(Box::new(second_client)).await.unwrap();
        let mut unused = [0u8; 1];
        assert_eq!(
            tokio::time::timeout(
                Duration::from_secs(1),
                unused_second_server.read(&mut unused),
            )
            .await
            .unwrap()
            .unwrap(),
            0,
            "the second physical stream must be discarded when XMUX reuses HTTP/1.1",
        );
        second.write_all(b"two").await.unwrap();
        let mut second_reply = [0u8; 3];
        second.read_exact(&mut second_reply).await.unwrap();
        assert_eq!(&second_reply, b"two");
        drop(second);
        drop(client);
        tokio::time::timeout(Duration::from_secs(2), server)
            .await
            .expect("XMUX HTTP/1.1 server timed out")
            .unwrap();
    }

    #[tokio::test]
    async fn stream_one_roundtrips_over_http3_connector_datagram() {
        crate::setup_default_crypto_provider();
        let server_addr = serve_h3_stream_one_echo().await;
        let resolver = Arc::new(SystemResolver::new(false).unwrap());
        let socket = tokio::net::UdpSocket::bind((Ipv4Addr::LOCALHOST, 0))
            .await
            .unwrap();
        let datagram = OutboundDatagramImpl::new(socket, resolver);
        let mut options = config("stream-one");
        options.http_version = Some("h3".to_owned());
        options.h3_tls = Some(H3TlsConfig {
            sni: "localhost".to_owned(),
            skip_cert_verify: true,
            certificate_fingerprint: None,
            ech: None,
            tls_cert: None,
            tls_key: None,
        });
        let client = Client::new(options).unwrap();
        assert!(client.uses_datagram());
        let mut stream = tokio::time::timeout(
            Duration::from_secs(3),
            client.proxy_datagram(
                Box::new(datagram),
                SocksAddr::Ip(server_addr),
                server_addr,
            ),
        )
        .await
        .expect("xhttp HTTP/3 client handshake timed out")
        .unwrap();
        tokio::time::timeout(Duration::from_secs(2), stream.write_all(b"ping"))
            .await
            .expect("xhttp HTTP/3 upload timed out")
            .unwrap();
        let mut response = [0u8; 4];
        tokio::time::timeout(
            Duration::from_secs(2),
            stream.read_exact(&mut response),
        )
        .await
        .expect("xhttp HTTP/3 download timed out")
        .unwrap();
        assert_eq!(&response, b"ping");
    }

    #[tokio::test]
    async fn xmux_reuses_one_http3_connection_across_concurrent_sessions() {
        crate::setup_default_crypto_provider();
        let server_addr = serve_h3_reuse_echo().await;
        let resolver = Arc::new(SystemResolver::new(false).unwrap());
        let first_socket = tokio::net::UdpSocket::bind((Ipv4Addr::LOCALHOST, 0))
            .await
            .unwrap();
        let second_socket = tokio::net::UdpSocket::bind((Ipv4Addr::LOCALHOST, 0))
            .await
            .unwrap();
        let first_datagram =
            OutboundDatagramImpl::new(first_socket, resolver.clone());
        let second_datagram = OutboundDatagramImpl::new(second_socket, resolver);
        let mut options = config("stream-one");
        options.http_version = Some("h3".to_owned());
        options.h3_tls = Some(H3TlsConfig {
            sni: "localhost".to_owned(),
            skip_cert_verify: true,
            certificate_fingerprint: None,
            ech: None,
            tls_cert: None,
            tls_key: None,
        });
        options.reuse = Some(ReuseConfig {
            max_concurrency: Some("2".to_owned()),
            max_connections: Some("1".to_owned()),
            h_max_request_times: Some("10".to_owned()),
            ..Default::default()
        });
        let client = Client::new(options).unwrap();
        let mut first = client
            .proxy_datagram(
                Box::new(first_datagram),
                SocksAddr::Ip(server_addr),
                server_addr,
            )
            .await
            .unwrap();
        let mut second = client
            .proxy_datagram(
                Box::new(second_datagram),
                SocksAddr::Ip(server_addr),
                server_addr,
            )
            .await
            .unwrap();
        first.write_all(b"one").await.unwrap();
        second.write_all(b"two").await.unwrap();
        let mut first_reply = [0u8; 3];
        let mut second_reply = [0u8; 3];
        first.read_exact(&mut first_reply).await.unwrap();
        second.read_exact(&mut second_reply).await.unwrap();
        assert_eq!(&first_reply, b"one");
        assert_eq!(&second_reply, b"two");
        drop(first);
        drop(second);
        drop(client);
    }

    #[tokio::test]
    async fn stream_up_roundtrips_over_http3_connector_datagram() {
        h3_multi_roundtrip("stream-up").await;
    }

    #[tokio::test]
    async fn packet_up_roundtrips_over_http3_connector_datagram() {
        h3_multi_roundtrip("packet-up").await;
    }

    #[tokio::test]
    async fn stream_up_mixes_http2_upload_with_http3_download() {
        mixed_h2_upload_h3_download_roundtrip("stream-up").await;
    }

    #[tokio::test]
    async fn packet_up_mixes_http2_upload_with_http3_download() {
        mixed_h2_upload_h3_download_roundtrip("packet-up").await;
    }

    #[tokio::test]
    async fn stream_up_mixes_http3_upload_with_http2_download() {
        mixed_h3_upload_h2_download_roundtrip("stream-up").await;
    }

    #[tokio::test]
    async fn packet_up_mixes_http3_upload_with_http2_download() {
        mixed_h3_upload_h2_download_roundtrip("packet-up").await;
    }

    #[tokio::test]
    async fn stream_up_mixes_http1_upload_with_http2_download() {
        mixed_http1_h2_roundtrip(true).await;
    }

    #[tokio::test]
    async fn stream_up_mixes_http2_upload_with_http1_download() {
        mixed_http1_h2_roundtrip(false).await;
    }

    #[tokio::test]
    async fn stream_up_mixes_http1_upload_with_http3_download() {
        mixed_http1_h3_roundtrip(true).await;
    }

    #[tokio::test]
    async fn stream_up_mixes_http3_upload_with_http1_download() {
        mixed_http1_h3_roundtrip(false).await;
    }

    #[tokio::test]
    async fn stream_up_uses_independent_http3_download_connection() {
        crate::setup_default_crypto_provider();
        let server_addr = serve_h3_split_echo().await;
        let resolver = Arc::new(SystemResolver::new(false).unwrap());
        let upload_socket = tokio::net::UdpSocket::bind((Ipv4Addr::LOCALHOST, 0))
            .await
            .unwrap();
        let download_socket = tokio::net::UdpSocket::bind((Ipv4Addr::LOCALHOST, 0))
            .await
            .unwrap();
        let upload = OutboundDatagramImpl::new(upload_socket, resolver.clone());
        let download = OutboundDatagramImpl::new(download_socket, resolver);
        let tls = H3TlsConfig {
            sni: "localhost".to_owned(),
            skip_cert_verify: true,
            certificate_fingerprint: None,
            ech: None,
            tls_cert: None,
            tls_key: None,
        };
        let mut options = config("stream-up");
        options.http_version = Some("h3".to_owned());
        options.h3_tls = Some(tls.clone());
        options.download = Some(DownloadConfig {
            host: "download.example.com".to_owned(),
            path: "/download".to_owned(),
            http_version: Some("h3".to_owned()),
            headers: HashMap::new(),
            h3_tls: Some(tls),
            reuse: None,
        });
        let client = Client::new(options).unwrap();
        assert_eq!(client.additional_datagrams(), 1);
        let mut stream = tokio::time::timeout(
            Duration::from_secs(3),
            client.proxy_datagram_with_additional(
                Box::new(upload),
                SocksAddr::Ip(server_addr),
                server_addr,
                vec![(Box::new(download), SocksAddr::Ip(server_addr), server_addr)],
            ),
        )
        .await
        .expect("independent xhttp HTTP/3 handshake timed out")
        .unwrap();
        stream.write_all(b"ping").await.unwrap();
        let mut response = [0u8; 4];
        tokio::time::timeout(
            Duration::from_secs(3),
            stream.read_exact(&mut response),
        )
        .await
        .expect("independent xhttp HTTP/3 download timed out")
        .unwrap();
        assert_eq!(&response, b"ping");
    }

    #[tokio::test]
    async fn stream_one_roundtrips_over_http1_chunked_body() {
        use hyper::service::service_fn;

        let (client_side, server_side) = tokio::io::duplex(64 * 1024);
        let server = tokio::spawn(async move {
            let service = service_fn(
                |mut request: hyper::Request<hyper::body::Incoming>| async move {
                    assert_eq!(request.method(), http::Method::POST);
                    assert_eq!(request.uri().path(), "/xhttp/");
                    assert_eq!(
                        request.headers()["content-type"],
                        "application/grpc"
                    );
                    assert!(
                        request.headers()["referer"]
                            .to_str()
                            .unwrap()
                            .contains("x_padding=")
                    );
                    let (mut output, body) = Channel::<Bytes, io::Error>::new(4);
                    tokio::spawn(async move {
                        while let Some(frame) = request.body_mut().frame().await {
                            let frame = frame.unwrap();
                            if let Ok(data) = frame.into_data() {
                                output.send_data(data).await.unwrap();
                            }
                        }
                    });
                    Ok::<_, Infallible>(http::Response::new(body))
                },
            );
            hyper::server::conn::http1::Builder::new()
                .serve_connection(TokioIo::new(server_side), service)
                .await
                .unwrap();
        });

        let mut config = config("stream-one");
        config.http_version = Some("http/1.1".to_owned());
        let client = Client::new(config).unwrap();
        let mut stream = client.proxy_stream(Box::new(client_side)).await.unwrap();
        stream.write_all(b"ping").await.unwrap();
        let mut response = [0u8; 4];
        tokio::time::timeout(
            Duration::from_secs(2),
            stream.read_exact(&mut response),
        )
        .await
        .expect("xhttp HTTP/1.1 download timed out")
        .unwrap();
        assert_eq!(&response, b"ping");
        drop(stream);
        tokio::time::timeout(Duration::from_secs(2), server)
            .await
            .expect("xhttp HTTP/1.1 server timed out")
            .unwrap();
    }

    #[tokio::test]
    async fn stream_up_roundtrips_over_two_http1_connections() {
        let (upload_client, upload_server) = tokio::io::duplex(64 * 1024);
        let (download_client, download_server) = tokio::io::duplex(64 * 1024);
        let server = tokio::spawn(serve_http1_multi_echo(
            upload_server,
            download_server,
            true,
        ));
        let mut config = config("stream-up");
        config.http_version = Some("http/1.1".to_owned());
        let client = Client::new(config).unwrap();
        assert_eq!(client.additional_streams(), 1);
        let mut stream = client
            .proxy_stream_with_additional(
                Box::new(upload_client),
                vec![Box::new(download_client)],
            )
            .await
            .unwrap();
        stream.write_all(b"ping").await.unwrap();
        let mut response = [0u8; 4];
        tokio::time::timeout(
            Duration::from_secs(2),
            stream.read_exact(&mut response),
        )
        .await
        .expect("xhttp HTTP/1.1 stream-up download timed out")
        .unwrap();
        assert_eq!(&response, b"ping");
        drop(stream);
        tokio::time::timeout(Duration::from_secs(2), server)
            .await
            .expect("xhttp HTTP/1.1 stream-up server timed out")
            .unwrap();
    }

    #[tokio::test]
    async fn packet_up_roundtrips_over_two_http1_connections() {
        let (upload_client, upload_server) = tokio::io::duplex(64 * 1024);
        let (download_client, download_server) = tokio::io::duplex(64 * 1024);
        let server = tokio::spawn(serve_http1_multi_echo(
            upload_server,
            download_server,
            false,
        ));
        let mut config = config("packet-up");
        config.http_version = Some("http/1.1".to_owned());
        config.sc_max_each_post_bytes = Some("4".to_owned());
        config.sc_min_posts_interval_ms = Some("1".to_owned());
        let client = Client::new(config).unwrap();
        assert_eq!(client.additional_streams(), 1);
        let mut stream = client
            .proxy_stream_with_additional(
                Box::new(upload_client),
                vec![Box::new(download_client)],
            )
            .await
            .unwrap();
        stream.write_all(b"ping").await.unwrap();
        let mut response = [0u8; 4];
        tokio::time::timeout(
            Duration::from_secs(2),
            stream.read_exact(&mut response),
        )
        .await
        .expect("xhttp HTTP/1.1 packet-up download timed out")
        .unwrap();
        assert_eq!(&response, b"ping");
        drop(stream);
        tokio::time::timeout(Duration::from_secs(2), server)
            .await
            .expect("xhttp HTTP/1.1 packet-up server timed out")
            .unwrap();
    }

    #[tokio::test]
    async fn stream_up_uses_shared_session_over_http2() {
        let (upload_client, upload_server) = tokio::io::duplex(64 * 1024);
        let (download_client, download_server) = tokio::io::duplex(64 * 1024);
        let (session_tx, session_rx) = tokio::sync::oneshot::channel::<String>();
        let (payload_tx, payload_rx) = tokio::sync::oneshot::channel::<Bytes>();
        let download_task = tokio::spawn(async move {
            let mut connection =
                h2::server::handshake(download_server).await.unwrap();
            let (download, mut download_response) =
                connection.accept().await.unwrap().unwrap();
            assert_eq!(download.method(), http::Method::GET);
            assert!(download.uri().path().starts_with("/download/"));
            assert_eq!(download.headers()["x-download"], "flclash");
            let session =
                download.uri().path().rsplit('/').next().unwrap().to_owned();
            session_tx.send(session).unwrap();
            let reply = http::Response::builder().status(200).body(()).unwrap();
            let mut output = download_response.send_response(reply, false).unwrap();
            let response_task = tokio::spawn(async move {
                output.send_data(payload_rx.await.unwrap(), true).unwrap();
            });
            while let Some(request) = connection.accept().await {
                request.unwrap();
            }
            response_task.await.unwrap();
        });
        let upload_task = tokio::spawn(async move {
            let session = session_rx.await.unwrap();
            let mut connection = h2::server::handshake(upload_server).await.unwrap();
            let (upload, mut upload_response) =
                connection.accept().await.unwrap().unwrap();
            assert_eq!(upload.method(), http::Method::POST);
            assert_eq!(upload.uri().path(), format!("/xhttp/{session}"));
            assert_eq!(upload.headers()["content-type"], "application/grpc");
            upload_response
                .send_response(
                    http::Response::builder().status(200).body(()).unwrap(),
                    true,
                )
                .unwrap();
            let mut body = upload.into_body();
            let data = body.data().await.unwrap().unwrap();
            body.flow_control().release_capacity(data.len()).unwrap();
            payload_tx.send(data).unwrap();
        });

        let mut config = config("stream-up");
        config.download = Some(DownloadConfig {
            host: "download.example.com".to_owned(),
            path: "/download".to_owned(),
            http_version: Some("h2".to_owned()),
            headers: [("X-Download".to_owned(), "flclash".to_owned())]
                .into_iter()
                .collect(),
            h3_tls: None,
            reuse: None,
        });
        let client = Client::new(config).unwrap();
        assert_eq!(client.additional_streams(), 1);
        let mut stream = client
            .proxy_stream_with_additional(
                Box::new(upload_client),
                vec![Box::new(download_client)],
            )
            .await
            .unwrap();
        tokio::time::timeout(Duration::from_secs(2), stream.write_all(b"ping"))
            .await
            .expect("xhttp stream-up upload timed out")
            .unwrap();
        let mut response = [0u8; 4];
        tokio::time::timeout(
            Duration::from_secs(2),
            stream.read_exact(&mut response),
        )
        .await
        .expect("xhttp stream-up download timed out")
        .unwrap();
        assert_eq!(&response, b"ping");
        drop(stream);
        tokio::time::timeout(Duration::from_secs(2), download_task)
            .await
            .expect("xhttp stream-up download server timed out")
            .unwrap();
        tokio::time::timeout(Duration::from_secs(2), upload_task)
            .await
            .expect("xhttp stream-up upload server timed out")
            .unwrap();
    }

    #[tokio::test]
    async fn packet_up_posts_sequenced_payload_over_http2() {
        let (client_side, server_side) = tokio::io::duplex(64 * 1024);
        let server = tokio::spawn(async move {
            let mut connection = h2::server::handshake(server_side).await.unwrap();
            let (download, mut download_response) =
                connection.accept().await.unwrap().unwrap();
            assert_eq!(download.method(), http::Method::GET);
            let session_path = download.uri().path().to_owned();
            let reply = http::Response::builder().status(200).body(()).unwrap();
            let mut output = download_response.send_response(reply, false).unwrap();

            let (packet, mut packet_response) =
                connection.accept().await.unwrap().unwrap();
            assert_eq!(packet.method(), http::Method::POST);
            assert_eq!(packet.uri().path(), format!("{session_path}/0"));
            assert!(
                packet.headers()["referer"]
                    .to_str()
                    .unwrap()
                    .contains("x_padding=")
            );
            let mut body = packet.into_body();
            packet_response
                .send_response(
                    http::Response::builder().status(200).body(()).unwrap(),
                    true,
                )
                .unwrap();
            let request_task = tokio::spawn(async move {
                let data = body.data().await.unwrap().unwrap();
                body.flow_control().release_capacity(data.len()).unwrap();
                output.send_data(data, true).unwrap();
            });
            while let Some(request) = connection.accept().await {
                request.unwrap();
            }
            request_task.await.unwrap();
        });

        let mut config = config("packet-up");
        config.sc_max_each_post_bytes = Some("4".to_owned());
        config.sc_min_posts_interval_ms = Some("1".to_owned());
        let client = Client::new(config).unwrap();
        let mut stream = client.proxy_stream(Box::new(client_side)).await.unwrap();
        tokio::time::timeout(Duration::from_secs(2), stream.write_all(b"ping"))
            .await
            .expect("xhttp packet-up upload timed out")
            .unwrap();
        let mut response = [0u8; 4];
        tokio::time::timeout(
            Duration::from_secs(2),
            stream.read_exact(&mut response),
        )
        .await
        .expect("xhttp packet-up download timed out")
        .unwrap();
        assert_eq!(&response, b"ping");
        drop(stream);
        tokio::time::timeout(Duration::from_secs(2), server)
            .await
            .expect("xhttp packet-up server timed out")
            .unwrap();
    }
}
