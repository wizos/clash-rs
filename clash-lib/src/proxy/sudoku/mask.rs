//! Sudoku legacy HTTP masking (`httpmask` with mode empty/`legacy`).
//!
//! Before the Sudoku handshake the client writes one randomized, plausible
//! HTTP/1.1 request header (a `POST` upload with a large `Content-Length`, or
//! occasionally a WebSocket-upgrade-looking `GET`) over the raw TCP connection,
//! then immediately switches to the raw obfuscation/record/KIP stream on the
//! same socket. The server consumes the header (any valid method + headers up
//! to the blank line) and treats the remainder as the raw Sudoku stream. This
//! is a one-shot cover prefix, not a real HTTP exchange — it is deliberately
//! *not* CDN-compatible.
//!
//! The CDN-friendly HTTP tunnel modes (`stream`/`poll`/`auto`/`ws`, which run a
//! real bidirectional HTTP/WebSocket tunnel) are a larger, separate protocol
//! and are still rejected at config time; see [`super`] docs.

use anyhow::{Result, anyhow};
use tokio::io::{AsyncWrite, AsyncWriteExt};

// Header value pools mirrored from upstream `pkg/obfs/httpmask/masker_*.txt`.
const USER_AGENTS: &[&str] = &[
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like \
     Gecko) Chrome/120.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like \
     Gecko) Chrome/121.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:121.0) Gecko/20100101 \
     Firefox/121.0",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, \
     like Gecko) Version/17.2 Safari/605.1.15",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 14_2_1) AppleWebKit/605.1.15 (KHTML, \
     like Gecko) Version/17.2 Safari/605.1.15",
    "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) \
     Chrome/120.0.0.0 Safari/537.36",
    "Mozilla/5.0 (iPhone; CPU iPhone OS 17_2 like Mac OS X) AppleWebKit/605.1.15 \
     (KHTML, like Gecko) Version/17.2 Mobile/15E148 Safari/604.1",
    "Mozilla/5.0 (Linux; Android 14; Pixel 7) AppleWebKit/537.36 (KHTML, like \
     Gecko) Chrome/121.0.0.0 Mobile Safari/537.36",
];

const ACCEPTS: &[&str] = &[
    "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/\
     *;q=0.8",
    "application/json, text/plain, */*",
    "application/octet-stream",
    "*/*",
];

const ACCEPT_LANGUAGES: &[&str] = &[
    "en-US,en;q=0.9",
    "en-GB,en;q=0.9",
    "zh-CN,zh;q=0.9,en-US;q=0.8,en;q=0.7",
    "ja-JP,ja;q=0.9,en-US;q=0.8,en;q=0.7",
    "de-DE,de;q=0.9,en-US;q=0.8,en;q=0.7",
];

const ACCEPT_ENCODINGS: &[&str] =
    &["gzip, deflate, br", "gzip, deflate", "br, gzip, deflate"];

const PATHS: &[&str] = &[
    "/api/v1/upload",
    "/data/sync",
    "/uploads/raw",
    "/api/report",
    "/feed/update",
    "/v2/events",
    "/v1/telemetry",
    "/session",
    "/stream",
    "/ws",
];

const CONTENT_TYPES: &[&str] = &[
    "application/octet-stream",
    "application/x-protobuf",
    "application/json",
];

const MIN_CONTENT_LENGTH: u64 = 4 * 1024;
const MAX_CONTENT_LENGTH: u64 = 10 * 1024 * 1024;

/// Parsed legacy HTTP-mask parameters (present only when masking is enabled).
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct HttpMaskConfig {
    /// Value of the `Host` header (and `Referer`/`Origin` host), e.g.
    /// `example.com:443`.
    pub host: String,
    /// Optional single first-level path prefix applied to every masked path.
    pub path_root: String,
}

/// A tiny OS-seeded byte source used only for cosmetic header selection. The
/// server merely validates the method and consumes to the blank line, so header
/// choice needs randomness but not wire compatibility with upstream's RNG.
struct MaskRng {
    bytes: Vec<u8>,
    pos: usize,
}

impl MaskRng {
    fn new(n: usize) -> Result<Self> {
        let mut bytes = vec![0u8; n.max(1)];
        getrandom::fill(&mut bytes)
            .map_err(|_| anyhow!("sudoku/mask: system RNG unavailable"))?;
        Ok(Self { bytes, pos: 0 })
    }

    fn byte(&mut self) -> u8 {
        let b = self.bytes[self.pos % self.bytes.len()];
        self.pos = self.pos.wrapping_add(1);
        b
    }

    /// A uniform-ish index into `[0, n)`.
    fn below(&mut self, n: usize) -> usize {
        (self.byte() as usize) % n.max(1)
    }

    fn pick<'a>(&mut self, list: &[&'a str]) -> &'a str {
        list[self.below(list.len())]
    }

    fn u64(&mut self) -> u64 {
        let mut v = 0u64;
        for _ in 0..8 {
            v = (v << 8) | u64::from(self.byte());
        }
        v
    }
}

/// Normalize a configured path root to `"/<segment>"`. Only a single segment of
/// `[A-Za-z0-9_-]` is allowed; anything else disables the prefix (returns
/// `""`).
fn normalize_path_root(root: &str) -> String {
    let trimmed = root.trim().trim_matches('/');
    if trimmed.is_empty() {
        return String::new();
    }
    if trimmed
        .bytes()
        .all(|c| c.is_ascii_alphanumeric() || c == b'_' || c == b'-')
    {
        format!("/{trimmed}")
    } else {
        String::new()
    }
}

fn join_path_root(root: &str, path: &str) -> String {
    let root = normalize_path_root(root);
    if root.is_empty() {
        return path.to_string();
    }
    if path.is_empty() {
        return root;
    }
    if path.starts_with('/') {
        format!("{root}{path}")
    } else {
        format!("{root}/{path}")
    }
}

/// Strip an optional `host:port` down to the bare host for `Referer`/`Origin`.
fn trim_port_for_host(host: &str) -> &str {
    if host.starts_with('[') {
        // IPv6 literal like "[::1]:443" -> "[::1]".
        if let Some(end) = host.find(']') {
            return &host[..=end];
        }
        return host;
    }
    match host.rsplit_once(':') {
        Some((h, p)) if !h.is_empty() && p.bytes().all(|c| c.is_ascii_digit()) => h,
        _ => host,
    }
}

fn append_common_headers(buf: &mut Vec<u8>, host: &str, rng: &mut MaskRng) {
    buf.extend_from_slice(b"Host: ");
    buf.extend_from_slice(host.as_bytes());
    buf.extend_from_slice(b"\r\nUser-Agent: ");
    buf.extend_from_slice(rng.pick(USER_AGENTS).as_bytes());
    buf.extend_from_slice(b"\r\nAccept: ");
    buf.extend_from_slice(rng.pick(ACCEPTS).as_bytes());
    buf.extend_from_slice(b"\r\nAccept-Language: ");
    buf.extend_from_slice(rng.pick(ACCEPT_LANGUAGES).as_bytes());
    buf.extend_from_slice(b"\r\nAccept-Encoding: ");
    buf.extend_from_slice(rng.pick(ACCEPT_ENCODINGS).as_bytes());
    buf.extend_from_slice(b"\r\nConnection: keep-alive\r\n");
    buf.extend_from_slice(b"Cache-Control: no-cache\r\nPragma: no-cache\r\n");
}

/// Build a randomized fake HTTP/1.1 request header, faithfully mirroring
/// upstream `WriteRandomRequestHeaderWithPathRoot` (≈20% WebSocket-upgrade
/// `GET`, ≈80% `POST` upload with a large random `Content-Length`).
fn build_request_header(
    host: &str,
    path_root: &str,
    rng: &mut MaskRng,
) -> Result<Vec<u8>> {
    let path = join_path_root(path_root, rng.pick(PATHS));
    let ctype = rng.pick(CONTENT_TYPES);
    let mut buf = Vec::with_capacity(512);

    if rng.below(10) < 2 {
        // WebSocket-like upgrade.
        let host_no_port = trim_port_for_host(host);
        let mut key = [0u8; 16];
        getrandom::fill(&mut key)
            .map_err(|_| anyhow!("sudoku/mask: system RNG unavailable"))?;
        let ws_key = base64_standard(&key);

        buf.extend_from_slice(b"GET ");
        buf.extend_from_slice(path.as_bytes());
        buf.extend_from_slice(b" HTTP/1.1\r\n");
        append_common_headers(&mut buf, host, rng);
        buf.extend_from_slice(
            b"Upgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Version: 13\r\nSec-WebSocket-Key: ",
        );
        buf.extend_from_slice(ws_key.as_bytes());
        buf.extend_from_slice(b"\r\nOrigin: https://");
        buf.extend_from_slice(host_no_port.as_bytes());
    } else {
        // POST upload with a plausible Content-Length in [4KiB, 10MiB].
        let span = MAX_CONTENT_LENGTH - MIN_CONTENT_LENGTH + 1;
        let content_length = MIN_CONTENT_LENGTH + rng.u64() % span;

        buf.extend_from_slice(b"POST ");
        buf.extend_from_slice(path.as_bytes());
        buf.extend_from_slice(b" HTTP/1.1\r\n");
        append_common_headers(&mut buf, host, rng);
        buf.extend_from_slice(b"Content-Type: ");
        buf.extend_from_slice(ctype.as_bytes());
        buf.extend_from_slice(b"\r\nContent-Length: ");
        buf.extend_from_slice(content_length.to_string().as_bytes());
        if rng.below(2) == 0 {
            buf.extend_from_slice(b"\r\nX-Requested-With: XMLHttpRequest");
        }
        if rng.below(3) == 0 {
            buf.extend_from_slice(b"\r\nReferer: https://");
            buf.extend_from_slice(trim_port_for_host(host).as_bytes());
            buf.extend_from_slice(b"/");
        }
    }
    // Terminate the last header line and add the blank line ending the block.
    buf.extend_from_slice(b"\r\n\r\n");
    Ok(buf)
}

/// Write the legacy HTTP-mask request header, then flush so the server can read
/// it before the raw Sudoku handshake begins.
pub(crate) async fn write_request_header<W>(
    w: &mut W,
    config: &HttpMaskConfig,
) -> Result<()>
where
    W: AsyncWrite + Unpin,
{
    let mut rng = MaskRng::new(64)?;
    let header = build_request_header(&config.host, &config.path_root, &mut rng)?;
    w.write_all(&header).await?;
    w.flush().await?;
    Ok(())
}

/// Standard base64 (with padding) for the cosmetic `Sec-WebSocket-Key`.
fn base64_standard(input: &[u8]) -> String {
    const ALPHABET: &[u8; 64] =
        b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut out = String::with_capacity(input.len().div_ceil(3) * 4);
    for chunk in input.chunks(3) {
        let b0 = chunk[0] as u32;
        let b1 = chunk.get(1).copied().unwrap_or(0) as u32;
        let b2 = chunk.get(2).copied().unwrap_or(0) as u32;
        let n = (b0 << 16) | (b1 << 8) | b2;
        out.push(ALPHABET[((n >> 18) & 0x3F) as usize] as char);
        out.push(ALPHABET[((n >> 12) & 0x3F) as usize] as char);
        if chunk.len() > 1 {
            out.push(ALPHABET[((n >> 6) & 0x3F) as usize] as char);
        } else {
            out.push('=');
        }
        if chunk.len() > 2 {
            out.push(ALPHABET[(n & 0x3F) as usize] as char);
        } else {
            out.push('=');
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn path_root_normalization() {
        assert_eq!(normalize_path_root(""), "");
        assert_eq!(normalize_path_root("aabbcc"), "/aabbcc");
        assert_eq!(normalize_path_root("/aabbcc/"), "/aabbcc");
        assert_eq!(normalize_path_root("a/b"), ""); // multi-segment rejected
        assert_eq!(normalize_path_root("bad space"), "");
        assert_eq!(join_path_root("root", "/session"), "/root/session");
        assert_eq!(join_path_root("", "/session"), "/session");
    }

    #[test]
    fn trims_port() {
        assert_eq!(trim_port_for_host("example.com:443"), "example.com");
        assert_eq!(trim_port_for_host("example.com"), "example.com");
        assert_eq!(trim_port_for_host("[::1]:443"), "[::1]");
    }

    #[test]
    fn base64_matches_known_vectors() {
        assert_eq!(base64_standard(b""), "");
        assert_eq!(base64_standard(b"f"), "Zg==");
        assert_eq!(base64_standard(b"fo"), "Zm8=");
        assert_eq!(base64_standard(b"foo"), "Zm9v");
        assert_eq!(base64_standard(b"foobar"), "Zm9vYmFy");
    }

    #[test]
    fn header_is_well_formed_http() {
        let cfg = HttpMaskConfig {
            host: "example.com:443".to_string(),
            path_root: "root".to_string(),
        };
        // Exercise both templates across many draws.
        for _ in 0..64 {
            let mut rng = MaskRng::new(64).expect("rng");
            let header = build_request_header(&cfg.host, &cfg.path_root, &mut rng)
                .expect("header");
            let text = String::from_utf8(header).expect("ascii header");
            assert!(
                text.ends_with("\r\n\r\n"),
                "header must end with blank line: {text:?}"
            );
            let line = text.lines().next().expect("request line");
            assert!(
                line.starts_with("GET /root/") || line.starts_with("POST /root/"),
                "unexpected request line: {line:?}"
            );
            assert!(
                line.ends_with(" HTTP/1.1"),
                "unexpected request line: {line:?}"
            );
            assert!(
                text.contains("Host: example.com:443\r\n"),
                "missing Host header: {text:?}"
            );
        }
    }
}
