use std::{
    io,
    sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
    },
    time::{Duration, SystemTime, UNIX_EPOCH},
};

use anyhow::{Context, Result, bail};
use base64::{
    Engine as _,
    engine::general_purpose::{STANDARD, URL_SAFE_NO_PAD},
};
use bytes::{Bytes, BytesMut};
use futures::{SinkExt, StreamExt};
use hmac::{Hmac, Mac};
use http::{Method, Request, Response, StatusCode, header};
use http_body_util::{BodyExt, Full};
use hyper::{
    body::Incoming,
    client::conn::{http1, http2},
};
use hyper_util::rt::{TokioExecutor, TokioIo};
use sha2::{Digest, Sha256};
use tokio::io::{AsyncReadExt, AsyncWriteExt, DuplexStream};
use tokio_tungstenite::{
    client_async,
    tungstenite::{Message, client::IntoClientRequest},
};

use crate::{
    app::{dns::ThreadSafeDNSResolver, net::OutboundInterface},
    proxy::{
        AnyStream, RemoteConnector,
        transport::{TlsClient, Transport},
    },
};

use super::{HttpMaskMode, SudokuOutboundConfig, client_aead_seed};

type HmacSha256 = Hmac<Sha256>;

#[derive(Clone)]
pub(crate) struct Dialer {
    connector: Arc<dyn RemoteConnector>,
    resolver: ThreadSafeDNSResolver,
    server: String,
    port: u16,
    iface: Option<OutboundInterface>,
    #[cfg(target_os = "linux")]
    so_mark: Option<u32>,
    tls_h1: Option<Arc<TlsClient>>,
    tls_h2: Option<Arc<TlsClient>>,
    h2_sender: Arc<tokio::sync::Mutex<Option<http2::SendRequest<Full<Bytes>>>>>,
    h2_disabled: Arc<AtomicBool>,
}

impl Dialer {
    pub(crate) fn new(
        connector: Arc<dyn RemoteConnector>,
        resolver: ThreadSafeDNSResolver,
        config: &SudokuOutboundConfig,
        iface: Option<OutboundInterface>,
        #[cfg(target_os = "linux")] so_mark: Option<u32>,
    ) -> io::Result<Self> {
        let tls_h1 = config
            .http_mask_tls
            .then(|| {
                let sni = tls_server_name(config);
                TlsClient::new(
                    false,
                    sni,
                    Some(vec!["http/1.1".to_owned()]),
                    None,
                    None,
                    None,
                )
                .map(Arc::new)
            })
            .transpose()?;
        let tls_h2 = (config.http_mask_tls && config.http_mask_multiplex != "off")
            .then(|| {
                let sni = tls_server_name(config);
                TlsClient::new(
                    false,
                    sni,
                    Some(vec!["h2".to_owned()]),
                    Some("h2".to_owned()),
                    None,
                    None,
                )
                .map(Arc::new)
            })
            .transpose()?;
        Ok(Self {
            connector,
            resolver,
            server: config.server.clone(),
            port: config.port,
            iface,
            #[cfg(target_os = "linux")]
            so_mark,
            tls_h1,
            tls_h2,
            h2_sender: Arc::new(tokio::sync::Mutex::new(None)),
            h2_disabled: Arc::new(AtomicBool::new(false)),
        })
    }

    async fn connect_raw(&self) -> io::Result<AnyStream> {
        self.connector
            .connect_stream(
                self.resolver.clone(),
                &self.server,
                self.port,
                self.iface.as_ref(),
                #[cfg(target_os = "linux")]
                self.so_mark,
            )
            .await
    }

    async fn connect(&self) -> io::Result<AnyStream> {
        let stream = self.connect_raw().await?;
        match &self.tls_h1 {
            Some(tls) => tls.proxy_stream(stream).await,
            None => Ok(stream),
        }
    }

    async fn send_h2(
        &self,
        mut request: Request<Full<Bytes>>,
    ) -> Result<Response<Incoming>> {
        let tls = self
            .tls_h2
            .as_ref()
            .context("sudoku HTTP/2 transport is disabled")?;
        let authority = request
            .headers()
            .get(header::HOST)
            .context("sudoku HTTP/2 request has no Host")?
            .to_str()?
            .parse::<http::uri::Authority>()?;
        let path = request
            .uri()
            .path_and_query()
            .cloned()
            .context("sudoku HTTP/2 request has no path")?;
        *request.uri_mut() = http::Uri::builder()
            .scheme(http::uri::Scheme::HTTPS)
            .authority(authority)
            .path_and_query(path)
            .build()?;
        *request.version_mut() = http::Version::HTTP_2;
        request.headers_mut().remove(header::HOST);
        request.headers_mut().remove(header::CONNECTION);

        let mut sender = {
            let mut pooled = self.h2_sender.lock().await;
            if pooled.is_none() {
                let stream =
                    self.connect_raw().await.context("sudoku HTTP/2 dial")?;
                let stream = tls
                    .proxy_stream(stream)
                    .await
                    .context("sudoku HTTP/2 TLS handshake")?;
                let (sender, connection) =
                    http2::handshake(TokioExecutor::new(), TokioIo::new(stream))
                        .await
                        .context("sudoku HTTP/2 handshake")?;
                tokio::spawn(async move {
                    let _ = connection.await;
                });
                *pooled = Some(sender);
            }
            pooled.as_ref().expect("initialized above").clone()
        };
        sender
            .send_request(request)
            .await
            .context("sudoku HTTP/2 request")
    }

    async fn send_request(
        &self,
        request: Request<Full<Bytes>>,
    ) -> Result<Response<Incoming>> {
        if self.tls_h2.is_some() && !self.h2_disabled.load(Ordering::Acquire) {
            let h1_request = clone_request(&request)?;
            match self.send_h2(request).await {
                Ok(response) => return Ok(response),
                Err(_) => {
                    *self.h2_sender.lock().await = None;
                    self.h2_disabled.store(true, Ordering::Release);
                    return send_http1_request(self, h1_request).await;
                }
            }
        }
        send_http1_request(self, request).await
    }
}

fn clone_request(request: &Request<Full<Bytes>>) -> Result<Request<Full<Bytes>>> {
    let mut cloned = Request::builder()
        .method(request.method())
        .uri(request.uri())
        .version(request.version());
    *cloned.headers_mut().expect("request builder headers") =
        request.headers().clone();
    Ok(cloned.body(request.body().clone())?)
}

fn tls_server_name(config: &SudokuOutboundConfig) -> String {
    let host = config.http_mask_host.trim();
    if host.is_empty() {
        return config.server.clone();
    }
    host.strip_prefix('[')
        .and_then(|value| value.split_once(']'))
        .map(|(host, _)| host.to_owned())
        .or_else(|| {
            host.rsplit_once(':')
                .filter(|(_, port)| port.parse::<u16>().is_ok())
                .map(|(host, _)| host.to_owned())
        })
        .unwrap_or_else(|| host.to_owned())
}

fn header_host(config: &SudokuOutboundConfig) -> String {
    let host = config.http_mask_host.trim();
    if host.is_empty() {
        format!("{}:{}", config.server, config.port)
    } else {
        host.to_owned()
    }
}

fn rooted_path(config: &SudokuOutboundConfig, path: &str) -> String {
    if config.http_mask_path_root.is_empty() {
        path.to_owned()
    } else {
        format!(
            "/{}/{}",
            config.http_mask_path_root,
            path.trim_start_matches('/')
        )
    }
}

fn mode_name(mode: HttpMaskMode) -> &'static str {
    match mode {
        HttpMaskMode::Stream => "stream",
        HttpMaskMode::Poll => "poll",
        HttpMaskMode::WebSocket => "ws",
        HttpMaskMode::Auto => "auto",
        HttpMaskMode::Disabled => "disabled",
        HttpMaskMode::Legacy => "legacy",
    }
}

fn auth_token(
    key: &str,
    mode: HttpMaskMode,
    method: &Method,
    path: &str,
) -> Result<String> {
    let timestamp = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .context("sudoku HTTP mask system clock is before Unix epoch")?
        .as_secs() as i64;
    let derived = Sha256::digest(
        [
            b"sudoku-httpmask-auth-v1:".as_slice(),
            key.trim().as_bytes(),
        ]
        .concat(),
    );
    let mut mac = <HmacSha256 as hmac::KeyInit>::new_from_slice(&derived)
        .context("sudoku HTTP mask HMAC key")?;
    mac.update(mode_name(mode).as_bytes());
    mac.update(&[0]);
    mac.update(method.as_str().to_ascii_uppercase().as_bytes());
    mac.update(&[0]);
    mac.update(path.trim().as_bytes());
    mac.update(&[0]);
    mac.update(&timestamp.to_be_bytes());
    let signature = mac.finalize().into_bytes();
    let mut token = [0u8; 24];
    token[..8].copy_from_slice(&timestamp.to_be_bytes());
    token[8..].copy_from_slice(&signature[..16]);
    Ok(URL_SAFE_NO_PAD.encode(token))
}

fn request_builder(
    config: &SudokuOutboundConfig,
    mode: HttpMaskMode,
    method: Method,
    canonical_path: &str,
    query: &[(&str, &str)],
) -> Result<http::request::Builder> {
    let auth = auth_token(
        &client_aead_seed(&config.key),
        mode,
        &method,
        canonical_path,
    )?;
    let mut uri = rooted_path(config, canonical_path);
    let mut params = query
        .iter()
        .map(|(key, value)| format!("{key}={value}"))
        .collect::<Vec<_>>();
    params.push(format!("auth={auth}"));
    if !params.is_empty() {
        uri.push('?');
        uri.push_str(&params.join("&"));
    }
    Ok(Request::builder()
        .method(method)
        .uri(uri)
        .header(header::HOST, header_host(config))
        .header(header::USER_AGENT, "Mozilla/5.0")
        .header(header::ACCEPT, "*/*")
        .header(header::ACCEPT_LANGUAGE, "en-US,en;q=0.9")
        .header(header::ACCEPT_ENCODING, "identity")
        .header(header::CACHE_CONTROL, "no-cache")
        .header(header::PRAGMA, "no-cache")
        .header(header::CONNECTION, "keep-alive")
        .header("X-Sudoku-Tunnel", mode_name(mode))
        .header("X-Sudoku-Version", "1")
        .header(header::AUTHORIZATION, format!("Bearer {auth}")))
}

async fn send_http1_request(
    dialer: &Dialer,
    request: Request<Full<Bytes>>,
) -> Result<Response<Incoming>> {
    let stream = dialer.connect().await.context("sudoku HTTP mask dial")?;
    let (mut sender, connection) = http1::handshake(TokioIo::new(stream))
        .await
        .context("sudoku HTTP mask HTTP/1.1 handshake")?;
    tokio::spawn(async move {
        let _ = connection.await;
    });
    sender
        .send_request(request)
        .await
        .context("sudoku HTTP mask request")
}

async fn authorize(
    dialer: &Dialer,
    config: &SudokuOutboundConfig,
    mode: HttpMaskMode,
) -> Result<String> {
    let request = request_builder(config, mode, Method::GET, "/session", &[])?
        .body(Full::new(Bytes::new()))?;
    let response = dialer.send_request(request).await?;
    if response.status() != StatusCode::OK {
        bail!(
            "sudoku HTTP mask {} authorize returned {}",
            mode_name(mode),
            response.status()
        );
    }
    let body = response.into_body().collect().await?.to_bytes();
    let text = std::str::from_utf8(&body)
        .context("sudoku HTTP mask authorize response is not UTF-8")?;
    text.lines()
        .find_map(|line| line.strip_prefix("token="))
        .filter(|token| !token.is_empty())
        .map(str::to_owned)
        .context("sudoku HTTP mask authorize response has no token")
}

async fn push(
    dialer: &Dialer,
    config: &SudokuOutboundConfig,
    mode: HttpMaskMode,
    session_token: &str,
    payload: Bytes,
) -> Result<()> {
    let body = if mode == HttpMaskMode::Poll {
        let mut encoded = String::new();
        for chunk in payload.chunks(16 * 1024) {
            encoded.push_str(&STANDARD.encode(chunk));
            encoded.push('\n');
        }
        Bytes::from(encoded)
    } else {
        payload
    };
    let content_type = if mode == HttpMaskMode::Poll {
        "text/plain"
    } else {
        "application/octet-stream"
    };
    let request = request_builder(
        config,
        mode,
        Method::POST,
        "/api/v1/upload",
        &[("token", session_token)],
    )?
    .header(header::CONTENT_TYPE, content_type)
    .body(Full::new(body))?;
    let response = dialer.send_request(request).await?;
    if response.status() != StatusCode::OK {
        bail!(
            "sudoku HTTP mask {} push returned {}",
            mode_name(mode),
            response.status()
        );
    }
    let _ = response.into_body().collect().await;
    Ok(())
}

async fn signal(
    dialer: &Dialer,
    config: &SudokuOutboundConfig,
    mode: HttpMaskMode,
    session_token: &str,
    signal: &str,
) {
    let request = request_builder(
        config,
        mode,
        Method::POST,
        "/api/v1/upload",
        &[("token", session_token), (signal, "1")],
    )
    .and_then(|builder| builder.body(Full::new(Bytes::new())).map_err(Into::into));
    if let Ok(request) = request
        && let Ok(response) = dialer.send_request(request).await
    {
        let _ = response.into_body().collect().await;
    }
}

async fn pull_once(
    dialer: &Dialer,
    config: &SudokuOutboundConfig,
    mode: HttpMaskMode,
    session_token: &str,
    writer: &mut tokio::io::WriteHalf<DuplexStream>,
) -> Result<bool> {
    let request = request_builder(
        config,
        mode,
        Method::GET,
        "/stream",
        &[("token", session_token)],
    )?
    .body(Full::new(Bytes::new()))?;
    let response = dialer.send_request(request).await?;
    if response.status() != StatusCode::OK {
        bail!(
            "sudoku HTTP mask {} pull returned {}",
            mode_name(mode),
            response.status()
        );
    }
    let mut body = response.into_body();
    let mut received = false;
    let mut encoded = BytesMut::new();
    while let Some(frame) = body.frame().await {
        let frame = frame?;
        let Some(data) = frame.data_ref() else {
            continue;
        };
        if mode == HttpMaskMode::Poll {
            encoded.extend_from_slice(data);
            while let Some(index) = encoded.iter().position(|byte| *byte == b'\n') {
                let mut line = encoded.split_to(index + 1);
                line.truncate(index);
                let line = line
                    .iter()
                    .copied()
                    .filter(|byte| !byte.is_ascii_whitespace())
                    .collect::<Vec<_>>();
                if line.is_empty() {
                    continue;
                }
                let decoded = STANDARD
                    .decode(line)
                    .context("sudoku HTTP mask poll base64")?;
                writer.write_all(&decoded).await?;
                received |= !decoded.is_empty();
            }
        } else {
            writer.write_all(data).await?;
            received |= !data.is_empty();
        }
    }
    if mode == HttpMaskMode::Poll && !encoded.iter().all(u8::is_ascii_whitespace) {
        let decoded = STANDARD
            .decode(
                encoded
                    .iter()
                    .copied()
                    .filter(|byte| !byte.is_ascii_whitespace())
                    .collect::<Vec<_>>(),
            )
            .context("sudoku HTTP mask poll trailing base64")?;
        writer.write_all(&decoded).await?;
        received |= !decoded.is_empty();
    }
    Ok(received)
}

async fn connect_split(
    dialer: Dialer,
    config: SudokuOutboundConfig,
    mode: HttpMaskMode,
) -> Result<AnyStream> {
    let session_token = authorize(&dialer, &config, mode).await?;
    let (app, worker) = tokio::io::duplex(256 * 1024);
    let (mut reader, mut writer) = tokio::io::split(worker);

    let push_dialer = dialer.clone();
    let push_config = config.clone();
    let push_token = session_token.clone();
    tokio::spawn(async move {
        let mut buffer = vec![0u8; 512 * 1024];
        loop {
            match reader.read(&mut buffer).await {
                Ok(0) => {
                    signal(&push_dialer, &push_config, mode, &push_token, "fin")
                        .await;
                    return;
                }
                Ok(length) => {
                    if push(
                        &push_dialer,
                        &push_config,
                        mode,
                        &push_token,
                        Bytes::copy_from_slice(&buffer[..length]),
                    )
                    .await
                    .is_err()
                    {
                        signal(
                            &push_dialer,
                            &push_config,
                            mode,
                            &push_token,
                            "close",
                        )
                        .await;
                        return;
                    }
                }
                Err(_) => return,
            }
        }
    });

    tokio::spawn(async move {
        loop {
            match pull_once(&dialer, &config, mode, &session_token, &mut writer)
                .await
            {
                Ok(received) => {
                    if !received {
                        tokio::time::sleep(Duration::from_millis(25)).await;
                    }
                }
                Err(_) => {
                    signal(&dialer, &config, mode, &session_token, "close").await;
                    let _ = writer.shutdown().await;
                    return;
                }
            }
        }
    });
    Ok(Box::new(app))
}

async fn connect_websocket(
    dialer: Dialer,
    config: SudokuOutboundConfig,
) -> Result<AnyStream> {
    let auth = auth_token(
        &client_aead_seed(&config.key),
        HttpMaskMode::WebSocket,
        &Method::GET,
        "/ws",
    )?;
    let scheme = if config.http_mask_tls { "wss" } else { "ws" };
    let uri = format!(
        "{scheme}://{}{}?auth={auth}",
        header_host(&config),
        rooted_path(&config, "/ws"),
    );
    let mut request = uri.into_client_request()?;
    let headers = request.headers_mut();
    headers.insert(header::HOST, header_host(&config).parse()?);
    headers.insert(header::USER_AGENT, "Mozilla/5.0".parse()?);
    headers.insert(header::CACHE_CONTROL, "no-cache".parse()?);
    headers.insert(header::PRAGMA, "no-cache".parse()?);
    headers.insert("X-Sudoku-Tunnel", "ws".parse()?);
    headers.insert("X-Sudoku-Version", "1".parse()?);
    headers.insert(header::AUTHORIZATION, format!("Bearer {auth}").parse()?);
    let raw = dialer.connect().await?;
    let (websocket, response) = client_async(request, raw).await?;
    if response.status() != StatusCode::SWITCHING_PROTOCOLS {
        bail!("sudoku HTTP mask websocket returned {}", response.status());
    }
    let (mut ws_writer, mut ws_reader) = websocket.split();
    let (app, worker) = tokio::io::duplex(256 * 1024);
    let (mut reader, mut writer) = tokio::io::split(worker);
    tokio::spawn(async move {
        let mut buffer = vec![0u8; 64 * 1024];
        loop {
            match reader.read(&mut buffer).await {
                Ok(0) => {
                    let _ = ws_writer.close().await;
                    return;
                }
                Ok(length) => {
                    if ws_writer
                        .send(Message::Binary(Bytes::copy_from_slice(
                            &buffer[..length],
                        )))
                        .await
                        .is_err()
                    {
                        return;
                    }
                }
                Err(_) => return,
            }
        }
    });
    tokio::spawn(async move {
        while let Some(message) = ws_reader.next().await {
            match message {
                Ok(Message::Binary(data)) => {
                    if writer.write_all(&data).await.is_err() {
                        break;
                    }
                }
                Ok(Message::Text(data)) => {
                    if writer.write_all(data.as_bytes()).await.is_err() {
                        break;
                    }
                }
                Ok(Message::Ping(_))
                | Ok(Message::Pong(_))
                | Ok(Message::Frame(_)) => {}
                Ok(Message::Close(_)) | Err(_) => break,
            }
        }
        let _ = writer.shutdown().await;
    });
    Ok(Box::new(app))
}

pub(crate) async fn connect(
    dialer: Dialer,
    config: &SudokuOutboundConfig,
) -> Result<AnyStream> {
    match config.http_mask_mode {
        HttpMaskMode::Stream => {
            connect_split(dialer, config.clone(), HttpMaskMode::Stream).await
        }
        HttpMaskMode::Poll => {
            connect_split(dialer, config.clone(), HttpMaskMode::Poll).await
        }
        HttpMaskMode::WebSocket => connect_websocket(dialer, config.clone()).await,
        HttpMaskMode::Auto => {
            match tokio::time::timeout(
                Duration::from_secs(3),
                connect_split(dialer.clone(), config.clone(), HttpMaskMode::Stream),
            )
            .await
            {
                Ok(Ok(stream)) => Ok(stream),
                _ => connect_split(dialer, config.clone(), HttpMaskMode::Poll).await,
            }
        }
        HttpMaskMode::Disabled | HttpMaskMode::Legacy => {
            bail!("sudoku HTTP tunnel requested for non-tunnel mode")
        }
    }
}

#[cfg(test)]
mod tests {
    use std::{
        convert::Infallible,
        io,
        net::SocketAddr,
        path::PathBuf,
        process::Stdio,
        sync::{
            Arc,
            atomic::{AtomicUsize, Ordering},
        },
    };

    use async_trait::async_trait;
    use tokio::{
        io::{AsyncBufReadExt, AsyncReadExt, AsyncWriteExt, BufReader},
        net::{TcpListener, TcpStream},
        process::{Child, Command},
    };
    use tokio_rustls::TlsAcceptor;

    use crate::{
        app::dns::ThreadSafeDNSResolver,
        proxy::{
            AnyOutboundDatagram, AnyStream, HandlerCommonOptions, OutboundHandler,
            RemoteConnector, utils::test_utils::noop::NoopResolver,
        },
        session::{Session, SocksAddr},
    };

    use super::{
        super::{Handler, HandlerOptions, SudokuOutboundConfig},
        *,
    };

    #[derive(Clone, Debug)]
    struct FixtureConnector(SocketAddr);

    #[async_trait]
    impl RemoteConnector for FixtureConnector {
        fn clone_connector(&self) -> Arc<dyn RemoteConnector> {
            Arc::new(self.clone())
        }

        async fn connect_stream(
            &self,
            _resolver: ThreadSafeDNSResolver,
            _address: &str,
            _port: u16,
            _iface: Option<&OutboundInterface>,
            #[cfg(target_os = "linux")] _so_mark: Option<u32>,
        ) -> io::Result<AnyStream> {
            Ok(Box::new(TcpStream::connect(self.0).await?))
        }

        async fn connect_datagram(
            &self,
            _resolver: ThreadSafeDNSResolver,
            _src: Option<SocketAddr>,
            _destination: SocksAddr,
            _iface: Option<&OutboundInterface>,
            #[cfg(target_os = "linux")] _so_mark: Option<u32>,
        ) -> io::Result<AnyOutboundDatagram> {
            Err(io::Error::new(
                io::ErrorKind::Unsupported,
                "fixture is TCP only",
            ))
        }
    }

    async fn spawn_mihomo(mode: &str) -> Option<(Child, SocketAddr)> {
        let mihomo = std::env::var_os("MIHOMO_SOURCE_DIR").map(PathBuf::from)?;
        let fixture = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("tests/fixtures/sudoku_mihomo_server.go");
        let mut child = Command::new("go")
            .arg("run")
            .arg(fixture)
            .arg("tunnel")
            .arg(mode)
            .arg("flclash")
            .arg("interop-secret")
            .current_dir(mihomo)
            .stdout(Stdio::piped())
            .stderr(Stdio::inherit())
            .kill_on_drop(true)
            .spawn()
            .expect("start Mihomo Sudoku fixture");
        let mut line = String::new();
        BufReader::new(child.stdout.take().expect("fixture stdout"))
            .read_line(&mut line)
            .await
            .expect("read fixture address");
        let address = line.trim().parse().expect("fixture socket address");
        Some((child, address))
    }

    async fn spawn_full_mihomo(mode: &str) -> Option<(Child, SocketAddr, String)> {
        let mihomo = std::env::var_os("MIHOMO_SOURCE_DIR").map(PathBuf::from)?;
        let fixture = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("tests/fixtures/sudoku_mihomo_server.go");
        let mut child = Command::new("go")
            .arg("run")
            .arg(fixture)
            .arg("full")
            .arg(mode)
            .arg("flclash")
            .arg("unused")
            .current_dir(mihomo)
            .stdout(Stdio::piped())
            .stderr(Stdio::inherit())
            .kill_on_drop(true)
            .spawn()
            .expect("start full Mihomo Sudoku fixture");
        let mut line = String::new();
        BufReader::new(child.stdout.take().expect("fixture stdout"))
            .read_line(&mut line)
            .await
            .expect("read full fixture parameters");
        let mut values = line.split_whitespace();
        let address = values
            .next()
            .expect("fixture address")
            .parse()
            .expect("fixture socket address");
        let private_key = values.next().expect("fixture private key").to_owned();
        Some((child, address, private_key))
    }

    fn config(address: SocketAddr, mode: &str) -> SudokuOutboundConfig {
        config_with_key(address, mode, "interop-secret")
    }

    fn config_with_key(
        address: SocketAddr,
        mode: &str,
        key: &str,
    ) -> SudokuOutboundConfig {
        SudokuOutboundConfig::new(
            address.ip().to_string(),
            address.port(),
            key.to_owned(),
            "chacha20-poly1305".to_owned(),
            "prefer_entropy".to_owned(),
            None,
            Vec::new(),
            None,
            None,
            None,
            true,
            mode.to_owned(),
            false,
            "masked.example".to_owned(),
            "flclash".to_owned(),
            "off".to_owned(),
        )
        .unwrap()
    }

    async fn assert_mihomo_round_trip(client_mode: &str, server_mode: &str) {
        let Some((_child, address)) = spawn_mihomo(server_mode).await else {
            eprintln!("MIHOMO_SOURCE_DIR is unset; skipping cross-language fixture");
            return;
        };
        let config = config(address, client_mode);
        let resolver: ThreadSafeDNSResolver = Arc::new(NoopResolver);
        let dialer = Dialer::new(
            Arc::new(FixtureConnector(address)),
            resolver,
            &config,
            None,
            #[cfg(target_os = "linux")]
            None,
        )
        .unwrap();
        let mut stream =
            tokio::time::timeout(Duration::from_secs(10), connect(dialer, &config))
                .await
                .expect("Mihomo tunnel timeout")
                .expect("Mihomo tunnel connect");
        let payload = b"FlClash clash-rs <-> Mihomo Sudoku HTTP mask";
        stream.write_all(payload).await.unwrap();
        stream.flush().await.unwrap();
        let mut echoed = vec![0u8; payload.len()];
        tokio::time::timeout(
            Duration::from_secs(10),
            stream.read_exact(&mut echoed),
        )
        .await
        .expect("Mihomo echo timeout")
        .unwrap();
        assert_eq!(echoed, payload);
    }

    #[tokio::test]
    async fn mihomo_stream_round_trip() {
        assert_mihomo_round_trip("stream", "stream").await;
    }

    #[tokio::test]
    async fn mihomo_poll_round_trip() {
        assert_mihomo_round_trip("poll", "poll").await;
    }

    #[tokio::test]
    async fn mihomo_auto_falls_back_to_poll() {
        assert_mihomo_round_trip("auto", "poll").await;
    }

    #[tokio::test]
    async fn mihomo_websocket_round_trip() {
        assert_mihomo_round_trip("ws", "ws").await;
    }

    async fn assert_full_mihomo_round_trip(mode: &str) {
        let Some((_child, address, private_key)) = spawn_full_mihomo(mode).await
        else {
            eprintln!("MIHOMO_SOURCE_DIR is unset; skipping cross-language fixture");
            return;
        };
        let config = config_with_key(address, mode, &private_key);
        let resolver: ThreadSafeDNSResolver = Arc::new(NoopResolver);
        let dialer = Dialer::new(
            Arc::new(FixtureConnector(address)),
            resolver,
            &config,
            None,
            #[cfg(target_os = "linux")]
            None,
        )
        .unwrap();
        let tunnel = tokio::time::timeout(
            Duration::from_secs(10),
            super::connect(dialer, &config),
        )
        .await
        .expect("full Mihomo tunnel timeout")
        .expect("full Mihomo tunnel connect");
        let target = SocksAddr::Domain("echo.example".to_owned(), 443);
        let mut stream = tokio::time::timeout(
            Duration::from_secs(10),
            super::super::connect(&config, &target, tunnel),
        )
        .await
        .expect("full Mihomo handshake timeout")
        .expect("full Mihomo handshake");
        let payload = b"split Ed25519 key over full Sudoku stack";
        stream.write_all(payload).await.unwrap();
        stream.flush().await.unwrap();
        let mut echoed = vec![0u8; payload.len()];
        tokio::time::timeout(
            Duration::from_secs(10),
            stream.read_exact(&mut echoed),
        )
        .await
        .expect("full Mihomo echo timeout")
        .unwrap();
        assert_eq!(echoed, payload);
    }

    #[tokio::test]
    async fn full_mihomo_stream_with_split_ed25519_key() {
        assert_full_mihomo_round_trip("stream").await;
    }

    #[tokio::test]
    async fn full_mihomo_poll_with_split_ed25519_key() {
        assert_full_mihomo_round_trip("poll").await;
    }

    #[tokio::test]
    async fn full_mihomo_websocket_with_split_ed25519_key() {
        assert_full_mihomo_round_trip("ws").await;
    }

    #[tokio::test]
    async fn full_mihomo_uot_round_trip() {
        let Some((_child, address, private_key)) = spawn_full_mihomo("stream").await
        else {
            eprintln!("MIHOMO_SOURCE_DIR is unset; skipping cross-language fixture");
            return;
        };
        let config = config_with_key(address, "stream", &private_key);
        let resolver: ThreadSafeDNSResolver = Arc::new(NoopResolver);
        let dialer = Dialer::new(
            Arc::new(FixtureConnector(address)),
            resolver,
            &config,
            None,
            #[cfg(target_os = "linux")]
            None,
        )
        .unwrap();
        let tunnel = super::connect(dialer, &config).await.unwrap();
        let mut stream = super::super::uot::start(&config, tunnel).await.unwrap();
        let target = SocksAddr::Domain("dns.example".to_owned(), 53);
        let payload = b"Mihomo UoT datagram";
        super::super::uot::write_packet(&mut stream, &target, payload)
            .await
            .unwrap();
        let (source, echoed) = tokio::time::timeout(
            Duration::from_secs(10),
            super::super::uot::read_packet(&mut stream),
        )
        .await
        .expect("Mihomo UoT echo timeout")
        .unwrap();
        assert_eq!(source, target);
        assert_eq!(echoed, payload);
    }

    #[tokio::test]
    async fn handler_auto_retries_full_handshake_with_poll() {
        let Some((_child, address, private_key)) = spawn_full_mihomo("poll").await
        else {
            eprintln!("MIHOMO_SOURCE_DIR is unset; skipping cross-language fixture");
            return;
        };
        let config = config_with_key(address, "auto", &private_key);
        let handler = Handler::new(HandlerOptions {
            name: "sudoku-auto".to_owned(),
            common_opts: HandlerCommonOptions::default(),
            config,
        })
        .unwrap();
        let connector = FixtureConnector(address);
        let resolver: ThreadSafeDNSResolver = Arc::new(NoopResolver);
        let session = Session {
            destination: SocksAddr::Domain("fallback.example".to_owned(), 443),
            ..Default::default()
        };
        let mut stream = handler
            .connect_stream_with_connector(&session, resolver, &connector)
            .await
            .unwrap();
        let payload = b"auto retried the complete KIP handshake over poll";
        stream.write_all(payload).await.unwrap();
        stream.flush().await.unwrap();
        let mut echoed = vec![0u8; payload.len()];
        tokio::time::timeout(
            Duration::from_secs(10),
            stream.read_exact(&mut echoed),
        )
        .await
        .expect("auto fallback echo timeout")
        .unwrap();
        assert_eq!(echoed, payload);
    }

    #[tokio::test]
    async fn tls_multiplex_reuses_one_http2_connection() {
        crate::setup_default_crypto_provider();
        let rcgen::CertifiedKey { cert, signing_key } =
            rcgen::generate_simple_self_signed(vec!["localhost".to_owned()])
                .unwrap();
        let key =
            rustls::pki_types::PrivateKeyDer::try_from(signing_key.serialize_der())
                .unwrap();
        let mut server_config = rustls::ServerConfig::builder()
            .with_no_client_auth()
            .with_single_cert(vec![cert.der().clone()], key)
            .unwrap();
        server_config.alpn_protocols = vec![b"h2".to_vec()];
        let acceptor = TlsAcceptor::from(Arc::new(server_config));
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let accepted = Arc::new(AtomicUsize::new(0));
        let server_accepted = accepted.clone();
        let server = tokio::spawn(async move {
            loop {
                let (stream, _) = listener.accept().await.unwrap();
                server_accepted.fetch_add(1, Ordering::AcqRel);
                let acceptor = acceptor.clone();
                tokio::spawn(async move {
                    let stream = acceptor.accept(stream).await.unwrap();
                    let service = hyper::service::service_fn(|_request| async {
                        Ok::<_, Infallible>(Response::new(Full::new(
                            Bytes::from_static(b"ok"),
                        )))
                    });
                    let _ = hyper::server::conn::http2::Builder::new(
                        TokioExecutor::new(),
                    )
                    .serve_connection(TokioIo::new(stream), service)
                    .await;
                });
            }
        });

        let mut config = config(address, "stream");
        config.http_mask_tls = true;
        config.http_mask_multiplex = "auto".to_owned();
        config.http_mask_host = "localhost".to_owned();
        let resolver: ThreadSafeDNSResolver = Arc::new(NoopResolver);
        let mut dialer = Dialer::new(
            Arc::new(FixtureConnector(address)),
            resolver,
            &config,
            None,
            #[cfg(target_os = "linux")]
            None,
        )
        .unwrap();
        dialer.tls_h1 = Some(Arc::new(
            TlsClient::new(
                true,
                "localhost".to_owned(),
                Some(vec!["http/1.1".to_owned()]),
                None,
                None,
                None,
            )
            .unwrap(),
        ));
        dialer.tls_h2 = Some(Arc::new(
            TlsClient::new(
                true,
                "localhost".to_owned(),
                Some(vec!["h2".to_owned()]),
                Some("h2".to_owned()),
                None,
                None,
            )
            .unwrap(),
        ));

        for _ in 0..2 {
            let request = request_builder(
                &config,
                HttpMaskMode::Stream,
                Method::GET,
                "/session",
                &[],
            )
            .unwrap()
            .body(Full::new(Bytes::new()))
            .unwrap();
            let response = dialer.send_request(request).await.unwrap();
            assert_eq!(response.status(), StatusCode::OK);
            assert_eq!(
                response.into_body().collect().await.unwrap().to_bytes(),
                Bytes::from_static(b"ok"),
            );
        }
        assert_eq!(accepted.load(Ordering::Acquire), 1);
        server.abort();
    }
}
