use async_trait::async_trait;
use rand::{RngExt, distr::Distribution};
use std::{
    io,
    pin::Pin,
    ptr::copy_nonoverlapping,
    sync::{Arc, Mutex},
    task::{Context, Poll},
};
use stream::{ProxyTlsStream, VerifiedStream};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio_rustls::{TlsConnector, client::TlsStream};
use utils::Hmac;

mod prelude;
mod stream;
mod utils;
mod v2;

use super::Transport;
#[cfg(feature = "utls")]
use super::browser_tls::Client as BrowserTlsClient;
use crate::{
    common::{
        errors::map_io_error,
        tls::{DefaultTlsVerifier, build_tls_client_config_with_protocol_versions},
    },
    proxy::AnyStream,
};
use prelude::*;

pub struct Client {
    host: String,
    password: String,
    strict: bool,
    version: u8,
    alpn: Vec<String>,
    skip_cert_verify: bool,
    fingerprint: Option<String>,
    certificate: Option<String>,
    private_key: Option<String>,
    client_fingerprint: Option<String>,
}

impl Client {
    // Retained as the Mihomo-compatible ShadowTLS v3 convenience constructor.
    #[allow(dead_code)]
    pub fn new(host: String, password: String, strict: bool) -> Self {
        Self {
            host,
            password,
            strict,
            version: 3,
            alpn: vec!["h2".to_owned(), "http/1.1".to_owned()],
            skip_cert_verify: false,
            fingerprint: None,
            certificate: None,
            private_key: None,
            client_fingerprint: None,
        }
    }

    #[allow(clippy::too_many_arguments)]
    pub fn new_with_options(
        host: String,
        password: String,
        strict: bool,
        version: u8,
        alpn: Option<Vec<String>>,
        skip_cert_verify: bool,
        fingerprint: Option<String>,
        certificate: Option<String>,
        private_key: Option<String>,
    ) -> Self {
        Self {
            host,
            password,
            strict,
            version,
            alpn: alpn
                .unwrap_or_else(|| vec!["h2".to_owned(), "http/1.1".to_owned()]),
            skip_cert_verify,
            fingerprint,
            certificate,
            private_key,
            client_fingerprint: None,
        }
    }

    pub fn with_client_fingerprint(
        mut self,
        client_fingerprint: Option<String>,
    ) -> io::Result<Self> {
        if client_fingerprint.is_some() && self.version == 3 {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "ShadowTLS v3 client-fingerprint requires a custom uTLS session-id \
                 callback that is not implemented",
            ));
        }
        self.client_fingerprint = client_fingerprint;
        Ok(self)
    }

    pub async fn wrap_shadow_tls_stream(
        &self,
        stream: AnyStream,
    ) -> std::io::Result<AnyStream> {
        match self.version {
            1 => self.wrap_legacy_stream(stream, false).await,
            2 => self.wrap_legacy_stream(stream, true).await,
            3 => self.wrap_v3_stream(stream).await,
            version => Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                format!("unsupported ShadowTLS version {version}"),
            )),
        }
    }

    async fn wrap_v3_stream(&self, stream: AnyStream) -> io::Result<AnyStream> {
        let proxy_stream = ProxyTlsStream::new(stream, &self.password);

        // handshake
        let hamc_handshake = Hmac::new(&self.password, (&[], &[]));
        let sni_name = rustls::pki_types::ServerName::try_from(self.host.clone())
            .map_err(map_io_error)?;
        let session_id_generator =
            move |data: &_| generate_session_id(&hamc_handshake, data);
        let connector = self.new_connector(false)?;
        let mut tls = connector
            .connect_with_session_id_generator(
                sni_name,
                proxy_stream,
                Some(session_id_generator),
                |_| {},
            )
            .await?;

        // check if is authorized
        let authorized = tls.get_mut().0.authorized();
        let maybe_server_random_and_hamc = tls
            .get_mut()
            .0
            .state()
            .as_ref()
            .map(|s| (s.server_random, s.hmac.to_owned()));

        // whatever the fake_request is successful or not, we should return an
        // error when strict mode is enabled
        if (!authorized || maybe_server_random_and_hamc.is_none()) && self.strict {
            tracing::warn!(
                "shadow-tls V3 strict enabled: traffic hijacked or TLS1.3 is not \
                 supported, perform fake request"
            );

            tls.get_mut().0.fake_request = true;
            fake_request(tls).await?;

            return Err(io::Error::other(
                "V3 strict enabled: traffic hijacked or TLS1.3 is not supported, \
                 fake request",
            ));
        }

        let (server_random, hmac_nop) = match maybe_server_random_and_hamc {
            Some(inner) => inner,
            None => {
                return Err(io::Error::other(
                    "server random and hmac not extracted from handshake, fail to \
                     connect",
                ));
            }
        };

        let hmac_client =
            Hmac::new(&self.password, (&server_random, "C".as_bytes()));
        let hmac_server =
            Hmac::new(&self.password, (&server_random, "S".as_bytes()));

        // now the shadow tls stream is connected, we can use it to send data
        let verified_stream = VerifiedStream::new(
            tls.into_inner().0.raw,
            hmac_client,
            hmac_server,
            Some(hmac_nop),
        );

        Ok(Box::new(verified_stream))
    }

    async fn wrap_legacy_stream(
        &self,
        stream: AnyStream,
        v2: bool,
    ) -> io::Result<AnyStream> {
        if let Some(client_fingerprint) = self.client_fingerprint.as_deref() {
            #[cfg(feature = "utls")]
            return self
                .wrap_browser_legacy_stream(stream, v2, client_fingerprint)
                .await;
            #[cfg(not(feature = "utls"))]
            return Err(io::Error::new(
                io::ErrorKind::Unsupported,
                format!(
                    "ShadowTLS client-fingerprint `{client_fingerprint}` requires \
                     the utls feature"
                ),
            ));
        }

        let hashed = HashedReadStream::new(stream, &self.password);
        let server_name = rustls::pki_types::ServerName::try_from(self.host.clone())
            .map_err(map_io_error)?;
        let tls = self
            .new_connector(!v2)?
            .connect(server_name, hashed)
            .await?;
        let hashed = tls.into_inner().0;
        let first_auth = hashed
            .hmac
            .lock()
            .map_err(|_| io::Error::other("ShadowTLS handshake HMAC poisoned"))?
            .finalize_v2();
        let raw = hashed.raw;
        if v2 {
            Ok(Box::new(v2::Stream::new(raw, first_auth)))
        } else {
            Ok(raw)
        }
    }

    #[cfg(feature = "utls")]
    async fn wrap_browser_legacy_stream(
        &self,
        stream: AnyStream,
        v2: bool,
        client_fingerprint: &str,
    ) -> io::Result<AnyStream> {
        let hashed = HashedReadStream::new(stream, &self.password);
        let handshake_hmac = Arc::clone(&hashed.hmac);
        let connector = BrowserTlsClient::new_shadow_tls(
            client_fingerprint,
            self.skip_cert_verify,
            self.host.clone(),
            Some(self.alpn.clone()),
            self.fingerprint.clone(),
            self.certificate.as_deref(),
            self.private_key.as_deref(),
            !v2,
        )?;
        let tls = connector.connect_stream(Box::new(hashed)).await?;
        let first_auth = handshake_hmac
            .lock()
            .map_err(|_| io::Error::other("ShadowTLS handshake HMAC poisoned"))?
            .finalize_v2();
        let raw = BrowserTlsRawStream { tls };
        if v2 {
            Ok(Box::new(v2::Stream::new(raw, first_auth)))
        } else {
            Ok(Box::new(raw))
        }
    }

    fn new_connector(&self, tls12_only: bool) -> io::Result<TlsConnector> {
        let verifier = Arc::new(DefaultTlsVerifier::try_new(
            self.fingerprint.clone(),
            self.skip_cert_verify,
        )?);
        let versions = if tls12_only {
            &[&rustls::version::TLS12][..]
        } else {
            rustls::DEFAULT_VERSIONS
        };
        let mut config = build_tls_client_config_with_protocol_versions(
            verifier,
            self.certificate.as_deref(),
            self.private_key.as_deref(),
            versions,
        )?;
        config.alpn_protocols = self
            .alpn
            .iter()
            .map(|protocol| protocol.as_bytes().to_vec())
            .collect();
        Ok(TlsConnector::from(Arc::new(config)))
    }
}

#[async_trait]
impl Transport for Client {
    async fn proxy_stream(&self, stream: AnyStream) -> std::io::Result<AnyStream> {
        self.wrap_shadow_tls_stream(stream).await
    }
}

struct HashedReadStream {
    raw: AnyStream,
    hmac: Arc<Mutex<Hmac>>,
}

impl HashedReadStream {
    fn new(raw: AnyStream, password: &str) -> Self {
        Self {
            raw,
            hmac: Arc::new(Mutex::new(Hmac::new(password, (&[], &[])))),
        }
    }
}

impl AsyncRead for HashedReadStream {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buffer: &mut tokio::io::ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        let before = buffer.filled().len();
        match Pin::new(&mut this.raw).poll_read(cx, buffer) {
            Poll::Ready(Ok(())) => {
                this.hmac
                    .lock()
                    .map_err(|_| {
                        io::Error::other("ShadowTLS handshake HMAC poisoned")
                    })?
                    .update(&buffer.filled()[before..]);
                Poll::Ready(Ok(()))
            }
            other => other,
        }
    }
}

#[cfg(feature = "utls")]
struct BrowserTlsRawStream {
    tls: tokio_btls::SslStream<AnyStream>,
}

#[cfg(feature = "utls")]
impl AsyncRead for BrowserTlsRawStream {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buffer: &mut tokio::io::ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        Pin::new(&mut self.get_mut().tls)
            .get_pin_mut()
            .poll_read(cx, buffer)
    }
}

#[cfg(feature = "utls")]
impl AsyncWrite for BrowserTlsRawStream {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buffer: &[u8],
    ) -> Poll<io::Result<usize>> {
        Pin::new(&mut self.get_mut().tls)
            .get_pin_mut()
            .poll_write(cx, buffer)
    }

    fn poll_flush(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<io::Result<()>> {
        Pin::new(&mut self.get_mut().tls)
            .get_pin_mut()
            .poll_flush(cx)
    }

    fn poll_shutdown(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<io::Result<()>> {
        Pin::new(&mut self.get_mut().tls)
            .get_pin_mut()
            .poll_shutdown(cx)
    }
}

impl AsyncWrite for HashedReadStream {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buffer: &[u8],
    ) -> Poll<io::Result<usize>> {
        Pin::new(&mut self.get_mut().raw).poll_write(cx, buffer)
    }

    fn poll_flush(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<io::Result<()>> {
        Pin::new(&mut self.get_mut().raw).poll_flush(cx)
    }

    fn poll_shutdown(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<io::Result<()>> {
        Pin::new(&mut self.get_mut().raw).poll_shutdown(cx)
    }
}

/// Take a slice of tls message[5..] and returns signed session id.
///
/// Only used by V3 protocol.
fn generate_session_id(hmac: &Hmac, buf: &[u8]) -> [u8; TLS_SESSION_ID_SIZE] {
    /// Note: SESSION_ID_START does not include 5 TLS_HEADER_SIZE.
    const SESSION_ID_START: usize = 1 + 3 + 2 + TLS_RANDOM_SIZE + 1;

    if buf.len() < SESSION_ID_START + TLS_SESSION_ID_SIZE {
        tracing::warn!("unexpected client hello length");
        return [0; TLS_SESSION_ID_SIZE];
    }

    let mut session_id = [0; TLS_SESSION_ID_SIZE];
    rand::fill(&mut session_id[..TLS_SESSION_ID_SIZE - HMAC_SIZE]);
    let mut hmac = hmac.to_owned();
    hmac.update(&buf[0..SESSION_ID_START]);
    hmac.update(&session_id);
    hmac.update(&buf[SESSION_ID_START + TLS_SESSION_ID_SIZE..]);
    let hmac_val = hmac.finalize();
    unsafe {
        copy_nonoverlapping(
            hmac_val.as_ptr(),
            session_id.as_mut_ptr().add(TLS_SESSION_ID_SIZE - HMAC_SIZE),
            HMAC_SIZE,
        )
    }
    session_id
}

/// Doing fake request.
///
/// Only used by V3 protocol.
async fn fake_request<S: AsyncRead + AsyncWrite + Unpin>(
    mut stream: TlsStream<S>,
) -> std::io::Result<()> {
    const HEADER: &[u8; 207] = b"GET / HTTP/1.1\nUser-Agent: Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/109.0.0.0 Safari/537.36\nAccept: gzip, deflate, br\nConnection: Close\nCookie: sessionid=";
    const FAKE_REQUEST_LENGTH_RANGE: (usize, usize) = (16, 64);
    let cnt = rand::rng()
        .random_range(FAKE_REQUEST_LENGTH_RANGE.0..FAKE_REQUEST_LENGTH_RANGE.1);
    let mut buffer = Vec::with_capacity(cnt + HEADER.len() + 1);

    buffer.extend_from_slice(HEADER);
    rand::distr::Alphanumeric
        .sample_iter(rand::rng())
        .take(cnt)
        .for_each(|c| buffer.push(c));
    buffer.push(b'\n');

    stream.write_all(&buffer).await?;
    let _ = stream.shutdown().await;

    // read until eof
    let mut buf = Vec::with_capacity(1024);
    let r = stream.read_to_end(&mut buf).await;
    r.map(|_| ())
}

#[cfg(all(test, feature = "utls"))]
mod tests {
    use std::sync::Arc;

    use tokio::{
        io::{AsyncReadExt, AsyncWriteExt},
        net::TcpListener,
    };
    use tokio_rustls::TlsAcceptor;

    use super::Client;
    use crate::{
        common::tls::resolve_server_cert_and_key, proxy::transport::Transport,
    };

    async fn browser_fingerprint_roundtrip(version: u8) {
        let (certificates, private_key) =
            resolve_server_cert_and_key(None, None, "shadow-tls-test").unwrap();
        let mut server_config = rustls::ServerConfig::builder_with_provider(
            rustls::crypto::aws_lc_rs::default_provider().into(),
        )
        .with_safe_default_protocol_versions()
        .unwrap()
        .with_no_client_auth()
        .with_single_cert(certificates, private_key)
        .unwrap();
        server_config.alpn_protocols = vec![b"h2".to_vec(), b"http/1.1".to_vec()];
        let acceptor = TlsAcceptor::from(Arc::new(server_config));
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let (server_ready_tx, server_ready_rx) = tokio::sync::oneshot::channel();
        let server = tokio::spawn(async move {
            let (tcp, _) = listener.accept().await.unwrap();
            let tls = acceptor.accept(tcp).await.unwrap();
            let (mut raw, _) = tls.into_inner();
            server_ready_tx.send(()).unwrap();
            if version == 1 {
                let mut request = [0u8; 4];
                raw.read_exact(&mut request).await.unwrap();
                assert_eq!(&request, b"ping");
            } else {
                let mut request = [0u8; 17];
                raw.read_exact(&mut request).await.unwrap();
                assert_eq!(&request[..5], &[0x17, 0x03, 0x03, 0, 12]);
                assert_eq!(&request[13..], b"ping");
            }
        });

        let tcp = tokio::net::TcpStream::connect(address).await.unwrap();
        let client = Client::new_with_options(
            "localhost".to_owned(),
            "shadow-secret".to_owned(),
            true,
            version,
            None,
            true,
            None,
            None,
            None,
        )
        .with_client_fingerprint(Some("chrome".to_owned()))
        .unwrap();
        let mut stream = client.proxy_stream(Box::new(tcp)).await.unwrap();
        server_ready_rx.await.unwrap();
        stream.write_all(b"ping").await.unwrap();
        server.await.unwrap();
    }

    #[tokio::test]
    async fn shadow_tls_v1_uses_real_browser_fingerprint_handshake() {
        browser_fingerprint_roundtrip(1).await;
    }

    #[tokio::test]
    async fn shadow_tls_v2_uses_real_browser_fingerprint_handshake() {
        browser_fingerprint_roundtrip(2).await;
    }
}
