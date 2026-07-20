use std::{
    fs, io,
    sync::{Arc, LazyLock, Mutex},
};

use async_trait::async_trait;
use base64::{Engine as _, engine::general_purpose::STANDARD};
use btls::{
    pkey::PKey,
    ssl::{
        CertificateCompressionAlgorithm, SslConnector, SslMethod, SslOptions,
        SslVerifyMode, SslVersion,
    },
    x509::{
        X509,
        store::{X509Store, X509StoreBuilder},
    },
};
use tokio::sync::OnceCell;
use tokio_btls::SslStream;
use wreq::{
    IntoEmulation,
    tls::{
        TlsOptions, TlsVersion,
        compress::{CertificateCompressor, Codec},
    },
};
use wreq_util::Profile;

use super::{
    Transport,
    tls::{EchOptions, resolve_ech_config_list},
};
use crate::{
    common::{
        tls::normalize_certificate_fingerprint,
        utils::{encode_hex, sha256},
    },
    proxy::{AnyStream, transport::tls::build_alpn_wire},
};

static ROOT_STORE: LazyLock<X509Store> = LazyLock::new(|| {
    let mut store = X509StoreBuilder::new()
        .expect("BoringSSL root certificate store must initialize");
    for certificate in webpki_root_certs::TLS_SERVER_ROOT_CERTS {
        let certificate = X509::from_der(certificate.as_ref())
            .expect("bundled WebPKI root must contain valid DER");
        store
            .add_cert(certificate)
            .expect("bundled WebPKI root must be accepted by BoringSSL");
    }
    store.build()
});

enum EchSource {
    Fixed(Vec<u8>),
    Dns {
        name: String,
        value: OnceCell<Vec<u8>>,
    },
}

pub struct Client {
    sni: String,
    expected_alpn: Option<String>,
    alpn: Vec<Vec<u8>>,
    connector: SslConnector,
    options: TlsOptions,
    ech: Option<EchSource>,
    certificate_fingerprint: Option<String>,
}

impl Client {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        client_fingerprint: &str,
        skip_cert_verify: bool,
        sni: String,
        alpn: Option<Vec<String>>,
        expected_alpn: Option<String>,
        certificate_fingerprint: Option<String>,
        ech: Option<EchOptions>,
        tls_cert: Option<&str>,
        tls_key: Option<&str>,
    ) -> io::Result<Self> {
        Self::new_inner(
            client_fingerprint,
            skip_cert_verify,
            sni,
            alpn,
            expected_alpn,
            certificate_fingerprint,
            ech,
            tls_cert,
            tls_key,
            false,
        )
    }

    #[allow(clippy::too_many_arguments)]
    pub(super) fn new_shadow_tls(
        client_fingerprint: &str,
        skip_cert_verify: bool,
        sni: String,
        alpn: Option<Vec<String>>,
        certificate_fingerprint: Option<String>,
        tls_cert: Option<&str>,
        tls_key: Option<&str>,
        tls12_only: bool,
    ) -> io::Result<Self> {
        Self::new_inner(
            client_fingerprint,
            skip_cert_verify,
            sni,
            alpn,
            None,
            certificate_fingerprint,
            None,
            tls_cert,
            tls_key,
            tls12_only,
        )
    }

    #[allow(clippy::too_many_arguments)]
    fn new_inner(
        client_fingerprint: &str,
        skip_cert_verify: bool,
        sni: String,
        alpn: Option<Vec<String>>,
        expected_alpn: Option<String>,
        certificate_fingerprint: Option<String>,
        ech: Option<EchOptions>,
        tls_cert: Option<&str>,
        tls_key: Option<&str>,
        tls12_only: bool,
    ) -> io::Result<Self> {
        let profile = profile_for(client_fingerprint)?;
        let emulation = profile.into_emulation();
        let options = emulation.tls_options.ok_or_else(|| {
            io::Error::new(
                io::ErrorKind::InvalidInput,
                format!("TLS profile `{client_fingerprint}` has no TLS options"),
            )
        })?;
        let certificate_fingerprint = certificate_fingerprint
            .map(|value| normalize_certificate_fingerprint(&value))
            .transpose()?;
        let connector = build_connector(
            &options,
            skip_cert_verify || certificate_fingerprint.is_some(),
            tls_cert,
            tls_key,
            tls12_only,
        )?;
        let ech = ech
            .map(|options| {
                if let Some(config) = options
                    .config
                    .as_deref()
                    .filter(|config| !config.trim().is_empty())
                {
                    STANDARD
                        .decode(config.trim())
                        .map(EchSource::Fixed)
                        .map_err(|error| {
                            io::Error::new(
                                io::ErrorKind::InvalidInput,
                                format!("base64 decode ECH config failed: {error}"),
                            )
                        })
                } else {
                    Ok(EchSource::Dns {
                        name: options
                            .query_server_name
                            .filter(|name| !name.trim().is_empty())
                            .unwrap_or_else(|| sni.clone()),
                        value: OnceCell::new(),
                    })
                }
            })
            .transpose()?;

        Ok(Self {
            sni,
            expected_alpn,
            alpn: alpn
                .unwrap_or_default()
                .into_iter()
                .map(String::into_bytes)
                .collect(),
            connector,
            options,
            ech,
            certificate_fingerprint,
        })
    }

    async fn ech_config_list(&self) -> io::Result<Option<&[u8]>> {
        match self.ech.as_ref() {
            Some(EchSource::Fixed(value)) => Ok(Some(value)),
            Some(EchSource::Dns { name, value }) => value
                .get_or_try_init(|| resolve_ech_config_list(name))
                .await
                .map(|value| Some(value.as_slice())),
            None => Ok(None),
        }
    }

    pub(super) async fn connect_stream(
        &self,
        stream: AnyStream,
    ) -> io::Result<SslStream<AnyStream>> {
        let mut config = self.connector.configure().map_err(io::Error::other)?;
        config.set_use_server_name_indication(true);
        config.set_verify_hostname(self.certificate_fingerprint.is_none());
        let mut ssl = config.into_ssl(&self.sni).map_err(io::Error::other)?;
        if !self.alpn.is_empty() {
            ssl.set_alpn_protos(&build_alpn_wire(&self.alpn)?)
                .map_err(io::Error::other)?;
        }
        ssl.set_enable_ech_grease(self.options.enable_ech_grease);
        if let Some(key_shares) = self.options.key_shares.as_deref() {
            ssl.set_client_key_shares(key_shares)
                .map_err(io::Error::other)?;
        }
        if self.options.alps_protocols.is_some() {
            for protocol in &self.alpn {
                ssl.add_application_settings(protocol)
                    .map_err(io::Error::other)?;
            }
            ssl.set_alps_use_new_codepoint(self.options.alps_use_new_codepoint);
        }
        if self.options.random_aes_hw_override {
            ssl.set_aes_hw_override(rand::random());
        }
        if let Some(ech_config_list) = self.ech_config_list().await? {
            ssl.set_ech_config_list(ech_config_list)
                .map_err(io::Error::other)?;
        }

        let mut stream = SslStream::new(ssl, stream).map_err(io::Error::other)?;
        std::pin::Pin::new(&mut stream)
            .connect()
            .await
            .map_err(io::Error::other)?;

        if let Some(fingerprint) = self.certificate_fingerprint.as_deref()
            && !certificate_fingerprint_matches(&stream, fingerprint)?
        {
            return Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                "certificate fingerprints do not match",
            ));
        }
        if let Some(expected_alpn) = self.expected_alpn.as_deref()
            && stream.ssl().selected_alpn_protocol()
                != Some(expected_alpn.as_bytes())
        {
            return Err(io::Error::other(format!(
                "unexpected alpn protocol: {:?}, expected: {expected_alpn:?}",
                stream.ssl().selected_alpn_protocol(),
            )));
        }

        Ok(stream)
    }
}

fn profile_for(value: &str) -> io::Result<Profile> {
    let normalized = value.trim().to_ascii_lowercase();
    let profile = match normalized.as_str() {
        "chrome" | "360" | "qq" => Profile::Chrome149,
        "firefox" => Profile::Firefox151,
        "safari" => Profile::Safari26_4,
        "ios" => Profile::SafariIos26_2,
        "android" => Profile::OkHttp5,
        "edge" => Profile::Edge148,
        "random" | "randomized" => match rand::random_range(0..6) {
            0 => Profile::Chrome149,
            1 => Profile::Firefox151,
            2 => Profile::Safari26_4,
            3 => Profile::SafariIos26_2,
            4 => Profile::OkHttp5,
            _ => Profile::Edge148,
        },
        _ => {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                format!(
                    "unsupported client-fingerprint `{value}`; expected chrome, \
                     firefox, safari, ios, android, edge, 360, qq, random, \
                     randomized or none"
                ),
            ));
        }
    };
    Ok(profile)
}

fn build_connector(
    options: &TlsOptions,
    skip_cert_verify: bool,
    tls_cert: Option<&str>,
    tls_key: Option<&str>,
    tls12_only: bool,
) -> io::Result<SslConnector> {
    let mut builder =
        SslConnector::bare_builder(SslMethod::tls()).map_err(io::Error::other)?;
    builder.set_cert_store_ref(&ROOT_STORE);
    builder.set_verify(if skip_cert_verify {
        SslVerifyMode::NONE
    } else {
        SslVerifyMode::PEER
    });

    if let Some(version) = options.min_tls_version {
        builder
            .set_min_proto_version(Some(ssl_version(version)?))
            .map_err(io::Error::other)?;
    }
    if tls12_only {
        builder
            .set_max_proto_version(Some(SslVersion::TLS1_2))
            .map_err(io::Error::other)?;
    } else if let Some(version) = options.max_tls_version {
        builder
            .set_max_proto_version(Some(ssl_version(version)?))
            .map_err(io::Error::other)?;
    }

    if !options.session_ticket {
        builder.set_options(SslOptions::NO_TICKET);
    }
    if !options.psk_dhe_ke {
        builder.set_options(SslOptions::NO_PSK_DHE_KE);
    }
    if !options.renegotiation {
        builder.set_options(SslOptions::NO_RENEGOTIATION);
    }
    if options.enable_ocsp_stapling {
        builder.enable_ocsp_stapling();
    }
    if options.enable_signed_cert_timestamps {
        builder.enable_signed_cert_timestamps();
    }
    if let Some(value) = options.grease_enabled {
        builder.set_grease_enabled(value);
    }
    if let Some(value) = options.permute_extensions {
        builder.set_permute_extensions(value);
    }
    if let Some(value) = options.curves_list.as_deref() {
        builder.set_curves_list(value).map_err(io::Error::other)?;
    }
    if let Some(value) = options.sigalgs_list.as_deref() {
        builder.set_sigalgs_list(value).map_err(io::Error::other)?;
    }
    if let Some(value) = options.preserve_tls13_cipher_list {
        builder.set_preserve_tls13_cipher_list(value);
    }
    if let Some(value) = options.cipher_list.as_deref() {
        builder.set_cipher_list(value).map_err(io::Error::other)?;
    }
    if let Some(value) = options.delegated_credentials.as_deref() {
        builder
            .set_delegated_credentials(value)
            .map_err(io::Error::other)?;
    }
    if let Some(value) = options.record_size_limit {
        builder.set_record_size_limit(value);
    }
    if let Some(value) = options.aes_hw_override {
        builder.set_aes_hw_override(value);
    }
    if let Some(value) = options.extension_permutation.as_deref() {
        builder
            .set_extension_permutation(value)
            .map_err(io::Error::other)?;
    }
    if let Some(compressors) = options.certificate_compressors.as_deref() {
        for compressor in compressors {
            register_certificate_compressor(*compressor, &mut builder)?;
        }
    }

    configure_client_identity(&mut builder, tls_cert, tls_key)?;
    configure_key_log(&mut builder)?;
    Ok(builder.build())
}

fn ssl_version(version: TlsVersion) -> io::Result<SslVersion> {
    match version {
        TlsVersion::TLS_1_0 => Ok(SslVersion::TLS1),
        TlsVersion::TLS_1_1 => Ok(SslVersion::TLS1_1),
        TlsVersion::TLS_1_2 => Ok(SslVersion::TLS1_2),
        TlsVersion::TLS_1_3 => Ok(SslVersion::TLS1_3),
        _ => Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            format!("unsupported TLS version in browser profile: {version:?}"),
        )),
    }
}

struct DynamicZlibCompressor {
    compress: Codec,
    decompress: Codec,
}

struct DynamicBrotliCompressor {
    compress: Codec,
    decompress: Codec,
}

struct DynamicZstdCompressor {
    compress: Codec,
    decompress: Codec,
}

fn run_codec(
    codec: &Codec,
    input: &[u8],
    output: &mut dyn io::Write,
) -> io::Result<()> {
    match codec {
        Codec::Pointer(callback) => callback(input, output),
        Codec::Dynamic(callback) => callback(input, output),
    }
}

macro_rules! impl_dynamic_compressor {
    ($type:ty, $algorithm:expr) => {
        impl btls::ssl::CertificateCompressor for $type {
            const ALGORITHM: CertificateCompressionAlgorithm = $algorithm;
            const CAN_COMPRESS: bool = true;
            const CAN_DECOMPRESS: bool = true;

            fn compress<W>(&self, input: &[u8], output: &mut W) -> io::Result<()>
            where
                W: io::Write,
            {
                run_codec(&self.compress, input, output)
            }

            fn decompress<W>(&self, input: &[u8], output: &mut W) -> io::Result<()>
            where
                W: io::Write,
            {
                run_codec(&self.decompress, input, output)
            }
        }
    };
}

impl_dynamic_compressor!(
    DynamicZlibCompressor,
    CertificateCompressionAlgorithm::ZLIB
);
impl_dynamic_compressor!(
    DynamicBrotliCompressor,
    CertificateCompressionAlgorithm::BROTLI
);
impl_dynamic_compressor!(
    DynamicZstdCompressor,
    CertificateCompressionAlgorithm::ZSTD
);

fn register_certificate_compressor(
    compressor: &'static dyn CertificateCompressor,
    builder: &mut btls::ssl::SslConnectorBuilder,
) -> io::Result<()> {
    let compress = compressor.compress();
    let decompress = compressor.decompress();
    let result = match compressor.algorithm() {
        CertificateCompressionAlgorithm::ZLIB => builder
            .add_certificate_compression_algorithm(DynamicZlibCompressor {
                compress,
                decompress,
            }),
        CertificateCompressionAlgorithm::BROTLI => builder
            .add_certificate_compression_algorithm(DynamicBrotliCompressor {
                compress,
                decompress,
            }),
        CertificateCompressionAlgorithm::ZSTD => builder
            .add_certificate_compression_algorithm(DynamicZstdCompressor {
                compress,
                decompress,
            }),
        algorithm => {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                format!(
                    "unsupported certificate compression algorithm: {algorithm:?}"
                ),
            ));
        }
    };
    result.map_err(io::Error::other)
}

fn read_pem_input(value: &str) -> io::Result<Vec<u8>> {
    if value.contains("-----BEGIN") {
        Ok(value.as_bytes().to_vec())
    } else {
        fs::read(value).map_err(|error| {
            io::Error::new(
                error.kind(),
                format!("failed to read TLS credential `{value}`: {error}"),
            )
        })
    }
}

fn configure_client_identity(
    builder: &mut btls::ssl::SslConnectorBuilder,
    tls_cert: Option<&str>,
    tls_key: Option<&str>,
) -> io::Result<()> {
    match (tls_cert, tls_key) {
        (None, None) => Ok(()),
        (Some(cert), Some(key)) => {
            let mut certificates = X509::stack_from_pem(&read_pem_input(cert)?)
                .map_err(io::Error::other)?
                .into_iter();
            let leaf = certificates.next().ok_or_else(|| {
                io::Error::new(
                    io::ErrorKind::InvalidInput,
                    "no valid certificates found in PEM",
                )
            })?;
            let private_key = PKey::private_key_from_pem(&read_pem_input(key)?)
                .map_err(io::Error::other)?;
            builder.set_certificate(&leaf).map_err(io::Error::other)?;
            builder
                .set_private_key(&private_key)
                .map_err(io::Error::other)?;
            for certificate in certificates {
                builder
                    .add_extra_chain_cert(certificate)
                    .map_err(io::Error::other)?;
            }
            builder.check_private_key().map_err(io::Error::other)
        }
        _ => Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "tls-cert and tls-key must both be set or both omitted",
        )),
    }
}

fn configure_key_log(
    builder: &mut btls::ssl::SslConnectorBuilder,
) -> io::Result<()> {
    let Ok(path) = std::env::var("SSLKEYLOGFILE") else {
        return Ok(());
    };
    let file = fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(path)?;
    let file = Arc::new(Mutex::new(file));
    builder.set_keylog_callback(move |_, line| {
        use std::io::Write;
        if let Ok(mut file) = file.lock() {
            let _ = writeln!(file, "{line}");
        }
    });
    Ok(())
}

fn certificate_fingerprint_matches(
    stream: &SslStream<AnyStream>,
    fingerprint: &str,
) -> io::Result<bool> {
    if let Some(chain) = stream.ssl().peer_cert_chain() {
        for certificate in chain {
            let der = certificate.to_der().map_err(io::Error::other)?;
            if encode_hex(&sha256(&der)) == fingerprint {
                return Ok(true);
            }
        }
    }
    if let Some(certificate) = stream.ssl().peer_certificate() {
        let der = certificate.to_der().map_err(io::Error::other)?;
        return Ok(encode_hex(&sha256(&der)) == fingerprint);
    }
    Ok(false)
}

#[async_trait]
impl Transport for Client {
    async fn proxy_stream(&self, stream: AnyStream) -> io::Result<AnyStream> {
        Ok(Box::new(self.connect_stream(stream).await?))
    }
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;

    use tokio::{
        io::{AsyncReadExt, AsyncWriteExt},
        net::TcpListener,
    };
    use tokio_rustls::TlsAcceptor;

    use super::{Client, profile_for};
    use crate::{
        common::tls::resolve_server_cert_and_key, proxy::transport::Transport,
    };

    #[test]
    fn accepts_all_mihomo_client_fingerprint_names() {
        for name in [
            "chrome",
            "firefox",
            "safari",
            "ios",
            "android",
            "edge",
            "360",
            "qq",
            "random",
            "randomized",
        ] {
            assert!(profile_for(name).is_ok(), "{name}");
        }
    }

    #[test]
    fn rejects_unknown_client_fingerprint() {
        assert!(profile_for("netscape").is_err());
    }

    #[tokio::test]
    async fn chrome_profile_completes_real_tls_handshake() {
        let (certificates, private_key) =
            resolve_server_cert_and_key(None, None, "browser-tls-test").unwrap();
        let mut server_config = rustls::ServerConfig::builder_with_provider(
            rustls::crypto::aws_lc_rs::default_provider().into(),
        )
        .with_safe_default_protocol_versions()
        .unwrap()
        .with_no_client_auth()
        .with_single_cert(certificates, private_key)
        .unwrap();
        server_config.alpn_protocols = vec![b"http/1.1".to_vec()];
        let acceptor = TlsAcceptor::from(Arc::new(server_config));
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let server = tokio::spawn(async move {
            let (stream, _) = listener.accept().await.unwrap();
            let mut stream = acceptor.accept(stream).await.unwrap();
            let mut request = [0u8; 4];
            stream.read_exact(&mut request).await.unwrap();
            assert_eq!(&request, b"ping");
            stream.write_all(b"pong").await.unwrap();
        });

        let tcp = tokio::net::TcpStream::connect(address).await.unwrap();
        let client = Client::new(
            "chrome",
            true,
            "localhost".to_string(),
            Some(vec!["http/1.1".to_string()]),
            Some("http/1.1".to_string()),
            None,
            None,
            None,
            None,
        )
        .unwrap();
        let mut stream = client.proxy_stream(Box::new(tcp)).await.unwrap();
        stream.write_all(b"ping").await.unwrap();
        let mut response = [0u8; 4];
        stream.read_exact(&mut response).await.unwrap();
        assert_eq!(&response, b"pong");
        server.await.unwrap();
    }
}
