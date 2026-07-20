use async_trait::async_trait;
use base64::{Engine as _, engine::general_purpose::STANDARD};
use hickory_proto::rr::{RData, RecordType, rdata::svcb::SvcParamValue};
use hickory_resolver::{
    TokioResolver,
    config::{CLOUDFLARE, ResolverConfig},
    net::runtime::TokioRuntimeProvider,
};
use serde::Serialize;
use std::{io, sync::Arc};
use tokio::sync::OnceCell;

use super::Transport;
use crate::{
    common::{
        errors::map_io_error,
        tls::{
            DefaultTlsVerifier, build_tls_client_config,
            build_tls_client_config_with_ech,
        },
    },
    proxy::AnyStream,
};

#[derive(Serialize, Clone, Default)]
pub struct TLSOptions {
    pub skip_cert_verify: bool,
    pub sni: String,
    pub alpn: Option<Vec<String>>,
    /// File path or inline PEM client certificate for mTLS.
    /// Must be set together with `tls_key`.
    pub tls_cert: Option<String>,
    /// File path or inline PEM client private key for mTLS.
    /// Must be set together with `tls_cert`.
    pub tls_key: Option<String>,
}

impl TryFrom<TLSOptions> for Client {
    type Error = io::Error;

    fn try_from(opt: TLSOptions) -> Result<Self, Self::Error> {
        Client::new(
            opt.skip_cert_verify,
            opt.sni,
            opt.alpn,
            None,
            opt.tls_cert.as_deref(),
            opt.tls_key.as_deref(),
        )
    }
}

pub struct Client {
    pub sni: String,
    pub expected_alpn: Option<String>,
    /// Cached connector built once at construction time.
    /// Sharing this across connections enables TLS session resumption
    /// (both TLS 1.2 session IDs/tickets and TLS 1.3 PSK resumption),
    /// which saves a full round-trip on every subsequent connection to the
    /// same proxy server.
    connector: Connector,
}

#[derive(Clone, Debug, Default)]
pub struct EchOptions {
    /// Base64-encoded binary ECHConfigList. When omitted, the list is read
    /// from the HTTPS DNS record for `query_server_name` (or the TLS SNI).
    pub config: Option<String>,
    pub query_server_name: Option<String>,
}

pub(super) fn build_alpn_wire(protocols: &[Vec<u8>]) -> io::Result<Vec<u8>> {
    let mut wire = Vec::new();
    for protocol in protocols {
        let length = u8::try_from(protocol.len()).map_err(|_| {
            io::Error::new(
                io::ErrorKind::InvalidInput,
                "TLS ALPN protocol name exceeds 255 bytes",
            )
        })?;
        wire.push(length);
        wire.extend_from_slice(protocol);
    }
    Ok(wire)
}

struct DeferredEchConnector {
    connector: OnceCell<tokio_rustls::TlsConnector>,
    verifier: Arc<DefaultTlsVerifier>,
    tls_cert: Option<String>,
    tls_key: Option<String>,
    query_server_name: String,
    alpn: Vec<Vec<u8>>,
}

enum Connector {
    Ready(tokio_rustls::TlsConnector),
    DeferredEch(DeferredEchConnector),
}

impl Client {
    #[allow(clippy::too_many_arguments)]
    pub fn new_mihomo(
        skip_cert_verify: bool,
        sni: String,
        alpn: Option<Vec<String>>,
        expected_alpn: Option<String>,
        certificate_fingerprint: Option<String>,
        client_fingerprint: Option<&str>,
        ech: Option<EchOptions>,
        tls_cert: Option<&str>,
        tls_key: Option<&str>,
    ) -> io::Result<Box<dyn Transport>> {
        if let Some(client_fingerprint) = client_fingerprint
            .map(str::trim)
            .filter(|value| !value.is_empty() && !value.eq_ignore_ascii_case("none"))
        {
            #[cfg(feature = "utls")]
            {
                return Ok(Box::new(super::browser_tls::Client::new(
                    client_fingerprint,
                    skip_cert_verify,
                    sni,
                    alpn,
                    expected_alpn,
                    certificate_fingerprint,
                    ech,
                    tls_cert,
                    tls_key,
                )?));
            }
            #[cfg(not(feature = "utls"))]
            {
                return Err(io::Error::new(
                    io::ErrorKind::Unsupported,
                    format!(
                        "client-fingerprint `{client_fingerprint}` requires the \
                         clash-lib `utls` feature"
                    ),
                ));
            }
        }

        Ok(Box::new(Self::new_with_ech(
            skip_cert_verify,
            sni,
            alpn,
            expected_alpn,
            certificate_fingerprint,
            ech,
            tls_cert,
            tls_key,
        )?))
    }

    /// Create a new TLS client.
    ///
    /// When `tls_cert` and `tls_key` are both `Some`, mutual TLS (mTLS) is
    /// enabled: the client will present the given certificate to the server.
    /// Both must be either `None` (no client auth) or `Some` (mTLS); mixing
    /// them returns an error.
    pub fn new(
        skip_cert_verify: bool,
        sni: String,
        alpn: Option<Vec<String>>,
        expected_alpn: Option<String>,
        tls_cert: Option<&str>,
        tls_key: Option<&str>,
    ) -> io::Result<Self> {
        Self::new_with_fingerprint(
            skip_cert_verify,
            sni,
            alpn,
            expected_alpn,
            None,
            tls_cert,
            tls_key,
        )
    }

    pub fn new_with_fingerprint(
        skip_cert_verify: bool,
        sni: String,
        alpn: Option<Vec<String>>,
        expected_alpn: Option<String>,
        fingerprint: Option<String>,
        tls_cert: Option<&str>,
        tls_key: Option<&str>,
    ) -> io::Result<Self> {
        Self::new_with_ech(
            skip_cert_verify,
            sni,
            alpn,
            expected_alpn,
            fingerprint,
            None,
            tls_cert,
            tls_key,
        )
    }

    #[allow(clippy::too_many_arguments)]
    pub fn new_with_ech(
        skip_cert_verify: bool,
        sni: String,
        alpn: Option<Vec<String>>,
        expected_alpn: Option<String>,
        fingerprint: Option<String>,
        ech: Option<EchOptions>,
        tls_cert: Option<&str>,
        tls_key: Option<&str>,
    ) -> io::Result<Self> {
        let verifier =
            Arc::new(DefaultTlsVerifier::try_new(fingerprint, skip_cert_verify)?);
        let alpn = alpn
            .unwrap_or_default()
            .into_iter()
            .map(|x| x.as_bytes().to_vec())
            .collect::<Vec<_>>();

        let connector = match ech {
            Some(ech) => match ech.config.as_deref() {
                Some(config) if !config.trim().is_empty() => {
                    let list = STANDARD.decode(config.trim()).map_err(|error| {
                        io::Error::new(
                            io::ErrorKind::InvalidInput,
                            format!("base64 decode ECH config failed: {error}"),
                        )
                    })?;
                    Connector::Ready(build_connector(
                        verifier,
                        tls_cert,
                        tls_key,
                        &alpn,
                        Some(list),
                    )?)
                }
                _ => Connector::DeferredEch(DeferredEchConnector {
                    connector: OnceCell::new(),
                    verifier,
                    tls_cert: tls_cert.map(ToOwned::to_owned),
                    tls_key: tls_key.map(ToOwned::to_owned),
                    query_server_name: ech
                        .query_server_name
                        .filter(|name| !name.trim().is_empty())
                        .unwrap_or_else(|| sni.clone()),
                    alpn,
                }),
            },
            None => Connector::Ready(build_connector(
                verifier, tls_cert, tls_key, &alpn, None,
            )?),
        };

        Ok(Self {
            sni,
            expected_alpn,
            connector,
        })
    }
}

fn build_connector(
    verifier: Arc<DefaultTlsVerifier>,
    tls_cert: Option<&str>,
    tls_key: Option<&str>,
    alpn: &[Vec<u8>],
    ech_config_list: Option<Vec<u8>>,
) -> io::Result<tokio_rustls::TlsConnector> {
    let mut tls_config = match ech_config_list {
        Some(list) => {
            build_tls_client_config_with_ech(verifier, tls_cert, tls_key, list)?
        }
        None => build_tls_client_config(verifier, tls_cert, tls_key)?,
    };
    tls_config.alpn_protocols = alpn.to_vec();
    if std::env::var("SSLKEYLOGFILE").is_ok() {
        tls_config.key_log = Arc::new(rustls::KeyLogFile::new());
    }
    Ok(tokio_rustls::TlsConnector::from(Arc::new(tls_config)))
}

pub(crate) async fn resolve_ech_config_list(name: &str) -> io::Result<Vec<u8>> {
    let builder = TokioResolver::builder_tokio().unwrap_or_else(|_| {
        TokioResolver::builder_with_config(
            ResolverConfig::udp_and_tcp(&CLOUDFLARE),
            TokioRuntimeProvider::default(),
        )
    });
    let resolver = builder.build().map_err(map_io_error)?;
    let lookup = resolver
        .lookup(name, RecordType::HTTPS)
        .await
        .map_err(map_io_error)?;

    lookup
        .answers()
        .iter()
        .filter_map(|record| match &record.data {
            RData::HTTPS(https) => Some(&https.svc_params),
            _ => None,
        })
        .flatten()
        .find_map(|(_, value)| match value {
            SvcParamValue::EchConfigList(list) => Some(list.0.clone()),
            _ => None,
        })
        .ok_or_else(|| {
            io::Error::new(
                io::ErrorKind::NotFound,
                format!("HTTPS DNS record for {name} contains no ECH config"),
            )
        })
}

pub(crate) async fn build_rustls_client_config_with_optional_ech(
    verifier: Arc<dyn rustls::client::danger::ServerCertVerifier>,
    tls_cert: Option<&str>,
    tls_key: Option<&str>,
    ech: Option<&EchOptions>,
    ech_query_name: &str,
) -> io::Result<rustls::ClientConfig> {
    let Some(ech) = ech else {
        return build_tls_client_config(verifier, tls_cert, tls_key);
    };
    let list = match ech.config.as_deref() {
        Some(config) if !config.trim().is_empty() => {
            STANDARD.decode(config.trim()).map_err(|error| {
                io::Error::new(
                    io::ErrorKind::InvalidInput,
                    format!("base64 decode ECH config failed: {error}"),
                )
            })?
        }
        _ => {
            let query_name = ech
                .query_server_name
                .as_deref()
                .filter(|name| !name.trim().is_empty())
                .unwrap_or(ech_query_name);
            resolve_ech_config_list(query_name).await?
        }
    };
    build_tls_client_config_with_ech(verifier, tls_cert, tls_key, list)
}

#[async_trait]
impl Transport for Client {
    async fn proxy_stream(&self, stream: AnyStream) -> io::Result<AnyStream> {
        let dns_name =
            rustls::pki_types::ServerName::try_from(self.sni.as_str().to_owned())
                .map_err(map_io_error)?;

        let connector = match &self.connector {
            Connector::Ready(connector) => connector,
            Connector::DeferredEch(deferred) => {
                deferred
                    .connector
                    .get_or_try_init(|| async {
                        let list =
                            resolve_ech_config_list(&deferred.query_server_name)
                                .await?;
                        build_connector(
                            deferred.verifier.clone(),
                            deferred.tls_cert.as_deref(),
                            deferred.tls_key.as_deref(),
                            &deferred.alpn,
                            Some(list),
                        )
                    })
                    .await?
            }
        };

        let c = connector.connect(dns_name, stream).await.and_then(|x| {
            if let Some(expected_alpn) = self.expected_alpn.as_ref()
                && x.get_ref().1.alpn_protocol() != Some(expected_alpn.as_bytes())
            {
                return Err(io::Error::other(format!(
                    "unexpected alpn protocol: {:?}, expected: {:?}",
                    x.get_ref().1.alpn_protocol(),
                    expected_alpn
                )));
            }

            Ok(x)
        });
        c.map(|x| Box::new(x) as _)
    }
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;

    use quinn::crypto::rustls::QuicClientConfig;

    use super::{
        Client, Connector, EchOptions, build_rustls_client_config_with_optional_ech,
    };
    use crate::common::tls::DefaultTlsVerifier;

    const ECH_CONFIG: &str = "AEn+DQBFKwAgACABWIHUGj4u+PIggYXcR5JF0gYk3dCRioBW8uJq9H4mKAAIAAEAAQABAANAEnB1YmxpYy50bHMtZWNoLmRldgAA";

    #[test]
    fn accepts_mihomo_base64_ech_config() {
        crate::setup_default_crypto_provider();
        let client = Client::new_with_ech(
            true,
            "tls-ech.dev".to_owned(),
            Some(vec!["h2".to_owned()]),
            None,
            None,
            Some(EchOptions {
                config: Some(ECH_CONFIG.to_owned()),
                query_server_name: None,
            }),
            None,
            None,
        )
        .unwrap();

        assert!(matches!(client.connector, Connector::Ready(_)));
    }

    #[test]
    fn rejects_malformed_mihomo_ech_config() {
        crate::setup_default_crypto_provider();
        let error = match Client::new_with_ech(
            true,
            "example.com".to_owned(),
            None,
            None,
            None,
            Some(EchOptions {
                config: Some("not-base64".to_owned()),
                query_server_name: None,
            }),
            None,
            None,
        ) {
            Ok(_) => panic!("malformed ECH config must fail"),
            Err(error) => error,
        };

        assert!(error.to_string().contains("base64 decode ECH config"));
    }

    #[test]
    fn defers_dns_ech_lookup_until_connection() {
        crate::setup_default_crypto_provider();
        let client = Client::new_with_ech(
            true,
            "inner.example".to_owned(),
            None,
            None,
            None,
            Some(EchOptions {
                config: None,
                query_server_name: Some("ech.example".to_owned()),
            }),
            None,
            None,
        )
        .unwrap();

        let Connector::DeferredEch(deferred) = client.connector else {
            panic!("ECH without an explicit config must use DNS discovery");
        };
        assert_eq!(deferred.query_server_name, "ech.example");
    }

    #[tokio::test]
    async fn explicit_ech_config_is_compatible_with_quic() {
        crate::setup_default_crypto_provider();
        let verifier = Arc::new(DefaultTlsVerifier::new(None, true));
        let mut config = build_rustls_client_config_with_optional_ech(
            verifier,
            None,
            None,
            Some(&EchOptions {
                config: Some(ECH_CONFIG.to_owned()),
                query_server_name: None,
            }),
            "tls-ech.dev",
        )
        .await
        .unwrap();
        config.alpn_protocols = vec![b"h3".to_vec()];
        assert!(QuicClientConfig::try_from(config).is_ok());
    }
}
