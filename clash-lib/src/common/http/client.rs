use crate::{
    app::dns::{RuleDispatch, ThreadSafeDNSResolver},
    common::tls::GLOBAL_ROOT_STORE,
    config::internal::proxy::PROXY_DIRECT,
    proxy::{AnyOutboundHandler, direct, utils::OutboundHandlerRegistry},
    session::Session,
};
use futures::FutureExt;
use hyper_util::rt::TokioIo;
use std::sync::Arc;
use tracing::{trace, warn};

#[derive(Clone, Debug)]
pub(crate) struct ClashHTTPClientExt {
    pub(crate) outbound: Option<String>,
}

/// A simple HTTP client that can be used to make HTTP requests.
/// Not performant for lack of connection pooling, but useful for simple tasks.
#[derive(Clone)]
pub struct HttpClient {
    dns_resolver: ThreadSafeDNSResolver,
    outbounds: Option<OutboundHandlerRegistry>,
    rule_dispatch: Option<Arc<RuleDispatch>>,
    tls_config: Arc<rustls::ClientConfig>,
    timeout: tokio::time::Duration,
}

impl HttpClient {
    pub fn new(
        dns_resolver: ThreadSafeDNSResolver,
        bootstrap_outbounds: Option<OutboundHandlerRegistry>,
        timeout: Option<tokio::time::Duration>,
    ) -> std::io::Result<HttpClient> {
        let mut tls_config = rustls::ClientConfig::builder()
            .with_root_certificates(GLOBAL_ROOT_STORE.clone())
            .with_no_client_auth();
        if std::env::var("SSLKEYLOGFILE").is_ok() {
            tls_config.key_log = Arc::new(rustls::KeyLogFile::new());
        }

        Ok(HttpClient {
            dns_resolver,
            outbounds: bootstrap_outbounds,
            rule_dispatch: None,
            tls_config: Arc::new(tls_config),
            timeout: timeout.unwrap_or(tokio::time::Duration::from_secs(10)),
        })
    }

    pub fn with_rule_dispatch(mut self, rule_dispatch: Arc<RuleDispatch>) -> Self {
        self.rule_dispatch = Some(rule_dispatch);
        self
    }

    pub async fn request<T>(
        &self,
        mut req: http::Request<T>,
    ) -> Result<http::Response<hyper::body::Incoming>, std::io::Error>
    where
        T: hyper::body::Body + Send + 'static,
        <T as hyper::body::Body>::Data: Send,
        <T as hyper::body::Body>::Error: std::error::Error + Send + Sync,
    {
        let uri = req.uri().clone();

        let host = uri
            .host()
            .ok_or(std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                format!("uri must have a host: {uri}"),
            ))?
            .to_owned();
        let port = uri.port_u16().unwrap_or(match uri.scheme_str() {
            None => 80,
            Some(s) => match s {
                "http" => 80,
                "https" => 443,
                _ => {
                    return Err(std::io::Error::new(
                        std::io::ErrorKind::InvalidInput,
                        format!("unsupported scheme: {s}"),
                    ));
                }
            },
        });

        if req.headers_mut().get(http::header::HOST).is_none() {
            req.headers_mut().insert(
                http::header::HOST,
                uri.host()
                    .ok_or(std::io::Error::new(
                        std::io::ErrorKind::InvalidInput,
                        "uri must have a host",
                    ))?
                    .parse()
                    .expect("must parse host header"),
            );
        }
        *req.uri_mut() = uri
            .path_and_query()
            .map(|value| value.as_str())
            .unwrap_or("/")
            .parse()
            .expect("path and query must be a valid request target");

        let outbound_name = req
            .extensions()
            .get::<ClashHTTPClientExt>()
            .and_then(|ext| ext.outbound.clone());
        let make_direct =
            || Arc::new(direct::Handler::new(PROXY_DIRECT)) as AnyOutboundHandler;
        let mut sess = Session {
            network: crate::session::Network::Tcp,
            typ: crate::session::Type::Ignore,
            destination: crate::session::SocksAddr::Domain(host.clone(), port),
            ..Default::default()
        };
        let outbound: AnyOutboundHandler = if let Some(name) = outbound_name {
            if let Some(registry) = &self.outbounds {
                registry
                    .read()
                    .await
                    .get(&name)
                    .cloned()
                    .unwrap_or_else(make_direct)
            } else if let Some(rule_dispatch) = &self.rule_dispatch
                && let Some(manager) = rule_dispatch.outbound_manager.get()
            {
                manager
                    .get_outbound(&name)
                    .await
                    .unwrap_or_else(make_direct)
            } else {
                make_direct()
            }
        } else if let Some(rule_dispatch) = &self.rule_dispatch
            && let (Some(router), Some(manager)) = (
                rule_dispatch.router.get(),
                rule_dispatch.outbound_manager.get(),
            )
        {
            let (name, _) = router.match_route(&mut sess).await;
            manager.get_outbound(name).await.unwrap_or_else(make_direct)
        } else {
            make_direct()
        };

        trace!(outbound = %outbound.name(), "using outbound");
        let stream = tokio::time::timeout(
            self.timeout,
            outbound.connect_stream(&sess, self.dns_resolver.clone()),
        )
        .await?
        .inspect_err(|e| {
            warn!(outbound = outbound.name(), err = ?e, "download via proxy");
        })?;

        let resp = match uri.scheme() {
            Some(scheme) if scheme == &http::uri::Scheme::HTTP => {
                let io = TokioIo::new(stream);
                let (mut sender, conn) = hyper::client::conn::http1::handshake(io)
                    .await
                    .map_err(std::io::Error::other)?;

                tokio::task::spawn(async move {
                    if let Err(err) = conn.await {
                        warn!("HTTP connection error: {}", err);
                    }
                });

                sender.send_request(req).boxed()
            }
            Some(scheme) if scheme == &http::uri::Scheme::HTTPS => {
                let connector =
                    tokio_rustls::TlsConnector::from(self.tls_config.clone());

                let stream = tokio::time::timeout(
                    self.timeout,
                    connector.connect(
                        host.try_into().expect("must be valid SNI"),
                        stream,
                    ),
                )
                .await??;

                let io = TokioIo::new(stream);

                let (mut sender, conn) = hyper::client::conn::http1::handshake(io)
                    .await
                    .map_err(std::io::Error::other)?;

                tokio::task::spawn(async move {
                    if let Err(err) = conn.await {
                        warn!("HTTP connection error: {}", err);
                    }
                });

                sender.send_request(req).boxed()
            }
            _ => {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::InvalidInput,
                    format!("invalid url: {uri}: unsupported scheme"),
                ));
            }
        };

        resp.await
            .map_err(|e| std::io::Error::other(format!("HTTP request failed: {e}")))
    }
}

/// Creates a new HTTP client with the given DNS resolver and optional bootstrap
/// outbounds, that is used by clash to send outgoing HTTP requests.
pub fn new_http_client(
    dns_resolver: ThreadSafeDNSResolver,
    bootstrap_outbounds: Option<OutboundHandlerRegistry>,
) -> std::io::Result<HttpClient> {
    HttpClient::new(dns_resolver, bootstrap_outbounds, None)
}
