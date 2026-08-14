use super::{ProviderVehicle, ProviderVehicleType, SubscriptionInfo};
use crate::{
    app::dns::{RuleDispatch, ThreadSafeDNSResolver},
    common::{
        errors::map_io_error,
        http::{ClashHTTPClientExt, HttpClient},
    },
};

use async_trait::async_trait;

use http_body_util::BodyExt;
use hyper::Uri;

use http::Request;
use std::{
    io,
    path::{Path, PathBuf},
    sync::{Arc, RwLock},
    time::Duration,
};

/// Matches Mihomo's `resource.DefaultHttpTimeout` for HTTP providers. Keep
/// this provider-specific: changing the generic Clash HTTP client timeout
/// would also alter unrelated router, geodata and test behavior.
pub const DEFAULT_PROVIDER_HTTP_TIMEOUT: Duration = Duration::from_secs(20);

pub struct Vehicle {
    pub url: Uri,
    pub path: PathBuf,
    http_client: HttpClient,
    outbound: Option<String>,
    headers: http::HeaderMap,
    subscription_info: RwLock<Option<SubscriptionInfo>>,
}

impl Vehicle {
    pub fn new<T: Into<Uri>, P: AsRef<Path>>(
        url: T,
        path: P,
        cwd: Option<P>,
        dns_resolver: ThreadSafeDNSResolver,
    ) -> Self {
        let client =
            HttpClient::new(dns_resolver, None, Some(DEFAULT_PROVIDER_HTTP_TIMEOUT))
                .expect("failed to create http client");
        Self {
            url: url.into(),
            path: match cwd {
                Some(cwd) => cwd.as_ref().join(path),
                None => path.as_ref().to_path_buf(),
            },
            http_client: client,
            outbound: None,
            headers: http::HeaderMap::new(),
            subscription_info: RwLock::new(None),
        }
    }

    pub fn with_rule_dispatch(mut self, rule_dispatch: Arc<RuleDispatch>) -> Self {
        self.http_client = self
            .http_client
            .with_user_agent(rule_dispatch.user_agent.clone())
            .with_rule_dispatch(rule_dispatch);
        self
    }

    pub fn with_user_agent(mut self, user_agent: http::HeaderValue) -> Self {
        self.http_client = self.http_client.with_user_agent(user_agent);
        self
    }

    pub fn with_outbound(mut self, outbound: String) -> Self {
        self.outbound = Some(outbound);
        self
    }

    pub fn with_headers(
        mut self,
        headers: std::collections::HashMap<
            String,
            crate::config::internal::proxy::StringList,
        >,
    ) -> io::Result<Self> {
        for (name, values) in headers {
            let name = name.parse::<http::HeaderName>().map_err(io::Error::other)?;
            for value in values.to_vec() {
                self.headers.append(
                    name.clone(),
                    value
                        .parse::<http::HeaderValue>()
                        .map_err(io::Error::other)?,
                );
            }
        }
        Ok(self)
    }

    async fn read_with_redirects(&self) -> std::io::Result<Vec<u8>> {
        let mut url =
            url::Url::parse(&self.url.to_string()).map_err(io::Error::other)?;
        for redirects in 0..=10 {
            let mut req = Request::default();
            *req.headers_mut() = self.headers.clone();
            *req.body_mut() = http_body_util::Empty::<bytes::Bytes>::new();
            *req.uri_mut() =
                url.as_str().parse::<Uri>().map_err(io::Error::other)?;
            if let Some(outbound) = &self.outbound {
                req.extensions_mut().insert(ClashHTTPClientExt {
                    outbound: Some(outbound.clone()),
                });
            }
            let response = self
                .http_client
                .request(req)
                .await
                .map_err(|x| io::Error::other(x.to_string()))?;

            if response.status().is_redirection() {
                if redirects == 10 {
                    return Err(io::Error::other("too many HTTP redirects"));
                }
                let location = response
                    .headers()
                    .get(http::header::LOCATION)
                    .ok_or_else(|| {
                        io::Error::other("HTTP redirect without location")
                    })?
                    .to_str()
                    .map_err(io::Error::other)?;
                url = url.join(location).map_err(io::Error::other)?;
                continue;
            }
            if !response.status().is_success() {
                return Err(io::Error::other(format!(
                    "provider download failed: {}",
                    response.status()
                )));
            }
            let subscription_info = response
                .headers()
                .get("subscription-userinfo")
                .and_then(|value| value.to_str().ok())
                .and_then(parse_subscription_info);
            *self
                .subscription_info
                .write()
                .expect("subscription info lock poisoned") = subscription_info;
            return response
                .into_body()
                .collect()
                .await
                .map(|x| x.to_bytes().to_vec())
                .map_err(map_io_error);
        }
        unreachable!()
    }
}

#[async_trait]
impl ProviderVehicle for Vehicle {
    async fn read(&self) -> std::io::Result<Vec<u8>> {
        tokio::time::timeout(
            DEFAULT_PROVIDER_HTTP_TIMEOUT,
            self.read_with_redirects(),
        )
        .await
        .map_err(|_| {
            io::Error::new(
                io::ErrorKind::TimedOut,
                "provider HTTP download timed out after 20 seconds",
            )
        })?
    }

    fn path(&self) -> &str {
        self.path.to_str().unwrap()
    }

    fn typ(&self) -> ProviderVehicleType {
        ProviderVehicleType::Http
    }

    fn subscription_info(&self) -> Option<SubscriptionInfo> {
        self.subscription_info
            .read()
            .expect("subscription info lock poisoned")
            .clone()
    }
}

fn parse_subscription_info(value: &str) -> Option<SubscriptionInfo> {
    let mut info = SubscriptionInfo::default();
    let mut found = false;
    for field in value.split(';') {
        let Some((key, value)) = field.trim().split_once('=') else {
            continue;
        };
        let Ok(value) = value.trim().parse::<u64>() else {
            continue;
        };
        match key.trim().to_ascii_lowercase().as_str() {
            "upload" => info.upload = value,
            "download" => info.download = value,
            "total" => info.total = value,
            "expire" => info.expire = value,
            _ => continue,
        }
        found = true;
    }
    found.then_some(info)
}

#[cfg(test)]
mod tests {
    use super::{
        DEFAULT_PROVIDER_HTTP_TIMEOUT, ProviderVehicle, parse_subscription_info,
    };
    use crate::{
        app::dns::{EnhancedResolver, ThreadSafeDNSResolver},
        tests::initialize,
    };
    use httpmock::{Method::GET, MockServer};
    use hyper::Uri;
    use std::{str, sync::Arc};
    use tokio::{
        io::{AsyncReadExt, AsyncWriteExt},
        net::TcpListener,
    };

    #[test]
    fn provider_http_timeout_matches_mihomo() {
        assert_eq!(DEFAULT_PROVIDER_HTTP_TIMEOUT.as_secs(), 20);
    }

    #[tokio::test]
    async fn test_http_vehicle() {
        initialize();
        let server = MockServer::start();
        let mock = server.mock(|when, then| {
            when.method(GET).path("/test_http_vehicle");
            then.status(200)
                .header("content-type", "text/html; charset=UTF-8")
                .body("HTTPBIN is awesome");
        });
        let u = server.url("/test_http_vehicle").parse::<Uri>().unwrap();
        let p = std::env::temp_dir().join("test_http_vehicle");
        let r = Arc::new(EnhancedResolver::new_default().await);
        let v = super::Vehicle::new(u, p, None, r.clone() as ThreadSafeDNSResolver);

        let data = v.read().await.unwrap();
        mock.assert();
        assert_eq!(str::from_utf8(&data).unwrap(), "HTTPBIN is awesome");
    }

    #[tokio::test]
    async fn test_http_vehicle_follows_redirects() {
        initialize();
        let server = MockServer::start();
        let redirect = server.mock(|when, then| {
            when.method(GET).path("/redirect");
            then.status(302).header("location", "/provider.yaml");
        });
        let provider = server.mock(|when, then| {
            when.method(GET).path("/provider.yaml");
            then.status(200).body("proxies: []");
        });
        let url = server.url("/redirect").parse::<Uri>().unwrap();
        let path = std::env::temp_dir().join("redirected_http_vehicle");
        let resolver = Arc::new(EnhancedResolver::new_default().await);
        let vehicle =
            super::Vehicle::new(url, path, None, resolver as ThreadSafeDNSResolver);

        assert_eq!(vehicle.read().await.unwrap(), b"proxies: []");
        redirect.assert();
        provider.assert();
    }

    #[tokio::test]
    async fn provider_http_uses_origin_form() {
        initialize();
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let server = tokio::spawn(async move {
            let (mut stream, _) = listener.accept().await.unwrap();
            let mut request = [0; 1024];
            let length = stream.read(&mut request).await.unwrap();
            assert!(
                str::from_utf8(&request[..length])
                    .unwrap()
                    .starts_with("GET /provider.yaml?source=test HTTP/1.1\r\n")
            );
            stream
                .write_all(
                    b"HTTP/1.1 200 OK\r\ncontent-length: 11\r\n\r\nproxies: []",
                )
                .await
                .unwrap();
        });
        let url = format!("http://{address}/provider.yaml?source=test")
            .parse::<Uri>()
            .unwrap();
        let path = std::env::temp_dir().join("origin_form_http_vehicle");
        let resolver = Arc::new(EnhancedResolver::new_default().await);
        let vehicle =
            super::Vehicle::new(url, path, None, resolver as ThreadSafeDNSResolver);

        assert_eq!(vehicle.read().await.unwrap(), b"proxies: []");
        server.await.unwrap();
    }

    #[test]
    fn parses_mihomo_subscription_userinfo_header() {
        let info =
            parse_subscription_info("upload=12; download=34; total=56; expire=78")
                .expect("valid subscription metadata");
        assert_eq!(info.upload, 12);
        assert_eq!(info.download, 34);
        assert_eq!(info.total, 56);
        assert_eq!(info.expire, 78);
        assert!(parse_subscription_info("invalid").is_none());
    }
}
