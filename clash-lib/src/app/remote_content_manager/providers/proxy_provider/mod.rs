pub mod plain_provider;

pub mod proxy_set_provider;

pub use plain_provider::PlainProvider;
pub use proxy_set_provider::ProxySetProvider;

use std::{collections::HashMap, io, sync::Arc};

use async_trait::async_trait;
use erased_serde::Serialize;

use crate::{
    Error,
    app::remote_content_manager::providers::{
        Provider, ProviderType, ProviderVehicleType,
    },
    proxy::AnyOutboundHandler,
};

pub type ArcProxyProvider = Arc<dyn ProxyProvider + Send + Sync>;

#[async_trait]
pub trait ProxyProvider: Provider {
    async fn proxies(&self) -> Vec<AnyOutboundHandler>;
    async fn touch(&self);
    /// this is a blocking call, you may want to spawn a new task to run this
    async fn healthcheck(&self);
    fn start_healthcheck(&self) {}
    fn register_healthcheck(&self, _url: &str, _interval: u64) {}
}

struct ProxyFilter {
    include: Vec<regex::Regex>,
    exclude: Vec<regex::Regex>,
}

impl ProxyFilter {
    fn new(include: Option<&str>, exclude: Option<&str>) -> Result<Self, Error> {
        fn compile(value: Option<&str>) -> Result<Vec<regex::Regex>, Error> {
            value
                .unwrap_or_default()
                .split('`')
                .filter(|pattern| !pattern.is_empty())
                .map(|pattern| {
                    regex::Regex::new(pattern).map_err(|error| {
                        Error::InvalidConfig(format!(
                            "invalid proxy group filter `{pattern}`: {error}"
                        ))
                    })
                })
                .collect()
        }

        Ok(Self {
            include: compile(include)?,
            exclude: compile(exclude)?,
        })
    }

    fn is_empty(&self) -> bool {
        self.include.is_empty() && self.exclude.is_empty()
    }

    fn allows_name(&self, name: &str, apply_include: bool) -> bool {
        (!apply_include
            || self.include.is_empty()
            || self.include.iter().any(|filter| filter.is_match(name)))
            && !self.exclude.iter().any(|filter| filter.is_match(name))
    }
}

pub struct FilteredProvider {
    inner: ArcProxyProvider,
    filter: ProxyFilter,
}

impl FilteredProvider {
    pub fn wrap(
        inner: ArcProxyProvider,
        include: Option<&str>,
        exclude: Option<&str>,
    ) -> Result<ArcProxyProvider, Error> {
        let filter = ProxyFilter::new(include, exclude)?;
        if filter.is_empty() {
            return Ok(inner);
        }
        Ok(Arc::new(Self { inner, filter }))
    }
}

#[async_trait]
impl Provider for FilteredProvider {
    fn name(&self) -> &str {
        self.inner.name()
    }

    fn vehicle_type(&self) -> ProviderVehicleType {
        self.inner.vehicle_type()
    }

    fn typ(&self) -> ProviderType {
        self.inner.typ()
    }

    async fn initialize(&self) -> io::Result<()> {
        self.inner.initialize().await
    }

    async fn update(&self) -> io::Result<()> {
        self.inner.update().await
    }

    async fn as_map(&self) -> HashMap<String, Box<dyn Serialize + Send>> {
        self.inner.as_map().await
    }
}

#[async_trait]
impl ProxyProvider for FilteredProvider {
    async fn proxies(&self) -> Vec<AnyOutboundHandler> {
        let apply_include =
            self.inner.vehicle_type() != ProviderVehicleType::Compatible;
        self.inner
            .proxies()
            .await
            .into_iter()
            .filter(|proxy| self.filter.allows_name(proxy.name(), apply_include))
            .collect()
    }

    async fn touch(&self) {
        self.inner.touch().await;
    }

    async fn healthcheck(&self) {
        self.inner.healthcheck().await;
    }

    fn start_healthcheck(&self) {
        self.inner.start_healthcheck();
    }
}

#[cfg(test)]
mod tests {
    use super::ProxyFilter;

    #[test]
    fn proxy_filter_applies_include_then_exclude() {
        let filter = ProxyFilter::new(Some("(?i)hong kong|🇭🇰"), Some("☁️")).unwrap();
        assert!(filter.allows_name("Hong Kong 01 🇭🇰", true));
        assert!(!filter.allows_name("Hong Kong ☁️", true));
        assert!(!filter.allows_name("Tokyo 01", true));
        assert!(filter.allows_name("Tokyo 01", false));
    }
}
