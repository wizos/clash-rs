use async_trait::async_trait;

use std::{
    fmt::Debug,
    sync::{Arc, LazyLock, OnceLock, RwLock},
};

use hickory_proto::op;

#[cfg(test)]
use mockall::automock;

pub mod config;
mod dhcp;
mod dns_client;
mod fakeip;
mod filters;
mod helper;
pub mod resolver;
mod rule_dispatch;
mod runtime;
mod server;
mod system_dns;

pub use config::{Config, EdnsClientSubnet};

pub use filters::PendingMmdb;
pub use rule_dispatch::{PendingOutboundManager, PendingRouter, RuleDispatch};

pub type PendingGeoData = Arc<OnceLock<crate::common::geodata::GeoDataLookup>>;

pub use resolver::{EnhancedResolver, SystemResolver, new as new_resolver};

pub use server::{DnsRunner, exchange_with_resolver};
pub use system_dns::update_system_dns_servers;

#[async_trait]
pub trait Client: Sync + Send + Debug {
    /// used to identify the client for logging
    fn id(&self) -> String;
    async fn exchange(&self, msg: &op::Message) -> anyhow::Result<op::Message>;
    async fn reset_connection(&self) {}
}

type ThreadSafeDNSClient = Arc<dyn Client>;

pub enum ResolverKind {
    Clash,
    System,
}

pub type ThreadSafeDNSResolver = Arc<dyn ClashResolver>;

// ponytail: the core owns one active runtime per process; plumb resolver
// ownership through transports if concurrent runtimes are introduced.
static ACTIVE_DNS_RESOLVER: LazyLock<RwLock<Option<ThreadSafeDNSResolver>>> =
    LazyLock::new(|| RwLock::new(None));

pub(crate) fn set_active_resolver(resolver: ThreadSafeDNSResolver) {
    *ACTIVE_DNS_RESOLVER
        .write()
        .expect("active DNS resolver lock poisoned") = Some(resolver);
}

pub(crate) fn active_resolver() -> Option<ThreadSafeDNSResolver> {
    ACTIVE_DNS_RESOLVER
        .read()
        .expect("active DNS resolver lock poisoned")
        .clone()
}

/// A implementation of "anti-poisoning" Resolver
/// it can hold multiple clients in different protocols
/// each client can also hold a "default_resolver"
/// in case they need to resolve DoH in domain names etc.
#[cfg_attr(test, automock)]
#[async_trait]
pub trait ClashResolver: Sync + Send {
    async fn resolve(
        &self,
        host: &str,
        enhanced: bool,
    ) -> anyhow::Result<Option<std::net::IpAddr>>;
    async fn resolve_v4(
        &self,
        host: &str,
        enhanced: bool,
    ) -> anyhow::Result<Option<std::net::Ipv4Addr>>;
    async fn resolve_v6(
        &self,
        host: &str,
        enhanced: bool,
    ) -> anyhow::Result<Option<std::net::Ipv6Addr>>;

    async fn cached_for(&self, ip: std::net::IpAddr) -> Option<String>;

    /// Used for DNS Server
    async fn exchange(&self, message: &op::Message) -> anyhow::Result<op::Message>;

    /// Used for proxy-server metadata such as ECH HTTPS records.
    async fn exchange_proxy_server(
        &self,
        message: &op::Message,
    ) -> anyhow::Result<op::Message> {
        self.exchange(message).await
    }

    /// Only used for look up fake IP
    async fn reverse_lookup(&self, ip: std::net::IpAddr) -> Option<String>;
    async fn is_fake_ip(&self, ip: std::net::IpAddr) -> bool;
    fn fake_ip_enabled(&self) -> bool;
    async fn fake_ip_active_for(&self, _host: &str) -> bool {
        false
    }

    fn ipv6(&self) -> bool;
    fn set_ipv6(&self, enable: bool);

    async fn flush_cache(&self) {}
    async fn flush_fakeip(&self) {}
    async fn reset_connections(&self) {}

    fn kind(&self) -> ResolverKind;
}

/// Returns the IP address if `host` is a valid IP literal, otherwise `None`.
/// Used by resolvers to short-circuit DNS resolution for IP literals.
pub(crate) fn parse_ip_literal(host: &str) -> Option<std::net::IpAddr> {
    host.parse().ok()
}
