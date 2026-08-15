use crate::proxy::{AnyOutboundHandler, OutboundHandler};
use async_trait::async_trait;
use erased_serde::Serialize;
use std::collections::HashMap;

pub mod fallback;
pub mod loadbalance;
#[doc(hidden)]
pub mod race;
pub mod relay;
pub mod route_race;
pub mod selector;
pub mod smart;
pub mod urltest;

/// Convenience trait for group proxy serializing API responses.
#[async_trait]
pub trait GroupProxyAPIResponse: OutboundHandler {
    /// Returns all proxies in the group, which are usually stored in a list of
    /// ProxyProviders.
    async fn get_proxies(&self) -> Vec<AnyOutboundHandler>;
    /// Returns the current effective proxy for the group.
    /// e.g. for a selector, it returns the currently selected proxy, and for
    /// urltest, it returns the fastest proxy, etc.
    async fn get_active_proxy(&self) -> Option<AnyOutboundHandler>;

    /// Returns the latency test URL for the group.
    fn get_latency_test_url(&self) -> Option<String>;

    fn failover_race_enabled(&self) -> bool {
        false
    }

    async fn failover_race_candidate(&self) -> Option<race::FailoverCandidate> {
        None
    }

    async fn is_manually_selected(&self) -> bool {
        false
    }

    async fn last_failover_race(&self) -> Option<race::FailoverRecord> {
        None
    }

    /// used in the API responses.
    async fn as_map(&self) -> HashMap<String, Box<dyn Serialize + Send>> {
        let all = self.get_proxies().await;

        let mut m = HashMap::new();

        if let Some(active) = self.get_active_proxy().await {
            m.insert("now".to_string(), Box::new(active.name().to_owned()) as _);
        }

        m.insert(
            "icon".to_string(),
            Box::new(self.icon().unwrap_or_default()) as _,
        );
        m.insert("hidden".to_string(), Box::new(false) as _);
        m.insert(
            "testUrl".to_string(),
            Box::new(self.get_latency_test_url().unwrap_or_default()) as _,
        );
        m.insert(
            "failoverRace".to_string(),
            Box::new(self.failover_race_enabled()) as _,
        );
        if let Some(last) = self.last_failover_race().await {
            m.insert("failoverRaceFrom".to_string(), Box::new(last.from) as _);
            m.insert("failoverRaceWinner".to_string(), Box::new(last.winner) as _);
        }

        m.insert(
            "all".to_string(),
            Box::new(all.iter().map(|x| x.name().to_owned()).collect::<Vec<_>>())
                as _,
        );
        m
    }

    fn icon(&self) -> Option<String> {
        None
    }
}
