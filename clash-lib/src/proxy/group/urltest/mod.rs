use std::{io, sync::atomic::AtomicU16, time::Duration};

use async_trait::async_trait;
use tracing::trace;

use crate::{
    app::{
        dispatcher::{BoxedChainedDatagram, BoxedChainedStream},
        dns::ThreadSafeDNSResolver,
        remote_content_manager::{
            ProxyManager, providers::proxy_provider::ArcProxyProvider,
        },
    },
    proxy::{
        AnyOutboundHandler, ConnectorType, DialWithConnector, HandlerCommonOptions,
        OutboundHandler, OutboundType,
        group::GroupProxyAPIResponse,
        utils::{RemoteConnector, provider_helper::get_proxies_from_providers},
    },
    session::Session,
};

#[derive(Default)]
pub struct HandlerOptions {
    pub common_opts: HandlerCommonOptions,
    pub name: String,
    pub udp: bool,
}

pub struct Handler {
    opts: HandlerOptions,
    tolerance: u16,

    providers: Vec<ArcProxyProvider>,
    proxy_manager: ProxyManager,
    fastest_proxy_index: AtomicU16,
}

impl std::fmt::Debug for Handler {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("UrlTest")
            .field("name", &self.opts.name)
            .finish()
    }
}

impl Handler {
    pub fn new(
        opts: HandlerOptions,
        tolerance: u16,
        providers: Vec<ArcProxyProvider>,
        proxy_manager: ProxyManager,
    ) -> Self {
        Self {
            opts,
            tolerance,
            providers,
            proxy_manager,
            fastest_proxy_index: AtomicU16::new(0),
        }
    }

    async fn get_proxies(&self, touch: bool) -> Vec<AnyOutboundHandler> {
        get_proxies_from_providers(&self.providers, touch).await
    }

    async fn fastest(&self, touch: bool) -> Option<AnyOutboundHandler> {
        let proxies = self.get_proxies(touch).await;
        if proxies.is_empty() {
            return None;
        }
        let current_index = std::cmp::min(
            self.fastest_proxy_index
                .load(std::sync::atomic::Ordering::Relaxed),
            proxies.len() as u16 - 1,
        ) as usize;
        let mut delays = Vec::with_capacity(proxies.len());
        for proxy in &proxies {
            delays.push(self.proxy_manager.last_delay(proxy.name()).await);
        }
        let selected_index = select_fastest_index(
            current_index,
            Duration::from_millis(self.tolerance as u64),
            &delays,
        );
        self.fastest_proxy_index
            .store(selected_index as u16, std::sync::atomic::Ordering::Relaxed);
        let selected = &proxies[selected_index];

        trace!(
            fastest = %selected.name(),
            delay = ?delays[selected_index],
            "`{}` fastest",
            self.name(),
        );

        Some(selected.clone())
    }
}

fn select_fastest_index(
    current_index: usize,
    tolerance: Duration,
    delays: &[Option<Duration>],
) -> usize {
    let fastest = delays
        .iter()
        .enumerate()
        .filter_map(|(index, delay)| delay.map(|delay| (index, delay)))
        .min_by_key(|(_, delay)| *delay);
    let Some((fastest_index, fastest_delay)) = fastest else {
        return current_index.min(delays.len().saturating_sub(1));
    };
    match delays.get(current_index).copied().flatten() {
        Some(current_delay) if current_delay <= fastest_delay + tolerance => {
            current_index
        }
        _ => fastest_index,
    }
}

impl DialWithConnector for Handler {}

#[async_trait]
impl OutboundHandler for Handler {
    /// The name of the outbound handler
    fn name(&self) -> &str {
        &self.opts.name
    }

    /// The protocol of the outbound handler
    fn proto(&self) -> OutboundType {
        OutboundType::UrlTest
    }

    /// whether the outbound handler support UDP
    async fn support_udp(&self) -> bool {
        if self.opts.udp {
            return true;
        }
        match self.fastest(false).await {
            Some(fastest) => fastest.support_udp().await,
            None => false,
        }
    }

    /// connect to remote target via TCP
    async fn connect_stream(
        &self,
        sess: &Session,
        resolver: ThreadSafeDNSResolver,
    ) -> io::Result<BoxedChainedStream> {
        let fastest = self.fastest(false).await.ok_or_else(|| {
            io::Error::other(format!("no proxy found for {}", self.name()))
        })?;
        let s = fastest.connect_stream(sess, resolver).await?;

        s.append_to_chain(self.name()).await;

        Ok(s)
    }

    /// connect to remote target via UDP
    async fn connect_datagram(
        &self,
        sess: &Session,
        resolver: ThreadSafeDNSResolver,
    ) -> io::Result<BoxedChainedDatagram> {
        let fastest = self.fastest(false).await.ok_or_else(|| {
            io::Error::other(format!("no proxy found for {}", self.name()))
        })?;
        let d = fastest.connect_datagram(sess, resolver).await?;

        d.append_to_chain(self.name()).await;

        Ok(d)
    }

    async fn support_connector(&self) -> ConnectorType {
        match self.fastest(false).await {
            Some(fastest) => fastest.support_connector().await,
            None => ConnectorType::Tcp,
        }
    }

    async fn connect_stream_with_connector(
        &self,
        sess: &Session,
        resolver: ThreadSafeDNSResolver,
        connector: &dyn RemoteConnector,
    ) -> io::Result<BoxedChainedStream> {
        let s = self
            .fastest(true)
            .await
            .ok_or_else(|| {
                io::Error::other(format!("no proxy found for {}", self.name()))
            })?
            .connect_stream_with_connector(sess, resolver, connector)
            .await?;

        s.append_to_chain(self.name()).await;
        Ok(s)
    }

    async fn connect_datagram_with_connector(
        &self,
        sess: &Session,
        resolver: ThreadSafeDNSResolver,
        connector: &dyn RemoteConnector,
    ) -> io::Result<BoxedChainedDatagram> {
        self.fastest(true)
            .await
            .ok_or_else(|| {
                io::Error::other(format!("no proxy found for {}", self.name()))
            })?
            .connect_datagram_with_connector(sess, resolver, connector)
            .await
    }

    fn try_as_group_handler(&self) -> Option<&dyn GroupProxyAPIResponse> {
        Some(self as _)
    }
}

#[async_trait]
impl GroupProxyAPIResponse for Handler {
    async fn get_proxies(&self) -> Vec<AnyOutboundHandler> {
        Handler::get_proxies(self, false).await
    }

    async fn get_active_proxy(&self) -> Option<AnyOutboundHandler> {
        self.fastest(false).await
    }

    fn get_latency_test_url(&self) -> Option<String> {
        self.opts.common_opts.url.clone()
    }

    fn icon(&self) -> Option<String> {
        self.opts.common_opts.icon.clone()
    }
}

#[cfg(test)]
mod tests {
    use std::{sync::Arc, time::Duration};

    use crate::{
        app::remote_content_manager::ProxyManager,
        proxy::{
            group::GroupProxyAPIResponse, mocks::MockDummyProxyProvider,
            utils::test_utils::noop::NoopResolver,
        },
    };

    #[tokio::test]
    async fn test_empty_provider_returns_none_active_proxy() {
        let mut provider = MockDummyProxyProvider::new();
        provider.expect_name().return_const("provider1".to_owned());
        provider.expect_proxies().returning(Vec::new);

        let proxy_manager = ProxyManager::new(Arc::new(NoopResolver), None);
        let handler = super::Handler::new(
            super::HandlerOptions {
                name: "test".to_owned(),
                udp: true,
                ..Default::default()
            },
            0,
            vec![Arc::new(provider)],
            proxy_manager,
        );

        assert!(handler.get_active_proxy().await.is_none());
    }

    #[test]
    fn tolerance_keeps_current_proxy_until_it_is_materially_slower() {
        let delays = [
            Some(Duration::from_millis(120)),
            Some(Duration::from_millis(100)),
        ];
        assert_eq!(
            super::select_fastest_index(0, Duration::from_millis(30), &delays),
            0
        );
        assert_eq!(
            super::select_fastest_index(0, Duration::from_millis(10), &delays),
            1
        );
    }
}
