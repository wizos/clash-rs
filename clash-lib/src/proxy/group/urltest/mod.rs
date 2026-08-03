use std::{io, sync::atomic::AtomicU16, time::Duration};

use async_trait::async_trait;
use tracing::trace;

use crate::{
    Error,
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
        group::{GroupProxyAPIResponse, selector::SelectorControl},
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
    selected: tokio::sync::RwLock<Option<String>>,
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
            selected: tokio::sync::RwLock::new(None),
        }
    }

    async fn get_proxies(&self, touch: bool) -> Vec<AnyOutboundHandler> {
        get_proxies_from_providers(&self.providers, touch).await
    }

    fn test_url(&self) -> &str {
        self.opts.common_opts.url.as_deref().unwrap_or_default()
    }

    async fn fastest_from(
        &self,
        proxies: &[AnyOutboundHandler],
    ) -> Option<AnyOutboundHandler> {
        if proxies.is_empty() {
            return None;
        }
        let selected_name = self.selected.read().await.clone();
        if let Some(selected_name) = selected_name
            && let Some(selected) = proxies
                .iter()
                .find(|proxy| proxy.name() == selected_name.as_str())
            && self
                .proxy_manager
                .available_for(selected.name(), self.test_url())
                .await
        {
            return Some(selected.clone());
        }
        let mut current_index = std::cmp::min(
            self.fastest_proxy_index
                .load(std::sync::atomic::Ordering::Relaxed),
            proxies.len() as u16 - 1,
        ) as usize;
        let mut delays = Vec::with_capacity(proxies.len());
        let mut available = Vec::with_capacity(proxies.len());
        for proxy in proxies {
            let is_available = self
                .proxy_manager
                .available_for(proxy.name(), self.test_url())
                .await;
            available.push(is_available);
            delays.push(if is_available {
                self.proxy_manager
                    .last_delay_for(proxy.name(), self.test_url())
                    .await
            } else {
                None
            });
        }
        if !available[current_index]
            && let Some(index) = available.iter().position(|available| *available)
        {
            current_index = index;
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

    async fn fastest(&self, touch: bool) -> Option<AnyOutboundHandler> {
        let proxies = self.get_proxies(touch).await;
        self.fastest_from(&proxies).await
    }

    async fn candidates(&self, touch: bool) -> Vec<AnyOutboundHandler> {
        let proxies = self.get_proxies(touch).await;
        let Some(first) = self.fastest_from(&proxies).await else {
            return Vec::new();
        };
        let mut ranked = Vec::new();
        for proxy in &proxies {
            if self
                .proxy_manager
                .available_for(proxy.name(), self.test_url())
                .await
            {
                ranked.push((
                    proxy.clone(),
                    self.proxy_manager
                        .last_delay_for(proxy.name(), self.test_url())
                        .await,
                ));
            }
        }
        ranked.sort_by_key(|(_, delay)| delay.unwrap_or(Duration::MAX));

        let mut candidates = vec![];
        if let Some(index) = ranked
            .iter()
            .position(|(proxy, _)| proxy.name() == first.name())
        {
            candidates.push(ranked.remove(index).0);
        }
        candidates.extend(ranked.into_iter().map(|(proxy, _)| proxy));
        if candidates.is_empty()
            && !self
                .proxy_manager
                .checking_after_failure(first.name(), self.test_url())
                .await
        {
            candidates.push(first);
        }
        candidates
    }

    async fn check_after_failure(&self, proxy: AnyOutboundHandler) {
        self.proxy_manager
            .check_after_failure(proxy, self.test_url())
            .await;
    }
}

#[async_trait]
impl SelectorControl for Handler {
    async fn select(&self, name: &str) -> Result<(), Error> {
        if name.is_empty() {
            *self.selected.write().await = None;
            return Ok(());
        }
        if self
            .get_proxies(false)
            .await
            .iter()
            .any(|proxy| proxy.name() == name)
        {
            *self.selected.write().await = Some(name.to_owned());
            Ok(())
        } else {
            Err(Error::Operation(format!("proxy {name} not found")))
        }
    }

    #[cfg(test)]
    async fn current(&self) -> String {
        self.selected
            .read()
            .await
            .clone()
            .unwrap_or_else(|| "<none>".to_owned())
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
        let mut last_error = None;
        for proxy in self.candidates(false).await.into_iter().take(2) {
            match proxy.connect_stream(sess, resolver.clone()).await {
                Ok(stream) => {
                    stream.append_to_chain(self.name()).await;
                    return Ok(stream);
                }
                Err(error) => {
                    self.check_after_failure(proxy).await;
                    last_error = Some(error);
                }
            }
        }
        Err(last_error.unwrap_or_else(|| {
            io::Error::other(format!("no proxy found for {}", self.name()))
        }))
    }

    /// connect to remote target via UDP
    async fn connect_datagram(
        &self,
        sess: &Session,
        resolver: ThreadSafeDNSResolver,
    ) -> io::Result<BoxedChainedDatagram> {
        let mut last_error = None;
        for proxy in self.candidates(false).await.into_iter().take(2) {
            match proxy.connect_datagram(sess, resolver.clone()).await {
                Ok(datagram) => {
                    datagram.append_to_chain(self.name()).await;
                    return Ok(datagram);
                }
                Err(error) => {
                    self.check_after_failure(proxy).await;
                    last_error = Some(error);
                }
            }
        }
        Err(last_error.unwrap_or_else(|| {
            io::Error::other(format!("no proxy found for {}", self.name()))
        }))
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
        let mut last_error = None;
        for proxy in self.candidates(true).await.into_iter().take(2) {
            match proxy
                .connect_stream_with_connector(sess, resolver.clone(), connector)
                .await
            {
                Ok(stream) => {
                    stream.append_to_chain(self.name()).await;
                    return Ok(stream);
                }
                Err(error) => {
                    self.check_after_failure(proxy).await;
                    last_error = Some(error);
                }
            }
        }
        Err(last_error.unwrap_or_else(|| {
            io::Error::other(format!("no proxy found for {}", self.name()))
        }))
    }

    async fn connect_datagram_with_connector(
        &self,
        sess: &Session,
        resolver: ThreadSafeDNSResolver,
        connector: &dyn RemoteConnector,
    ) -> io::Result<BoxedChainedDatagram> {
        let mut last_error = None;
        for proxy in self.candidates(true).await.into_iter().take(2) {
            match proxy
                .connect_datagram_with_connector(sess, resolver.clone(), connector)
                .await
            {
                Ok(datagram) => return Ok(datagram),
                Err(error) => {
                    self.check_after_failure(proxy).await;
                    last_error = Some(error);
                }
            }
        }
        Err(last_error.unwrap_or_else(|| {
            io::Error::other(format!("no proxy found for {}", self.name()))
        }))
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
        app::{
            dispatcher::ChainedStreamWrapper, remote_content_manager::ProxyManager,
        },
        config::internal::proxy::PROXY_COMPATIBLE,
        proxy::{
            HandlerCommonOptions, OutboundHandler,
            group::{GroupProxyAPIResponse, selector::SelectorControl},
            mocks::{MockDummyOutboundHandler, MockDummyProxyProvider},
            utils::test_utils::noop::NoopResolver,
        },
        session::Session,
    };

    #[tokio::test]
    async fn empty_provider_uses_compatible_fallback() {
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

        assert_eq!(
            handler.get_active_proxy().await.unwrap().name(),
            PROXY_COMPATIBLE,
        );
    }

    #[tokio::test]
    async fn manual_selection_overrides_fastest_proxy() {
        let mut provider = MockDummyProxyProvider::new();
        provider.expect_name().return_const("provider".to_owned());
        provider.expect_proxies().returning(|| {
            let mut first = MockDummyOutboundHandler::new();
            first.expect_name().return_const("first".to_owned());
            let mut selected = MockDummyOutboundHandler::new();
            selected.expect_name().return_const("selected".to_owned());
            vec![Arc::new(first), Arc::new(selected)]
        });
        let handler = super::Handler::new(
            super::HandlerOptions {
                name: "test".to_owned(),
                ..Default::default()
            },
            0,
            vec![Arc::new(provider)],
            ProxyManager::new(Arc::new(NoopResolver), None),
        );

        handler.select("selected").await.unwrap();
        assert_eq!(handler.get_active_proxy().await.unwrap().name(), "selected");

        handler.select("").await.unwrap();
        assert_eq!(handler.get_active_proxy().await.unwrap().name(), "first");
    }

    #[tokio::test]
    async fn retries_the_next_proxy_after_a_dial_failure() {
        let mut failed = MockDummyOutboundHandler::new();
        failed.expect_name().return_const("failed".to_owned());
        failed
            .expect_connect_stream()
            .times(1)
            .returning(|_, _| Err(std::io::Error::other("dial failed")));
        let failed: crate::proxy::AnyOutboundHandler = Arc::new(failed);

        let mut next = MockDummyOutboundHandler::new();
        next.expect_name().return_const("next".to_owned());
        next.expect_connect_stream().times(1).returning(|_, _| {
            let (stream, _) = tokio::io::duplex(64);
            Ok(Box::new(ChainedStreamWrapper::new(stream)))
        });
        let next: crate::proxy::AnyOutboundHandler = Arc::new(next);

        let mut provider = MockDummyProxyProvider::new();
        provider.expect_name().return_const("provider".to_owned());
        provider
            .expect_proxies()
            .returning(move || vec![failed.clone(), next.clone()]);
        let resolver = Arc::new(NoopResolver);
        let handler = super::Handler::new(
            super::HandlerOptions {
                name: "test".to_owned(),
                common_opts: HandlerCommonOptions {
                    url: Some("invalid".to_owned()),
                    ..Default::default()
                },
                ..Default::default()
            },
            0,
            vec![Arc::new(provider)],
            ProxyManager::new(resolver.clone(), None),
        );

        handler
            .connect_stream(&Session::default(), resolver)
            .await
            .unwrap();
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
