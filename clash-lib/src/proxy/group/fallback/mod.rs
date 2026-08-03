use async_trait::async_trait;

use std::{fmt::Debug, io};
use tracing::debug;

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

#[derive(Default, Clone)]
pub struct HandlerOptions {
    pub common_opts: HandlerCommonOptions,
    pub name: String,
    pub udp: bool,
}

pub struct Handler {
    opts: HandlerOptions,
    providers: Vec<ArcProxyProvider>,
    proxy_manager: ProxyManager,
    selected: tokio::sync::RwLock<Option<String>>,
}

impl Debug for Handler {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Fallback")
            .field("name", &self.opts.name)
            .finish()
    }
}

impl Handler {
    pub fn new(
        opts: HandlerOptions,
        providers: Vec<ArcProxyProvider>,
        proxy_manager: ProxyManager,
    ) -> Self {
        Self {
            opts,
            providers,
            proxy_manager,
            selected: tokio::sync::RwLock::new(None),
        }
    }

    async fn get_proxies(&self, touch: bool) -> Vec<AnyOutboundHandler> {
        get_proxies_from_providers(&self.providers, touch).await
    }

    fn test_url(&self) -> &str {
        self.opts.common_opts.url.as_deref().unwrap_or_default()
    }

    async fn candidates(&self, touch: bool) -> Vec<AnyOutboundHandler> {
        let proxies = self.get_proxies(touch).await;
        let mut candidates = Vec::new();
        let selected_name = self.selected.read().await.clone();
        if let Some(selected_name) = selected_name {
            let selected = proxies
                .iter()
                .find(|proxy| proxy.name() == selected_name.as_str());
            let checking = match selected {
                Some(selected) => {
                    self.proxy_manager
                        .checking_after_failure(selected.name(), self.test_url())
                        .await
                }
                None => false,
            };
            if let Some(selected) = selected
                && self
                    .proxy_manager
                    .available_for(selected.name(), self.test_url())
                    .await
            {
                candidates.push(selected.clone());
            } else if !checking {
                let mut selected = self.selected.write().await;
                if selected.as_deref() == Some(selected_name.as_str()) {
                    *selected = None;
                }
            }
        }
        for proxy in proxies.iter() {
            if candidates
                .iter()
                .any(|candidate| candidate.name() == proxy.name())
            {
                continue;
            }
            if self
                .proxy_manager
                .available_for(proxy.name(), self.test_url())
                .await
            {
                candidates.push(proxy.clone());
            }
        }
        if candidates.is_empty()
            && let Some(first) = proxies.first()
            && !self
                .proxy_manager
                .checking_after_failure(first.name(), self.test_url())
                .await
        {
            candidates.push(first.clone());
        }
        candidates
    }

    async fn find_alive_proxy(&self, touch: bool) -> Option<AnyOutboundHandler> {
        let proxy = self.candidates(touch).await.into_iter().next();
        if let Some(proxy) = &proxy {
            debug!("`{}` fallback to `{}`", self.name(), proxy.name());
        }
        proxy
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

impl DialWithConnector for Handler {}

#[async_trait]
impl OutboundHandler for Handler {
    /// The name of the outbound handler
    fn name(&self) -> &str {
        &self.opts.name
    }

    /// The protocol of the outbound handler
    /// only contains Type information, do not rely on the underlying value
    fn proto(&self) -> OutboundType {
        OutboundType::Fallback
    }

    /// whether the outbound handler support UDP
    async fn support_udp(&self) -> bool {
        if self.opts.udp {
            return true;
        }
        match self.find_alive_proxy(false).await {
            Some(proxy) => proxy.support_udp().await,
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
        for proxy in self.candidates(true).await.into_iter().take(2) {
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
        for proxy in self.candidates(true).await.into_iter().take(2) {
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
        ConnectorType::Tcp
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
                Ok(stream) => return Ok(stream),
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
        Handler::find_alive_proxy(self, false).await
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
    use std::sync::Arc;

    use crate::{
        app::{
            dispatcher::ChainedStreamWrapper, remote_content_manager::ProxyManager,
        },
        proxy::{
            HandlerCommonOptions, OutboundHandler,
            group::{GroupProxyAPIResponse, selector::SelectorControl},
            mocks::{MockDummyOutboundHandler, MockDummyProxyProvider},
            utils::test_utils::noop::NoopResolver,
        },
        session::Session,
    };

    #[tokio::test]
    async fn manual_selection_overrides_fallback_order() {
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
            vec![Arc::new(provider)],
            ProxyManager::new(Arc::new(NoopResolver), None),
        );

        handler.select("selected").await.unwrap();
        assert_eq!(handler.get_active_proxy().await.unwrap().name(), "selected");
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
        provider.expect_touch().returning(|| ());
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
            vec![Arc::new(provider)],
            ProxyManager::new(resolver.clone(), None),
        );

        handler
            .connect_stream(&Session::default(), resolver)
            .await
            .unwrap();
    }
}
