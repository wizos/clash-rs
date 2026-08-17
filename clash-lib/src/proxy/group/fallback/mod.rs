use async_trait::async_trait;

use std::{fmt::Debug, io, sync::Arc, time::Duration};
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
        group::{
            GroupProxyAPIResponse,
            race::{self, FailoverRecord, FailoverState},
            selector::SelectorControl,
        },
        utils::{RemoteConnector, provider_helper::get_proxies_from_providers},
    },
    session::Session,
};

#[derive(Default, Clone)]
pub struct HandlerOptions {
    pub common_opts: HandlerCommonOptions,
    pub name: String,
    pub udp: bool,
    pub failover_race: bool,
    pub race_delay: Option<Duration>,
}

pub struct Handler {
    opts: HandlerOptions,
    providers: Vec<ArcProxyProvider>,
    proxy_manager: ProxyManager,
    selected: tokio::sync::RwLock<Option<String>>,
    failover: Arc<FailoverState>,
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
        let failover_race = opts.failover_race;
        Self {
            opts,
            providers,
            proxy_manager,
            selected: tokio::sync::RwLock::new(None),
            failover: Arc::new(FailoverState::new(failover_race)),
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
        self.candidates_from(&proxies).await
    }

    async fn candidates_from(
        &self,
        proxies: &[AnyOutboundHandler],
    ) -> Vec<AnyOutboundHandler> {
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
                    self.failover.advance();
                    self.failover.clear().await;
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

    async fn failover_candidates(&self, touch: bool) -> Vec<AnyOutboundHandler> {
        let proxies = self.get_proxies(touch).await;
        let Some(primary) = self.candidates_from(&proxies).await.into_iter().next()
        else {
            return Vec::new();
        };
        let primary_index = proxies
            .iter()
            .position(|proxy| proxy.name() == primary.name())
            .unwrap_or_default();
        let primary_leaf = race::effective_leaf_name(primary.clone()).await;
        let mut candidates = vec![primary];
        for index in race::indexes_after(proxies.len(), primary_index) {
            let proxy = &proxies[index];
            if self
                .proxy_manager
                .available_for(proxy.name(), self.test_url())
                .await
                && race::effective_leaf_name(proxy.clone()).await != primary_leaf
            {
                candidates.push(proxy.clone());
                break;
            }
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

    async fn owns_failover_race(&self, sess: &Session) -> bool {
        let Some(plan) = sess.race_context.failover_plan(self.name(), self).await
        else {
            return false;
        };
        sess.race_context.failover_is_owned_by(&plan, self.name())
    }

    async fn connect_stream_race(
        &self,
        sess: &Session,
        resolver: ThreadSafeDNSResolver,
        connector: Option<&dyn RemoteConnector>,
    ) -> io::Result<BoxedChainedStream> {
        let mut candidates = self.failover_candidates(true).await.into_iter();
        let primary = candidates.next().ok_or_else(|| {
            io::Error::other(format!("no proxy found for {}", self.name()))
        })?;
        let Some(challenger) = candidates.next() else {
            sess.race_context.mark_failover_due();
            let result = match connector {
                Some(connector) => {
                    primary
                        .connect_stream_with_connector(sess, resolver, connector)
                        .await
                }
                None => primary.connect_stream(sess, resolver).await,
            };
            if result.is_err() {
                self.check_after_failure(primary).await;
            }
            return result;
        };
        let epoch = self.failover.epoch();
        let challenger_leaf = race::effective_leaf_name(challenger.clone()).await;
        let key = race::shared_key(
            &crate::app::remote_content_manager::network_link_generation()
                .to_string(),
            &challenger_leaf,
            sess,
        );
        let failover = self.failover.clone();
        let group = self.name().to_owned();
        let from = primary.name().to_owned();
        let winner = challenger.name().to_owned();
        let callbacks = race::group_callbacks(
            primary.clone(),
            challenger.clone(),
            self.proxy_manager.clone(),
            self.test_url().to_owned(),
            move || {
                tokio::spawn(async move {
                    failover.promote(&group, from, winner, epoch, || {}).await;
                });
            },
        );
        race::connect_group_stream(
            primary.clone(),
            challenger.clone(),
            sess,
            resolver,
            connector,
            &self.proxy_manager,
            self.test_url(),
            self.opts.race_delay.unwrap_or(race::RACE_DELAY),
            key,
            callbacks,
        )
        .await
    }
}

#[async_trait]
impl SelectorControl for Handler {
    async fn select(&self, name: &str) -> Result<(), Error> {
        if name.is_empty() {
            let _guard = self.failover.lock().await;
            *self.selected.write().await = None;
            self.failover.advance();
            self.failover.clear().await;
            return Ok(());
        }
        if !self
            .get_proxies(false)
            .await
            .iter()
            .any(|proxy| proxy.name() == name)
        {
            return Err(Error::Operation(format!("proxy {name} not found")));
        }
        let _guard = self.failover.lock().await;
        *self.selected.write().await = Some(name.to_owned());
        self.failover.advance();
        self.failover.clear().await;
        Ok(())
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
        if self.failover.enabled() && self.owns_failover_race(sess).await {
            let stream = self.connect_stream_race(sess, resolver, None).await?;
            stream.append_to_chain(self.name()).await;
            return Ok(stream);
        }
        let proxy = self.find_alive_proxy(true).await.ok_or_else(|| {
            io::Error::other(format!("no proxy found for {}", self.name()))
        })?;
        let stream = proxy.connect_stream(sess, resolver).await?;
        stream.append_to_chain(self.name()).await;
        Ok(stream)
    }

    /// connect to remote target via UDP
    async fn connect_datagram(
        &self,
        sess: &Session,
        resolver: ThreadSafeDNSResolver,
    ) -> io::Result<BoxedChainedDatagram> {
        let proxy = self.find_alive_proxy(true).await.ok_or_else(|| {
            io::Error::other(format!("no proxy found for {}", self.name()))
        })?;
        let datagram = proxy.connect_datagram(sess, resolver).await?;
        datagram.append_to_chain(self.name()).await;
        Ok(datagram)
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
        if self.failover.enabled() && self.owns_failover_race(sess).await {
            return self
                .connect_stream_race(sess, resolver, Some(connector))
                .await;
        }
        let proxy = self.find_alive_proxy(true).await.ok_or_else(|| {
            io::Error::other(format!("no proxy found for {}", self.name()))
        })?;
        proxy
            .connect_stream_with_connector(sess, resolver, connector)
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
        Handler::find_alive_proxy(self, false).await
    }

    fn get_latency_test_url(&self) -> Option<String> {
        self.opts.common_opts.url.clone()
    }

    fn failover_race_enabled(&self) -> bool {
        self.failover.enabled()
    }

    async fn failover_race_candidate(&self) -> Option<race::FailoverCandidate> {
        if !self.failover.enabled() || self.is_manually_selected().await {
            return None;
        }
        let mut candidates = self.failover_candidates(false).await.into_iter();
        candidates.next()?;
        let candidate = candidates.next()?;
        Some(race::FailoverCandidate {
            name: candidate.name().to_owned(),
            leaf: race::effective_leaf_name(candidate).await,
            kind: race::FailoverCandidateKind::Sequential,
        })
    }

    async fn is_manually_selected(&self) -> bool {
        self.selected.read().await.is_some()
    }

    async fn last_failover_race(&self) -> Option<FailoverRecord> {
        self.failover.last().await
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
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

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
    async fn failover_race_promotes_after_a_dial_failure() {
        let mut failed = MockDummyOutboundHandler::new();
        failed.expect_name().return_const("failed".to_owned());
        failed
            .expect_connect_stream()
            .times(2)
            .returning(|_, _| Err(std::io::Error::other("dial failed")));
        let failed: crate::proxy::AnyOutboundHandler = Arc::new(failed);

        let mut next = MockDummyOutboundHandler::new();
        next.expect_name().return_const("next".to_owned());
        next.expect_connect_stream().times(1).returning(|_, _| {
            let (stream, mut peer) = tokio::io::duplex(64);
            tokio::spawn(async move {
                peer.write_all(b"ok").await.unwrap();
            });
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
                name: "fallback-race".to_owned(),
                common_opts: HandlerCommonOptions {
                    url: Some("invalid".to_owned()),
                    ..Default::default()
                },
                failover_race: true,
                ..Default::default()
            },
            vec![Arc::new(provider)],
            ProxyManager::new(resolver.clone(), None),
        );

        let sess = Session {
            destination: "fallback-race.test:443".parse().unwrap(),
            ..Default::default()
        };
        let mut stream = handler.connect_stream(&sess, resolver).await.unwrap();
        let mut response = [0; 2];
        stream.read_exact(&mut response).await.unwrap();
        tokio::task::yield_now().await;
        assert_eq!(handler.current().await, "<none>");
        assert_eq!(handler.get_active_proxy().await.unwrap().name(), "next");
    }

    #[tokio::test]
    async fn manual_selection_disables_failover_race() {
        let mut selected = MockDummyOutboundHandler::new();
        selected.expect_name().return_const("selected".to_owned());
        selected
            .expect_connect_stream()
            .times(1)
            .returning(|_, _| Err(std::io::Error::other("dial failed")));
        let selected: crate::proxy::AnyOutboundHandler = Arc::new(selected);

        let mut challenger = MockDummyOutboundHandler::new();
        challenger
            .expect_name()
            .return_const("challenger".to_owned());
        challenger.expect_connect_stream().times(0);
        let challenger: crate::proxy::AnyOutboundHandler = Arc::new(challenger);

        let mut provider = MockDummyProxyProvider::new();
        provider.expect_name().return_const("provider".to_owned());
        provider.expect_touch().returning(|| ());
        provider
            .expect_proxies()
            .returning(move || vec![selected.clone(), challenger.clone()]);
        let resolver = Arc::new(NoopResolver);
        let handler = super::Handler::new(
            super::HandlerOptions {
                name: "test".to_owned(),
                common_opts: HandlerCommonOptions {
                    url: Some("invalid".to_owned()),
                    ..Default::default()
                },
                failover_race: true,
                ..Default::default()
            },
            vec![Arc::new(provider)],
            ProxyManager::new(resolver.clone(), None),
        );

        handler.select("selected").await.unwrap();
        assert!(
            handler
                .connect_stream(&Session::default(), resolver)
                .await
                .is_err()
        );
    }
}
