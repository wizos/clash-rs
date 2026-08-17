use std::{
    io,
    sync::{Arc, atomic::AtomicU16},
    time::Duration,
};

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
        group::{
            GroupProxyAPIResponse,
            race::{self, FailoverRecord, FailoverState},
            selector::SelectorControl,
        },
        utils::{RemoteConnector, provider_helper::get_proxies_from_providers},
    },
    session::Session,
};

#[derive(Default)]
pub struct HandlerOptions {
    pub common_opts: HandlerCommonOptions,
    pub name: String,
    pub udp: bool,
    pub failover_race: bool,
    pub race_delay: Option<Duration>,
}

pub struct Handler {
    opts: HandlerOptions,
    tolerance: u16,

    providers: Vec<ArcProxyProvider>,
    proxy_manager: ProxyManager,
    fastest_proxy_index: Arc<AtomicU16>,
    selected: tokio::sync::RwLock<Option<String>>,
    failover: Arc<FailoverState>,
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
        let failover_race = opts.failover_race;
        Self {
            opts,
            tolerance,
            providers,
            proxy_manager,
            fastest_proxy_index: Arc::new(AtomicU16::new(0)),
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

    async fn failover_candidates(&self, touch: bool) -> Vec<AnyOutboundHandler> {
        let proxies = self.get_proxies(touch).await;
        let Some(primary) = self.fastest_from(&proxies).await else {
            return Vec::new();
        };
        let primary_index = proxies
            .iter()
            .position(|proxy| proxy.name() == primary.name())
            .unwrap_or_default();
        let mut ranked = Vec::new();
        for (offset, index) in
            race::indexes_after(proxies.len(), primary_index).enumerate()
        {
            let proxy = &proxies[index];
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
                    offset,
                ));
            }
        }
        ranked.sort_by_key(|(_, delay, offset)| {
            (delay.is_none(), delay.unwrap_or(Duration::MAX), *offset)
        });

        let primary_leaf = race::effective_leaf_name(primary.clone()).await;
        let mut candidates = vec![primary];
        for (proxy, _, _) in ranked {
            if race::effective_leaf_name(proxy.clone()).await != primary_leaf {
                candidates.push(proxy);
                break;
            }
        }
        candidates
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
        touch: bool,
        connector: Option<&dyn RemoteConnector>,
    ) -> io::Result<BoxedChainedStream> {
        let mut candidates = self.failover_candidates(touch).await.into_iter();
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
        let fastest_proxy_index = self.fastest_proxy_index.clone();
        let providers = self.providers.clone();
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
                    let winner_index = get_proxies_from_providers(&providers, false)
                        .await
                        .iter()
                        .position(|proxy| proxy.name() == winner)
                        .map(|index| index as u16);
                    failover
                        .promote(&group, from, winner, epoch, || {
                            if let Some(index) = winner_index {
                                fastest_proxy_index.store(
                                    index,
                                    std::sync::atomic::Ordering::Relaxed,
                                );
                            }
                        })
                        .await;
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
        if self.failover.enabled() && self.owns_failover_race(sess).await {
            let stream = self
                .connect_stream_race(sess, resolver, false, None)
                .await?;
            stream.append_to_chain(self.name()).await;
            return Ok(stream);
        }
        let fastest = self.fastest(false).await.ok_or_else(|| {
            io::Error::other(format!("no proxy found for {}", self.name()))
        })?;
        let stream = fastest.connect_stream(sess, resolver).await?;
        stream.append_to_chain(self.name()).await;
        Ok(stream)
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
        let datagram = fastest.connect_datagram(sess, resolver).await?;
        datagram.append_to_chain(self.name()).await;
        Ok(datagram)
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
        if self.failover.enabled() && self.owns_failover_race(sess).await {
            let stream = self
                .connect_stream_race(sess, resolver, true, Some(connector))
                .await?;
            stream.append_to_chain(self.name()).await;
            return Ok(stream);
        }
        let stream = self
            .fastest(true)
            .await
            .ok_or_else(|| {
                io::Error::other(format!("no proxy found for {}", self.name()))
            })?
            .connect_stream_with_connector(sess, resolver, connector)
            .await?;
        stream.append_to_chain(self.name()).await;
        Ok(stream)
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
        let kind = if self
            .proxy_manager
            .last_delay_for(candidate.name(), self.test_url())
            .await
            .is_some()
        {
            race::FailoverCandidateKind::Measured
        } else {
            race::FailoverCandidateKind::Sequential
        };
        Some(race::FailoverCandidate {
            name: candidate.name().to_owned(),
            leaf: race::effective_leaf_name(candidate).await,
            kind,
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
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

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
        provider
            .expect_proxies()
            .returning(move || vec![failed.clone(), next.clone()]);
        let resolver = Arc::new(NoopResolver);
        let handler = super::Handler::new(
            super::HandlerOptions {
                name: "urltest-race".to_owned(),
                common_opts: HandlerCommonOptions {
                    url: Some("invalid".to_owned()),
                    ..Default::default()
                },
                failover_race: true,
                ..Default::default()
            },
            0,
            vec![Arc::new(provider)],
            ProxyManager::new(resolver.clone(), None),
        );

        let sess = Session {
            destination: "urltest-race.test:443".parse().unwrap(),
            ..Default::default()
        };
        let mut stream = handler.connect_stream(&sess, resolver).await.unwrap();
        let mut response = [0; 2];
        stream.read_exact(&mut response).await.unwrap();
        tokio::task::yield_now().await;
        assert_eq!(
            crate::app::dispatcher::ChainedStream::chain(stream.as_ref())
                .race_type()
                .await,
            crate::proxy::group::race::GROUP_RACE_TYPE,
        );
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
            0,
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
