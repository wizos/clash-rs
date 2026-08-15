use std::{
    collections::HashMap,
    fmt,
    future::Future,
    io,
    pin::Pin,
    sync::atomic::{AtomicUsize, Ordering},
    time::Duration,
};

use async_trait::async_trait;
use erased_serde::Serialize;
use moka::future::Cache;
use tracing::info;

use crate::{
    app::{
        dispatcher::{BoxedChainedDatagram, BoxedChainedStream},
        dns::ThreadSafeDNSResolver,
        remote_content_manager::network_link_generation,
    },
    proxy::{
        AnyOutboundHandler, ConnectorType, DialWithConnector, OutboundHandler,
        OutboundType,
        group::{
            GroupProxyAPIResponse,
            race::{self, FailoverRecord},
        },
    },
    session::Session,
};

const CACHE_TTL: Duration = Duration::from_secs(10 * 60);
const CACHE_CAPACITY: u64 = 4096;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum Winner {
    Primary,
    Route,
}

pub struct Handler {
    primary: AnyOutboundHandler,
    route: AnyOutboundHandler,
    delay: Duration,
    failover_delay: Duration,
    winners: Cache<String, Winner>,
    epoch: AtomicUsize,
}

impl Handler {
    pub fn new(
        primary: AnyOutboundHandler,
        route: AnyOutboundHandler,
        delay: Duration,
        failover_delay: Duration,
    ) -> Self {
        Self {
            primary,
            route,
            delay,
            failover_delay,
            winners: Cache::builder()
                .max_capacity(CACHE_CAPACITY)
                .time_to_live(CACHE_TTL)
                .build(),
            epoch: AtomicUsize::new(0),
        }
    }

    fn cache_key(&self, sess: &Session) -> String {
        format!(
            "{}:{}:{}",
            network_link_generation(),
            self.epoch.load(Ordering::Acquire),
            sess.destination.to_string().to_ascii_lowercase(),
        )
    }

    async fn should_bypass_race(&self, route_leaf: &str) -> bool {
        let mut handler = self.primary.clone();
        for _ in 0..16 {
            if handler.name() == route_leaf {
                return true;
            }
            let Some(group) = handler.try_as_group_handler() else {
                return false;
            };
            if group.is_manually_selected().await {
                return true;
            }
            let Some(active) = group.get_active_proxy().await else {
                return false;
            };
            handler = active;
        }
        false
    }

    async fn race(
        &self,
        sess: &Session,
        resolver: ThreadSafeDNSResolver,
        first: Winner,
        trigger: Pin<Box<dyn Future<Output = ()> + Send>>,
    ) -> io::Result<(Winner, BoxedChainedStream)> {
        let (first_handler, second_handler, second) = match first {
            Winner::Primary => (&self.primary, &self.route, Winner::Route),
            Winner::Route => (&self.route, &self.primary, Winner::Primary),
        };
        let second_leaf = race::effective_leaf_name(second_handler.clone()).await;
        let key = race::shared_key(
            &network_link_generation().to_string(),
            &second_leaf,
            sess,
        );
        let (winner, stream) = race::staggered_with_trigger(
            first_handler.connect_stream(sess, resolver.clone()),
            || second_handler.connect_stream(sess, resolver),
            trigger,
            key,
            || {},
        )
        .await?;
        Ok((
            match winner {
                race::Winner::Primary => first,
                race::Winner::Challenger => second,
            },
            stream,
        ))
    }
}

impl fmt::Debug for Handler {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("RouteRace")
            .field("name", &self.primary.name())
            .field("route", &self.route.name())
            .finish()
    }
}

impl DialWithConnector for Handler {}

#[async_trait]
impl OutboundHandler for Handler {
    fn name(&self) -> &str {
        self.primary.name()
    }

    fn proto(&self) -> OutboundType {
        self.primary.proto()
    }

    async fn support_udp(&self) -> bool {
        self.primary.support_udp().await
    }

    async fn connect_stream(
        &self,
        sess: &Session,
        resolver: ThreadSafeDNSResolver,
    ) -> io::Result<BoxedChainedStream> {
        let route_leaf = race::effective_leaf_name(self.route.clone()).await;
        if self.should_bypass_race(&route_leaf).await {
            return self.primary.connect_stream(sess, resolver).await;
        }
        if !sess.race_context.try_claim_route() {
            return self.primary.connect_stream(sess, resolver).await;
        }

        let key = self.cache_key(sess);
        let cached = self.winners.get(&key).await;
        let failover_plan = sess.race_context.failover_plan(self.name(), self).await;
        let same_candidate = failover_plan
            .as_ref()
            .is_some_and(|plan| plan.candidate_leaf == route_leaf);
        if same_candidate {
            sess.race_context.suppress_failover();
        }
        let first = cached.unwrap_or(Winner::Primary);
        let trigger: Pin<Box<dyn Future<Output = ()> + Send>> = match first {
            Winner::Route => Box::pin(tokio::time::sleep(self.delay)),
            Winner::Primary if same_candidate => {
                Box::pin(tokio::time::sleep(self.failover_delay))
            }
            Winner::Primary if failover_plan.is_some() => {
                let context = sess.race_context.clone();
                let delay = self.delay;
                Box::pin(async move {
                    context.wait_route_after_failover(delay).await;
                })
            }
            Winner::Primary => Box::pin(tokio::time::sleep(self.delay)),
        };
        let (winner, stream) = self.race(sess, resolver, first, trigger).await?;
        self.winners.insert(key, winner).await;
        if winner == Winner::Route {
            stream.chain().set_race_type(race::ROUTE_RACE_TYPE).await;
            stream.append_to_chain(self.name()).await;
            if cached != Some(Winner::Route) {
                info!(
                    group = self.name(),
                    winner = self.route.name(),
                    "route race selected the alternate path"
                );
            }
        }
        Ok(stream)
    }

    async fn connect_datagram(
        &self,
        sess: &Session,
        resolver: ThreadSafeDNSResolver,
    ) -> io::Result<BoxedChainedDatagram> {
        self.primary.connect_datagram(sess, resolver).await
    }

    async fn support_connector(&self) -> ConnectorType {
        self.primary.support_connector().await
    }

    async fn connect_stream_with_connector(
        &self,
        sess: &Session,
        resolver: ThreadSafeDNSResolver,
        connector: &dyn crate::proxy::utils::RemoteConnector,
    ) -> io::Result<BoxedChainedStream> {
        self.primary
            .connect_stream_with_connector(sess, resolver, connector)
            .await
    }

    async fn connect_datagram_with_connector(
        &self,
        sess: &Session,
        resolver: ThreadSafeDNSResolver,
        connector: &dyn crate::proxy::utils::RemoteConnector,
    ) -> io::Result<BoxedChainedDatagram> {
        self.primary
            .connect_datagram_with_connector(sess, resolver, connector)
            .await
    }

    fn try_as_group_handler(&self) -> Option<&dyn GroupProxyAPIResponse> {
        Some(self)
    }

    fn clear_route_cache(&self) {
        self.epoch.fetch_add(1, Ordering::AcqRel);
        self.winners.invalidate_all();
    }
}

#[async_trait]
impl GroupProxyAPIResponse for Handler {
    async fn get_proxies(&self) -> Vec<AnyOutboundHandler> {
        match self.primary.try_as_group_handler() {
            Some(group) => group.get_proxies().await,
            None => Vec::new(),
        }
    }

    async fn get_active_proxy(&self) -> Option<AnyOutboundHandler> {
        match self.primary.try_as_group_handler() {
            Some(group) => group.get_active_proxy().await,
            None => None,
        }
    }

    fn get_latency_test_url(&self) -> Option<String> {
        self.primary
            .try_as_group_handler()
            .and_then(GroupProxyAPIResponse::get_latency_test_url)
    }

    fn failover_race_enabled(&self) -> bool {
        self.primary
            .try_as_group_handler()
            .is_some_and(GroupProxyAPIResponse::failover_race_enabled)
    }

    async fn failover_race_candidate(&self) -> Option<race::FailoverCandidate> {
        match self.primary.try_as_group_handler() {
            Some(group) => group.failover_race_candidate().await,
            None => None,
        }
    }

    async fn is_manually_selected(&self) -> bool {
        match self.primary.try_as_group_handler() {
            Some(group) => group.is_manually_selected().await,
            None => false,
        }
    }

    async fn last_failover_race(&self) -> Option<FailoverRecord> {
        match self.primary.try_as_group_handler() {
            Some(group) => group.last_failover_race().await,
            None => None,
        }
    }

    fn icon(&self) -> Option<String> {
        self.primary
            .try_as_group_handler()
            .and_then(GroupProxyAPIResponse::icon)
    }

    async fn as_map(&self) -> HashMap<String, Box<dyn Serialize + Send>> {
        let mut map = match self.primary.try_as_group_handler() {
            Some(group) => group.as_map().await,
            None => HashMap::new(),
        };
        map.insert(
            "routeRace".to_owned(),
            Box::new(self.route.name().to_owned()),
        );
        map
    }
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;

    use super::*;
    use crate::{
        app::{
            dispatcher::{ChainedStream, ChainedStreamWrapper},
            remote_content_manager::ProxyManager,
        },
        proxy::{
            HandlerCommonOptions,
            group::{selector::SelectorControl, urltest},
            mocks::{MockDummyOutboundHandler, MockDummyProxyProvider},
            utils::test_utils::noop::NoopResolver,
        },
    };

    #[tokio::test]
    async fn route_winner_is_visible_in_chain() {
        let mut primary = MockDummyOutboundHandler::new();
        primary.expect_name().return_const("GROUP".to_owned());
        primary
            .expect_connect_stream()
            .returning(|_, _| Err(io::Error::other("blocked")));

        let mut route = MockDummyOutboundHandler::new();
        route.expect_name().return_const("DIRECT".to_owned());
        route.expect_connect_stream().returning(|_, _| {
            let (stream, _) = tokio::io::duplex(64);
            let stream = ChainedStreamWrapper::new(stream);
            futures::executor::block_on(stream.append_to_chain("DIRECT"));
            Ok(Box::new(stream) as BoxedChainedStream)
        });
        let handler = Handler::new(
            Arc::new(primary),
            Arc::new(route),
            race::RACE_DELAY,
            race::RACE_DELAY,
        );

        let stream = handler
            .connect_stream(
                &Session::default(),
                Arc::new(crate::proxy::utils::test_utils::noop::NoopResolver),
            )
            .await
            .unwrap();
        assert_eq!(stream.chain().snapshot().await, ["DIRECT", "GROUP"]);
        assert_eq!(stream.chain().race_type().await, race::ROUTE_RACE_TYPE,);
    }

    #[tokio::test]
    async fn manual_group_selection_disables_route_race() {
        let mut selected = MockDummyOutboundHandler::new();
        selected.expect_name().return_const("selected".to_owned());
        selected
            .expect_connect_stream()
            .times(1)
            .returning(|_, _| Err(io::Error::other("dial failed")));
        let selected: AnyOutboundHandler = Arc::new(selected);

        let mut provider = MockDummyProxyProvider::new();
        provider.expect_name().return_const("provider".to_owned());
        provider.expect_touch().returning(|| ());
        provider
            .expect_proxies()
            .returning(move || vec![selected.clone()]);
        let resolver = Arc::new(NoopResolver);
        let primary = urltest::Handler::new(
            urltest::HandlerOptions {
                name: "group".to_owned(),
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
        primary.select("selected").await.unwrap();

        let mut route = MockDummyOutboundHandler::new();
        route.expect_name().return_const("DIRECT".to_owned());
        route.expect_connect_stream().times(0);
        let handler = Handler::new(
            Arc::new(primary),
            Arc::new(route),
            race::RACE_DELAY,
            race::RACE_DELAY,
        );

        assert!(
            handler
                .connect_stream(&Session::default(), resolver)
                .await
                .is_err()
        );
    }

    #[tokio::test]
    async fn outermost_route_race_owns_the_connection() {
        let mut primary = MockDummyOutboundHandler::new();
        primary.expect_name().return_const("GROUP".to_owned());
        primary
            .expect_connect_stream()
            .times(1)
            .returning(|_, _| Err(io::Error::other("blocked")));

        let mut inner_route = MockDummyOutboundHandler::new();
        inner_route
            .expect_name()
            .return_const("INNER-ROUTE".to_owned());
        inner_route.expect_connect_stream().times(0);
        let inner = Arc::new(Handler::new(
            Arc::new(primary),
            Arc::new(inner_route),
            Duration::ZERO,
            Duration::ZERO,
        ));

        let mut outer_route = MockDummyOutboundHandler::new();
        outer_route
            .expect_name()
            .return_const("OUTER-ROUTE".to_owned());
        outer_route
            .expect_connect_stream()
            .times(1)
            .returning(|_, _| {
                let (stream, _) = tokio::io::duplex(64);
                Ok(Box::new(ChainedStreamWrapper::new(stream)))
            });
        let handler = Handler::new(
            inner,
            Arc::new(outer_route),
            Duration::ZERO,
            Duration::ZERO,
        );
        let sess = Session {
            destination: "outer-route.test:443".parse().unwrap(),
            ..Default::default()
        };

        let stream = handler.connect_stream(&sess, Arc::new(NoopResolver)).await;
        assert_eq!(
            stream.unwrap().chain().race_type().await,
            race::ROUTE_RACE_TYPE,
        );
    }

    #[tokio::test]
    async fn matching_failover_candidate_runs_once_as_route() {
        let mut primary = MockDummyOutboundHandler::new();
        primary.expect_name().return_const("PRIMARY".to_owned());
        primary
            .expect_connect_stream()
            .times(1)
            .returning(|_, _| Err(io::Error::other("blocked")));
        let primary: AnyOutboundHandler = Arc::new(primary);

        let mut shared = MockDummyOutboundHandler::new();
        shared.expect_name().return_const("DIRECT".to_owned());
        shared.expect_connect_stream().times(1).returning(|_, _| {
            let (stream, _) = tokio::io::duplex(64);
            Ok(Box::new(ChainedStreamWrapper::new(stream)))
        });
        let shared: AnyOutboundHandler = Arc::new(shared);

        let mut provider = MockDummyProxyProvider::new();
        provider.expect_name().return_const("provider".to_owned());
        provider
            .expect_proxies()
            .returning(move || vec![primary.clone(), shared.clone()]);
        let resolver = Arc::new(NoopResolver);
        let group = urltest::Handler::new(
            urltest::HandlerOptions {
                name: "group".to_owned(),
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
        let route = group.get_proxies().await[1].clone();
        let handler = Handler::new(
            Arc::new(group),
            route,
            Duration::from_secs(1),
            Duration::from_secs(1),
        );
        let sess = Session {
            destination: "same-candidate.test:443".parse().unwrap(),
            ..Default::default()
        };

        let stream = handler.connect_stream(&sess, resolver).await.unwrap();
        assert_eq!(stream.chain().race_type().await, race::ROUTE_RACE_TYPE);
    }
}
