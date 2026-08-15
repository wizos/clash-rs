use std::{
    collections::HashMap,
    future::Future,
    io,
    sync::{
        Arc, LazyLock, Mutex,
        atomic::{AtomicBool, Ordering},
    },
    time::{Duration, Instant},
};

use serde::Serialize;
use tokio::sync::{Mutex as AsyncMutex, MutexGuard, Notify, OnceCell, Semaphore};

use crate::{
    app::{
        dispatcher::BoxedChainedStream, dns::ThreadSafeDNSResolver,
        remote_content_manager::ProxyManager,
    },
    proxy::{AnyOutboundHandler, utils::RemoteConnector},
    session::Session,
};

use super::GroupProxyAPIResponse;

pub const RACE_DELAY: Duration = Duration::from_millis(100);
pub const GROUP_RACE_TYPE: &str = "group";
pub const ROUTE_RACE_TYPE: &str = "route";
const SLOT_COOLDOWN: Duration = Duration::from_secs(1);
const SLOT_TIMEOUT: Duration = Duration::from_secs(30);
const MAX_SLOTS: usize = 4096;
const MAX_EXTRA_CONNECTIONS: usize = 64;

static RACE_SLOTS: LazyLock<Mutex<HashMap<String, Instant>>> =
    LazyLock::new(|| Mutex::new(HashMap::new()));
static EXTRA_CONNECTIONS: LazyLock<Arc<Semaphore>> =
    LazyLock::new(|| Arc::new(Semaphore::new(MAX_EXTRA_CONNECTIONS)));

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum FailoverCandidateKind {
    Measured,
    Sequential,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct FailoverCandidate {
    pub name: String,
    pub leaf: String,
    pub kind: FailoverCandidateKind,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct FailoverPlan {
    pub owner: String,
    pub candidate: String,
    pub candidate_leaf: String,
}

#[derive(Default)]
pub struct RaceContext {
    failover_plan: OnceCell<Option<FailoverPlan>>,
    failover_suppressed: AtomicBool,
    failover_due: AtomicBool,
    failover_due_notify: Notify,
    failover_failed: AtomicBool,
    failover_failed_notify: Notify,
    route_claimed: AtomicBool,
}

impl RaceContext {
    pub async fn failover_plan(
        &self,
        initial_name: &str,
        initial_group: &dyn GroupProxyAPIResponse,
    ) -> Option<FailoverPlan> {
        self.failover_plan
            .get_or_init(|| plan_failover(initial_name, initial_group))
            .await
            .clone()
    }

    pub fn suppress_failover(&self) {
        self.failover_suppressed.store(true, Ordering::Release);
    }

    pub fn failover_is_owned_by(&self, plan: &FailoverPlan, name: &str) -> bool {
        !self.failover_suppressed.load(Ordering::Acquire) && plan.owner == name
    }

    pub fn mark_failover_due(&self) {
        self.failover_due.store(true, Ordering::Release);
        self.failover_due_notify.notify_waiters();
    }

    pub async fn wait_failover_due(&self) {
        while !self.failover_due.load(Ordering::Acquire) {
            let notified = self.failover_due_notify.notified();
            if self.failover_due.load(Ordering::Acquire) {
                break;
            }
            notified.await;
        }
    }

    pub fn mark_failover_failed(&self) {
        self.failover_failed.store(true, Ordering::Release);
        self.failover_failed_notify.notify_waiters();
    }

    pub fn failover_failed(&self) -> bool {
        self.failover_failed.load(Ordering::Acquire)
    }

    pub async fn wait_failover_failed(&self) {
        while !self.failover_failed() {
            let notified = self.failover_failed_notify.notified();
            if self.failover_failed() {
                break;
            }
            notified.await;
        }
    }

    pub async fn wait_route_after_failover(&self, delay: Duration) {
        self.wait_failover_due().await;
        if self.failover_failed() {
            return;
        }
        tokio::select! {
            _ = tokio::time::sleep(delay) => {}
            _ = self.wait_failover_failed() => {}
        }
    }

    pub fn try_claim_route(&self) -> bool {
        self.route_claimed
            .compare_exchange(false, true, Ordering::AcqRel, Ordering::Acquire)
            .is_ok()
    }
}

pub async fn effective_leaf_name(mut handler: AnyOutboundHandler) -> String {
    let mut name = handler.name().to_owned();
    for _ in 0..16 {
        let Some(group) = handler.try_as_group_handler() else {
            break;
        };
        let Some(active) = group.get_active_proxy().await else {
            break;
        };
        name = active.name().to_owned();
        handler = active;
    }
    name
}

async fn plan_failover(
    initial_name: &str,
    initial_group: &dyn GroupProxyAPIResponse,
) -> Option<FailoverPlan> {
    let mut measured = None;
    let mut sequential = None;

    if initial_group.is_manually_selected().await {
        return None;
    }
    record_candidate(
        initial_name,
        initial_group.failover_race_candidate().await,
        &mut measured,
        &mut sequential,
    );

    let mut active = initial_group.get_active_proxy().await;
    for _ in 0..16 {
        let Some(handler) = active else {
            break;
        };
        let Some(group) = handler.try_as_group_handler() else {
            break;
        };
        if group.is_manually_selected().await {
            return None;
        }
        record_candidate(
            handler.name(),
            group.failover_race_candidate().await,
            &mut measured,
            &mut sequential,
        );
        active = group.get_active_proxy().await;
    }

    measured.or(sequential)
}

fn record_candidate(
    owner: &str,
    candidate: Option<FailoverCandidate>,
    measured: &mut Option<FailoverPlan>,
    sequential: &mut Option<FailoverPlan>,
) {
    let Some(candidate) = candidate else {
        return;
    };
    let plan = FailoverPlan {
        owner: owner.to_owned(),
        candidate: candidate.name,
        candidate_leaf: candidate.leaf,
    };
    match candidate.kind {
        FailoverCandidateKind::Measured => *measured = Some(plan),
        FailoverCandidateKind::Sequential => *sequential = Some(plan),
    }
}

#[derive(Clone, Debug, Serialize)]
pub struct FailoverRecord {
    pub from: String,
    pub winner: String,
}

pub struct FailoverState {
    enabled: bool,
    epoch: std::sync::atomic::AtomicUsize,
    change_lock: AsyncMutex<()>,
    last: tokio::sync::RwLock<Option<FailoverRecord>>,
}

impl FailoverState {
    pub fn new(enabled: bool) -> Self {
        Self {
            enabled,
            epoch: 0.into(),
            change_lock: AsyncMutex::new(()),
            last: tokio::sync::RwLock::new(None),
        }
    }

    pub fn enabled(&self) -> bool {
        self.enabled
    }

    pub fn epoch(&self) -> usize {
        self.epoch.load(std::sync::atomic::Ordering::Acquire)
    }

    pub async fn lock(&self) -> MutexGuard<'_, ()> {
        self.change_lock.lock().await
    }

    pub fn advance(&self) {
        self.epoch.fetch_add(1, std::sync::atomic::Ordering::AcqRel);
    }

    pub async fn clear(&self) {
        *self.last.write().await = None;
    }

    pub async fn record(&self, from: String, winner: String) {
        *self.last.write().await = Some(FailoverRecord { from, winner });
    }

    pub async fn last(&self) -> Option<FailoverRecord> {
        self.last.read().await.clone()
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Winner {
    Primary,
    Challenger,
}

pub fn shared_key(scope: &str, challenger: &str, sess: &Session) -> String {
    format!(
        "{scope}:{challenger}:{}",
        sess.destination.to_string().to_ascii_lowercase(),
    )
}

pub fn indexes_after(len: usize, current: usize) -> impl Iterator<Item = usize> {
    (1..len).map(move |offset| (current + offset) % len)
}

#[allow(clippy::too_many_arguments)]
pub async fn connect_group_stream(
    primary: AnyOutboundHandler,
    challenger: AnyOutboundHandler,
    sess: &Session,
    resolver: ThreadSafeDNSResolver,
    connector: Option<&dyn RemoteConnector>,
    proxy_manager: &ProxyManager,
    test_url: &str,
    delay: Duration,
    key: String,
) -> io::Result<(Winner, BoxedChainedStream)> {
    let primary_connect = primary.clone();
    let challenger_connect = challenger.clone();
    let primary_for_check = primary.clone();
    let challenger_for_check = challenger.clone();
    let primary_manager = proxy_manager.clone();
    let challenger_manager = proxy_manager.clone();
    let primary_url = test_url.to_owned();
    let challenger_url = test_url.to_owned();
    let primary_resolver = resolver.clone();
    let due_context = sess.race_context.clone();
    let failure_context = sess.race_context.clone();
    let result = staggered_with_trigger(
        async move {
            let result = match connector {
                Some(connector) => {
                    primary_connect
                        .connect_stream_with_connector(
                            sess,
                            primary_resolver,
                            connector,
                        )
                        .await
                }
                None => primary_connect.connect_stream(sess, primary_resolver).await,
            };
            if result.is_err() {
                primary_manager
                    .check_after_failure(primary_for_check, &primary_url)
                    .await;
            }
            result
        },
        || async move {
            let result = match connector {
                Some(connector) => {
                    challenger_connect
                        .connect_stream_with_connector(sess, resolver, connector)
                        .await
                }
                None => challenger_connect.connect_stream(sess, resolver).await,
            };
            if result.is_err() {
                failure_context.mark_failover_failed();
                challenger_manager
                    .check_after_failure(challenger_for_check, &challenger_url)
                    .await;
            }
            result
        },
        tokio::time::sleep(delay),
        key,
        move || due_context.mark_failover_due(),
    )
    .await?;
    if result.0 == Winner::Challenger {
        result.1.chain().set_race_type(GROUP_RACE_TYPE).await;
        proxy_manager.check_after_failure(primary, test_url).await;
    }
    Ok(result)
}

#[cfg(test)]
pub async fn staggered<T, P, C, CFut>(
    primary: P,
    challenger: C,
    delay: Duration,
    key: String,
) -> io::Result<(Winner, T)>
where
    P: Future<Output = io::Result<T>>,
    C: FnOnce() -> CFut,
    CFut: Future<Output = io::Result<T>>,
{
    staggered_with_trigger(
        primary,
        challenger,
        tokio::time::sleep(delay),
        key,
        || {},
    )
    .await
}

pub async fn staggered_with_trigger<T, P, C, CFut, D, O>(
    primary: P,
    challenger: C,
    trigger: D,
    key: String,
    on_challenger_due: O,
) -> io::Result<(Winner, T)>
where
    P: Future<Output = io::Result<T>>,
    C: FnOnce() -> CFut,
    CFut: Future<Output = io::Result<T>>,
    D: Future<Output = ()>,
    O: FnOnce(),
{
    let primary = primary;
    tokio::pin!(primary);
    tokio::pin!(trigger);
    let mut challenger = Some(challenger);
    let mut on_challenger_due = Some(on_challenger_due);

    let primary_error = tokio::select! {
        result = &mut primary => match result {
            Ok(value) => return Ok((Winner::Primary, value)),
            Err(error) => error,
        },
        _ = &mut trigger => {
            on_challenger_due.take().expect("challenger due once")();
            let slot = RaceSlot::acquire(key.clone());
            let permit = slot.as_ref().and_then(|_| {
                EXTRA_CONNECTIONS.clone().try_acquire_owned().ok()
            });
            if let (Some(_slot), Some(_permit)) = (slot, permit) {
                let second = challenger.take().expect("challenger used once")();
                tokio::pin!(second);
                return tokio::select! {
                    result = &mut primary => match result {
                        Ok(value) => Ok((Winner::Primary, value)),
                        Err(first_error) => second.await
                            .map(|value| (Winner::Challenger, value))
                            .map_err(|second_error| combined_error(first_error, second_error)),
                    },
                    result = &mut second => match result {
                        Ok(value) => Ok((Winner::Challenger, value)),
                        Err(second_error) => primary.await
                            .map(|value| (Winner::Primary, value))
                            .map_err(|first_error| combined_error(first_error, second_error)),
                    },
                };
            }
            return primary.await.map(|value| (Winner::Primary, value));
        }
    };

    on_challenger_due.take().expect("challenger due once")();
    let slot = RaceSlot::acquire(key);
    let permit = slot
        .as_ref()
        .and_then(|_| EXTRA_CONNECTIONS.clone().try_acquire_owned().ok());
    if let (Some(_slot), Some(_permit)) = (slot, permit) {
        return challenger.take().expect("challenger used once")()
            .await
            .map(|value| (Winner::Challenger, value))
            .map_err(|second_error| combined_error(primary_error, second_error));
    }
    Err(primary_error)
}

fn combined_error(first: io::Error, second: io::Error) -> io::Error {
    io::Error::other(format!(
        "racing paths failed: primary: {first}; challenger: {second}"
    ))
}

struct RaceSlot {
    key: String,
}

impl RaceSlot {
    fn acquire(key: String) -> Option<Self> {
        let now = Instant::now();
        let mut slots = RACE_SLOTS
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        slots.retain(|_, expires| *expires > now);
        if slots.contains_key(&key) || slots.len() >= MAX_SLOTS {
            return None;
        }
        slots.insert(key.clone(), now + SLOT_TIMEOUT);
        Some(Self { key })
    }
}

impl Drop for RaceSlot {
    fn drop(&mut self) {
        let mut slots = RACE_SLOTS
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        slots.insert(self.key.clone(), Instant::now() + SLOT_COOLDOWN);
    }
}

#[cfg(test)]
mod tests {
    use std::sync::{
        Arc,
        atomic::{AtomicUsize, Ordering},
    };

    use super::*;

    #[tokio::test]
    async fn fast_primary_does_not_start_challenger() {
        let calls = Arc::new(AtomicUsize::new(0));
        let challenger_calls = calls.clone();
        let (winner, value) = staggered(
            async { Ok(1) },
            move || {
                challenger_calls.fetch_add(1, Ordering::Relaxed);
                async { Ok(2) }
            },
            Duration::from_millis(1),
            "fast-primary".to_owned(),
        )
        .await
        .unwrap();

        assert_eq!((winner, value), (Winner::Primary, 1));
        assert_eq!(calls.load(Ordering::Relaxed), 0);
    }

    #[tokio::test]
    async fn primary_error_starts_challenger_without_waiting() {
        let started = Instant::now();
        let (winner, value) = staggered(
            async { Err(io::Error::other("failed")) },
            || async { Ok(2) },
            Duration::from_secs(1),
            "failed-primary".to_owned(),
        )
        .await
        .unwrap();

        assert_eq!((winner, value), (Winner::Challenger, 2));
        assert!(started.elapsed() < Duration::from_millis(100));
    }

    #[tokio::test]
    async fn duplicate_slot_suppresses_challenger_after_primary_error() {
        let key = "duplicate-after-error".to_owned();
        let _slot = RaceSlot::acquire(key.clone()).unwrap();
        let calls = Arc::new(AtomicUsize::new(0));
        let challenger_calls = calls.clone();
        let result = staggered(
            async { Err::<usize, _>(io::Error::other("failed")) },
            move || {
                challenger_calls.fetch_add(1, Ordering::Relaxed);
                async { Ok(2) }
            },
            Duration::from_secs(1),
            key,
        )
        .await;

        assert!(result.is_err());
        assert_eq!(calls.load(Ordering::Relaxed), 0);
    }

    #[test]
    fn candidate_order_wraps_once_after_current() {
        assert_eq!(indexes_after(4, 2).collect::<Vec<_>>(), [3, 0, 1]);
    }

    #[test]
    fn measured_candidates_win_before_depth_and_depth_breaks_ties() {
        let mut measured = None;
        let mut sequential = None;
        record_candidate(
            "outer",
            Some(FailoverCandidate {
                name: "outer-fast".to_owned(),
                leaf: "outer-fast".to_owned(),
                kind: FailoverCandidateKind::Measured,
            }),
            &mut measured,
            &mut sequential,
        );
        record_candidate(
            "inner",
            Some(FailoverCandidate {
                name: "inner-next".to_owned(),
                leaf: "inner-next".to_owned(),
                kind: FailoverCandidateKind::Sequential,
            }),
            &mut measured,
            &mut sequential,
        );
        assert_eq!(measured.as_ref().unwrap().owner, "outer");

        record_candidate(
            "inner",
            Some(FailoverCandidate {
                name: "inner-fast".to_owned(),
                leaf: "inner-fast".to_owned(),
                kind: FailoverCandidateKind::Measured,
            }),
            &mut measured,
            &mut sequential,
        );
        assert_eq!(measured.unwrap().owner, "inner");
    }

    #[tokio::test(start_paused = true)]
    async fn route_delay_is_anchored_to_failover_due() {
        let context = Arc::new(RaceContext::default());
        let waiting_context = context.clone();
        let wait = tokio::spawn(async move {
            waiting_context
                .wait_route_after_failover(Duration::from_millis(100))
                .await;
        });

        tokio::time::advance(Duration::from_secs(1)).await;
        assert!(!wait.is_finished());
        context.mark_failover_due();
        tokio::task::yield_now().await;
        tokio::time::advance(Duration::from_millis(99)).await;
        assert!(!wait.is_finished());
        tokio::time::advance(Duration::from_millis(1)).await;
        wait.await.unwrap();

        let context = Arc::new(RaceContext::default());
        context.mark_failover_due();
        let waiting_context = context.clone();
        let wait = tokio::spawn(async move {
            waiting_context
                .wait_route_after_failover(Duration::from_secs(60))
                .await;
        });
        tokio::task::yield_now().await;
        context.mark_failover_failed();
        tokio::task::yield_now().await;
        assert!(wait.is_finished());
    }
}
