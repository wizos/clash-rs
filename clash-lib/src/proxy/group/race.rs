use std::{
    collections::HashMap,
    future::Future,
    io,
    pin::Pin,
    sync::{
        Arc, LazyLock, Mutex,
        atomic::{AtomicBool, Ordering},
    },
    task::{Context, Poll},
    time::{Duration, Instant},
};

use async_trait::async_trait;
use serde::Serialize;
use tokio::{
    io::{AsyncRead, AsyncWrite, ReadBuf},
    sync::{
        Mutex as AsyncMutex, MutexGuard, Notify, OnceCell, OwnedSemaphorePermit,
        Semaphore,
    },
};

use crate::{
    app::{
        dispatcher::{BoxedChainedStream, ChainedStream, ProxyChain},
        dns::ThreadSafeDNSResolver,
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

    pub async fn promote(
        &self,
        group: &str,
        from: String,
        winner: String,
        epoch: usize,
        before_commit: impl FnOnce(),
    ) -> bool {
        let _guard = self.lock().await;
        if self.epoch() != epoch {
            return false;
        }
        before_commit();
        self.advance();
        self.record(from.clone(), winner.clone()).await;
        tracing::info!(group, from, winner, "failover race promoted proxy");
        crate::app::events::emit_app("healthcheck", ());
        true
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Winner {
    Primary,
    Challenger,
}

type ConnectFuture =
    Pin<Box<dyn Future<Output = io::Result<BoxedChainedStream>> + Send>>;
type ConfirmedCallback = Box<dyn FnOnce(Winner, ProxyChain) + Send + Sync>;
type FailedCallback = Arc<dyn Fn(Winner) + Send + Sync>;

pub struct RaceCallbacks {
    confirmed: Option<ConfirmedCallback>,
    failed: FailedCallback,
}

impl RaceCallbacks {
    pub fn new(
        confirmed: impl FnOnce(Winner, ProxyChain) + Send + Sync + 'static,
        failed: impl Fn(Winner) + Send + Sync + 'static,
    ) -> Self {
        Self {
            confirmed: Some(Box::new(confirmed)),
            failed: Arc::new(failed),
        }
    }
}

pub fn group_callbacks(
    primary: AnyOutboundHandler,
    challenger: AnyOutboundHandler,
    proxy_manager: ProxyManager,
    test_url: String,
    on_challenger_confirmed: impl FnOnce() + Send + Sync + 'static,
) -> RaceCallbacks {
    let primary_failed = Arc::new(AtomicBool::new(false));
    let primary_failed_on_confirm = primary_failed.clone();
    let failed_primary = primary.clone();
    let failed_challenger = challenger.clone();
    let failed_manager = proxy_manager.clone();
    let failed_url = test_url.clone();
    RaceCallbacks::new(
        move |winner, chain| {
            if winner != Winner::Challenger {
                return;
            }
            on_challenger_confirmed();
            tokio::spawn(async move {
                chain.set_race_type(GROUP_RACE_TYPE).await;
                if !primary_failed_on_confirm.load(Ordering::Acquire) {
                    proxy_manager.check_after_failure(primary, &test_url).await;
                }
            });
        },
        move |winner| {
            let outbound = match winner {
                Winner::Primary => {
                    primary_failed.store(true, Ordering::Release);
                    failed_primary.clone()
                }
                Winner::Challenger => failed_challenger.clone(),
            };
            let manager = failed_manager.clone();
            let url = failed_url.clone();
            tokio::spawn(async move {
                manager.check_after_failure(outbound, &url).await;
            });
        },
    )
}

struct ConnectedPath {
    stream: BoxedChainedStream,
    names: Vec<String>,
}

struct GuardedStream {
    inner: BoxedChainedStream,
    guards: Option<(RaceSlot, OwnedSemaphorePermit)>,
}

impl GuardedStream {
    fn release(&mut self) {
        self.guards.take();
    }
}

#[async_trait]
impl ChainedStream for GuardedStream {
    fn chain(&self) -> &ProxyChain {
        self.inner.chain()
    }

    async fn append_to_chain(&self, name: &str) {
        self.inner.append_to_chain(name).await;
    }
}

impl AsyncRead for GuardedStream {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        Pin::new(self.inner.as_mut()).poll_read(cx, buf)
    }
}

impl AsyncWrite for GuardedStream {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        Pin::new(self.inner.as_mut()).poll_write(cx, buf)
    }

    fn poll_flush(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<io::Result<()>> {
        Pin::new(self.inner.as_mut()).poll_flush(cx)
    }

    fn poll_shutdown(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<io::Result<()>> {
        Pin::new(self.inner.as_mut()).poll_shutdown(cx)
    }
}

enum PathState {
    Connecting(
        Mutex<Pin<Box<dyn Future<Output = io::Result<ConnectedPath>> + Send>>>,
    ),
    Connected(ConnectedPath),
    Failed(String),
    Gone,
}

impl PathState {
    fn connecting(future: ConnectFuture) -> Self {
        Self::Connecting(Mutex::new(Box::pin(async move {
            let stream = future.await?;
            let names = stream.chain().snapshot().await;
            Ok(ConnectedPath { stream, names })
        })))
    }

    fn poll_connect(&mut self, cx: &mut Context<'_>) -> bool {
        let result = match self {
            Self::Connecting(future) => future
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner)
                .as_mut()
                .poll(cx),
            _ => return false,
        };
        match result {
            Poll::Ready(Ok(path)) => {
                *self = Self::Connected(path);
                false
            }
            Poll::Ready(Err(error)) => {
                *self = Self::Failed(error.to_string());
                true
            }
            Poll::Pending => false,
        }
    }

    fn error(&self) -> Option<&str> {
        match self {
            Self::Failed(error) => Some(error),
            _ => None,
        }
    }
}

struct FailureSignal {
    failed: AtomicBool,
    notify: Notify,
}

impl FailureSignal {
    fn new() -> Self {
        Self {
            failed: AtomicBool::new(false),
            notify: Notify::new(),
        }
    }

    fn fail(&self) {
        self.failed.store(true, Ordering::Release);
        self.notify.notify_waiters();
    }

    async fn wait(&self) {
        while !self.failed.load(Ordering::Acquire) {
            let notified = self.notify.notified();
            if self.failed.load(Ordering::Acquire) {
                break;
            }
            notified.await;
        }
    }
}

/// Keeps both paths eligible until one performs irreversible I/O. A successful
/// write selects that path and is never replayed; persistent race state is only
/// committed after the first downstream byte.
struct FirstIoRaceStream {
    primary: PathState,
    challenger: PathState,
    selected: Option<Winner>,
    confirmed: bool,
    chain: ProxyChain,
    initial_winner: Winner,
    initial_prefix_len: usize,
    callbacks: RaceCallbacks,
}

impl FirstIoRaceStream {
    async fn new(
        initial_winner: Winner,
        initial: BoxedChainedStream,
        other: PathState,
        callbacks: RaceCallbacks,
    ) -> Self {
        let names = initial.chain().snapshot().await;
        let chain = initial.chain().clone();
        let initial_prefix_len = names.len();
        let initial = PathState::Connected(ConnectedPath {
            stream: initial,
            names,
        });
        let (primary, challenger) = match initial_winner {
            Winner::Primary => (initial, other),
            Winner::Challenger => (other, initial),
        };
        Self {
            primary,
            challenger,
            selected: None,
            confirmed: false,
            chain,
            initial_winner,
            initial_prefix_len,
            callbacks,
        }
    }

    fn path_mut(&mut self, winner: Winner) -> &mut PathState {
        match winner {
            Winner::Primary => &mut self.primary,
            Winner::Challenger => &mut self.challenger,
        }
    }

    fn poll_connections(&mut self, cx: &mut Context<'_>) {
        if self.primary.poll_connect(cx) {
            self.fail(Winner::Primary);
        }
        if self.challenger.poll_connect(cx) {
            self.fail(Winner::Challenger);
        }
    }

    fn select(&mut self, winner: Winner) {
        self.selected = Some(winner);
        let loser = match winner {
            Winner::Primary => &mut self.challenger,
            Winner::Challenger => &mut self.primary,
        };
        *loser = PathState::Gone;
        if winner == Winner::Challenger
            && let PathState::Connected(path) = self.path_mut(winner)
            && let Some(stream) = path.stream.downcast_mut::<GuardedStream>()
        {
            stream.release();
        }
        if winner != self.initial_winner {
            let names = match self.path_mut(winner) {
                PathState::Connected(path) => path.names.clone(),
                _ => return,
            };
            let chain = self.chain.clone();
            let old_len = self.initial_prefix_len;
            tokio::spawn(async move {
                chain.replace_prefix(old_len, names).await;
            });
        }
    }

    fn confirm(&mut self, winner: Winner) {
        if self.confirmed {
            return;
        }
        self.confirmed = true;
        if let Some(callback) = self.callbacks.confirmed.take() {
            callback(winner, self.chain.clone());
        }
    }

    fn fail(&self, winner: Winner) {
        (self.callbacks.failed)(winner);
    }

    fn both_failed(&self) -> Option<io::Error> {
        match (self.primary.error(), self.challenger.error()) {
            (Some(primary), Some(challenger)) => Some(io::Error::other(format!(
                "racing paths failed: primary: {primary}; challenger: {challenger}"
            ))),
            _ => None,
        }
    }

    fn poll_read_path(
        &mut self,
        winner: Winner,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<usize>> {
        let selected = self.selected == Some(winner);
        let before = buf.filled().len();
        let PathState::Connected(path) = self.path_mut(winner) else {
            return Poll::Pending;
        };
        match Pin::new(path.stream.as_mut()).poll_read(cx, buf) {
            Poll::Ready(Ok(())) => {
                let read = buf.filled().len() - before;
                if read == 0 {
                    if selected {
                        if !self.confirmed {
                            self.fail(winner);
                        }
                        return Poll::Ready(Ok(0));
                    }
                    *self.path_mut(winner) = PathState::Failed(
                        "connection closed before data".to_owned(),
                    );
                    self.fail(winner);
                    Poll::Ready(Err(io::ErrorKind::UnexpectedEof.into()))
                } else {
                    Poll::Ready(Ok(read))
                }
            }
            Poll::Ready(Err(error)) => {
                *self.path_mut(winner) = PathState::Failed(error.to_string());
                self.fail(winner);
                Poll::Ready(Err(error))
            }
            Poll::Pending => Poll::Pending,
        }
    }

    fn poll_write_path(
        &mut self,
        winner: Winner,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        let PathState::Connected(path) = self.path_mut(winner) else {
            return Poll::Pending;
        };
        match Pin::new(path.stream.as_mut()).poll_write(cx, buf) {
            Poll::Ready(Ok(0)) => {
                *self.path_mut(winner) =
                    PathState::Failed("connection wrote zero bytes".to_owned());
                self.fail(winner);
                Poll::Ready(Err(io::ErrorKind::WriteZero.into()))
            }
            Poll::Ready(Err(error)) => {
                *self.path_mut(winner) = PathState::Failed(error.to_string());
                self.fail(winner);
                Poll::Ready(Err(error))
            }
            result => result,
        }
    }
}

#[async_trait]
impl ChainedStream for FirstIoRaceStream {
    fn chain(&self) -> &ProxyChain {
        &self.chain
    }

    async fn append_to_chain(&self, name: &str) {
        self.chain.push(name.to_owned()).await;
    }
}

impl AsyncRead for FirstIoRaceStream {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        self.poll_connections(cx);
        if let Some(winner) = self.selected {
            return match self.poll_read_path(winner, cx, buf) {
                Poll::Ready(Ok(read)) => {
                    if read != 0 {
                        self.confirm(winner);
                    }
                    Poll::Ready(Ok(()))
                }
                Poll::Ready(Err(error)) => Poll::Ready(Err(error)),
                Poll::Pending => Poll::Pending,
            };
        }

        for winner in [Winner::Primary, Winner::Challenger] {
            match self.poll_read_path(winner, cx, buf) {
                Poll::Ready(Ok(_)) => {
                    self.select(winner);
                    self.confirm(winner);
                    return Poll::Ready(Ok(()));
                }
                Poll::Ready(Err(_)) | Poll::Pending => {}
            }
        }
        if let Some(error) = self.both_failed() {
            Poll::Ready(Err(error))
        } else {
            Poll::Pending
        }
    }
}

impl AsyncWrite for FirstIoRaceStream {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        self.poll_connections(cx);
        if let Some(winner) = self.selected {
            return self.poll_write_path(winner, cx, buf);
        }

        for winner in [Winner::Primary, Winner::Challenger] {
            match self.poll_write_path(winner, cx, buf) {
                Poll::Ready(Ok(written)) => {
                    self.select(winner);
                    return Poll::Ready(Ok(written));
                }
                Poll::Ready(Err(_)) | Poll::Pending => {}
            }
        }
        if let Some(error) = self.both_failed() {
            Poll::Ready(Err(error))
        } else {
            Poll::Pending
        }
    }

    fn poll_flush(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<io::Result<()>> {
        let Some(winner) = self.selected else {
            return Poll::Ready(Ok(()));
        };
        let PathState::Connected(path) = self.path_mut(winner) else {
            return Poll::Ready(Err(io::ErrorKind::BrokenPipe.into()));
        };
        Pin::new(path.stream.as_mut()).poll_flush(cx)
    }

    fn poll_shutdown(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<io::Result<()>> {
        let winner = self.selected.unwrap_or(self.initial_winner);
        let PathState::Connected(path) = self.path_mut(winner) else {
            return Poll::Ready(Ok(()));
        };
        Pin::new(path.stream.as_mut()).poll_shutdown(cx)
    }
}

pub fn shared_key(scope: &str, challenger: &str, sess: &Session) -> String {
    format!(
        "{scope}:{challenger}:{}",
        sess.destination.to_string().to_ascii_lowercase(),
    )
}

pub async fn staggered_until_first_io<P, C, CFut, D, O>(
    primary: P,
    challenger: C,
    trigger: D,
    key: String,
    on_challenger_due: O,
    callbacks: RaceCallbacks,
) -> io::Result<BoxedChainedStream>
where
    P: Future<Output = io::Result<BoxedChainedStream>> + Send + 'static,
    C: FnOnce() -> CFut + Send + 'static,
    CFut: Future<Output = io::Result<BoxedChainedStream>> + Send + 'static,
    D: Future<Output = ()> + Send + 'static,
    O: FnOnce() + Send + 'static,
{
    let primary_failed = Arc::new(FailureSignal::new());
    let failure_signal = primary_failed.clone();
    let mut primary: ConnectFuture = Box::pin(async move {
        let result = primary.await;
        if result.is_err() {
            failure_signal.fail();
        }
        result
    });
    let mut challenger: ConnectFuture = Box::pin(async move {
        tokio::select! {
            _ = trigger => {}
            _ = primary_failed.wait() => {}
        }
        on_challenger_due();
        let slot = RaceSlot::acquire(key)
            .ok_or_else(|| io::Error::other("challenger suppressed by race slot"))?;
        let permit =
            EXTRA_CONNECTIONS.clone().try_acquire_owned().map_err(|_| {
                io::Error::other("challenger suppressed by connection limit")
            })?;
        let stream = challenger().await?;
        Ok(Box::new(GuardedStream {
            inner: stream,
            guards: Some((slot, permit)),
        }) as BoxedChainedStream)
    });

    tokio::select! {
        result = &mut primary => match result {
            Ok(stream) => Ok(Box::new(FirstIoRaceStream::new(
                Winner::Primary,
                stream,
                PathState::connecting(challenger),
                callbacks,
            ).await)),
            Err(primary_error) => {
                (callbacks.failed)(Winner::Primary);
                match challenger.await {
                Ok(stream) => Ok(Box::new(FirstIoRaceStream::new(
                    Winner::Challenger,
                    stream,
                    PathState::Failed(primary_error.to_string()),
                    callbacks,
                ).await)),
                Err(challenger_error) => {
                    (callbacks.failed)(Winner::Challenger);
                    Err(combined_error(primary_error, challenger_error))
                },
            }
            },
        },
        result = &mut challenger => match result {
            Ok(stream) => Ok(Box::new(FirstIoRaceStream::new(
                Winner::Challenger,
                stream,
                PathState::connecting(primary),
                callbacks,
            ).await)),
            Err(challenger_error) => {
                (callbacks.failed)(Winner::Challenger);
                match primary.await {
                Ok(stream) => Ok(Box::new(FirstIoRaceStream::new(
                    Winner::Primary,
                    stream,
                    PathState::Failed(challenger_error.to_string()),
                    callbacks,
                ).await)),
                Err(primary_error) => {
                    (callbacks.failed)(Winner::Primary);
                    Err(combined_error(primary_error, challenger_error))
                },
            }
            },
        },
    }
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
    callbacks: RaceCallbacks,
) -> io::Result<BoxedChainedStream> {
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
    if let Some(connector) = connector {
        let result = staggered_with_trigger(
            async move {
                let result = primary_connect
                    .connect_stream_with_connector(sess, primary_resolver, connector)
                    .await;
                if result.is_err() {
                    primary_manager
                        .check_after_failure(primary_for_check, &primary_url)
                        .await;
                }
                result
            },
            || async move {
                let result = challenger_connect
                    .connect_stream_with_connector(sess, resolver, connector)
                    .await;
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
        return Ok(Box::new(
            FirstIoRaceStream::new(
                result.0,
                result.1,
                PathState::Failed("connector race already resolved".to_owned()),
                callbacks,
            )
            .await,
        ));
    }

    let primary_sess = sess.clone();
    let challenger_sess = sess.clone();
    staggered_until_first_io(
        async move {
            primary_connect
                .connect_stream(&primary_sess, primary_resolver)
                .await
        },
        move || async move {
            let result = challenger_connect
                .connect_stream(&challenger_sess, resolver)
                .await;
            if result.is_err() {
                failure_context.mark_failover_failed();
            }
            result
        },
        tokio::time::sleep(delay),
        key,
        move || due_context.mark_failover_due(),
        callbacks,
    )
    .await
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
    use crate::app::dispatcher::ChainedStreamWrapper;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    #[tokio::test]
    async fn connected_primary_without_io_keeps_challenger_eligible() {
        let selected = Arc::new(AtomicUsize::new(0));
        let selected_for_callback = selected.clone();
        let challenger_calls = Arc::new(AtomicUsize::new(0));
        let calls = challenger_calls.clone();
        let mut stream = staggered_until_first_io(
            async {
                let (mut stream, peer) = tokio::io::duplex(1);
                stream.write_all(b"x").await.unwrap();
                tokio::spawn(async move {
                    std::future::pending::<()>().await;
                    drop(peer);
                });
                Ok(Box::new(ChainedStreamWrapper::new(stream))
                    as BoxedChainedStream)
            },
            move || {
                calls.fetch_add(1, Ordering::Relaxed);
                async {
                    let (stream, mut peer) = tokio::io::duplex(64);
                    tokio::spawn(async move {
                        let mut byte = [0];
                        peer.read_exact(&mut byte).await.unwrap();
                        peer.write_all(b"r").await.unwrap();
                    });
                    Ok(Box::new(ChainedStreamWrapper::new(stream))
                        as BoxedChainedStream)
                }
            },
            tokio::time::sleep(Duration::from_millis(1)),
            "first-io-primary-stalled".to_owned(),
            || {},
            RaceCallbacks::new(
                move |winner, _| {
                    selected_for_callback.store(
                        match winner {
                            Winner::Primary => 1,
                            Winner::Challenger => 2,
                        },
                        Ordering::Relaxed,
                    );
                },
                |_| {},
            ),
        )
        .await
        .unwrap();

        tokio::time::sleep(Duration::from_millis(5)).await;
        stream.write_all(b"q").await.unwrap();
        let mut response = [0];
        stream.read_exact(&mut response).await.unwrap();

        assert_eq!(response, *b"r");
        assert_eq!(challenger_calls.load(Ordering::Relaxed), 1);
        assert_eq!(selected.load(Ordering::Relaxed), 2);
    }

    #[tokio::test]
    async fn primary_data_before_delay_cancels_challenger() {
        let challenger_calls = Arc::new(AtomicUsize::new(0));
        let calls = challenger_calls.clone();
        let mut stream = staggered_until_first_io(
            async {
                let (stream, mut peer) = tokio::io::duplex(64);
                tokio::spawn(async move {
                    peer.write_all(b"ok").await.unwrap();
                });
                Ok(Box::new(ChainedStreamWrapper::new(stream))
                    as BoxedChainedStream)
            },
            move || {
                calls.fetch_add(1, Ordering::Relaxed);
                async { Err(io::Error::other("must not start")) }
            },
            tokio::time::sleep(Duration::from_millis(20)),
            "first-io-primary-fast".to_owned(),
            || {},
            RaceCallbacks::new(|_, _| {}, |_| {}),
        )
        .await
        .unwrap();

        let mut response = [0; 2];
        stream.read_exact(&mut response).await.unwrap();
        tokio::time::sleep(Duration::from_millis(30)).await;

        assert_eq!(response, *b"ok");
        assert_eq!(challenger_calls.load(Ordering::Relaxed), 0);
    }

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
