use std::{
    collections::{HashMap, VecDeque},
    sync::{Arc, Mutex as StdMutex, Weak, atomic::Ordering},
};

use chrono::Utc;
use memory_stats::memory_stats;
use portable_atomic::AtomicU64;
use serde::Serialize;
use tokio::{
    sync::{Mutex, RwLock, oneshot::Sender},
    task::JoinHandle,
};
use tokio_util::sync::CancellationToken;

use crate::session::Session;

use super::tracked::Tracked;

/// Per-user traffic since the last drain.  Both upload and download are in
/// bytes.
#[derive(Serialize, Clone, Debug, Default)]
pub struct UserTraffic {
    pub upload: u64,
    pub download: u64,
}

#[derive(Default, Debug)]
struct ProxyChainState {
    names: Vec<String>,
    race_type: String,
}

#[derive(Default, Clone, Debug)]
pub struct ProxyChain(Arc<RwLock<ProxyChainState>>);

impl ProxyChain {
    pub async fn push(&self, s: String) {
        self.0.write().await.names.push(s);
    }

    pub async fn snapshot(&self) -> Vec<String> {
        self.0.read().await.names.clone()
    }

    pub async fn replace_prefix(&self, old_len: usize, mut names: Vec<String>) {
        let mut state = self.0.write().await;
        let old_len = old_len.min(state.names.len());
        names.extend(state.names.drain(old_len..));
        state.names = names;
    }

    pub async fn set_race_type(&self, race_type: &str) {
        self.0.write().await.race_type = race_type.to_owned();
    }

    pub async fn race_type(&self) -> String {
        self.0.read().await.race_type.clone()
    }
}

#[derive(Serialize, Default)]
pub struct TrackerInfo {
    #[serde(rename = "id")]
    pub uuid: uuid::Uuid,
    #[serde(rename = "metadata")]
    pub session: HashMap<String, Box<dyn erased_serde::Serialize + Send + Sync>>,
    #[serde(rename = "upload")]
    pub upload_total: AtomicU64,
    #[serde(rename = "download")]
    pub download_total: AtomicU64,
    #[serde(rename = "start")]
    pub start_time: chrono::DateTime<Utc>,
    #[serde(rename = "chains")]
    pub proxy_chain: Vec<String>,
    #[serde(rename = "rule")]
    pub rule: String,
    #[serde(rename = "rulePayload")]
    pub rule_payload: String,
    #[serde(rename = "raceType", skip_serializing_if = "String::is_empty")]
    pub race_type: String,

    #[serde(skip)]
    pub proxy_chain_holder: ProxyChain,
    #[serde(skip)]
    pub session_holder: Session,
    #[serde(skip)]
    pub is_proxy: bool,

    /// Per-user byte counters, separate from `upload_total`/`download_total`.
    /// Only incremented when `session_holder.inbound_user` is set.
    /// Swapped to 0 on drain — never touched by `snapshot()`.
    #[serde(skip)]
    pub user_upload: AtomicU64,
    #[serde(skip)]
    pub user_download: AtomicU64,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct ActivityEvent<'a> {
    #[serde(flatten)]
    tracker: &'a TrackerInfo,
    status: &'a str,
    revision: u8,
    phase: &'a str,
    failure_stage: &'a str,
    error: &'a str,
    route_proxy: &'a str,
    end: Option<chrono::DateTime<Utc>>,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct Snapshot {
    download_total: u64,
    upload_total: u64,
    connections: Vec<TrackerInfo>,
    memory: usize,
}

type ConnectionMap = HashMap<uuid::Uuid, (Tracked, Sender<()>)>;

pub struct Manager {
    connections: Arc<Mutex<ConnectionMap>>,
    closed_flows: Arc<Mutex<VecDeque<Arc<TrackerInfo>>>>,
    upload_temp: AtomicU64,
    download_temp: AtomicU64,
    upload_blip: AtomicU64,
    download_blip: AtomicU64,
    upload_total: AtomicU64,
    download_total: AtomicU64,
    proxy_upload_temp: AtomicU64,
    proxy_download_temp: AtomicU64,
    proxy_upload_blip: AtomicU64,
    proxy_download_blip: AtomicU64,
    proxy_upload_total: AtomicU64,
    proxy_download_total: AtomicU64,
    /// Bytes accumulated from **closed** connections, keyed by inbound_user.
    /// Drained (and reset) by [`Manager::drain_user_stats`].
    user_period_stats: Arc<Mutex<HashMap<String, UserTraffic>>>,
    cancel_token: CancellationToken,
    task_handle: StdMutex<Option<JoinHandle<()>>>,
}

impl Manager {
    pub fn new() -> Arc<Self> {
        let v = Arc::new(Self {
            connections: Arc::new(Mutex::new(HashMap::new())),
            closed_flows: Arc::new(Mutex::new(VecDeque::new())),
            upload_temp: AtomicU64::new(0),
            download_temp: AtomicU64::new(0),
            upload_blip: AtomicU64::new(0),
            download_blip: AtomicU64::new(0),
            upload_total: AtomicU64::new(0),
            download_total: AtomicU64::new(0),
            proxy_upload_temp: AtomicU64::new(0),
            proxy_download_temp: AtomicU64::new(0),
            proxy_upload_blip: AtomicU64::new(0),
            proxy_download_blip: AtomicU64::new(0),
            proxy_upload_total: AtomicU64::new(0),
            proxy_download_total: AtomicU64::new(0),
            user_period_stats: Arc::new(Mutex::new(HashMap::new())),
            cancel_token: CancellationToken::new(),
            task_handle: StdMutex::new(None),
        });
        let manager = Arc::downgrade(&v);
        let cancel_token = v.cancel_token.clone();
        let task_handle = tokio::spawn(async move {
            Self::kick_off(manager, cancel_token).await;
        });
        *v.task_handle
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner()) = Some(task_handle);
        v
    }

    pub async fn shutdown(&self) {
        self.cancel_token.cancel();
        if let Some(task_handle) = self.take_task_handle() {
            let _ = task_handle.await;
        }
    }

    pub async fn track(&self, item: Tracked, close_notify: Sender<()>) {
        let event = Self::tracker_snapshot(&item.tracker_info()).await;
        let mut connections = self.connections.lock().await;
        connections.insert(item.id(), (item, close_notify));
        drop(connections);
        crate::app::events::emit("request", &event);
        let route_proxy = event.proxy_chain.last().map(String::as_str).unwrap_or("");
        Self::emit_activity(
            &event,
            "connected",
            2,
            "connected",
            "",
            "",
            route_proxy,
            None,
        );
    }

    #[allow(clippy::too_many_arguments)]
    pub fn emit_activity_for_session(
        id: uuid::Uuid,
        start_time: chrono::DateTime<Utc>,
        session: &Session,
        rule: &str,
        rule_payload: &str,
        route_proxy: &str,
        status: &str,
        revision: u8,
        phase: &str,
        failure_stage: &str,
        error: &str,
    ) {
        let tracker = TrackerInfo {
            uuid: id,
            session: session.as_map(),
            start_time,
            rule: rule.to_owned(),
            rule_payload: rule_payload.to_owned(),
            ..Default::default()
        };
        let end = matches!(status, "failed" | "rejected").then(Utc::now);
        Self::emit_activity(
            &tracker,
            status,
            revision,
            phase,
            failure_stage,
            error,
            route_proxy,
            end,
        );
    }

    #[allow(clippy::too_many_arguments)]
    fn emit_activity(
        tracker: &TrackerInfo,
        status: &str,
        revision: u8,
        phase: &str,
        failure_stage: &str,
        error: &str,
        route_proxy: &str,
        end: Option<chrono::DateTime<Utc>>,
    ) {
        crate::app::events::emit(
            "activity",
            ActivityEvent {
                tracker,
                status,
                revision,
                phase,
                failure_stage,
                error,
                route_proxy,
                end,
            },
        );
    }

    /// Untrack a connection.
    /// This method is not async because it is called in Drop.
    /// When the connection has an inbound_user, its final byte counts are
    /// accumulated into `user_period_stats` so they survive connection close.
    pub fn untrack(&self, id: uuid::Uuid) {
        let connections = self.connections.clone();
        let user_period_stats = self.user_period_stats.clone();
        let closed_flows = self.closed_flows.clone();

        tokio::spawn(async move {
            let mut connections = connections.lock().await;
            if let Some((tracked, _)) = connections.remove(&id) {
                let info = tracked.tracker_info();
                // Atomically take the remaining user-accounting bytes.
                // upload_total/download_total are left intact for /connections.
                let upload = info.user_upload.swap(0, Ordering::AcqRel);
                let download = info.user_download.swap(0, Ordering::AcqRel);
                if let Some(ref user) = info.session_holder.inbound_user
                    && (upload > 0 || download > 0)
                {
                    let mut stats = user_period_stats.lock().await;
                    let entry = stats
                        .entry(user.clone())
                        .or_insert_with(UserTraffic::default);
                    entry.upload += upload;
                    entry.download += download;
                }

                // Push to the closed_flows ring buffer (cap 1000).
                let mut ring = closed_flows.lock().await;
                ring.push_back(info.clone());
                if ring.len() > 1000 {
                    ring.pop_front();
                }
                drop(ring);

                let event = Self::tracker_snapshot(&info).await;
                let route_proxy =
                    event.proxy_chain.last().map(String::as_str).unwrap_or("");
                Self::emit_activity(
                    &event,
                    "closed",
                    3,
                    "closed",
                    "",
                    "",
                    route_proxy,
                    Some(Utc::now()),
                );
            }
        });
    }

    /// Return `Arc<TrackerInfo>` for every currently-active connection.
    /// Unlike `snapshot()`, this preserves the full `session_holder` so
    /// callers can access destination, source, and network fields directly.
    pub async fn active_connections_snapshot(&self) -> Vec<Arc<TrackerInfo>> {
        let conns = self.connections.lock().await;
        conns
            .values()
            .map(|(tracked, _)| tracked.tracker_info())
            .collect()
    }

    /// Return a snapshot of recently closed connections (up to 1000 entries).
    pub async fn closed_flows_snapshot(&self) -> Vec<Arc<TrackerInfo>> {
        let ring = self.closed_flows.lock().await;
        ring.iter().cloned().collect()
    }

    /// Return per-user traffic accumulated since the last call (for both closed
    /// and currently-active connections) and reset all counters.
    ///
    /// Called by the `/user-stats` REST endpoint so FAC can poll for deltas.
    pub async fn drain_user_stats(&self) -> HashMap<String, UserTraffic> {
        // Drain the closed-connection accumulator.
        let mut result: HashMap<String, UserTraffic> = {
            let mut stats = self.user_period_stats.lock().await;
            std::mem::take(&mut *stats)
        };

        // Include bytes from still-active connections by atomically swapping
        // their user counters to 0. upload_total/download_total are untouched
        // so /connections keeps seeing the correct cumulative values.
        let connections = self.connections.lock().await;
        for (tracked, _) in connections.values() {
            let info = tracked.tracker_info();
            if let Some(ref user) = info.session_holder.inbound_user {
                let upload = info.user_upload.swap(0, Ordering::AcqRel);
                let download = info.user_download.swap(0, Ordering::AcqRel);
                if upload > 0 || download > 0 {
                    let entry = result.entry(user.clone()).or_default();
                    entry.upload += upload;
                    entry.download += download;
                }
            }
        }

        result
    }

    pub async fn close(&self, id: uuid::Uuid) -> bool {
        let mut connections = self.connections.lock().await;
        if let Some((tracked, close_notify)) = connections.remove(&id) {
            let event = Self::tracker_snapshot(&tracked.tracker_info()).await;
            let route_proxy =
                event.proxy_chain.last().map(String::as_str).unwrap_or("");
            Self::emit_activity(
                &event,
                "closed",
                3,
                "closed",
                "",
                "",
                route_proxy,
                Some(Utc::now()),
            );
            let _ = close_notify.send(());
            true
        } else {
            false
        }
    }

    pub async fn close_all(&self) {
        let connections = self.connections.clone();

        let mut connections = connections.lock().await;
        for (_, (tracked, close_notify)) in connections.drain() {
            let event = Self::tracker_snapshot(&tracked.tracker_info()).await;
            let route_proxy =
                event.proxy_chain.last().map(String::as_str).unwrap_or("");
            Self::emit_activity(
                &event,
                "closed",
                3,
                "closed",
                "",
                "",
                route_proxy,
                Some(Utc::now()),
            );
            let _ = close_notify.send(());
        }
    }

    pub fn push_uploaded(&self, n: usize, is_proxy: bool) {
        self.upload_temp
            .fetch_add(n as u64, std::sync::atomic::Ordering::Relaxed);
        self.upload_total
            .fetch_add(n as u64, std::sync::atomic::Ordering::Relaxed);
        if is_proxy {
            self.proxy_upload_temp
                .fetch_add(n as u64, std::sync::atomic::Ordering::Relaxed);
            self.proxy_upload_total
                .fetch_add(n as u64, std::sync::atomic::Ordering::Relaxed);
        }
    }

    pub fn push_downloaded(&self, n: usize, is_proxy: bool) {
        self.download_temp
            .fetch_add(n as u64, std::sync::atomic::Ordering::Relaxed);
        self.download_total
            .fetch_add(n as u64, std::sync::atomic::Ordering::Relaxed);
        if is_proxy {
            self.proxy_download_temp
                .fetch_add(n as u64, std::sync::atomic::Ordering::Relaxed);
            self.proxy_download_total
                .fetch_add(n as u64, std::sync::atomic::Ordering::Relaxed);
        }
    }

    pub fn now(&self, only_proxy: bool) -> (u64, u64) {
        if only_proxy {
            (
                self.proxy_upload_blip.load(Ordering::Relaxed),
                self.proxy_download_blip.load(Ordering::Relaxed),
            )
        } else {
            (
                self.upload_blip.load(Ordering::Relaxed),
                self.download_blip.load(Ordering::Relaxed),
            )
        }
    }

    pub async fn snapshot(&self, only_proxy: bool) -> Snapshot {
        let mut connections = vec![];
        let conns = self.connections.lock().await;
        for v in conns.values() {
            connections.push(Self::tracker_snapshot(&v.0.tracker_info()).await);
        }

        Snapshot {
            download_total: if only_proxy {
                self.proxy_download_total.load(Ordering::Relaxed)
            } else {
                self.download_total.load(Ordering::Relaxed)
            },
            upload_total: if only_proxy {
                self.proxy_upload_total.load(Ordering::Relaxed)
            } else {
                self.upload_total.load(Ordering::Relaxed)
            },
            connections,
            memory: self.memory_usage(),
        }
    }

    async fn tracker_snapshot(tracker: &Arc<TrackerInfo>) -> TrackerInfo {
        TrackerInfo {
            uuid: tracker.uuid,
            upload_total: AtomicU64::new(
                tracker.upload_total.load(Ordering::Acquire),
            ),
            download_total: AtomicU64::new(
                tracker.download_total.load(Ordering::Acquire),
            ),
            start_time: tracker.start_time,
            proxy_chain: tracker.proxy_chain_holder.snapshot().await,
            rule: tracker.rule.clone(),
            rule_payload: tracker.rule_payload.clone(),
            race_type: tracker.proxy_chain_holder.race_type().await,
            session: tracker.session_holder.as_map(),
            ..Default::default()
        }
    }

    #[allow(dead_code)]
    pub fn reset_statistic(&self) {
        self.upload_temp.store(0, Ordering::Relaxed);
        self.upload_blip.store(0, Ordering::Relaxed);
        self.upload_total.store(0, Ordering::Relaxed);
        self.download_temp.store(0, Ordering::Relaxed);
        self.download_blip.store(0, Ordering::Relaxed);
        self.download_total.store(0, Ordering::Relaxed);
        self.proxy_upload_temp.store(0, Ordering::Relaxed);
        self.proxy_upload_blip.store(0, Ordering::Relaxed);
        self.proxy_upload_total.store(0, Ordering::Relaxed);
        self.proxy_download_temp.store(0, Ordering::Relaxed);
        self.proxy_download_blip.store(0, Ordering::Relaxed);
        self.proxy_download_total.store(0, Ordering::Relaxed);
    }

    pub fn memory_usage(&self) -> usize {
        memory_stats().map(|x| x.physical_mem).unwrap_or(0)
    }

    /// Test helper: directly populate `user_period_stats` to simulate closed
    /// connections without going through the full `Tracked` machinery.
    #[cfg(test)]
    pub async fn inject_closed_user_bytes(
        &self,
        user: &str,
        upload: u64,
        download: u64,
    ) {
        let mut stats = self.user_period_stats.lock().await;
        let entry = stats.entry(user.to_string()).or_default();
        entry.upload += upload;
        entry.download += download;
    }

    async fn kick_off(manager: Weak<Self>, cancel_token: CancellationToken) {
        let mut ticker = tokio::time::interval(std::time::Duration::from_secs(1));
        loop {
            tokio::select! {
                _ = cancel_token.cancelled() => break,
                _ = ticker.tick() => {
                    let Some(manager) = manager.upgrade() else {
                        break;
                    };
                    manager.upload_blip.store(
                        manager.upload_temp.load(Ordering::Relaxed),
                        Ordering::Relaxed,
                    );
                    manager.upload_temp.store(0, Ordering::Relaxed);
                    manager.download_blip.store(
                        manager.download_temp.load(Ordering::Relaxed),
                        Ordering::Relaxed,
                    );
                    manager.download_temp.store(0, Ordering::Relaxed);
                    manager.proxy_upload_blip.store(
                        manager.proxy_upload_temp.load(Ordering::Relaxed),
                        Ordering::Relaxed,
                    );
                    manager.proxy_upload_temp.store(0, Ordering::Relaxed);
                    manager.proxy_download_blip.store(
                        manager.proxy_download_temp.load(Ordering::Relaxed),
                        Ordering::Relaxed,
                    );
                    manager.proxy_download_temp.store(0, Ordering::Relaxed);
                }
            }
        }
    }

    fn take_task_handle(&self) -> Option<JoinHandle<()>> {
        self.task_handle
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .take()
    }
}

impl Drop for Manager {
    fn drop(&mut self) {
        self.cancel_token.cancel();
        if let Some(task_handle) = self.take_task_handle() {
            task_handle.abort();
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_drain_user_stats_empty() {
        let mgr = Manager::new();
        let stats = mgr.drain_user_stats().await;
        assert!(stats.is_empty(), "fresh manager should have no user stats");
    }

    #[tokio::test]
    async fn test_shutdown_releases_background_task() {
        let mgr = Manager::new();
        let weak = Arc::downgrade(&mgr);

        mgr.shutdown().await;
        assert!(mgr.cancel_token.is_cancelled());
        assert!(mgr.take_task_handle().is_none());

        drop(mgr);
        assert!(weak.upgrade().is_none());
    }

    #[tokio::test]
    async fn test_drain_user_stats_returns_closed_connection_bytes() {
        let mgr = Manager::new();
        mgr.inject_closed_user_bytes("user1", 1000, 2000).await;

        let stats = mgr.drain_user_stats().await;
        let u = stats.get("user1").expect("user1 not found");
        assert_eq!(u.upload, 1000);
        assert_eq!(u.download, 2000);
    }

    #[tokio::test]
    async fn test_drain_user_stats_resets_on_read() {
        let mgr = Manager::new();
        mgr.inject_closed_user_bytes("user1", 500, 750).await;

        let first = mgr.drain_user_stats().await;
        assert!(!first.is_empty());

        let second = mgr.drain_user_stats().await;
        assert!(
            second.is_empty(),
            "second drain should be empty after reset"
        );
    }

    #[tokio::test]
    async fn test_drain_user_stats_multiple_users() {
        let mgr = Manager::new();
        mgr.inject_closed_user_bytes("alice", 100, 200).await;
        mgr.inject_closed_user_bytes("bob", 300, 400).await;

        let stats = mgr.drain_user_stats().await;
        assert_eq!(stats.len(), 2);
        assert_eq!(stats["alice"].upload, 100);
        assert_eq!(stats["alice"].download, 200);
        assert_eq!(stats["bob"].upload, 300);
        assert_eq!(stats["bob"].download, 400);
    }

    #[tokio::test]
    async fn test_drain_user_stats_accumulates_across_connections() {
        let mgr = Manager::new();
        // Same user closes two separate connections before a drain.
        mgr.inject_closed_user_bytes("user1", 100, 200).await;
        mgr.inject_closed_user_bytes("user1", 50, 80).await;

        let stats = mgr.drain_user_stats().await;
        let u = stats.get("user1").expect("user1 not found");
        assert_eq!(u.upload, 150, "upload should be sum of both connections");
        assert_eq!(
            u.download, 280,
            "download should be sum of both connections"
        );
    }

    #[tokio::test]
    async fn proxy_totals_exclude_direct_connections() {
        let mgr = Manager::new();
        mgr.push_uploaded(100, false);
        mgr.push_downloaded(200, false);
        mgr.push_uploaded(30, true);
        mgr.push_downloaded(40, true);

        let all = mgr.snapshot(false).await;
        let proxy = mgr.snapshot(true).await;
        assert_eq!(all.upload_total, 130);
        assert_eq!(all.download_total, 240);
        assert_eq!(proxy.upload_total, 30);
        assert_eq!(proxy.download_total, 40);
    }
}
