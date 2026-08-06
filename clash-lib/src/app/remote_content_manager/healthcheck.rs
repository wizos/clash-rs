use std::{
    sync::{
        Arc,
        atomic::{AtomicU64, Ordering},
    },
    time::Duration,
};

use parking_lot::RwLock;
use tokio::time::Instant;
use tokio_util::sync::CancellationToken;
use tracing::debug;

use crate::proxy::AnyOutboundHandler;

use super::ProxyManager;

struct HealCheckInner {
    last_touch: Instant,
    proxies: Vec<AnyOutboundHandler>,
    task_handle: Option<Arc<tokio::task::JoinHandle<()>>>,
}

pub struct HealthCheck {
    url: String,
    extra_urls: Arc<RwLock<Vec<String>>>,
    interval: Arc<AtomicU64>,
    lazy: bool,
    proxy_manager: ProxyManager,
    inner: Arc<tokio::sync::RwLock<HealCheckInner>>,
    check_state: Arc<tokio::sync::Mutex<Option<Instant>>>,
    cancel_token: CancellationToken,
}

impl Drop for HealthCheck {
    fn drop(&mut self) {
        self.cancel_token.cancel();
    }
}

impl HealthCheck {
    pub fn new(
        proxies: Vec<AnyOutboundHandler>,
        url: String,
        interval: u64,
        lazy: bool,
        proxy_manager: ProxyManager,
    ) -> Self {
        Self {
            url,
            extra_urls: Arc::new(RwLock::new(vec![])),
            interval: Arc::new(AtomicU64::new(interval)),
            lazy,
            proxy_manager,
            inner: Arc::new(tokio::sync::RwLock::new(HealCheckInner {
                last_touch: tokio::time::Instant::now(),
                proxies,
                task_handle: None,
            })),
            check_state: Arc::new(tokio::sync::Mutex::new(None)),
            cancel_token: CancellationToken::new(),
        }
    }

    pub async fn kick_off(&self) {
        let interval = self.interval.load(Ordering::Relaxed);
        if interval == 0 {
            return;
        }

        let mut inner_guard = self.inner.write().await;
        if inner_guard.task_handle.is_some() {
            return;
        }

        let lazy = self.lazy;
        let inner = self.inner.clone();
        let proxy_manager = self.proxy_manager.clone();
        let url = self.url.clone();
        let extra_urls = self.extra_urls.clone();
        let check_state = self.check_state.clone();
        let cancel_token = self.cancel_token.clone();
        let task_handle = tokio::spawn(async move {
            // Let Android finish the TUN/listener control path before the
            // initial batch of automatic checks competes for the runtime.
            #[cfg(target_os = "android")]
            tokio::time::sleep(tokio::time::Duration::from_millis(250)).await;
            let mut ticker =
                tokio::time::interval(tokio::time::Duration::from_secs(interval));
            loop {
                tokio::select! {
                    _ = cancel_token.cancelled() => break,
                    _ = ticker.tick() => {
                        debug!("healthcheck ticking, lazy: {}", lazy);
                        let now = tokio::time::Instant::now();
                        let last_touch = inner.read().await.last_touch;
                        if should_check(lazy, now.duration_since(last_touch), interval) {
                            let proxies = inner.read().await.proxies.clone();
                            let extra_urls = extra_urls.read().clone();
                            run_check(
                                &proxy_manager,
                                &proxies,
                                &url,
                                &extra_urls,
                                &check_state,
                            )
                            .await;
                        } else {
                            debug!(
                                "skipping lazy healthcheck after {} idle seconds",
                                now.duration_since(last_touch).as_secs(),
                            );
                        }
                    },
                }
            }
        });

        inner_guard.task_handle = Some(Arc::new(task_handle));
    }

    pub async fn touch(&self) {
        self.inner.write().await.last_touch = tokio::time::Instant::now();
    }

    pub async fn check(&self) {
        let proxies = self.inner.read().await.proxies.clone();
        let extra_urls = self.extra_urls.read().clone();
        run_check(
            &self.proxy_manager,
            &proxies,
            &self.url,
            &extra_urls,
            &self.check_state,
        )
        .await;
    }

    pub async fn update(&self, proxies: Vec<AnyOutboundHandler>) {
        self.inner.write().await.proxies = proxies;
    }

    pub fn auto(&self) -> bool {
        self.interval.load(Ordering::Relaxed) != 0
    }

    pub fn register(&self, url: &str, interval: u64) {
        let url = url.trim();
        if url.is_empty() || url == self.url {
            return;
        }

        let mut extra_urls = self.extra_urls.write();
        if !extra_urls.iter().any(|item| item == url) {
            extra_urls.push(url.to_owned());
            debug!("registered provider healthcheck URL: {}", url);
        }
        if self.interval.load(Ordering::Relaxed) == 0 && interval != 0 {
            self.interval.store(interval, Ordering::Relaxed);
        }
    }
}

fn should_check(lazy: bool, idle: Duration, interval: u64) -> bool {
    !lazy || idle < Duration::from_secs(interval)
}

async fn check_urls(
    proxy_manager: &ProxyManager,
    proxies: &[AnyOutboundHandler],
    url: &str,
    extra_urls: &[String],
) {
    if !url.is_empty() {
        proxy_manager.check(proxies, url, None).await;
    }
    for url in extra_urls {
        proxy_manager.check(proxies, url, None).await;
    }
}

async fn run_check(
    proxy_manager: &ProxyManager,
    proxies: &[AnyOutboundHandler],
    url: &str,
    extra_urls: &[String],
    check_state: &tokio::sync::Mutex<Option<Instant>>,
) {
    let requested_at = Instant::now();
    let mut last_completed = check_state.lock().await;
    if last_completed.is_some_and(|completed| {
        completed >= requested_at
            || requested_at.duration_since(completed) < Duration::from_secs(1)
    }) {
        debug!("coalesced duplicate healthcheck");
        return;
    }
    check_urls(proxy_manager, proxies, url, extra_urls).await;
    *last_completed = Some(Instant::now());
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::app::dns::MockClashResolver;

    #[test]
    fn lazy_healthcheck_only_runs_after_recent_use() {
        assert!(should_check(false, Duration::from_secs(600), 300));
        assert!(should_check(true, Duration::from_secs(299), 300));
        assert!(!should_check(true, Duration::from_secs(300), 300));
    }

    #[test]
    fn extra_url_can_enable_provider_healthcheck() {
        let healthcheck = HealthCheck::new(
            vec![],
            String::new(),
            0,
            true,
            ProxyManager::new(Arc::new(MockClashResolver::new()), None),
        );

        healthcheck.register(" https://example.com/generate_204 ", 300);
        healthcheck.register("https://example.com/generate_204", 300);

        assert!(healthcheck.auto());
        assert_eq!(
            healthcheck.extra_urls.read().as_slice(),
            &["https://example.com/generate_204".to_owned()],
        );
    }

    #[tokio::test]
    async fn duplicate_healthchecks_share_recent_completion() {
        let manager = ProxyManager::new(Arc::new(MockClashResolver::new()), None);
        let state = tokio::sync::Mutex::new(None);

        run_check(&manager, &[], "https://example.com", &[], &state).await;
        let first_completion = *state.lock().await;
        run_check(&manager, &[], "https://example.com", &[], &state).await;

        assert_eq!(*state.lock().await, first_completion);
    }
}
