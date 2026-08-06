use super::dns::ThreadSafeDNSResolver;
use crate::{
    app::net::outbound_interface_snapshot,
    common::{
        errors::new_io_error, timed_future::TimedFuture, tls::GLOBAL_ROOT_STORE,
        utils::serialize_duration,
    },
    proxy::AnyOutboundHandler,
    session::Session,
};
use bytes::Bytes;
use chrono::{DateTime, Utc};
use futures::{FutureExt, StreamExt, stream};
use http_body_util::Empty;
use hyper::Request;
use hyper_util::rt::TokioIo;
use serde::Serialize;
use std::{
    collections::{HashMap, VecDeque},
    sync::{
        Arc,
        atomic::{AtomicBool, AtomicUsize, Ordering},
    },
    time::Duration,
};
use tokio::sync::RwLock;
use tracing::{debug, info, instrument, trace, warn};

pub mod healthcheck;
pub mod providers;

pub const MIN_HEALTHCHECK_CONCURRENCY: usize = 1;
pub const DEFAULT_HEALTHCHECK_CONCURRENCY: usize = 40;
pub const MAX_HEALTHCHECK_CONCURRENCY: usize = 40;

struct ProxyCheckOutcome {
    result: std::io::Result<(Duration, Duration)>,
    queue_elapsed: Duration,
    test_elapsed: Duration,
}

async fn check_proxy(
    manager: ProxyManager,
    semaphore: Arc<tokio::sync::Semaphore>,
    outbound: AnyOutboundHandler,
    url: String,
    timeout: Option<Duration>,
) -> ProxyCheckOutcome {
    let queue_started = std::time::Instant::now();
    let permit = semaphore.acquire_owned().await;
    let queue_elapsed = queue_started.elapsed();
    let _permit = match permit {
        Ok(permit) => permit,
        Err(error) => {
            return ProxyCheckOutcome {
                result: Err(new_io_error(format!(
                    "healthcheck semaphore closed: {error}"
                ))),
                queue_elapsed,
                test_elapsed: Duration::ZERO,
            };
        }
    };
    let proxy_name = outbound.name().to_owned();
    let test_started = std::time::Instant::now();
    let result = manager
        .url_test(outbound, url.as_str(), timeout)
        .await
        .inspect_err(|error| {
            debug!("healthcheck {proxy_name} -> {url} failed: {error}")
        });
    ProxyCheckOutcome {
        result,
        queue_elapsed,
        test_elapsed: test_started.elapsed(),
    }
}

#[derive(Clone, Debug, Default, Serialize)]
pub struct TrafficStats {
    /// Total bytes uploaded in this session
    pub bytes_uploaded: u64,
    /// Total bytes downloaded in this session
    pub bytes_downloaded: u64,
    /// Duration of the connection
    pub connection_duration: Duration,
    /// Average throughput in bytes per second
    pub average_throughput: f64,
    /// Peak throughput observed
    pub peak_throughput: f64,
    /// Frequency of requests per second
    pub request_frequency: f64,
    /// Whether traffic flows both ways significantly
    pub is_bidirectional: bool,
}

#[derive(Clone, Debug, PartialEq)]
pub enum TrafficPatternType {
    /// Web browsing - moderate download, low upload, short-medium duration
    WebBrowsing,
    /// Video streaming - high download, low upload, long duration, steady
    /// throughput
    VideoStreaming,
    /// File download - very high download, minimal upload, variable duration
    FileDownload,
    /// File upload - minimal download, high upload, variable duration
    FileUpload,
    /// Gaming - low throughput, high frequency, bidirectional, low latency
    /// critical
    Gaming,
    /// Voice call - moderate bidirectional, steady throughput, medium duration
    VoiceCall,
    /// Video call - high bidirectional, steady throughput, medium-long duration
    VideoCall,
    /// Messaging - very low throughput, sporadic, bidirectional
    Messaging,
    /// Unknown pattern
    Unknown,
}

/// Result of traffic pattern analysis with confidence score
#[derive(Clone, Debug)]
pub struct TrafficPattern {
    pub pattern_type: TrafficPatternType,
    /// Confidence score from 0.0 to 1.0
    pub confidence: f64,
}

#[derive(Clone, Serialize)]
pub struct DelayHistory {
    time: DateTime<Utc>,
    #[serde(serialize_with = "serialize_duration")]
    delay: Duration,
    url: String,
}

#[derive(Default)]
struct ProxyState {
    alive: AtomicBool,
    delay_by_url: HashMap<String, Option<Duration>>,
    delay_history: VecDeque<DelayHistory>,
}

/// ProxyManager is the latency registry.
#[derive(Clone)]
pub struct ProxyManager {
    proxy_state: Arc<RwLock<HashMap<String, ProxyState>>>,
    failure_checks: Arc<tokio::sync::Mutex<HashMap<(String, String), Option<bool>>>>,
    healthcheck_semaphore: Arc<tokio::sync::Semaphore>,
    healthcheck_concurrency: Arc<AtomicUsize>,
    healthcheck_resize_lock: Arc<tokio::sync::Mutex<()>>,
    dns_resolver: ThreadSafeDNSResolver,
    /// Firewall Mark for url test
    fw_mark: Option<u32>,
    unified_delay: Arc<AtomicBool>,
}

#[derive(Clone, Default)]
pub struct SiteTuning {
    pub delay_weight: Option<f64>,
    pub packet_loss_weight: Option<f64>,
    pub rtt_weight: Option<f64>,
    pub alive_penalty: Option<f64>,
}

impl ProxyManager {
    pub fn new(dns_resolver: ThreadSafeDNSResolver, fw_mark: Option<u32>) -> Self {
        Self {
            dns_resolver,
            proxy_state: Default::default(),
            failure_checks: Default::default(),
            healthcheck_semaphore: Arc::new(tokio::sync::Semaphore::new(
                DEFAULT_HEALTHCHECK_CONCURRENCY,
            )),
            healthcheck_concurrency: Arc::new(AtomicUsize::new(
                DEFAULT_HEALTHCHECK_CONCURRENCY,
            )),
            healthcheck_resize_lock: Default::default(),
            fw_mark,
            unified_delay: Arc::new(AtomicBool::new(false)),
        }
    }

    pub fn set_unified_delay(&self, enabled: bool) {
        self.unified_delay.store(enabled, Ordering::Relaxed);
    }

    pub async fn set_healthcheck_concurrency(
        &self,
        concurrency: usize,
    ) -> Result<(), String> {
        if !(MIN_HEALTHCHECK_CONCURRENCY..=MAX_HEALTHCHECK_CONCURRENCY)
            .contains(&concurrency)
        {
            return Err(format!(
                "healthcheck concurrency must be between {MIN_HEALTHCHECK_CONCURRENCY} and \
                 {MAX_HEALTHCHECK_CONCURRENCY}"
            ));
        }
        let _guard = self.healthcheck_resize_lock.lock().await;
        let current = self.healthcheck_concurrency.load(Ordering::Acquire);
        if concurrency == current {
            return Ok(());
        }
        if concurrency > current {
            self.healthcheck_semaphore
                .add_permits(concurrency - current);
        } else if concurrency < current {
            self.healthcheck_semaphore
                .clone()
                .acquire_many_owned((current - concurrency) as u32)
                .await
                .map_err(|error| format!("healthcheck semaphore closed: {error}"))?
                .forget();
        }
        self.healthcheck_concurrency
            .store(concurrency, Ordering::Release);
        info!("healthcheck concurrency updated: {current} -> {concurrency}");
        Ok(())
    }

    pub fn selected_delay(&self, actual: Duration, overall: Duration) -> Duration {
        if self.unified_delay.load(Ordering::Relaxed) {
            actual
        } else {
            overall
        }
    }

    /// Handy wrapper of `url_test` that checks multiple proxies
    #[instrument(skip(self))]
    pub async fn check(
        &self,
        outbounds: &[AnyOutboundHandler],
        url: &str,
        timeout: Option<Duration>,
    ) -> Vec<std::io::Result<(Duration, Duration)>> {
        let started_at = std::time::Instant::now();
        let concurrency = self.healthcheck_concurrency.load(Ordering::Acquire);
        let manager = self.clone();
        let semaphore = self.healthcheck_semaphore.clone();
        let checks = outbounds
            .iter()
            .cloned()
            .map(|outbound| {
                check_proxy(
                    manager.clone(),
                    semaphore.clone(),
                    outbound,
                    url.to_owned(),
                    timeout,
                )
            })
            .collect::<Vec<_>>();
        let outcomes: Vec<_> =
            stream::iter(checks).buffered(concurrency).collect().await;
        let failed = outcomes
            .iter()
            .filter(|outcome| outcome.result.is_err())
            .count();
        let failure_samples = outcomes
            .iter()
            .filter_map(|outcome| outcome.result.as_ref().err())
            .take(3)
            .map(|error| error.to_string().chars().take(160).collect::<String>())
            .collect::<Vec<_>>()
            .join(" | ");
        let summary = format!(
            "healthcheck completed: url={url} total={} succeeded={} failed={} elapsed_ms={}{}",
            outcomes.len(),
            outcomes.len() - failed,
            failed,
            started_at.elapsed().as_millis(),
            if failure_samples.is_empty() {
                String::new()
            } else {
                format!(" samples=[{failure_samples}]")
            },
        );
        let queue_total_ms: u128 = outcomes
            .iter()
            .map(|outcome| outcome.queue_elapsed.as_millis())
            .sum();
        let queue_max_ms = outcomes
            .iter()
            .map(|outcome| outcome.queue_elapsed.as_millis())
            .max()
            .unwrap_or_default();
        let test_total_ms: u128 = outcomes
            .iter()
            .map(|outcome| outcome.test_elapsed.as_millis())
            .sum();
        let test_max_ms = outcomes
            .iter()
            .map(|outcome| outcome.test_elapsed.as_millis())
            .max()
            .unwrap_or_default();
        let count = outcomes.len().max(1) as u128;
        let metrics = format!(
            " concurrency={concurrency} queue_avg_ms={} queue_max_ms={queue_max_ms} \
             test_avg_ms={} test_max_ms={test_max_ms}",
            queue_total_ms / count,
            test_total_ms / count,
        );
        if failed == outcomes.len() && !outcomes.is_empty() {
            warn!("{summary}{metrics}");
        } else if failed > 0 {
            info!("{summary}{metrics}");
        } else {
            debug!("{summary}{metrics}");
        }
        outcomes.into_iter().map(|outcome| outcome.result).collect()
    }

    pub async fn alive(&self, name: &str) -> bool {
        self.proxy_state
            .read()
            .await
            .get(name)
            .map(|x| x.alive.load(Ordering::Relaxed))
            .unwrap_or(true) // if not found, assume it's alive
    }

    pub async fn alive_for(&self, name: &str, url: &str) -> bool {
        self.proxy_state
            .read()
            .await
            .get(name)
            .and_then(|state| state.delay_by_url.get(url))
            .map(Option::is_some)
            .unwrap_or(true)
    }

    pub async fn checking_after_failure(&self, name: &str, url: &str) -> bool {
        self.failure_checks
            .lock()
            .await
            .get(&(name.to_owned(), url.to_owned()))
            .is_some_and(Option::is_none)
    }

    pub async fn available_for(&self, name: &str, url: &str) -> bool {
        self.alive_for(name, url).await
            && !self.checking_after_failure(name, url).await
    }

    pub async fn check_after_failure(
        &self,
        outbound: AnyOutboundHandler,
        url: &str,
    ) {
        use crate::config::internal::proxy::{
            PROXY_COMPATIBLE, PROXY_DIRECT, PROXY_REJECT,
        };

        if matches!(
            outbound.name(),
            PROXY_DIRECT | PROXY_COMPATIBLE | PROXY_REJECT
        ) {
            return;
        }
        let key = (outbound.name().to_owned(), url.to_owned());
        {
            let mut checks = self.failure_checks.lock().await;
            if checks.contains_key(&key) {
                return;
            }
            checks.insert(key.clone(), None);
        }

        let manager = self.clone();
        let url = url.to_owned();
        tokio::spawn(async move {
            let semaphore = manager.healthcheck_semaphore.clone();
            if let Ok(_permit) = semaphore.acquire_owned().await {
                let _ = manager.url_test(outbound, &url, None).await;
            }
            manager.failure_checks.lock().await.remove(&key);
        });
    }

    pub async fn report_alive(
        &self,
        name: &str,
        alive: bool,
        history: Option<DelayHistory>,
    ) {
        let history_url = history.as_ref().map(|entry| entry.url.clone());
        {
            let mut state = self.proxy_state.write().await;
            let entry = state.entry(name.to_owned()).or_default();
            entry.alive.store(alive, Ordering::Relaxed);
            if let Some(ins) = history {
                entry
                    .delay_by_url
                    .insert(ins.url.clone(), alive.then_some(ins.delay));
                entry.delay_history.push_back(ins);
                if entry.delay_history.len() > 10 {
                    entry.delay_history.pop_front();
                }
            }
        }
        if let Some(url) = history_url
            && let Some(result) = self
                .failure_checks
                .lock()
                .await
                .get_mut(&(name.to_owned(), url))
        {
            *result = Some(alive);
        }
    }

    pub async fn delay_history(&self, name: &str) -> Vec<DelayHistory> {
        self.proxy_state
            .read()
            .await
            .get(name)
            .map(|x| x.delay_history.clone())
            .unwrap_or_default()
            .into()
    }

    pub async fn last_delay(&self, name: &str) -> Option<Duration> {
        if !self.alive(name).await {
            return None;
        }
        self.delay_history(name)
            .await
            .last()
            .map(|x| x.delay.to_owned())
    }

    pub async fn last_delay_for(&self, name: &str, url: &str) -> Option<Duration> {
        self.proxy_state
            .read()
            .await
            .get(name)
            .and_then(|state| state.delay_by_url.get(url))
            .copied()
            .flatten()
    }

    pub async fn get_packet_loss(&self, name: &str) -> Option<f64> {
        let history = self.delay_history(name).await;
        if history.is_empty() {
            None
        } else {
            let failed_count = history.iter().filter(|x| x.delay.is_zero()).count();
            Some(failed_count as f64 / history.len() as f64)
        }
    }

    pub async fn get_rtt(&self, name: &str) -> Option<f64> {
        let history = self.delay_history(name).await;
        if history.is_empty() {
            None
        } else {
            let avg_rtt =
                history.iter().map(|x| x.delay.as_millis_f64()).sum::<f64>()
                    / history.len() as f64;
            Some(avg_rtt)
        }
    }

    /// This method analyzes traffic characteristics using multiple detection
    /// algorithms and applies confidence boosting based on session context.
    pub async fn analyze_traffic_pattern(
        &self,
        stats: &TrafficStats,
        sess: &Session,
    ) -> TrafficPattern {
        let mut patterns = Vec::new();

        // Early exit for minimal data
        if stats.bytes_uploaded + stats.bytes_downloaded < 1024 {
            return TrafficPattern {
                pattern_type: TrafficPatternType::Unknown,
                confidence: 0.1,
            };
        }

        // Run all pattern detection algorithms
        patterns.push(self.detect_streaming_pattern(stats, sess));
        patterns.push(self.detect_download_pattern(stats, sess));
        patterns.push(self.detect_upload_pattern(stats, sess));
        patterns.push(self.detect_gaming_pattern(stats, sess));
        patterns.push(self.detect_voip_pattern(stats, sess));
        patterns.push(self.detect_video_call_pattern(stats, sess));
        patterns.push(self.detect_web_browsing_pattern(stats, sess));
        patterns.push(self.detect_messaging_pattern(stats, sess));

        // Find the pattern with highest confidence
        let best_pattern = patterns
            .into_iter()
            .max_by(|a, b| {
                a.confidence
                    .partial_cmp(&b.confidence)
                    .unwrap_or(std::cmp::Ordering::Equal)
            })
            .unwrap_or(TrafficPattern {
                pattern_type: TrafficPatternType::Unknown,
                confidence: 0.0,
            });

        debug!(
            "Traffic pattern analysis for {}: {:?} (confidence: {:.2})",
            sess.destination.host(),
            best_pattern.pattern_type,
            best_pattern.confidence
        );

        best_pattern
    }

    fn detect_streaming_pattern(
        &self,
        stats: &TrafficStats,
        sess: &Session,
    ) -> TrafficPattern {
        let download_ratio = if stats.bytes_uploaded + stats.bytes_downloaded > 0 {
            stats.bytes_downloaded as f64
                / (stats.bytes_uploaded + stats.bytes_downloaded) as f64
        } else {
            0.0
        };

        let duration_secs = stats.connection_duration.as_secs();
        let mut confidence = 0.0;

        // Domain-based detection boost
        let host = sess.destination.host().to_lowercase();
        if host.contains("youtube")
            || host.contains("netflix")
            || host.contains("twitch")
            || host.contains("video")
            || host.contains("stream")
            || host.contains("hls")
        {
            confidence += 0.2;
        }

        // High download ratio (>88% download, slightly relaxed)
        if download_ratio > 0.88 {
            confidence += 0.3;
        }

        // Long duration indicates streaming
        match duration_secs {
            0..=60 => {}                      // Too short for streaming
            61..=300 => confidence += 0.1,    // Short stream
            301..=1800 => confidence += 0.25, // Medium stream
            _ => confidence += 0.3,           // Long stream
        }

        // Steady moderate to high throughput
        if stats.average_throughput > 500_000.0
            && stats.average_throughput < 100_000_000.0
        {
            confidence += 0.25;
        }

        // Consistent throughput (streaming should be relatively stable)
        if stats.peak_throughput > 0.0 && stats.average_throughput > 0.0 {
            let variance_ratio = stats.peak_throughput / stats.average_throughput;
            if variance_ratio < 4.0 {
                // Less variance indicates streaming
                confidence += 0.15;
            }
        }

        TrafficPattern {
            pattern_type: TrafficPatternType::VideoStreaming,
            confidence,
        }
    }

    fn detect_download_pattern(
        &self,
        stats: &TrafficStats,
        sess: &Session,
    ) -> TrafficPattern {
        let download_ratio = if stats.bytes_uploaded + stats.bytes_downloaded > 0 {
            stats.bytes_downloaded as f64
                / (stats.bytes_uploaded + stats.bytes_downloaded) as f64
        } else {
            0.0
        };

        let mut confidence = 0.0;
        let host = sess.destination.host().to_lowercase();

        // Domain-based detection
        if host.contains("cdn")
            || host.contains("download")
            || host.contains("files")
            || host.contains("github")
            || host.contains("releases")
        {
            confidence += 0.2;
        }

        // Very high download ratio (>94%)
        if download_ratio > 0.94 {
            confidence += 0.4;
        }

        // High sustained throughput
        if stats.average_throughput > 5_000_000.0 {
            confidence += 0.3;
        }

        // Large total download size
        match stats.bytes_downloaded {
            10_000_000..=100_000_000 => confidence += 0.2, // 10-100MB
            100_000_001.. => confidence += 0.3,            // >100MB
            _ => {}
        }

        TrafficPattern {
            pattern_type: TrafficPatternType::FileDownload,
            confidence,
        }
    }

    fn detect_upload_pattern(
        &self,
        stats: &TrafficStats,
        sess: &Session,
    ) -> TrafficPattern {
        let upload_ratio = if stats.bytes_uploaded + stats.bytes_downloaded > 0 {
            stats.bytes_uploaded as f64
                / (stats.bytes_uploaded + stats.bytes_downloaded) as f64
        } else {
            0.0
        };

        let mut confidence = 0.0;
        let host = sess.destination.host().to_lowercase();

        // Domain-based detection
        if host.contains("upload")
            || host.contains("cloud")
            || host.contains("drive")
            || host.contains("storage")
            || host.contains("backup")
        {
            confidence += 0.2;
        }

        // High upload ratio (>75%)
        if upload_ratio > 0.75 {
            confidence += 0.4;
        }

        // Sustained upload throughput
        if stats.average_throughput > 2_000_000.0 {
            confidence += 0.3;
        }

        // Large upload size
        if stats.bytes_uploaded > 20_000_000 {
            // 20MB+
            confidence += 0.3;
        }

        TrafficPattern {
            pattern_type: TrafficPatternType::FileUpload,
            confidence,
        }
    }

    fn detect_gaming_pattern(
        &self,
        stats: &TrafficStats,
        sess: &Session,
    ) -> TrafficPattern {
        let mut confidence = 0.0;
        let host = sess.destination.host().to_lowercase();
        let port = sess.destination.port();

        // Gaming-related domains and ports
        if host.contains("game")
            || host.contains("steam")
            || host.contains("riot")
            || host.contains("blizzard")
            || host.contains("xbox")
            || host.contains("playstation")
        {
            confidence += 0.3;
        }

        // Common gaming ports
        if matches!(port, 3478..=3480 | 27000..=28000 | 7777..=7784) {
            confidence += 0.2;
        }

        // High request frequency with low latency requirements
        if stats.request_frequency > 20.0 {
            confidence += 0.3;
        }

        // Low overall throughput but highly bidirectional
        if stats.average_throughput < 1_000_000.0 && stats.is_bidirectional {
            confidence += 0.3;
        }

        // Gaming sessions tend to be long
        if stats.connection_duration.as_secs() > 600 {
            // 10+ minutes
            confidence += 0.2;
        }

        TrafficPattern {
            pattern_type: TrafficPatternType::Gaming,
            confidence,
        }
    }

    fn detect_voip_pattern(
        &self,
        stats: &TrafficStats,
        sess: &Session,
    ) -> TrafficPattern {
        let upload_download_ratio = if stats.bytes_downloaded > 0 {
            stats.bytes_uploaded as f64 / stats.bytes_downloaded as f64
        } else {
            f64::INFINITY
        };

        let mut confidence = 0.0;
        let host = sess.destination.host().to_lowercase();

        // VoIP service domains
        if host.contains("skype")
            || host.contains("zoom")
            || host.contains("teams")
            || host.contains("discord")
            || host.contains("webex")
            || host.contains("voip")
        {
            confidence += 0.3;
        }

        // Balanced upload/download (0.4 to 2.5 ratio for VoIP)
        if upload_download_ratio > 0.4 && upload_download_ratio < 2.5 {
            confidence += 0.4;
        }

        // Voice codec throughput range
        if stats.average_throughput > 16_000.0
            && stats.average_throughput < 320_000.0
        {
            confidence += 0.3;
        }

        // Call duration patterns
        match stats.connection_duration.as_secs() {
            60..=3600 => confidence += 0.3, // 1 minute to 1 hour
            3601.. => confidence += 0.2,    // Very long calls
            _ => {}
        }

        TrafficPattern {
            pattern_type: TrafficPatternType::VoiceCall,
            confidence,
        }
    }

    fn detect_video_call_pattern(
        &self,
        stats: &TrafficStats,
        sess: &Session,
    ) -> TrafficPattern {
        let upload_download_ratio = if stats.bytes_downloaded > 0 {
            stats.bytes_uploaded as f64 / stats.bytes_downloaded as f64
        } else {
            f64::INFINITY
        };

        let mut confidence = 0.0;
        let host = sess.destination.host().to_lowercase();

        // Video call service domains
        if host.contains("zoom")
            || host.contains("teams")
            || host.contains("meet")
            || host.contains("webex")
            || host.contains("facetime")
            || host.contains("hangouts")
        {
            confidence += 0.3;
        }

        // Balanced but higher bandwidth than voice
        if upload_download_ratio > 0.2 && upload_download_ratio < 5.0 {
            confidence += 0.3;
        }

        // Video call throughput range
        if stats.average_throughput > 200_000.0
            && stats.average_throughput < 15_000_000.0
        {
            confidence += 0.4;
        }

        // Video call duration patterns
        if stats.connection_duration.as_secs() > 120 {
            confidence += 0.3;
        }

        TrafficPattern {
            pattern_type: TrafficPatternType::VideoCall,
            confidence,
        }
    }

    fn detect_web_browsing_pattern(
        &self,
        stats: &TrafficStats,
        sess: &Session,
    ) -> TrafficPattern {
        let mut confidence = 0.0;
        let port = sess.destination.port();
        let host = sess.destination.host().to_lowercase();

        // HTTP/HTTPS ports get strong signal
        if port == 80 || port == 443 {
            confidence += 0.4;
        }

        // Common web domains
        if host.contains("www")
            || host.contains("com")
            || host.contains("org")
            || host.contains("net")
            || host.ends_with(".io")
        {
            confidence += 0.1;
        }

        // Web browsing download preference
        let download_ratio = if stats.bytes_uploaded + stats.bytes_downloaded > 0 {
            stats.bytes_downloaded as f64
                / (stats.bytes_uploaded + stats.bytes_downloaded) as f64
        } else {
            0.0
        };

        if download_ratio > 0.65 && download_ratio < 0.93 {
            confidence += 0.3;
        }

        // Web browsing throughput characteristics
        if stats.average_throughput > 50_000.0
            && stats.average_throughput < 8_000_000.0
        {
            confidence += 0.2;
        }

        // Browsing sessions are typically shorter
        if stats.connection_duration.as_secs() < 1800 {
            // Less than 30 minutes
            confidence += 0.1;
        }

        TrafficPattern {
            pattern_type: TrafficPatternType::WebBrowsing,
            confidence,
        }
    }

    fn detect_messaging_pattern(
        &self,
        stats: &TrafficStats,
        sess: &Session,
    ) -> TrafficPattern {
        let mut confidence = 0.0;
        let host = sess.destination.host().to_lowercase();

        // Messaging service domains
        if host.contains("whatsapp")
            || host.contains("telegram")
            || host.contains("signal")
            || host.contains("messenger")
            || host.contains("slack")
            || host.contains("discord")
        {
            confidence += 0.3;
        }

        // Very low sustained throughput
        if stats.average_throughput < 100_000.0 {
            confidence += 0.4;
        }

        // Bidirectional but low volume
        if stats.is_bidirectional
            && stats.bytes_uploaded + stats.bytes_downloaded < 5_000_000
        {
            // Less than 5MB total
            confidence += 0.3;
        }

        // Messaging can have long idle connections
        if stats.connection_duration.as_secs() > 300 {
            confidence += 0.3;
        }

        TrafficPattern {
            pattern_type: TrafficPatternType::Messaging,
            confidence,
        }
    }

    /// Calculate adjustment factor based on total data transferred
    fn calculate_data_size_factor(&self, stats: &TrafficStats) -> f64 {
        let total_bytes = stats.bytes_uploaded + stats.bytes_downloaded;

        match total_bytes {
            0..=1_000_000 => 1.0,           // Small data: standard weights
            1_000_001..=100_000_000 => 1.2, // Medium data: slightly favor stability
            100_000_001..=1_000_000_000 => 1.5, // Large data: favor stability more
            _ => 2.0,                       /* Very large data: heavily favor
                                              * stability */
        }
    }

    #[instrument(skip(self))]
    /// returns (actual_http_round_trip_time,
    /// overall_round_trip_time_including_tls_handshake)
    pub async fn url_test(
        &self,
        outbound: AnyOutboundHandler,
        url: &str,
        timeout: Option<Duration>,
    ) -> std::io::Result<(Duration, Duration)> {
        trace!("started");
        let name = outbound.name().to_owned();
        let name_clone = name.clone();
        let default_timeout = Duration::from_secs(5);
        let timeout = timeout.unwrap_or(default_timeout);
        let unified_delay = self.unified_delay.load(Ordering::Relaxed);

        let dns_resolver = self.dns_resolver.clone();
        let tester = async move {
            let name = name_clone;

            let uri = url
                .parse::<http::Uri>()
                .map_err(|e| new_io_error(format!("invalid url: {url}: {e}")))?;

            let host = uri
                .host()
                .ok_or(new_io_error(format!("invalid url: {url}: no host found")))?
                .to_owned();
            let port = uri.port_u16().unwrap_or(match uri.scheme_str() {
                None => 80,
                Some(s) => match s {
                    "http" => 80,
                    "https" => 443,
                    _ => {
                        return Err(new_io_error(format!(
                            "invalid url: {url}: unsupported scheme {s}"
                        )));
                    }
                },
            });

            let sess = Session {
                destination: (host.to_owned(), port)
                    .try_into()
                    .expect("must be valid destination"),
                iface: outbound_interface_snapshot().await,
                so_mark: self.fw_mark,
                ..Default::default()
            };

            let started_at = tokio::time::Instant::now();
            let deadline = started_at + timeout;
            let (stream, _) = tokio::time::timeout_at(
                deadline,
                TimedFuture::new(outbound.connect_stream(&sess, dns_resolver)),
            )
            .await
            .map_err(|_| new_io_error(format!("timeout for {url}")))?;
            let stream = stream?;

            let request = || {
                Request::head(url)
                    .header(hyper::header::HOST, host.as_str())
                    .version(hyper::Version::HTTP_11)
                    .body(Empty::<Bytes>::new())
                    .unwrap()
            };

            let mut sender = match uri.scheme() {
                Some(scheme) if scheme == &http::uri::Scheme::HTTP => {
                    let io = TokioIo::new(stream);
                    let (sender, conn) = tokio::time::timeout_at(
                        deadline,
                        hyper::client::conn::http1::handshake(io),
                    )
                    .await
                    .map_err(|_| new_io_error("HTTP handshake timed out"))?
                    .map_err(|e| {
                        new_io_error(format!("failed to handshake: {e}"))
                    })?;

                    tokio::task::spawn(async move {
                        if let Err(err) = conn.await {
                            warn!("HTTP connection error: {}", err);
                        }
                    });

                    sender
                }
                Some(scheme) if scheme == &http::uri::Scheme::HTTPS => {
                    let mut tls_config = rustls::ClientConfig::builder()
                        .with_root_certificates(GLOBAL_ROOT_STORE.clone())
                        .with_no_client_auth();

                    if std::env::var("SSLKEYLOGFILE").is_ok() {
                        debug!("Enabling TLS key logging");
                        tls_config.key_log = Arc::new(rustls::KeyLogFile::new());
                    }

                    let connector =
                        tokio_rustls::TlsConnector::from(Arc::new(tls_config));

                    let stream = tokio::time::timeout_at(
                        deadline,
                        connector.connect(
                            host.clone().try_into().expect("must be valid SNI"),
                            stream,
                        ),
                    )
                    .await
                    .map_err(|_| new_io_error(format!("timeout for {url}")))??;

                    let io = TokioIo::new(stream);

                    let (sender, conn) = tokio::time::timeout_at(
                        deadline,
                        hyper::client::conn::http1::handshake(io),
                    )
                    .await
                    .map_err(|_| new_io_error("HTTPS handshake timed out"))?
                    .map_err(|e| {
                        new_io_error(format!("failed to handshake: {e}"))
                    })?;

                    tokio::task::spawn(async move {
                        if let Err(err) = conn.await {
                            warn!("HTTP connection error: {}", err);
                        }
                    });

                    sender
                }
                _ => {
                    return Err(new_io_error(format!(
                        "invalid url: {url}: unsupported scheme"
                    )));
                }
            };

            let (response, first_request_delay) = tokio::time::timeout_at(
                deadline,
                TimedFuture::new(sender.send_request(request()).boxed()),
            )
            .await
            .map_err(|_| new_io_error(format!("timeout for {url}")))?;
            let response = response.map_err(|error| {
                new_io_error(format!("urltest for proxy {name} failed: {error}"))
            })?;
            let status = response.status();
            drop(response);
            trace!(delay = ?first_request_delay, status = ?status, "success");

            let overall_delay = started_at.elapsed();
            let actual_delay = if unified_delay {
                match tokio::time::timeout_at(
                    deadline,
                    TimedFuture::new(sender.send_request(request()).boxed()),
                )
                .await
                {
                    Ok((Ok(response), delay)) => {
                        trace!(delay = ?delay, status = ?response.status(), "unified delay");
                        delay
                    }
                    Ok((Err(error), _)) => {
                        debug!(e = ?error, "unified delay request failed");
                        started_at.elapsed()
                    }
                    Err(_) => {
                        debug!("unified delay request timed out");
                        started_at.elapsed()
                    }
                }
            } else {
                first_request_delay
            };

            Ok((actual_delay, overall_delay))
        };

        let result = tester.await;
        let selected_delay = result
            .as_ref()
            .map(|(actual, overall)| self.selected_delay(*actual, *overall));

        self.report_alive(
            &name,
            result.is_ok(),
            Some(DelayHistory {
                time: Utc::now(),
                delay: selected_delay.unwrap_or_default(),
                url: url.to_owned(),
            }),
        )
        .await;

        crate::app::events::emit(
            "delay",
            serde_json::json!({
                "url": url,
                "name": name.clone(),
                "value": selected_delay
                    .map(|delay| delay.as_millis().min(i32::MAX as u128) as i32)
                    .unwrap_or(-1),
            }),
        );

        result
    }

    /// Based on session characteristics and traffic statistics.
    pub async fn get_site_tuning(&self, sess: &Session) -> SiteTuning {
        // Extract traffic statistics from the session if available
        let traffic_stats = sess.traffic_stats.as_ref();

        // Attempt intelligent pattern detection if traffic statistics are available
        if let Some(stats) = traffic_stats {
            let pattern = self.analyze_traffic_pattern(stats, sess).await;

            // Only use pattern-specific tuning if confidence is high enough
            if pattern.confidence > 0.6 {
                // Apply pattern-specific tuning parameters optimized for each
                // traffic type
                let mut tuning = match pattern.pattern_type {
                    // Gaming: Ultra-low latency critical, high packet loss penalty
                    TrafficPatternType::Gaming => SiteTuning {
                        delay_weight: Some(0.1),
                        packet_loss_weight: Some(8000.0),
                        rtt_weight: Some(0.1),
                        alive_penalty: Some(20000.0),
                    },
                    // Voice calls: Low latency important, moderate packet loss
                    // sensitivity
                    TrafficPatternType::VoiceCall => SiteTuning {
                        delay_weight: Some(0.2),
                        packet_loss_weight: Some(6000.0),
                        rtt_weight: Some(0.2),
                        alive_penalty: Some(15000.0),
                    },
                    // Video calls: Balance between latency and stability
                    TrafficPatternType::VideoCall => SiteTuning {
                        delay_weight: Some(0.4),
                        packet_loss_weight: Some(5000.0),
                        rtt_weight: Some(0.3),
                        alive_penalty: Some(12000.0),
                    },
                    // Video streaming: Favor stability over low latency
                    TrafficPatternType::VideoStreaming => SiteTuning {
                        delay_weight: Some(0.5),
                        packet_loss_weight: Some(4000.0),
                        rtt_weight: Some(0.4),
                        alive_penalty: Some(10000.0),
                    },
                    // Web browsing: Balanced approach for general usage
                    TrafficPatternType::WebBrowsing => SiteTuning {
                        delay_weight: Some(0.6),
                        packet_loss_weight: Some(2000.0),
                        rtt_weight: Some(0.5),
                        alive_penalty: Some(6000.0),
                    },
                    // Messaging: Moderate latency tolerance, low bandwidth
                    TrafficPatternType::Messaging => SiteTuning {
                        delay_weight: Some(0.8),
                        packet_loss_weight: Some(1500.0),
                        rtt_weight: Some(0.4),
                        alive_penalty: Some(5000.0),
                    },
                    // File upload: Prioritize connection stability over speed
                    TrafficPatternType::FileUpload => SiteTuning {
                        delay_weight: Some(1.2),
                        packet_loss_weight: Some(800.0),
                        rtt_weight: Some(0.8),
                        alive_penalty: Some(4000.0),
                    },
                    // File download: Maximum stability for large transfers
                    TrafficPatternType::FileDownload => SiteTuning {
                        delay_weight: Some(1.5),
                        packet_loss_weight: Some(500.0),
                        rtt_weight: Some(1.0),
                        alive_penalty: Some(3000.0),
                    },
                    // Unknown patterns: Use fallback logic
                    _ => self.get_fallback_tuning(sess),
                };

                // Apply data size scaling factor for large transfers
                // Larger transfers benefit more from stable connections
                let data_size_factor = self.calculate_data_size_factor(stats);
                if let Some(ref mut delay_weight) = tuning.delay_weight {
                    *delay_weight *= data_size_factor;
                }
                return tuning;
            }
        }

        // Fallback to protocol and port-based tuning when no traffic data
        // is available or pattern confidence is too low
        self.get_fallback_tuning(sess)
    }

    /// Fallback tuning based on protocol and port
    fn get_fallback_tuning(&self, sess: &Session) -> SiteTuning {
        let is_udp = matches!(sess.network, crate::session::Network::Udp);
        let port = sess.destination.port();

        if is_udp {
            // UDP: games, VoIP, real-time - prioritize low latency
            SiteTuning {
                delay_weight: Some(0.3),
                packet_loss_weight: Some(3000.0),
                rtt_weight: Some(0.3),
                alive_penalty: Some(15000.0),
            }
        } else if port == 80 || port == 443 {
            // HTTP/HTTPS: balance latency and stability
            SiteTuning {
                delay_weight: Some(0.7),
                packet_loss_weight: Some(2000.0),
                rtt_weight: Some(0.7),
                alive_penalty: Some(8000.0),
            }
        } else if matches!(port, 21 | 22 | 115 | 989 | 990) {
            // FTP/SFTP: prioritize stability for file transfers
            SiteTuning {
                delay_weight: Some(1.2),
                packet_loss_weight: Some(1000.0),
                rtt_weight: Some(1.2),
                alive_penalty: Some(5000.0),
            }
        } else {
            // Default balanced tuning
            SiteTuning::default()
        }
    }
}

#[cfg(test)]
mod tests {
    use crate::{
        app::{
            dispatcher::ChainedStreamWrapper, dns::MockClashResolver,
            remote_content_manager,
        },
        config::internal::proxy::PROXY_DIRECT,
        proxy::{
            direct, mocks::MockDummyOutboundHandler,
            utils::test_utils::noop::NoopResolver,
        },
        tests::initialize,
    };
    use futures::TryFutureExt;
    use httpmock::{Method::HEAD, MockServer};
    use std::{net::Ipv4Addr, sync::Arc, time::Duration};

    #[test]
    fn cloned_proxy_managers_share_healthcheck_limit() {
        let manager = remote_content_manager::ProxyManager::new(
            Arc::new(MockClashResolver::new()),
            None,
        );
        let clone = manager.clone();

        assert!(Arc::ptr_eq(
            &manager.healthcheck_semaphore,
            &clone.healthcheck_semaphore,
        ));
        assert_eq!(
            manager.healthcheck_semaphore.available_permits(),
            remote_content_manager::DEFAULT_HEALTHCHECK_CONCURRENCY,
        );
    }

    #[tokio::test]
    async fn healthcheck_concurrency_is_bounded_and_resizable() {
        let manager = remote_content_manager::ProxyManager::new(
            Arc::new(MockClashResolver::new()),
            None,
        );

        manager.set_healthcheck_concurrency(40).await.unwrap();
        assert_eq!(manager.healthcheck_semaphore.available_permits(), 40);
        manager.set_healthcheck_concurrency(1).await.unwrap();
        assert_eq!(manager.healthcheck_semaphore.available_permits(), 1);
        assert!(manager.set_healthcheck_concurrency(0).await.is_err());
        assert!(manager.set_healthcheck_concurrency(41).await.is_err());
    }

    #[tokio::test]
    async fn healthcheck_timeout_starts_after_a_slot_is_available() {
        let manager = remote_content_manager::ProxyManager::new(
            Arc::new(MockClashResolver::new()),
            None,
        );
        manager.set_healthcheck_concurrency(1).await.unwrap();
        let held_permit = manager
            .healthcheck_semaphore
            .clone()
            .acquire_owned()
            .await
            .unwrap();

        let mut outbound = MockDummyOutboundHandler::new();
        outbound
            .expect_name()
            .return_const("queued-node".to_owned());
        outbound
            .expect_connect_stream()
            .returning(|_, _| Err(std::io::Error::other("network test started")));
        let manager_clone = manager.clone();
        let task = tokio::spawn(async move {
            manager_clone
                .check(
                    &[Arc::new(outbound)],
                    "https://example.com/generate_204",
                    Some(Duration::from_millis(5)),
                )
                .await
        });

        tokio::time::sleep(Duration::from_millis(20)).await;
        assert!(!task.is_finished());
        drop(held_permit);

        let results = task.await.unwrap();
        assert!(
            results[0]
                .as_ref()
                .unwrap_err()
                .to_string()
                .contains("network test started")
        );
    }

    #[tokio::test]
    async fn tracks_availability_per_test_url() {
        let manager =
            remote_content_manager::ProxyManager::new(Arc::new(NoopResolver), None);
        manager
            .report_alive(
                "node",
                false,
                Some(remote_content_manager::DelayHistory {
                    time: chrono::Utc::now(),
                    delay: Duration::ZERO,
                    url: "https://failed.example".to_owned(),
                }),
            )
            .await;
        manager
            .report_alive(
                "node",
                true,
                Some(remote_content_manager::DelayHistory {
                    time: chrono::Utc::now(),
                    delay: Duration::from_millis(10),
                    url: "https://alive.example".to_owned(),
                }),
            )
            .await;

        assert!(!manager.alive_for("node", "https://failed.example").await);
        assert!(manager.alive_for("node", "https://alive.example").await);
        assert_eq!(
            manager
                .last_delay_for("node", "https://alive.example")
                .await,
            Some(Duration::from_millis(10)),
        );
    }

    #[tokio::test]
    async fn test_proxy_manager_alive() {
        initialize();

        let server = MockServer::start();
        server.mock(|when, then| {
            when.method(HEAD).path("/generate_204");
            then.status(204);
        });
        let url = server.url("/generate_204");

        let mut mock_resolver = MockClashResolver::new();
        mock_resolver
            .expect_resolve()
            .returning(|_, _| Ok(Some(std::net::IpAddr::V4(Ipv4Addr::LOCALHOST))));
        mock_resolver.expect_ipv6().return_const(false);

        let manager =
            remote_content_manager::ProxyManager::new(Arc::new(mock_resolver), None);

        let mock_handler = Arc::new(direct::Handler::new(PROXY_DIRECT));

        manager
            .url_test(mock_handler.clone(), &url, None)
            .await
            .expect("test failed");

        assert!(manager.alive(PROXY_DIRECT).await);
        assert!(
            manager
                .last_delay(PROXY_DIRECT)
                .await
                .is_some_and(|x| x.as_nanos() > 0)
        );
        let history = manager.delay_history(PROXY_DIRECT).await;
        assert_eq!(
            history.last().map(|entry| entry.url.as_str()),
            Some(url.as_str())
        );

        manager.report_alive(PROXY_DIRECT, false, None).await;
        assert!(!manager.alive(PROXY_DIRECT).await);

        for _ in 0..10 {
            manager
                .url_test(mock_handler.clone(), &url, None)
                .await
                .expect("test failed");
        }

        assert!(manager.alive(PROXY_DIRECT).await);
        assert!(
            manager
                .last_delay(PROXY_DIRECT)
                .await
                .is_some_and(|x| x.as_nanos() > 0)
        );
        assert_eq!(manager.delay_history(PROXY_DIRECT).await.len(), 10);
    }

    #[tokio::test]
    async fn unified_delay_sends_a_second_head_request() {
        initialize();

        let server = MockServer::start();
        let request = server.mock(|when, then| {
            when.method(HEAD).path("/generate_204");
            then.status(204);
        });
        let url = server.url("/generate_204");

        let mut mock_resolver = MockClashResolver::new();
        mock_resolver
            .expect_resolve()
            .returning(|_, _| Ok(Some(std::net::IpAddr::V4(Ipv4Addr::LOCALHOST))));
        mock_resolver.expect_ipv6().return_const(false);

        let manager =
            remote_content_manager::ProxyManager::new(Arc::new(mock_resolver), None);
        manager.set_unified_delay(true);

        manager
            .url_test(Arc::new(direct::Handler::new(PROXY_DIRECT)), &url, None)
            .await
            .expect("test failed");

        request.assert_calls(2);
    }

    #[tokio::test]
    async fn test_proxy_manager_timeout() {
        initialize();

        let mut mock_resolver = MockClashResolver::new();
        mock_resolver.expect_resolve().returning(|_, _| {
            Ok(Some(std::net::IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1))))
        });

        let manager =
            remote_content_manager::ProxyManager::new(Arc::new(mock_resolver), None);

        let mut mock_handler = MockDummyOutboundHandler::new();
        mock_handler
            .expect_name()
            .return_const(PROXY_DIRECT.to_owned());
        mock_handler.expect_connect_stream().returning(|_, _| {
            Ok(Box::new(ChainedStreamWrapper::new(
                tokio_test::io::Builder::new()
                    .wait(Duration::from_secs(10))
                    .build(),
            )))
        });

        let mock_handler = Arc::new(mock_handler);

        let result = manager
            .url_test(
                mock_handler.clone(),
                "http://www.gstatic.com/generate_204",
                Some(Duration::from_secs(3)),
            )
            .map_err(|x| assert!(x.to_string().contains("timeout")))
            .await;

        assert!(result.is_err());
        assert!(!manager.alive(PROXY_DIRECT).await);
        assert_eq!(manager.last_delay(PROXY_DIRECT).await, None);
        assert_eq!(manager.delay_history(PROXY_DIRECT).await.len(), 1);
    }
}
