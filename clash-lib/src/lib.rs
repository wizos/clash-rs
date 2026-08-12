#![feature(ip)]
#![feature(duration_millis_float)]

#[cfg(feature = "tun")]
use crate::proxy::tun;
use crate::{
    app::{
        dispatcher::{Dispatcher, StatisticsManager},
        dns::{self, SystemResolver, ThreadSafeDNSResolver, config::DNSListenAddr},
        inbound::manager::InboundManager,
        logging::LogEvent,
        net::init_net_config,
        outbound::manager::OutboundManager,
        profile,
        router::Router,
        sniffer::Sniffer,
    },
    common::{
        auth, dashboard,
        geodata::{DEFAULT_GEOSITE_DOWNLOAD_URL, GeoDataLookup},
        http::new_http_client,
        mmdb::{
            self, DEFAULT_ASN_MMDB_DOWNLOAD_URL, DEFAULT_COUNTRY_MMDB_DOWNLOAD_URL,
        },
    },
    config::{
        InternalConfig,
        def::{self, LogLevel, RunMode},
        internal::{
            proxy::{OutboundProxy, PROXY_COMPATIBLE, PROXY_DIRECT, PROXY_REJECT},
            rule::RuleType,
        },
    },
    runner::Runner,
};

use std::sync::{Mutex as StdMutex, mpsc as std_mpsc};
use std::{
    collections::HashSet,
    io,
    path::PathBuf,
    sync::{Arc, OnceLock},
};
#[cfg(feature = "tun")]
use std::{
    sync::LazyLock,
    time::{Duration, Instant},
};
use thiserror::Error;
use tokio::sync::{Mutex, broadcast, mpsc};
use tracing::{debug, error, info, warn};

pub mod app;
pub mod config;

mod common;
mod flow_metadata;
pub mod process_resolver;
mod proxy;
mod runner;
mod session;

/// Registers the process-wide Android VM and application context used by
/// platform-aware dependencies such as the system DNS resolver.
///
/// # Safety
/// Both pointers must remain valid for the lifetime of the process, and this
/// function must be called exactly once before starting the core.
#[cfg(target_os = "android")]
pub unsafe fn initialize_android_context(
    java_vm: *mut std::ffi::c_void,
    context: *mut std::ffi::c_void,
) {
    unsafe {
        ndk_context::initialize_android_context(java_vm, context);
    }
}

use crate::common::{geodata, mmdb::MmdbLookup};
pub use config::{
    DNSListen as ClashDNSListen, RuntimeConfig as ClashRuntimeConfig,
    def::{Config as ClashConfigDef, DNS as ClashDNSConfigDef},
};

#[derive(Error, Debug)]
pub enum Error {
    #[error(transparent)]
    IpNet(#[from] ipnet::AddrParseError),
    #[error(transparent)]
    Io(#[from] io::Error),
    #[error("invalid config: {0}")]
    InvalidConfig(String),
    #[error("profile error: {0}")]
    ProfileError(String),
    #[error("dns error: {0}")]
    DNSError(String),
    #[error(transparent)]
    DNSServerError(#[from] watfaq_dns::DNSError),
    #[error("crypto error: {0}")]
    Crypto(String),
    #[error("operation error: {0}")]
    Operation(String),
    #[error(transparent)]
    Other(#[from] anyhow::Error),
}
pub type Result<T> = std::result::Result<T, Error>;

#[cfg(feature = "tun")]
type ArcRunner = Arc<dyn Runner>;

#[cfg(feature = "tun")]
struct RuntimeTunCommand {
    config: config::internal::config::TunConfig,
    result: std_mpsc::SyncSender<Result<()>>,
}

#[cfg(feature = "tun")]
static RUNTIME_TUN_CONTROL: LazyLock<
    StdMutex<Option<mpsc::UnboundedSender<RuntimeTunCommand>>>,
> = LazyLock::new(|| StdMutex::new(None));

struct RuntimeControllerCommand {
    method: String,
    path: String,
    body: Option<String>,
    result: std_mpsc::SyncSender<Result<app::api::ControllerResponse>>,
}

static RUNTIME_CONTROLLER: std::sync::LazyLock<
    StdMutex<Option<mpsc::UnboundedSender<RuntimeControllerCommand>>>,
> = std::sync::LazyLock::new(|| StdMutex::new(None));
#[cfg(feature = "tun")]
const RUNTIME_TUN_START_TIMEOUT: Duration = Duration::from_secs(10);
#[cfg(feature = "tun")]
const RUNTIME_TUN_STOP_TIMEOUT: Duration = Duration::from_secs(1);

#[cfg(feature = "tun")]
fn external_tun_config(
    fd: i32,
    addresses: &str,
    dns: &str,
) -> Result<config::internal::config::TunConfig> {
    if fd <= 0 {
        return Err(Error::InvalidConfig(format!("invalid tun fd: {fd}")));
    }

    let mut gateway = None;
    let mut gateway_v6 = None;
    for address in addresses
        .split(',')
        .map(str::trim)
        .filter(|value| !value.is_empty())
    {
        match address.parse::<ipnet::IpNet>()? {
            ipnet::IpNet::V4(value) if gateway.is_none() => gateway = Some(value),
            ipnet::IpNet::V6(value) if gateway_v6.is_none() => {
                gateway_v6 = Some(value)
            }
            _ => {}
        }
    }

    let dns_hijack_targets = dns
        .split(',')
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .map(str::parse::<std::net::IpAddr>)
        .collect::<std::result::Result<Vec<_>, _>>()
        .map_err(|error| {
            Error::InvalidConfig(format!("invalid DNS hijack address: {error}"))
        })?;
    let dns_hijack = !dns_hijack_targets.is_empty();
    let dns_hijack_targets = dns_hijack_targets
        .into_iter()
        .filter(|address| !address.is_unspecified())
        .collect();

    Ok(config::internal::config::TunConfig {
        enable: true,
        device_id: format!("fd://{fd}"),
        gateway: gateway.ok_or_else(|| {
            Error::InvalidConfig("tun requires an IPv4 address".to_string())
        })?,
        gateway_v6,
        dns_hijack,
        dns_hijack_targets,
        ..Default::default()
    })
}

#[cfg(feature = "tun")]
fn replace_runtime_tun(config: config::internal::config::TunConfig) -> Result<()> {
    let sender = RUNTIME_TUN_CONTROL
        .lock()
        .map_err(|_| {
            Error::Operation("runtime TUN control is poisoned".to_string())
        })?
        .clone()
        .ok_or_else(|| {
            Error::Operation("runtime TUN control is unavailable".to_string())
        })?;
    let (result_tx, result_rx) = std_mpsc::sync_channel(1);
    sender
        .send(RuntimeTunCommand {
            config,
            result: result_tx,
        })
        .map_err(|_| Error::Operation("runtime TUN control stopped".to_string()))?;
    result_rx
        .recv_timeout(RUNTIME_TUN_START_TIMEOUT + Duration::from_secs(2))
        .map_err(|error| {
            Error::Operation(format!("runtime TUN response failed: {error}"))
        })?
}

#[cfg(feature = "tun")]
async fn stop_runtime_tun_runner(runner: &ArcRunner, timeout: Duration) {
    runner.shutdown();
    match tokio::time::timeout(timeout, runner.join()).await {
        Ok(Ok(())) => {}
        Ok(Err(error)) => warn!("previous TUN runner stopped with error: {error}"),
        Err(_) => warn!(
            "previous TUN runner did not stop within {}ms; continuing replacement",
            timeout.as_millis(),
        ),
    }
}

#[cfg(feature = "tun")]
pub fn attach_external_tun(fd: i32, addresses: &str, dns: &str) -> Result<()> {
    replace_runtime_tun(external_tun_config(fd, addresses, dns)?)
}

#[cfg(feature = "tun")]
pub fn detach_external_tun() -> Result<()> {
    replace_runtime_tun(config::internal::config::TunConfig::default())
}

pub fn controller_request(
    method: &str,
    path: &str,
    body: Option<&str>,
    timeout: std::time::Duration,
) -> Result<app::api::ControllerResponse> {
    let sender = RUNTIME_CONTROLLER
        .lock()
        .map_err(|_| Error::Operation("runtime controller is poisoned".to_owned()))?
        .clone()
        .ok_or_else(|| {
            Error::Operation("runtime controller is unavailable".to_owned())
        })?;
    let (result_tx, result_rx) = std_mpsc::sync_channel(1);
    sender
        .send(RuntimeControllerCommand {
            method: method.to_owned(),
            path: path.to_owned(),
            body: body.map(str::to_owned),
            result: result_tx,
        })
        .map_err(|_| Error::Operation("runtime controller stopped".to_owned()))?;
    result_rx
        .recv_timeout(timeout + std::time::Duration::from_secs(1))
        .map_err(|error| {
            Error::Operation(format!("runtime controller response failed: {error}"))
        })?
}

enum RuntimeEvent {
    Shutdown,
    Reload(Option<(u64, Config)>),
    Controller(Option<RuntimeControllerCommand>),
    #[cfg(feature = "tun")]
    Tun(Option<RuntimeTunCommand>),
}

pub struct Options {
    pub config: Config,
    pub cwd: Option<String>,
    pub rt: Option<TokioRuntime>,
    pub log_file: Option<String>,
    /// The original config file path, used to support "reload current config"
    /// from the dashboard. Set this when starting from a file; leave `None`
    /// for string/inline configs (e.g. FFI).
    pub config_path: Option<String>,
}

pub enum TokioRuntime {
    MultiThread,
    SingleThread,
}

/// Owns one background Clash runtime and its shutdown boundary.
///
/// Callers may use [`Self::runtime_handle`] to run adapter tasks on the same
/// Tokio runtime. Shutdown must happen from outside that runtime thread.
pub struct ScaffoldInstance {
    runtime_thread: std::thread::JoinHandle<()>,
    runtime_handle: tokio::runtime::Handle,
    shutdown_token: tokio_util::sync::CancellationToken,
}

impl ScaffoldInstance {
    pub fn runtime_handle(&self) -> tokio::runtime::Handle {
        self.runtime_handle.clone()
    }

    pub fn cancel(&self) {
        self.shutdown_token.cancel();
    }

    pub fn shutdown(self) -> Result<()> {
        self.shutdown_token.cancel();
        if self.runtime_thread.thread().id() == std::thread::current().id() {
            return Err(Error::Operation(
                "cannot join the Clash runtime from its own thread".to_owned(),
            ));
        }
        self.runtime_thread.join().map_err(|_| {
            Error::Operation(
                "Clash runtime thread panicked during shutdown".to_owned(),
            )
        })
    }
}

#[allow(clippy::large_enum_variant)]
pub enum Config {
    Def(ClashConfigDef),
    Internal(InternalConfig),
    File(String),
    Str(String),
}

impl Config {
    pub fn try_parse(self) -> Result<InternalConfig> {
        match self {
            Config::Def(c) => c.try_into(),
            Config::Internal(c) => c.validate(),
            Config::File(file) => {
                TryInto::<def::Config>::try_into(PathBuf::from(file))?.try_into()
            }
            Config::Str(s) => s.parse::<def::Config>()?.try_into(),
        }
    }

    /// Like [`try_parse`] but additionally validates that the YAML source
    /// contains no unknown top-level or `dns`-section fields, returning an
    /// error when any unrecognised key is found.
    ///
    /// Enable this via the `--strict-config` CLI flag.
    pub fn try_parse_strict(self) -> Result<InternalConfig> {
        let yaml = match self {
            Config::File(file) => std::fs::read_to_string(file)?,
            Config::Str(s) => s,
            // Def/Internal are already structured Rust values — no YAML to
            // check for unknown fields.
            other => return other.try_parse(),
        };
        def::check_unknown_fields(&yaml)?.try_into()
    }
}

pub struct GlobalState {
    log_level: LogLevel,
    reload_generation: u64,
    reload_attempt: u64,
    reload_completed: u64,
    reload_error: Option<String>,
    reload_phase: String,
    #[cfg(feature = "tun")]
    tunnel_runner: ArcRunner,
    dns_listener: Arc<dns::DnsRunner>,
    reload_tx: mpsc::Sender<(u64, Config)>,
    cwd: String,
    /// Path to the config file used at startup. Used by the dashboard "Reload"
    /// button which sends an empty path to mean "reload current config".
    config_path: Option<String>,
}

pub fn start_scaffold(opts: Options) -> Result<()> {
    let rt = match opts.rt.as_ref().unwrap_or(&TokioRuntime::MultiThread) {
        TokioRuntime::MultiThread => tokio::runtime::Builder::new_multi_thread()
            .enable_all()
            .build()?,
        TokioRuntime::SingleThread => tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()?,
    };
    let config_path = opts.config_path.or_else(|| {
        if let Config::File(ref p) = opts.config {
            Some(p.clone())
        } else {
            None
        }
    });
    let config: InternalConfig = opts.config.try_parse()?;
    let cwd = opts.cwd.unwrap_or_else(|| ".".to_string());
    let (log_tx, _) = broadcast::channel(100);

    let log_collector = app::logging::EventCollector::new(vec![log_tx.clone()]);

    app::logging::setup_logging(
        config.general.log_level,
        log_collector,
        &cwd,
        opts.log_file,
    );

    let shutdown_token = tokio_util::sync::CancellationToken::new();
    {
        let mut token_guard = SHUTDOWN_TOKEN.lock().unwrap();
        token_guard.push(shutdown_token.clone());
    }
    rt.block_on(async {
        match start(config, cwd, config_path, log_tx, shutdown_token).await {
            Err(e) => {
                eprintln!("start error: {e}");
                Err(e)
            }
            Ok(_) => Ok(()),
        }
    })
}

/// Start a Clash instance in a background thread with independent lifecycle.
/// Returns an owned runtime instance with explicit task and shutdown access.
/// Unlike `start_scaffold`, this does NOT register in the global
/// SHUTDOWN_TOKEN.
pub fn start_scaffold_instance(opts: Options) -> Result<ScaffoldInstance> {
    start_scaffold_instance_with_inbounds(opts, true)
}

/// Start an embedded Clash instance without opening configured inbound
/// listeners. The host can start them later through the controller API.
pub fn start_scaffold_instance_deferred_inbounds(
    opts: Options,
) -> Result<ScaffoldInstance> {
    start_scaffold_instance_with_inbounds(opts, false)
}

fn start_scaffold_instance_with_inbounds(
    opts: Options,
    start_inbounds: bool,
) -> Result<ScaffoldInstance> {
    let config_path = opts.config_path.or_else(|| {
        if let Config::File(ref p) = opts.config {
            Some(p.clone())
        } else {
            None
        }
    });
    let config: InternalConfig = opts.config.try_parse()?;
    let cwd = opts.cwd.unwrap_or_else(|| ".".to_string());
    let rt_kind = opts.rt.unwrap_or(TokioRuntime::MultiThread);
    let log_file = opts.log_file.filter(|path| !path.is_empty());

    let token = tokio_util::sync::CancellationToken::new();
    let token_clone = token.clone();
    let (ready_tx, ready_rx) =
        std_mpsc::sync_channel::<std::result::Result<(), String>>(1);
    let (runtime_tx, runtime_rx) = std_mpsc::sync_channel(1);
    let startup_tx = ready_tx.clone();

    let handle = std::thread::spawn(move || {
        let mut runtime_builder = match rt_kind {
            TokioRuntime::MultiThread => tokio::runtime::Builder::new_multi_thread(),
            TokioRuntime::SingleThread => {
                tokio::runtime::Builder::new_current_thread()
            }
        };
        let rt = match runtime_builder.enable_all().build() {
            Ok(runtime) => runtime,
            Err(error) => {
                let _ = runtime_tx.send(Err(error.to_string()));
                return;
            }
        };
        if runtime_tx.send(Ok(rt.handle().clone())).is_err() {
            return;
        }

        let (log_tx, _) = tokio::sync::broadcast::channel(100);
        let log_collector = app::logging::EventCollector::new(vec![log_tx.clone()]);
        app::logging::setup_logging(
            config.general.log_level,
            log_collector,
            &cwd,
            log_file,
        );

        let result = rt.block_on(start_runtime(
            config,
            cwd,
            config_path,
            log_tx,
            token_clone,
            Some(startup_tx),
            start_inbounds,
        ));
        if let Err(e) = result {
            let _ = ready_tx.try_send(Err(e.to_string()));
            eprintln!("Clash instance error: {}", e);
        }
    });

    let runtime_handle = match runtime_rx.recv() {
        Ok(Ok(runtime_handle)) => runtime_handle,
        Ok(Err(error)) => {
            let _ = handle.join();
            return Err(Error::Operation(format!(
                "failed to build Clash runtime: {error}"
            )));
        }
        Err(error) => {
            let _ = handle.join();
            return Err(Error::Operation(format!(
                "Clash runtime stopped before initialization: {error}"
            )));
        }
    };

    match ready_rx.recv() {
        Ok(Ok(())) => Ok(ScaffoldInstance {
            runtime_thread: handle,
            runtime_handle,
            shutdown_token: token,
        }),
        Ok(Err(error)) => {
            let _ = handle.join();
            Err(Error::Operation(error))
        }
        Err(error) => {
            let _ = handle.join();
            Err(Error::Operation(format!(
                "clash runtime stopped before startup completed: {error}"
            )))
        }
    }
}

static SHUTDOWN_TOKEN: std::sync::Mutex<Vec<tokio_util::sync::CancellationToken>> =
    std::sync::Mutex::new(Vec::new());

pub fn shutdown() -> bool {
    let mut token_guard = SHUTDOWN_TOKEN.lock().unwrap();
    if !token_guard.is_empty() {
        for token in token_guard.drain(..) {
            token.cancel();
        }
        warn!("Shutdown signal sent, waiting for shutdown to complete...");
        true
    } else {
        warn!("Shutdown token not initialized, cannot shutdown");
        false
    }
}

static CRYPTO_PROVIDER_LOCK: OnceLock<()> = OnceLock::new();

pub fn setup_default_crypto_provider() {
    CRYPTO_PROVIDER_LOCK.get_or_init(|| {
        #[cfg(feature = "aws-lc-rs")]
        {
            _ = rustls::crypto::aws_lc_rs::default_provider().install_default();
        }
        #[cfg(all(feature = "ring", not(feature = "aws-lc-rs")))]
        {
            _ = rustls::crypto::ring::default_provider().install_default();
        }
    });
}

pub async fn start(
    config: InternalConfig,
    cwd: String,
    config_path: Option<String>,
    log_tx: broadcast::Sender<LogEvent>,
    shutdown_token: tokio_util::sync::CancellationToken,
) -> Result<()> {
    start_runtime(config, cwd, config_path, log_tx, shutdown_token, None, true).await
}

async fn start_runtime(
    config: InternalConfig,
    cwd: String,
    config_path: Option<String>,
    log_tx: broadcast::Sender<LogEvent>,
    shutdown_token: tokio_util::sync::CancellationToken,
    startup_tx: Option<std_mpsc::SyncSender<std::result::Result<(), String>>>,
    start_inbounds: bool,
) -> Result<()> {
    setup_default_crypto_provider();

    let cwd = PathBuf::from(cwd);

    // things we need to clone before consuming config
    let controller_cfg = config.general.controller.clone();
    let log_level = config.general.log_level;

    let components = create_components(cwd.clone(), config).await?;

    let (reload_tx, mut reload_rx) = mpsc::channel(1);

    let global_state = Arc::new(Mutex::new(GlobalState {
        log_level,
        reload_generation: 0,
        reload_attempt: 0,
        reload_completed: 0,
        reload_error: None,
        reload_phase: "idle".to_owned(),
        #[cfg(feature = "tun")]
        tunnel_runner: components.tun_runner.clone(),
        dns_listener: components.dns_listener.clone(),
        reload_tx,
        cwd: cwd.to_string_lossy().to_string(),
        config_path,
    }));

    let mut api_listener = Arc::new(app::api::ApiRunner::new(
        controller_cfg.clone(),
        log_tx.clone(),
        components.inbound_manager.clone(),
        components.dispatcher.clone(),
        global_state.clone(),
        components.dns_resolver.clone(),
        components.outbound_manager.clone(),
        components.statistics_manager.clone(),
        components.cache_store.clone(),
        components.router.clone(),
        cwd.to_string_lossy().to_string(),
        Some(shutdown_token.child_token()),
        components.dns_listen.clone(),
        components.dns_enabled,
    ));

    // api_listener is not part of components because it requires components to be
    // initialized before it can be initialized. start it manually.
    api_listener.run_async();

    {
        let mut g = global_state.lock().await;
        #[cfg(feature = "tun")]
        {
            g.tunnel_runner = components.tun_runner.clone();
        }
        g.dns_listener = components.dns_listener.clone();
    }

    components.start_all(start_inbounds).await?;

    let (runtime_controller_tx, mut runtime_controller_rx) =
        mpsc::unbounded_channel();
    *RUNTIME_CONTROLLER.lock().unwrap() = Some(runtime_controller_tx.clone());

    let cwd_clone = cwd.clone();

    #[cfg(feature = "tun")]
    let (runtime_tun_tx, mut runtime_tun_rx) = mpsc::unbounded_channel();
    #[cfg(feature = "tun")]
    {
        *RUNTIME_TUN_CONTROL.lock().unwrap() = Some(runtime_tun_tx.clone());
    }

    let reload_token = shutdown_token.child_token();
    let runtime_handle = tokio::runtime::Handle::current();
    // Keep control-plane commands responsive even when data-plane tasks occupy
    // the runtime workers (notably Android's initial health checks).
    let reload_task = async move {
        let mut components = components;
        // Listen for config reload signal and reload config
        loop {
            #[cfg(feature = "tun")]
            let event = tokio::select! {
                _ = reload_token.cancelled() => RuntimeEvent::Shutdown,
                next = reload_rx.recv() => RuntimeEvent::Reload(next),
                command = runtime_tun_rx.recv() => RuntimeEvent::Tun(command),
                command = runtime_controller_rx.recv() => RuntimeEvent::Controller(command),
            };
            #[cfg(not(feature = "tun"))]
            let event = tokio::select! {
                _ = reload_token.cancelled() => RuntimeEvent::Shutdown,
                next = reload_rx.recv() => RuntimeEvent::Reload(next),
                command = runtime_controller_rx.recv() => RuntimeEvent::Controller(command),
            };
            let (reload_attempt, config) = match event {
                RuntimeEvent::Shutdown | RuntimeEvent::Reload(None) => {
                    api_listener.shutdown();
                    components.stop_all().await;
                    api_listener.join().await.ok();
                    break;
                }
                RuntimeEvent::Reload(Some(value)) => value,
                RuntimeEvent::Controller(Some(command)) => {
                    let controller = api_listener.clone();
                    tokio::spawn(async move {
                        let result = controller
                            .request(&command.method, &command.path, command.body)
                            .await;
                        let _ = command.result.send(result);
                    });
                    continue;
                }
                RuntimeEvent::Controller(None) => continue,
                #[cfg(feature = "tun")]
                RuntimeEvent::Tun(Some(command)) => {
                    let result =
                        components.replace_tun(command.config, &global_state).await;
                    let _ = command.result.send(result);
                    continue;
                }
                #[cfg(feature = "tun")]
                RuntimeEvent::Tun(None) => continue,
            };
            info!("reloading config");
            {
                let mut state = global_state.lock().await;
                state.reload_phase = "parsing".to_owned();
            }
            let config = match config.try_parse() {
                Ok(c) => c,
                Err(e) => {
                    error!("failed to reload config: {}", e);
                    let mut state = global_state.lock().await;
                    state.reload_completed = reload_attempt;
                    state.reload_error = Some(e.to_string());
                    state.reload_phase = "failed".to_owned();
                    continue;
                }
            };

            let controller_cfg = config.general.controller.clone();

            {
                let mut state = global_state.lock().await;
                state.reload_phase = "creating-components".to_owned();
            }
            let new_components =
                match create_components(cwd_clone.clone(), config).await {
                    Ok(components) => components,
                    Err(error) => {
                        error!("failed to create replacement components: {}", error);
                        let mut state = global_state.lock().await;
                        state.reload_completed = reload_attempt;
                        state.reload_error = Some(error.to_string());
                        state.reload_phase = "failed".to_owned();
                        continue;
                    }
                };

            {
                let mut state = global_state.lock().await;
                state.reload_phase = "stopping-old-components".to_owned();
            }
            components.stop_all().await;
            {
                let mut state = global_state.lock().await;
                state.reload_phase = "starting-new-components".to_owned();
            }
            if let Err(error) = new_components.start_all(true).await {
                error!("failed to start replacement components: {error}");
                let mut state = global_state.lock().await;
                state.reload_completed = reload_attempt;
                state.reload_error = Some(error.to_string());
                state.reload_phase = "failed".to_owned();
                continue;
            }

            // TODO: every reload is causing the API server to restart, we should
            // make the API server reloadable instead of restarting it.
            // maybe adding APIs to replace components
            // and only recreate the listeners when necessary (e.g. when the listen
            // address or port is changed)
            let new_api_listener = Arc::new(app::api::ApiRunner::new(
                controller_cfg,
                log_tx.clone(),
                new_components.inbound_manager.clone(),
                new_components.dispatcher.clone(),
                global_state.clone(),
                new_components.dns_resolver.clone(),
                new_components.outbound_manager.clone(),
                new_components.statistics_manager.clone(),
                new_components.cache_store.clone(),
                new_components.router.clone(),
                cwd_clone.to_string_lossy().to_string(),
                Some(reload_token.child_token()),
                new_components.dns_listen.clone(),
                new_components.dns_enabled,
            ));
            {
                let mut g = global_state.lock().await;
                #[cfg(feature = "tun")]
                {
                    g.tunnel_runner = new_components.tun_runner.clone();
                }
                g.dns_listener = new_components.dns_listener.clone();
            }

            {
                let mut state = global_state.lock().await;
                state.reload_phase = "restarting-api".to_owned();
            }
            api_listener.shutdown();
            // Wait for the old API server to fully stop before starting the new
            // one, to avoid EADDRINUSE on the same port.
            api_listener.join().await.ok();
            new_api_listener.run_async();
            api_listener = new_api_listener;
            components = new_components;
            let mut g = global_state.lock().await;
            g.reload_generation = g.reload_generation.saturating_add(1);
            g.reload_completed = reload_attempt;
            g.reload_error = None;
            g.reload_phase = "idle".to_owned();
        }
        Ok::<(), Error>(())
    };
    let reload_handle =
        tokio::task::spawn_blocking(move || runtime_handle.block_on(reload_task));

    if let Some(startup_tx) = startup_tx {
        let _ = startup_tx.send(Ok(()));
    }

    tokio::select! {
        result = tokio::signal::ctrl_c() => { result.map_err(Error::Io)?; }
        _ = shutdown_token.cancelled() => {}
    }
    shutdown_token.cancel();
    reload_handle.await.map_err(|error| {
        Error::Operation(format!("reload task join failed: {error}"))
    })??;
    #[cfg(feature = "tun")]
    {
        let mut control = RUNTIME_TUN_CONTROL.lock().unwrap();
        if control
            .as_ref()
            .is_some_and(|current| current.same_channel(&runtime_tun_tx))
        {
            *control = None;
        }
    }
    {
        let mut control = RUNTIME_CONTROLLER.lock().unwrap();
        if control
            .as_ref()
            .is_some_and(|current| current.same_channel(&runtime_controller_tx))
        {
            *control = None;
        }
    }
    Ok(())
}

struct RuntimeComponents {
    cache_store: profile::ThreadSafeCacheFile,
    dns_resolver: ThreadSafeDNSResolver,
    outbound_manager: Arc<OutboundManager>,
    router: Arc<Router>,
    dispatcher: Arc<Dispatcher>,
    statistics_manager: Arc<StatisticsManager>,

    #[cfg(feature = "tun")]
    tun_runner: ArcRunner,
    dns_listener: Arc<dns::DnsRunner>,
    inbound_manager: Arc<InboundManager>,
    dns_listen: DNSListenAddr,
    dns_enabled: bool,
}

impl RuntimeComponents {
    fn start_post_ready_tasks(&self) {
        self.outbound_manager.start_background_proxy_providers();
        self.router.initialize_rule_providers();
        self.outbound_manager.start_healthchecks();
    }

    #[cfg(feature = "tun")]
    async fn replace_tun(
        &mut self,
        config: config::internal::config::TunConfig,
        global_state: &Arc<Mutex<GlobalState>>,
    ) -> Result<()> {
        let enabled = config.enable;
        let started = Instant::now();
        let runner = Arc::new(tun::TunRunner::new(
            config,
            self.dispatcher.clone(),
            self.dns_resolver.clone(),
            None,
        )?);
        let replacement: ArcRunner = runner.clone();
        let previous = std::mem::replace(&mut self.tun_runner, replacement.clone());
        global_state.lock().await.tunnel_runner = replacement;

        let stop_started = Instant::now();
        stop_runtime_tun_runner(&previous, RUNTIME_TUN_STOP_TIMEOUT).await;
        let stop_elapsed = stop_started.elapsed();
        warn!(
            "replace_tun: stop_runtime_tun_runner took {}ms",
            stop_elapsed.as_millis(),
        );

        let start_started = Instant::now();
        let result = match tokio::time::timeout(
            RUNTIME_TUN_START_TIMEOUT,
            runner.start_and_wait(),
        )
        .await
        {
            Ok(result) => result,
            Err(_) => {
                runner.shutdown();
                Err(Error::Operation("TUN startup timed out".to_string()))
            }
        };
        let start_elapsed = start_started.elapsed();
        warn!(
            "replace_tun: start_and_wait took {}ms",
            start_elapsed.as_millis(),
        );

        match &result {
            Ok(()) => info!(
                "runtime TUN {} in {}ms",
                if enabled { "attached" } else { "detached" },
                started.elapsed().as_millis(),
            ),
            Err(error) => error!(
                "runtime TUN {} failed after {}ms: {error}",
                if enabled { "attach" } else { "detach" },
                started.elapsed().as_millis(),
            ),
        }
        if enabled && result.is_ok() {
            let hc_started = Instant::now();
            self.start_post_ready_tasks();
            warn!(
                "replace_tun: start_healthchecks took {}ms",
                hc_started.elapsed().as_millis(),
            );
        }
        warn!(
            "replace_tun: total took {}ms (stop={}ms, start={}ms)",
            started.elapsed().as_millis(),
            stop_elapsed.as_millis(),
            start_elapsed.as_millis(),
        );
        result
    }

    async fn start_all(&self, start_inbounds: bool) -> Result<()> {
        #[cfg(feature = "tun")]
        self.tun_runner.run_async();
        if start_inbounds {
            self.dns_listener.start_and_wait().await?;
            if let Err(error) = self.inbound_manager.restart().await {
                self.dns_listener.stop_listener();
                return Err(error);
            }
            self.start_post_ready_tasks();
        }
        Ok(())
    }

    async fn stop_all(&self) {
        #[cfg(feature = "tun")]
        self.tun_runner.shutdown();
        self.dns_listener.shutdown();
        self.inbound_manager.shutdown();
        #[cfg(feature = "tun")]
        if let Err(error) = self.tun_runner.join().await {
            warn!("failed to join TUN runner: {error}");
        }
        if let Err(error) = self.dns_listener.join().await {
            warn!("failed to join DNS listener: {error}");
        }
        if let Err(error) = self.inbound_manager.join().await {
            warn!("failed to join inbound listeners: {error}");
        }
        self.statistics_manager.shutdown().await;
    }
}

fn group_has_static_path(
    name: &str,
    config: &InternalConfig,
    visiting: &mut HashSet<String>,
) -> bool {
    if !visiting.insert(name.to_owned()) {
        return false;
    }
    let result = config
        .proxy_groups
        .get(name)
        .and_then(|proxy| match proxy {
            OutboundProxy::ProxyGroup(group) => Some(group),
            _ => None,
        })
        .and_then(|group| group.proxies())
        .is_some_and(|proxies| {
            proxies.iter().any(|proxy| {
                config.proxies.contains_key(proxy)
                    || group_has_static_path(proxy, config, visiting)
            })
        });
    visiting.remove(name);
    result
}

fn collect_group_providers(
    name: &str,
    config: &InternalConfig,
    providers: &mut HashSet<String>,
    visiting: &mut HashSet<String>,
) {
    if !visiting.insert(name.to_owned()) {
        return;
    }
    if let Some(OutboundProxy::ProxyGroup(group)) = config.proxy_groups.get(name) {
        providers.extend(group.use_providers().into_iter().flatten().cloned());
        for proxy in group.proxies().into_iter().flatten() {
            collect_group_providers(proxy, config, providers, visiting);
        }
    }
    visiting.remove(name);
}

fn required_proxy_providers(config: &InternalConfig) -> HashSet<String> {
    let has_user_proxy = config.proxies.keys().any(|name| {
        !matches!(
            name.as_str(),
            PROXY_DIRECT | PROXY_REJECT | PROXY_COMPATIBLE
        )
    });
    let target = match config.general.mode {
        RunMode::Direct => return HashSet::new(),
        RunMode::Global if has_user_proxy => return HashSet::new(),
        RunMode::Global => None,
        RunMode::Rule => config.rules.iter().rev().find_map(|rule| match rule {
            RuleType::Match { target } => Some(target.as_str()),
            _ => None,
        }),
    };
    let Some(target) = target else {
        return if has_user_proxy {
            HashSet::new()
        } else {
            config.proxy_providers.keys().cloned().collect()
        };
    };
    if config.proxies.contains_key(target)
        || group_has_static_path(target, config, &mut HashSet::new())
    {
        return HashSet::new();
    }
    let mut providers = HashSet::new();
    collect_group_providers(target, config, &mut providers, &mut HashSet::new());
    providers
}

async fn create_components(
    cwd: PathBuf,
    config: InternalConfig,
) -> Result<RuntimeComponents> {
    let required_proxy_providers = required_proxy_providers(&config);
    let sniffer = Sniffer::from_config(config.general.sniffer.as_ref())?;
    let unified_delay = config.general.unified_delay;
    crate::proxy::utils::set_tcp_concurrent(config.general.tcp_concurrent);
    crate::process_resolver::set_find_process_mode(config.general.find_process_mode);
    init_net_config(config.general.interface.as_ref(), config.tun.so_mark).await;

    let cancellation_token = tokio_util::sync::CancellationToken::new();

    debug!("initializing cache store");
    let cache_store = profile::ThreadSafeCacheFile::new(
        cwd.join("cache.db").as_path().to_str().unwrap(),
        config.profile.store_selected,
    );

    let system_resolver = Arc::new(
        SystemResolver::new(config.dns.ipv6)
            .map_err(|x| Error::DNSError(x.to_string()))?,
    );

    debug!("initializing bootstrap outbounds");

    let plain_outbounds = OutboundManager::load_plain_outbounds(
        config
            .proxies
            .into_values()
            .filter_map(|x| match x {
                OutboundProxy::ProxyServer(s) => Some(s),
                _ => None,
            })
            .collect(),
    )?;

    // Create a shared outbound registry seeded with plain outbounds.
    // After OutboundManager is initialized it will be extended with all
    // handlers (plain + proxy groups + provider proxies), so DNS clients
    // and the HTTP client can use any of them for bootstrap traffic.
    let outbound_registry = Arc::new(tokio::sync::RwLock::new(
        plain_outbounds
            .iter()
            .map(|x| (x.name().to_string(), x.clone()))
            .collect(),
    ));

    let client =
        new_http_client(system_resolver.clone(), Some(outbound_registry.clone()))
            .map_err(|x| Error::DNSError(x.to_string()))?;

    // Download the dashboard if both `external-ui` and `external-ui-url` are
    // configured and the directory is absent or empty. This is done here so
    // it can use the proxy-aware HTTP client (plain outbound handlers are
    // already loaded into the registry at this point).
    if let (Some(ui_path), Some(download_url)) = (
        &config.general.controller.external_ui,
        &config.general.controller.external_ui_download_url,
    ) {
        let dir = cwd.join(ui_path);
        let url = download_url.clone();
        dashboard::download_dashboard(dir, &url, &client)
            .await
            .unwrap_or_else(|e| warn!("dashboard download failed: {}", e));
    }

    debug!("initializing dns resolver");
    // Clone the dns.listen for the DNS Server later before we consume the config
    // TODO: we should separate the DNS resolver and DNS server config here
    let dns_listen = config.dns.listen.clone();
    let dns_enable = config.dns.enable;

    // Extract the country MMDB file/url config early so they can be consumed
    // here, while the actual MMDB loading happens after OutboundManager (like
    // geodata and asn_mmdb) so it benefits from the fully-populated outbound
    // registry when downloading the file.
    let country_mmdb_file = config.general.mmdb;
    let country_mmdb_download_url = config.general.mmdb_download_url;
    let geosite_file = config.general.geosite;
    let geosite_download_url = config.general.geosite_download_url;

    // Create a shared pending handle that the DNS resolver's GeoIPFilter holds.
    // It starts empty and is populated once the MMDB is loaded below.
    let pending_country_mmdb: Option<dns::PendingMmdb> = country_mmdb_file
        .as_ref()
        .map(|_| Arc::new(OnceLock::new()));
    let pending_geodata: Option<dns::PendingGeoData> =
        geosite_file.as_ref().map(|_| Arc::new(OnceLock::new()));

    // When `dns.respect-rules` is true, share a `RuleDispatch` between the
    // resolver and the (later-built) router + outbound manager. The DNS
    // runtime provider consults the OnceLocks at dial time and falls back to
    // DIRECT until they are populated.
    let rule_dispatch = dns::RuleDispatch::new();
    let dns_rule_dispatch = config.dns.respect_rules.then(|| rule_dispatch.clone());

    let dns_resolver = dns::new_resolver(
        config.dns,
        Some(cache_store.clone()),
        pending_country_mmdb.clone(),
        pending_geodata.clone(),
        outbound_registry.clone(),
        dns_rule_dispatch,
    )
    .await;
    dns::set_active_resolver(dns_resolver.clone());

    debug!("initializing outbound manager");
    let outbound_manager = Arc::new(
        OutboundManager::new(
            plain_outbounds,
            config
                .proxy_groups
                .into_values()
                .filter_map(|x| match x {
                    OutboundProxy::ProxyGroup(g) => Some(g),
                    _ => None,
                })
                .collect(),
            config.proxy_providers,
            config.proxy_names,
            dns_resolver.clone(),
            cache_store.clone(),
            cwd.to_string_lossy().to_string(),
            config.general.routing_mask,
            outbound_registry.clone(),
            rule_dispatch.clone(),
        )
        .await?,
    );
    outbound_manager.set_unified_delay(unified_delay);

    if rule_dispatch
        .outbound_manager
        .set(outbound_manager.clone())
        .is_err()
    {
        warn!(
            "RuleDispatch outbound_manager OnceLock was already set — this is \
             unexpected and indicates a double-initialization bug"
        );
    }

    debug!("initializing mmdb");
    let country_mmdb = if let Some(ref mmdb_file) = country_mmdb_file {
        let mmdb = Arc::new(
            mmdb::Mmdb::new(
                cwd.join(mmdb_file),
                country_mmdb_download_url
                    .unwrap_or(DEFAULT_COUNTRY_MMDB_DOWNLOAD_URL.to_string()),
                client.clone(),
            )
            .await?,
        ) as MmdbLookup;
        // Populate the shared handle so the DNS resolver's GeoIPFilter can use
        // it. Any inflight DNS fallback-IP filtering that ran before this point
        // will have been permissive (MMDB absent = pass-through), which is the
        // safe default during startup.
        if let Some(pending) = &pending_country_mmdb
            && pending.set(mmdb.clone()).is_err()
        {
            warn!(
                "country MMDB OnceLock was already set — this is unexpected and \
                 indicates a double-initialization bug"
            );
        }
        Some(mmdb)
    } else {
        debug!("country mmdb not set, skipping");
        None
    };

    debug!("initializing geosite");
    let geodata = if let Some(geosite_file) = geosite_file {
        let geodata = Arc::new(
            geodata::GeoData::new(
                cwd.join(&geosite_file),
                geosite_download_url
                    .unwrap_or(DEFAULT_GEOSITE_DOWNLOAD_URL.to_string()),
                client.clone(),
            )
            .await?,
        ) as GeoDataLookup;
        if let Some(pending) = &pending_geodata {
            if pending.set(geodata.clone()).is_err() {
                warn!(
                    "geodata OnceLock was already set — this is unexpected and \
                     indicates a double-initialization bug"
                );
            }
            dns_resolver.flush_cache().await;
        }
        Some(geodata)
    } else {
        debug!("geosite not set, skipping");
        None
    };

    debug!("initializing country asn mmdb");
    let asn_mmdb = if let Some(asn_mmdb_name) = config.general.asn_mmdb {
        Some(Arc::new(
            mmdb::Mmdb::new(
                cwd.join(&asn_mmdb_name),
                config
                    .general
                    .asn_mmdb_download_url
                    .unwrap_or(DEFAULT_ASN_MMDB_DOWNLOAD_URL.to_string()),
                client.clone(),
            )
            .await?,
        ) as MmdbLookup)
    } else {
        debug!("ASN mmdb not found and not configured for download, skipping");
        None
    };

    debug!("initializing router");
    let router = Arc::new(
        Router::new(
            config.rules,
            config.sub_rules,
            config.rule_providers,
            dns_resolver.clone(),
            country_mmdb,
            asn_mmdb,
            geodata,
            cwd.to_string_lossy().to_string(),
            rule_dispatch.clone(),
        )
        .await,
    );

    if rule_dispatch.router.set(router.clone()).is_err() {
        warn!(
            "RuleDispatch router OnceLock was already set — this is unexpected and \
             indicates a double-initialization bug"
        );
    }
    outbound_manager
        .initialize_proxy_providers(&required_proxy_providers)
        .await?;

    let statistics_manager = StatisticsManager::new();

    debug!("initializing dispatcher");
    let dispatcher = Arc::new(Dispatcher::new(
        outbound_manager.clone(),
        router.clone(),
        dns_resolver.clone(),
        config.general.mode,
        statistics_manager.clone(),
        config.experimental.and_then(|e| e.tcp_buffer_size),
        sniffer,
    ));

    debug!("initializing authenticator");
    let authenticator = Arc::new(auth::PlainAuthenticator::new(config.users));

    debug!("initializing inbound manager");
    let inbound_manager = Arc::new(
        InboundManager::new(
            dispatcher.clone(),
            authenticator,
            config.listeners,
            Some(cancellation_token.child_token()),
        )
        .await,
    );
    if !config.inbound_providers.is_empty() {
        debug!("loading inbound providers");
        inbound_manager
            .load_inbound_providers(
                cwd.to_string_lossy().to_string(),
                config.inbound_providers,
                dns_resolver.clone(),
            )
            .await;
    }

    #[cfg(feature = "tun")]
    debug!("initializing tun runner");
    #[cfg(feature = "tun")]
    let tun_runner: ArcRunner = Arc::new(tun::TunRunner::new(
        config.tun,
        dispatcher.clone(),
        dns_resolver.clone(),
        Some(cancellation_token.child_token()),
    )?);

    debug!("initializing dns listener");
    let dns_listener = Arc::new(dns::DnsRunner::new(
        dns_enable,
        dns_listen.clone(),
        dns_resolver.clone(),
        &cwd,
        Some(cancellation_token.child_token()),
    ));

    info!("all components initialized");
    Ok(RuntimeComponents {
        cache_store,
        dns_resolver,
        outbound_manager,
        router,
        dispatcher,
        statistics_manager,
        inbound_manager,
        #[cfg(feature = "tun")]
        tun_runner,
        dns_listener,
        dns_listen,
        dns_enabled: dns_enable,
    })
}

#[cfg(test)]
mod tests {
    use crate::{
        Config, Options, required_proxy_providers, shutdown, start_scaffold,
    };
    use std::{sync::Once, thread, time::Duration};

    static INIT: Once = Once::new();

    pub fn initialize() {
        INIT.call_once(|| {
            env_logger::init();
            crate::setup_default_crypto_provider();
        });
    }

    #[test]
    fn waits_for_provider_when_match_has_no_static_path() {
        let config = Config::Str(
            r#"
proxy-providers:
  remote:
    type: http
    url: https://example.com/proxies.yaml
    path: ./remote.yaml
    interval: 3600
proxy-groups:
  - name: proxy
    type: select
    use: [remote]
rules:
  - MATCH,proxy
"#
            .to_owned(),
        )
        .try_parse()
        .unwrap();

        assert_eq!(
            required_proxy_providers(&config),
            ["remote".to_owned()].into()
        );
    }

    #[test]
    fn static_match_path_does_not_wait_for_provider() {
        let config = Config::Str(
            r#"
proxies:
  - name: local
    type: socks5
    server: 127.0.0.1
    port: 1080
proxy-providers:
  remote:
    type: http
    url: https://example.com/proxies.yaml
    path: ./remote.yaml
    interval: 3600
proxy-groups:
  - name: proxy
    type: select
    proxies: [local]
    use: [remote]
rules:
  - MATCH,proxy
"#
            .to_owned(),
        )
        .try_parse()
        .unwrap();

        assert!(required_proxy_providers(&config).is_empty());
    }

    #[test]
    fn start_and_stop() {
        let conf = r#"
        socks-port: 7891
        bind-address: 127.0.0.1
        mmdb: "tests/data/Country.mmdb"
        proxies:
          - {name: DIRECT_alias, type: direct}
          - {name: REJECT_alias, type: reject}
        "#;

        let handle = thread::spawn(|| {
            start_scaffold(Options {
                config: Config::Str(conf.to_string()),
                cwd: None,
                rt: None,
                log_file: None,
                config_path: None,
            })
            .unwrap()
        });

        thread::spawn(|| {
            thread::sleep(Duration::from_secs(3));
            assert!(shutdown());
        });

        handle.join().unwrap();
    }

    #[cfg(feature = "tun")]
    #[test]
    fn builds_external_tun_from_flclash_android_arguments() {
        let config = crate::external_tun_config(
            42,
            "172.19.0.1/30,fdfe:dcba:9876::1/126",
            "172.19.0.2,fdfe:dcba:9876::2",
        )
        .unwrap();

        assert!(config.enable);
        assert_eq!(config.device_id, "fd://42");
        assert_eq!(config.gateway.to_string(), "172.19.0.1/30");
        assert_eq!(
            config.gateway_v6.map(|value| value.to_string()).as_deref(),
            Some("fdfe:dcba:9876::1/126"),
        );
        assert!(config.dns_hijack);
        assert_eq!(
            config.dns_hijack_targets,
            vec![
                "172.19.0.2".parse::<std::net::IpAddr>().unwrap(),
                "fdfe:dcba:9876::2".parse::<std::net::IpAddr>().unwrap(),
            ],
        );
        assert!(!config.route_all);
        let any_dns =
            crate::external_tun_config(42, "172.19.0.1/30", "0.0.0.0").unwrap();
        assert!(any_dns.dns_hijack);
        assert!(any_dns.dns_hijack_targets.is_empty());
        assert!(crate::external_tun_config(0, "172.19.0.1/30", "").is_err());
    }

    #[cfg(feature = "tun")]
    #[tokio::test]
    async fn stuck_tun_runner_does_not_block_replacement() {
        use crate::{ArcRunner, Error, Runner, stop_runtime_tun_runner};
        use futures::{FutureExt, future::BoxFuture};
        use std::{future, sync::Arc, time::Instant};

        struct StuckRunner;

        impl Runner for StuckRunner {
            fn run_async(&self) {}

            fn shutdown(&self) {}

            fn join(&self) -> BoxFuture<'_, Result<(), Error>> {
                future::pending().boxed()
            }
        }

        let runner: ArcRunner = Arc::new(StuckRunner);
        let started = Instant::now();
        stop_runtime_tun_runner(&runner, Duration::from_millis(10)).await;

        assert!(started.elapsed() < Duration::from_secs(1));
    }
}
