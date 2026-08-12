use std::{path::PathBuf, sync::Arc};

use axum::{
    Json, Router,
    extract::{Query, State},
    response::IntoResponse,
    routing::{get, post},
};

use http::StatusCode;
use serde::{Deserialize, Serialize};
use serde_json::json;
use tokio::sync::Mutex;

use crate::{
    GlobalState,
    app::{
        api::AppState,
        dispatcher,
        dns::{ThreadSafeDNSResolver, config::DNSListenAddr},
        inbound::manager::{InboundEndpoint, InboundManager, Ports},
        outbound::manager::ThreadSafeOutboundManager,
        router::ArcRouter,
    },
    config::{def, internal::config::BindAddress},
};

#[derive(Serialize)]
struct DnsListenInfo {
    #[serde(skip_serializing_if = "Option::is_none")]
    udp: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    tcp: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    doh: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    dot: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    doh3: Option<String>,
}

#[derive(Clone)]
struct ConfigState {
    inbound_manager: Arc<InboundManager>,
    dispatcher: Arc<dispatcher::Dispatcher>,
    global_state: Arc<Mutex<GlobalState>>,
    dns_resolver: ThreadSafeDNSResolver,
    dns_listen_addr: DNSListenAddr,
    dns_enabled: bool,
    outbound_manager: ThreadSafeOutboundManager,
    router: ArcRouter,
}

pub fn routes(
    inbound_manager: Arc<InboundManager>,
    dispatcher: Arc<dispatcher::Dispatcher>,
    global_state: Arc<Mutex<GlobalState>>,
    dns_resolver: ThreadSafeDNSResolver,
    dns_listen_addr: DNSListenAddr,
    dns_enabled: bool,
    outbound_manager: ThreadSafeOutboundManager,
    router: ArcRouter,
) -> Router<Arc<AppState>> {
    Router::new()
        .route(
            "/",
            get(get_configs).put(update_configs).patch(patch_configs),
        )
        .route("/listeners/start", post(start_listeners))
        .route("/listeners/stop", post(stop_listeners))
        .with_state(ConfigState {
            inbound_manager,
            dispatcher,
            global_state,
            dns_resolver,
            dns_listen_addr,
            dns_enabled,
            outbound_manager,
            router,
        })
}

#[derive(Default, Deserialize)]
struct StartListenerQuery {
    #[serde(default, rename = "defer-healthchecks")]
    defer_healthchecks: bool,
}

async fn start_listeners(
    State(state): State<ConfigState>,
    Query(query): Query<StartListenerQuery>,
) -> impl IntoResponse {
    let dns_listener = state.global_state.lock().await.dns_listener.clone();
    if let Err(error) = dns_listener.start_and_wait().await {
        return (
            StatusCode::INTERNAL_SERVER_ERROR,
            format!("failed to start DNS listener: {error}"),
        )
            .into_response();
    }
    match state.inbound_manager.restart().await {
        Ok(()) => {
            if !query.defer_healthchecks {
                state.outbound_manager.start_background_proxy_providers();
                state.router.initialize_rule_providers();
                state.outbound_manager.start_healthchecks();
            }
            StatusCode::NO_CONTENT.into_response()
        }
        Err(error) => {
            dns_listener.stop_listener();
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                format!("failed to start listeners: {error}"),
            )
                .into_response()
        }
    }
}

async fn stop_listeners(State(state): State<ConfigState>) -> impl IntoResponse {
    state.global_state.lock().await.dns_listener.stop_listener();
    state.inbound_manager.stop_listeners().await;
    StatusCode::NO_CONTENT
}

async fn get_configs(State(state): State<ConfigState>) -> impl IntoResponse {
    let run_mode = state.dispatcher.get_mode().await;
    let (
        log_level,
        reload_generation,
        reload_attempt,
        reload_completed,
        reload_error,
        reload_phase,
    ) = {
        let global_state = state.global_state.lock().await;
        (
            global_state.log_level,
            global_state.reload_generation,
            global_state.reload_attempt,
            global_state.reload_completed,
            global_state.reload_error.clone(),
            global_state.reload_phase.clone(),
        )
    };
    let inbound_manager = state.inbound_manager.clone();

    let ports = inbound_manager.get_ports().await;
    let allow_lan = inbound_manager.get_allow_lan().await;
    let listeners = inbound_manager.get_listeners().await;
    let bind_address = inbound_manager.get_bind_address().await.0.to_string();

    let lan_ips = if allow_lan {
        use network_interface::{NetworkInterface, NetworkInterfaceConfig};
        Some({
            let mut ips = NetworkInterface::show()
                .unwrap_or_default()
                .into_iter()
                .flat_map(|iface| {
                    iface.addr.into_iter().filter_map(|addr| match addr {
                        network_interface::Addr::V4(v4)
                            if !v4.ip.is_loopback() && !v4.ip.is_link_local() =>
                        {
                            Some(v4.ip.to_string())
                        }
                        _ => None,
                    })
                })
                .collect::<Vec<_>>();
            ips.sort();
            ips.dedup();
            ips
        })
    } else {
        None
    };

    let dns_listen = if state.dns_enabled {
        let addr = &state.dns_listen_addr;
        Some(DnsListenInfo {
            udp: addr.udp.map(|a| a.to_string()),
            tcp: addr.tcp.map(|a| a.to_string()),
            doh: addr.doh.as_ref().map(|c| c.addr.to_string()),
            dot: addr.dot.as_ref().map(|c| c.addr.to_string()),
            doh3: addr.doh3.as_ref().map(|c| c.addr.to_string()),
        })
    } else {
        None
    };

    axum::response::Json(GetConfigResponse {
        port: ports.port,
        socks_port: ports.socks_port,
        redir_port: ports.redir_port,
        tproxy_port: ports.tproxy_port,
        mixed_port: ports.mixed_port,
        bind_address: Some(bind_address),
        mode: Some(run_mode),
        log_level: Some(log_level),
        ipv6: Some(state.dns_resolver.ipv6()),
        allow_lan: Some(allow_lan),
        listeners: Some(listeners),
        lan_ips,
        dns_listen,
        reload_generation,
        reload_attempt,
        reload_completed,
        reload_error,
        reload_phase,
    })
}

#[derive(Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
struct UpdateConfigRequest {
    path: Option<String>,
    payload: Option<String>,
}

#[derive(Serialize, Deserialize)]
struct UploadConfigQuery {
    force: Option<bool>,
}

async fn update_configs(
    _q: Query<UploadConfigQuery>,
    State(state): State<ConfigState>,
    Json(req): Json<UpdateConfigRequest>,
) -> impl IntoResponse {
    // Extract only what we need, then drop the lock before the async reload.
    let (reload_tx, cwd, config_path) = {
        let g = state.global_state.lock().await;
        (g.reload_tx.clone(), g.cwd.clone(), g.config_path.clone())
    };

    let cfg = match (req.path.as_deref(), req.payload) {
        (_, Some(payload)) => crate::Config::Str(payload),

        // Non-empty explicit path: validate and reload from that file.
        (Some(p), None) if !p.is_empty() => {
            let mut path = p.to_string();
            if !PathBuf::from(&path).is_absolute() {
                path = PathBuf::from(&cwd).join(path).to_string_lossy().to_string();
            }
            if !PathBuf::from(&path).exists() {
                return (
                    StatusCode::BAD_REQUEST,
                    format!("config file {path} not found"),
                )
                    .into_response();
            }
            if PathBuf::from(&path).is_dir() {
                return (
                    StatusCode::BAD_REQUEST,
                    format!("config path {path} is a directory"),
                )
                    .into_response();
            }
            crate::Config::File(path)
        }

        // Empty path or no path: reload from the startup config file.
        _ => match config_path {
            Some(p) => crate::Config::File(p),
            None => {
                return (StatusCode::BAD_REQUEST, "no path or payload provided")
                    .into_response();
            }
        },
    };

    // A reload replaces the API server itself. Waiting for completion in this
    // request creates a cycle: the reload waits for the old server to stop,
    // while the old server keeps this request alive waiting for the reload.
    // Acknowledge the queued attempt and let clients observe the terminal state
    // through GET /configs.
    let reload_attempt = {
        let mut global_state = state.global_state.lock().await;
        global_state.reload_attempt = global_state.reload_attempt.saturating_add(1);
        global_state.reload_phase = "queued".to_owned();
        global_state.reload_attempt
    };
    match reload_tx.send((reload_attempt, cfg)).await {
        Ok(_) => (
            StatusCode::ACCEPTED,
            Json(json!({"reload-attempt": reload_attempt})),
        )
            .into_response(),
        Err(_) => {
            let error = "could not signal config reload".to_string();
            let mut global_state = state.global_state.lock().await;
            global_state.reload_completed = reload_attempt;
            global_state.reload_error = Some(error.clone());
            global_state.reload_phase = "failed".to_owned();
            (StatusCode::INTERNAL_SERVER_ERROR, error).into_response()
        }
    }
}

#[derive(Serialize)]
#[serde(rename_all = "kebab-case")]
struct GetConfigResponse {
    port: Option<u16>,
    socks_port: Option<u16>,
    redir_port: Option<u16>,
    tproxy_port: Option<u16>,
    mixed_port: Option<u16>,
    bind_address: Option<String>,
    mode: Option<def::RunMode>,
    log_level: Option<def::LogLevel>,
    ipv6: Option<bool>,
    allow_lan: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    listeners: Option<Vec<InboundEndpoint>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    lan_ips: Option<Vec<String>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    dns_listen: Option<DnsListenInfo>,
    reload_generation: u64,
    reload_attempt: u64,
    reload_completed: u64,
    #[serde(skip_serializing_if = "Option::is_none")]
    reload_error: Option<String>,
    reload_phase: String,
}

#[derive(Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
struct PatchConfigRequest {
    port: Option<u16>,
    socks_port: Option<u16>,
    redir_port: Option<u16>,
    tproxy_port: Option<u16>,
    mixed_port: Option<u16>,
    bind_address: Option<String>,
    mode: Option<def::RunMode>,
    log_level: Option<def::LogLevel>,
    ipv6: Option<bool>,
    allow_lan: Option<bool>,
    sniffing: Option<bool>,
    tcp_concurrent: Option<bool>,
    interface_name: Option<String>,
    unified_delay: Option<bool>,
    healthcheck_concurrency: Option<usize>,
    find_process_mode: Option<def::FindProcessMode>,
    suspended: Option<bool>,
}

impl PatchConfigRequest {
    fn rebuild_listeners(&self) -> bool {
        self.port.is_some()
            || self.socks_port.is_some()
            || self.redir_port.is_some()
            || self.tproxy_port.is_some()
            || self.mixed_port.is_some()
            || self.bind_address.is_some()
    }
}

async fn patch_configs(
    State(state): State<ConfigState>,
    Json(payload): Json<PatchConfigRequest>,
) -> impl IntoResponse {
    let inbound_manager = state.inbound_manager.clone();
    let mut need_restart = false;
    if let Some(bind_address) = payload.bind_address.clone() {
        match bind_address.parse::<BindAddress>() {
            Ok(bind_address) => {
                need_restart |= inbound_manager.set_bind_address(bind_address).await;
            }
            Err(_) => {
                return (
                    StatusCode::BAD_REQUEST,
                    format!("invalid bind address: {bind_address}"),
                )
                    .into_response();
            }
        }
    }

    if payload.rebuild_listeners() {
        let ports = Ports {
            port: payload.port,
            socks_port: payload.socks_port,
            redir_port: payload.redir_port,
            tproxy_port: payload.tproxy_port,
            mixed_port: payload.mixed_port,
        };
        let changed = inbound_manager.change_ports(ports).await;
        need_restart |= changed;
    }

    if let Some(allow_lan) = payload.allow_lan
        && allow_lan != inbound_manager.get_allow_lan().await
    {
        inbound_manager.set_allow_lan(allow_lan).await;
        // TODO: can be done with AtomicBool in each inbound manager, but requires
        // more changes
        need_restart = true;
    }

    // Apply mode change before restarting listeners so that new connections
    // established after the restart immediately use the updated mode.
    if let Some(mode) = payload.mode {
        state.dispatcher.set_mode(mode).await;
    }

    if let Some(sniffing) = payload.sniffing {
        state.dispatcher.set_sniffing(sniffing);
    }
    if let Some(tcp_concurrent) = payload.tcp_concurrent {
        crate::proxy::utils::set_tcp_concurrent(tcp_concurrent);
    }
    if let Some(interface_name) = payload.interface_name
        && let Err(error) =
            crate::app::net::set_outbound_interface(Some(&interface_name)).await
    {
        return (StatusCode::BAD_REQUEST, error).into_response();
    }
    if let Some(unified_delay) = payload.unified_delay {
        state.outbound_manager.set_unified_delay(unified_delay);
    }
    if let Some(concurrency) = payload.healthcheck_concurrency
        && let Err(error) = state
            .outbound_manager
            .set_healthcheck_concurrency(concurrency)
            .await
    {
        return (StatusCode::BAD_REQUEST, error).into_response();
    }
    if let Some(find_process_mode) = payload.find_process_mode {
        crate::process_resolver::set_find_process_mode(find_process_mode);
    }
    if let Some(suspended) = payload.suspended {
        state.dispatcher.set_suspended(suspended);
    }

    if need_restart {
        let _ = inbound_manager.restart().await;
    }

    if let Some(ipv6) = payload.ipv6 {
        state.dns_resolver.set_ipv6(ipv6);
    }

    // Only lock global_state for the small section that actually needs it.
    // Holding it across inbound_manager.restart() (which can be slow) was
    // blocking concurrent GET /configs requests unnecessarily.
    if let Some(log_level) = payload.log_level {
        let mut global_state = state.global_state.lock().await;
        global_state.log_level = log_level;
    }

    (
        StatusCode::ACCEPTED,
        axum::response::Json(json!({"message": "configs updated"})),
    )
        .into_response()
}
