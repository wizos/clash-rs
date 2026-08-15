use super::utils::proxy_groups_dag_sort;
#[cfg(feature = "masque")]
use crate::proxy::masque;
#[cfg(feature = "mieru")]
use crate::proxy::mieru;
#[cfg(feature = "openvpn")]
use crate::proxy::openvpn;
#[cfg(feature = "shadowquic")]
use crate::proxy::shadowquic;
#[cfg(feature = "shadowsocks")]
use crate::proxy::shadowsocks;
#[cfg(feature = "ssh")]
use crate::proxy::ssh;
#[cfg(feature = "sudoku")]
use crate::proxy::sudoku;
#[cfg(feature = "tailscale")]
use crate::proxy::tailscale;
#[cfg(feature = "onion")]
use crate::proxy::tor;
#[cfg(feature = "tuic")]
use crate::proxy::tuic;
#[cfg(feature = "wireguard")]
use crate::proxy::wg;
use crate::{
    Error,
    app::{
        dns::{RuleDispatch, ThreadSafeDNSResolver},
        profile::ThreadSafeCacheFile,
        remote_content_manager::{
            ProxyManager,
            healthcheck::HealthCheck,
            providers::{
                ProviderVehicleType, ThreadSafeProviderVehicle, file_vehicle,
                http_vehicle,
                proxy_provider::{
                    ArcProxyProvider, FilteredProvider, PlainProvider,
                    ProxySetProvider,
                },
            },
        },
    },
    config::internal::proxy::{
        DEFAULT_LATENCY_TEST_URL, OutboundGroupProtocol, OutboundGroupSelection,
        OutboundProxyProtocol, OutboundProxyProviderDef, PROXY_COMPATIBLE,
        PROXY_DIRECT, PROXY_GLOBAL, PROXY_REJECT,
    },
    proxy::{
        AnyOutboundHandler, anytls,
        direct::{self},
        dns as dns_outbound, fallback, gost_relay,
        group::{route_race, smart},
        http, hysteria, hysteria2, loadbalance, reject, relay,
        selector::{self, ThreadSafeSelectorControl},
        snell, socks, trojan, trusttunnel, urltest,
        utils::{DirectConnector, OutboundHandlerRegistry, ProxyConnector},
        vless, vmess,
    },
};
use anyhow::Result;
use erased_serde::Serialize;
use hyper::Uri;
use parking_lot::Mutex;
use std::{
    collections::{HashMap, HashSet},
    path::PathBuf,
    sync::Arc,
    time::Duration,
};
use tracing::{debug, error, info};
use uuid::Uuid;

static RESERVED_PROVIDER_NAME: &str = "default";

fn group_healthcheck_interval(auto_healthcheck_group: bool, interval: u64) -> u64 {
    if auto_healthcheck_group && interval == 0 {
        300
    } else {
        interval
    }
}

pub struct OutboundManager {
    /// Shared registry used by both OutboundManager lookups and the DNS /
    /// HTTP bootstrap clients.  Populated at the end of `new()` and is the
    /// single source of truth for all handlers after initialization.
    registry: OutboundHandlerRegistry,
    /// name -> provider
    proxy_providers: HashMap<String, ArcProxyProvider>,
    proxy_manager: ProxyManager,
    selector_control: HashMap<String, ThreadSafeSelectorControl>,
    started_proxy_providers: Mutex<HashSet<String>>,
}

pub type ThreadSafeOutboundManager = Arc<OutboundManager>;

/// Init process:
/// 1. Load all plaint outbounds from config using the unbounded function
///    `load_plain_outbounds`, so that any bootstrap proxy can be used to
///    download datasets
/// 2. Load all proxy providers from config, this should happen before loading
///    groups as groups my reference providers with `use_provider`
/// 3. Finally load all groups, and create `PlainProvider` for each explicit
///    referenced proxies in each group and register them in the
///    `proxy_providers` map.
/// 4. Create a `PlainProvider` for the global proxy set, which is the GLOBAL
///    selector, which should contain all plain outbound + provider proxies +
///    groups
///
/// Note that the `PlainProvider` is a special provider that contains plain
/// proxies for API compatibility with actual remote providers.
/// TODO: refactor this giant class
#[allow(clippy::too_many_arguments)]
impl OutboundManager {
    pub async fn new(
        outbounds: Vec<AnyOutboundHandler>,
        outbound_groups: Vec<OutboundGroupProtocol>,
        proxy_providers: HashMap<String, OutboundProxyProviderDef>,
        proxy_names: Vec<String>,
        dns_resolver: ThreadSafeDNSResolver,
        cache_store: ThreadSafeCacheFile,
        cwd: String,
        fw_mark: Option<u32>,
        failover_race_delay: Duration,
        route_race_delay: Duration,
        registry: OutboundHandlerRegistry,
        rule_dispatch: Arc<RuleDispatch>,
    ) -> Result<Self, Error> {
        // Build all handlers in a plain HashMap during initialization.
        // Once fully assembled it is written into the shared registry so that
        // DNS clients and the HTTP client can look up any handler by name.
        let mut handlers: HashMap<String, AnyOutboundHandler> = HashMap::new();
        let provider_registry = HashMap::new();
        let selector_control = HashMap::new();
        let proxy_manager = ProxyManager::new(dns_resolver.clone(), fw_mark);

        let mut m = Self {
            registry,
            proxy_manager,
            selector_control,
            proxy_providers: provider_registry,
            started_proxy_providers: Mutex::new(HashSet::new()),
        };

        debug!("initializing proxy providers");
        m.load_proxy_providers(cwd, proxy_providers, dns_resolver, rule_dispatch)
            .await?;

        debug!("initializing handlers");
        m.load_handlers(
            &mut handlers,
            outbounds,
            outbound_groups,
            proxy_names,
            cache_store,
            failover_race_delay,
            route_race_delay,
        )
        .await?;

        debug!("initializing connectors");
        m.init_handler_connectors(&handlers).await?;

        // Replace the shared registry with the freshly assembled handler map.
        // Using `clone()` + `*reg = ...` ensures stale entries from previous
        // initialisation rounds (e.g. across hot reloads) are removed.
        {
            let mut reg = m.registry.write().await;
            *reg = handlers
                .iter()
                .map(|(k, v)| {
                    debug!("registering outbound '{}' in bootstrap registry", k);
                    (k.clone(), v.clone())
                })
                .collect();
        }

        Ok(m)
    }

    /// Look up a handler by name. Returns `None` when the name is not
    /// registered.  The registry is read under a shared lock, so this method
    /// is `async` — callers must `.await` the result.
    pub async fn get_outbound(&self, name: &str) -> Option<AnyOutboundHandler> {
        self.registry.read().await.get(name).cloned()
    }

    pub async fn get_provider_proxy(
        &self,
        name: &str,
    ) -> Option<AnyOutboundHandler> {
        for provider in self.proxy_providers.values() {
            if let Some(proxy) = provider
                .proxies()
                .await
                .into_iter()
                .find(|proxy| proxy.name() == name)
            {
                return Some(proxy);
            }
        }

        None
    }

    /// this doesn't populate history/liveness information
    pub fn get_proxy_provider(&self, name: &str) -> Option<ArcProxyProvider> {
        self.proxy_providers.get(name).cloned()
    }

    // API handles start
    pub fn get_selector_control(
        &self,
        name: &str,
    ) -> Option<ThreadSafeSelectorControl> {
        self.selector_control.get(name).cloned()
    }

    /// Get all proxies in the manager, including those in providers.
    pub async fn get_proxies(&self) -> HashMap<String, Box<dyn Serialize + Send>> {
        let mut r = HashMap::new();

        // Snapshot the registry without holding the lock across async calls.
        let handlers: Vec<(String, AnyOutboundHandler)> = self
            .registry
            .read()
            .await
            .iter()
            .map(|(k, v)| (k.clone(), v.clone()))
            .collect();

        for (k, v) in handlers {
            let mut m = if let Some(g) = v.try_as_group_handler() {
                g.as_map().await
            } else if let Some(p) = v.try_as_plain_handler() {
                p.as_map().await
            } else {
                HashMap::new()
            };

            self.apply_common_proxy_fields(&mut m, &v, &k).await;

            r.insert(k.clone(), Box::new(m) as _);
        }

        for provider in self.proxy_providers.values() {
            for proxy in provider.proxies().await {
                let name = proxy.name().to_owned();
                if r.contains_key(&name) {
                    continue;
                }

                r.insert(name.clone(), Box::new(self.get_proxy(&proxy).await) as _);
            }
        }

        r
    }

    pub async fn get_proxy(
        &self,
        proxy: &AnyOutboundHandler,
    ) -> HashMap<String, Box<dyn Serialize + Send>> {
        let mut r = if let Some(g) = proxy.try_as_group_handler() {
            g.as_map().await
        } else if let Some(p) = proxy.try_as_plain_handler() {
            p.as_map().await
        } else {
            HashMap::new()
        };
        self.apply_common_proxy_fields(&mut r, proxy, proxy.name())
            .await;

        r
    }

    async fn apply_common_proxy_fields(
        &self,
        m: &mut HashMap<String, Box<dyn Serialize + Send>>,
        proxy: &AnyOutboundHandler,
        name: &str,
    ) {
        let alive = self.proxy_manager.alive(name).await;
        let history = self.proxy_manager.delay_history(name).await;
        let health_by_url = self.proxy_manager.health_by_url(name).await;
        let support_udp = proxy.support_udp().await;

        let id = Uuid::new_v5(&Uuid::NAMESPACE_OID, name.as_bytes());
        m.insert("id".to_string(), Box::new(id.to_string()));
        m.insert("history".to_string(), Box::new(history));
        m.insert("healthByUrl".to_string(), Box::new(health_by_url));
        m.insert("alive".to_string(), Box::new(alive));
        m.insert("name".to_string(), Box::new(name.to_owned()));
        m.insert("type".to_string(), Box::new(proxy.proto().to_string()));
        m.insert("udp".to_string(), Box::new(support_udp));
        m.insert("uot".to_string(), Box::new(false));
        m.insert("xudp".to_string(), Box::new(false));
        m.insert("tfo".to_string(), Box::new(false));
        m.insert("mptcp".to_string(), Box::new(false));
        m.insert("smux".to_string(), Box::new(false));
        m.insert("interface".to_string(), Box::new(""));
        m.insert("dialer-proxy".to_string(), Box::new(""));
        m.insert("routing-mark".to_string(), Box::new(0));
        m.insert("provider-name".to_string(), Box::new(""));
        m.insert(
            "extra".to_string(),
            Box::new(HashMap::<String, String>::new()),
        );
    }

    /// a wrapper of proxy_manager.url_test so that proxy_manager is not exposed
    pub async fn url_test(
        &self,
        outbounds: &Vec<AnyOutboundHandler>,
        url: &str,
        timeout: Duration,
    ) -> Vec<std::io::Result<(Duration, Duration)>> {
        let proxy_manager = self.proxy_manager.clone();
        proxy_manager.check(outbounds, url, Some(timeout)).await
    }

    pub fn set_unified_delay(&self, enabled: bool) {
        self.proxy_manager.set_unified_delay(enabled);
    }

    pub async fn set_healthcheck_concurrency(
        &self,
        concurrency: usize,
    ) -> Result<(), String> {
        self.proxy_manager
            .set_healthcheck_concurrency(concurrency)
            .await
    }

    pub fn start_healthchecks(&self) {
        for provider in self.proxy_providers.values() {
            provider.start_healthcheck();
        }
    }

    pub async fn clear_route_caches(&self) {
        for handler in self.registry.read().await.values() {
            handler.clear_route_cache();
        }
    }

    pub fn selected_delay(
        &self,
        actual: std::time::Duration,
        overall: std::time::Duration,
    ) -> std::time::Duration {
        self.proxy_manager.selected_delay(actual, overall)
    }

    pub fn get_proxy_providers(&self) -> HashMap<String, ArcProxyProvider> {
        self.proxy_providers.clone()
    }

    pub async fn initialize_proxy_providers(
        &self,
        required: &HashSet<String>,
    ) -> Result<(), Error> {
        if required.is_empty() {
            return Ok(());
        }
        let (tx, mut rx) = tokio::sync::mpsc::unbounded_channel();
        let providers = {
            let mut started = self.started_proxy_providers.lock();
            self.proxy_providers
                .iter()
                .filter(|(name, _)| {
                    required.contains(*name) && started.insert((*name).clone())
                })
                .map(|(_, provider)| provider.clone())
                .collect::<Vec<_>>()
        };
        for provider in providers {
            let tx = tx.clone();
            tokio::spawn(async move {
                let name = provider.name().to_owned();
                info!("initializing proxy provider {name}");
                let result = provider.initialize().await;
                if let Err(error) = &result {
                    error!("failed to initialize proxy provider {name}: {error}");
                } else {
                    info!("initialized proxy provider {name}");
                }
                let _ = tx.send((name, result));
            });
        }
        drop(tx);

        let mut failures = Vec::new();
        while let Some((name, result)) = rx.recv().await {
            if !required.contains(&name) {
                continue;
            }
            match result {
                Ok(()) => return Ok(()),
                Err(error) => failures.push(format!("{name}: {error}")),
            }
            if failures.len() == required.len() {
                break;
            }
        }
        Err(Error::Operation(format!(
            "required proxy provider unavailable: {}",
            failures.join("; ")
        )))
    }

    pub fn start_background_proxy_providers(&self) {
        let providers = {
            let mut started = self.started_proxy_providers.lock();
            self.proxy_providers
                .iter()
                .filter(|(name, _)| started.insert((*name).clone()))
                .map(|(_, provider)| provider.clone())
                .collect::<Vec<_>>()
        };
        for provider in providers {
            tokio::spawn(async move {
                let name = provider.name().to_owned();
                info!("initializing background proxy provider {name}");
                if let Err(error) = provider.initialize().await {
                    error!("failed to initialize proxy provider {name}: {error}");
                }
            });
        }
    }

    // API handlers end

    /// Lazy initialization of connectors for each handler.
    async fn init_handler_connectors(
        &self,
        handlers: &HashMap<String, AnyOutboundHandler>,
    ) -> Result<(), Error> {
        let mut connectors = HashMap::new();
        for handler in handlers.values() {
            if let Some(connector_name) = handler.support_dialer() {
                let outbound = handlers
                    .get(connector_name)
                    .ok_or(Error::InvalidConfig(format!(
                        "connector {connector_name} not found"
                    )))?
                    .clone();
                let connector =
                    connectors.entry(connector_name).or_insert_with(|| {
                        Arc::new(ProxyConnector::new(
                            outbound,
                            Box::new(DirectConnector::new()),
                        ))
                    });
                handler.register_connector(connector.clone()).await;
            }
        }

        Ok(())
    }

    pub fn load_plain_outbounds(
        outbounds: Vec<OutboundProxyProtocol>,
    ) -> Result<Vec<AnyOutboundHandler>, Error> {
        outbounds
            .into_iter()
            .map(|outbound| match outbound {
                OutboundProxyProtocol::Direct(d) => {
                    Ok(Arc::new(direct::Handler::new(&d.name)) as _)
                }
                OutboundProxyProtocol::Reject(r) => {
                    Ok(Arc::new(reject::Handler::new(&r.name)) as _)
                }
                OutboundProxyProtocol::Dns(d) => {
                    Ok(Arc::new(dns_outbound::Handler::new(&d.name)) as _)
                }
                OutboundProxyProtocol::GostRelay(relay) => {
                    let name = relay.common_opts.name.clone();
                    relay
                        .try_into()
                        .map(|handler: gost_relay::Handler| {
                            Arc::new(handler) as AnyOutboundHandler
                        })
                        .map_err(|error| {
                            Error::InvalidConfig(format!(
                                "failed to load GOST Relay outbound {name}: {error}"
                            ))
                        })
                }
                OutboundProxyProtocol::Snell(config) => {
                    let name = config.common_opts.name.clone();
                    config
                        .try_into()
                        .map(|handler: snell::Handler| {
                            Arc::new(handler) as AnyOutboundHandler
                        })
                        .map_err(|error| {
                            Error::InvalidConfig(format!(
                                "failed to load Snell outbound {name}: {error}"
                            ))
                        })
                }
                OutboundProxyProtocol::TrustTunnel(config) => {
                    let name = config.common_opts.name.clone();
                    config
                        .try_into()
                        .map(|handler: trusttunnel::Handler| {
                            Arc::new(handler) as AnyOutboundHandler
                        })
                        .map_err(|error| {
                            Error::InvalidConfig(format!(
                                "failed to load TrustTunnel outbound {name}: \
                                 {error}"
                            ))
                        })
                }
                #[cfg(feature = "masque")]
                OutboundProxyProtocol::Masque(config) => {
                    let name = config.common_opts.name.clone();
                    config
                        .try_into()
                        .map(|handler: masque::Handler| {
                            Arc::new(handler) as AnyOutboundHandler
                        })
                        .map_err(|error| {
                            Error::InvalidConfig(format!(
                                "failed to load MASQUE outbound {name}: {error}"
                            ))
                        })
                }
                #[cfg(feature = "mieru")]
                OutboundProxyProtocol::Mieru(config) => {
                    let name = config.name.clone();
                    config
                        .try_into()
                        .map(|handler: mieru::Handler| {
                            Arc::new(handler) as AnyOutboundHandler
                        })
                        .map_err(|error| {
                            Error::InvalidConfig(format!(
                                "failed to load Mieru outbound {name}: {error}"
                            ))
                        })
                }
                #[cfg(feature = "sudoku")]
                OutboundProxyProtocol::Sudoku(config) => {
                    let name = config.common_opts.name.clone();
                    config
                        .try_into()
                        .map(|handler: sudoku::Handler| {
                            Arc::new(handler) as AnyOutboundHandler
                        })
                        .map_err(|error| {
                            Error::InvalidConfig(format!(
                                "failed to load sudoku outbound {name}: {error}"
                            ))
                        })
                }
                #[cfg(feature = "shadowsocks")]
                OutboundProxyProtocol::Ss(s) => {
                    let name = s.common_opts.name.clone();
                    s.try_into()
                        .map(|x: shadowsocks::outbound::Handler| {
                            Arc::new(x) as AnyOutboundHandler
                        })
                        .map_err(|error| {
                            Error::InvalidConfig(format!(
                                "failed to load shadowsocks outbound {name}: \
                                 {error}"
                            ))
                        })
                }
                #[cfg(feature = "shadowsocks")]
                OutboundProxyProtocol::Ssr(s) => {
                    let name = s.common_opts.name.clone();
                    s.try_into()
                        .map(|handler: shadowsocks::outbound::Handler| {
                            Arc::new(handler) as AnyOutboundHandler
                        })
                        .map_err(|error| {
                            Error::InvalidConfig(format!(
                                "failed to load shadowsocksr outbound {name}: \
                                 {error}"
                            ))
                        })
                }
                OutboundProxyProtocol::Socks5(s) => {
                    let name = s.common_opts.name.clone();
                    s.try_into()
                        .map(|x: socks::outbound::Handler| {
                            Arc::new(x) as AnyOutboundHandler
                        })
                        .map_err(|error| {
                            Error::InvalidConfig(format!(
                                "failed to load socks5 outbound {name}: {error}"
                            ))
                        })
                }
                OutboundProxyProtocol::Http(h) => {
                    let name = h.common_opts.name.clone();
                    h.try_into()
                        .map(|handler: http::HttpOutbound| {
                            Arc::new(handler) as AnyOutboundHandler
                        })
                        .map_err(|error| {
                            Error::InvalidConfig(format!(
                                "failed to load HTTP outbound {name}: {error}"
                            ))
                        })
                }
                OutboundProxyProtocol::Anytls(v) => {
                    let name = v.common_opts.name.clone();
                    v.try_into()
                        .map(|x: anytls::Handler| Arc::new(x) as _)
                        .map_err(|error| {
                            Error::InvalidConfig(format!(
                                "failed to load anytls outbound {name}: {error}"
                            ))
                        })
                }
                OutboundProxyProtocol::Vmess(v) => {
                    let name = v.common_opts.name.clone();
                    v.try_into()
                        .map(|x: vmess::Handler| Arc::new(x) as AnyOutboundHandler)
                        .map_err(|error| {
                            Error::InvalidConfig(format!(
                                "failed to load vmess outbound {name}: {error}"
                            ))
                        })
                }
                OutboundProxyProtocol::Vless(v) => {
                    let name = v.common_opts.name.clone();
                    v.try_into()
                        .map(|x: vless::Handler| Arc::new(x) as AnyOutboundHandler)
                        .map_err(|error| {
                            Error::InvalidConfig(format!(
                                "failed to load vless outbound {name}: {error}"
                            ))
                        })
                }
                OutboundProxyProtocol::Trojan(v) => {
                    let name = v.common_opts.name.clone();
                    v.try_into()
                        .map(|x: trojan::Handler| Arc::new(x) as _)
                        .map_err(|error| {
                            Error::InvalidConfig(format!(
                                "failed to load trojan outbound {name}: {error}"
                            ))
                        })
                }
                OutboundProxyProtocol::Hysteria2(h) => {
                    let name = h.name.clone();
                    h.try_into()
                        .map(|x: hysteria2::Handler| Arc::new(x) as _)
                        .map_err(|error| {
                            Error::InvalidConfig(format!(
                                "failed to load hysteria2 outbound {name}: {error}"
                            ))
                        })
                }
                OutboundProxyProtocol::Hysteria(h) => {
                    let name = h.name.clone();
                    h.try_into()
                        .map(|x: hysteria::Handler| Arc::new(x) as _)
                        .map_err(|error| {
                            Error::InvalidConfig(format!(
                                "failed to load hysteria outbound {name}: {error}"
                            ))
                        })
                }
                #[cfg(feature = "wireguard")]
                OutboundProxyProtocol::Wireguard(wg) => {
                    let name = wg.common_opts.name.clone();
                    wg.try_into()
                        .map(|x: wg::Handler| Arc::new(x) as AnyOutboundHandler)
                        .map_err(|error| {
                            Error::InvalidConfig(format!(
                                "failed to load wireguard outbound {name}: {error}"
                            ))
                        })
                }
                #[cfg(feature = "openvpn")]
                OutboundProxyProtocol::Openvpn(openvpn_config) => {
                    let name = openvpn_config.common_opts.name.clone();
                    openvpn_config
                        .try_into()
                        .map(|handler: openvpn::Handler| {
                            Arc::new(handler) as AnyOutboundHandler
                        })
                        .map_err(|error| {
                            Error::InvalidConfig(format!(
                                "failed to load openvpn outbound {name}: {error}"
                            ))
                        })
                }
                #[cfg(feature = "ssh")]
                OutboundProxyProtocol::Ssh(ssh) => {
                    let name = ssh.common_opts.name.clone();
                    ssh.try_into()
                        .map(|x: ssh::Handler| Arc::new(x) as _)
                        .map_err(|error| {
                            Error::InvalidConfig(format!(
                                "failed to load ssh outbound {name}: {error}"
                            ))
                        })
                }
                #[cfg(feature = "onion")]
                OutboundProxyProtocol::Tor(tor) => {
                    let name = tor.name.clone();
                    tor.try_into()
                        .map(|x: tor::Handler| Arc::new(x) as _)
                        .map_err(|error| {
                            Error::InvalidConfig(format!(
                                "failed to load tor outbound {name}: {error}"
                            ))
                        })
                }
                #[cfg(feature = "tuic")]
                OutboundProxyProtocol::Tuic(tuic) => {
                    let name = tuic.common_opts.name.clone();
                    tuic.try_into()
                        .map(|x: tuic::Handler| Arc::new(x) as _)
                        .map_err(|error| {
                            Error::InvalidConfig(format!(
                                "failed to load tuic outbound {name}: {error}"
                            ))
                        })
                }
                #[cfg(feature = "shadowquic")]
                OutboundProxyProtocol::ShadowQuic(sqcfg) => {
                    let name = sqcfg.common_opts.name.clone();
                    sqcfg
                        .try_into()
                        .map(|x: shadowquic::Handler| {
                            Arc::new(x) as AnyOutboundHandler
                        })
                        .map_err(|error| {
                            Error::InvalidConfig(format!(
                                "failed to load shadowquic outbound {name}: {error}"
                            ))
                        })
                }
                #[cfg(feature = "tailscale")]
                OutboundProxyProtocol::Tailscale(tscfg) => {
                    let name = tscfg.name.clone();
                    tscfg
                        .try_into()
                        .map(|x: tailscale::Handler| {
                            Arc::new(x) as AnyOutboundHandler
                        })
                        .map_err(|error| {
                            Error::InvalidConfig(format!(
                                "failed to load tailscale outbound {name}: {error}"
                            ))
                        })
                }
            })
            .collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        app::dns::MockClashResolver,
        proxy::{
            OutboundType,
            mocks::{MockDummyOutboundHandler, MockDummyProxyProvider},
        },
    };
    use tokio::sync::RwLock;

    #[test]
    fn defaults_direct_group_healthcheck_to_300_seconds() {
        assert_eq!(group_healthcheck_interval(true, 0), 300);
        assert_eq!(group_healthcheck_interval(false, 0), 0);
        assert_eq!(group_healthcheck_interval(true, 120), 120);
    }

    #[tokio::test]
    async fn provider_proxies_are_available_by_name_and_in_api_list() {
        let mut provider_proxy = MockDummyOutboundHandler::new();
        provider_proxy
            .expect_name()
            .return_const("provider-proxy".to_owned());
        provider_proxy
            .expect_proto()
            .return_const(OutboundType::Direct);
        provider_proxy.expect_support_udp().return_const(true);
        let provider_proxy: AnyOutboundHandler = Arc::new(provider_proxy);
        let proxy_for_provider = provider_proxy.clone();
        let mut provider = MockDummyProxyProvider::new();
        provider
            .expect_proxies()
            .returning(move || vec![proxy_for_provider.clone()]);

        let manager = OutboundManager {
            registry: Arc::new(RwLock::new(HashMap::new())),
            proxy_providers: HashMap::from([(
                "provider".to_owned(),
                Arc::new(provider) as ArcProxyProvider,
            )]),
            proxy_manager: ProxyManager::new(
                Arc::new(MockClashResolver::new()),
                None,
            ),
            selector_control: HashMap::new(),
            started_proxy_providers: Mutex::new(HashSet::new()),
        };

        assert!(manager.get_provider_proxy("provider-proxy").await.is_some());
        assert!(manager.get_proxies().await.contains_key("provider-proxy"));
    }
}

impl OutboundManager {
    /// Load handlers from the provided outbound protocols and groups.
    /// handlers in proxy_providers are not loaded here as they are stored in
    /// the provider separately.
    async fn load_handlers(
        &mut self,
        handlers: &mut HashMap<String, AnyOutboundHandler>,
        outbounds: Vec<AnyOutboundHandler>,
        outbound_groups: Vec<OutboundGroupProtocol>,
        proxy_names: Vec<String>,
        cache_store: ThreadSafeCacheFile,
        failover_race_delay: Duration,
        route_race_delay: Duration,
    ) -> Result<(), Error> {
        handlers.extend(outbounds.into_iter().map(|h| {
            let name = h.name().to_owned();
            (name, h)
        }));

        self.load_group_outbounds(
            handlers,
            outbound_groups,
            cache_store.clone(),
            failover_race_delay,
            route_race_delay,
        )
        .await?;

        // insert GLOBAL
        let mut g = vec![];
        let mut keys = handlers.keys().collect::<Vec<_>>();
        keys.sort_by(|a, b| {
            proxy_names
                .iter()
                .position(|x| &x == a)
                .cmp(&proxy_names.iter().position(|x| &x == b))
        });
        for name in keys {
            if name == PROXY_COMPATIBLE {
                continue;
            }
            g.push(handlers.get(name).unwrap().clone());
        }
        let hc = HealthCheck::new(
            g.clone(),
            DEFAULT_LATENCY_TEST_URL.to_owned(),
            0, // this is a manual HC
            true,
            self.proxy_manager.clone(),
        );

        let pd: ArcProxyProvider =
            Arc::new(PlainProvider::new(PROXY_GLOBAL.to_owned(), g, hc)?);

        let stored_selection = cache_store.get_selected(PROXY_GLOBAL).await;
        let mut providers: Vec<ArcProxyProvider> = vec![pd.clone()];
        for p in self.proxy_providers.values() {
            let vehicle_type = p.vehicle_type();
            if matches!(
                vehicle_type,
                ProviderVehicleType::Http | ProviderVehicleType::File
            ) {
                providers.push(p.clone());
            }
        }

        let h = selector::Handler::new(
            selector::HandlerOptions {
                name: PROXY_GLOBAL.to_owned(),
                udp: true,
                common_opts: crate::proxy::HandlerCommonOptions {
                    icon: None,
                    ..Default::default()
                },
                ..Default::default()
            },
            providers,
            stored_selection,
        )
        .await;

        self.proxy_providers
            .insert(RESERVED_PROVIDER_NAME.to_owned(), pd);
        handlers.insert(PROXY_GLOBAL.to_owned(), Arc::new(h.clone()));
        self.selector_control
            .insert(PROXY_GLOBAL.to_owned(), Arc::new(h));

        Ok(())
    }

    async fn load_group_outbounds(
        &mut self,
        handlers: &mut HashMap<String, AnyOutboundHandler>,
        outbound_groups: Vec<OutboundGroupProtocol>,
        cache_store: ThreadSafeCacheFile,
        failover_race_delay: Duration,
        route_race_delay: Duration,
    ) -> Result<(), Error> {
        // Sort outbound groups to ensure dependencies are resolved
        let mut outbound_groups = outbound_groups;
        proxy_groups_dag_sort(&mut outbound_groups)?;

        let proxy_manager = &self.proxy_manager;
        let provider_registry = &mut self.proxy_providers;
        let selector_control = &mut self.selector_control;

        /// Common boilerplate: build providers list from proxies and
        /// use_provider. Returns `Vec<ArcProxyProvider>`
        /// directly — the caller checks for emptiness.
        #[allow(clippy::too_many_arguments)]
        fn build_group_providers(
            name: &str,
            proxies: &Option<Vec<String>>,
            use_provider: &Option<Vec<String>>,
            selection: &OutboundGroupSelection,
            interval: u64,
            lazy: bool,
            health_check_url: &str,
            auto_healthcheck_group: bool,
            handlers: &HashMap<String, AnyOutboundHandler>,
            proxy_manager: &ProxyManager,
            provider_registry: &mut HashMap<String, ArcProxyProvider>,
        ) -> Result<Vec<ArcProxyProvider>, Error> {
            let mut providers: Vec<ArcProxyProvider> = vec![];

            if let Some(proxies) = proxies
                && !proxies.is_empty()
            {
                let pd = make_provider_from_proxies(
                    name,
                    proxies,
                    group_healthcheck_interval(auto_healthcheck_group, interval),
                    lazy,
                    health_check_url,
                    handlers,
                    proxy_manager.clone(),
                    provider_registry,
                )?;
                providers.push(pd);
            }

            if let Some(provider_names) = use_provider {
                for provider_name in provider_names {
                    let provider = provider_registry
                        .get(provider_name)
                        .ok_or_else(|| {
                            Error::InvalidConfig(format!(
                                "proxy provider `{provider_name}` referenced by \
                                 proxy group `{name}` was not found"
                            ))
                        })?
                        .clone();
                    if auto_healthcheck_group {
                        provider.register_healthcheck(health_check_url, interval);
                    }
                    providers.push(provider);
                }
            }

            let mut providers = providers
                .into_iter()
                .map(|provider| {
                    FilteredProvider::wrap(
                        provider,
                        selection.filter.as_deref(),
                        selection.exclude_filter.as_deref(),
                    )
                })
                .collect::<Result<Vec<_>, Error>>()?;
            let fallback = handlers
                .get(&selection.empty_fallback)
                .cloned()
                .ok_or_else(|| {
                    Error::InvalidConfig(format!(
                        "empty fallback proxy `{}` referenced by proxy group \
                         `{name}` was not loaded",
                        selection.empty_fallback
                    ))
                })?;
            let hc = HealthCheck::new(
                vec![fallback.clone()],
                health_check_url.to_owned(),
                0,
                true,
                proxy_manager.clone(),
            );
            providers.push(Arc::new(PlainProvider::new_fallback(
                format!("{name}#empty-fallback"),
                vec![fallback],
                hc,
            )?));
            Ok(providers)
        }

        #[allow(clippy::too_many_arguments)]
        fn make_provider_from_proxies(
            name: &str,
            proxies: &[String],
            interval: u64,
            lazy: bool,
            health_check_url: &str,
            handlers: &HashMap<String, AnyOutboundHandler>,
            proxy_manager: ProxyManager,
            provider_registry: &mut HashMap<String, ArcProxyProvider>,
        ) -> Result<ArcProxyProvider, Error> {
            if matches!(name, PROXY_DIRECT | PROXY_COMPATIBLE | PROXY_REJECT) {
                return Err(Error::InvalidConfig(format!(
                    "proxy group name `{name}` is reserved"
                )));
            }
            let proxies: Vec<_> = proxies
                .iter()
                .map(|proxy| {
                    handlers.get(proxy).cloned().ok_or_else(|| {
                        Error::InvalidConfig(format!(
                            "proxy `{proxy}` referenced by proxy group `{name}` \
                             was not loaded"
                        ))
                    })
                })
                .collect::<Result<Vec<_>, Error>>()?;

            let hc = HealthCheck::new(
                proxies.clone(),
                health_check_url.to_owned(),
                interval,
                lazy,
                proxy_manager,
            );

            let pd: ArcProxyProvider = Arc::new(
                PlainProvider::new(name.to_owned(), proxies, hc).map_err(|x| {
                    Error::InvalidConfig(format!("invalid provider config: {x}"))
                })?,
            );

            provider_registry.insert(name.to_owned(), pd.clone());

            Ok(pd)
        }

        // Initialize handlers for each outbound group protocol
        for outbound_group in outbound_groups.iter() {
            match outbound_group {
                OutboundGroupProtocol::Relay(proto) => {
                    let providers = build_group_providers(
                        &proto.name,
                        &proto.proxies,
                        &proto.use_provider,
                        &proto.selection,
                        0,
                        true,
                        proto.url.as_deref().unwrap_or(DEFAULT_LATENCY_TEST_URL),
                        false,
                        handlers,
                        proxy_manager,
                        provider_registry,
                    )?;
                    if providers.is_empty() {
                        tracing::warn!(
                            "proxy group {} has no proxies, skipping",
                            proto.name
                        );
                        continue;
                    }

                    handlers.insert(
                        proto.name.clone(),
                        relay::Handler::new(
                            relay::HandlerOptions {
                                name: proto.name.clone(),
                                common_opts: crate::proxy::HandlerCommonOptions {
                                    icon: proto.icon.clone(),
                                    url: proto.url.clone(),
                                    connector: None,
                                },
                            },
                            providers,
                        ),
                    );
                }
                OutboundGroupProtocol::UrlTest(proto) => {
                    let providers = build_group_providers(
                        &proto.name,
                        &proto.proxies,
                        &proto.use_provider,
                        &proto.selection,
                        proto.interval,
                        proto.lazy.unwrap_or(true),
                        &proto.url,
                        true,
                        handlers,
                        proxy_manager,
                        provider_registry,
                    )?;
                    if providers.is_empty() {
                        tracing::warn!(
                            "proxy group {} has no proxies, skipping",
                            proto.name
                        );
                        continue;
                    }

                    let url_test = urltest::Handler::new(
                        urltest::HandlerOptions {
                            name: proto.name.clone(),
                            common_opts: crate::proxy::HandlerCommonOptions {
                                icon: proto.icon.clone(),
                                url: Some(proto.url.clone()),
                                connector: None,
                            },
                            failover_race: proto.selection.failover_race,
                            race_delay: Some(failover_race_delay),
                            ..Default::default()
                        },
                        proto.tolerance.unwrap_or_default(),
                        providers,
                        proxy_manager.clone(),
                    );

                    let url_test = Arc::new(url_test);
                    handlers.insert(proto.name.clone(), url_test.clone());
                    selector_control.insert(proto.name.clone(), url_test);
                }
                OutboundGroupProtocol::Fallback(proto) => {
                    let providers = build_group_providers(
                        &proto.name,
                        &proto.proxies,
                        &proto.use_provider,
                        &proto.selection,
                        proto.interval,
                        proto.lazy.unwrap_or(true),
                        &proto.url,
                        true,
                        handlers,
                        proxy_manager,
                        provider_registry,
                    )?;
                    if providers.is_empty() {
                        tracing::warn!(
                            "proxy group {} has no proxies, skipping",
                            proto.name
                        );
                        continue;
                    }

                    let fallback = Arc::new(fallback::Handler::new(
                        fallback::HandlerOptions {
                            name: proto.name.clone(),
                            common_opts: crate::proxy::HandlerCommonOptions {
                                icon: proto.icon.clone(),
                                url: Some(proto.url.clone()),
                                connector: None,
                            },
                            failover_race: proto.selection.failover_race,
                            race_delay: Some(failover_race_delay),
                            ..Default::default()
                        },
                        providers,
                        proxy_manager.clone(),
                    ));
                    handlers.insert(proto.name.clone(), fallback.clone());
                    selector_control.insert(proto.name.clone(), fallback);
                }
                OutboundGroupProtocol::LoadBalance(proto) => {
                    let providers = build_group_providers(
                        &proto.name,
                        &proto.proxies,
                        &proto.use_provider,
                        &proto.selection,
                        proto.interval,
                        proto.lazy.unwrap_or(true),
                        &proto.url,
                        true,
                        handlers,
                        proxy_manager,
                        provider_registry,
                    )?;
                    if providers.is_empty() {
                        tracing::warn!(
                            "proxy group {} has no proxies, skipping",
                            proto.name
                        );
                        continue;
                    }

                    handlers.insert(
                        proto.name.clone(),
                        Arc::new(loadbalance::Handler::new(
                            loadbalance::HandlerOptions {
                                name: proto.name.clone(),
                                common_opts: crate::proxy::HandlerCommonOptions {
                                    icon: proto.icon.clone(),
                                    url: Some(proto.url.clone()),
                                    connector: None,
                                },
                                ..Default::default()
                            },
                            providers,
                            proxy_manager.clone(),
                        )),
                    );
                }
                OutboundGroupProtocol::Select(proto) => {
                    let providers = build_group_providers(
                        &proto.name,
                        &proto.proxies,
                        &proto.use_provider,
                        &proto.selection,
                        0,
                        true,
                        proto.url.as_deref().unwrap_or(DEFAULT_LATENCY_TEST_URL),
                        false,
                        handlers,
                        proxy_manager,
                        provider_registry,
                    )?;
                    if providers.is_empty() {
                        tracing::warn!(
                            "proxy group {} has no proxies, skipping",
                            proto.name
                        );
                        continue;
                    }

                    let stored_selection =
                        cache_store.get_selected(&proto.name).await;

                    let selector = selector::Handler::new(
                        selector::HandlerOptions {
                            name: proto.name.clone(),
                            udp: proto.udp.unwrap_or(true),
                            common_opts: crate::proxy::HandlerCommonOptions {
                                icon: proto.icon.clone(),
                                url: proto.url.clone(),
                                connector: None,
                            },
                        },
                        providers,
                        stored_selection,
                    )
                    .await;

                    handlers.insert(proto.name.clone(), Arc::new(selector.clone()));
                    selector_control.insert(proto.name.clone(), Arc::new(selector));
                }
                OutboundGroupProtocol::Smart(proto) => {
                    let providers = build_group_providers(
                        &proto.name,
                        &proto.proxies,
                        &proto.use_provider,
                        &proto.selection,
                        0,
                        proto.lazy.unwrap_or_default(),
                        proto.url.as_deref().unwrap_or(DEFAULT_LATENCY_TEST_URL),
                        false,
                        handlers,
                        proxy_manager,
                        provider_registry,
                    )?;
                    if providers.is_empty() {
                        tracing::warn!(
                            "proxy group {} has no proxies, skipping",
                            proto.name
                        );
                        continue;
                    }

                    handlers.insert(
                        proto.name.clone(),
                        Arc::new(smart::Handler::new_with_cache(
                            smart::HandlerOptions {
                                name: proto.name.clone(),
                                common_opts: crate::proxy::HandlerCommonOptions {
                                    icon: proto.icon.clone(),
                                    url: proto.url.clone(),
                                    connector: None,
                                },
                                udp: proto.udp.unwrap_or(true),
                                max_retries: proto.max_retries,
                                bandwidth_weight: proto.bandwidth_weight,
                            },
                            providers,
                            proxy_manager.clone(),
                            cache_store.clone(),
                        )),
                    );
                }
            }

            let Some(route_race_name) = outbound_group.route_race() else {
                continue;
            };
            let name = outbound_group.name();
            let primary = handlers.get(name).cloned().ok_or_else(|| {
                Error::InvalidConfig(format!(
                    "proxy group `{name}` was not loaded before route-race"
                ))
            })?;
            let route_race = handlers.get(route_race_name).cloned().ok_or_else(|| {
                Error::InvalidConfig(format!(
                    "route-race `{route_race_name}` for proxy group `{name}` was not loaded"
                ))
            })?;
            if route_race.support_dialer().is_some() {
                return Err(Error::InvalidConfig(format!(
                    "route-race `{route_race_name}` for proxy group `{name}` must not use dialer-proxy"
                )));
            }
            handlers.insert(
                name.to_owned(),
                Arc::new(route_race::Handler::new(
                    primary,
                    route_race,
                    route_race_delay,
                    failover_race_delay,
                )),
            );
        }

        Ok(())
    }

    async fn load_proxy_providers(
        &mut self,
        cwd: String,
        proxy_providers: HashMap<String, OutboundProxyProviderDef>,
        resolver: ThreadSafeDNSResolver,
        rule_dispatch: Arc<RuleDispatch>,
    ) -> Result<(), Error> {
        let proxy_manager = &self.proxy_manager;
        let provider_registry = &mut self.proxy_providers;
        fn make_proxy_set_provider(
            name: &str,
            vehicle: ThreadSafeProviderVehicle,
            interval_secs: u64,
            hc: HealthCheck,
            override_options: crate::config::internal::proxy::OutboundProxyProviderOverride,
        ) -> Result<ArcProxyProvider, Error> {
            ProxySetProvider::new(
                name.to_owned(),
                Duration::from_secs(interval_secs),
                vehicle,
                hc,
                override_options,
            )
            .map(|p| Arc::new(p) as ArcProxyProvider)
            .map_err(|x| {
                Error::InvalidConfig(format!("invalid provider config: {x}"))
            })
        }

        for (name, provider) in proxy_providers.into_iter() {
            let (vehicle, interval_secs, health_check, override_options) =
                match provider {
                    OutboundProxyProviderDef::Http(http) => {
                        let mut vehicle = http_vehicle::Vehicle::new(
                            http.url.parse::<Uri>().map_err(|error| {
                                Error::InvalidConfig(format!(
                                    "invalid URL for proxy provider `{name}`: \
                                     {error}"
                                ))
                            })?,
                            http.path,
                            Some(cwd.clone()),
                            resolver.clone(),
                        )
                        .with_headers(http.header)?
                        .with_rule_dispatch(rule_dispatch.clone());
                        if let Some(proxy) =
                            http.proxy.filter(|value| !value.is_empty())
                        {
                            vehicle = vehicle.with_outbound(proxy);
                        }
                        (
                            Arc::new(vehicle) as ThreadSafeProviderVehicle,
                            http.interval,
                            http.health_check,
                            http.override_options,
                        )
                    }
                    OutboundProxyProviderDef::File(file) => {
                        let vehicle = file_vehicle::Vehicle::new(
                            PathBuf::from(cwd.clone())
                                .join(&file.path)
                                .to_str()
                                .unwrap(),
                        );
                        (
                            Arc::new(vehicle) as ThreadSafeProviderVehicle,
                            file.interval.unwrap_or_default(),
                            file.health_check,
                            file.override_options,
                        )
                    }
                };

            let healthcheck_interval = health_check.effective_interval();
            let healthcheck_url = if health_check.enable {
                health_check.url
            } else {
                String::new()
            };
            let hc = HealthCheck::new(
                vec![],
                healthcheck_url,
                healthcheck_interval,
                health_check.lazy.unwrap_or(true),
                proxy_manager.clone(),
            );

            let provider = make_proxy_set_provider(
                &name,
                vehicle,
                interval_secs,
                hc,
                override_options,
            )?;
            provider_registry.insert(name, provider);
        }

        Ok(())
    }
}
