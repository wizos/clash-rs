use crate::{
    common::auth::ThreadSafeAuthenticator,
    config::listener::{InboundOpts, InboundUser},
    proxy::{
        anytls::inbound::{AnytlsInbound, InboundOptions as AnytlsInboundOptions},
        http::HttpInbound,
        hysteria2::inbound::{
            Hysteria2Inbound, InboundOptions as Hysteria2InboundOptions,
        },
        inbound::InboundHandlerTrait,
        mixed::MixedInbound,
        socks::inbound::SocksInbound,
        tunnel::TunnelInbound,
    },
};

#[cfg(all(any(target_os = "linux", target_os = "android"), feature = "redir"))]
use crate::proxy::redir::RedirInbound;
#[cfg(all(
    any(target_os = "linux", target_os = "android"),
    feature = "tproxy"
))]
use crate::proxy::tproxy::TproxyInbound;

use crate::Dispatcher;
use futures::future::BoxFuture;
use tracing::{error, info, warn};

#[cfg(feature = "shadowsocks")]
use crate::proxy::shadowsocks::inbound::{InboundOptions, ShadowsocksInbound};
use std::sync::Arc;

const LISTENER_RESTART_DELAYS: [std::time::Duration; 5] = [
    std::time::Duration::from_millis(100),
    std::time::Duration::from_millis(250),
    std::time::Duration::from_millis(500),
    std::time::Duration::from_secs(1),
    std::time::Duration::from_secs(2),
];
const LISTENER_STARTUP_GRACE: std::time::Duration =
    std::time::Duration::from_millis(100);
const LISTENER_STABLE_RUNTIME: std::time::Duration =
    std::time::Duration::from_secs(30);

pub(crate) async fn supervise_network_listener(
    name: String,
    handler: Arc<dyn InboundHandlerTrait>,
    tcp: bool,
) -> Result<(), crate::Error> {
    supervise_listener(name, tcp, || {
        let handler = handler.clone();
        async move {
            if tcp {
                handler.listen_tcp().await
            } else {
                handler.listen_udp().await
            }
        }
    })
    .await
}

async fn supervise_listener<F, Fut>(
    name: String,
    tcp: bool,
    mut listen: F,
) -> Result<(), crate::Error>
where
    F: FnMut() -> Fut,
    Fut: std::future::Future<Output = std::io::Result<()>>,
{
    let protocol = if tcp { "TCP" } else { "UDP" };
    let mut failures = 0;
    let mut starting = true;
    loop {
        let started = tokio::time::Instant::now();
        let listener = listen();
        tokio::pin!(listener);
        let result = if starting {
            tokio::select! {
                result = &mut listener => return result.map_err(Into::into),
                _ = tokio::time::sleep(LISTENER_STARTUP_GRACE) => {
                    starting = false;
                    listener.await
                }
            }
        } else {
            listener.await
        };

        let error = match result {
            Ok(()) => std::io::Error::other("listener exited unexpectedly"),
            Err(error) => error,
        };
        if started.elapsed() >= LISTENER_STABLE_RUNTIME {
            failures = 0;
        }
        let Some(delay) = LISTENER_RESTART_DELAYS.get(failures).copied() else {
            error!(
                "handler {} {} unavailable after {} restart attempts: {}",
                name,
                protocol,
                LISTENER_RESTART_DELAYS.len(),
                error,
            );
            crate::app::events::emit_app(
                "listenerFailure",
                serde_json::json!({
                    "name": name,
                    "protocol": protocol.to_ascii_lowercase(),
                    "error": error.to_string(),
                    "attempts": LISTENER_RESTART_DELAYS.len(),
                }),
            );
            return Err(error.into());
        };

        failures += 1;
        warn!(
            "handler {} {} failed: {}; restarting in {}ms ({}/{})",
            name,
            protocol,
            error,
            delay.as_millis(),
            failures,
            LISTENER_RESTART_DELAYS.len(),
        );
        tokio::time::sleep(delay).await;
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::{
        Arc,
        atomic::{AtomicUsize, Ordering},
    };

    #[tokio::test(start_paused = true)]
    async fn startup_failure_is_returned_without_retry() {
        let attempts = Arc::new(AtomicUsize::new(0));
        let result = supervise_listener("test".to_owned(), true, {
            let attempts = attempts.clone();
            move || {
                attempts.fetch_add(1, Ordering::Relaxed);
                std::future::ready(Err(std::io::Error::new(
                    std::io::ErrorKind::AddrInUse,
                    "busy",
                )))
            }
        })
        .await;

        assert!(result.is_err());
        assert_eq!(attempts.load(Ordering::Relaxed), 1);
    }

    #[tokio::test(start_paused = true)]
    async fn runtime_failure_retries_until_the_limit() {
        let attempts = Arc::new(AtomicUsize::new(0));
        let result = supervise_listener("test".to_owned(), true, {
            let attempts = attempts.clone();
            move || {
                let attempt = attempts.fetch_add(1, Ordering::Relaxed);
                async move {
                    if attempt == 0 {
                        tokio::time::sleep(
                            LISTENER_STARTUP_GRACE
                                + std::time::Duration::from_millis(1),
                        )
                        .await;
                    }
                    Err(std::io::Error::new(
                        std::io::ErrorKind::NotConnected,
                        "disconnected",
                    ))
                }
            }
        })
        .await;

        assert!(result.is_err());
        assert_eq!(
            attempts.load(Ordering::Relaxed),
            LISTENER_RESTART_DELAYS.len() + 1,
        );
    }

    #[tokio::test(start_paused = true)]
    async fn unexpected_listener_exit_is_retried() {
        let attempts = Arc::new(AtomicUsize::new(0));
        let result = supervise_listener("test".to_owned(), true, {
            let attempts = attempts.clone();
            move || {
                let attempt = attempts.fetch_add(1, Ordering::Relaxed);
                async move {
                    if attempt == 0 {
                        tokio::time::sleep(
                            LISTENER_STARTUP_GRACE
                                + std::time::Duration::from_millis(1),
                        )
                        .await;
                    }
                    Ok(())
                }
            }
        })
        .await;

        assert!(result.is_err());
        assert_eq!(
            attempts.load(Ordering::Relaxed),
            LISTENER_RESTART_DELAYS.len() + 1,
        );
    }
}

pub(crate) fn build_network_listeners(
    inbound_opts: &InboundOpts,
    dispatcher: Arc<Dispatcher>,
    authenticator: ThreadSafeAuthenticator,
    users_rx: Option<tokio::sync::watch::Receiver<Vec<InboundUser>>>,
) -> Option<Vec<BoxFuture<'static, Result<(), crate::Error>>>> {
    let name = &inbound_opts.common_opts().name;
    let addr = inbound_opts.common_opts().listen.0;
    let port = inbound_opts.common_opts().port;
    let dispatcher = Arc::new(dispatcher.with_inbound_metadata(name.clone(), port));

    if let Some(handler) =
        build_handler(inbound_opts, dispatcher, authenticator, users_rx)
    {
        let mut runners: Vec<BoxFuture<'static, Result<(), crate::Error>>> =
            Vec::new();

        if handler.handle_tcp() {
            let tcp_listener = handler.clone();

            let name = name.clone();
            runners.push(Box::pin(async move {
                info!("{} TCP listening at: {}:{}", name, addr, port,);
                supervise_network_listener(name, tcp_listener, true).await
            }));
        }

        if handler.handle_udp() {
            let udp_listener = handler.clone();
            let name = name.clone();
            runners.push(Box::pin(async move {
                info!("{} UDP listening at: {}:{}", name, addr, port,);
                supervise_network_listener(name, udp_listener, false).await
            }));
        }

        if runners.is_empty() {
            warn!("no listener for {}", name);
            return None;
        }
        Some(runners)
    } else {
        None
    }
}

fn build_handler(
    listener: &InboundOpts,
    dispatcher: Arc<Dispatcher>,
    authenticator: ThreadSafeAuthenticator,
    #[allow(unused)] users_rx: Option<
        tokio::sync::watch::Receiver<Vec<InboundUser>>,
    >,
) -> Option<Arc<dyn InboundHandlerTrait>> {
    let fw_mark = listener.common_opts().fw_mark;
    match listener {
        InboundOpts::Http { common_opts, .. } => Some(Arc::new(HttpInbound::new(
            (common_opts.listen.0, common_opts.port).into(),
            common_opts.allow_lan,
            dispatcher,
            authenticator,
            fw_mark,
        ))),

        InboundOpts::Socks { common_opts, .. } => Some(Arc::new(SocksInbound::new(
            (common_opts.listen.0, common_opts.port).into(),
            common_opts.allow_lan,
            dispatcher,
            authenticator,
            fw_mark,
        ))),
        InboundOpts::Mixed { common_opts, .. } => Some(Arc::new(MixedInbound::new(
            (common_opts.listen.0, common_opts.port).into(),
            common_opts.allow_lan,
            dispatcher,
            authenticator,
            fw_mark,
        ))),
        #[cfg(feature = "tproxy")]
        InboundOpts::TProxy {
            #[cfg(any(target_os = "linux", target_os = "android"))]
            common_opts,
            ..
        } => {
            #[cfg(any(target_os = "linux", target_os = "android"))]
            {
                Some(Arc::new(TproxyInbound::new(
                    (common_opts.listen.0, common_opts.port).into(),
                    common_opts.allow_lan,
                    dispatcher,
                    fw_mark,
                )))
            }

            #[cfg(not(any(target_os = "linux", target_os = "android")))]
            {
                warn!("tproxy is not supported on this platform");
                None
            }
        }
        #[cfg(feature = "redir")]
        InboundOpts::Redir {
            #[cfg(any(target_os = "linux", target_os = "android"))]
            common_opts,
            ..
        } => {
            #[cfg(any(target_os = "linux", target_os = "android"))]
            {
                Some(Arc::new(RedirInbound::new(
                    (common_opts.listen.0, common_opts.port).into(),
                    common_opts.allow_lan,
                    dispatcher,
                    fw_mark,
                )))
            }
            #[cfg(not(any(target_os = "linux", target_os = "android")))]
            {
                warn!("redir is not supported on this platform");
                None
            }
        }
        InboundOpts::Tunnel {
            common_opts,
            network,
            target,
        } => TunnelInbound::new(
            (common_opts.listen.0, common_opts.port).into(),
            dispatcher,
            network.clone(),
            target.clone(),
            fw_mark,
        )
        .inspect_err(|x| {
            warn!("tunnel inbound handler failed to create: {x}");
        })
        .map(|x| Arc::new(x) as _)
        .ok(),
        #[cfg(feature = "shadowsocks")]
        InboundOpts::Shadowsocks {
            common_opts,
            udp,
            cipher,
            password,
            users,
        } => {
            // Use the provided watch receiver, or create a static one for
            // non-provider (static config) inbounds whose user list never changes.
            let rx = users_rx
                .unwrap_or_else(|| tokio::sync::watch::channel(users.clone()).1);
            Some(Arc::new(ShadowsocksInbound::new(InboundOptions {
                addr: (common_opts.listen.0, common_opts.port).into(),
                password: password.clone(),
                udp: *udp,
                cipher: cipher.clone(),
                allow_lan: common_opts.allow_lan,
                dispatcher,
                authenticator,
                fw_mark: common_opts.fw_mark,
                users_rx: rx,
            })))
        }
        InboundOpts::Anytls {
            common_opts,
            password,
            certificate,
            private_key,
            fallback,
            users,
        } => {
            let rx = users_rx
                .unwrap_or_else(|| tokio::sync::watch::channel(users.clone()).1);
            match AnytlsInbound::new(AnytlsInboundOptions {
                addr: (common_opts.listen.0, common_opts.port).into(),
                password: password.clone(),
                certificate: certificate.clone(),
                private_key: private_key.clone(),
                fallback: fallback.clone(),
                allow_lan: common_opts.allow_lan,
                dispatcher,
                fw_mark: common_opts.fw_mark,
                users_rx: rx,
            }) {
                Ok(h) => Some(Arc::new(h)),
                Err(e) => {
                    warn!("anytls inbound failed to init: {e}");
                    None
                }
            }
        }
        InboundOpts::Hysteria2 {
            common_opts,
            password,
            certificate,
            private_key,
            users,
        } => {
            let rx = users_rx
                .unwrap_or_else(|| tokio::sync::watch::channel(users.clone()).1);
            match Hysteria2Inbound::new(Hysteria2InboundOptions {
                addr: (common_opts.listen.0, common_opts.port).into(),
                password: password.clone(),
                certificate: certificate.clone(),
                private_key: private_key.clone(),
                allow_lan: common_opts.allow_lan,
                dispatcher,
                fw_mark: common_opts.fw_mark,
                users_rx: rx,
            }) {
                Ok(h) => Some(Arc::new(h)),
                Err(e) => {
                    warn!("hysteria2 inbound failed to init: {e}");
                    None
                }
            }
        }
    }
}
