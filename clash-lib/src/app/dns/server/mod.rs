use hickory_proto::op::Message;
use parking_lot::Mutex;
use std::sync::Arc;

use tracing::{error, info, instrument};
use watfaq_dns::DNSListenAddr;

use crate::runner::Runner;

use super::ThreadSafeDNSResolver;

mod handler;
pub use handler::exchange_with_resolver;

static DEFAULT_DNS_SERVER_TTL: u32 = 60;

struct DnsMessageExchanger {
    resolver: ThreadSafeDNSResolver,
}

impl watfaq_dns::DnsMessageExchanger for DnsMessageExchanger {
    fn ipv6(&self) -> bool {
        self.resolver.ipv6()
    }

    #[instrument(skip(self))]
    async fn exchange(
        &self,
        message: &Message,
    ) -> Result<Message, watfaq_dns::DNSError> {
        exchange_with_resolver(&self.resolver, message, true).await
    }
}

#[derive(Clone)]
pub struct DnsRunner {
    enable: bool,
    listener: DNSListenAddr,
    resolver: ThreadSafeDNSResolver,
    cwd: std::path::PathBuf,

    cancellation_token: tokio_util::sync::CancellationToken,
    active_token: Arc<Mutex<Option<tokio_util::sync::CancellationToken>>>,
}

impl DnsRunner {
    pub fn new(
        enable: bool,
        listen: DNSListenAddr,
        resolver: ThreadSafeDNSResolver,
        cwd: &std::path::Path,
        cancellation_token: Option<tokio_util::sync::CancellationToken>,
    ) -> Self {
        Self {
            enable,
            listener: listen,
            resolver,
            cwd: cwd.to_path_buf(),
            cancellation_token: cancellation_token.unwrap_or_default(),
            active_token: Arc::new(Mutex::new(None)),
        }
    }

    pub async fn start_and_wait(&self) -> Result<(), crate::Error> {
        if !self.enable {
            info!("dns listener is disabled, skipping");
            return Ok(());
        }
        if self.active_token.lock().is_some() {
            return Ok(());
        }

        let h = DnsMessageExchanger {
            resolver: self.resolver.clone(),
        };
        let listener =
            watfaq_dns::get_dns_listener(self.listener.clone(), h, &self.cwd)
                .await
                .map_err(|error| crate::Error::Operation(error.to_string()))?;
        let Some(listener) = listener else {
            info!("dns listener: no listen addresses configured, skipping");
            return Ok(());
        };
        if self.cancellation_token.is_cancelled() {
            return Err(crate::Error::Operation(
                "DNS runtime is already shut down".to_owned(),
            ));
        }
        let cancellation_token = self.cancellation_token.child_token();
        *self.active_token.lock() = Some(cancellation_token.clone());
        tokio::spawn(async move {
            tokio::select! {
                result = listener => {
                    if let Err(error) = result {
                        error!("dns listener error: {error}");
                    }
                },
                _ = cancellation_token.cancelled() => {
                    info!("dns listener is closed");
                },
            }
        });
        Ok(())
    }

    pub fn stop_listener(&self) {
        if let Some(token) = self.active_token.lock().take() {
            token.cancel();
        }
    }
}

impl Runner for DnsRunner {
    fn run_async(&self) {
        let runner = self.clone();
        tokio::spawn(async move {
            if let Err(error) = runner.start_and_wait().await {
                error!("failed to start DNS listener: {error}");
            }
        });
    }

    fn shutdown(&self) {
        info!("Shutting down DNS server");
        self.stop_listener();
        self.cancellation_token.cancel();
    }

    fn join(&self) -> futures::future::BoxFuture<'_, Result<(), crate::Error>> {
        Box::pin(async move { Ok(()) })
    }
}
