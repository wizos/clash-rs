use crate::dns::{
    Client, EnhancedResolver, ThreadSafeDNSClient,
    dns_client::{DNSNetMode, DnsClient, Opts},
};
use async_trait::async_trait;
use hickory_proto::op::Message;
use std::{
    fmt::{Debug, Formatter},
    net::SocketAddr,
    sync::{
        Arc, LazyLock, RwLock,
        atomic::{AtomicU64, Ordering},
    },
    time::{Duration, Instant},
};
use tracing::{info, warn};

#[allow(dead_code)]
const SYSTEM_DNS_FLUSH_INTERVAL: Duration = Duration::from_secs(300); // 5 minutes
const DNS_TIMEOUT: Duration = Duration::from_secs(5);

// Default fallback DNS servers (same as mihomo)
const DEFAULT_DNS: &[&str] = &["114.114.114.114:53", "8.8.8.8:53"];

pub struct SystemDnsClient {
    inner: std::sync::Mutex<SystemDnsInner>,
    fw_mark: Option<u32>,
}

struct SystemDnsInner {
    clients: Vec<ThreadSafeDNSClient>,
    #[allow(dead_code)]
    last_flush: Instant,
    generation: u64,
}

static SYSTEM_DNS_SERVERS: LazyLock<RwLock<Vec<String>>> =
    LazyLock::new(|| RwLock::new(Vec::new()));
static SYSTEM_DNS_GENERATION: AtomicU64 = AtomicU64::new(0);

pub fn update_system_dns_servers(servers: Vec<String>) -> Result<(), String> {
    let normalized = normalize_system_dns_servers(servers)?;
    *SYSTEM_DNS_SERVERS
        .write()
        .expect("system DNS override lock poisoned") = normalized;
    SYSTEM_DNS_GENERATION.fetch_add(1, Ordering::Release);
    Ok(())
}

fn normalize_system_dns_servers(
    servers: Vec<String>,
) -> Result<Vec<String>, String> {
    let mut normalized = Vec::new();
    for server in servers {
        let server = server.trim();
        if server.is_empty() {
            continue;
        }
        if server.parse::<SocketAddr>().is_err()
            && server.parse::<std::net::IpAddr>().is_err()
        {
            return Err(format!("invalid system DNS server `{server}`"));
        }
        normalized.push(server.to_string());
    }
    Ok(normalized)
}

impl Debug for SystemDnsClient {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SystemDnsClient").finish()
    }
}

#[async_trait]
impl Client for SystemDnsClient {
    fn id(&self) -> String {
        "system".to_string()
    }

    async fn exchange(&self, msg: &Message) -> anyhow::Result<Message> {
        self.refresh_if_needed().await;
        let clients = self.get_clients();
        if clients.is_empty() {
            return Err(anyhow::anyhow!("no system DNS servers available"));
        }
        tokio::time::timeout(
            DNS_TIMEOUT,
            EnhancedResolver::batch_exchange(&clients, msg),
        )
        .await?
    }

    async fn reset_connection(&self) {
        for client in self.get_clients() {
            client.reset_connection().await;
        }
    }
}

impl SystemDnsClient {
    pub fn new(
        fw_mark: Option<u32>,
    ) -> std::pin::Pin<Box<dyn std::future::Future<Output = Self> + Send>> {
        Box::pin(async move {
            let clients = Self::build_clients(fw_mark).await;
            let inner = SystemDnsInner {
                clients,
                last_flush: Instant::now(),
                generation: SYSTEM_DNS_GENERATION.load(Ordering::Acquire),
            };
            Self {
                inner: std::sync::Mutex::new(inner),
                fw_mark,
            }
        })
    }

    async fn refresh_if_needed(&self) {
        let generation = SYSTEM_DNS_GENERATION.load(Ordering::Acquire);
        if self.inner.lock().unwrap().generation == generation {
            return;
        }
        let clients = Self::build_clients(self.fw_mark).await;
        let mut inner = self.inner.lock().unwrap();
        inner.clients = clients;
        inner.last_flush = Instant::now();
        inner.generation = generation;
    }

    fn get_clients(&self) -> Vec<ThreadSafeDNSClient> {
        let inner = self.inner.lock().unwrap();
        inner.clients.clone()
    }

    async fn build_clients(fw_mark: Option<u32>) -> Vec<ThreadSafeDNSClient> {
        let override_servers = SYSTEM_DNS_SERVERS
            .read()
            .expect("system DNS override lock poisoned")
            .clone();
        let servers = if override_servers.is_empty() {
            read_system_dns_servers()
        } else {
            override_servers
        };
        let servers = if servers.is_empty() {
            warn!("system dns: no system DNS found, using fallback");
            DEFAULT_DNS.iter().map(|s| s.to_string()).collect()
        } else {
            info!("system dns: found servers: {:?}", servers);
            servers
        };

        let proxy = Arc::new(crate::proxy::direct::Handler::new("system-dns"));
        let mut clients = Vec::new();

        for server in &servers {
            let addr: SocketAddr = match server.parse() {
                Ok(a) => a,
                Err(_) => match server.parse::<std::net::IpAddr>() {
                    Ok(ip) => SocketAddr::new(ip, 53),
                    Err(_) => continue,
                },
            };

            let host = match addr.ip() {
                std::net::IpAddr::V4(v4) => url::Host::Ipv4(v4),
                std::net::IpAddr::V6(v6) => url::Host::Ipv6(v6),
            };

            // Create UDP DNS client directly (not through System path)
            match DnsClient::new_client(Opts {
                net: DNSNetMode::Udp,
                host,
                port: addr.port(),
                path: String::new(),
                iface: None,
                proxy: proxy.clone(),
                father: None,
                fw_mark,
                ecs: None,
                rule_dispatch: None,
            })
            .await
            {
                Ok(c) => clients.push(c),
                Err(e) => {
                    warn!("system dns: failed to create client for {}: {}", addr, e)
                }
            }
        }

        if !clients.is_empty() {
            info!("system dns: created {} UDP clients", clients.len());
        }

        clients
    }
}

/// Read system DNS servers from /etc/resolv.conf (POSIX) or registry (Windows)
fn read_system_dns_servers() -> Vec<String> {
    #[cfg(all(unix, not(target_os = "android")))]
    {
        read_resolv_conf()
    }

    #[cfg(windows)]
    {
        read_windows_dns()
    }

    #[cfg(target_os = "android")]
    {
        Vec::new()
    }
}

#[cfg(all(unix, not(target_os = "android")))]
fn read_resolv_conf() -> Vec<String> {
    use std::{
        fs,
        io::{BufRead, BufReader},
    };

    let path = "/etc/resolv.conf";
    let file = match fs::File::open(path) {
        Ok(f) => f,
        Err(e) => {
            warn!("system dns: failed to open {}: {}", path, e);
            return Vec::new();
        }
    };

    let reader = BufReader::new(file);
    let mut servers = Vec::new();

    for line in reader.lines() {
        let line = match line {
            Ok(l) => l,
            Err(_) => continue,
        };
        let line = line.trim();
        if let Some(rest) = line.strip_prefix("nameserver") {
            let server = rest.trim();
            if !server.is_empty() {
                servers.push(server.to_string());
            }
        }
    }

    servers
}

#[cfg(windows)]
fn read_windows_dns() -> Vec<String> {
    use std::process::Command;

    let output = match Command::new("ipconfig").arg("/all").output() {
        Ok(o) => o,
        Err(_) => return Vec::new(),
    };

    let stdout = String::from_utf8_lossy(&output.stdout);
    let mut servers = Vec::new();

    for line in stdout.lines() {
        let line = line.trim();
        if line.contains("DNS Servers") || line.contains("DNS 服务器") {
            if let Some(addr) = line.split(':').last() {
                let addr = addr.trim();
                if addr.parse::<std::net::IpAddr>().is_ok() {
                    servers.push(addr.to_string());
                }
            }
        }
    }

    servers
}

#[cfg(test)]
mod tests {
    use super::normalize_system_dns_servers;

    #[test]
    fn accepts_mihomo_system_dns_ip_and_socket_forms() {
        assert_eq!(
            normalize_system_dns_servers(vec![
                " 1.1.1.1 ".to_owned(),
                "[2606:4700:4700::1111]:5353".to_owned(),
                "".to_owned(),
            ])
            .unwrap(),
            ["1.1.1.1", "[2606:4700:4700::1111]:5353"],
        );
    }

    #[test]
    fn rejects_non_address_system_dns_values() {
        assert!(
            normalize_system_dns_servers(vec![
                "8.8.8.8".to_owned(),
                "https://dns.example/dns-query".to_owned(),
            ])
            .is_err(),
        );
    }
}
