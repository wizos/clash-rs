use std::{net, sync::Arc};

use crate::{Error, common::trie};

use async_trait::async_trait;
use byteorder::{BigEndian, ByteOrder};
use tokio::sync::RwLock;

mod file_store;
mod mem_store;

pub use file_store::FileStore;
pub use mem_store::InMemStore;

pub struct Opts {
    pub ipnet: ipnet::IpNet,
    pub skipped_hostnames: Option<trie::StringTrie<bool>>,
    pub store: Box<dyn Store>,
}

#[async_trait]
pub trait Store: Sync + Send {
    async fn get_by_host(&mut self, host: &str) -> Option<net::IpAddr>;
    async fn pub_by_host(&mut self, host: &str, ip: net::IpAddr);
    async fn get_by_ip(&mut self, ip: net::IpAddr) -> Option<String>;
    async fn put_by_ip(&mut self, ip: net::IpAddr, host: &str);
    async fn del_by_ip(&mut self, ip: net::IpAddr);
    async fn exist(&mut self, ip: net::IpAddr) -> bool;
    async fn copy_to(&self, store: &mut Box<dyn Store>);
    async fn flush(&mut self);
}

pub type ThreadSafeFakeDns = Arc<RwLock<FakeDns>>;

pub struct FakeDns {
    max: u32,
    min: u32,
    #[allow(dead_code)]
    gateway: u32,
    offset: u32,
    skipped_hostnames: Option<trie::StringTrie<bool>>,
    ipnet: ipnet::IpNet,
    store: Box<dyn Store>,
}

impl FakeDns {
    pub fn new(opt: Opts) -> Result<Self, Error> {
        let (gateway, min, max) = Self::allocatable_bounds(opt.ipnet)?;

        Ok(Self {
            max,
            min,
            gateway,
            offset: 0,
            skipped_hostnames: opt.skipped_hostnames,
            ipnet: opt.ipnet,
            store: opt.store,
        })
    }

    pub(crate) fn validate_ipnet(ipnet: ipnet::IpNet) -> Result<(), Error> {
        Self::allocatable_bounds(ipnet).map(|_| ())
    }

    fn allocatable_bounds(ipnet: ipnet::IpNet) -> Result<(u32, u32, u32), Error> {
        let ipnet::IpNet::V4(ipnet) = ipnet else {
            return Err(Error::InvalidConfig(
                "fake ip range must be IPv4".to_owned(),
            ));
        };
        let network = Self::ip_to_uint(&ipnet.network());
        let host_bits = 32 - ipnet.prefix_len();
        let host_mask = match host_bits {
            32 => u32::MAX,
            bits => (1u32 << bits) - 1,
        };
        let last = network | host_mask;
        let gateway = network.checked_add(1).ok_or_else(|| {
            Error::InvalidConfig("fake ip range has no gateway address".to_owned())
        })?;
        let min = network.checked_add(2).ok_or_else(|| {
            Error::InvalidConfig(
                "fake ip range has no allocatable addresses".to_owned(),
            )
        })?;
        let max =
            last.checked_sub(1)
                .filter(|max| *max >= min)
                .ok_or_else(|| {
                    Error::InvalidConfig(
                        "fake ip range has no allocatable addresses".to_owned(),
                    )
                })?;

        Ok((gateway, min, max))
    }

    pub async fn lookup(&mut self, host: &str) -> net::IpAddr {
        if let Some(ip) = self.store.get_by_host(host).await
            && self.contains_allocatable(ip)
        {
            return ip;
        }

        let ip = self.get(host).await;
        self.store.pub_by_host(host, ip).await;
        ip
    }

    pub async fn reverse_lookup(&mut self, ip: net::IpAddr) -> Option<String> {
        if !ip.is_ipv4() {
            None
        } else {
            self.store.get_by_ip(ip).await
        }
    }

    pub fn should_skip(&self, domain: &str) -> bool {
        match &self.skipped_hostnames {
            None => false,
            Some(host) => host.search(domain).is_some(),
        }
    }

    #[allow(dead_code)]
    pub async fn exist(&mut self, ip: net::IpAddr) -> bool {
        if !ip.is_ipv4() {
            false
        } else {
            self.store.exist(ip).await
        }
    }

    pub async fn is_fake_ip(&mut self, ip: net::IpAddr) -> bool {
        let net::IpAddr::V4(v4) = ip else {
            return false;
        };
        // Broadcast and multicast addresses are never allocated as fake IPs.
        if v4.is_broadcast() || v4.is_multicast() {
            return false;
        }
        // Only IPs that are both within the fake-IP range *and* have actually
        // been allocated in the store should be treated as fake IPs.  This
        // prevents directed-broadcast addresses (e.g. 198.18.0.255 for the
        // /24 TUN subnet) that fall inside the wider fake-IP /16 range from
        // triggering a failed reverse-lookup in the dispatcher.
        self.contains_allocatable(ip) && self.store.exist(ip).await
    }

    #[allow(dead_code)]
    pub fn gateway(&self) -> net::Ipv4Addr {
        net::Ipv4Addr::from(self.gateway)
    }

    #[allow(dead_code)]
    pub fn ipnet(&self) -> ipnet::IpNet {
        self.ipnet
    }

    #[allow(dead_code)]
    pub async fn copy_from(&mut self, src: &Self) {
        src.store.copy_to(&mut self.store).await;
    }

    async fn get(&mut self, host: &str) -> net::IpAddr {
        let start = self.offset;
        let victim = net::IpAddr::V4((self.min + start).into());

        let ip = loop {
            let value = self.min + self.offset;
            let candidate = net::IpAddr::V4(value.into());
            self.offset = if value == self.max {
                0
            } else {
                self.offset + 1
            };

            if !self.store.exist(candidate).await {
                break candidate;
            }
            if self.offset == start {
                self.store.del_by_ip(victim).await;
                self.offset = if self.min + start == self.max {
                    0
                } else {
                    start + 1
                };
                break victim;
            }
        };

        self.store.put_by_ip(ip, host).await;
        ip
    }

    pub async fn flush(&mut self) {
        self.store.flush().await;
        self.offset = 0;
    }

    fn ip_to_uint(ip: &net::Ipv4Addr) -> u32 {
        BigEndian::read_u32(&ip.octets())
    }

    fn contains_allocatable(&self, ip: net::IpAddr) -> bool {
        let net::IpAddr::V4(ip) = ip else {
            return false;
        };
        self.ipnet.contains(&net::IpAddr::V4(ip))
            && (self.min..=self.max).contains(&Self::ip_to_uint(&ip))
    }
}

#[cfg(test)]
mod tests {
    use std::{net, sync::Arc};

    use crate::{app::dns::fakeip::mem_store::InMemStore, common::trie};

    use super::{FakeDns, Opts, Store};

    #[tokio::test]
    async fn test_inmem_basic() {
        let ipnet = "192.168.0.0/29".parse::<ipnet::IpNet>().unwrap();
        let store = Box::new(InMemStore::new(10));
        let mut pool = FakeDns::new(Opts {
            ipnet,
            skipped_hostnames: None,
            store,
        })
        .unwrap();

        let first = pool.lookup("foo.com").await;
        let last = pool.lookup("bar.com").await;

        let bar = pool.reverse_lookup(last).await;

        assert_eq!(first, net::IpAddr::from([192, 168, 0, 2]));
        assert_eq!(
            pool.lookup("foo.com").await,
            net::IpAddr::from([192, 168, 0, 2])
        );
        assert_eq!(last, net::IpAddr::from([192, 168, 0, 3]));
        assert!(bar.is_some());
        assert_eq!(bar, Some("bar.com".into()));
        assert_eq!(pool.gateway(), net::IpAddr::from([192, 168, 0, 1]));
        assert_eq!(pool.ipnet().to_string(), ipnet.to_string());
        assert!(pool.exist(net::IpAddr::from([192, 168, 0, 3])).await);
        assert!(!pool.exist(net::IpAddr::from([192, 168, 0, 4])).await);
        assert!(!pool.exist("::1".parse().unwrap()).await);
    }

    #[tokio::test]
    async fn test_inmem_cycle_used() {
        let store = Box::new(InMemStore::new(10));

        let ipnet = "192.168.0.0/29".parse::<ipnet::IpNet>().unwrap();
        let mut pool = FakeDns::new(Opts {
            ipnet,
            skipped_hostnames: None,
            store,
        })
        .unwrap();

        let foo = pool.lookup("foo.com").await;
        let bar = pool.lookup("bar.com").await;

        for i in 0..3 {
            pool.lookup(&format!("{}.com", i)).await;
        }

        let baz = pool.lookup("baz.com").await;
        let next = pool.lookup("foo.com").await;
        assert_eq!(foo, baz);
        assert_eq!(next, bar);
    }

    #[tokio::test]
    async fn ipv4_pool_excludes_network_gateway_and_broadcast() {
        let mut pool = FakeDns::new(Opts {
            ipnet: "192.0.2.0/29".parse().unwrap(),
            skipped_hostnames: None,
            store: Box::new(InMemStore::new(10)),
        })
        .unwrap();

        let mut allocated = Vec::new();
        for index in 0..5 {
            allocated.push(pool.lookup(&format!("{index}.example")).await);
        }
        assert_eq!(
            allocated,
            [
                "192.0.2.2".parse::<net::IpAddr>().unwrap(),
                "192.0.2.3".parse::<net::IpAddr>().unwrap(),
                "192.0.2.4".parse::<net::IpAddr>().unwrap(),
                "192.0.2.5".parse::<net::IpAddr>().unwrap(),
                "192.0.2.6".parse::<net::IpAddr>().unwrap(),
            ],
        );
        assert_eq!(pool.lookup("wrapped.example").await, allocated[0]);
    }

    #[tokio::test]
    async fn cached_reserved_address_is_not_reused() {
        let mut store = InMemStore::new(10);
        let gateway = "192.0.2.1".parse::<net::IpAddr>().unwrap();
        store.put_by_ip(gateway, "example.com").await;
        store.pub_by_host("example.com", gateway).await;
        let mut pool = FakeDns::new(Opts {
            ipnet: "192.0.2.0/29".parse().unwrap(),
            skipped_hostnames: None,
            store: Box::new(store),
        })
        .unwrap();

        assert_eq!(
            pool.lookup("example.com").await,
            "192.0.2.2".parse::<net::IpAddr>().unwrap(),
        );
    }

    #[tokio::test]
    async fn test_pool_skip() {
        let store = Box::new(InMemStore::new(10));

        let ipnet = "192.168.0.0/30".parse::<ipnet::IpNet>().unwrap();
        let mut tree = trie::StringTrie::new();
        tree.insert("example.com", Arc::new(false));

        let pool = FakeDns::new(Opts {
            ipnet,
            skipped_hostnames: Some(tree),
            store,
        })
        .unwrap();

        assert!(pool.should_skip("example.com"));
        assert!(!pool.should_skip("foo.com"));
    }

    #[tokio::test]
    async fn test_pool_max_cache_size() {
        let store = Box::new(InMemStore::new(2));

        let ipnet = "192.168.0.0/24".parse::<ipnet::IpNet>().unwrap();
        let mut pool = FakeDns::new(Opts {
            ipnet,
            skipped_hostnames: None,
            store,
        })
        .unwrap();

        let first = pool.lookup("foo.com").await;

        pool.lookup("bar.com").await;
        pool.lookup("baz.com").await;
        let next = pool.lookup("foo.com").await;

        assert_ne!(first, next);
    }

    #[tokio::test]
    #[ignore = "copy not implemented"]
    async fn test_pool_clone() {
        let store = Box::new(InMemStore::new(2));

        let ipnet = "192.168.0.0/24".parse::<ipnet::IpNet>().unwrap();
        let mut pool = FakeDns::new(Opts {
            ipnet,
            skipped_hostnames: None,
            store,
        })
        .unwrap();

        let first = pool.lookup("foo.com").await;
        let last = pool.lookup("bar.com").await;
        assert_eq!(first, net::IpAddr::from([192, 168, 0, 2]));
        assert_eq!(last, net::IpAddr::from([192, 168, 0, 3]));

        let store = Box::new(InMemStore::new(2));

        let mut new_pool = FakeDns::new(Opts {
            ipnet,
            skipped_hostnames: None,
            store,
        })
        .unwrap();

        new_pool.copy_from(&pool).await;

        assert!(new_pool.reverse_lookup(first).await.is_some());
        assert!(new_pool.reverse_lookup(last).await.is_some());
    }

    #[tokio::test]
    async fn test_is_fake_ip_excludes_broadcast_and_unallocated() {
        let store = Box::new(InMemStore::new(10));

        // Use 198.18.0.0/16 (the default fake-ip-range) to mirror the real
        // production setup described in the bug report, where the TUN gateway
        // is 198.18.0.1/24 and its subnet broadcast 198.18.0.255 fell inside
        // the wider /16 fake-ip range.
        let ipnet = "198.18.0.0/16".parse::<ipnet::IpNet>().unwrap();
        let mut pool = FakeDns::new(Opts {
            ipnet,
            skipped_hostnames: None,
            store,
        })
        .unwrap();

        // Allocate one real fake IP.
        let allocated = pool.lookup("foo.com").await;
        assert!(
            pool.is_fake_ip(allocated).await,
            "allocated IP must be fake"
        );

        // Directed broadcast for the /24 TUN subnet (198.18.0.0/24) – never
        // allocated, yet it falls inside the /16 range.
        let directed_broadcast: net::IpAddr = "198.18.0.255".parse().unwrap();
        assert!(
            !pool.is_fake_ip(directed_broadcast).await,
            "directed broadcast must not be treated as a fake IP"
        );

        // Global broadcast must never be a fake IP.
        let global_broadcast: net::IpAddr = "255.255.255.255".parse().unwrap();
        assert!(
            !pool.is_fake_ip(global_broadcast).await,
            "255.255.255.255 must not be a fake IP"
        );

        // A multicast address must never be a fake IP.
        let multicast: net::IpAddr = "224.0.0.1".parse().unwrap();
        assert!(
            !pool.is_fake_ip(multicast).await,
            "multicast must not be a fake IP"
        );

        // An IP in the range that was never allocated must not be fake.
        let unallocated: net::IpAddr = "198.18.1.1".parse().unwrap();
        assert!(
            !pool.is_fake_ip(unallocated).await,
            "unallocated in-range IP must not be treated as a fake IP"
        );
    }
}
