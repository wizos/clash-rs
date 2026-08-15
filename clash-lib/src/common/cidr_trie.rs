use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

use ip_network_table_deps_treebitmap::IpLookupTable;

pub struct CidrTrie {
    v4: IpLookupTable<Ipv4Addr, bool>,
    v6: IpLookupTable<Ipv6Addr, bool>,
}

impl CidrTrie {
    pub fn new() -> Self {
        Self {
            v4: IpLookupTable::new(),
            v6: IpLookupTable::new(),
        }
    }

    pub fn insert(&mut self, cidr: &str) -> bool {
        cidr.parse::<ipnet::IpNet>()
            .is_ok_and(|cidr| self.insert_ip(cidr.addr(), cidr.prefix_len()))
    }

    pub fn insert_ip(&mut self, ip: IpAddr, prefix: u8) -> bool {
        match ipnet::IpNet::new(ip, prefix) {
            Ok(ipnet::IpNet::V4(network)) => {
                self.v4.insert(network.trunc().addr(), prefix.into(), true);
                true
            }
            Ok(ipnet::IpNet::V6(network)) => {
                self.v6.insert(network.trunc().addr(), prefix.into(), true);
                true
            }
            _ => false,
        }
    }

    pub fn len(&self) -> usize {
        self.v4.len() + self.v6.len()
    }

    pub fn contains(&self, ip: IpAddr) -> bool {
        match ip {
            IpAddr::V4(ip) => self.v4.longest_match(ip).is_some(),
            IpAddr::V6(ip) => self.v6.longest_match(ip).is_some(),
        }
    }
}
