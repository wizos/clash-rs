use std::{
    net,
    sync::{Arc, OnceLock},
};

use crate::{
    app::dns::PendingGeoData,
    common::{mmdb::MmdbLookup, trie},
};

pub trait FallbackIPFilter: Sync + Send {
    fn apply(&self, ip: &net::IpAddr) -> bool;
}

/// A shared, lazily-populated MMDB handle.  The `OnceLock` starts empty and is
/// filled in after the `OutboundManager` (and its full outbound registry) is
/// ready, so that any MMDB download can use proxy groups if needed.
pub type PendingMmdb = Arc<OnceLock<MmdbLookup>>;

pub struct GeoIPFilter(String, Option<PendingMmdb>, Option<PendingGeoData>);

impl GeoIPFilter {
    pub fn new(
        code: &str,
        mmdb: Option<PendingMmdb>,
        geodata: Option<PendingGeoData>,
    ) -> Self {
        Self(code.to_owned(), mmdb, geodata)
    }
}

impl FallbackIPFilter for GeoIPFilter {
    fn apply(&self, ip: &net::IpAddr) -> bool {
        if let Some(geodata) = self.2.as_ref().and_then(|pending| pending.get())
            && geodata.has_geoip()
        {
            return !geodata
                .get_ip(&self.0)
                .is_some_and(|matcher| matcher.contains(*ip));
        }
        // When the OnceLock is not yet populated (e.g. during startup before the
        // MMDB is loaded) `lock.get()` returns `None`, making this return `true`
        // — the permissive default that lets all IPs through to the fallback
        // resolver.  Once the MMDB is set the filter behaves normally.
        !self
            .1
            .as_ref()
            .and_then(|lock| lock.get())
            .is_some_and(|mmdb| {
                mmdb.lookup_country(*ip)
                    .map(|x| x.country_code)
                    .is_ok_and(|x| x == self.0)
            })
    }
}

pub struct IPNetFilter(ipnet::IpNet);

impl IPNetFilter {
    pub fn new(ipnet: ipnet::IpNet) -> Self {
        Self(ipnet)
    }
}

impl FallbackIPFilter for IPNetFilter {
    fn apply(&self, ip: &net::IpAddr) -> bool {
        self.0.contains(ip)
    }
}

pub trait FallbackDomainFilter: Sync + Send {
    fn apply(&self, domain: &str) -> bool;
}

pub struct DomainFilter(trie::StringTrie<Option<String>>);

impl DomainFilter {
    pub fn new(domains: Vec<&str>) -> Self {
        let mut f = DomainFilter(trie::StringTrie::new());
        for d in domains {
            f.0.insert(d, Arc::new(None));
        }
        f
    }
}

impl FallbackDomainFilter for DomainFilter {
    fn apply(&self, domain: &str) -> bool {
        self.0.search(domain).is_some()
    }
}

#[cfg(test)]
mod tests {
    use prost::Message;

    use super::*;
    use crate::common::geodata::{GeoData, GeoDataLookup, geodata_proto};

    #[tokio::test]
    async fn geoip_dat_drives_fallback_filter_after_loader_is_ready() {
        let bytes = geodata_proto::GeoIpList {
            entry: vec![geodata_proto::GeoIp {
                country_code: "CN".to_owned(),
                cidr: vec![geodata_proto::Cidr {
                    ip: vec![1, 2, 3, 0],
                    prefix: 24,
                }],
                reverse_match: false,
            }],
        }
        .encode_to_vec();
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("geoip.dat");
        std::fs::write(&path, bytes).unwrap();
        let pending: PendingGeoData = Arc::new(OnceLock::new());
        let filter = GeoIPFilter::new("CN", None, Some(pending.clone()));

        assert!(filter.apply(&"1.2.3.4".parse().unwrap()));
        let geodata = Arc::new(GeoData::from_files(None, Some(path)).await.unwrap())
            as GeoDataLookup;
        assert!(pending.set(geodata).is_ok());
        assert!(!filter.apply(&"1.2.3.4".parse().unwrap()));
        assert!(filter.apply(&"8.8.8.8".parse().unwrap()));
    }
}
