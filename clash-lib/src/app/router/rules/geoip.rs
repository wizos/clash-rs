use std::sync::Arc;

use tracing::warn;

use super::RuleMatcher;
use crate::{
    common::{cidr_trie::CidrTrie, geodata::GeoDataLookup, mmdb::MmdbLookup},
    session::Session,
};

#[derive(Clone)]
enum GeoIpDatabase {
    Dat(Option<Arc<CidrTrie>>),
    Mmdb(Option<MmdbLookup>),
}

#[derive(Clone)]
pub struct GeoIP {
    pub target: String,
    pub country_code: String,
    pub no_resolve: bool,
    pub is_src: bool,
    database: GeoIpDatabase,
}

impl GeoIP {
    pub fn new(
        target: String,
        country_code: String,
        no_resolve: bool,
        is_src: bool,
        mmdb: Option<MmdbLookup>,
        geodata: Option<&GeoDataLookup>,
    ) -> Self {
        let database = if geodata.is_some_and(|loader| loader.has_geoip()) {
            let matcher = geodata.and_then(|loader| loader.get_ip(&country_code));
            if matcher.is_none() {
                warn!("GeoIP.dat country {country_code} is unavailable");
            }
            GeoIpDatabase::Dat(matcher)
        } else {
            GeoIpDatabase::Mmdb(mmdb)
        };
        Self {
            target,
            country_code,
            no_resolve,
            is_src,
            database,
        }
    }
}

impl std::fmt::Display for GeoIP {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "GeoIP({} - {})", self.target, self.country_code)
    }
}

impl RuleMatcher for GeoIP {
    fn apply(&self, sess: &Session) -> bool {
        let ip = if self.is_src {
            Some(sess.source.ip())
        } else {
            sess.resolved_ip.or(sess.destination.ip())
        };

        if let Some(ip) = ip {
            match &self.database {
                GeoIpDatabase::Dat(Some(matcher)) => matcher.contains(ip),
                GeoIpDatabase::Dat(None) => false,
                GeoIpDatabase::Mmdb(Some(mmdb)) => {
                    mmdb.lookup_country(ip).is_ok_and(|country| {
                        country
                            .country_code
                            .eq_ignore_ascii_case(&self.country_code)
                    })
                }
                GeoIpDatabase::Mmdb(None) => false,
            }
        } else {
            false
        }
    }

    fn target(&self) -> &str {
        self.target.as_str()
    }

    fn payload(&self) -> String {
        self.country_code.clone()
    }

    fn type_name(&self) -> &str {
        if self.is_src { "SrcGeoIP" } else { "GeoIP" }
    }

    fn should_resolve_ip(&self) -> bool {
        !self.is_src && !self.no_resolve
    }
}

#[cfg(test)]
mod tests {
    use prost::Message;

    use super::*;
    use crate::common::geodata::{GeoData, geodata_proto};

    #[tokio::test]
    async fn matches_geoip_dat_when_configured() {
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
        let geodata = Arc::new(GeoData::from_files(None, Some(path)).await.unwrap())
            as GeoDataLookup;
        let rule = GeoIP::new(
            "DIRECT".to_owned(),
            "CN".to_owned(),
            true,
            false,
            None,
            Some(&geodata),
        );

        assert!(rule.apply(&Session {
            destination: "1.2.3.4:443".parse().unwrap(),
            ..Default::default()
        }));
        assert!(!rule.apply(&Session {
            destination: "8.8.8.8:443".parse().unwrap(),
            ..Default::default()
        }));
    }
}
