use tracing::debug;

use super::RuleMatcher;
use crate::{common::mmdb::MmdbLookup, session::Session};

#[derive(Clone)]
pub struct IpAsn {
    pub target: String,
    pub asn: String,
    pub no_resolve: bool,
    pub is_src: bool,
    pub mmdb: Option<MmdbLookup>,
}

impl std::fmt::Display for IpAsn {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let rule_type = if self.is_src { "SRC-IP-ASN" } else { "IP-ASN" };
        write!(f, "{}({} - {})", rule_type, self.target, self.asn)
    }
}

impl RuleMatcher for IpAsn {
    fn apply(&self, sess: &Session) -> bool {
        let ip = if self.is_src {
            Some(sess.source.ip())
        } else {
            sess.resolved_ip.or(sess.destination.ip())
        };

        if let Some(ip) = ip {
            if let Some(mmdb) = &self.mmdb {
                mmdb.lookup_asn(ip).is_ok_and(|asn_result| {
                    asn_result.asn_number.to_string() == self.asn
                })
            } else {
                debug!(
                    "IP-ASN lookup failed: ASN MMDB not available. Maybe \
                     config.asn-mmdb is not set?"
                );
                false
            }
        } else {
            false
        }
    }

    fn target(&self) -> &str {
        self.target.as_str()
    }

    fn payload(&self) -> String {
        self.asn.clone()
    }

    fn type_name(&self) -> &str {
        if self.is_src { "SRC-IP-ASN" } else { "IP-ASN" }
    }

    fn should_resolve_ip(&self) -> bool {
        !self.no_resolve && !self.is_src
    }
}
