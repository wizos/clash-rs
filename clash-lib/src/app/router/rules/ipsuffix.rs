use super::RuleMatcher;
use crate::session::Session;
use ipnet::IpNet;
use std::net::IpAddr;

pub struct IpSuffix {
    pub ipnet: IpNet,
    pub target: String,
    pub no_resolve: bool,
    pub is_src: bool,
}

impl IpSuffix {
    fn matches_ip(&self, ip: IpAddr) -> bool {
        match (self.ipnet.addr(), ip) {
            (IpAddr::V4(pattern), IpAddr::V4(candidate)) => suffix_matches(
                u32::from(pattern) as u128,
                u32::from(candidate) as u128,
                self.ipnet.prefix_len(),
                32,
            ),
            (IpAddr::V6(pattern), IpAddr::V6(candidate)) => suffix_matches(
                u128::from(pattern),
                u128::from(candidate),
                self.ipnet.prefix_len(),
                128,
            ),
            _ => false,
        }
    }
}

fn suffix_matches(pattern: u128, candidate: u128, bits: u8, width: u8) -> bool {
    let mask = match bits {
        0 => 0,
        bits if bits == width => u128::MAX >> (128 - width),
        bits => (1_u128 << bits) - 1,
    };
    pattern & mask == candidate & mask
}

impl std::fmt::Display for IpSuffix {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{} ip suffix {}", self.target, self.ipnet)
    }
}

impl RuleMatcher for IpSuffix {
    fn apply(&self, sess: &Session) -> bool {
        let ip = if self.is_src {
            Some(sess.source.ip())
        } else {
            sess.resolved_ip.or(sess.destination.ip())
        };
        ip.is_some_and(|ip| self.matches_ip(ip))
    }

    fn target(&self) -> &str {
        &self.target
    }

    fn payload(&self) -> String {
        self.ipnet.to_string()
    }

    fn type_name(&self) -> &str {
        if self.is_src {
            "SrcIPSuffix"
        } else {
            "IPSuffix"
        }
    }

    fn should_resolve_ip(&self) -> bool {
        !self.is_src && !self.no_resolve
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn matches_ipv4_suffix_bits() {
        let matcher = IpSuffix {
            ipnet: "8.8.8.8/24".parse().unwrap(),
            target: "PROXY".to_string(),
            no_resolve: false,
            is_src: false,
        };

        assert!(matcher.matches_ip("1.8.8.8".parse().unwrap()));
        assert!(!matcher.matches_ip("8.8.8.9".parse().unwrap()));
    }
}
