use crate::{
    config::internal::proxy::OutboundHysteria,
    proxy::hysteria::{self, Handler, HystOption, XPlusObfs},
    session::SocksAddr,
};
use std::{
    num::{NonZeroU16, ParseIntError},
    ops::RangeInclusive,
};

#[derive(Clone)]
pub struct PortGenerator {
    // must have a default port
    pub default: u16,
    ports: Vec<u16>,
    range: Vec<RangeInclusive<u16>>,
}

impl PortGenerator {
    pub fn new(port: u16) -> Self {
        PortGenerator {
            default: port,
            ports: vec![],
            range: vec![],
        }
    }

    pub fn add_single(&mut self, port: u16) {
        self.ports.push(port);
    }

    fn add_range(&mut self, start: u16, end: u16) {
        self.range.push(start..=end);
    }

    pub fn get(&self) -> u16 {
        let len =
            1 + self.ports.len() + self.range.iter().map(|r| r.len()).sum::<usize>();
        let idx = rand::random_range(0..len);
        match idx {
            0 => self.default,
            idx if idx <= self.ports.len() => self.ports[idx - 1],
            idx => {
                let mut x = self.range.iter().cloned().flatten();
                x.nth(idx - 1 - self.ports.len()).unwrap()
            }
        }
    }

    pub fn parse_ports_str(self, ports: &str) -> Result<Self, ParseIntError> {
        if ports.is_empty() {
            return Ok(self);
        }
        ports
            .split(',')
            .map(|s| s.trim())
            .try_fold(self, |mut acc, ports| {
                let x: Result<_, ParseIntError> = ports
                    .parse::<u16>()
                    .map(|p| acc.add_single(p))
                    .or_else(|e| {
                        let mut iter = ports.split('-');
                        let start = iter.next().ok_or(e.clone())?;
                        let end = iter.next().ok_or(e)?;
                        let start = start.parse::<NonZeroU16>()?;
                        let end = end.parse::<NonZeroU16>()?;
                        acc.add_range(start.get(), end.get());
                        Ok(())
                    })
                    .map(|_| acc);
                x
            })
    }
}

/// Parse a bandwidth string like "100 mbps", "1 gbps", "200 Kbps" into bytes
/// per second. Follows the same format as the Go implementation:
/// - Format: `<number> [K|M|G|T][B|B]ps`
/// - If no unit, treat as Mbps
/// - Bps = bytes per second, bps = bits per second (divide by 8)
fn string_to_bps(s: &str) -> u64 {
    let s = s.trim();
    if s.is_empty() {
        return 0;
    }

    // If it's just a number, treat as Mbps
    if let Ok(v) = s.parse::<u64>() {
        return string_to_bps(&format!("{} Mbps", v));
    }

    // Parse format: <number> [K|M|G|T][B|b]ps (case insensitive for prefix, case
    // sensitive for B/b)
    let s_upper = s.to_uppercase();
    let re = regex::Regex::new(r"^(\d+)\s*([KMGT]?)([Bb])PS$").unwrap();
    // In mihomo convention for hysteria2, all bandwidth values are treated as
    // bytes/s regardless of B/b case. Mbps = MB/s, Kbps = KB/s, etc.
    // Only pure "bps" (no prefix) would be bits/s, but that's extremely rare in
    // configs.
    if let Some(caps) = re.captures(&s_upper) {
        let value: u64 = caps[1].parse().unwrap_or(0);
        let mut multiplier: u64 = 1;
        match &caps[2] {
            "T" => multiplier *= 1000 * 1000 * 1000 * 1000,
            "G" => multiplier *= 1000 * 1000 * 1000,
            "M" => multiplier *= 1000 * 1000,
            "K" => multiplier *= 1000,
            _ => {}
        }
        let result = value * multiplier;
        return result;
    }

    0
}

impl TryFrom<OutboundHysteria> for Handler {
    type Error = crate::Error;

    fn try_from(value: OutboundHysteria) -> Result<Self, Self::Error> {
        let addr = SocksAddr::try_from((value.server, value.port))?;

        let obfs = if let Some(obfs_str) = value.obfs.as_ref() {
            if !obfs_str.is_empty() {
                Some(hysteria::Obfs::XPlus(XPlusObfs {
                    key: obfs_str.as_bytes().to_vec(),
                }))
            } else {
                None
            }
        } else {
            None
        };

        let ports_gen = if let Some(ports) = value.ports {
            Some(
                PortGenerator::new(value.port)
                    .parse_ports_str(&ports)
                    .map_err(|e| {
                        crate::Error::InvalidConfig(format!(
                            "hysteria parse ports error: {e:?}, ports: {ports:?}"
                        ))
                    })?,
            )
        } else {
            None
        };

        // Parse auth: auth-str takes priority, auth is base64 encoded
        let auth = if let Some(auth_str) = value.auth_str {
            auth_str.into_bytes()
        } else if let Some(auth) = value.auth {
            // auth is base64 encoded
            use base64::Engine;
            base64::engine::general_purpose::STANDARD
                .decode(&auth)
                .map_err(|e| {
                    crate::Error::InvalidConfig(format!(
                        "hysteria auth base64 decode error: {e:?}"
                    ))
                })?
        } else {
            vec![]
        };

        // Parse bandwidth strings
        let up_bps = if let Some(up) = value.up {
            string_to_bps(&up)
        } else {
            0
        };
        let down_bps = if let Some(down) = value.down {
            string_to_bps(&down)
        } else {
            0
        };

        if up_bps == 0 || down_bps == 0 {
            return Err(crate::Error::InvalidConfig(
                "hysteria: invalid up/down bandwidth, must be non-zero".to_owned(),
            ));
        }

        let opts = HystOption {
            name: value.name,
            sni: value.sni.or(addr.domain().map(|s| s.to_owned())),
            addr,
            alpn: value.alpn.unwrap_or_default(),
            ca: value.ca.map(|s| s.into()),
            fingerprint: value.fingerprint,
            skip_cert_verify: value.skip_cert_verify,
            auth,
            ports: ports_gen,
            obfs,
            up_bps,
            down_bps,
            fast_open: value.fast_open.unwrap_or(false),
            hop_interval: value.hop_interval,
            disable_mtu_discovery: value.disable_mtu_discovery.unwrap_or(false),
            ca_str: value.ca_str,
            recv_window_conn: value.recv_window_conn,
            recv_window: value.recv_window,
            ech: super::utils::tls_ech_options(value.ech_opts.as_ref()),
            tls_cert: value.tls_cert,
            tls_key: value.tls_key,
        };

        Ok(Handler::new(opts))
    }
}

#[test]
fn test_port_gen() {
    let p = PortGenerator::new(1000).parse_ports_str("").unwrap();
    let p = p.parse_ports_str("1001,1002,1003, 5000-5001").unwrap();

    for _ in 0..100 {
        println!("{}", p.get());
    }
}

#[test]
fn test_string_to_bps() {
    // Test Mbps (treated as MB/s in mihomo convention)
    assert_eq!(string_to_bps("100 Mbps"), 100 * 1000 * 1000);
    // Test Gbps (treated as GB/s)
    assert_eq!(string_to_bps("1 Gbps"), 1u64 * 1000 * 1000 * 1000);
    // Test Kbps (treated as KB/s in mihomo convention)
    assert_eq!(string_to_bps("200 Kbps"), 200 * 1000);
    // Test MBps (bytes)
    assert_eq!(string_to_bps("10 MBps"), 10 * 1000 * 1000);
    // Test plain number (treated as Mbps)
    assert_eq!(string_to_bps("100"), 100 * 1000 * 1000);
    // Test TBps
    assert_eq!(string_to_bps("1 TBps"), 1u64 * 1000 * 1000 * 1000 * 1000);
}
