use ipnet::IpNet;
use std::net::IpAddr;

use crate::{
    Error,
    config::internal::proxy::OutboundWireguard,
    proxy::{
        HandlerCommonOptions,
        wg::{Handler, HandlerOptions},
    },
};

impl TryFrom<OutboundWireguard> for Handler {
    type Error = crate::Error;

    fn try_from(value: OutboundWireguard) -> Result<Self, Self::Error> {
        (&value).try_into()
    }
}

impl TryFrom<&OutboundWireguard> for Handler {
    type Error = crate::Error;

    fn try_from(s: &OutboundWireguard) -> Result<Self, Self::Error> {
        let h = Handler::new(HandlerOptions {
            name: s.common_opts.name.to_owned(),
            common_opts: HandlerCommonOptions {
                connector: s.common_opts.connect_via.clone(),
                ..Default::default()
            },
            server: s.common_opts.server.to_owned(),
            port: s.common_opts.port,
            ip: match parse_wireguard_address(&s.ip, "ip")? {
                IpAddr::V4(ip) => ip,
                IpAddr::V6(_) => {
                    return Err(Error::InvalidConfig(
                        "WireGuard `ip` must be an IPv4 address".to_owned(),
                    ));
                }
            },
            ipv6: s
                .ipv6
                .as_deref()
                .map(|value| match parse_wireguard_address(value, "ipv6")? {
                    IpAddr::V6(ip) => Ok(ip),
                    IpAddr::V4(_) => Err(Error::InvalidConfig(
                        "WireGuard `ipv6` must be an IPv6 address".to_owned(),
                    )),
                })
                .transpose()?,
            private_key: s.private_key.to_owned(),
            public_key: s.public_key.to_owned(),
            pre_shared_key: s.pre_shared_key.as_ref().map(|x| x.to_owned()),
            remote_dns_resolve: s.remote_dns_resolve.unwrap_or_default(),
            dns: s.dns.as_ref().map(|x| x.to_owned()),
            mtu: s.mtu,
            udp: s.udp.unwrap_or_default(),
            allowed_ips: s.allowed_ips.as_ref().map(|x| x.to_owned()),
            reserved_bits: s.reserved_bits.as_ref().map(|x| x.to_owned()),
        });
        Ok(h)
    }
}

/// Mihomo accepts both host addresses and CIDR prefixes in WireGuard's `ip`
/// and `ipv6` fields, normalizing bare hosts to /32 or /128 internally.
fn parse_wireguard_address(value: &str, field: &str) -> Result<IpAddr, Error> {
    value
        .parse::<IpNet>()
        .map(|network| network.addr())
        .or_else(|_| value.parse::<IpAddr>())
        .map_err(|error| {
            Error::InvalidConfig(format!(
                "invalid WireGuard `{field}` address `{value}`: {error}"
            ))
        })
}

#[cfg(test)]
mod tests {
    use super::parse_wireguard_address;
    use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

    #[test]
    fn accepts_mihomo_wireguard_host_and_prefix_addresses() {
        assert_eq!(
            parse_wireguard_address("100.80.234.177", "ip").unwrap(),
            IpAddr::V4(Ipv4Addr::new(100, 80, 234, 177))
        );
        assert_eq!(
            parse_wireguard_address("100.80.234.177/32", "ip").unwrap(),
            IpAddr::V4(Ipv4Addr::new(100, 80, 234, 177))
        );
        assert_eq!(
            parse_wireguard_address("fd00::1", "ipv6").unwrap(),
            IpAddr::V6("fd00::1".parse::<Ipv6Addr>().unwrap())
        );
        assert_eq!(
            parse_wireguard_address("fd00::1/128", "ipv6").unwrap(),
            IpAddr::V6("fd00::1".parse::<Ipv6Addr>().unwrap())
        );
    }

    #[test]
    fn rejects_invalid_wireguard_addresses() {
        assert!(parse_wireguard_address("not-an-ip", "ip").is_err());
    }
}
