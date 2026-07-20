use std::net::{IpAddr, Ipv4Addr};

use ipnet::IpNet;

use crate::{
    Error,
    config::internal::proxy::OutboundMasque,
    proxy::{
        HandlerCommonOptions,
        masque::{Handler, HandlerOptions, MasqueNetwork, MasqueTlsClient},
    },
};

const DEFAULT_SNI: &str = "consumer-masque.cloudflareclient.com";
const DEFAULT_URI: &str = "https://cloudflareaccess.com";

fn parse_address(
    value: Option<&str>,
    expected_v4: bool,
) -> Result<Option<IpAddr>, Error> {
    let Some(value) = value.filter(|value| !value.trim().is_empty()) else {
        return Ok(None);
    };
    let address = if value.contains('/') {
        value
            .parse::<IpNet>()
            .map_err(|error| {
                Error::InvalidConfig(format!(
                    "invalid MASQUE local address `{value}`: {error}"
                ))
            })?
            .addr()
    } else {
        value.parse::<IpAddr>().map_err(|error| {
            Error::InvalidConfig(format!(
                "invalid MASQUE local address `{value}`: {error}"
            ))
        })?
    };
    if address.is_ipv4() != expected_v4 {
        return Err(Error::InvalidConfig(format!(
            "MASQUE `{value}` is not an {} address",
            if expected_v4 { "IPv4" } else { "IPv6" },
        )));
    }
    Ok(Some(address))
}

impl TryFrom<OutboundMasque> for Handler {
    type Error = Error;

    fn try_from(config: OutboundMasque) -> Result<Self, Self::Error> {
        let network = config.network.as_deref().unwrap_or("h3");
        let network = match network.to_ascii_lowercase().as_str() {
            "h2" => MasqueNetwork::H2,
            "h3" => MasqueNetwork::H3,
            value => {
                return Err(Error::InvalidConfig(format!(
                    "unsupported MASQUE network `{value}`"
                )));
            }
        };

        let ipv4 = parse_address(config.ip.as_deref(), true)?.and_then(|address| {
            match address {
                IpAddr::V4(address) => Some(address),
                IpAddr::V6(_) => None,
            }
        });
        let ipv6 =
            parse_address(config.ipv6.as_deref(), false)?.and_then(|address| {
                match address {
                    IpAddr::V4(_) => None,
                    IpAddr::V6(address) => Some(address),
                }
            });
        if ipv4.is_none() && ipv6.is_none() {
            return Err(Error::InvalidConfig(
                "MASQUE requires `ip` and/or `ipv6`".to_owned(),
            ));
        }

        let tls = MasqueTlsClient::new(
            &config.private_key,
            &config.public_key,
            config.sni.unwrap_or_else(|| DEFAULT_SNI.to_owned()),
            config.skip_cert_verify,
            network,
        )?;

        Handler::new(HandlerOptions {
            name: config.common_opts.name,
            common_opts: HandlerCommonOptions {
                connector: config.common_opts.connect_via,
                ..Default::default()
            },
            server: config.common_opts.server,
            port: config.common_opts.port,
            ip: ipv4.unwrap_or(Ipv4Addr::UNSPECIFIED),
            has_ipv4: ipv4.is_some(),
            ipv6,
            uri: config.uri.unwrap_or_else(|| DEFAULT_URI.to_owned()),
            mtu: if config.mtu == 0 { 1280 } else { config.mtu },
            udp: config.udp,
            remote_dns_resolve: config.remote_dns_resolve,
            dns: config.dns,
            network,
            tls,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::parse_address;

    #[test]
    fn accepts_mihomo_local_address_with_or_without_prefix() {
        assert_eq!(
            parse_address(Some("100.64.0.2/32"), true).unwrap(),
            Some("100.64.0.2".parse().unwrap()),
        );
        assert_eq!(
            parse_address(Some("fd00::2"), false).unwrap(),
            Some("fd00::2".parse().unwrap()),
        );
    }
}
