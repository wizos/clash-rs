use std::{io, net::IpAddr};

use ipnet::IpNet;

use super::packet::PEER_ID_UNSET;

#[derive(Clone, Debug, Eq, PartialEq)]
pub(super) struct PushReply {
    pub prefixes: Vec<IpNet>,
    pub routes: Vec<IpNet>,
    pub dns: Vec<IpAddr>,
    pub peer_id: u32,
    pub redirect: bool,
    pub block_ipv6: bool,
}

impl PushReply {
    pub(super) fn parse(message: &str) -> io::Result<Self> {
        let message = message.trim_end_matches('\0');
        if !message.starts_with("PUSH_REPLY") {
            return Err(invalid("unexpected openvpn push message"));
        }
        let mut reply = Self {
            prefixes: Vec::new(),
            routes: Vec::new(),
            dns: Vec::new(),
            peer_id: PEER_ID_UNSET,
            redirect: false,
            block_ipv6: false,
        };
        for option in message.split(',').skip(1).map(str::trim) {
            let fields: Vec<&str> = option.split_ascii_whitespace().collect();
            match fields.as_slice() {
                ["ifconfig", address, mask_or_peer, ..] => reply
                    .prefixes
                    .push(parse_ipv4_prefix(address, mask_or_peer, true)?),
                ["ifconfig-ipv6", prefix, ..] => {
                    reply.prefixes.push(prefix.parse().map_err(|error| {
                        invalid(format!("invalid pushed ipv6 prefix: {error}"))
                    })?)
                }
                ["route", network, mask, ..] => {
                    if let Ok(route) = parse_ipv4_prefix(network, mask, false) {
                        reply.routes.push(route);
                    }
                }
                ["route-ipv6", prefix, ..] => {
                    if let Ok(route) = prefix.parse() {
                        reply.routes.push(route);
                    }
                }
                ["dhcp-option", "DNS", address, ..] => {
                    if let Ok(address) = address.parse() {
                        reply.dns.push(address);
                    }
                }
                ["peer-id", value, ..] => {
                    reply.peer_id = value
                        .parse::<u32>()
                        .ok()
                        .filter(|value| *value <= PEER_ID_UNSET)
                        .ok_or_else(|| invalid("invalid pushed openvpn peer-id"))?;
                }
                ["redirect-gateway", ..] => reply.redirect = true,
                ["block-ipv6", ..] => reply.block_ipv6 = true,
                _ => {}
            }
        }
        if reply.prefixes.is_empty() {
            return Err(invalid("openvpn push reply missing ifconfig address"));
        }
        Ok(reply)
    }
}

fn parse_ipv4_prefix(
    address: &str,
    mask_or_peer: &str,
    allow_peer: bool,
) -> io::Result<IpNet> {
    let address: std::net::Ipv4Addr = address.parse().map_err(|error| {
        invalid(format!("invalid openvpn ipv4 address: {error}"))
    })?;
    let mask: std::net::Ipv4Addr = mask_or_peer
        .parse()
        .map_err(|error| invalid(format!("invalid openvpn ipv4 mask: {error}")))?;
    let prefix = mask_size(mask)
        .or(if allow_peer { Some(32) } else { None })
        .ok_or_else(|| invalid("non-contiguous openvpn route mask"))?;
    IpNet::new(address.into(), prefix)
        .map_err(|error| invalid(format!("invalid openvpn prefix: {error}")))
}

fn mask_size(mask: std::net::Ipv4Addr) -> Option<u8> {
    let value = u32::from(mask);
    let prefix = value.leading_ones() as u8;
    (value << prefix == 0).then_some(prefix)
}

fn invalid(message: impl Into<String>) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, message.into())
}

#[cfg(test)]
mod tests {
    use super::PushReply;

    #[test]
    fn parses_mihomo_push_options() {
        let reply = PushReply::parse(
            "PUSH_REPLY,ifconfig 10.8.0.2 255.255.255.0,route 10.0.0.0 \
             255.0.0.0,dhcp-option DNS 10.8.0.1,peer-id \
             7,redirect-gateway,block-ipv6\0",
        )
        .unwrap();
        assert_eq!(reply.prefixes[0].to_string(), "10.8.0.2/24");
        assert_eq!(reply.routes[0].to_string(), "10.0.0.0/8");
        assert_eq!(reply.peer_id, 7);
        assert!(reply.redirect && reply.block_ipv6);
    }
}
