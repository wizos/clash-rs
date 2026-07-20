use crate::Error;
use std::{fmt::Display, str::FromStr};

pub enum RuleType {
    Domain {
        domain: String,
        target: String,
    },
    DomainSuffix {
        domain_suffix: String,
        target: String,
    },
    DomainRegex {
        regex: regex::Regex,
        target: String,
    },
    DomainKeyword {
        domain_keyword: String,
        target: String,
    },
    DomainWildcard {
        pattern: String,
        target: String,
    },
    GeoIP {
        target: String,
        country_code: String,
        no_resolve: bool,
        is_src: bool,
    },
    SrcGeoIP {
        target: String,
        country_code: String,
    },
    IpAsn {
        target: String,
        asn: String,
        no_resolve: bool,
        is_src: bool,
    },
    SrcIpAsn {
        target: String,
        asn: String,
    },
    GeoSite {
        target: String,
        country_code: String,
    },
    IpCidr {
        ipnet: ipnet::IpNet,
        target: String,
        no_resolve: bool,
        is_src: bool,
    },
    SrcCidr {
        ipnet: ipnet::IpNet,
        target: String,
        no_resolve: bool,
    },
    IpSuffix {
        ipnet: ipnet::IpNet,
        target: String,
        no_resolve: bool,
        is_src: bool,
    },
    SRCPort {
        target: String,
        payload: String,
        port_ranges: Vec<(u16, u16)>,
    },
    DSTPort {
        target: String,
        payload: String,
        port_ranges: Vec<(u16, u16)>,
    },
    InboundPort {
        target: String,
        payload: String,
        port_ranges: Vec<(u16, u16)>,
    },
    ProcessName {
        process_name: String,
        target: String,
    },
    ProcessPath {
        process_path: String,
        target: String,
    },
    ProcessNameRegex {
        regex: regex::Regex,
        target: String,
    },
    ProcessPathRegex {
        regex: regex::Regex,
        target: String,
    },
    ProcessNameWildcard {
        pattern: String,
        target: String,
    },
    ProcessPathWildcard {
        pattern: String,
        target: String,
    },
    InboundType {
        inbound_types: Vec<String>,
        target: String,
    },
    InboundUser {
        inbound_users: Vec<String>,
        target: String,
    },
    InboundName {
        inbound_names: Vec<String>,
        target: String,
    },
    Uid {
        payload: String,
        uid_ranges: Vec<(u32, u32)>,
        target: String,
    },
    Dscp {
        payload: String,
        dscp_ranges: Vec<(u32, u32)>,
        target: String,
    },
    RuleSet {
        rule_set: String,
        target: String,
    },
    Match {
        target: String,
    },
    Network {
        network: crate::session::Network,
        target: String,
    },
    Composite {
        operator: String,
        expression: String,
        target: String,
    },
    SubRule {
        condition: Box<RuleType>,
        payload: String,
        sub_rule: String,
    },
}

impl RuleType {
    pub fn target(&self) -> &str {
        match self {
            RuleType::Domain { target, .. } => target,
            RuleType::DomainSuffix { target, .. } => target,
            RuleType::DomainRegex { target, .. } => target,
            RuleType::DomainKeyword { target, .. } => target,
            RuleType::DomainWildcard { target, .. } => target,
            RuleType::GeoIP { target, .. } => target,
            RuleType::SrcGeoIP { target, .. } => target,
            RuleType::IpAsn { target, .. } => target,
            RuleType::SrcIpAsn { target, .. } => target,
            RuleType::GeoSite { target, .. } => target,
            RuleType::IpCidr { target, .. } => target,
            RuleType::SrcCidr { target, .. } => target,
            RuleType::IpSuffix { target, .. } => target,
            RuleType::SRCPort { target, .. } => target,
            RuleType::DSTPort { target, .. } => target,
            RuleType::InboundPort { target, .. } => target,
            RuleType::ProcessName { target, .. } => target,
            RuleType::ProcessPath { target, .. } => target,
            RuleType::ProcessNameRegex { target, .. } => target,
            RuleType::ProcessPathRegex { target, .. } => target,
            RuleType::ProcessNameWildcard { target, .. } => target,
            RuleType::ProcessPathWildcard { target, .. } => target,
            RuleType::InboundType { target, .. } => target,
            RuleType::InboundUser { target, .. } => target,
            RuleType::InboundName { target, .. } => target,
            RuleType::Uid { target, .. } => target,
            RuleType::Dscp { target, .. } => target,
            RuleType::RuleSet { target, .. } => target,
            RuleType::Match { target } => target,
            RuleType::Network { target, .. } => target,
            RuleType::Composite { target, .. } => target,
            RuleType::SubRule { sub_rule, .. } => sub_rule,
        }
    }
}

impl Display for RuleType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            RuleType::Domain { domain, target } => {
                write!(f, "DOMAIN,{domain},{target}")
            }
            RuleType::DomainRegex { regex, target } => {
                write!(f, "DOMAIN-REGEX,{regex},{target}")
            }
            RuleType::DomainSuffix { .. } => write!(f, "DOMAIN-SUFFIX"),
            RuleType::DomainKeyword { .. } => write!(f, "DOMAIN-KEYWORD"),
            RuleType::DomainWildcard { .. } => write!(f, "DOMAIN-WILDCARD"),
            RuleType::GeoIP { .. } => write!(f, "GEOIP"),
            RuleType::SrcGeoIP { .. } => write!(f, "SRC-GEOIP"),
            RuleType::IpAsn { .. } => write!(f, "IP-ASN"),
            RuleType::SrcIpAsn { .. } => write!(f, "SRC-IP-ASN"),
            RuleType::GeoSite { .. } => write!(f, "GEOSITE"),
            RuleType::IpCidr { .. } => write!(f, "IP-CIDR"),
            RuleType::SrcCidr { .. } => write!(f, "SRC-IP-CIDR"),
            RuleType::IpSuffix { is_src: true, .. } => {
                write!(f, "SRC-IP-SUFFIX")
            }
            RuleType::IpSuffix { is_src: false, .. } => write!(f, "IP-SUFFIX"),
            RuleType::SRCPort { .. } => write!(f, "SRC-PORT"),
            RuleType::DSTPort { .. } => write!(f, "DST-PORT"),
            RuleType::InboundPort { .. } => write!(f, "IN-PORT"),
            RuleType::ProcessName { .. } => write!(f, "PROCESS-NAME"),
            RuleType::ProcessPath { .. } => write!(f, "PROCESS-PATH"),
            RuleType::ProcessNameRegex { .. } => {
                write!(f, "PROCESS-NAME-REGEX")
            }
            RuleType::ProcessPathRegex { .. } => {
                write!(f, "PROCESS-PATH-REGEX")
            }
            RuleType::ProcessNameWildcard { .. } => {
                write!(f, "PROCESS-NAME-WILDCARD")
            }
            RuleType::ProcessPathWildcard { .. } => {
                write!(f, "PROCESS-PATH-WILDCARD")
            }
            RuleType::InboundType { .. } => write!(f, "IN-TYPE"),
            RuleType::InboundUser { .. } => write!(f, "IN-USER"),
            RuleType::InboundName { .. } => write!(f, "IN-NAME"),
            RuleType::Uid { .. } => write!(f, "UID"),
            RuleType::Dscp { .. } => write!(f, "DSCP"),
            RuleType::RuleSet { .. } => write!(f, "RULE-SET"),
            RuleType::Match { .. } => write!(f, "MATCH"),
            RuleType::Network { .. } => write!(f, "NETWORK"),
            RuleType::Composite { .. } => write!(f, "COMPOSITE"),
            RuleType::SubRule { .. } => write!(f, "SUB-RULE"),
        }
    }
}

impl RuleType {
    pub fn new(
        proto: &str,
        payload: &str,
        target: &str,
        params: Option<Vec<&str>>,
    ) -> Result<Self, Error> {
        match proto {
            "DOMAIN" => Ok(RuleType::Domain {
                domain: payload.to_string(),
                target: target.to_string(),
            }),
            "DOMAIN-REGEX" => Ok(RuleType::DomainRegex {
                regex: regex::Regex::new(payload)
                    .map_err(|e| Error::InvalidConfig(e.to_string()))?,
                target: target.to_string(),
            }),
            "DOMAIN-SUFFIX" => Ok(RuleType::DomainSuffix {
                domain_suffix: payload.to_string(),
                target: target.to_string(),
            }),
            "DOMAIN-KEYWORD" => Ok(RuleType::DomainKeyword {
                domain_keyword: payload.to_string(),
                target: target.to_string(),
            }),
            "DOMAIN-WILDCARD" => Ok(RuleType::DomainWildcard {
                pattern: payload.to_string(),
                target: target.to_string(),
            }),
            "GEOSITE" => Ok(RuleType::GeoSite {
                target: target.to_string(),
                country_code: payload.to_string(),
            }),
            "GEOIP" => Ok(RuleType::GeoIP {
                target: target.to_string(),
                country_code: payload.to_string(),
                no_resolve: params
                    .as_ref()
                    .is_some_and(|params| params.contains(&"no-resolve")),
                is_src: params
                    .as_ref()
                    .is_some_and(|params| params.contains(&"src")),
            }),
            "SRC-GEOIP" => Ok(RuleType::SrcGeoIP {
                target: target.to_string(),
                country_code: payload.to_string(),
            }),
            "IP-ASN" => Ok(RuleType::IpAsn {
                target: target.to_string(),
                asn: payload.to_string(),
                no_resolve: params
                    .as_ref()
                    .is_some_and(|params| params.contains(&"no-resolve")),
                is_src: params
                    .as_ref()
                    .is_some_and(|params| params.contains(&"src")),
            }),
            "SRC-IP-ASN" => Ok(RuleType::SrcIpAsn {
                target: target.to_string(),
                asn: payload.to_string(),
            }),
            "IP-CIDR" | "IP-CIDR6" => Ok(RuleType::IpCidr {
                ipnet: payload.parse()?,
                target: target.to_string(),
                no_resolve: params
                    .as_ref()
                    .is_some_and(|params| params.contains(&"no-resolve")),
                is_src: params
                    .as_ref()
                    .is_some_and(|params| params.contains(&"src")),
            }),
            "SRC-IP-CIDR" => Ok(RuleType::SrcCidr {
                ipnet: payload.parse()?,
                target: target.to_string(),
                no_resolve: true,
            }),
            "IP-SUFFIX" => Ok(RuleType::IpSuffix {
                ipnet: payload.parse()?,
                target: target.to_string(),
                no_resolve: params
                    .as_ref()
                    .is_some_and(|params| params.contains(&"no-resolve")),
                is_src: params
                    .as_ref()
                    .is_some_and(|params| params.contains(&"src")),
            }),
            "SRC-IP-SUFFIX" => Ok(RuleType::IpSuffix {
                ipnet: payload.parse()?,
                target: target.to_string(),
                no_resolve: true,
                is_src: true,
            }),
            "SRC-PORT" => Ok(RuleType::SRCPort {
                target: target.to_string(),
                payload: payload.to_string(),
                port_ranges: parse_port_ranges(payload)?,
            }),
            "DST-PORT" => Ok(RuleType::DSTPort {
                target: target.to_string(),
                payload: payload.to_string(),
                port_ranges: parse_port_ranges(payload)?,
            }),
            "IN-PORT" => Ok(RuleType::InboundPort {
                target: target.to_string(),
                payload: payload.to_string(),
                port_ranges: parse_port_ranges(payload)?,
            }),
            "PROCESS-NAME" => Ok(RuleType::ProcessName {
                process_name: payload.to_string(),
                target: target.to_string(),
            }),
            "PROCESS-PATH" => Ok(RuleType::ProcessPath {
                process_path: payload.to_string(),
                target: target.to_string(),
            }),
            "PROCESS-NAME-REGEX" => Ok(RuleType::ProcessNameRegex {
                regex: compile_process_regex(payload)?,
                target: target.to_string(),
            }),
            "PROCESS-PATH-REGEX" => Ok(RuleType::ProcessPathRegex {
                regex: compile_process_regex(payload)?,
                target: target.to_string(),
            }),
            "PROCESS-NAME-WILDCARD" => Ok(RuleType::ProcessNameWildcard {
                pattern: payload.to_string(),
                target: target.to_string(),
            }),
            "PROCESS-PATH-WILDCARD" => Ok(RuleType::ProcessPathWildcard {
                pattern: payload.to_string(),
                target: target.to_string(),
            }),
            "IN-TYPE" => Ok(RuleType::InboundType {
                inbound_types: parse_slash_separated(payload, "inbound type")?,
                target: target.to_string(),
            }),
            "IN-USER" => Ok(RuleType::InboundUser {
                inbound_users: parse_slash_separated(payload, "inbound user")?,
                target: target.to_string(),
            }),
            "IN-NAME" => Ok(RuleType::InboundName {
                inbound_names: parse_slash_separated(payload, "inbound name")?,
                target: target.to_string(),
            }),
            "UID" => Ok(RuleType::Uid {
                payload: payload.to_string(),
                uid_ranges: parse_u32_ranges(payload, u32::MAX, "uid")?,
                target: target.to_string(),
            }),
            "DSCP" => Ok(RuleType::Dscp {
                payload: payload.to_string(),
                dscp_ranges: parse_u32_ranges(payload, 63, "DSCP")?,
                target: target.to_string(),
            }),
            "RULE-SET" => Ok(RuleType::RuleSet {
                rule_set: payload.to_string(),
                target: target.to_string(),
            }),
            "MATCH" => Ok(RuleType::Match {
                target: target.to_string(),
            }),
            "NETWORK" => {
                let network = match payload {
                    "TCP" | "tcp" => crate::session::Network::Tcp,
                    "UDP" | "udp" => crate::session::Network::Udp,
                    _ => {
                        return Err(Error::InvalidConfig(format!(
                            "invalid network type: {}, expected TCP or UDP",
                            payload
                        )));
                    }
                };
                Ok(RuleType::Network {
                    network,
                    target: target.to_string(),
                })
            }
            "AND" | "OR" | "NOT" => Ok(RuleType::Composite {
                operator: proto.to_string(),
                expression: payload.to_string(),
                target: target.to_string(),
            }),
            "SUB-RULE" => Ok(RuleType::SubRule {
                condition: Box::new(parse_logic_condition(payload)?),
                payload: payload.to_string(),
                sub_rule: target.to_string(),
            }),

            _ => Err(Error::InvalidConfig(format!(
                "unsupported rule type: {proto}"
            ))),
        }
    }
}

fn compile_process_regex(payload: &str) -> Result<regex::Regex, Error> {
    regex::RegexBuilder::new(payload)
        .case_insensitive(true)
        .build()
        .map_err(|e| Error::InvalidConfig(e.to_string()))
}

fn parse_logic_condition(payload: &str) -> Result<RuleType, Error> {
    let condition = payload.trim();
    if !condition.starts_with('(') || !condition.ends_with(')') {
        return Err(Error::InvalidConfig(format!(
            "logic condition must be wrapped in parentheses: {payload}"
        )));
    }
    let inner = condition[1..condition.len() - 1].trim();
    let (proto, rest) = inner.split_once(',').ok_or_else(|| {
        Error::InvalidConfig(format!("invalid logic condition: {payload}"))
    })?;
    let proto = proto.trim();
    let rest = rest.trim();

    if matches!(proto, "MATCH" | "SUB-RULE") {
        return Err(Error::InvalidConfig(format!(
            "unsupported rule type in logic condition: {proto}"
        )));
    }
    if matches!(proto, "AND" | "OR" | "NOT") {
        return Ok(RuleType::Composite {
            operator: proto.to_string(),
            expression: rest.to_string(),
            target: String::new(),
        });
    }

    let mut parts = rest.split(',').map(str::trim);
    let rule_payload = parts.next().unwrap_or_default();
    let params = parts.collect::<Vec<_>>();
    RuleType::new(
        proto,
        rule_payload,
        "",
        (!params.is_empty()).then_some(params),
    )
}

fn parse_port_ranges(payload: &str) -> Result<Vec<(u16, u16)>, Error> {
    let ranges = payload
        .split('/')
        .map(str::trim)
        .map(|value| {
            let (start, end) = match value.split_once('-') {
                Some((start, end)) => (start, end),
                None => (value, value),
            };
            let start = start.parse::<u16>().map_err(|_| {
                Error::InvalidConfig(format!("invalid port: {value}"))
            })?;
            let end = end.parse::<u16>().map_err(|_| {
                Error::InvalidConfig(format!("invalid port: {value}"))
            })?;
            if start > end {
                return Err(Error::InvalidConfig(format!(
                    "invalid port range: {value}"
                )));
            }
            Ok((start, end))
        })
        .collect::<Result<Vec<_>, Error>>()?;

    if ranges.is_empty() {
        return Err(Error::InvalidConfig("invalid empty port range".to_string()));
    }

    Ok(ranges)
}

fn parse_u32_ranges(
    payload: &str,
    maximum: u32,
    kind: &str,
) -> Result<Vec<(u32, u32)>, Error> {
    let ranges = payload
        .split('/')
        .map(str::trim)
        .map(|value| {
            let (start, end) = match value.split_once('-') {
                Some((start, end)) => (start, end),
                None => (value, value),
            };
            let start = start.parse::<u32>().map_err(|_| {
                Error::InvalidConfig(format!("invalid {kind}: {value}"))
            })?;
            let end = end.parse::<u32>().map_err(|_| {
                Error::InvalidConfig(format!("invalid {kind}: {value}"))
            })?;
            if start > end || end > maximum {
                return Err(Error::InvalidConfig(format!(
                    "invalid {kind} range: {value}"
                )));
            }
            Ok((start, end))
        })
        .collect::<Result<Vec<_>, Error>>()?;

    if ranges.is_empty() {
        return Err(Error::InvalidConfig(format!("invalid empty {kind} range")));
    }

    Ok(ranges)
}

fn parse_slash_separated(payload: &str, kind: &str) -> Result<Vec<String>, Error> {
    let values = payload
        .split('/')
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .map(str::to_string)
        .collect::<Vec<_>>();

    if values.is_empty() {
        return Err(Error::InvalidConfig(format!("invalid {kind}: {payload}")));
    }

    Ok(values)
}

impl TryFrom<String> for RuleType {
    type Error = crate::Error;

    fn try_from(line: String) -> Result<Self, Self::Error> {
        // Only logic rules use the special parenthesized parser. Regular
        // expressions may legitimately contain parentheses as payload.
        let proto = line.split_once(',').map(|(proto, _)| proto.trim());
        if matches!(proto, Some("AND" | "OR" | "NOT" | "SUB-RULE")) {
            // For composite rules: OPERATOR,((expression)),TARGET
            // Split on first and last comma
            let first_comma = line.find(',').ok_or_else(|| {
                Error::InvalidConfig(format!("invalid rule line (no comma): {line}"))
            })?;

            let last_comma = line.rfind(',').ok_or_else(|| {
                Error::InvalidConfig(format!("invalid rule line (no comma): {line}"))
            })?;

            if first_comma == last_comma {
                return Err(Error::InvalidConfig(format!(
                    "composite rule needs at least 2 commas: {line}"
                )));
            }

            let operator = line[..first_comma].trim();
            let expression = line[first_comma + 1..last_comma].trim();
            let target = line[last_comma + 1..].trim();

            return RuleType::new(operator, expression, target, None);
        }

        // For non-composite rules, use simple split
        let parts = line.split(',').map(str::trim).collect::<Vec<&str>>();

        match parts.as_slice() {
            [proto, target] => RuleType::new(proto, "", target, None),
            [proto, payload, target] => RuleType::new(proto, payload, target, None),
            [proto, payload, target, params @ ..] => {
                RuleType::new(proto, payload, target, Some(params.to_vec()))
            }
            _ => Err(Error::InvalidConfig(format!("invalid rule line: {line}"))),
        }
    }
}

impl FromStr for RuleType {
    type Err = Error;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        s.to_string().try_into()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_network_rule_parsing() {
        // Test TCP network rule
        let rule = RuleType::try_from("NETWORK,TCP,PROXY".to_string()).unwrap();
        match rule {
            RuleType::Network { network, target } => {
                assert_eq!(network, crate::session::Network::Tcp);
                assert_eq!(target, "PROXY");
            }
            _ => panic!("Expected Network rule"),
        }

        // Test UDP network rule
        let rule = RuleType::try_from("NETWORK,UDP,PROXY".to_string()).unwrap();
        match rule {
            RuleType::Network { network, target } => {
                assert_eq!(network, crate::session::Network::Udp);
                assert_eq!(target, "PROXY");
            }
            _ => panic!("Expected Network rule"),
        }

        // Test lowercase network types
        let rule = RuleType::try_from("NETWORK,tcp,PROXY".to_string()).unwrap();
        match rule {
            RuleType::Network { network, target } => {
                assert_eq!(network, crate::session::Network::Tcp);
                assert_eq!(target, "PROXY");
            }
            _ => panic!("Expected Network rule"),
        }

        // Test invalid network type
        let rule = RuleType::try_from("NETWORK,INVALID,PROXY".to_string());
        assert!(rule.is_err());
    }

    #[test]
    fn test_mihomo_compat_rule_parsing() {
        assert!(matches!(
            RuleType::try_from("SRC-GEOIP,cn,DIRECT".to_string()).unwrap(),
            RuleType::SrcGeoIP { country_code, target }
                if country_code == "cn" && target == "DIRECT"
        ));

        assert!(matches!(
            RuleType::try_from("DST-PORT,80/443/1000-2000,PROXY".to_string())
                .unwrap(),
            RuleType::DSTPort { port_ranges, .. }
                if port_ranges == [(80, 80), (443, 443), (1000, 2000)]
        ));

        assert!(matches!(
            RuleType::try_from("DOMAIN-WILDCARD,*.google.com,PROXY".to_string())
                .unwrap(),
            RuleType::DomainWildcard { pattern, target }
                if pattern == "*.google.com" && target == "PROXY"
        ));

        assert!(matches!(
            RuleType::try_from("IP-SUFFIX,8.8.8.8/24,PROXY".to_string()).unwrap(),
            RuleType::IpSuffix { ipnet, target, no_resolve: false, is_src: false }
                if ipnet.addr().to_string() == "8.8.8.8" && target == "PROXY"
        ));

        assert!(matches!(
            RuleType::try_from("PROCESS-NAME-REGEX,(?i)Telegram,PROXY".to_string())
                .unwrap(),
            RuleType::ProcessNameRegex { regex, target }
                if regex.as_str() == "(?i)Telegram" && target == "PROXY"
        ));

        assert!(matches!(
            RuleType::try_from("PROCESS-PATH-REGEX,.*bin/wget,PROXY".to_string())
                .unwrap(),
            RuleType::ProcessPathRegex { regex, target }
                if regex.as_str() == ".*bin/wget" && target == "PROXY"
        ));

        assert!(matches!(
            RuleType::try_from("IN-TYPE,SOCKS/HTTP,PROXY".to_string()).unwrap(),
            RuleType::InboundType { inbound_types, target }
                if inbound_types == ["SOCKS", "HTTP"] && target == "PROXY"
        ));

        assert!(matches!(
            RuleType::try_from("IN-USER,alice/bob,DIRECT".to_string()).unwrap(),
            RuleType::InboundUser { inbound_users, target }
                if inbound_users == ["alice", "bob"] && target == "DIRECT"
        ));

        assert!(matches!(
            RuleType::try_from("IN-PORT,7890/8000-8100,PROXY".to_string()).unwrap(),
            RuleType::InboundPort { port_ranges, target, .. }
                if port_ranges == [(7890, 7890), (8000, 8100)] && target == "PROXY"
        ));
        assert!(matches!(
            RuleType::try_from("IN-NAME,DEFAULT-TUN/mixed-in,PROXY".to_string())
                .unwrap(),
            RuleType::InboundName { inbound_names, target }
                if inbound_names == ["DEFAULT-TUN", "mixed-in"] && target == "PROXY"
        ));
        assert!(matches!(
            RuleType::try_from("UID,1000/10000-19999,DIRECT".to_string()).unwrap(),
            RuleType::Uid { uid_ranges, target, .. }
                if uid_ranges == [(1000, 1000), (10000, 19999)] && target == "DIRECT"
        ));
        assert!(matches!(
            RuleType::try_from("DSCP,0/8-16,PROXY".to_string()).unwrap(),
            RuleType::Dscp { dscp_ranges, target, .. }
                if dscp_ranges == [(0, 0), (8, 16)] && target == "PROXY"
        ));
        assert!(RuleType::try_from("DSCP,64,PROXY".to_string()).is_err());
        assert!(matches!(
            RuleType::try_from(
                "SUB-RULE,(OR,((NETWORK,TCP),(NETWORK,UDP))),network-rules"
                    .to_string()
            )
            .unwrap(),
            RuleType::SubRule { condition, sub_rule, .. }
                if matches!(*condition, RuleType::Composite { ref operator, .. } if operator == "OR")
                    && sub_rule == "network-rules"
        ));
    }
}
