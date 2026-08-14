use crate::{
    Error,
    app::{
        dns,
        net::Interface,
        remote_content_manager::providers::rule_provider::{
            RuleSetBehavior, RuleSetFormat,
        },
    },
    common::auth,
    config::{
        def::{self, LogLevel, RunMode},
        internal::{proxy::OutboundProxy, rule::RuleType},
    },
};
use anyhow::anyhow;
use hyper::Uri;
use ipnet::{IpNet, Ipv4Net, Ipv6Net};
use serde::{Deserialize, Serialize};
use std::{
    collections::{HashMap, HashSet},
    net::{IpAddr, Ipv4Addr, Ipv6Addr},
    str::FromStr,
};

use super::{
    listener::{InboundOpts, InboundProviderDef},
    proxy::OutboundProxyProviderDef,
};

pub struct Config {
    pub general: General,
    pub dns: dns::Config,
    pub tun: TunConfig,
    pub experimental: Option<def::Experimental>,
    pub profile: Profile,
    pub rules: Vec<RuleType>,
    pub sub_rules: HashMap<String, Vec<RuleType>>,
    pub rule_providers: HashMap<String, RuleProviderDef>,
    pub users: Vec<auth::User>,
    /// a list maintaining the order from the config file
    pub proxy_names: Vec<String>,
    pub proxies: HashMap<String, OutboundProxy>,
    pub proxy_groups: HashMap<String, OutboundProxy>,
    pub proxy_providers: HashMap<String, OutboundProxyProviderDef>,
    pub listeners: HashSet<InboundOpts>,
    pub inbound_providers: HashMap<String, InboundProviderDef>,
}

impl Config {
    pub fn validate(self) -> Result<Self, crate::Error> {
        for r in &self.rules {
            self.validate_rule_target(r)?;
        }
        for rules in self.sub_rules.values() {
            for rule in rules {
                self.validate_rule_target(rule)?;
            }
        }
        for name in self.sub_rules.keys() {
            self.validate_sub_rule_cycle(name, &mut Vec::new())?;
        }
        for group in self.proxy_groups.values() {
            let OutboundProxy::ProxyGroup(group) = group else {
                continue;
            };

            let has_proxies = group.proxies().is_some_and(|items| !items.is_empty());
            let has_providers =
                group.use_providers().is_some_and(|items| !items.is_empty());
            if !has_proxies && !has_providers {
                return Err(Error::InvalidConfig(format!(
                    "proxy group `{}` has no proxies or proxy providers",
                    group.name()
                )));
            }

            let empty_fallback = &group.selection().empty_fallback;
            if !self.proxies.contains_key(empty_fallback) {
                return Err(Error::InvalidConfig(format!(
                    "empty fallback proxy `{empty_fallback}` referenced by proxy group `{}` was not found",
                    group.name()
                )));
            }

            if let Some(proxies) = group.proxies() {
                for proxy in proxies {
                    if !self.proxies.contains_key(proxy)
                        && !self.proxy_groups.contains_key(proxy)
                    {
                        return Err(Error::InvalidConfig(format!(
                            "proxy `{proxy}` referenced by proxy group `{}` was \
                             not found",
                            group.name()
                        )));
                    }
                }
            }

            if let Some(providers) = group.use_providers() {
                for provider in providers {
                    if !self.proxy_providers.contains_key(provider) {
                        return Err(Error::InvalidConfig(format!(
                            "proxy provider `{provider}` referenced by proxy group \
                             `{}` was not found",
                            group.name()
                        )));
                    }
                }
            }
        }
        for name in self.proxy_groups.keys() {
            self.validate_proxy_group_cycle(name, &mut Vec::new())?;
        }
        for (name, provider) in &self.proxy_providers {
            if let OutboundProxyProviderDef::Http(provider) = provider {
                provider.url.parse::<Uri>().map_err(|error| {
                    Error::InvalidConfig(format!(
                        "invalid URL for proxy provider `{name}`: {error}"
                    ))
                })?;
                if let Some(proxy) = provider.proxy.as_deref()
                    && !self.proxies.contains_key(proxy)
                    && !self.proxy_groups.contains_key(proxy)
                {
                    return Err(Error::InvalidConfig(format!(
                        "proxy `{proxy}` referenced by proxy provider `{name}` was not found"
                    )));
                }
                if provider.proxy.is_some()
                    && !self.provider_has_bootstrap_path(name, &mut HashSet::new())
                {
                    return Err(Error::InvalidConfig(format!(
                        "provider bootstrap cycle: `{name}` has no independent outbound"
                    )));
                }
            }
        }
        for (name, provider) in &self.rule_providers {
            if let RuleProviderDef::Http(provider) = provider {
                provider.url.parse::<Uri>().map_err(|error| {
                    Error::InvalidConfig(format!(
                        "invalid URL for rule provider `{name}`: {error}"
                    ))
                })?;
                if let Some(proxy) = provider.proxy.as_deref()
                    && !self.proxies.contains_key(proxy)
                    && !self.proxy_groups.contains_key(proxy)
                {
                    return Err(Error::InvalidConfig(format!(
                        "proxy `{proxy}` referenced by rule provider `{name}` was not found"
                    )));
                }
            }
        }
        // Check for duplicate AnyTLS user passwords
        for opts in &self.listeners {
            if let crate::config::internal::listener::InboundOpts::Anytls {
                common_opts,
                users,
                ..
            } = opts
            {
                let mut seen = std::collections::HashSet::new();
                for u in users {
                    if !seen.insert(u.password.as_str()) {
                        return Err(Error::InvalidConfig(format!(
                            "anytls inbound '{}': duplicate user password",
                            common_opts.name
                        )));
                    }
                }
            }
        }
        Ok(self)
    }

    fn provider_has_bootstrap_path(
        &self,
        name: &str,
        visiting: &mut HashSet<String>,
    ) -> bool {
        if !visiting.insert(format!("provider:{name}")) {
            return false;
        }
        let result = match self.proxy_providers.get(name) {
            Some(OutboundProxyProviderDef::File(_)) => true,
            Some(OutboundProxyProviderDef::Http(provider)) => provider
                .proxy
                .as_deref()
                .is_none_or(|proxy| self.proxy_has_bootstrap_path(proxy, visiting)),
            None => false,
        };
        visiting.remove(&format!("provider:{name}"));
        result
    }

    fn proxy_has_bootstrap_path(
        &self,
        name: &str,
        visiting: &mut HashSet<String>,
    ) -> bool {
        if self.proxies.contains_key(name) {
            return true;
        }
        if !visiting.insert(format!("group:{name}")) {
            return false;
        }
        let result = self
            .proxy_groups
            .get(name)
            .and_then(|proxy| match proxy {
                OutboundProxy::ProxyGroup(group) => Some(group),
                _ => None,
            })
            .is_some_and(|group| {
                group
                    .proxies()
                    .into_iter()
                    .flatten()
                    .any(|proxy| self.proxy_has_bootstrap_path(proxy, visiting))
                    || group.use_providers().into_iter().flatten().any(|provider| {
                        self.provider_has_bootstrap_path(provider, visiting)
                    })
            });
        visiting.remove(&format!("group:{name}"));
        result
    }

    fn validate_rule_target(&self, rule: &RuleType) -> Result<(), crate::Error> {
        if let RuleType::RuleSet { rule_set, .. } = rule
            && !self.rule_providers.contains_key(rule_set)
        {
            return Err(Error::InvalidConfig(format!(
                "rule provider `{rule_set}` referenced in a rule was not found"
            )));
        }
        if let RuleType::SubRule { sub_rule, .. } = rule {
            if !self.sub_rules.contains_key(sub_rule) {
                return Err(Error::InvalidConfig(format!(
                    "sub-rule `{sub_rule}` referenced in a rule was not found"
                )));
            }
            return Ok(());
        }
        if !self.proxies.contains_key(rule.target())
            && !self.proxy_groups.contains_key(rule.target())
        {
            return Err(Error::InvalidConfig(format!(
                "proxy `{}` referenced in a rule was not found",
                rule.target()
            )));
        }
        Ok(())
    }

    fn validate_sub_rule_cycle(
        &self,
        name: &str,
        path: &mut Vec<String>,
    ) -> Result<(), crate::Error> {
        if path.iter().any(|item| item == name) {
            path.push(name.to_string());
            return Err(Error::InvalidConfig(format!(
                "sub-rule circular reference: {}",
                path.join(" -> ")
            )));
        }

        path.push(name.to_string());
        if let Some(rules) = self.sub_rules.get(name) {
            for rule in rules {
                if let RuleType::SubRule { sub_rule, .. } = rule {
                    self.validate_sub_rule_cycle(sub_rule, path)?;
                }
            }
        }
        path.pop();
        Ok(())
    }

    fn validate_proxy_group_cycle(
        &self,
        name: &str,
        path: &mut Vec<String>,
    ) -> Result<(), crate::Error> {
        if path.iter().any(|item| item == name) {
            path.push(name.to_string());
            return Err(Error::InvalidConfig(format!(
                "proxy group circular reference: {}",
                path.join(" -> ")
            )));
        }

        path.push(name.to_string());
        if let Some(OutboundProxy::ProxyGroup(group)) = self.proxy_groups.get(name)
            && let Some(proxies) = group.proxies()
        {
            for proxy in proxies {
                if self.proxy_groups.contains_key(proxy) {
                    self.validate_proxy_group_cycle(proxy, path)?;
                }
            }
        }
        path.pop();
        Ok(())
    }
}

pub struct General {
    pub authentication: Vec<String>,
    pub bind_address: BindAddress,
    pub controller: Controller,
    pub mode: RunMode,
    pub log_level: LogLevel,
    pub global_ua: http::HeaderValue,
    pub ipv6: bool,
    pub interface: Option<Interface>,
    pub routing_mask: Option<u32>,
    pub mmdb: Option<String>,
    pub mmdb_download_url: Option<String>,
    pub asn_mmdb: Option<String>,
    pub asn_mmdb_download_url: Option<String>,

    pub geosite: Option<String>,
    pub geosite_download_url: Option<String>,

    pub unified_delay: bool,
    pub tcp_concurrent: bool,
    pub find_process_mode: crate::config::def::FindProcessMode,
    pub sniffer: Option<crate::config::def::SnifferConfig>,
}

pub struct Profile {
    pub store_selected: bool,
    pub store_smart_stats: bool,
    // this is read to dns config directly
    // store_fake_ip: bool,
}

#[derive(Default, Clone)]
pub struct TunConfig {
    pub enable: bool,
    pub device_id: String,
    pub route_all: bool,
    pub routes: Vec<IpNet>,
    pub gateway: Ipv4Net,
    pub gateway_v6: Option<Ipv6Net>,
    pub mtu: Option<u16>,
    pub so_mark: Option<u32>,
    pub route_table: u32,
    pub dns_hijack: bool,
    pub dns_hijack_targets: Vec<IpAddr>,
    pub auto_detect_interface: bool,
}

#[derive(Serialize, Clone, Debug, Copy, PartialEq, Hash, Eq)]
#[serde(transparent)]
pub struct BindAddress(pub IpAddr);
impl BindAddress {
    pub fn all_v4() -> Self {
        Self(IpAddr::V4(Ipv4Addr::UNSPECIFIED))
    }

    pub fn dual_stack() -> Self {
        Self(IpAddr::V6(Ipv6Addr::UNSPECIFIED))
    }

    pub fn local() -> Self {
        Self(IpAddr::V4(Ipv4Addr::LOCALHOST))
    }

    pub fn is_localhost(&self) -> bool {
        match self.0 {
            IpAddr::V4(ip) => ip.is_loopback(),
            IpAddr::V6(ip) => ip.is_loopback(),
        }
    }
}
impl Default for BindAddress {
    fn default() -> Self {
        Self::all_v4()
    }
}

impl<'de> Deserialize<'de> for BindAddress {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let str = String::deserialize(deserializer)?;
        match str.as_str() {
            "*" => Ok(Self(IpAddr::V4(Ipv4Addr::UNSPECIFIED))),
            "localhost" => Ok(Self(IpAddr::from([127, 0, 0, 1]))),
            "[::]" | "::" => Ok(Self(IpAddr::V6(Ipv6Addr::UNSPECIFIED))),
            _ => {
                if let Ok(ip) = str.parse::<IpAddr>() {
                    Ok(Self(ip))
                } else {
                    Err(serde::de::Error::custom(format!(
                        "Invalid BindAddress value {str}"
                    )))
                }
            }
        }
    }
}

impl FromStr for BindAddress {
    type Err = anyhow::Error;

    fn from_str(str: &str) -> Result<Self, Self::Err> {
        match str {
            "*" => Ok(Self(IpAddr::V4(Ipv4Addr::UNSPECIFIED))),
            "localhost" => Ok(Self(IpAddr::from([127, 0, 0, 1]))),
            "[::]" | "::" => Ok(Self(IpAddr::V6(Ipv6Addr::UNSPECIFIED))),
            _ => {
                if let Ok(ip) = str.parse::<IpAddr>() {
                    Ok(Self(ip))
                } else {
                    Err(anyhow!("Invalid BindAddress value {str}"))
                }
            }
        }
    }
}

#[derive(Serialize, Deserialize, Default, Clone)]
pub struct Controller {
    pub external_controller: Option<String>,
    pub external_controller_ipc: Option<String>,
    pub external_ui: Option<String>,
    pub external_ui_download_url: Option<String>,
    pub secret: Option<String>,
    pub cors_allow_origins: Option<Vec<String>>,
}

#[derive(Serialize, Deserialize)]
#[serde(tag = "type")]
#[serde(rename_all = "kebab-case")]
pub enum RuleProviderDef {
    Http(HttpRuleProvider),
    File(FileRuleProvider),
    Inline(InlineRuleProvider),
}

#[derive(Serialize, Deserialize)]
pub struct HttpRuleProvider {
    pub url: String,
    pub proxy: Option<String>,
    pub interval: u64,
    pub behavior: RuleSetBehavior,
    pub path: String,
    #[serde(default)]
    pub header: HashMap<String, super::proxy::StringList>,
    pub format: Option<RuleSetFormat>,
    #[serde(alias = "payload")]
    pub inline_rules: Option<Vec<String>>,
}

#[derive(Serialize, Deserialize)]
pub struct FileRuleProvider {
    pub path: String,
    pub interval: Option<u64>,
    pub behavior: RuleSetBehavior,
    pub format: Option<RuleSetFormat>,
    #[serde(alias = "payload")]
    pub inline_rules: Option<Vec<String>>,
}

#[derive(Serialize, Deserialize)]
pub struct InlineRuleProvider {
    pub path: String,
    pub behavior: RuleSetBehavior,
    #[serde(alias = "payload")]
    pub inline_rules: Vec<String>,
}

#[cfg(test)]
mod validation_tests {
    use crate::{
        Config as SourceConfig,
        config::internal::{
            config::RuleProviderDef,
            proxy::{
                OutboundProxy, OutboundProxyProviderDef, PROXY_COMPATIBLE,
                PROXY_REJECT,
            },
        },
    };

    fn parse_error(yaml: &str) -> String {
        SourceConfig::Str(yaml.to_owned())
            .try_parse()
            .err()
            .expect("configuration unexpectedly validated")
            .to_string()
    }

    #[test]
    fn rejects_missing_proxy_group_member() {
        let error = parse_error(
            r#"
proxy-groups:
  - name: broken
    type: select
    proxies: [missing]
rules:
  - MATCH,broken
"#,
        );
        assert!(error.contains("missing"), "unexpected error: {error}");
    }

    #[test]
    fn rejects_missing_proxy_provider_reference() {
        let error = parse_error(
            r#"
proxy-groups:
  - name: broken
    type: select
    use: [missing-provider]
rules:
  - MATCH,broken
"#,
        );
        assert!(
            error.contains("missing-provider"),
            "unexpected error: {error}"
        );
    }

    #[test]
    fn rejects_proxy_group_cycle() {
        let error = parse_error(
            r#"
proxy-groups:
  - name: group-a
    type: select
    proxies: [group-b]
  - name: group-b
    type: select
    proxies: [group-a]
rules:
  - MATCH,group-a
"#,
        );
        assert!(
            error.contains("circular reference"),
            "unexpected error: {error}"
        );
    }

    #[test]
    fn rejects_proxy_provider_bootstrap_cycle() {
        let error = parse_error(
            r#"
proxy-providers:
  remote:
    type: http
    url: https://example.com/proxies.yaml
    proxy: bootstrap
    path: ./remote.yaml
    interval: 3600
proxy-groups:
  - name: bootstrap
    type: select
    use: [remote]
rules:
  - MATCH,bootstrap
"#,
        );
        assert!(error.contains("provider bootstrap cycle"), "{error}");
    }

    #[test]
    fn keeps_mihomo_rule_provider_proxy() {
        let config = SourceConfig::Str(
            r#"
rule-providers:
  remote:
    type: http
    url: https://example.com/rules.yaml
    proxy: DIRECT
    behavior: domain
rules:
  - RULE-SET,remote,DIRECT
  - MATCH,DIRECT
"#
            .to_owned(),
        )
        .try_parse()
        .expect("rule-provider proxy should validate");
        let RuleProviderDef::Http(provider) = &config.rule_providers["remote"]
        else {
            panic!("expected HTTP rule provider");
        };
        assert_eq!(provider.proxy.as_deref(), Some("DIRECT"));
    }

    #[test]
    fn keeps_global_user_agent_and_explicit_provider_headers() {
        let config = SourceConfig::Str(
            r#"
global-ua: Viaport/test
proxy-providers:
  proxies:
    type: http
    url: https://example.com/proxies.yaml
    path: ./proxies.yaml
    interval: 3600
    header:
      User-Agent: Proxy/test
rule-providers:
  rules:
    type: http
    url: https://example.com/rules.yaml
    behavior: domain
    header:
      User-Agent: Rule/test
rules:
  - RULE-SET,rules,DIRECT
  - MATCH,DIRECT
"#
            .to_owned(),
        )
        .try_parse()
        .expect("global and provider user agents should parse");

        assert_eq!(config.general.global_ua, "Viaport/test");
        let OutboundProxyProviderDef::Http(proxy_provider) =
            &config.proxy_providers["proxies"]
        else {
            panic!("expected HTTP proxy provider");
        };
        assert_eq!(proxy_provider.header["User-Agent"].to_vec(), ["Proxy/test"]);
        let RuleProviderDef::Http(rule_provider) = &config.rule_providers["rules"]
        else {
            panic!("expected HTTP rule provider");
        };
        assert_eq!(rule_provider.header["User-Agent"].to_vec(), ["Rule/test"]);
    }

    #[test]
    fn rejects_missing_rule_provider_reference() {
        let error = parse_error(
            r#"
rules:
  - RULE-SET,missing-provider,DIRECT
"#,
        );
        assert!(
            error.contains("missing-provider"),
            "unexpected error: {error}"
        );
    }

    #[test]
    fn expands_mihomo_include_all_proxy_groups() {
        let config = SourceConfig::Str(
            r#"
proxies:
  - name: Hong Kong 01 🇭🇰
    type: socks5
    server: 127.0.0.1
    port: 1080
  - name: Tokyo 01 🇯🇵
    type: socks5
    server: 127.0.0.1
    port: 1081
proxy-groups:
  - name: Hong Kong
    type: select
    include-all: true
    filter: 🇭🇰
rules:
  - MATCH,Hong Kong
"#
            .to_owned(),
        )
        .try_parse()
        .expect("include-all group should validate");

        let OutboundProxy::ProxyGroup(group) = &config.proxy_groups["Hong Kong"]
        else {
            panic!("expected proxy group");
        };
        assert_eq!(group.proxies().unwrap(), &["Hong Kong 01 🇭🇰"]);
    }

    #[test]
    fn empty_mihomo_include_all_group_uses_compatible_fallback() {
        let config = SourceConfig::Str(
            r#"
proxies:
  - name: Tokyo
    type: socks5
    server: 127.0.0.1
    port: 1080
proxy-groups:
  - name: Hong Kong
    type: select
    include-all: true
    filter: Hong Kong
rules:
  - MATCH,Hong Kong
"#
            .to_owned(),
        )
        .try_parse()
        .expect("dynamic empty group should use COMPATIBLE");

        let OutboundProxy::ProxyGroup(group) = &config.proxy_groups["Hong Kong"]
        else {
            panic!("expected proxy group");
        };
        assert_eq!(group.proxies().unwrap(), &[PROXY_COMPATIBLE]);
    }

    #[test]
    fn empty_mihomo_include_all_group_honors_custom_fallback() {
        let config = SourceConfig::Str(
            r#"
proxy-groups:
  - name: Empty
    type: select
    include-all-proxies: true
    filter: never-matches
    empty-fallback: REJECT
rules:
  - MATCH,Empty
"#
            .to_owned(),
        )
        .try_parse()
        .expect("custom empty fallback should validate");

        let OutboundProxy::ProxyGroup(group) = &config.proxy_groups["Empty"] else {
            panic!("expected proxy group");
        };
        assert_eq!(group.proxies().unwrap(), &[PROXY_REJECT]);
    }

    #[test]
    fn empty_include_all_providers_group_uses_fallback() {
        let config = SourceConfig::Str(
            r#"
proxy-groups:
  - name: Empty
    type: select
    include-all-providers: true
rules:
  - MATCH,Empty
"#
            .to_owned(),
        )
        .try_parse()
        .expect("empty provider expansion should use COMPATIBLE");

        let OutboundProxy::ProxyGroup(group) = &config.proxy_groups["Empty"] else {
            panic!("expected proxy group");
        };
        assert_eq!(group.proxies().unwrap(), &[PROXY_COMPATIBLE]);
    }

    #[test]
    fn rejects_plain_empty_proxy_group() {
        let error = parse_error(
            r#"
proxy-groups:
  - name: Empty
    type: select
rules:
  - MATCH,Empty
"#,
        );
        assert!(
            error.contains("has no proxies or proxy providers"),
            "{error}"
        );
    }

    #[test]
    fn rejects_proxy_group_as_empty_fallback() {
        let error = parse_error(
            r#"
proxy-groups:
  - name: Other
    type: select
    proxies: [DIRECT]
  - name: Empty
    type: select
    include-all-proxies: true
    filter: never-matches
    empty-fallback: Other
rules:
  - MATCH,Empty
"#,
        );
        assert!(error.contains("empty fallback proxy `Other`"), "{error}");
    }

    #[test]
    fn geox_urls_enable_mihomo_default_database_paths() {
        let config = SourceConfig::Str(
            r#"
geox-url:
  mmdb: https://example.com/Country.mmdb
  asn: https://example.com/ASN.mmdb
  geosite: https://example.com/GEOSITE.dat
rules:
  - MATCH,DIRECT
"#
            .to_owned(),
        )
        .try_parse()
        .unwrap();

        assert_eq!(config.general.mmdb.as_deref(), Some("Country.mmdb"));
        assert_eq!(config.general.asn_mmdb.as_deref(), Some("ASN.mmdb"));
        assert_eq!(config.general.geosite.as_deref(), Some("GEOSITE.dat"));
    }
}

#[cfg(test)]
mod tests {
    use crate::config::{def, internal::convert::convert, listener::InboundOpts};
    #[test]
    fn from_def_config() {
        let cfg = r#"
        port: 9090
        mixed-port: "9091"
        "#;
        let c = cfg.parse::<def::Config>().expect("should parse");
        assert_eq!(c.port.map(|x| x.into()), Some(9090));
        assert_eq!(c.mixed_port.map(|x| x.into()), Some(9091));
        let cc = convert(c).expect("should convert");

        assert!(cc.listeners.iter().any(|listener| match listener {
            InboundOpts::Http { common_opts, .. } => common_opts.port == 9090,
            _ => false,
        }));
        assert!(cc.listeners.iter().any(|listener| match listener {
            InboundOpts::Mixed { common_opts, .. } => common_opts.port == 9091,
            _ => false,
        }));
    }
}
