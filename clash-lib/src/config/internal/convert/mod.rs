use std::collections::HashMap;

use serde::{Deserialize, de::value::MapDeserializer};
use serde_yaml::Value;
use tracing::warn;

use crate::{
    Error,
    app::sniffer::Sniffer,
    common::auth,
    config::{
        def,
        internal::{
            proxy::{OutboundProxy, PROXY_DIRECT, PROXY_REJECT},
            rule::RuleType,
        },
        proxy::{OutboundDirect, OutboundProxyProtocol, OutboundReject},
    },
};

mod general;
mod listener;
mod proxy_group;
mod rule_provider;
mod tun;

use super::{
    config::{self, Profile},
    proxy::{OutboundGroupProtocol, map_serde_error},
};

impl TryFrom<def::Config> for config::Config {
    type Error = crate::Error;

    fn try_from(value: def::Config) -> Result<Self, Self::Error> {
        convert(value)
    }
}

pub(super) fn convert(mut c: def::Config) -> Result<config::Config, crate::Error> {
    let mut proxy_names =
        vec![String::from(PROXY_DIRECT), String::from(PROXY_REJECT)];
    let mut all_proxy_names = c
        .proxy
        .as_ref()
        .map(|proxies| {
            proxies
                .iter()
                .map(|proxy| proxy.name().to_owned())
                .collect::<Vec<_>>()
        })
        .unwrap_or_default();
    all_proxy_names.sort();
    let proxy_providers = c
        .proxy_provider
        .take()
        .unwrap_or_default()
        .into_iter()
        .map(|(name, mut provider)| {
            provider.set_name(name.clone());
            (name, provider)
        })
        .collect::<HashMap<_, _>>();
    let mut all_provider_names = proxy_providers.keys().cloned().collect::<Vec<_>>();
    all_provider_names.sort();

    if c.allow_lan.unwrap_or_default() && c.bind_address.is_localhost() {
        warn!(
            "allow-lan is set to true, but bind-address is set to localhost. This \
             will not allow any connections from the local network."
        );
    }
    if let Some(tun) = &mut c.tun
        && tun.so_mark.is_none()
    {
        tun.so_mark = c.routing_mark;
    }
    Sniffer::validate_config(c.sniffer.as_ref())?;
    let rules = parse_rules(c.rule.take().unwrap_or_default())?;
    let sub_rules = c
        .sub_rules
        .take()
        .unwrap_or_default()
        .into_iter()
        .map(|(name, rules)| {
            if name.trim().is_empty() {
                return Err(Error::InvalidConfig(
                    "sub-rule name is empty".to_string(),
                ));
            }
            Ok((name, parse_rules(rules)?))
        })
        .collect::<Result<HashMap<_, _>, Error>>()?;

    config::Config {
        general: general::convert(&c)?,
        dns: (&c).try_into()?,
        experimental: c.experimental.take(),
        tun: tun::convert(c.tun.take())?,
        profile: Profile {
            store_selected: c.profile.store_selected,
            store_smart_stats: c.profile.store_smart_stats,
        },
        rules,
        sub_rules,
        rule_providers: rule_provider::convert(c.rule_provider.take()),
        users: c
            .authentication
            .clone()
            .into_iter()
            .map(|u| {
                let mut parts = u.splitn(2, ':');
                let username = parts.next().unwrap().to_string();
                let password = parts.next().unwrap_or("").to_string();
                auth::User::new(username, password)
            })
            .collect(),
        proxies: c.proxy.take().unwrap_or_default().into_iter().try_fold(
            HashMap::from([
                (
                    String::from(PROXY_DIRECT),
                    OutboundProxy::ProxyServer(OutboundProxyProtocol::Direct(
                        OutboundDirect {
                            name: PROXY_DIRECT.to_string(),
                        },
                    )),
                ),
                (
                    String::from(PROXY_REJECT),
                    OutboundProxy::ProxyServer(OutboundProxyProtocol::Reject(
                        OutboundReject {
                            name: PROXY_REJECT.to_string(),
                        },
                    )),
                ),
            ]),
            |mut rv, protocol| {
                let name = protocol.name().to_owned();
                if rv.contains_key(name.as_str()) {
                    return Err(Error::InvalidConfig(format!(
                        "duplicated proxy name: {name}"
                    )));
                }
                proxy_names.push(name.clone());
                rv.insert(name, OutboundProxy::ProxyServer(protocol));
                Ok(rv)
            },
        )?,
        proxy_groups: proxy_group::convert(
            c.proxy_group.take(),
            &all_proxy_names,
            &all_provider_names,
            &mut proxy_names,
        )?,
        proxy_names,
        proxy_providers,
        listeners: listener::convert(c.listeners.take(), &c)?,
        inbound_providers: c
            .inbound_provider
            .take()
            .unwrap_or_default()
            .into_iter()
            .map(|(name, mut provider)| {
                provider.set_name(name.clone());
                (name, provider)
            })
            .collect(),
    }
    .validate()
}

fn parse_rules(rules: Vec<String>) -> Result<Vec<RuleType>, Error> {
    rules
        .into_iter()
        .map(|rule| {
            rule.parse::<RuleType>()
                .map_err(|error| Error::InvalidConfig(error.to_string()))
        })
        .collect()
}

impl TryFrom<HashMap<String, Value>> for OutboundGroupProtocol {
    type Error = Error;

    fn try_from(mapping: HashMap<String, Value>) -> Result<Self, Self::Error> {
        let name = mapping
            .get("name")
            .and_then(|x| x.as_str())
            .ok_or(Error::InvalidConfig(
                "missing field `name` in outbound proxy grouop".to_owned(),
            ))?
            .to_owned();
        OutboundGroupProtocol::deserialize(MapDeserializer::new(mapping.into_iter()))
            .map_err(map_serde_error(name))
    }
}
