use super::{
    dns::ThreadSafeDNSResolver,
    remote_content_manager::providers::{
        file_vehicle, http_vehicle,
        rule_provider::{RuleProviderImpl, ThreadSafeRuleProvider},
    },
};
use crate::{
    Error,
    app::router::rules::{
        domain::Domain, domain_keyword::DomainKeyword, domain_suffix::DomainSuffix,
        final_::Final, ipcidr::IpCidr, ruleset::RuleSet,
    },
    config::internal::{config::RuleProviderDef, rule::RuleType},
    print_and_exit,
    session::Session,
};

use std::{collections::HashMap, path::PathBuf, sync::Arc, time::Duration};

use hyper::Uri;
use rules::domain_regex::DomainRegex;
use tracing::{error, info, trace};

mod rules;

use crate::common::{geodata::GeoDataLookup, mmdb::MmdbLookup};
pub use rules::RuleMatcher;
pub(crate) use rules::geodata::GeoSiteMatcher;

pub struct Router {
    rules: Vec<Box<dyn RuleMatcher>>,
    dns_resolver: ThreadSafeDNSResolver,

    country_mmdb: Option<MmdbLookup>,
    asn_mmdb: Option<MmdbLookup>,
    rule_providers: HashMap<String, ThreadSafeRuleProvider>,
}

pub type ArcRouter = Arc<Router>;

#[deprecated(
    note = "ThreadSafeRouter has been renamed to ArcRouter; use ArcRouter instead"
)]
pub type ThreadSafeRouter = ArcRouter;

const MATCH: &str = "MATCH";

impl Router {
    pub async fn new(
        rules: Vec<RuleType>,
        sub_rules: HashMap<String, Vec<RuleType>>,
        rule_providers: HashMap<String, RuleProviderDef>,
        dns_resolver: ThreadSafeDNSResolver,
        country_mmdb: Option<MmdbLookup>,
        asn_mmdb: Option<MmdbLookup>,
        geodata: Option<GeoDataLookup>,
        cwd: String,
    ) -> Self {
        let mut rule_provider_registry = HashMap::new();

        Self::load_rule_providers(
            rule_providers,
            &mut rule_provider_registry,
            dns_resolver.clone(),
            country_mmdb.clone(),
            geodata.clone(),
            cwd,
        )
        .await
        .ok();

        let sub_rule_registry = rules::subrule::SubRuleRegistry::default();
        let rules = rules
            .into_iter()
            .map(|r| {
                map_rule_type(
                    r,
                    country_mmdb.clone(),
                    asn_mmdb.clone(),
                    geodata.clone(),
                    Some(&rule_provider_registry),
                    Some(&sub_rule_registry),
                )
            })
            .collect();
        let converted_sub_rules = sub_rules
            .into_iter()
            .map(|(name, rules)| {
                let rules = rules
                    .into_iter()
                    .map(|rule| {
                        map_rule_type(
                            rule,
                            country_mmdb.clone(),
                            asn_mmdb.clone(),
                            geodata.clone(),
                            Some(&rule_provider_registry),
                            Some(&sub_rule_registry),
                        )
                    })
                    .collect();
                (name, rules)
            })
            .collect();
        sub_rule_registry
            .set(converted_sub_rules)
            .unwrap_or_else(|_| {
                unreachable!("new sub-rule registry was already set")
            });

        Self {
            rules,
            dns_resolver,

            country_mmdb,
            asn_mmdb,
            rule_providers: rule_provider_registry,
        }
    }

    pub fn get_rule_providers(&self) -> &HashMap<String, ThreadSafeRuleProvider> {
        &self.rule_providers
    }

    /// this mutates the session, attaching resolved IP and ASN
    pub async fn match_route(
        &self,
        sess: &mut Session,
    ) -> (&str, Option<&Box<dyn RuleMatcher>>) {
        let mut sess_resolved = false;

        for r in self.rules.iter() {
            if r.should_resolve_process()
                && crate::process_resolver::should_resolve_for_rule()
            {
                crate::process_resolver::resolve_session(sess);
            }
            // Resolve IP when needed
            if sess.destination.is_domain()
                && r.should_resolve_ip()
                && !sess_resolved
                && let Ok(Some(ip)) = self
                    .dns_resolver
                    .resolve(sess.destination.domain().unwrap(), false)
                    .await
            {
                sess.resolved_ip = Some(ip);
                sess_resolved = true;
            }

            // Lookup geo information with guard clause
            if let Some(ip) = sess.resolved_ip.or(sess.destination.ip()) {
                Self::populate_geo_for_ip(
                    ip,
                    &self.country_mmdb,
                    &self.asn_mmdb,
                    sess,
                );
            }

            if let Some(target) = r.route_target(sess) {
                info!("matched {} to target {}[{}]", &sess, target, r.type_name());
                return (target, Some(r));
            }
        }

        (MATCH, None)
    }

    /// Look up country code and ASN for an IP address.
    /// Uses `country_mmdb` for the ISO 3166-1 alpha-2 country code.
    /// For ASN, preserves the original strategy: try
    /// `asn_mmdb.lookup_country()` first (simplified/fast path, e.g.
    /// Country.mmdb), fall back to `asn_mmdb.lookup_asn()` for the org
    /// name.
    fn populate_geo_for_ip(
        ip: std::net::IpAddr,
        country_mmdb: &Option<MmdbLookup>,
        asn_mmdb: &Option<MmdbLookup>,
        sess: &mut Session,
    ) {
        // Preserve existing geo metadata — avoids overriding prior enrichment
        if sess.country.is_some() && sess.asn.is_some() {
            return;
        }

        if sess.country.is_none()
            && let Some(country_mmdb) = country_mmdb
        {
            match country_mmdb.lookup_country(ip) {
                Ok(country) => {
                    trace!("country for {} is {:?}", ip, country.country_code);
                    sess.country = Some(country.country_code);
                }
                Err(e) => {
                    trace!("failed to lookup country for {}: {}", ip, e);
                }
            }
        }

        if sess.asn.is_none()
            && let Some(asn_mmdb) = asn_mmdb
        {
            // try simplified mmdb first (e.g. Country.mmdb doubles as a fast
            // country-code lookup on the asn_mmdb slot)
            if let Ok(country) = asn_mmdb.lookup_country(ip) {
                sess.asn = Some(country.country_code);
                return;
            }
            // fall back to full ASN lookup
            match asn_mmdb.lookup_asn(ip) {
                Ok(asn) => {
                    trace!("asn for {} is {:?}", ip, asn);
                    sess.asn = Some(asn.asn_name);
                }
                Err(e) => {
                    trace!("failed to lookup ASN for {}: {}", ip, e);
                }
            }
        }
    }

    async fn load_rule_providers(
        rule_providers: HashMap<String, RuleProviderDef>,
        rule_provider_registry: &mut HashMap<String, ThreadSafeRuleProvider>,
        resolver: ThreadSafeDNSResolver,
        mmdb: Option<MmdbLookup>,
        geodata: Option<GeoDataLookup>,
        cwd: String,
    ) -> Result<(), Error> {
        for (name, provider) in rule_providers.into_iter() {
            match provider {
                RuleProviderDef::Http(http) => {
                    let vehicle = http_vehicle::Vehicle::new(
                        http.url.parse::<Uri>().map_err(|error| {
                            Error::InvalidConfig(format!(
                                "invalid URL for rule provider `{name}`: {error}"
                            ))
                        })?,
                        http.path,
                        Some(cwd.clone()),
                        resolver.clone(),
                    );

                    // Default to yaml if not specified
                    let format = http.format.unwrap_or_default();
                    let provider = RuleProviderImpl::new(
                        name.clone(),
                        http.behavior,
                        format,
                        Some(Duration::from_secs(http.interval)),
                        Some(Arc::new(vehicle)),
                        mmdb.clone(),
                        geodata.clone(),
                        http.inline_rules,
                    );

                    rule_provider_registry.insert(name, Arc::new(provider));
                }
                RuleProviderDef::File(file) => {
                    let vehicle = file_vehicle::Vehicle::new(
                        PathBuf::from(cwd.clone())
                            .join(&file.path)
                            .to_str()
                            .unwrap(),
                    );

                    // Default to yaml if not specified
                    let format = file.format.unwrap_or_default();
                    // `interval` is optional for file providers: content is
                    // loaded at startup and live-reloaded via an OS file
                    // watcher, so polling is only an occasional fallback.
                    let interval = file.interval.map(Duration::from_secs);
                    let provider = RuleProviderImpl::new(
                        name.clone(),
                        file.behavior,
                        format,
                        interval,
                        Some(Arc::new(vehicle)),
                        mmdb.clone(),
                        geodata.clone(),
                        file.inline_rules,
                    );

                    rule_provider_registry.insert(name, Arc::new(provider));
                }
                RuleProviderDef::Inline(inline) => {
                    let provider = RuleProviderImpl::new(
                        name.clone(),
                        inline.behavior,
                        Default::default(), /* format really doesn't matter for
                                             * inline rules */
                        None,
                        None,
                        mmdb.clone(),
                        geodata.clone(),
                        Some(inline.inline_rules),
                    );

                    rule_provider_registry.insert(name, Arc::new(provider));
                }
            }
        }

        for p in rule_provider_registry.values() {
            let p = p.clone();
            tokio::spawn(async move {
                info!("initializing rule provider {}", p.name());
                match p.initialize().await {
                    Ok(_) => {
                        info!("rule provider {} initialized", p.name());
                    }
                    Err(err) => {
                        error!(
                            "failed to initialize rule provider {}: {}",
                            p.name(),
                            err
                        );
                    }
                }
            });
        }

        Ok(())
    }

    /// API handlers
    pub fn get_all_rules(&self) -> &Vec<Box<dyn RuleMatcher>> {
        &self.rules
    }
}

pub fn map_rule_type(
    rule_type: RuleType,
    mmdb: Option<MmdbLookup>,
    asn_mmdb: Option<MmdbLookup>,
    geodata: Option<GeoDataLookup>,
    rule_provider_registry: Option<&HashMap<String, ThreadSafeRuleProvider>>,
    sub_rule_registry: Option<&rules::subrule::SubRuleRegistry>,
) -> Box<dyn RuleMatcher> {
    match rule_type {
        RuleType::Domain { domain, target } => {
            Box::new(Domain { domain, target }) as Box<dyn RuleMatcher>
        }
        RuleType::DomainRegex { regex, target } => {
            Box::new(DomainRegex { regex, target })
        }
        RuleType::DomainSuffix {
            domain_suffix,
            target,
        } => Box::new(DomainSuffix {
            suffix: domain_suffix,
            target,
        }),
        RuleType::DomainKeyword {
            domain_keyword,
            target,
        } => Box::new(DomainKeyword {
            keyword: domain_keyword,
            target,
        }),
        RuleType::DomainWildcard { pattern, target } => {
            Box::new(rules::wildcard::DomainWildcard { pattern, target })
        }
        RuleType::IpCidr {
            ipnet,
            target,
            no_resolve,
            is_src,
        } => Box::new(IpCidr {
            ipnet,
            target,
            no_resolve,
            match_src: is_src,
        }),
        RuleType::SrcCidr {
            ipnet,
            target,
            no_resolve,
        } => Box::new(IpCidr {
            ipnet,
            target,
            no_resolve,
            match_src: true,
        }),
        RuleType::IpSuffix {
            ipnet,
            target,
            no_resolve,
            is_src,
        } => Box::new(rules::ipsuffix::IpSuffix {
            ipnet,
            target,
            no_resolve,
            is_src,
        }),

        RuleType::GeoIP {
            target,
            country_code,
            no_resolve,
            is_src,
        } => Box::new(rules::geoip::GeoIP {
            target,
            country_code,
            no_resolve,
            is_src,
            mmdb: mmdb.clone(),
        }),
        RuleType::SrcGeoIP {
            target,
            country_code,
        } => Box::new(rules::geoip::GeoIP {
            target,
            country_code,
            no_resolve: true,
            is_src: true,
            mmdb: mmdb.clone(),
        }),
        RuleType::IpAsn {
            target,
            asn,
            no_resolve,
            is_src,
        } => Box::new(rules::ipasn::IpAsn {
            target,
            asn,
            no_resolve,
            is_src,
            mmdb: asn_mmdb.clone(),
        }),
        RuleType::SrcIpAsn { target, asn } => Box::new(rules::ipasn::IpAsn {
            target,
            asn,
            no_resolve: true,
            is_src: true,
            mmdb: asn_mmdb.clone(),
        }),
        RuleType::GeoSite {
            target,
            country_code,
        } => {
            let res = rules::geodata::GeoSiteMatcher::new(
                country_code,
                target,
                geodata.as_ref(),
            )
            .unwrap();
            Box::new(res) as _
        }
        RuleType::SRCPort {
            target,
            payload,
            port_ranges,
        } => Box::new(rules::port::Port {
            payload,
            port_ranges,
            target,
            kind: rules::port::PortKind::Source,
        }),
        RuleType::DSTPort {
            target,
            payload,
            port_ranges,
        } => Box::new(rules::port::Port {
            payload,
            port_ranges,
            target,
            kind: rules::port::PortKind::Destination,
        }),
        RuleType::InboundPort {
            target,
            payload,
            port_ranges,
        } => Box::new(rules::port::Port {
            payload,
            port_ranges,
            target,
            kind: rules::port::PortKind::Inbound,
        }),
        RuleType::ProcessName {
            process_name,
            target,
        } => Box::new(rules::process::Process {
            name: process_name,
            target,
            name_only: true,
            regex: None,
            wildcard: false,
        }),
        RuleType::ProcessPath {
            process_path,
            target,
        } => Box::new(rules::process::Process {
            name: process_path,
            target,
            name_only: false,
            regex: None,
            wildcard: false,
        }),
        RuleType::ProcessNameRegex { regex, target } => {
            Box::new(rules::process::Process {
                name: regex.as_str().to_string(),
                target,
                name_only: true,
                regex: Some(regex),
                wildcard: false,
            })
        }
        RuleType::ProcessPathRegex { regex, target } => {
            Box::new(rules::process::Process {
                name: regex.as_str().to_string(),
                target,
                name_only: false,
                regex: Some(regex),
                wildcard: false,
            })
        }
        RuleType::ProcessNameWildcard { pattern, target } => {
            Box::new(rules::process::Process {
                name: pattern,
                target,
                name_only: true,
                regex: None,
                wildcard: true,
            })
        }
        RuleType::ProcessPathWildcard { pattern, target } => {
            Box::new(rules::process::Process {
                name: pattern,
                target,
                name_only: false,
                regex: None,
                wildcard: true,
            })
        }
        RuleType::InboundType {
            inbound_types,
            target,
        } => Box::new(rules::inbound::InboundType {
            inbound_types,
            target,
        }),
        RuleType::InboundUser {
            inbound_users,
            target,
        } => Box::new(rules::inbound::InboundUser {
            inbound_users,
            target,
        }),
        RuleType::InboundName {
            inbound_names,
            target,
        } => Box::new(rules::inbound::InboundName {
            inbound_names,
            target,
        }),
        RuleType::Uid {
            payload,
            uid_ranges,
            target,
        } => Box::new(rules::metadata::Metadata {
            payload,
            ranges: uid_ranges,
            target,
            kind: rules::metadata::MetadataKind::Uid,
        }),
        RuleType::Dscp {
            payload,
            dscp_ranges,
            target,
        } => Box::new(rules::metadata::Metadata {
            payload,
            ranges: dscp_ranges,
            target,
            kind: rules::metadata::MetadataKind::Dscp,
        }),
        RuleType::RuleSet { rule_set, target } => match rule_provider_registry {
            Some(rule_provider_registry) => Box::new(RuleSet::new(
                rule_set.clone(),
                target,
                rule_provider_registry
                    .get(&rule_set)
                    .unwrap_or_else(|| {
                        print_and_exit!("rule provider {} not found", rule_set)
                    })
                    .clone(),
            )),
            None => {
                // this is called in remote rule provider with no rule provider
                // registry, in this case, we should panic
                unreachable!("you shouldn't nest rule-set within another rule-set")
            }
        },
        RuleType::Network { network, target } => {
            Box::new(rules::network::NetworkRule { network, target })
        }
        RuleType::Composite {
            operator,
            expression,
            target,
        } => {
            match rules::composite::CompositeRule::new(
                &operator,
                &expression,
                &target,
                mmdb,
                asn_mmdb,
                geodata,
                rule_provider_registry,
            ) {
                Ok(rule) => Box::new(rule),
                Err(e) => {
                    error!(
                        "failed to create composite rule: {}, expression: {}. \
                         Using REJECT as fallback.",
                        e, expression
                    );
                    Box::new(Final {
                        target: "REJECT".to_string(),
                    })
                }
            }
        }
        RuleType::SubRule {
            condition,
            payload,
            sub_rule,
        } => {
            let registry = sub_rule_registry
                .expect("SUB-RULE is not supported inside rule providers")
                .clone();
            Box::new(rules::subrule::SubRule {
                condition: map_rule_type(
                    *condition,
                    mmdb,
                    asn_mmdb,
                    geodata,
                    rule_provider_registry,
                    Some(&registry),
                ),
                payload,
                name: sub_rule,
                registry,
            })
        }
        RuleType::Match { target } => Box::new(Final { target }),
    }
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;

    use anyhow::Ok;

    use crate::{
        app::dns::{MockClashResolver, SystemResolver},
        common::{
            geodata::{DEFAULT_GEOSITE_DOWNLOAD_URL, GeoData},
            http::new_http_client,
            mmdb::{DEFAULT_COUNTRY_MMDB_DOWNLOAD_URL, Mmdb},
        },
        config::internal::rule::RuleType,
        session::Session,
        tests::initialize,
    };

    #[tokio::test]
    async fn test_route_match() {
        initialize();

        let mut mock_resolver = MockClashResolver::new();
        mock_resolver.expect_resolve().returning(|host, _| {
            if host == "china.com" {
                Ok(Some("114.114.114.114".parse().unwrap()))
            } else if host == "t.me" {
                Ok(Some("149.154.0.1".parse().unwrap()))
            } else if host == "git.io" {
                Ok(Some("8.8.8.8".parse().unwrap()))
            } else {
                Ok(None)
            }
        });
        let mock_resolver = Arc::new(mock_resolver);

        let real_resolver = Arc::new(SystemResolver::new(false).unwrap());

        let client = new_http_client(real_resolver.clone(), None).unwrap();

        let temp_dir = tempfile::tempdir().unwrap();

        let mmdb = Mmdb::new(
            temp_dir.path().join("mmdb.mmdb"),
            DEFAULT_COUNTRY_MMDB_DOWNLOAD_URL.to_string(),
            client,
        )
        .await
        .unwrap();

        let client = new_http_client(real_resolver.clone(), None).unwrap();

        let geodata = GeoData::new(
            temp_dir.path().join("geodata.geodata"),
            DEFAULT_GEOSITE_DOWNLOAD_URL.to_string(),
            client,
        )
        .await
        .unwrap();

        let router = super::Router::new(
            vec![
                RuleType::GeoIP {
                    target: "DIRECT".to_string(),
                    country_code: "CN".to_string(),
                    no_resolve: false,
                    is_src: false,
                },
                RuleType::DomainRegex {
                    regex: regex::Regex::new(r"^regex").unwrap(),
                    target: "regex-match".to_string(),
                },
                RuleType::DomainSuffix {
                    domain_suffix: "t.me".to_string(),
                    target: "DS".to_string(),
                },
                RuleType::IpCidr {
                    ipnet: "149.154.0.0/16".parse().unwrap(),
                    target: "IC".to_string(),
                    no_resolve: false,
                    is_src: false,
                },
                RuleType::DomainSuffix {
                    domain_suffix: "git.io".to_string(),
                    target: "DS2".to_string(),
                },
            ],
            Default::default(),
            Default::default(),
            mock_resolver,
            Some(Arc::new(mmdb)),
            None,
            Some(Arc::new(geodata)),
            temp_dir.path().to_str().unwrap().to_string(),
        )
        .await;

        let cases = vec![
            ("china.com", "DIRECT", "should resolve and match IP"),
            ("regex", "regex-match", "should match regex"),
            ("t.me", "DS", "should match domain"),
            (
                "git.io",
                "DS2",
                "should still match domain after previous rule resolved IP and non \
                 match",
            ),
            (
                "no-match",
                "MATCH",
                "should fallback to MATCH when nothing matched",
            ),
            ("149.154.0.1", "IC", "should match CIDR"),
        ];

        for (domain, target, desc) in cases {
            assert_eq!(
                router
                    .match_route(&mut Session {
                        destination: crate::session::SocksAddr::Domain(
                            domain.to_string(),
                            1111
                        ),
                        ..Default::default()
                    })
                    .await
                    .0,
                target,
                "{}",
                desc
            );
        }
    }

    #[tokio::test]
    async fn test_network_rule() {
        initialize();

        let mut mock_resolver = MockClashResolver::new();
        mock_resolver.expect_resolve().returning(|_, _| Ok(None));
        let mock_resolver = Arc::new(mock_resolver);

        let router = super::Router::new(
            vec![
                RuleType::Network {
                    network: crate::session::Network::Tcp,
                    target: "TCP-PROXY".to_string(),
                },
                RuleType::Network {
                    network: crate::session::Network::Udp,
                    target: "UDP-PROXY".to_string(),
                },
            ],
            Default::default(),
            Default::default(),
            mock_resolver,
            None,
            None,
            None,
            std::env::temp_dir().to_str().unwrap().to_string(),
        )
        .await;

        // Test TCP network rule
        let mut tcp_session = Session {
            network: crate::session::Network::Tcp,
            destination: crate::session::SocksAddr::Domain(
                "example.com".to_string(),
                443,
            ),
            ..Default::default()
        };
        assert_eq!(
            router.match_route(&mut tcp_session).await.0,
            "TCP-PROXY",
            "should match TCP network rule"
        );

        // Test UDP network rule
        let mut udp_session = Session {
            network: crate::session::Network::Udp,
            destination: crate::session::SocksAddr::Domain(
                "example.com".to_string(),
                53,
            ),
            ..Default::default()
        };
        assert_eq!(
            router.match_route(&mut udp_session).await.0,
            "UDP-PROXY",
            "should match UDP network rule"
        );
    }

    #[tokio::test]
    async fn test_sub_rule_routes_to_nested_target() {
        initialize();

        let mut mock_resolver = MockClashResolver::new();
        mock_resolver.expect_resolve().returning(|_, _| Ok(None));
        let mock_resolver = Arc::new(mock_resolver);
        let sub_rules = std::collections::HashMap::from([(
            "tcp-branch".to_string(),
            vec![
                RuleType::Domain {
                    domain: "example.com".to_string(),
                    target: "DIRECT".to_string(),
                },
                RuleType::Match {
                    target: "REJECT".to_string(),
                },
            ],
        )]);
        let router = super::Router::new(
            vec![RuleType::SubRule {
                condition: Box::new(RuleType::Network {
                    network: crate::session::Network::Tcp,
                    target: String::new(),
                }),
                payload: "(NETWORK,TCP)".to_string(),
                sub_rule: "tcp-branch".to_string(),
            }],
            sub_rules,
            Default::default(),
            mock_resolver,
            None,
            None,
            None,
            std::env::temp_dir().to_str().unwrap().to_string(),
        )
        .await;

        let mut session = Session {
            network: crate::session::Network::Tcp,
            destination: crate::session::SocksAddr::Domain(
                "example.com".to_string(),
                443,
            ),
            ..Default::default()
        };
        assert_eq!(router.match_route(&mut session).await.0, "DIRECT");

        session.network = crate::session::Network::Udp;
        assert_eq!(router.match_route(&mut session).await.0, "MATCH");
    }
}
