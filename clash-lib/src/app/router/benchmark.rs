use super::Router;
use crate::{
    app::dns::{ClashResolver, ResolverKind, RuleDispatch},
    common::geodata::{GeoDataLookup, GeoDataLookupTrait, geodata_proto},
    config::internal::{
        config::{InlineRuleProvider, RuleProviderDef},
        rule::RuleType,
    },
    session::{Network, Session, SocksAddr},
};
use async_trait::async_trait;
use hickory_proto::op;
use std::{collections::HashMap, net::IpAddr, sync::Arc};

pub struct RuleBenchmark {
    router: Router,
    rule_count: usize,
}

impl RuleBenchmark {
    pub async fn new(rule_count: usize, dns_enrichment: bool) -> Self {
        assert!(rule_count >= 7);
        let provider_name = "anonymized-provider".to_owned();
        let mut rules = (0..rule_count - 6)
            .map(|index| RuleType::DomainSuffix {
                domain_suffix: format!("redacted-{index}.invalid"),
                target: "PROXY".to_owned(),
            })
            .collect::<Vec<_>>();
        rules.extend([
            RuleType::RuleSet {
                rule_set: provider_name.clone(),
                target: "PROXY".to_owned(),
            },
            RuleType::GeoSite {
                target: "PROXY".to_owned(),
                country_code: "benchmark".to_owned(),
            },
            RuleType::IpCidr {
                ipnet: "192.0.2.0/24".parse().unwrap(),
                target: "PROXY".to_owned(),
                no_resolve: !dns_enrichment,
                is_src: false,
            },
            RuleType::ProcessName {
                process_name: "redacted-process".to_owned(),
                target: "PROXY".to_owned(),
            },
            RuleType::SubRule {
                condition: Box::new(RuleType::Network {
                    network: Network::Udp,
                    target: String::new(),
                }),
                payload: "(NETWORK,UDP)".to_owned(),
                sub_rule: "udp-only".to_owned(),
            },
            RuleType::Match {
                target: "DIRECT".to_owned(),
            },
        ]);
        let providers = HashMap::from([(
            provider_name,
            RuleProviderDef::Inline(InlineRuleProvider {
                path: String::new(),
                behavior: crate::app::remote_content_manager::providers::rule_provider::RuleSetBehavior::Domain,
                inline_rules: vec!["redacted-provider.invalid".to_owned()],
            }),
        )]);
        let sub_rules = HashMap::from([(
            "udp-only".to_owned(),
            vec![RuleType::Match {
                target: "REJECT".to_owned(),
            }],
        )]);
        let geodata: GeoDataLookup = Arc::new(BenchmarkGeoData);
        let resolver = Arc::new(BenchmarkResolver);
        let router = Router::new(
            rules,
            sub_rules,
            providers,
            resolver,
            None,
            None,
            Some(geodata),
            String::new(),
            RuleDispatch::new(),
        )
        .await;
        for provider in router.get_rule_providers().values() {
            provider.initialize().await.unwrap();
        }
        assert_eq!(router.get_all_rules().len(), rule_count);
        Self { router, rule_count }
    }

    pub async fn run(&self) -> &str {
        let mut session = Session {
            network: Network::Tcp,
            destination: SocksAddr::Domain("benchmark.example".to_owned(), 443),
            process: "benchmark-process".to_owned(),
            ..Default::default()
        };
        let (target, _) = self.router.match_route(&mut session).await;
        assert_eq!(target, "DIRECT");
        target
    }

    pub fn rule_count(&self) -> usize {
        self.rule_count
    }
}

struct BenchmarkGeoData;

impl GeoDataLookupTrait for BenchmarkGeoData {
    fn get(&self, list: &str) -> Option<geodata_proto::GeoSite> {
        (list == "benchmark").then(|| geodata_proto::GeoSite {
            country_code: "BENCHMARK".to_owned(),
            domain: vec![geodata_proto::Domain {
                r#type: geodata_proto::domain::Type::Domain.into(),
                value: "redacted-geosite.invalid".to_owned(),
                attribute: vec![],
            }],
        })
    }
}

struct BenchmarkResolver;

#[async_trait]
impl ClashResolver for BenchmarkResolver {
    async fn resolve(
        &self,
        _host: &str,
        _enhanced: bool,
    ) -> anyhow::Result<Option<IpAddr>> {
        Ok(Some("203.0.113.1".parse().unwrap()))
    }

    async fn resolve_v4(
        &self,
        _host: &str,
        _enhanced: bool,
    ) -> anyhow::Result<Option<std::net::Ipv4Addr>> {
        Ok(Some("203.0.113.1".parse().unwrap()))
    }

    async fn resolve_v6(
        &self,
        _host: &str,
        _enhanced: bool,
    ) -> anyhow::Result<Option<std::net::Ipv6Addr>> {
        Ok(None)
    }

    async fn cached_for(&self, _ip: IpAddr) -> Option<String> {
        None
    }

    async fn exchange(&self, _message: &op::Message) -> anyhow::Result<op::Message> {
        anyhow::bail!("unused by rule benchmark")
    }

    async fn reverse_lookup(&self, _ip: IpAddr) -> Option<String> {
        None
    }

    async fn is_fake_ip(&self, _ip: IpAddr) -> bool {
        false
    }

    fn fake_ip_enabled(&self) -> bool {
        false
    }

    fn ipv6(&self) -> bool {
        false
    }

    fn set_ipv6(&self, _enable: bool) {}

    fn kind(&self) -> ResolverKind {
        ResolverKind::Clash
    }
}
