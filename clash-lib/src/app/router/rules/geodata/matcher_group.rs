use crate::{
    app::router::rules::geodata::str_matcher::{Matcher, try_new_matcher},
    common::{
        geodata::geodata_proto::{Domain, domain::Type},
        succinct_set::DomainSet,
        trie::StringTrie,
    },
};
use regex::RegexSet;
use std::sync::Arc;

pub trait DomainGroupMatcher: Send + Sync {
    fn apply(&self, domain: &str) -> bool;
}

pub struct SuccinctMatcherGroup {
    set: DomainSet,
    other_matchers: Vec<Box<dyn Matcher>>,
    regex_matcher: Option<RegexSet>,
    not: bool,
}

impl SuccinctMatcherGroup {
    pub fn try_new(domains: Vec<Domain>, not: bool) -> Result<Self, crate::Error> {
        let mut set = StringTrie::new();
        let mut other_matchers = Vec::new();
        let mut regexes = Vec::new();
        for domain in domains {
            let t = Type::try_from(domain.r#type).map_err(|x| {
                crate::Error::InvalidConfig(format!("invalid domain type: {x}"))
            })?;

            match t {
                Type::Plain => {
                    let matcher = try_new_matcher(domain.value, t)?;
                    other_matchers.push(matcher);
                }
                Type::Regex => regexes.push(domain.value),
                Type::Domain => {
                    let domain = format!("+.{}", domain.value);
                    set.insert(&domain, Arc::new(()));
                }
                Type::Full => {
                    set.insert(&domain.value, Arc::new(()));
                }
            }
        }
        let regex_matcher = if regexes.is_empty() {
            None
        } else {
            Some(RegexSet::new(regexes).map_err(|error| {
                crate::Error::InvalidConfig(format!("invalid regex: {error}"))
            })?)
        };
        Ok(SuccinctMatcherGroup {
            set: set.into(),
            other_matchers,
            regex_matcher,
            not,
        })
    }
}

impl DomainGroupMatcher for SuccinctMatcherGroup {
    fn apply(&self, domain: &str) -> bool {
        let mut is_matched = self.set.has(domain);
        if !is_matched {
            for matcher in &self.other_matchers {
                if matcher.matches(domain) {
                    is_matched = true;
                    break;
                }
            }
        }
        if !is_matched {
            is_matched = self
                .regex_matcher
                .as_ref()
                .is_some_and(|matcher| matcher.is_match(domain));
        }
        if self.not { !is_matched } else { is_matched }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn domain(value: &str, kind: Type) -> Domain {
        Domain {
            r#type: kind.into(),
            value: value.to_owned(),
            attribute: vec![],
        }
    }

    #[test]
    fn succinct_group_preserves_geosite_match_semantics() {
        let group = SuccinctMatcherGroup::try_new(
            vec![
                domain("example.com", Type::Domain),
                domain("only.example", Type::Full),
                domain("keyword", Type::Plain),
                domain(r"^regex\d+\.example$", Type::Regex),
                domain(r"^second\.example$", Type::Regex),
            ],
            false,
        )
        .unwrap();

        assert!(group.apply("www.example.com"));
        assert!(group.apply("only.example"));
        assert!(!group.apply("www.only.example"));
        assert!(group.apply("has-keyword.example"));
        assert!(group.apply("regex42.example"));
        assert!(group.apply("second.example"));
        assert!(!group.apply("unmatched.example"));
    }

    #[test]
    fn succinct_group_supports_matchers_without_domain_entries() {
        let group = SuccinctMatcherGroup::try_new(
            vec![domain("keyword", Type::Plain)],
            false,
        )
        .unwrap();

        assert!(group.apply("has-keyword.example"));
        assert!(!group.apply("unmatched.example"));
    }
}
