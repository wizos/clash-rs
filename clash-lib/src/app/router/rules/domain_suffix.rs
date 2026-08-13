use crate::{app::router::rules::RuleMatcher, session::Session};

#[derive(Clone)]
pub struct DomainSuffix {
    pub suffix: String,
    pub target: String,
}

impl std::fmt::Display for DomainSuffix {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{} suffix {}", self.target, self.suffix)
    }
}

impl RuleMatcher for DomainSuffix {
    fn apply(&self, sess: &Session) -> bool {
        sess.rule_host().is_some_and(|domain| {
            let domain = domain.as_bytes();
            let suffix = self.suffix.as_bytes();
            domain.eq_ignore_ascii_case(suffix)
                || (domain.len() > suffix.len()
                    && domain[domain.len() - suffix.len() - 1] == b'.'
                    && domain[domain.len() - suffix.len()..]
                        .eq_ignore_ascii_case(suffix))
        })
    }

    fn target(&self) -> &str {
        self.target.as_str()
    }

    fn payload(&self) -> String {
        self.suffix.clone()
    }

    fn type_name(&self) -> &str {
        "DomainSuffix"
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::session::SocksAddr;

    fn matches(rule: &DomainSuffix, domain: &str) -> bool {
        rule.apply(&Session {
            destination: SocksAddr::Domain(domain.to_owned(), 443),
            ..Default::default()
        })
    }

    #[test]
    fn matches_suffix_on_label_boundary_without_case_sensitivity() {
        let rule = DomainSuffix {
            suffix: "Example.COM".to_owned(),
            target: "PROXY".to_owned(),
        };
        assert!(matches(&rule, "example.com"));
        assert!(matches(&rule, "API.EXAMPLE.COM"));
        assert!(!matches(&rule, "notexample.com"));
        assert!(!matches(&rule, "com"));
    }
}
