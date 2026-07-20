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
            let domain = domain.to_ascii_lowercase();
            let suffix = self.suffix.to_ascii_lowercase();
            domain == suffix || domain.ends_with(&format!(".{suffix}"))
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
