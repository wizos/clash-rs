use super::RuleMatcher;
use crate::session::Session;

pub struct DomainWildcard {
    pub pattern: String,
    pub target: String,
}

pub(crate) fn matches(pattern: &str, value: &str) -> bool {
    let pattern = pattern.to_lowercase().chars().collect::<Vec<_>>();
    let value = value.to_lowercase().chars().collect::<Vec<_>>();
    let mut previous = vec![false; value.len() + 1];
    previous[0] = true;

    for token in pattern {
        let mut current = vec![false; value.len() + 1];
        if token == '*' {
            current[0] = previous[0];
        }
        for index in 1..=value.len() {
            current[index] = match token {
                '*' => previous[index] || current[index - 1],
                '?' => previous[index - 1],
                literal => previous[index - 1] && literal == value[index - 1],
            };
        }
        previous = current;
    }

    previous[value.len()]
}

impl std::fmt::Display for DomainWildcard {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{} domain wildcard {}", self.target, self.pattern)
    }
}

impl RuleMatcher for DomainWildcard {
    fn apply(&self, sess: &Session) -> bool {
        sess.rule_host()
            .is_some_and(|domain| matches(&self.pattern, domain))
    }

    fn target(&self) -> &str {
        &self.target
    }

    fn payload(&self) -> String {
        self.pattern.clone()
    }

    fn type_name(&self) -> &str {
        "DomainWildcard"
    }
}

#[cfg(test)]
mod tests {
    use super::matches;

    #[test]
    fn matches_star_and_question_mark() {
        assert!(matches("*.google.com", "mail.google.com"));
        assert!(matches("g??gle.com", "google.com"));
        assert!(!matches("*.google.com", "google.com"));
    }
}
