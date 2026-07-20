use std::{
    collections::HashMap,
    sync::{Arc, OnceLock},
};

use crate::{app::router::rules::RuleMatcher, session::Session};

pub type SubRuleRegistry = Arc<OnceLock<HashMap<String, Vec<Box<dyn RuleMatcher>>>>>;

pub struct SubRule {
    pub condition: Box<dyn RuleMatcher>,
    pub payload: String,
    pub name: String,
    pub registry: SubRuleRegistry,
}

impl SubRule {
    fn matched_target<'a>(&'a self, sess: &Session) -> Option<&'a str> {
        if !self.condition.apply(sess) {
            return None;
        }
        let rules = self.registry.get()?.get(&self.name)?;
        for rule in rules {
            if let Some(target) = rule.route_target(sess) {
                if target == "PASS-RULE" {
                    continue;
                }
                return Some(target);
            }
        }
        None
    }
}

impl std::fmt::Display for SubRule {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "sub-rule {} when {}", self.name, self.payload)
    }
}

impl RuleMatcher for SubRule {
    fn apply(&self, sess: &Session) -> bool {
        self.matched_target(sess).is_some()
    }

    fn target(&self) -> &str {
        &self.name
    }

    fn route_target(&self, sess: &Session) -> Option<&str> {
        self.matched_target(sess)
    }

    fn payload(&self) -> String {
        self.payload.clone()
    }

    fn type_name(&self) -> &str {
        "SubRule"
    }

    fn should_resolve_ip(&self) -> bool {
        if self.condition.should_resolve_ip() {
            return true;
        }
        self.registry
            .get()
            .and_then(|registry| registry.get(&self.name))
            .is_some_and(|rules| rules.iter().any(|rule| rule.should_resolve_ip()))
    }

    fn should_resolve_process(&self) -> bool {
        if self.condition.should_resolve_process() {
            return true;
        }
        self.registry
            .get()
            .and_then(|registry| registry.get(&self.name))
            .is_some_and(|rules| {
                rules.iter().any(|rule| rule.should_resolve_process())
            })
    }
}
