use super::RuleMatcher;
use crate::session::{Session, Type};

pub struct InboundType {
    pub inbound_types: Vec<String>,
    pub target: String,
}

impl std::fmt::Display for InboundType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{} inbound type {}", self.target, self.payload())
    }
}

impl RuleMatcher for InboundType {
    fn apply(&self, sess: &Session) -> bool {
        self.inbound_types.iter().any(|candidate| {
            sess.typ
                .inbound_type()
                .eq_ignore_ascii_case(candidate.as_str())
        })
    }

    fn target(&self) -> &str {
        &self.target
    }

    fn payload(&self) -> String {
        self.inbound_types.join("/")
    }

    fn type_name(&self) -> &str {
        "InboundType"
    }
}

pub struct InboundUser {
    pub inbound_users: Vec<String>,
    pub target: String,
}

pub struct InboundName {
    pub inbound_names: Vec<String>,
    pub target: String,
}

impl std::fmt::Display for InboundName {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{} inbound name {}", self.target, self.payload())
    }
}

impl RuleMatcher for InboundName {
    fn apply(&self, sess: &Session) -> bool {
        self.inbound_names
            .iter()
            .any(|name| name == &sess.inbound_name)
    }

    fn target(&self) -> &str {
        &self.target
    }

    fn payload(&self) -> String {
        self.inbound_names.join("/")
    }

    fn type_name(&self) -> &str {
        "InboundName"
    }
}

impl std::fmt::Display for InboundUser {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{} inbound user {}", self.target, self.payload())
    }
}

impl RuleMatcher for InboundUser {
    fn apply(&self, sess: &Session) -> bool {
        sess.inbound_user.as_ref().is_some_and(|user| {
            self.inbound_users.iter().any(|candidate| candidate == user)
        })
    }

    fn target(&self) -> &str {
        &self.target
    }

    fn payload(&self) -> String {
        self.inbound_users.join("/")
    }

    fn type_name(&self) -> &str {
        "InboundUser"
    }
}

impl Type {
    pub(crate) fn inbound_type(self) -> &'static str {
        match self {
            Type::Http | Type::HttpConnect => "HTTP",
            Type::Socks5 => "SOCKS",
            #[cfg(feature = "tun")]
            Type::Tun => "TUN",
            #[cfg(all(target_os = "linux", feature = "tproxy"))]
            Type::Tproxy => "TPROXY",
            #[cfg(all(target_os = "linux", feature = "redir"))]
            Type::Redir => "REDIR",
            Type::Tunnel => "TUNNEL",
            Type::Shadowsocks => "SHADOWSOCKS",
            Type::Anytls => "ANYTLS",
            Type::Hysteria2 => "HYSTERIA2",
            Type::Ignore => "INNER",
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn matches_multiple_inbound_types_case_insensitively() {
        let matcher = InboundType {
            inbound_types: vec!["SOCKS".to_string(), "HTTP".to_string()],
            target: "PROXY".to_string(),
        };
        let session = Session {
            typ: Type::HttpConnect,
            ..Default::default()
        };

        assert!(matcher.apply(&session));
    }

    #[test]
    fn matches_authenticated_inbound_user() {
        let matcher = InboundUser {
            inbound_users: vec!["alice".to_string(), "bob".to_string()],
            target: "DIRECT".to_string(),
        };
        let session = Session {
            inbound_user: Some("bob".to_string()),
            ..Default::default()
        };

        assert!(matcher.apply(&session));
    }
}
