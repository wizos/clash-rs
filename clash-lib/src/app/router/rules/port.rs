use crate::{app::router::rules::RuleMatcher, session::Session};

#[derive(Clone)]
pub struct Port {
    pub payload: String,
    pub port_ranges: Vec<(u16, u16)>,
    pub target: String,
    pub kind: PortKind,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum PortKind {
    Source,
    Destination,
    Inbound,
}

impl std::fmt::Display for Port {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "{} {} port {}",
            self.target,
            match self.kind {
                PortKind::Source => "src",
                PortKind::Destination => "dst",
                PortKind::Inbound => "inbound",
            },
            self.payload
        )
    }
}

impl RuleMatcher for Port {
    fn apply(&self, sess: &Session) -> bool {
        let port = match self.kind {
            PortKind::Source => sess.source.port(),
            PortKind::Destination => sess.destination.port(),
            PortKind::Inbound => sess.inbound_port,
        };
        self.port_ranges
            .iter()
            .any(|(start, end)| (*start..=*end).contains(&port))
    }

    fn target(&self) -> &str {
        self.target.as_str()
    }

    fn payload(&self) -> String {
        self.payload.clone()
    }

    fn type_name(&self) -> &str {
        "Port"
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::session::SocksAddr;

    #[test]
    fn matches_port_ranges() {
        let matcher = Port {
            payload: "80/443/1000-2000".to_string(),
            port_ranges: vec![(80, 80), (443, 443), (1000, 2000)],
            target: "PROXY".to_string(),
            kind: PortKind::Destination,
        };
        let session = Session {
            destination: SocksAddr::Domain("example.com".to_string(), 1443),
            ..Default::default()
        };

        assert!(matcher.apply(&session));
    }

    #[test]
    fn matches_inbound_port() {
        let matcher = Port {
            payload: "7890".to_string(),
            port_ranges: vec![(7890, 7890)],
            target: "PROXY".to_string(),
            kind: PortKind::Inbound,
        };
        let session = Session {
            inbound_port: 7890,
            ..Default::default()
        };

        assert!(matcher.apply(&session));
    }
}
