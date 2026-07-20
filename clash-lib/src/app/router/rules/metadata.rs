use crate::{app::router::rules::RuleMatcher, session::Session};

#[derive(Clone, Copy)]
pub enum MetadataKind {
    Uid,
    Dscp,
}

pub struct Metadata {
    pub payload: String,
    pub ranges: Vec<(u32, u32)>,
    pub target: String,
    pub kind: MetadataKind,
}

impl std::fmt::Display for Metadata {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{} {} {}", self.target, self.type_name(), self.payload)
    }
}

impl RuleMatcher for Metadata {
    fn apply(&self, sess: &Session) -> bool {
        let value = match self.kind {
            MetadataKind::Uid => sess.uid,
            MetadataKind::Dscp => u32::from(sess.dscp),
        };

        self.ranges
            .iter()
            .any(|(start, end)| (*start..=*end).contains(&value))
    }

    fn target(&self) -> &str {
        &self.target
    }

    fn payload(&self) -> String {
        self.payload.clone()
    }

    fn type_name(&self) -> &str {
        match self.kind {
            MetadataKind::Uid => "Uid",
            MetadataKind::Dscp => "Dscp",
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn matches_uid_and_dscp_ranges() {
        let session = Session {
            uid: 10_001,
            dscp: 16,
            ..Default::default()
        };
        assert!(
            Metadata {
                payload: "10000-19999".to_string(),
                ranges: vec![(10_000, 19_999)],
                target: "DIRECT".to_string(),
                kind: MetadataKind::Uid,
            }
            .apply(&session)
        );
        assert!(
            Metadata {
                payload: "8-16".to_string(),
                ranges: vec![(8, 16)],
                target: "PROXY".to_string(),
                kind: MetadataKind::Dscp,
            }
            .apply(&session)
        );
    }
}
