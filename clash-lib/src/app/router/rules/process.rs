use super::RuleMatcher;
use std::path::Path;

pub struct Process {
    pub name: String,
    pub target: String,
    pub name_only: bool,
    pub regex: Option<regex::Regex>,
    pub wildcard: bool,
}

impl Process {
    #[allow(dead_code)]
    fn matches_process(&self, process_path: &str) -> bool {
        let candidate = if self.name_only {
            Path::new(process_path)
                .file_name()
                .and_then(|name| name.to_str())
                .unwrap_or(process_path)
        } else {
            process_path
        };

        match &self.regex {
            Some(regex) => regex.is_match(candidate),
            None if self.wildcard => super::wildcard::matches(&self.name, candidate),
            None => candidate.eq_ignore_ascii_case(&self.name),
        }
    }
}

impl std::fmt::Display for Process {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{} process {}", self.target, self.name)
    }
}

impl RuleMatcher for Process {
    fn apply(&self, sess: &crate::session::Session) -> bool {
        let resolved = if self.name_only {
            &sess.process
        } else if sess.process_path.is_empty() {
            &sess.process
        } else {
            &sess.process_path
        };
        if !resolved.is_empty() {
            return self.matches_process(resolved);
        }

        #[cfg(any(target_os = "linux", target_os = "macos", target_os = "windows"))]
        {
            use crate::session::Network;
            use tracing::debug;

            sock2proc::find_process_name(
                Some(sess.source),
                sess.destination.clone().try_into_socket_addr(),
                match sess.network {
                    Network::Tcp => sock2proc::NetworkProtocol::TCP,
                    Network::Udp => sock2proc::NetworkProtocol::UDP,
                },
            )
            .is_some_and(|proc| {
                debug!("Matching process name: {} with {}", proc, self.name);
                self.matches_process(&proc)
            })
        }
        #[cfg(not(any(
            target_os = "linux",
            target_os = "macos",
            target_os = "windows"
        )))]
        {
            use tracing::info;

            info!("PROCESS-NAME not supported on this platform: {}", &sess);
            false
        }
    }

    fn target(&self) -> &str {
        &self.target
    }

    fn payload(&self) -> String {
        self.name.clone()
    }

    fn type_name(&self) -> &str {
        match (self.name_only, self.regex.is_some(), self.wildcard) {
            (true, true, _) => "ProcessNameRegex",
            (false, true, _) => "ProcessPathRegex",
            (true, false, true) => "ProcessNameWildcard",
            (false, false, true) => "ProcessPathWildcard",
            (true, false, false) => "ProcessName",
            (false, false, false) => "ProcessPath",
        }
    }

    fn should_resolve_process(&self) -> bool {
        true
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn matcher(name: &str, name_only: bool, regex: bool) -> Process {
        Process {
            name: name.to_string(),
            target: "PROXY".to_string(),
            name_only,
            regex: regex.then(|| regex::Regex::new(name).unwrap()),
            wildcard: false,
        }
    }

    #[test]
    fn matches_exact_process_name_from_full_path() {
        assert!(matcher("wget", true, false).matches_process("/usr/bin/wget"));
        assert!(!matcher("get", true, false).matches_process("/usr/bin/wget"));
    }

    #[test]
    fn matches_exact_process_path() {
        assert!(
            matcher("/usr/bin/wget", false, false).matches_process("/usr/bin/wget")
        );
        assert!(!matcher("bin/wget", false, false).matches_process("/usr/bin/wget"));
    }

    #[test]
    fn matches_process_regular_expressions() {
        assert!(matcher("(?i)WGET$", true, true).matches_process("/usr/bin/wget"));
        assert!(matcher(".*bin/wget", false, true).matches_process("/usr/bin/wget"));
    }

    #[test]
    fn matches_process_wildcard_case_insensitively() {
        let mut process = matcher("*Telegram*", true, false);
        process.wildcard = true;
        assert!(process.matches_process("/usr/bin/telegram-desktop"));
    }
}
