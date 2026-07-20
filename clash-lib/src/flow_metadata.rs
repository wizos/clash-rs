use std::{
    collections::HashMap,
    net::SocketAddr,
    sync::{Mutex, OnceLock},
    time::{Duration, Instant},
};

use crate::session::Network;

const MAX_FLOWS: usize = 4096;
const FLOW_TTL: Duration = Duration::from_secs(300);

#[derive(Clone, Copy, Eq, Hash, PartialEq)]
struct FlowKey {
    network: Network,
    source: SocketAddr,
    destination: SocketAddr,
}

#[derive(Clone, Copy)]
struct FlowValue {
    dscp: u8,
    updated_at: Instant,
}

fn flows() -> &'static Mutex<HashMap<FlowKey, FlowValue>> {
    static FLOWS: OnceLock<Mutex<HashMap<FlowKey, FlowValue>>> = OnceLock::new();
    FLOWS.get_or_init(|| Mutex::new(HashMap::new()))
}

pub fn record_dscp(
    network: Network,
    source: SocketAddr,
    destination: SocketAddr,
    dscp: u8,
) {
    let now = Instant::now();
    let mut flows = flows().lock().expect("flow metadata lock poisoned");
    if flows.len() >= MAX_FLOWS {
        flows.retain(|_, value| now.duration_since(value.updated_at) < FLOW_TTL);
        if flows.len() >= MAX_FLOWS
            && let Some(oldest) = flows
                .iter()
                .min_by_key(|(_, value)| value.updated_at)
                .map(|(key, _)| *key)
        {
            flows.remove(&oldest);
        }
    }
    flows.insert(
        FlowKey {
            network,
            source,
            destination,
        },
        FlowValue {
            dscp,
            updated_at: now,
        },
    );
}

pub fn dscp(
    network: Network,
    source: SocketAddr,
    destination: SocketAddr,
) -> Option<u8> {
    flows()
        .lock()
        .expect("flow metadata lock poisoned")
        .get(&FlowKey {
            network,
            source,
            destination,
        })
        .map(|value| value.dscp)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn records_dscp_by_flow_tuple() {
        let source = "10.0.0.2:12345".parse().unwrap();
        let destination = "1.1.1.1:443".parse().unwrap();
        record_dscp(Network::Udp, source, destination, 46);
        assert_eq!(dscp(Network::Udp, source, destination), Some(46));
    }
}
