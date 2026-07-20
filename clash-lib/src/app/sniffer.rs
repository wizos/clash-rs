use crate::{
    Error,
    config::def::SnifferConfig,
    proxy::ClientStream,
    session::{Session, SocksAddr},
};
use ipnet::IpNet;
use std::{
    collections::HashMap,
    io,
    net::{IpAddr, SocketAddr},
    pin::Pin,
    str::FromStr,
    sync::{
        Mutex,
        atomic::{AtomicBool, Ordering},
    },
    task::{Context, Poll},
    time::Duration,
};
use tokio::{
    io::{AsyncRead, AsyncReadExt, AsyncWrite, ReadBuf},
    time::{Instant, timeout},
};
use tracing::debug;

const SNIFF_TIMEOUT: Duration = Duration::from_secs(1);
const MAX_SNIFF_BYTES: usize = 64 * 1024 + 5;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Protocol {
    Http,
    Tls,
    Quic,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum UdpSniffStatus {
    NotApplicable,
    Pending,
    Matched,
}

impl Protocol {
    fn from_name(name: &str) -> Option<Self> {
        match name.to_ascii_uppercase().as_str() {
            "HTTP" => Some(Self::Http),
            "TLS" => Some(Self::Tls),
            "QUIC" => Some(Self::Quic),
            _ => None,
        }
    }

    fn default_port(self) -> u16 {
        match self {
            Self::Http => 80,
            Self::Tls | Self::Quic => 443,
        }
    }

    fn supports_tcp(self) -> bool {
        matches!(self, Self::Http | Self::Tls)
    }
}

#[derive(Clone, Copy, Debug)]
struct PortRange {
    start: u16,
    end: u16,
}

impl PortRange {
    fn contains(self, port: u16) -> bool {
        self.start <= port && port <= self.end
    }
}

#[derive(Debug)]
struct ProtocolConfig {
    protocol: Protocol,
    ports: Vec<PortRange>,
    override_destination: bool,
}

impl ProtocolConfig {
    fn supports_port(&self, port: u16) -> bool {
        self.ports.iter().any(|range| range.contains(port))
    }
}

#[derive(Debug)]
enum DomainPattern {
    Exact(String),
    Suffix(String),
    Wildcard(String),
}

impl DomainPattern {
    fn new(pattern: &str) -> Self {
        let pattern = pattern.trim().to_ascii_lowercase();
        if let Some(suffix) = pattern.strip_prefix("+.") {
            Self::Suffix(suffix.to_string())
        } else if pattern.contains(['*', '?']) {
            Self::Wildcard(pattern)
        } else {
            Self::Exact(pattern)
        }
    }

    fn matches(&self, domain: &str) -> bool {
        let domain = domain.to_ascii_lowercase();
        match self {
            Self::Exact(exact) => domain == *exact,
            Self::Suffix(suffix) => {
                domain == *suffix || domain.ends_with(&format!(".{suffix}"))
            }
            Self::Wildcard(pattern) => wildcard_matches(pattern, &domain),
        }
    }
}

fn wildcard_matches(pattern: &str, value: &str) -> bool {
    let pattern = pattern.chars().collect::<Vec<_>>();
    let value = value.chars().collect::<Vec<_>>();
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

/// Runtime implementation of Mihomo's sniffer block.
pub struct Sniffer {
    enabled: AtomicBool,
    protocols: Vec<ProtocolConfig>,
    force_domain: Vec<DomainPattern>,
    skip_domain: Vec<DomainPattern>,
    skip_src_address: Vec<IpNet>,
    skip_dst_address: Vec<IpNet>,
    force_dns_mapping: bool,
    parse_pure_ip: bool,
    quic_flows: Mutex<HashMap<QuicFlowKey, QuicFlow>>,
}

impl Sniffer {
    pub(crate) fn validate_config(
        config: Option<&SnifferConfig>,
    ) -> Result<(), Error> {
        Self::from_config(config).map(|_| ())
    }

    pub(crate) fn from_config(
        config: Option<&SnifferConfig>,
    ) -> Result<Option<Self>, Error> {
        let Some(config) = config else {
            return Ok(None);
        };

        let mut protocols = Vec::new();
        if config.sniff.is_empty() {
            for name in &config.sniffing {
                let protocol = parse_protocol(name)?;
                let ports = parse_ports(&config.ports, protocol.default_port())?;
                protocols.push(ProtocolConfig {
                    protocol,
                    ports,
                    override_destination: config.override_dest,
                });
            }
        } else {
            let mut entries = config.sniff.iter().collect::<Vec<_>>();
            entries.sort_by(|(left, _), (right, _)| left.cmp(right));
            for (name, protocol_config) in entries {
                let protocol = parse_protocol(name)?;
                protocols.push(ProtocolConfig {
                    protocol,
                    ports: parse_ports(
                        &protocol_config.ports,
                        protocol.default_port(),
                    )?,
                    override_destination: protocol_config
                        .override_destination
                        .unwrap_or(config.override_dest),
                });
            }
        }

        Ok(Some(Self {
            enabled: AtomicBool::new(config.enable),
            protocols,
            force_domain: config
                .force_domain
                .iter()
                .map(|pattern| DomainPattern::new(pattern))
                .collect(),
            skip_domain: config
                .skip_domain
                .iter()
                .map(|pattern| DomainPattern::new(pattern))
                .collect(),
            skip_src_address: parse_networks(
                &config.skip_src_address,
                "sniffer.skip-src-address",
            )?,
            skip_dst_address: parse_networks(
                &config.skip_dst_address,
                "sniffer.skip-dst-address",
            )?,
            force_dns_mapping: config.force_dns_mapping,
            parse_pure_ip: config.parse_pure_ip,
            quic_flows: Mutex::new(HashMap::new()),
        }))
    }

    pub(crate) fn set_enabled(&self, enabled: bool) {
        self.enabled.store(enabled, Ordering::Relaxed);
    }

    /// Inspect the first TCP application bytes and return a stream which
    /// replays every byte consumed by inspection before delegating to the
    /// original stream.
    pub(crate) async fn sniff_tcp(
        &self,
        sess: &mut Session,
        original_destination: &SocksAddr,
        mut stream: Box<dyn ClientStream>,
    ) -> Box<dyn ClientStream> {
        let port = original_destination.port();
        let candidates = self
            .protocols
            .iter()
            .filter(|config| {
                config.protocol.supports_tcp() && config.supports_port(port)
            })
            .collect::<Vec<_>>();

        if candidates.is_empty() || !self.should_sniff(sess, original_destination) {
            return stream;
        }

        let deadline = Instant::now() + SNIFF_TIMEOUT;
        let mut prefix = Vec::with_capacity(1024);
        let sniffed = loop {
            let mut need_more = prefix.is_empty();
            let mut result = None;

            for candidate in &candidates {
                match parse_tcp(candidate.protocol, &prefix) {
                    ParseResult::Matched(host) => {
                        result = Some((host, candidate.override_destination));
                        break;
                    }
                    ParseResult::NeedMore => need_more = true,
                    ParseResult::NoMatch => {}
                }
            }

            if result.is_some() || !need_more || prefix.len() >= MAX_SNIFF_BYTES {
                break result;
            }

            let remaining = deadline.saturating_duration_since(Instant::now());
            if remaining.is_zero() {
                break None;
            }
            let mut buffer = [0u8; 4096];
            let read = timeout(remaining, stream.read(&mut buffer)).await;
            match read {
                Ok(Ok(0)) | Ok(Err(_)) | Err(_) => break None,
                Ok(Ok(size)) => prefix.extend_from_slice(&buffer[..size]),
            }
        };

        if let Some((host, override_destination)) = sniffed
            && self.domain_can_replace(&host)
        {
            let host = host.to_ascii_lowercase();
            debug!("sniffed TCP host {host} for {}", sess.destination);
            sess.sniff_host.clone_from(&host);
            if override_destination {
                sess.destination = SocksAddr::Domain(host, port);
                sess.resolved_ip = None;
            }
        }

        if prefix.is_empty() {
            stream
        } else {
            Box::new(ReplayStream::new(prefix, stream))
        }
    }

    /// Inspect a QUIC Initial packet. The CRYPTO stream is reassembled across
    /// packets so fragmented ClientHello messages can still expose their SNI.
    pub(crate) fn sniff_udp(
        &self,
        sess: &mut Session,
        original_destination: &SocksAddr,
        packet: &[u8],
    ) -> UdpSniffStatus {
        let Some(config) = self.protocols.iter().find(|config| {
            config.protocol == Protocol::Quic
                && config.supports_port(original_destination.port())
        }) else {
            return UdpSniffStatus::NotApplicable;
        };
        if !self.should_sniff(sess, original_destination) {
            return UdpSniffStatus::NotApplicable;
        }

        let key = QuicFlowKey {
            source: sess.source,
            destination: original_destination.clone(),
        };
        let now = Instant::now();
        let state = {
            let Ok(mut flows) = self.quic_flows.lock() else {
                return UdpSniffStatus::NotApplicable;
            };
            flows.retain(|_, flow| {
                now.duration_since(flow.updated) < Duration::from_secs(3)
            });
            if flows.len() >= 128
                && !flows.contains_key(&key)
                && let Some(expired) = flows.keys().next().cloned()
            {
                flows.remove(&expired);
            }

            if let Some(flow) = flows.get(&key) {
                match &flow.state {
                    QuicFlowState::Matched(host) => {
                        return self.apply_quic_host(
                            sess,
                            original_destination,
                            config.override_destination,
                            host,
                        );
                    }
                    QuicFlowState::Bypass => {
                        return UdpSniffStatus::NotApplicable;
                    }
                    QuicFlowState::Pending => {}
                }
            }

            let fragments = match decrypt_quic_initial(packet) {
                Ok(fragments) => fragments,
                Err(_) if flows.contains_key(&key) => Vec::new(),
                Err(_) => return UdpSniffStatus::NotApplicable,
            };
            let flow = flows
                .entry(key.clone())
                .or_insert_with(|| QuicFlow::new(now));
            for fragment in fragments {
                flow.insert(fragment.offset, &fragment.data, now);
            }
            let host = flow.try_host();
            if let Some(host) = host {
                if self.domain_can_replace(&host) {
                    flow.state = QuicFlowState::Matched(host.clone());
                    QuicFlowState::Matched(host)
                } else {
                    flow.state = QuicFlowState::Bypass;
                    QuicFlowState::Bypass
                }
            } else {
                QuicFlowState::Pending
            }
        };

        match state {
            QuicFlowState::Matched(host) => self.apply_quic_host(
                sess,
                original_destination,
                config.override_destination,
                &host,
            ),
            QuicFlowState::Pending => UdpSniffStatus::Pending,
            QuicFlowState::Bypass => UdpSniffStatus::NotApplicable,
        }
    }

    pub(crate) fn finish_udp_wait(
        &self,
        sess: &Session,
        original_destination: &SocksAddr,
    ) {
        let key = QuicFlowKey {
            source: sess.source,
            destination: original_destination.clone(),
        };
        if let Ok(mut flows) = self.quic_flows.lock()
            && let Some(flow) = flows.get_mut(&key)
            && matches!(flow.state, QuicFlowState::Pending)
        {
            flow.state = QuicFlowState::Bypass;
            flow.updated = Instant::now();
        }
    }

    pub(crate) fn udp_wait_timeout(&self) -> Duration {
        SNIFF_TIMEOUT
    }

    fn apply_quic_host(
        &self,
        sess: &mut Session,
        original_destination: &SocksAddr,
        override_destination: bool,
        host: &str,
    ) -> UdpSniffStatus {
        let host = host.to_ascii_lowercase();
        debug!("sniffed QUIC host {host} for {}", sess.destination);
        sess.sniff_host.clone_from(&host);
        if override_destination {
            sess.destination = SocksAddr::Domain(host, original_destination.port());
            sess.resolved_ip = None;
        }
        UdpSniffStatus::Matched
    }

    fn should_sniff(
        &self,
        sess: &Session,
        original_destination: &SocksAddr,
    ) -> bool {
        if !self.enabled.load(Ordering::Relaxed)
            || self
                .skip_src_address
                .iter()
                .any(|network| network.contains(&sess.source.ip()))
            || original_destination.ip().is_some_and(|ip| {
                self.skip_dst_address
                    .iter()
                    .any(|network| network.contains(&ip))
            })
        {
            return false;
        }

        let original_was_ip = matches!(original_destination, SocksAddr::Ip(_));
        (original_was_ip && self.parse_pure_ip)
            || (original_was_ip
                && sess.destination.is_domain()
                && self.force_dns_mapping)
            || sess.destination.domain().is_some_and(|domain| {
                self.force_domain
                    .iter()
                    .any(|pattern| pattern.matches(domain))
            })
    }

    fn domain_can_replace(&self, host: &str) -> bool {
        is_domain_name(host)
            && !self.skip_domain.iter().any(|pattern| pattern.matches(host))
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Hash)]
struct QuicFlowKey {
    source: SocketAddr,
    destination: SocksAddr,
}

struct QuicFlow {
    data: Vec<u8>,
    ranges: Vec<(usize, usize)>,
    updated: Instant,
    state: QuicFlowState,
}

#[derive(Clone, Debug)]
enum QuicFlowState {
    Pending,
    Matched(String),
    Bypass,
}

impl QuicFlow {
    fn new(now: Instant) -> Self {
        Self {
            data: Vec::new(),
            ranges: Vec::new(),
            updated: now,
            state: QuicFlowState::Pending,
        }
    }

    fn insert(&mut self, offset: usize, data: &[u8], now: Instant) {
        let end = offset + data.len();
        if end > 16 * 1024 {
            return;
        }
        if self.data.len() < end {
            self.data.resize(end, 0);
        }
        self.data[offset..end].copy_from_slice(data);
        self.ranges.push((offset, end));
        self.ranges.sort_unstable_by_key(|range| range.0);
        let mut merged: Vec<(usize, usize)> = Vec::with_capacity(self.ranges.len());
        for (start, end) in self.ranges.drain(..) {
            if let Some(last) = merged.last_mut()
                && start <= last.1
            {
                last.1 = last.1.max(end);
                continue;
            }
            merged.push((start, end));
        }
        self.ranges = merged;
        self.updated = now;
    }

    fn try_host(&self) -> Option<String> {
        let covered = self
            .ranges
            .first()
            .filter(|range| range.0 == 0)
            .map(|range| range.1)?;
        if covered < 4 || self.data[0] != 0x01 {
            return None;
        }
        let length = ((self.data[1] as usize) << 16)
            | ((self.data[2] as usize) << 8)
            | self.data[3] as usize;
        if covered < 4 + length {
            return None;
        }
        match parse_client_hello(&self.data[4..4 + length]) {
            ParseResult::Matched(host) => Some(host),
            ParseResult::NeedMore | ParseResult::NoMatch => None,
        }
    }
}

struct CryptoFragment {
    offset: usize,
    data: Vec<u8>,
}

/// Decode a complete QUIC Initial packet and return the ClientHello SNI.
/// Exposed for compatibility probes and packet-corpus regression tests.
#[doc(hidden)]
pub fn sniff_quic_initial_host(packet: &[u8]) -> Option<String> {
    let fragments = decrypt_quic_initial(packet).ok()?;
    let now = Instant::now();
    let mut flow = QuicFlow::new(now);
    for fragment in fragments {
        flow.insert(fragment.offset, &fragment.data, now);
    }
    flow.try_host()
}

fn decrypt_quic_initial(packet: &[u8]) -> Result<Vec<CryptoFragment>, ()> {
    if packet.len() < 7 || packet[0] & 0xc0 != 0xc0 {
        return Err(());
    }
    let version_number =
        u32::from_be_bytes([packet[1], packet[2], packet[3], packet[4]]);
    let version = match version_number {
        0x0000_0001 => rustls::quic::Version::V1,
        0xff00_001d => rustls::quic::Version::V1Draft,
        _ => return Err(()),
    };
    // Initial is type 0 for QUIC v1 and draft-29. These bits are not protected.
    if packet[0] & 0x30 != 0 {
        return Ok(Vec::new());
    }

    let mut position = 5;
    let destination_id_len = *packet.get(position).ok_or(())? as usize;
    position += 1;
    if destination_id_len == 0 || position + destination_id_len > packet.len() {
        return Err(());
    }
    let destination_id = &packet[position..position + destination_id_len];
    position += destination_id_len;
    let source_id_len = *packet.get(position).ok_or(())? as usize;
    position += 1;
    if position + source_id_len > packet.len() {
        return Err(());
    }
    position += source_id_len;
    let token_len = read_quic_varint(packet, &mut position)? as usize;
    if position + token_len > packet.len() {
        return Err(());
    }
    position += token_len;
    let packet_len = read_quic_varint(packet, &mut position)? as usize;
    let packet_number_offset = position;
    if packet_number_offset + packet_len > packet.len()
        || packet_number_offset + 4 > packet.len()
    {
        return Err(());
    }

    let suite = initial_quic_suite().ok_or(())?;
    let keys = suite.keys(destination_id, rustls::Side::Server, version);
    let sample_len = keys.remote.header.sample_len();
    let sample_start = packet_number_offset + 4;
    if sample_start + sample_len > packet.len() {
        return Err(());
    }
    let mut first = packet[0];
    let mut packet_number = [0u8; 4];
    packet_number
        .copy_from_slice(&packet[packet_number_offset..packet_number_offset + 4]);
    keys.remote
        .header
        .decrypt_in_place(
            &packet[sample_start..sample_start + sample_len],
            &mut first,
            &mut packet_number,
        )
        .map_err(|_| ())?;
    let packet_number_len = (first & 0x03) as usize + 1;
    let header_len = packet_number_offset + packet_number_len;
    if header_len > packet_number_offset + packet_len {
        return Err(());
    }
    let mut header = packet[..header_len].to_vec();
    header[0] = first;
    header[packet_number_offset..header_len]
        .copy_from_slice(&packet_number[..packet_number_len]);
    let packet_number = packet_number[..packet_number_len]
        .iter()
        .fold(0u64, |value, byte| (value << 8) | u64::from(*byte));
    let mut payload = packet[header_len..packet_number_offset + packet_len].to_vec();
    let decrypted = keys
        .remote
        .packet
        .decrypt_in_place(packet_number, &header, &mut payload)
        .map_err(|_| ())?;
    parse_quic_initial_frames(decrypted)
}

fn initial_quic_suite() -> Option<rustls::quic::Suite> {
    #[cfg(feature = "ring")]
    let provider = rustls::crypto::ring::default_provider();
    #[cfg(all(not(feature = "ring"), feature = "aws-lc-rs"))]
    let provider = rustls::crypto::aws_lc_rs::default_provider();
    #[cfg(not(any(feature = "ring", feature = "aws-lc-rs")))]
    return None;

    #[cfg(any(feature = "ring", feature = "aws-lc-rs"))]
    provider.cipher_suites.iter().find_map(|suite| {
        (suite.suite() == rustls::CipherSuite::TLS13_AES_128_GCM_SHA256)
            .then(|| suite.tls13())
            .flatten()
            .and_then(|suite| suite.quic_suite())
    })
}

fn parse_quic_initial_frames(data: &[u8]) -> Result<Vec<CryptoFragment>, ()> {
    let mut position = 0;
    let mut fragments = Vec::new();
    while position < data.len() {
        let frame_type = read_quic_varint(data, &mut position)?;
        match frame_type {
            0x00 | 0x01 => {}
            0x02 | 0x03 => skip_ack_frame(data, &mut position, frame_type == 0x03)?,
            0x06 => {
                let offset = read_quic_varint(data, &mut position)? as usize;
                let length = read_quic_varint(data, &mut position)? as usize;
                if offset + length > 16 * 1024 || position + length > data.len() {
                    return Err(());
                }
                fragments.push(CryptoFragment {
                    offset,
                    data: data[position..position + length].to_vec(),
                });
                position += length;
            }
            0x1c => {
                let _error_code = read_quic_varint(data, &mut position)?;
                let _frame_type = read_quic_varint(data, &mut position)?;
                let reason_len = read_quic_varint(data, &mut position)? as usize;
                if position + reason_len > data.len() {
                    return Err(());
                }
                position += reason_len;
            }
            _ => return Err(()),
        }
    }
    Ok(fragments)
}

fn skip_ack_frame(data: &[u8], position: &mut usize, ecn: bool) -> Result<(), ()> {
    let _largest = read_quic_varint(data, position)?;
    let _delay = read_quic_varint(data, position)?;
    let range_count = read_quic_varint(data, position)?;
    let _first_range = read_quic_varint(data, position)?;
    for _ in 0..range_count {
        let _gap = read_quic_varint(data, position)?;
        let _range = read_quic_varint(data, position)?;
    }
    if ecn {
        let _ect0 = read_quic_varint(data, position)?;
        let _ect1 = read_quic_varint(data, position)?;
        let _ce = read_quic_varint(data, position)?;
    }
    Ok(())
}

fn read_quic_varint(data: &[u8], position: &mut usize) -> Result<u64, ()> {
    let first = *data.get(*position).ok_or(())?;
    let length = 1usize << (first >> 6);
    if *position + length > data.len() {
        return Err(());
    }
    let mut value = u64::from(first & 0x3f);
    for byte in &data[*position + 1..*position + length] {
        value = (value << 8) | u64::from(*byte);
    }
    *position += length;
    Ok(value)
}

fn parse_protocol(name: &str) -> Result<Protocol, Error> {
    Protocol::from_name(name).ok_or_else(|| {
        Error::InvalidConfig(format!("unknown sniffer protocol `{name}`"))
    })
}

fn parse_ports(values: &[String], default: u16) -> Result<Vec<PortRange>, Error> {
    if values.is_empty() {
        return Ok(vec![PortRange {
            start: default,
            end: default,
        }]);
    }

    let mut ranges = Vec::new();
    for value in values {
        for value in value.split(',') {
            let value = value.trim();
            if value.is_empty() {
                continue;
            }
            let (start, end) = if let Some((start, end)) = value.split_once('-') {
                (start.trim().parse::<u16>(), end.trim().parse::<u16>())
            } else {
                let port = value.parse::<u16>();
                (port.clone(), port)
            };
            let start = start.map_err(|_| invalid_port(value))?;
            let end = end.map_err(|_| invalid_port(value))?;
            if start > end {
                return Err(invalid_port(value));
            }
            ranges.push(PortRange { start, end });
        }
    }

    if ranges.is_empty() {
        Err(Error::InvalidConfig(
            "sniffer port list cannot be empty".to_string(),
        ))
    } else {
        Ok(ranges)
    }
}

fn invalid_port(value: &str) -> Error {
    Error::InvalidConfig(format!("invalid sniffer port or range `{value}`"))
}

fn parse_networks(values: &[String], field: &str) -> Result<Vec<IpNet>, Error> {
    values
        .iter()
        .map(|value| {
            if let Ok(network) = IpNet::from_str(value) {
                return Ok(network);
            }
            let ip = IpAddr::from_str(value).map_err(|_| {
                Error::InvalidConfig(format!("invalid {field} value `{value}`"))
            })?;
            Ok(IpNet::from(ip))
        })
        .collect()
}

fn parse_tcp(protocol: Protocol, bytes: &[u8]) -> ParseResult {
    match protocol {
        Protocol::Http => parse_http(bytes),
        Protocol::Tls => parse_tls(bytes),
        Protocol::Quic => ParseResult::NoMatch,
    }
}

enum ParseResult {
    Matched(String),
    NeedMore,
    NoMatch,
}

fn parse_http(bytes: &[u8]) -> ParseResult {
    const METHODS: [&[u8]; 9] = [
        b"GET", b"POST", b"HEAD", b"PUT", b"DELETE", b"OPTIONS", b"CONNECT",
        b"PATCH", b"TRACE",
    ];

    if bytes.is_empty() {
        return ParseResult::NeedMore;
    }
    let method_end = match bytes.iter().position(|byte| *byte == b' ') {
        Some(position) => position,
        None => {
            let possible = METHODS.iter().any(|method| {
                bytes.len() <= method.len()
                    && method[..bytes.len()].eq_ignore_ascii_case(bytes)
            });
            return if possible {
                ParseResult::NeedMore
            } else {
                ParseResult::NoMatch
            };
        }
    };
    if !METHODS
        .iter()
        .any(|method| method.eq_ignore_ascii_case(&bytes[..method_end]))
    {
        return ParseResult::NoMatch;
    }

    let Some(header_end) = bytes.windows(4).position(|window| window == b"\r\n\r\n")
    else {
        return ParseResult::NeedMore;
    };
    let headers = &bytes[..header_end + 2];
    for line in headers.split(|byte| *byte == b'\n').skip(1) {
        let line = line.strip_suffix(b"\r").unwrap_or(line);
        let Some(separator) = line.iter().position(|byte| *byte == b':') else {
            continue;
        };
        if !line[..separator].eq_ignore_ascii_case(b"host") {
            continue;
        }
        let Ok(host) = std::str::from_utf8(&line[separator + 1..]) else {
            return ParseResult::NoMatch;
        };
        let mut host = host.trim().to_string();
        if host.starts_with('[') && host.contains(']') {
            return ParseResult::NoMatch;
        }
        if let Some((candidate, port)) = host.rsplit_once(':')
            && !candidate.contains(':')
            && port.parse::<u16>().is_ok()
        {
            host = candidate.to_string();
        }
        return if is_domain_name(&host) {
            ParseResult::Matched(host)
        } else {
            ParseResult::NoMatch
        };
    }
    ParseResult::NoMatch
}

fn parse_tls(bytes: &[u8]) -> ParseResult {
    if bytes.len() < 5 {
        return ParseResult::NeedMore;
    }
    if bytes[0] != 0x16 || bytes[1] != 0x03 {
        return ParseResult::NoMatch;
    }
    let record_len = u16::from_be_bytes([bytes[3], bytes[4]]) as usize;
    if bytes.len() < 5 + record_len {
        return ParseResult::NeedMore;
    }
    let handshake = &bytes[5..5 + record_len];
    if handshake.len() < 4 || handshake[0] != 0x01 {
        return ParseResult::NoMatch;
    }
    let handshake_len = ((handshake[1] as usize) << 16)
        | ((handshake[2] as usize) << 8)
        | handshake[3] as usize;
    if handshake.len() < 4 + handshake_len {
        return ParseResult::NeedMore;
    }
    parse_client_hello(&handshake[4..4 + handshake_len])
}

fn parse_client_hello(data: &[u8]) -> ParseResult {
    if data.len() < 35 {
        return ParseResult::NoMatch;
    }
    let mut position = 34;
    let session_len = data[position] as usize;
    position += 1;
    if position + session_len + 2 > data.len() {
        return ParseResult::NoMatch;
    }
    position += session_len;
    let cipher_len = read_u16(data, position);
    position += 2;
    if cipher_len % 2 != 0 || position + cipher_len + 1 > data.len() {
        return ParseResult::NoMatch;
    }
    position += cipher_len;
    let compression_len = data[position] as usize;
    position += 1;
    if position + compression_len + 2 > data.len() {
        return ParseResult::NoMatch;
    }
    position += compression_len;
    let extensions_len = read_u16(data, position);
    position += 2;
    if position + extensions_len > data.len() {
        return ParseResult::NoMatch;
    }
    let extensions_end = position + extensions_len;

    while position + 4 <= extensions_end {
        let extension_type = read_u16(data, position);
        let extension_len = read_u16(data, position + 2);
        position += 4;
        if position + extension_len > extensions_end {
            return ParseResult::NoMatch;
        }
        if extension_type == 0 {
            return parse_server_name(&data[position..position + extension_len]);
        }
        position += extension_len;
    }
    ParseResult::NoMatch
}

fn parse_server_name(data: &[u8]) -> ParseResult {
    if data.len() < 2 {
        return ParseResult::NoMatch;
    }
    let list_len = read_u16(data, 0);
    if list_len + 2 != data.len() {
        return ParseResult::NoMatch;
    }
    let mut position = 2;
    while position + 3 <= data.len() {
        let name_type = data[position];
        let name_len = read_u16(data, position + 1);
        position += 3;
        if position + name_len > data.len() {
            return ParseResult::NoMatch;
        }
        if name_type == 0 {
            let Ok(host) = std::str::from_utf8(&data[position..position + name_len])
            else {
                return ParseResult::NoMatch;
            };
            return if is_domain_name(host) {
                ParseResult::Matched(host.to_string())
            } else {
                ParseResult::NoMatch
            };
        }
        position += name_len;
    }
    ParseResult::NoMatch
}

fn read_u16(data: &[u8], position: usize) -> usize {
    u16::from_be_bytes([data[position], data[position + 1]]) as usize
}

fn is_domain_name(host: &str) -> bool {
    if host.is_empty()
        || host.len() > 253
        || host.ends_with('.')
        || host.parse::<IpAddr>().is_ok()
    {
        return false;
    }
    host.split('.').all(|label| {
        !label.is_empty()
            && label.len() <= 63
            && !label.starts_with('-')
            && !label.ends_with('-')
            && label.bytes().all(|byte| {
                byte.is_ascii_alphanumeric() || byte == b'-' || byte == b'_'
            })
    })
}

struct ReplayStream {
    prefix: Vec<u8>,
    position: usize,
    inner: Box<dyn ClientStream>,
}

impl ReplayStream {
    fn new(prefix: Vec<u8>, inner: Box<dyn ClientStream>) -> Self {
        Self {
            prefix,
            position: 0,
            inner,
        }
    }
}

impl AsyncRead for ReplayStream {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buffer: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        if self.position < self.prefix.len() && buffer.remaining() > 0 {
            let size = buffer.remaining().min(self.prefix.len() - self.position);
            buffer.put_slice(&self.prefix[self.position..self.position + size]);
            self.position += size;
            Poll::Ready(Ok(()))
        } else {
            Pin::new(&mut *self.inner).poll_read(cx, buffer)
        }
    }
}

impl AsyncWrite for ReplayStream {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buffer: &[u8],
    ) -> Poll<Result<usize, io::Error>> {
        Pin::new(&mut *self.inner).poll_write(cx, buffer)
    }

    fn poll_flush(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<Result<(), io::Error>> {
        Pin::new(&mut *self.inner).poll_flush(cx)
    }

    fn poll_shutdown(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<Result<(), io::Error>> {
        Pin::new(&mut *self.inner).poll_shutdown(cx)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn quic_sniffer() -> Sniffer {
        Sniffer {
            enabled: AtomicBool::new(true),
            protocols: vec![ProtocolConfig {
                protocol: Protocol::Quic,
                ports: vec![PortRange {
                    start: 443,
                    end: 443,
                }],
                override_destination: true,
            }],
            force_domain: Vec::new(),
            skip_domain: Vec::new(),
            skip_src_address: Vec::new(),
            skip_dst_address: Vec::new(),
            force_dns_mapping: true,
            parse_pure_ip: true,
            quic_flows: Mutex::new(HashMap::new()),
        }
    }

    #[test]
    fn parses_http_host_with_port() {
        let request = b"GET / HTTP/1.1\r\nHost: Example.COM:8080\r\n\r\n";
        assert!(matches!(
            parse_http(request),
            ParseResult::Matched(host) if host == "Example.COM"
        ));
    }

    #[test]
    fn parses_port_ranges() {
        let ranges =
            parse_ports(&["80, 443".to_string(), "8000-8002".to_string()], 0)
                .unwrap();
        assert!(ranges.iter().any(|range| range.contains(8001)));
        assert!(!ranges.iter().any(|range| range.contains(9000)));
    }

    #[test]
    fn domain_patterns_match_mihomo_suffix_syntax() {
        let pattern = DomainPattern::new("+.example.com");
        assert!(pattern.matches("example.com"));
        assert!(pattern.matches("www.example.com"));
        assert!(!pattern.matches("notexample.com"));
    }

    #[test]
    fn matched_quic_flow_reuses_host_for_buffered_packets() {
        let sniffer = quic_sniffer();
        let destination = SocksAddr::Ip("203.0.113.10:443".parse().unwrap());
        let source = "192.0.2.10:53000".parse().unwrap();
        let key = QuicFlowKey {
            source,
            destination: destination.clone(),
        };
        let mut flow = QuicFlow::new(Instant::now());
        flow.state = QuicFlowState::Matched("www.example.com".into());
        sniffer.quic_flows.lock().unwrap().insert(key, flow);
        let mut session = Session {
            source,
            destination: destination.clone(),
            ..Default::default()
        };

        assert_eq!(
            sniffer.sniff_udp(&mut session, &destination, b"buffered"),
            UdpSniffStatus::Matched,
        );
        assert_eq!(session.sniff_host, "www.example.com");
        assert_eq!(
            session.destination,
            SocksAddr::Domain("www.example.com".into(), 443),
        );
    }

    #[test]
    fn timed_out_quic_flow_is_not_delayed_again() {
        let sniffer = quic_sniffer();
        let destination = SocksAddr::Ip("203.0.113.10:443".parse().unwrap());
        let source = "192.0.2.10:53000".parse().unwrap();
        let key = QuicFlowKey {
            source,
            destination: destination.clone(),
        };
        sniffer
            .quic_flows
            .lock()
            .unwrap()
            .insert(key, QuicFlow::new(Instant::now()));
        let mut session = Session {
            source,
            destination: destination.clone(),
            ..Default::default()
        };

        sniffer.finish_udp_wait(&session, &destination);
        assert_eq!(
            sniffer.sniff_udp(&mut session, &destination, b"buffered"),
            UdpSniffStatus::NotApplicable,
        );
    }
}
