use crate::{Error, common::utils::default_bool_true, config::utils};
use serde::{Deserialize, de::value::MapDeserializer};
use serde_yaml::Value;
#[cfg(feature = "shadowquic")]
use shadowquic::config::CongestionControl as SQCongestionControl;
use std::{
    collections::HashMap,
    fmt::{Display, Formatter},
};
use uuid::Uuid;

pub const PROXY_DIRECT: &str = "DIRECT";
pub const PROXY_COMPATIBLE: &str = "COMPATIBLE";
pub const PROXY_REJECT: &str = "REJECT";
pub const PROXY_GLOBAL: &str = "GLOBAL";
pub const DEFAULT_LATENCY_TEST_URL: &str = "http://www.gstatic.com/generate_204";

fn default_latency_test_url() -> String {
    DEFAULT_LATENCY_TEST_URL.to_owned()
}

#[allow(clippy::large_enum_variant)]
pub enum OutboundProxy {
    ProxyServer(OutboundProxyProtocol),
    ProxyGroup(OutboundGroupProtocol),
}

impl OutboundProxy {
    pub fn name(&self) -> String {
        match self {
            OutboundProxy::ProxyServer(s) => s.name().to_string(),
            OutboundProxy::ProxyGroup(g) => g.name().to_string(),
        }
    }
}

pub fn map_serde_error(
    name: String,
) -> impl FnOnce(serde_yaml::Error) -> crate::Error {
    move |x| {
        if let Some(loc) = x.location() {
            Error::InvalidConfig(format!(
                "invalid config for {} at line {}, column {} while parsing {}",
                name,
                loc.line(),
                loc.column(),
                name
            ))
        } else {
            Error::InvalidConfig(format!("error while parsing {name}: {x}"))
        }
    }
}

#[derive(serde::Serialize, serde::Deserialize, Debug)]
#[serde(tag = "type")]
pub enum OutboundProxyProtocol {
    #[serde(rename = "direct")]
    Direct(OutboundDirect),
    #[serde(rename = "reject")]
    Reject(OutboundReject),
    #[serde(rename = "dns")]
    Dns(OutboundDns),
    #[serde(rename = "gost-relay")]
    GostRelay(OutboundGostRelay),
    #[serde(rename = "snell")]
    Snell(OutboundSnell),
    #[serde(rename = "trusttunnel")]
    TrustTunnel(OutboundTrustTunnel),
    #[cfg(feature = "masque")]
    #[serde(rename = "masque")]
    Masque(OutboundMasque),
    #[cfg(feature = "mieru")]
    #[serde(rename = "mieru")]
    Mieru(OutboundMieru),
    #[cfg(feature = "sudoku")]
    #[serde(rename = "sudoku")]
    Sudoku(OutboundSudoku),
    #[cfg(feature = "shadowsocks")]
    #[serde(rename = "ss")]
    Ss(OutboundShadowsocks),
    #[cfg(feature = "shadowsocks")]
    #[serde(rename = "ssr")]
    Ssr(OutboundShadowsocksR),
    #[serde(rename = "socks5")]
    Socks5(OutboundSocks5),
    #[serde(rename = "http")]
    Http(OutboundHttp),
    #[serde(rename = "anytls")]
    Anytls(OutboundAnytls),
    #[serde(rename = "trojan")]
    Trojan(OutboundTrojan),
    #[serde(rename = "vmess")]
    Vmess(OutboundVmess),
    #[serde(rename = "vless")]
    Vless(OutboundVless),
    #[cfg(feature = "wireguard")]
    #[serde(rename = "wireguard")]
    Wireguard(OutboundWireguard),
    #[cfg(feature = "openvpn")]
    #[serde(rename = "openvpn")]
    Openvpn(OutboundOpenvpn),
    #[cfg(feature = "onion")]
    #[serde(rename = "tor")]
    Tor(OutboundTor),
    #[cfg(feature = "tuic")]
    #[serde(rename = "tuic")]
    Tuic(OutboundTuic),
    #[serde(rename = "hysteria2")]
    Hysteria2(OutboundHysteria2),
    #[serde(rename = "hysteria")]
    Hysteria(OutboundHysteria),
    #[serde(rename = "ssh")]
    #[cfg(feature = "ssh")]
    Ssh(OutboundSsh),
    #[serde(rename = "shadowquic")]
    #[cfg(feature = "shadowquic")]
    ShadowQuic(OutboundShadowQuic),
    #[serde(rename = "tailscale")]
    #[cfg(feature = "tailscale")]
    Tailscale(OutboundTailscale),
}

impl OutboundProxyProtocol {
    pub fn name(&self) -> &str {
        match &self {
            OutboundProxyProtocol::Direct(direct) => &direct.name,
            OutboundProxyProtocol::Reject(reject) => &reject.name,
            OutboundProxyProtocol::Dns(dns) => &dns.name,
            OutboundProxyProtocol::GostRelay(relay) => &relay.common_opts.name,
            OutboundProxyProtocol::Snell(snell) => &snell.common_opts.name,
            OutboundProxyProtocol::TrustTunnel(tunnel) => &tunnel.common_opts.name,
            #[cfg(feature = "masque")]
            OutboundProxyProtocol::Masque(masque) => &masque.common_opts.name,
            #[cfg(feature = "mieru")]
            OutboundProxyProtocol::Mieru(mieru) => &mieru.name,
            #[cfg(feature = "sudoku")]
            OutboundProxyProtocol::Sudoku(sudoku) => &sudoku.common_opts.name,
            #[cfg(feature = "shadowsocks")]
            OutboundProxyProtocol::Ss(ss) => &ss.common_opts.name,
            #[cfg(feature = "shadowsocks")]
            OutboundProxyProtocol::Ssr(ssr) => &ssr.common_opts.name,
            OutboundProxyProtocol::Socks5(socks5) => &socks5.common_opts.name,
            OutboundProxyProtocol::Http(http) => &http.common_opts.name,
            OutboundProxyProtocol::Anytls(anytls) => &anytls.common_opts.name,
            OutboundProxyProtocol::Trojan(trojan) => &trojan.common_opts.name,
            OutboundProxyProtocol::Vmess(vmess) => &vmess.common_opts.name,
            OutboundProxyProtocol::Vless(vless) => &vless.common_opts.name,
            #[cfg(feature = "wireguard")]
            OutboundProxyProtocol::Wireguard(wireguard) => {
                &wireguard.common_opts.name
            }
            #[cfg(feature = "openvpn")]
            OutboundProxyProtocol::Openvpn(openvpn) => &openvpn.common_opts.name,
            #[cfg(feature = "onion")]
            OutboundProxyProtocol::Tor(tor) => &tor.name,
            #[cfg(feature = "tuic")]
            OutboundProxyProtocol::Tuic(tuic) => &tuic.common_opts.name,
            OutboundProxyProtocol::Hysteria2(hysteria2) => &hysteria2.name,
            OutboundProxyProtocol::Hysteria(hysteria) => &hysteria.name,
            #[cfg(feature = "ssh")]
            OutboundProxyProtocol::Ssh(ssh) => &ssh.common_opts.name,
            #[cfg(feature = "shadowquic")]
            OutboundProxyProtocol::ShadowQuic(sq) => &sq.common_opts.name,
            #[cfg(feature = "tailscale")]
            OutboundProxyProtocol::Tailscale(ts) => &ts.name,
        }
    }
}

impl TryFrom<HashMap<String, Value>> for OutboundProxyProtocol {
    type Error = crate::Error;

    fn try_from(mapping: HashMap<String, Value>) -> Result<Self, Self::Error> {
        let name = mapping
            .get("name")
            .and_then(|x| x.as_str())
            .ok_or(Error::InvalidConfig(
                "missing field `name` in outbound proxy protocol".to_owned(),
            ))?
            .to_owned();
        OutboundProxyProtocol::deserialize(MapDeserializer::new(mapping.into_iter()))
            .map_err(map_serde_error(name))
    }
}

impl Display for OutboundProxyProtocol {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            #[cfg(feature = "shadowsocks")]
            OutboundProxyProtocol::Ss(_) => write!(f, "Shadowsocks"),
            #[cfg(feature = "shadowsocks")]
            OutboundProxyProtocol::Ssr(_) => write!(f, "ShadowsocksR"),
            OutboundProxyProtocol::Socks5(_) => write!(f, "Socks5"),
            OutboundProxyProtocol::Http(_) => write!(f, "Http"),
            OutboundProxyProtocol::Anytls(_) => write!(f, "AnyTLS"),
            OutboundProxyProtocol::Direct(_) => write!(f, "{PROXY_DIRECT}"),
            OutboundProxyProtocol::Reject(_) => write!(f, "{PROXY_REJECT}"),
            OutboundProxyProtocol::Dns(_) => write!(f, "Dns"),
            OutboundProxyProtocol::GostRelay(_) => write!(f, "GostRelay"),
            OutboundProxyProtocol::Snell(_) => write!(f, "Snell"),
            OutboundProxyProtocol::TrustTunnel(_) => write!(f, "TrustTunnel"),
            #[cfg(feature = "masque")]
            OutboundProxyProtocol::Masque(_) => write!(f, "Masque"),
            #[cfg(feature = "mieru")]
            OutboundProxyProtocol::Mieru(_) => write!(f, "Mieru"),
            #[cfg(feature = "sudoku")]
            OutboundProxyProtocol::Sudoku(_) => write!(f, "Sudoku"),
            OutboundProxyProtocol::Trojan(_) => write!(f, "Trojan"),
            OutboundProxyProtocol::Vmess(_) => write!(f, "Vmess"),
            OutboundProxyProtocol::Vless(_) => write!(f, "Vless"),
            #[cfg(feature = "wireguard")]
            OutboundProxyProtocol::Wireguard(_) => write!(f, "Wireguard"),
            #[cfg(feature = "openvpn")]
            OutboundProxyProtocol::Openvpn(_) => write!(f, "OpenVPN"),
            #[cfg(feature = "onion")]
            OutboundProxyProtocol::Tor(_) => write!(f, "Tor"),
            #[cfg(feature = "tuic")]
            OutboundProxyProtocol::Tuic(_) => write!(f, "Tuic"),
            OutboundProxyProtocol::Hysteria2(_) => write!(f, "Hysteria2"),
            OutboundProxyProtocol::Hysteria(_) => write!(f, "Hysteria"),
            #[cfg(feature = "ssh")]
            OutboundProxyProtocol::Ssh(_) => write!(f, "Ssh"),
            #[cfg(feature = "shadowquic")]
            OutboundProxyProtocol::ShadowQuic(_) => write!(f, "ShadowQUIC"),
            #[cfg(feature = "tailscale")]
            OutboundProxyProtocol::Tailscale(_) => write!(f, "Tailscale"),
        }
    }
}

#[derive(serde::Serialize, serde::Deserialize, Debug, Default, Clone)]
#[serde(rename_all = "kebab-case")]
pub struct CommonConfigOptions {
    pub name: String,
    pub server: String,
    pub port: u16,
    /// this can be a proxy name or a group name
    /// can't be a name in a proxy provider
    /// only applies to raw proxy, i.e. applying this to a proxy group does
    /// nothing
    #[serde(alias = "dialer-proxy")]
    pub connect_via: Option<String>,
}

#[derive(serde::Serialize, serde::Deserialize, Debug, Default)]
#[serde(rename_all = "kebab-case")]
pub struct OutboundDirect {
    pub name: String,
}

#[derive(serde::Serialize, serde::Deserialize, Debug, Default)]
#[serde(rename_all = "kebab-case")]
pub struct OutboundReject {
    pub name: String,
}

#[derive(serde::Serialize, serde::Deserialize, Debug, Default)]
#[serde(rename_all = "kebab-case")]
pub struct OutboundDns {
    pub name: String,
}

#[derive(serde::Serialize, serde::Deserialize, Debug, Default)]
#[serde(rename_all = "kebab-case")]
pub struct OutboundGostRelay {
    #[serde(flatten)]
    pub common_opts: CommonConfigOptions,
    #[serde(default)]
    pub forward: bool,
    #[serde(default)]
    pub udp: bool,
    #[serde(default)]
    pub tls: bool,
    #[serde(default)]
    pub mux: bool,
    pub sni: Option<String>,
    pub username: Option<String>,
    pub password: Option<String>,
    #[serde(default)]
    pub skip_cert_verify: bool,
    pub fingerprint: Option<String>,
    pub certificate: Option<String>,
    pub private_key: Option<String>,
    pub client_fingerprint: Option<String>,
}

#[derive(serde::Serialize, serde::Deserialize, Debug, Default)]
#[serde(rename_all = "kebab-case")]
pub struct OutboundSnell {
    #[serde(flatten)]
    pub common_opts: CommonConfigOptions,
    pub psk: String,
    #[serde(default)]
    pub udp: bool,
    #[serde(default)]
    pub version: u8,
    #[serde(default)]
    pub reuse: bool,
    pub obfs_opts: Option<OutboundSnellObfsOpts>,
}

#[derive(serde::Serialize, serde::Deserialize, Debug, Default)]
#[serde(rename_all = "kebab-case")]
pub struct OutboundSnellObfsOpts {
    #[serde(default)]
    pub mode: String,
    pub host: Option<String>,
}

#[derive(serde::Serialize, serde::Deserialize, Debug, Default, Clone)]
#[serde(rename_all = "kebab-case")]
pub struct EchOptions {
    #[serde(default)]
    pub enable: bool,
    pub config: Option<String>,
    pub query_server_name: Option<String>,
}

#[derive(serde::Serialize, serde::Deserialize, Debug, Default)]
#[serde(rename_all = "kebab-case")]
pub struct OutboundTrustTunnel {
    #[serde(flatten)]
    pub common_opts: CommonConfigOptions,
    pub username: Option<String>,
    pub password: Option<String>,
    pub alpn: Option<Vec<String>>,
    pub sni: Option<String>,
    pub ech_opts: Option<EchOptions>,
    pub client_fingerprint: Option<String>,
    #[serde(default)]
    pub skip_cert_verify: bool,
    pub fingerprint: Option<String>,
    pub certificate: Option<String>,
    pub private_key: Option<String>,
    #[serde(default)]
    pub udp: bool,
    #[serde(default)]
    pub health_check: bool,
    #[serde(default)]
    pub quic: bool,
    pub congestion_controller: Option<String>,
    #[serde(default)]
    pub cwnd: u64,
    pub bbr_profile: Option<String>,
    #[serde(default)]
    pub max_connections: usize,
    #[serde(default)]
    pub min_streams: usize,
    #[serde(default)]
    pub max_streams: usize,
}

#[cfg(feature = "masque")]
#[derive(serde::Serialize, serde::Deserialize, Debug, Default)]
#[serde(rename_all = "kebab-case")]
pub struct OutboundMasque {
    #[serde(flatten)]
    pub common_opts: CommonConfigOptions,
    pub private_key: String,
    pub public_key: String,
    pub ip: Option<String>,
    pub ipv6: Option<String>,
    pub uri: Option<String>,
    pub sni: Option<String>,
    #[serde(default)]
    pub mtu: u16,
    #[serde(default)]
    pub udp: bool,
    #[serde(default)]
    pub skip_cert_verify: bool,
    pub network: Option<String>,
    pub congestion_controller: Option<String>,
    #[serde(default)]
    pub cwnd: u64,
    pub bbr_profile: Option<String>,
    #[serde(default)]
    pub remote_dns_resolve: bool,
    pub dns: Option<Vec<String>>,
}

#[cfg(feature = "mieru")]
#[derive(serde::Serialize, serde::Deserialize, Debug, Default)]
#[serde(rename_all = "kebab-case")]
pub struct OutboundMieru {
    pub name: String,
    pub server: String,
    #[serde(default)]
    pub port: u16,
    pub port_range: Option<String>,
    pub transport: String,
    #[serde(default)]
    pub udp: bool,
    pub username: String,
    pub password: String,
    pub multiplexing: Option<String>,
    pub handshake_mode: Option<String>,
    pub traffic_pattern: Option<String>,
    #[serde(alias = "dialer-proxy")]
    pub connect_via: Option<String>,
}

#[cfg(feature = "sudoku")]
#[derive(serde::Serialize, serde::Deserialize, Debug, Default)]
#[serde(rename_all = "kebab-case")]
pub struct OutboundSudoku {
    #[serde(flatten)]
    pub common_opts: CommonConfigOptions,
    pub key: String,
    pub aead_method: Option<String>,
    pub padding_min: Option<u32>,
    pub padding_max: Option<u32>,
    pub table_type: Option<String>,
    pub enable_pure_downlink: Option<bool>,
    pub http_mask: Option<bool>,
    pub http_mask_mode: Option<String>,
    #[serde(default)]
    pub http_mask_tls: bool,
    pub http_mask_host: Option<String>,
    pub path_root: Option<String>,
    pub http_mask_multiplex: Option<String>,
    pub httpmask: Option<OutboundSudokuHttpMask>,
    pub custom_table: Option<String>,
    #[serde(default)]
    pub custom_tables: Vec<String>,
}

#[cfg(feature = "sudoku")]
#[derive(serde::Serialize, serde::Deserialize, Debug, Default)]
#[serde(rename_all = "kebab-case")]
pub struct OutboundSudokuHttpMask {
    #[serde(default)]
    pub disable: bool,
    pub mode: Option<String>,
    #[serde(default)]
    pub tls: bool,
    pub host: Option<String>,
    pub path_root: Option<String>,
    pub multiplex: Option<String>,
}

#[derive(serde::Serialize, serde::Deserialize, Debug, Default)]
#[serde(rename_all = "kebab-case")]
pub struct OutboundShadowsocks {
    #[serde(flatten)]
    pub common_opts: CommonConfigOptions,
    pub cipher: String,
    pub password: String,
    #[serde(default = "default_bool_true")]
    pub udp: bool,
    pub plugin: Option<String>,
    pub plugin_opts: Option<HashMap<String, serde_yaml::Value>>,
    #[serde(default)]
    pub udp_over_tcp: bool,
    #[serde(default)]
    pub udp_over_tcp_version: u8,
    pub client_fingerprint: Option<String>,
}

#[derive(serde::Serialize, serde::Deserialize, Debug, Default)]
#[serde(rename_all = "kebab-case")]
pub struct OutboundShadowsocksR {
    #[serde(flatten)]
    pub common_opts: CommonConfigOptions,
    pub cipher: String,
    pub password: String,
    pub obfs: String,
    pub obfs_param: Option<String>,
    pub protocol: String,
    pub protocol_param: Option<String>,
    #[serde(default = "default_bool_true")]
    pub udp: bool,
}

#[derive(serde::Serialize, serde::Deserialize, Debug, Default)]
#[serde(rename_all = "kebab-case")]
pub struct OutboundSocks5 {
    #[serde(flatten)]
    pub common_opts: CommonConfigOptions,
    pub username: Option<String>,
    pub password: Option<String>,
    #[serde(default = "Default::default")]
    pub tls: bool,
    pub sni: Option<String>,
    #[serde(default = "Default::default")]
    pub skip_cert_verify: bool,
    #[serde(default = "default_bool_true")]
    pub udp: bool,
}

#[derive(serde::Serialize, serde::Deserialize, Debug, Default)]
#[serde(rename_all = "kebab-case")]
pub struct OutboundHttp {
    #[serde(flatten)]
    pub common_opts: CommonConfigOptions,
    pub username: Option<String>,
    pub password: Option<String>,
    #[serde(default)]
    pub tls: bool,
    pub sni: Option<String>,
    #[serde(default)]
    pub skip_cert_verify: bool,
    pub headers: Option<HashMap<String, String>>,
    /// File path or inline PEM client certificate for mTLS.
    pub certificate: Option<String>,
    /// File path or inline PEM client private key for mTLS.
    pub private_key: Option<String>,
    /// SHA-256 certificate fingerprint used for TLS certificate pinning.
    pub fingerprint: Option<String>,
}

#[derive(serde::Serialize, serde::Deserialize, Debug, Default)]
#[serde(rename_all = "kebab-case")]
pub struct WsOpt {
    pub path: Option<String>,
    pub headers: Option<HashMap<String, String>>,
    pub max_early_data: Option<i32>,
    pub early_data_header_name: Option<String>,
}

#[derive(serde::Serialize, serde::Deserialize, Debug, Clone)]
#[serde(untagged)]
pub enum StringList {
    One(String),
    Many(Vec<String>),
}

impl StringList {
    pub fn to_vec(&self) -> Vec<String> {
        match self {
            Self::One(value) => vec![value.clone()],
            Self::Many(values) => values.clone(),
        }
    }
}

#[derive(serde::Serialize, serde::Deserialize, Debug, Default)]
#[serde(rename_all = "kebab-case")]
pub struct HttpOpt {
    pub method: Option<String>,
    pub path: Option<StringList>,
    pub headers: Option<HashMap<String, StringList>>,
}

#[derive(serde::Serialize, serde::Deserialize, Debug, Default)]
pub struct H2Opt {
    pub host: Option<Vec<String>>,
    pub path: Option<String>,
}

#[derive(serde::Serialize, serde::Deserialize, Debug, Default)]
#[serde(rename_all = "kebab-case")]
pub struct XHttpReuseSettings {
    #[serde(default, deserialize_with = "deserialize_optional_string_or_int")]
    pub max_concurrency: Option<String>,
    #[serde(default, deserialize_with = "deserialize_optional_string_or_int")]
    pub max_connections: Option<String>,
    #[serde(default, deserialize_with = "deserialize_optional_string_or_int")]
    pub c_max_reuse_times: Option<String>,
    #[serde(default, deserialize_with = "deserialize_optional_string_or_int")]
    pub h_max_request_times: Option<String>,
    #[serde(default, deserialize_with = "deserialize_optional_string_or_int")]
    pub h_max_reusable_secs: Option<String>,
    pub h_keep_alive_period: Option<i64>,
}

#[derive(serde::Serialize, serde::Deserialize, Debug, Default)]
#[serde(rename_all = "kebab-case")]
pub struct XHttpDownloadSettings {
    pub path: Option<String>,
    pub host: Option<String>,
    pub headers: Option<HashMap<String, String>>,
    pub reuse_settings: Option<XHttpReuseSettings>,
    pub server: Option<String>,
    pub port: Option<u16>,
    pub tls: Option<bool>,
    pub alpn: Option<Vec<String>>,
    pub ech_opts: Option<EchOptions>,
    pub reality_opts: Option<RealityOpt>,
    pub skip_cert_verify: Option<bool>,
    pub fingerprint: Option<String>,
    #[serde(alias = "certificate")]
    pub tls_cert: Option<String>,
    #[serde(alias = "private-key")]
    pub tls_key: Option<String>,
    #[serde(alias = "servername")]
    pub server_name: Option<String>,
    pub client_fingerprint: Option<String>,
}

#[derive(serde::Serialize, serde::Deserialize, Debug, Default)]
#[serde(rename_all = "kebab-case")]
pub struct XHttpOpt {
    pub path: Option<String>,
    pub host: Option<String>,
    pub mode: Option<String>,
    pub headers: Option<HashMap<String, String>>,
    #[serde(default)]
    pub no_grpc_header: bool,
    #[serde(default, deserialize_with = "deserialize_optional_string_or_int")]
    pub x_padding_bytes: Option<String>,
    #[serde(default)]
    pub x_padding_obfs_mode: bool,
    pub x_padding_key: Option<String>,
    pub x_padding_header: Option<String>,
    pub x_padding_placement: Option<String>,
    pub x_padding_method: Option<String>,
    pub uplink_http_method: Option<String>,
    pub session_placement: Option<String>,
    pub session_key: Option<String>,
    pub seq_placement: Option<String>,
    pub seq_key: Option<String>,
    pub uplink_data_placement: Option<String>,
    pub uplink_data_key: Option<String>,
    #[serde(default, deserialize_with = "deserialize_optional_string_or_int")]
    pub uplink_chunk_size: Option<String>,
    #[serde(default, deserialize_with = "deserialize_optional_string_or_int")]
    pub sc_max_each_post_bytes: Option<String>,
    #[serde(default, deserialize_with = "deserialize_optional_string_or_int")]
    pub sc_min_posts_interval_ms: Option<String>,
    pub reuse_settings: Option<XHttpReuseSettings>,
    pub download_settings: Option<XHttpDownloadSettings>,
}

#[derive(serde::Serialize, serde::Deserialize, Debug, Default)]
#[serde(rename_all = "kebab-case")]
pub struct GrpcOpt {
    pub grpc_service_name: Option<String>,
}

#[derive(serde::Serialize, serde::Deserialize, Debug, Default)]
#[serde(rename_all = "kebab-case")]
pub struct RealityOpt {
    pub public_key: String,
    #[serde(default, deserialize_with = "deserialize_string_or_int")]
    pub short_id: String,
}

#[derive(serde::Serialize, serde::Deserialize, Debug, Default)]
#[serde(rename_all = "kebab-case")]
pub struct OutboundAnytls {
    #[serde(flatten)]
    pub common_opts: CommonConfigOptions,
    pub password: String,
    pub alpn: Option<Vec<String>>,
    pub sni: Option<String>,
    pub skip_cert_verify: Option<bool>,
    pub fingerprint: Option<String>,
    pub client_fingerprint: Option<String>,
    pub ech_opts: Option<EchOptions>,
    pub udp: Option<bool>,
    pub idle_session_check_interval: Option<u64>,
    pub idle_session_timeout: Option<u64>,
    pub min_idle_session: Option<u64>,
    /// File path or inline PEM client certificate for mTLS.
    /// Must be set together with `tls-key`.
    #[serde(alias = "certificate")]
    pub tls_cert: Option<String>,
    /// File path or inline PEM client private key for mTLS.
    /// Must be set together with `tls-cert`.
    #[serde(alias = "private-key")]
    pub tls_key: Option<String>,
}

#[derive(serde::Serialize, serde::Deserialize, Debug, Default)]
#[serde(rename_all = "kebab-case")]
pub struct OutboundTrojan {
    #[serde(flatten)]
    pub common_opts: CommonConfigOptions,
    pub password: String,
    pub alpn: Option<Vec<String>>,
    pub sni: Option<String>,
    pub skip_cert_verify: Option<bool>,
    pub fingerprint: Option<String>,
    pub client_fingerprint: Option<String>,
    pub ech_opts: Option<EchOptions>,
    pub reality_opts: Option<RealityOpt>,
    pub ss_opts: Option<TrojanSsOpt>,
    pub udp: Option<bool>,
    pub network: Option<String>,
    pub grpc_opts: Option<GrpcOpt>,
    pub ws_opts: Option<WsOpt>,
    /// File path or inline PEM client certificate for mTLS.
    /// Must be set together with `tls-key`.
    #[serde(alias = "certificate")]
    pub tls_cert: Option<String>,
    /// File path or inline PEM client private key for mTLS.
    /// Must be set together with `tls-cert`.
    #[serde(alias = "private-key")]
    pub tls_key: Option<String>,
}

#[derive(serde::Serialize, serde::Deserialize, Debug, Default)]
#[serde(rename_all = "kebab-case")]
pub struct TrojanSsOpt {
    #[serde(default)]
    pub enabled: bool,
    pub method: Option<String>,
    pub password: Option<String>,
}

#[derive(serde::Serialize, serde::Deserialize, Debug, Default)]
#[serde(rename_all = "kebab-case")]
pub struct OutboundVmess {
    #[serde(flatten)]
    pub common_opts: CommonConfigOptions,
    pub uuid: String,
    #[serde(alias = "alterId", deserialize_with = "utils::deserialize_u64")]
    pub alter_id: u16,
    pub cipher: Option<String>,
    pub udp: Option<bool>,
    pub packet_addr: Option<bool>,
    pub xudp: Option<bool>,
    pub packet_encoding: Option<String>,
    pub global_padding: Option<bool>,
    pub authenticated_length: Option<bool>,
    pub tls: Option<bool>,
    pub alpn: Option<Vec<String>>,
    pub skip_cert_verify: Option<bool>,
    pub fingerprint: Option<String>,
    pub client_fingerprint: Option<String>,
    pub ech_opts: Option<EchOptions>,
    pub reality_opts: Option<RealityOpt>,
    #[serde(alias = "servername")]
    pub server_name: Option<String>,
    pub network: Option<String>,
    pub http_opts: Option<HttpOpt>,
    pub ws_opts: Option<WsOpt>,
    pub h2_opts: Option<H2Opt>,
    pub grpc_opts: Option<GrpcOpt>,
    /// File path or inline PEM client certificate for mTLS.
    /// Must be set together with `tls-key`.
    #[serde(alias = "certificate")]
    pub tls_cert: Option<String>,
    /// File path or inline PEM client private key for mTLS.
    /// Must be set together with `tls-cert`.
    #[serde(alias = "private-key")]
    pub tls_key: Option<String>,
}

#[derive(serde::Serialize, serde::Deserialize, Debug, Default)]
#[serde(rename_all = "kebab-case")]
pub struct OutboundVless {
    #[serde(flatten)]
    pub common_opts: CommonConfigOptions,
    pub uuid: String,
    pub udp: Option<bool>,
    pub packet_addr: Option<bool>,
    pub xudp: Option<bool>,
    pub packet_encoding: Option<String>,
    pub encryption: Option<String>,
    pub tls: Option<bool>,
    pub alpn: Option<Vec<String>>,
    pub skip_cert_verify: Option<bool>,
    pub fingerprint: Option<String>,
    #[serde(alias = "servername")]
    pub server_name: Option<String>,
    pub network: Option<String>,
    pub http_opts: Option<HttpOpt>,
    pub ws_opts: Option<WsOpt>,
    pub h2_opts: Option<H2Opt>,
    pub xhttp_opts: Option<XHttpOpt>,
    pub grpc_opts: Option<GrpcOpt>,
    pub reality_opts: Option<RealityOpt>,
    pub flow: Option<String>,
    pub client_fingerprint: Option<String>,
    pub ech_opts: Option<EchOptions>,
    /// File path or inline PEM client certificate for mTLS.
    /// Must be set together with `tls-key`.
    #[serde(alias = "certificate")]
    pub tls_cert: Option<String>,
    /// File path or inline PEM client private key for mTLS.
    /// Must be set together with `tls-cert`.
    #[serde(alias = "private-key")]
    pub tls_key: Option<String>,
}

#[cfg(feature = "wireguard")]
#[derive(serde::Serialize, serde::Deserialize, Debug, Default, Clone)]
#[serde(rename_all = "kebab-case")]
pub struct OutboundWireguard {
    #[serde(flatten)]
    pub common_opts: CommonConfigOptions,
    pub private_key: String,
    pub public_key: String,
    #[serde(alias = "preshared-key")]
    pub pre_shared_key: Option<String>,
    pub mtu: Option<u16>,
    pub udp: Option<bool>,
    pub ip: String,
    pub ipv6: Option<String>,
    pub remote_dns_resolve: Option<bool>,
    pub dns: Option<Vec<String>>,
    pub allowed_ips: Option<Vec<String>>,
    pub reserved_bits: Option<Vec<u8>>,
}

#[cfg(feature = "openvpn")]
#[derive(serde::Serialize, serde::Deserialize, Debug, Default, Clone)]
#[serde(rename_all = "kebab-case")]
pub struct OutboundOpenvpn {
    #[serde(flatten)]
    pub common_opts: CommonConfigOptions,
    pub proto: Option<String>,
    pub dev: Option<String>,
    pub cipher: Option<String>,
    pub auth: Option<String>,
    pub comp_lzo: Option<String>,
    pub ca: String,
    pub cert: Option<String>,
    pub key: Option<String>,
    pub tls_crypt: Option<String>,
    pub username: Option<String>,
    pub password: Option<String>,
    pub ping: Option<u64>,
    pub ping_restart: Option<u64>,
    pub mtu: Option<u16>,
    pub udp: Option<bool>,
    pub remote_dns_resolve: Option<bool>,
    pub dns: Option<Vec<String>>,
}

#[cfg(feature = "onion")]
#[derive(serde::Serialize, serde::Deserialize, Debug, Default)]
#[serde(rename_all = "kebab-case")]
pub struct OutboundTor {
    pub name: String,
}

#[derive(serde::Serialize, serde::Deserialize, Debug, Default)]
#[serde(rename_all = "kebab-case")]
pub struct OutboundTuic {
    #[serde(flatten)]
    pub common_opts: CommonConfigOptions,
    pub uuid: Uuid,
    pub password: String,
    /// override field 'server' dns record
    pub ip: Option<String>,
    pub heartbeat_interval: Option<u64>,
    /// h3
    pub alpn: Option<Vec<String>>,
    pub disable_sni: Option<bool>,
    pub reduce_rtt: Option<bool>,
    /// millis
    pub request_timeout: Option<u64>,
    /// millis
    pub idle_timeout: Option<u64>,
    pub udp_relay_mode: Option<String>,
    pub congestion_controller: Option<String>,
    /// bytes
    pub max_udp_relay_packet_size: Option<u64>,
    pub fast_open: Option<bool>,
    pub skip_cert_verify: Option<bool>,
    pub max_open_stream: Option<u64>,
    pub sni: Option<String>,
    pub ech_opts: Option<EchOptions>,
    /// millis
    pub gc_interval: Option<u64>,
    /// millis
    pub gc_lifetime: Option<u64>,
    pub send_window: Option<u64>,
    pub receive_window: Option<u64>,
    /// File path or inline PEM client certificate for mTLS.
    /// Must be set together with `tls-key`.
    #[serde(alias = "certificate")]
    pub tls_cert: Option<String>,
    /// File path or inline PEM client private key for mTLS.
    /// Must be set together with `tls-cert`.
    #[serde(alias = "private-key")]
    pub tls_key: Option<String>,
}

#[cfg(feature = "shadowquic")]
#[derive(serde::Serialize, serde::Deserialize, Debug, Default)]
#[serde(rename_all = "kebab-case")]
pub struct OutboundShadowQuic {
    #[serde(flatten)]
    pub common_opts: CommonConfigOptions,
    /// jls password, must be the same as the server
    pub password: String,
    /// jls username, must be the same as the server
    pub username: String,
    /// server name, must be the same as the server jls_upstream
    /// domain name
    pub server_name: String,
    /// alpn, default to "h3"
    pub alpn: Option<Vec<String>>,
    /// initial mtu, must be larger than min mtu, at least to be 1200.
    /// 1400 is recommended for high packet loss network. default to be 1300
    pub initial_mtu: Option<u16>,
    /// congestion control, default to "bbr"
    pub congestion_control: Option<SQCongestionControl>, // bbr, new-reno, cubic
    /// set to true to enable zero rtt, default to true
    pub zero_rtt: Option<bool>,
    /// if true, use quic stream to send UDP, otherwise use quic datagram
    /// extension, similar to native UDP in TUIC
    pub over_stream: Option<bool>,
    /// minimum mtu, must be smaller than initial mtu, at least to be 1200.
    /// 1400 is recommended for high packet loss network. default to be 1290
    pub min_mtu: Option<u16>,
    /// keep alive interval in milliseconds
    /// 0 means disable keep alive, should be smaller than 30_000(idle time)
    pub keep_alive_interval: Option<u32>,
    /// Whether to detect QUIC path black holes.
    pub blackhole_detection: Option<bool>,
    /// Generalized Segmentation Offload for QUIC udp connection, default to
    /// true.
    pub gso: Option<bool>,
    /// MTU discovery for QUIC connection, default to true. If false, will use
    /// initial mtu as fixed mtu. This is useful for network with stable MTU
    /// and high packet loss.
    pub mtu_discovery: Option<bool>,
}

#[cfg(feature = "ssh")]
#[derive(serde::Serialize, serde::Deserialize, Debug, Default)]
#[serde(rename_all = "kebab-case")]
pub struct OutboundSsh {
    #[serde(flatten)]
    pub common_opts: CommonConfigOptions,
    pub username: String,
    pub password: Option<String>,
    pub private_key: Option<String>,
    pub private_key_passphrase: Option<String>,
    pub host_key: Option<Vec<String>>,
    pub host_key_algorithms: Option<Vec<String>>,
    pub totp_opt: Option<TotpOption>,
}

#[cfg(feature = "tailscale")]
#[derive(serde::Serialize, serde::Deserialize, Debug, Default, Clone)]
#[serde(rename_all = "kebab-case")]
pub struct OutboundTailscale {
    pub name: String,
    pub state_dir: Option<String>,
    pub auth_key: Option<String>,
    pub hostname: Option<String>,
    pub control_url: Option<String>,
    pub client_name: Option<String>,
    #[serde(default)]
    pub ephemeral: bool,
}

#[cfg(feature = "ssh")]
#[derive(serde::Serialize, serde::Deserialize, Debug, Clone)]
#[serde(rename_all = "kebab-case")]
pub enum TotpOption {
    OtpAuth(String),
    Common(Totp),
}

#[cfg(feature = "ssh")]
#[derive(serde::Serialize, serde::Deserialize, Debug, Default, Clone)]
#[serde(rename_all = "kebab-case")]
pub struct Totp {
    pub secret: String,
    pub screw: u8,
    pub step: u64,
    pub digits: usize,
    pub algorithm: totp_rs::Algorithm,
}

#[derive(Clone, serde::Serialize, serde::Deserialize, Debug, Default)]
#[serde(rename_all = "kebab-case")]
pub struct OutboundHysteria2 {
    pub name: String,
    pub server: String,
    pub port: u16,
    /// port hopping
    pub ports: Option<String>,
    pub password: String,
    #[serde(default, deserialize_with = "deserialize_hysteria2_obfs")]
    pub obfs: Option<Hysteria2Obfs>,
    pub obfs_password: Option<String>,
    pub alpn: Option<Vec<String>>,
    /// set brutal congestion control, need compare with tx which is received by
    /// auth request (bytes per second, or bandwidth string like "200 Mbps")
    #[serde(default, deserialize_with = "deserialize_bandwidth_bps")]
    pub up: Option<u64>,
    /// receive_bps: send by auth request (bytes per second, or bandwidth
    /// string)
    #[serde(default, deserialize_with = "deserialize_bandwidth_bps")]
    pub down: Option<u64>,
    pub sni: Option<String>,
    pub ech_opts: Option<EchOptions>,
    #[serde(default)]
    pub skip_cert_verify: bool,
    pub ca: Option<String>,
    pub ca_str: Option<String>,
    pub fingerprint: Option<String>,
    pub udp_mtu: Option<u32>,
    pub disable_mtu_discovery: Option<bool>,
    /// bbr congestion control window
    pub cwnd: Option<u64>,
    /// File path or inline PEM client certificate for mTLS.
    /// Must be set together with `tls-key`.
    #[serde(alias = "certificate")]
    pub tls_cert: Option<String>,
    /// File path or inline PEM client private key for mTLS.
    /// Must be set together with `tls-cert`.
    #[serde(alias = "private-key")]
    pub tls_key: Option<String>,
}

#[derive(Clone, serde::Serialize, serde::Deserialize, Debug)]
#[serde(rename_all = "lowercase")]
pub enum Hysteria2Obfs {
    Salamander,
}

fn deserialize_hysteria2_obfs<'de, D>(
    deserializer: D,
) -> Result<Option<Hysteria2Obfs>, D::Error>
where
    D: serde::Deserializer<'de>,
{
    match Option::<String>::deserialize(deserializer)?.as_deref() {
        None | Some("") => Ok(None),
        Some("salamander") => Ok(Some(Hysteria2Obfs::Salamander)),
        Some(value) => {
            Err(serde::de::Error::unknown_variant(value, &["salamander"]))
        }
    }
}

#[derive(Clone, serde::Serialize, serde::Deserialize, Debug)]
#[serde(rename_all = "kebab-case")]
pub struct OutboundHysteria {
    pub name: String,
    pub server: String,
    pub port: u16,
    /// port hopping
    pub ports: Option<String>,
    /// bandwidth for upload, e.g. "100 mbps" or integer (Mbps)
    #[serde(deserialize_with = "deserialize_bandwidth")]
    pub up: Option<String>,
    /// bandwidth for download, e.g. "100 mbps" or integer (Mbps)
    #[serde(deserialize_with = "deserialize_bandwidth")]
    pub down: Option<String>,
    /// base64 encoded auth
    pub auth: Option<String>,
    /// plain text auth string
    pub auth_str: Option<String>,
    /// XPlus obfuscation key
    pub obfs: Option<String>,
    pub alpn: Option<Vec<String>>,
    pub sni: Option<String>,
    pub ech_opts: Option<EchOptions>,
    #[serde(default)]
    pub skip_cert_verify: bool,
    pub ca: Option<String>,
    pub ca_str: Option<String>,
    pub fingerprint: Option<String>,
    pub disable_mtu_discovery: Option<bool>,
    pub fast_open: Option<bool>,
    /// port hopping interval in seconds
    pub hop_interval: Option<u64>,
    /// receive window for stream
    pub recv_window_conn: Option<u64>,
    /// receive window for connection
    pub recv_window: Option<u64>,
    #[serde(alias = "certificate")]
    pub tls_cert: Option<String>,
    #[serde(alias = "private-key")]
    pub tls_key: Option<String>,
}

#[derive(serde::Serialize, serde::Deserialize, Debug, Clone)]
#[serde(tag = "type")]
pub enum OutboundGroupProtocol {
    #[serde(rename = "relay")]
    Relay(OutboundGroupRelay),
    #[serde(rename = "url-test")]
    UrlTest(OutboundGroupUrlTest),
    #[serde(rename = "fallback")]
    Fallback(OutboundGroupFallback),
    #[serde(rename = "load-balance")]
    LoadBalance(OutboundGroupLoadBalance),
    #[serde(rename = "smart")]
    Smart(OutboundGroupSmart),
    #[serde(rename = "select")]
    Select(OutboundGroupSelect),
}

#[derive(serde::Serialize, serde::Deserialize, Debug, Clone)]
pub struct OutboundGroupSelection {
    /// Optional static outbound that races the group for TCP connections.
    #[serde(rename = "route-race")]
    pub route_race: Option<String>,
    /// Enables a two-path race inside url-test and fallback groups.
    #[serde(rename = "failover-race", default)]
    pub failover_race: bool,
    #[serde(rename = "include-all", default)]
    pub include_all: bool,
    #[serde(rename = "include-all-proxies", default)]
    pub include_all_proxies: bool,
    #[serde(rename = "include-all-providers", default)]
    pub include_all_providers: bool,
    pub filter: Option<String>,
    #[serde(rename = "exclude-filter")]
    pub exclude_filter: Option<String>,
    #[serde(rename = "empty-fallback", default = "default_empty_fallback")]
    pub empty_fallback: String,
}

impl Default for OutboundGroupSelection {
    fn default() -> Self {
        Self {
            route_race: None,
            failover_race: false,
            include_all: false,
            include_all_proxies: false,
            include_all_providers: false,
            filter: None,
            exclude_filter: None,
            empty_fallback: default_empty_fallback(),
        }
    }
}

fn default_empty_fallback() -> String {
    PROXY_COMPATIBLE.to_owned()
}

impl OutboundGroupSelection {
    fn expand(
        &self,
        proxies: &mut Option<Vec<String>>,
        use_provider: &mut Option<Vec<String>>,
        all_proxies: &[String],
        all_providers: &[String],
    ) -> Result<(), crate::Error> {
        if self.include_all || self.include_all_providers {
            *use_provider = Some(all_providers.to_vec());
        }
        if self.include_all || self.include_all_proxies {
            let filters = self
                .filter
                .as_deref()
                .filter(|filter| !filter.is_empty())
                .map(|filter| {
                    filter
                        .split('`')
                        .map(regex::Regex::new)
                        .collect::<Result<Vec<_>, _>>()
                        .map_err(|error| {
                            crate::Error::InvalidConfig(format!(
                                "invalid proxy group filter: {error}"
                            ))
                        })
                })
                .transpose()?;
            let proxies = proxies.get_or_insert_default();
            for name in all_proxies {
                if filters.as_ref().is_none_or(|filters| {
                    filters.iter().any(|filter| filter.is_match(name))
                }) && !proxies.contains(name)
                {
                    proxies.push(name.clone());
                }
            }
        }
        if (self.include_all
            || self.include_all_proxies
            || self.include_all_providers)
            && proxies.as_ref().is_none_or(Vec::is_empty)
            && use_provider.as_ref().is_none_or(Vec::is_empty)
        {
            let proxies = proxies.get_or_insert_default();
            proxies.push(self.empty_fallback.clone());
        }
        Ok(())
    }
}

/// Only used statically in config parsing.
/// Runtime access is done via the `try_as_group_handler`.
impl OutboundGroupProtocol {
    /// Returns the name of the group.
    pub fn name(&self) -> &str {
        match &self {
            OutboundGroupProtocol::Relay(g) => &g.name,
            OutboundGroupProtocol::UrlTest(g) => &g.name,
            OutboundGroupProtocol::Fallback(g) => &g.name,
            OutboundGroupProtocol::LoadBalance(g) => &g.name,
            OutboundGroupProtocol::Smart(g) => &g.name,
            OutboundGroupProtocol::Select(g) => &g.name,
        }
    }

    /// Returns the proxies in the group, if any.
    pub fn proxies(&self) -> Option<&Vec<String>> {
        match &self {
            OutboundGroupProtocol::Relay(g) => g.proxies.as_ref(),
            OutboundGroupProtocol::UrlTest(g) => g.proxies.as_ref(),
            OutboundGroupProtocol::Fallback(g) => g.proxies.as_ref(),
            OutboundGroupProtocol::LoadBalance(g) => g.proxies.as_ref(),
            OutboundGroupProtocol::Smart(g) => g.proxies.as_ref(),
            OutboundGroupProtocol::Select(g) => g.proxies.as_ref(),
        }
    }

    /// Returns the proxy providers used by the group, if any.
    pub fn use_providers(&self) -> Option<&Vec<String>> {
        match &self {
            OutboundGroupProtocol::Relay(g) => g.use_provider.as_ref(),
            OutboundGroupProtocol::UrlTest(g) => g.use_provider.as_ref(),
            OutboundGroupProtocol::Fallback(g) => g.use_provider.as_ref(),
            OutboundGroupProtocol::LoadBalance(g) => g.use_provider.as_ref(),
            OutboundGroupProtocol::Smart(g) => g.use_provider.as_ref(),
            OutboundGroupProtocol::Select(g) => g.use_provider.as_ref(),
        }
    }

    pub fn selection(&self) -> &OutboundGroupSelection {
        match self {
            OutboundGroupProtocol::Relay(g) => &g.selection,
            OutboundGroupProtocol::UrlTest(g) => &g.selection,
            OutboundGroupProtocol::Fallback(g) => &g.selection,
            OutboundGroupProtocol::LoadBalance(g) => &g.selection,
            OutboundGroupProtocol::Smart(g) => &g.selection,
            OutboundGroupProtocol::Select(g) => &g.selection,
        }
    }

    pub fn route_race(&self) -> Option<&str> {
        self.selection().route_race.as_deref()
    }

    pub fn failover_race(&self) -> bool {
        matches!(self, Self::UrlTest(_) | Self::Fallback(_))
            && self.selection().failover_race
    }

    pub fn expand_include_all(
        &mut self,
        all_proxies: &[String],
        all_providers: &[String],
    ) -> Result<(), crate::Error> {
        match self {
            OutboundGroupProtocol::Relay(g) => g.selection.expand(
                &mut g.proxies,
                &mut g.use_provider,
                all_proxies,
                all_providers,
            ),
            OutboundGroupProtocol::UrlTest(g) => g.selection.expand(
                &mut g.proxies,
                &mut g.use_provider,
                all_proxies,
                all_providers,
            ),
            OutboundGroupProtocol::Fallback(g) => g.selection.expand(
                &mut g.proxies,
                &mut g.use_provider,
                all_proxies,
                all_providers,
            ),
            OutboundGroupProtocol::LoadBalance(g) => g.selection.expand(
                &mut g.proxies,
                &mut g.use_provider,
                all_proxies,
                all_providers,
            ),
            OutboundGroupProtocol::Smart(g) => g.selection.expand(
                &mut g.proxies,
                &mut g.use_provider,
                all_proxies,
                all_providers,
            ),
            OutboundGroupProtocol::Select(g) => g.selection.expand(
                &mut g.proxies,
                &mut g.use_provider,
                all_proxies,
                all_providers,
            ),
        }
    }
}

impl Display for OutboundGroupProtocol {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        match self {
            OutboundGroupProtocol::Relay(g) => write!(f, "{}", g.name),
            OutboundGroupProtocol::UrlTest(g) => write!(f, "{}", g.name),
            OutboundGroupProtocol::Fallback(g) => write!(f, "{}", g.name),
            OutboundGroupProtocol::LoadBalance(g) => write!(f, "{}", g.name),
            OutboundGroupProtocol::Select(g) => write!(f, "{}", g.name),
            OutboundGroupProtocol::Smart(g) => write!(f, "{}", g.name),
        }
    }
}

#[derive(serde::Serialize, serde::Deserialize, Debug, Default, Clone)]
pub struct OutboundGroupRelay {
    pub name: String,
    pub proxies: Option<Vec<String>>,
    #[serde(rename = "use")]
    pub use_provider: Option<Vec<String>>,
    pub icon: Option<String>,
    pub url: Option<String>,
    #[serde(flatten)]
    pub selection: OutboundGroupSelection,
}

#[derive(serde::Serialize, serde::Deserialize, Debug, Default, Clone)]
pub struct OutboundGroupUrlTest {
    pub name: String,

    pub proxies: Option<Vec<String>>,
    #[serde(rename = "use")]
    pub use_provider: Option<Vec<String>>,

    #[serde(default = "default_latency_test_url")]
    pub url: String,
    #[serde(default, deserialize_with = "utils::deserialize_u64")]
    pub interval: u64,
    pub lazy: Option<bool>,
    pub tolerance: Option<u16>,
    pub icon: Option<String>,
    #[serde(flatten)]
    pub selection: OutboundGroupSelection,
}
#[derive(serde::Serialize, serde::Deserialize, Debug, Default, Clone)]
pub struct OutboundGroupFallback {
    pub name: String,

    pub proxies: Option<Vec<String>>,
    #[serde(rename = "use")]
    pub use_provider: Option<Vec<String>>,

    #[serde(default = "default_latency_test_url")]
    pub url: String,
    #[serde(default, deserialize_with = "utils::deserialize_u64")]
    pub interval: u64,
    pub lazy: Option<bool>,
    pub icon: Option<String>,
    #[serde(flatten)]
    pub selection: OutboundGroupSelection,
}

#[derive(serde::Serialize, serde::Deserialize, Debug, Default, Clone)]
pub struct OutboundGroupLoadBalance {
    pub name: String,

    pub proxies: Option<Vec<String>>,
    #[serde(rename = "use")]
    pub use_provider: Option<Vec<String>>,

    #[serde(default = "default_latency_test_url")]
    pub url: String,
    #[serde(default, deserialize_with = "utils::deserialize_u64")]
    pub interval: u64,
    pub lazy: Option<bool>,
    pub strategy: Option<LoadBalanceStrategy>,
    pub icon: Option<String>,
    #[serde(flatten)]
    pub selection: OutboundGroupSelection,
}

#[derive(serde::Serialize, serde::Deserialize, Debug, Clone, Copy, Default)]
pub enum LoadBalanceStrategy {
    #[default]
    #[serde(rename = "consistent-hashing")]
    ConsistentHashing,
    #[serde(rename = "round-robin")]
    RoundRobin,
    #[serde(rename = "sticky-session")]
    StickySession,
}

#[derive(serde::Serialize, serde::Deserialize, Debug, Default, Clone)]
pub struct OutboundGroupSmart {
    pub name: String,

    pub proxies: Option<Vec<String>>,
    pub udp: Option<bool>,
    #[serde(rename = "use")]
    pub use_provider: Option<Vec<String>>,

    pub lazy: Option<bool>,
    pub icon: Option<String>,
    pub url: Option<String>,

    /// Maximum retries for failed connections (default: 3)
    #[serde(rename = "max-retries")]
    pub max_retries: Option<u32>,

    /// Site stickiness factor (0.0-1.0, default: 0.8)
    /// Higher values make the same site more likely to use the same proxy
    #[serde(rename = "site-stickiness")]
    pub site_stickiness: Option<f64>,

    /// Bandwidth consideration weight (default: 0.0 - disabled)
    /// When > 0, bandwidth metrics are included in selection algorithm
    #[serde(rename = "bandwidth-weight")]
    pub bandwidth_weight: Option<f64>,
    #[serde(flatten)]
    pub selection: OutboundGroupSelection,
}

#[derive(serde::Serialize, serde::Deserialize, Debug, Default, Clone)]
pub struct OutboundGroupSelect {
    pub name: String,

    pub proxies: Option<Vec<String>>,
    #[serde(rename = "use")]
    pub use_provider: Option<Vec<String>>,
    pub udp: Option<bool>,

    pub url: Option<String>,
    pub icon: Option<String>,
    #[serde(flatten)]
    pub selection: OutboundGroupSelection,
}

#[derive(serde::Serialize, serde::Deserialize, Debug)]
#[serde(tag = "type")]
#[serde(rename_all = "kebab-case")]
pub enum OutboundProxyProviderDef {
    Http(OutboundHttpProvider),
    File(OutboundFileProvider),
}

impl OutboundProxyProviderDef {
    pub fn set_name(&mut self, name: String) {
        match self {
            OutboundProxyProviderDef::Http(p) => p.name = name,
            OutboundProxyProviderDef::File(p) => p.name = name,
        }
    }
}

#[derive(serde::Serialize, serde::Deserialize, Debug)]
#[serde(rename_all = "kebab-case")]
pub struct OutboundHttpProvider {
    #[serde(skip)]
    pub name: String,
    pub url: String,
    /// Optional outbound used to download this provider. This is the
    /// `proxy:` field supported by Mihomo proxy providers.
    #[serde(default)]
    pub proxy: Option<String>,
    pub interval: u64,
    pub path: String,
    #[serde(default)]
    pub header: HashMap<String, StringList>,
    #[serde(default)]
    pub health_check: HealthCheck,
    #[serde(rename = "override", default)]
    pub override_options: OutboundProxyProviderOverride,
}

#[derive(serde::Serialize, serde::Deserialize, Debug)]
#[serde(rename_all = "kebab-case")]
pub struct OutboundFileProvider {
    #[serde(skip)]
    pub name: String,
    pub path: String,
    pub interval: Option<u64>,
    #[serde(default)]
    pub health_check: HealthCheck,
    #[serde(rename = "override", default)]
    pub override_options: OutboundProxyProviderOverride,
}

#[derive(serde::Serialize, serde::Deserialize, Debug, Default, Clone)]
#[serde(rename_all = "kebab-case", default)]
pub struct OutboundProxyProviderOverride {
    pub tfo: Option<bool>,
    pub mptcp: Option<bool>,
    pub udp: Option<bool>,
    pub udp_over_tcp: Option<bool>,
    pub up: Option<String>,
    pub down: Option<String>,
    pub dialer_proxy: Option<String>,
    pub skip_cert_verify: Option<bool>,
    pub interface_name: Option<String>,
    pub routing_mark: Option<i64>,
    pub ip_version: Option<String>,
    pub additional_prefix: Option<String>,
    pub additional_suffix: Option<String>,
    pub proxy_name: Vec<OutboundProxyNameOverride>,
}

#[derive(serde::Serialize, serde::Deserialize, Debug, Clone)]
#[serde(rename_all = "kebab-case")]
pub struct OutboundProxyNameOverride {
    pub pattern: String,
    pub target: String,
}

impl OutboundProxyProviderOverride {
    pub fn apply(
        &self,
        mapping: &mut HashMap<String, Value>,
    ) -> Result<(), crate::Error> {
        macro_rules! set_value {
            ($field:ident, $key:literal) => {
                if let Some(value) = &self.$field {
                    mapping.insert(
                        $key.to_owned(),
                        serde_yaml::to_value(value).map_err(|error| {
                            crate::Error::InvalidConfig(format!(
                                "invalid proxy provider override `{}`: {error}",
                                $key
                            ))
                        })?,
                    );
                }
            };
        }

        set_value!(tfo, "tfo");
        set_value!(mptcp, "mptcp");
        set_value!(udp, "udp");
        set_value!(udp_over_tcp, "udp-over-tcp");
        set_value!(up, "up");
        set_value!(down, "down");
        set_value!(dialer_proxy, "dialer-proxy");
        set_value!(skip_cert_verify, "skip-cert-verify");
        set_value!(interface_name, "interface-name");
        set_value!(routing_mark, "routing-mark");
        set_value!(ip_version, "ip-version");

        let mut name = mapping
            .get("name")
            .and_then(Value::as_str)
            .ok_or_else(|| {
                crate::Error::InvalidConfig(
                    "proxy provider entry is missing string field `name`".to_owned(),
                )
            })?
            .to_owned();
        for replacement in &self.proxy_name {
            let pattern =
                regex::Regex::new(&replacement.pattern).map_err(|error| {
                    crate::Error::InvalidConfig(format!(
                        "invalid proxy provider name override `{}`: {error}",
                        replacement.pattern
                    ))
                })?;
            name = pattern
                .replace_all(&name, replacement.target.as_str())
                .into_owned();
        }
        if let Some(prefix) = &self.additional_prefix {
            name.insert_str(0, prefix);
        }
        if let Some(suffix) = &self.additional_suffix {
            name.push_str(suffix);
        }
        mapping.insert("name".to_owned(), Value::String(name));
        Ok(())
    }
}

#[derive(serde::Serialize, serde::Deserialize, Debug)]
#[serde(default)]
pub struct HealthCheck {
    pub enable: bool,
    pub url: String,
    pub interval: u64,
    pub lazy: Option<bool>,
}

impl HealthCheck {
    pub fn effective_interval(&self) -> u64 {
        if !self.enable || self.url.is_empty() {
            0
        } else if self.interval == 0 {
            300
        } else {
            self.interval
        }
    }
}

impl Default for HealthCheck {
    fn default() -> Self {
        Self {
            enable: false,
            url: String::new(),
            interval: 0,
            lazy: Some(true),
        }
    }
}

impl TryFrom<HashMap<String, Value>> for OutboundProxyProviderDef {
    type Error = crate::Error;

    fn try_from(mapping: HashMap<String, Value>) -> Result<Self, Self::Error> {
        let name = mapping
            .get("name")
            .and_then(|x| x.as_str())
            .ok_or(Error::InvalidConfig(
                "missing field `name` in outbound proxy provider".to_owned(),
            ))?
            .to_owned();
        OutboundProxyProviderDef::deserialize(MapDeserializer::new(
            mapping.into_iter(),
        ))
        .map_err(map_serde_error(name))
    }
}

#[cfg(test)]
mod proxy_provider_compatibility_tests {
    use super::{OutboundProxyProviderDef, OutboundProxyProviderDef::Http};

    #[test]
    fn parses_mihomo_proxy_provider_download_proxy() {
        let yaml = r#"
            type: http
            url: https://example.com/provider.yaml
            proxy: Proxy
            interval: 3600
            path: ./provider.yaml
            health-check:
              enable: true
              url: https://example.com/generate_204
              interval: 300
        "#;

        let Http(provider) =
            serde_yaml::from_str::<OutboundProxyProviderDef>(yaml).unwrap()
        else {
            panic!("expected HTTP provider");
        };
        assert_eq!(provider.proxy.as_deref(), Some("Proxy"));
        assert_eq!(provider.health_check.effective_interval(), 300);
    }

    #[test]
    fn defaults_enabled_mihomo_healthcheck_to_300_seconds_and_lazy() {
        let yaml = r#"
            type: http
            url: https://example.com/provider.yaml
            interval: 3600
            path: ./provider.yaml
            health-check:
              enable: true
              url: https://example.com/generate_204
        "#;

        let Http(provider) =
            serde_yaml::from_str::<OutboundProxyProviderDef>(yaml).unwrap()
        else {
            panic!("expected HTTP provider");
        };
        assert_eq!(provider.health_check.effective_interval(), 300);
        assert_eq!(provider.health_check.lazy, Some(true));
        assert_eq!(super::HealthCheck::default().effective_interval(), 0);
    }
}

/// Deserialize a field that can be either a string or an integer (converts int
/// to string) Used for fields like short-id that YAML may parse as integer
fn deserialize_string_or_int<'de, D>(deserializer: D) -> Result<String, D::Error>
where
    D: serde::Deserializer<'de>,
{
    use serde::de;
    struct StringOrIntVisitor;

    impl<'de> de::Visitor<'de> for StringOrIntVisitor {
        type Value = String;

        fn expecting(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
            write!(f, "a string or integer")
        }

        fn visit_str<E: de::Error>(self, v: &str) -> Result<Self::Value, E> {
            Ok(v.to_string())
        }

        fn visit_u64<E: de::Error>(self, v: u64) -> Result<Self::Value, E> {
            Ok(v.to_string())
        }

        fn visit_i64<E: de::Error>(self, v: i64) -> Result<Self::Value, E> {
            Ok(v.to_string())
        }
    }

    deserializer.deserialize_any(StringOrIntVisitor)
}

fn deserialize_optional_string_or_int<'de, D>(
    deserializer: D,
) -> Result<Option<String>, D::Error>
where
    D: serde::Deserializer<'de>,
{
    use serde::de;

    match Option::<Value>::deserialize(deserializer)? {
        None | Some(Value::Null) => Ok(None),
        Some(Value::String(value)) => Ok(Some(value)),
        Some(Value::Number(value)) => Ok(Some(value.to_string())),
        Some(value) => Err(de::Error::custom(format!(
            "expected a string or integer, got {value:?}"
        ))),
    }
}

/// Deserialize bandwidth that can be either a string ("100 mbps") or integer
/// (Mbps)
fn deserialize_bandwidth<'de, D>(deserializer: D) -> Result<Option<String>, D::Error>
where
    D: serde::Deserializer<'de>,
{
    use serde::de;
    struct BandwidthVisitor;

    impl<'de> de::Visitor<'de> for BandwidthVisitor {
        type Value = Option<String>;

        fn expecting(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
            write!(f, "a string or integer for bandwidth")
        }

        fn visit_str<E: de::Error>(self, v: &str) -> Result<Self::Value, E> {
            Ok(Some(v.to_string()))
        }

        fn visit_u64<E: de::Error>(self, v: u64) -> Result<Self::Value, E> {
            Ok(Some(format!("{} Mbps", v)))
        }

        fn visit_i64<E: de::Error>(self, v: i64) -> Result<Self::Value, E> {
            Ok(Some(format!("{} Mbps", v)))
        }

        fn visit_none<E: de::Error>(self) -> Result<Self::Value, E> {
            Ok(None)
        }

        fn visit_unit<E: de::Error>(self) -> Result<Self::Value, E> {
            Ok(None)
        }
    }

    deserializer.deserialize_any(BandwidthVisitor)
}

/// Parse a bandwidth string like "200 Mbps", "1 Gbps", "100 mbps" into bytes
/// per second
fn parse_bandwidth_str(s: &str) -> Option<u64> {
    let s = s.trim().to_lowercase();
    let (num_str, multiplier) = if s.ends_with("gbps") {
        (&s[..s.len() - 4], 1_000_000_000u64 / 8)
    } else if s.ends_with("g bps") {
        (&s[..s.len() - 5], 1_000_000_000u64 / 8)
    } else if s.ends_with("mbps") {
        (&s[..s.len() - 4], 1_000_000u64 / 8)
    } else if s.ends_with("m bps") {
        (&s[..s.len() - 5], 1_000_000u64 / 8)
    } else if s.ends_with("kbps") {
        (&s[..s.len() - 4], 1_000u64 / 8)
    } else if s.ends_with("k bps") {
        (&s[..s.len() - 5], 1_000u64 / 8)
    } else if s.ends_with("bps") {
        (&s[..s.len() - 3], 1u64)
    } else if s.ends_with("gb/s") {
        (&s[..s.len() - 4], 1_000_000_000u64 / 8)
    } else if s.ends_with("mb/s") {
        (&s[..s.len() - 4], 1_000_000u64 / 8)
    } else if s.ends_with("kb/s") {
        (&s[..s.len() - 4], 1_000u64 / 8)
    } else if s.ends_with("b/s") {
        (&s[..s.len() - 3], 1u64)
    } else {
        // Try as plain number (Mbps)
        if let Ok(n) = s.parse::<u64>() {
            return Some(n * 1_000_000 / 8);
        }
        return None;
    };
    num_str.trim().parse::<u64>().ok().map(|n| n * multiplier)
}

/// Deserialize bandwidth for hysteria2: string ("200 Mbps") or integer (already
/// BPS)
fn deserialize_bandwidth_bps<'de, D>(
    deserializer: D,
) -> Result<Option<u64>, D::Error>
where
    D: serde::Deserializer<'de>,
{
    use serde::de;
    struct BpsVisitor;

    impl<'de> de::Visitor<'de> for BpsVisitor {
        type Value = Option<u64>;

        fn expecting(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
            write!(f, "a string or integer for bandwidth")
        }

        fn visit_str<E: de::Error>(self, v: &str) -> Result<Self::Value, E> {
            Ok(parse_bandwidth_str(v))
        }

        fn visit_u64<E: de::Error>(self, v: u64) -> Result<Self::Value, E> {
            Ok(Some(v))
        }

        fn visit_i64<E: de::Error>(self, v: i64) -> Result<Self::Value, E> {
            Ok(Some(v as u64))
        }

        fn visit_none<E: de::Error>(self) -> Result<Self::Value, E> {
            Ok(None)
        }

        fn visit_unit<E: de::Error>(self) -> Result<Self::Value, E> {
            Ok(None)
        }
    }

    deserializer.deserialize_any(BpsVisitor)
}

#[cfg(test)]
mod hysteria2_compatibility_tests {
    use super::{OutboundProxyProtocol, OutboundProxyProtocol::Hysteria2};

    #[test]
    fn treats_empty_mihomo_obfs_as_disabled() {
        let yaml = r#"
            name: hysteria2-empty-obfs
            type: hysteria2
            server: 192.0.2.1
            port: 443
            password: secret
            obfs: ""
            obfs-password: ""
            up: ""
            down: ""
        "#;

        let Hysteria2(config) =
            serde_yaml::from_str::<OutboundProxyProtocol>(yaml).unwrap()
        else {
            panic!("expected Hysteria2 config");
        };
        assert!(config.obfs.is_none());
        assert_eq!(config.obfs_password.as_deref(), Some(""));
        assert!(config.up.is_none());
        assert!(config.down.is_none());
    }
}

#[cfg(all(test, feature = "tailscale"))]
mod tailscale_tests {
    use super::{OutboundProxyProtocol, OutboundTailscale};
    use serde_yaml::Value;
    use std::collections::HashMap;

    #[test]
    fn parse_tailscale_outbound_proxy_protocol() {
        let mapping = HashMap::from([
            ("name".to_owned(), Value::String("ts-out".to_owned())),
            ("type".to_owned(), Value::String("tailscale".to_owned())),
            ("state-dir".to_owned(), Value::String("/tmp/ts".to_owned())),
            (
                "auth-key".to_owned(),
                Value::String("tskey-auth-xxxx".to_owned()),
            ),
            ("hostname".to_owned(), Value::String("clash-rs".to_owned())),
            (
                "control-url".to_owned(),
                Value::String("https://controlplane.tailscale.com".to_owned()),
            ),
            ("ephemeral".to_owned(), Value::Bool(true)),
        ]);

        let protocol = OutboundProxyProtocol::try_from(mapping)
            .expect("tailscale proxy should parse");
        let OutboundProxyProtocol::Tailscale(OutboundTailscale {
            name,
            state_dir,
            auth_key,
            hostname,
            control_url,
            client_name: _,
            ephemeral,
        }) = protocol
        else {
            panic!("expected tailscale variant")
        };

        assert_eq!(name, "ts-out");
        assert_eq!(state_dir.as_deref(), Some("/tmp/ts"));
        assert_eq!(auth_key.as_deref(), Some("tskey-auth-xxxx"));
        assert_eq!(hostname.as_deref(), Some("clash-rs"));
        assert_eq!(
            control_url.as_deref(),
            Some("https://controlplane.tailscale.com")
        );
        assert!(ephemeral);
    }
}

#[cfg(all(test, feature = "openvpn"))]
mod openvpn_tests {
    use super::{OutboundOpenvpn, OutboundProxyProtocol};

    #[test]
    fn parses_all_current_mihomo_openvpn_fields() {
        let yaml = r#"
name: corporate-vpn
type: openvpn
server: vpn.example.com
port: 1194
proto: tcp4-client
dev: tun
cipher: AES-256-CBC
auth: SHA512
comp-lzo: adaptive
ca: |
  -----BEGIN CERTIFICATE-----
  example
  -----END CERTIFICATE-----
username: user
password: secret
ping: 10
ping-restart: 60
mtu: 1400
udp: false
dialer-proxy: bootstrap
remote-dns-resolve: true
dns: [1.1.1.1, 8.8.8.8]
"#;
        let protocol: OutboundProxyProtocol = serde_yaml::from_str(yaml).unwrap();
        let OutboundProxyProtocol::Openvpn(OutboundOpenvpn {
            common_opts,
            proto,
            cipher,
            auth,
            comp_lzo,
            username,
            ping,
            ping_restart,
            mtu,
            udp,
            remote_dns_resolve,
            dns,
            ..
        }) = protocol
        else {
            panic!("expected openvpn outbound")
        };
        assert_eq!(common_opts.connect_via.as_deref(), Some("bootstrap"));
        assert_eq!(proto.as_deref(), Some("tcp4-client"));
        assert_eq!(cipher.as_deref(), Some("AES-256-CBC"));
        assert_eq!(auth.as_deref(), Some("SHA512"));
        assert_eq!(comp_lzo.as_deref(), Some("adaptive"));
        assert_eq!(username.as_deref(), Some("user"));
        assert_eq!(ping, Some(10));
        assert_eq!(ping_restart, Some(60));
        assert_eq!(mtu, Some(1400));
        assert_eq!(udp, Some(false));
        assert_eq!(remote_dns_resolve, Some(true));
        assert_eq!(dns.unwrap(), ["1.1.1.1", "8.8.8.8"]);
    }
}

#[cfg(all(test, feature = "wireguard"))]
mod tests {
    use super::*;

    #[test]
    fn test_wireguard_pre_shared_key_field_name() {
        // Test the new standard field name "pre-shared-key"
        let yaml_new = r#"
            name: wg-test
            type: wireguard
            server: example.com
            port: 51820
            private-key: KIlDUePHyYwzjgn18przw/ZwPioJhh2aEyhxb/dtCXI=
            public-key: INBZyvB715sA5zatkiX8Jn3Dh5tZZboZ09x4pkr66ig=
            pre-shared-key: +JmZErvtDT4ZfQequxWhZSydBV+ItqUcPMHUWY1j2yc=
            ip: 10.0.0.2/32
        "#;

        let config: OutboundWireguard = serde_yaml::from_str(yaml_new)
            .expect("should parse with pre-shared-key");
        assert!(config.pre_shared_key.is_some());
        assert_eq!(
            config.pre_shared_key.unwrap(),
            "+JmZErvtDT4ZfQequxWhZSydBV+ItqUcPMHUWY1j2yc="
        );
    }

    #[test]
    fn test_wireguard_preshared_key_legacy_alias() {
        // Test the legacy field name "preshared-key" for backward compatibility
        let yaml_legacy = r#"
            name: wg-test
            type: wireguard
            server: example.com
            port: 51820
            private-key: KIlDUePHyYwzjgn18przw/ZwPioJhh2aEyhxb/dtCXI=
            public-key: INBZyvB715sA5zatkiX8Jn3Dh5tZZboZ09x4pkr66ig=
            preshared-key: +JmZErvtDT4ZfQequxWhZSydBV+ItqUcPMHUWY1j2yc=
            ip: 10.0.0.2/32
        "#;

        let config: OutboundWireguard = serde_yaml::from_str(yaml_legacy)
            .expect("should parse with preshared-key (legacy)");
        assert!(config.pre_shared_key.is_some());
        assert_eq!(
            config.pre_shared_key.unwrap(),
            "+JmZErvtDT4ZfQequxWhZSydBV+ItqUcPMHUWY1j2yc="
        );
    }

    #[test]
    fn test_wireguard_without_pre_shared_key() {
        // Test config without pre-shared-key (should be optional)
        let yaml_no_psk = r#"
            name: wg-test
            type: wireguard
            server: example.com
            port: 51820
            private-key: KIlDUePHyYwzjgn18przw/ZwPioJhh2aEyhxb/dtCXI=
            public-key: INBZyvB715sA5zatkiX8Jn3Dh5tZZboZ09x4pkr66ig=
            ip: 10.0.0.2/32
        "#;

        let config: OutboundWireguard = serde_yaml::from_str(yaml_no_psk)
            .expect("should parse without pre-shared-key");
        assert!(config.pre_shared_key.is_none());
    }
}

#[cfg(test)]
mod anytls_tests {
    use super::{OutboundProxyProtocol, OutboundProxyProtocol::Anytls};

    #[test]
    fn test_anytls_deserialize() {
        let yaml = r#"
            name: anytls-test
            type: anytls
            server: example.com
            port: 443
            password: example-password
            sni: sni.example.com
            skip-cert-verify: true
            udp: true
            idle-session-check-interval: 30
            idle-session-timeout: 300
            min-idle-session: 2
        "#;

        let config: OutboundProxyProtocol =
            serde_yaml::from_str(yaml).expect("should parse anytls");

        let Anytls(config) = config else {
            panic!("expected anytls config");
        };

        assert_eq!(config.common_opts.name, "anytls-test");
        assert_eq!(config.common_opts.server, "example.com");
        assert_eq!(config.common_opts.port, 443);
        assert_eq!(config.password, "example-password");
        assert_eq!(config.sni.as_deref(), Some("sni.example.com"));
        assert_eq!(config.skip_cert_verify, Some(true));
        assert_eq!(config.udp, Some(true));
        assert_eq!(config.idle_session_check_interval, Some(30));
        assert_eq!(config.idle_session_timeout, Some(300));
        assert_eq!(config.min_idle_session, Some(2));
    }
}

#[cfg(test)]
mod proxy_group_defaults_tests {
    use super::{
        DEFAULT_LATENCY_TEST_URL, OutboundGroupProtocol,
        OutboundGroupProtocol::{Fallback, LoadBalance, UrlTest},
    };

    #[test]
    fn defaults_mihomo_health_check_fields_when_omitted() {
        let groups = [
            "name: auto\ntype: url-test\nproxies: [DIRECT]",
            "name: fallback\ntype: fallback\nproxies: [DIRECT]",
            "name: balance\ntype: load-balance\nproxies: [DIRECT]",
        ];

        for yaml in groups {
            let group: OutboundGroupProtocol = serde_yaml::from_str(yaml)
                .expect("group with defaults should parse");
            let (url, interval) = match group {
                UrlTest(group) => (group.url, group.interval),
                Fallback(group) => (group.url, group.interval),
                LoadBalance(group) => (group.url, group.interval),
                _ => unreachable!(),
            };
            assert_eq!(url, DEFAULT_LATENCY_TEST_URL);
            assert_eq!(interval, 0);
        }
    }

    #[test]
    fn parses_racing_options() {
        let group: OutboundGroupProtocol = serde_yaml::from_str(
            "type: url-test\nname: test\nproxies: [DIRECT]\nroute-race: DIRECT\nfailover-race: true\n",
        )
        .unwrap();

        assert_eq!(group.route_race(), Some("DIRECT"));
        assert!(group.failover_race());

        for group_type in ["select", "load-balance", "smart", "relay"] {
            let yaml = format!(
                "type: {group_type}\nname: ignored\nproxies: [DIRECT]\nfailover-race: true\n"
            );
            let group: OutboundGroupProtocol = serde_yaml::from_str(&yaml).unwrap();
            assert!(
                !group.failover_race(),
                "{group_type} must ignore failover-race"
            );
        }
    }
}

#[cfg(test)]
mod mihomo_tls_field_tests {
    use super::{OutboundProxyProtocol, OutboundProxyProtocol::*};

    #[test]
    fn parses_mihomo_tls_field_names_for_common_v2ray_protocols() {
        let cases = [
            r#"
                name: trojan-tls
                type: trojan
                server: example.com
                port: 443
                password: secret
                fingerprint: 00:11
                client-fingerprint: chrome
                certificate: cert.pem
                private-key: key.pem
            "#,
            r#"
                name: vmess-tls
                type: vmess
                server: example.com
                port: 443
                uuid: 00000000-0000-0000-0000-000000000001
                alterId: 0
                tls: true
                alpn: [h2, http/1.1]
                fingerprint: 00:11
                client-fingerprint: chrome
                certificate: cert.pem
                private-key: key.pem
            "#,
            r#"
                name: vless-tls
                type: vless
                server: example.com
                port: 443
                uuid: 00000000-0000-0000-0000-000000000001
                tls: true
                alpn: [h2, http/1.1]
                fingerprint: 00:11
                client-fingerprint: chrome
                certificate: cert.pem
                private-key: key.pem
            "#,
            r#"
                name: anytls-tls
                type: anytls
                server: example.com
                port: 443
                password: secret
                certificate: cert.pem
                private-key: key.pem
            "#,
        ];

        for yaml in cases {
            let proxy: OutboundProxyProtocol = serde_yaml::from_str(yaml).unwrap();
            let (certificate, private_key) = match proxy {
                Trojan(proxy) => (proxy.tls_cert, proxy.tls_key),
                Vmess(proxy) => (proxy.tls_cert, proxy.tls_key),
                Vless(proxy) => (proxy.tls_cert, proxy.tls_key),
                Anytls(proxy) => (proxy.tls_cert, proxy.tls_key),
                _ => unreachable!(),
            };
            assert_eq!(certificate.as_deref(), Some("cert.pem"));
            assert_eq!(private_key.as_deref(), Some("key.pem"));
        }
    }

    #[test]
    fn parses_mihomo_vmess_string_alter_id() {
        let yaml = r#"
            name: vmess-string-alter-id
            type: vmess
            server: example.com
            port: 443
            uuid: 00000000-0000-0000-0000-000000000001
            alterId: "0"
        "#;

        let Vmess(config) =
            serde_yaml::from_str::<OutboundProxyProtocol>(yaml).unwrap()
        else {
            panic!("expected VMess config");
        };
        assert_eq!(config.alter_id, 0);
    }
}

#[cfg(all(test, feature = "shadowsocks"))]
mod shadowsocks_compatibility_tests {
    use super::{OutboundProxyProtocol, OutboundProxyProtocol::Ss};

    #[test]
    fn parses_mihomo_uot_and_tls_plugin_fields() {
        let yaml = r#"
            name: ss-uot
            type: ss
            server: example.com
            port: 443
            cipher: aes-128-gcm
            password: secret
            udp: true
            udp-over-tcp: true
            udp-over-tcp-version: 2
            client-fingerprint: chrome
            plugin: gost-plugin
            plugin-opts:
              mode: websocket
              tls: true
              fingerprint: 01:02:03
              certificate: cert.pem
              private-key: key.pem
        "#;
        let config: OutboundProxyProtocol = serde_yaml::from_str(yaml).unwrap();
        let Ss(config) = config else {
            panic!("expected Shadowsocks config");
        };
        assert!(config.udp_over_tcp);
        assert_eq!(config.udp_over_tcp_version, 2);
        assert_eq!(config.client_fingerprint.as_deref(), Some("chrome"));
        assert_eq!(config.plugin.as_deref(), Some("gost-plugin"));
    }
}
