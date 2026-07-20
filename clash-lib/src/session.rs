use crate::app::net::OutboundInterface;
use anyhow::anyhow;
use bytes::{Buf, BufMut};
use erased_serde::Serialize as ESerialize;
use serde::Serialize;
use std::{
    collections::HashMap,
    fmt::{Debug, Display, Formatter},
    io,
    net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr},
    str::FromStr,
};
use tokio::io::{AsyncRead, AsyncReadExt};

#[derive(Debug, PartialEq, Eq, Hash, Serialize)]
pub enum SocksAddr {
    Ip(SocketAddr),
    Domain(String, u16),
}

impl FromStr for SocksAddr {
    type Err = anyhow::Error;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let mut s = s.to_string();
        if !s.contains(':') {
            s = format!("{s}:80");
        }
        match SocketAddr::from_str(&s) {
            Ok(v) => Ok(Self::Ip(v)),
            Err(_) => {
                let tokens: Vec<_> = s.split(':').collect();
                if tokens.len() == 2 {
                    let port: u16 = tokens.get(1).unwrap().parse()?;
                    Ok(Self::Domain(tokens.first().unwrap().to_string(), port))
                } else {
                    Err(anyhow!("SocksAddr parse error, value: {s}"))
                }
            }
        }
    }
}
#[test]
fn test_from_str() {
    assert_eq!(
        SocksAddr::from_str("127.0.0.1").unwrap(),
        SocksAddr::Ip(SocketAddr::V4("127.0.0.1:80".parse().unwrap()))
    );
    assert!(SocksAddr::from_str("127.0.0.1:80").is_ok());
    assert!(SocksAddr::from_str("hosta.com").is_ok());
    assert!(SocksAddr::from_str("hosta.com:443").is_ok());
    assert!(SocksAddr::from_str("hosta.:com:443").is_err());
}

impl Default for SocksAddr {
    fn default() -> Self {
        Self::Ip(SocketAddr::new(IpAddr::V4(Ipv4Addr::new(0, 0, 0, 0)), 0))
    }
}

impl Display for SocksAddr {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "{}",
            match self {
                SocksAddr::Ip(ip) => ip.to_string(),
                SocksAddr::Domain(host, port) => format!("{host}:{port}"),
            }
        )
    }
}

pub struct SocksAddrType;

impl SocksAddrType {
    pub const DOMAIN: u8 = 0x3;
    pub const V4: u8 = 0x1;
    pub const V6: u8 = 0x4;
}

impl SocksAddr {
    pub fn any_ipv4() -> Self {
        Self::Ip(SocketAddr::new(IpAddr::V4(Ipv4Addr::new(0, 0, 0, 0)), 0))
    }

    pub fn any_ipv6() -> Self {
        Self::Ip(SocketAddr::new(
            IpAddr::V6(Ipv6Addr::new(0, 0, 0, 0, 0, 0, 0, 0)),
            0,
        ))
    }

    pub fn write_buf<T: BufMut>(&self, buf: &mut T) {
        match self {
            Self::Ip(addr) => match addr {
                SocketAddr::V4(addr) => {
                    buf.put_u8(SocksAddrType::V4);
                    buf.put_slice(&addr.ip().octets());
                    buf.put_u16(addr.port());
                }
                SocketAddr::V6(addr) => {
                    buf.put_u8(SocksAddrType::V6);
                    buf.put_slice(&addr.ip().octets());
                    buf.put_u16(addr.port());
                }
            },
            Self::Domain(domain, port) => {
                buf.put_u8(SocksAddrType::DOMAIN);
                buf.put_u8(domain.len() as u8);
                buf.put_slice(domain.as_bytes());
                buf.put_u16(*port);
            }
        }
    }

    pub fn is_domain(&self) -> bool {
        match self {
            SocksAddr::Ip(_) => false,
            SocksAddr::Domain(..) => true,
        }
    }

    pub fn domain(&self) -> Option<&str> {
        match self {
            SocksAddr::Ip(_) => None,
            SocksAddr::Domain(domain, _) => Some(domain.as_str()),
        }
    }

    pub fn must_into_socket_addr(self) -> SocketAddr {
        let self_clone = self.clone();
        self.try_into_socket_addr()
            .unwrap_or_else(|| panic!("not a socket address: {self_clone:?}"))
    }

    pub fn try_into_socket_addr(self) -> Option<SocketAddr> {
        match self {
            SocksAddr::Ip(addr) => Some(addr),
            SocksAddr::Domain(..) => None,
        }
    }

    pub fn ip(&self) -> Option<IpAddr> {
        match self {
            SocksAddr::Ip(addr) => Some(addr.ip()),
            SocksAddr::Domain(host, _) => host.parse().ok(),
        }
    }

    pub fn host(&self) -> String {
        match self {
            SocksAddr::Ip(ip) => ip.ip().to_string(),
            SocksAddr::Domain(domain, _) => domain.to_string(),
        }
    }

    pub fn port(&self) -> u16 {
        match self {
            SocksAddr::Ip(ip) => ip.port(),
            SocksAddr::Domain(_, port) => *port,
        }
    }

    pub fn size(&self) -> usize {
        match self {
            // SOCKS5 ATYP
            SocksAddr::Ip(ip) => match ip {
                SocketAddr::V4(_) => 1 + 4 + 2, // ATYP + IPv4 len + port len
                SocketAddr::V6(_) => 1 + 16 + 2,
            },
            SocksAddr::Domain(domain, _) => 1 + 1 + domain.len() + 2,
        }
    }

    pub fn peek_read(buf: &[u8]) -> io::Result<Self> {
        let mut cur = io::Cursor::new(buf);
        Self::peek_cursor(&mut cur)
    }

    #[inline]
    fn peek_cursor<T: AsRef<[u8]>>(cur: &mut io::Cursor<T>) -> io::Result<Self> {
        if cur.remaining() < 2 {
            return Err(io::Error::other("invalid buf"));
        }

        let atyp = cur.get_u8();
        match atyp {
            SocksAddrType::V4 => {
                if cur.remaining() < 4 + 2 {
                    return Err(io::Error::other("invalid buf"));
                }
                let addr = Ipv4Addr::from(cur.get_u32());
                let port = cur.get_u16();
                Ok(Self::Ip((addr, port).into()))
            }
            SocksAddrType::V6 => {
                if cur.remaining() < 16 + 2 {
                    return Err(io::Error::other("invalid buf"));
                }
                let addr = Ipv6Addr::from(cur.get_u128());
                let port = cur.get_u16();
                Ok(Self::Ip((addr, port).into()))
            }
            SocksAddrType::DOMAIN => {
                let domain_len = cur.get_u8() as usize;
                if cur.remaining() < domain_len {
                    return Err(io::Error::other("invalid buf"));
                }
                let mut buf = vec![0u8; domain_len];
                cur.copy_to_slice(&mut buf);
                let port = cur.get_u16();
                let domain_name =
                    String::from_utf8(buf).map_err(|_x| invalid_domain())?;
                Ok(Self::Domain(domain_name, port))
            }
            _ => Err(invalid_atyp()),
        }
    }

    pub async fn read_from<T: AsyncRead + Unpin>(r: &mut T) -> io::Result<Self> {
        match r.read_u8().await? {
            SocksAddrType::V4 => {
                let ip = Ipv4Addr::from(r.read_u32().await?);
                let port = r.read_u16().await?;
                Ok(Self::Ip((ip, port).into()))
            }
            SocksAddrType::V6 => {
                let ip = Ipv6Addr::from(r.read_u128().await?);
                let port = r.read_u16().await?;
                Ok(Self::Ip((ip, port).into()))
            }
            SocksAddrType::DOMAIN => {
                let domain_len = r.read_u8().await? as usize;
                let mut buf = vec![0u8; domain_len];
                let n = r.read_exact(&mut buf).await?;
                if n != domain_len {
                    return Err(io::Error::other("invalid domain length"));
                }
                let domain = String::from_utf8(buf).map_err(|_| invalid_domain())?;
                let port = r.read_u16().await?;
                Ok(Self::Domain(domain, port))
            }
            _ => Err(invalid_atyp()),
        }
    }
}

impl Clone for SocksAddr {
    fn clone(&self) -> Self {
        match self {
            SocksAddr::Ip(a) => Self::from(a.to_owned()),
            SocksAddr::Domain(domain, port) => {
                Self::try_from((domain.clone(), *port)).unwrap()
            }
        }
    }
}

impl From<(IpAddr, u16)> for SocksAddr {
    fn from(value: (IpAddr, u16)) -> Self {
        Self::Ip(value.into())
    }
}

impl From<(Ipv4Addr, u16)> for SocksAddr {
    fn from(value: (Ipv4Addr, u16)) -> Self {
        Self::Ip(value.into())
    }
}

impl From<(Ipv6Addr, u16)> for SocksAddr {
    fn from(value: (Ipv6Addr, u16)) -> Self {
        Self::Ip(value.into())
    }
}

impl From<SocketAddr> for SocksAddr {
    fn from(value: SocketAddr) -> Self {
        Self::Ip(value)
    }
}

impl TryFrom<(String, u16)> for SocksAddr {
    type Error = io::Error;

    fn try_from(value: (String, u16)) -> Result<Self, Self::Error> {
        if let Ok(ip) = value.0.parse::<IpAddr>() {
            return Ok(Self::from((ip, value.1)));
        }
        if value.0.len() > 0xff {
            return Err(io::Error::other("domain too long"));
        }
        Ok(Self::Domain(value.0, value.1))
    }
}

impl TryFrom<&[u8]> for SocksAddr {
    type Error = io::Error;

    fn try_from(buf: &[u8]) -> Result<Self, Self::Error> {
        if buf.is_empty() {
            return Err(insuff_bytes());
        }

        match buf[0] {
            SocksAddrType::V4 => {
                if buf.len() < 1 + 4 + 2 {
                    // ATYP + DST.ADDR + DST.PORT
                    return Err(insuff_bytes());
                }

                let mut ip_bytes = [0u8; 4];
                ip_bytes.copy_from_slice(&buf[1..5]);
                let ip = Ipv4Addr::from(ip_bytes);
                let mut port_bytes = [0u8; 2];
                port_bytes.copy_from_slice(&buf[5..7]);
                let port = u16::from_be_bytes(port_bytes);
                Ok(Self::Ip((ip, port).into()))
            }

            SocksAddrType::V6 => {
                if buf.len() < 1 + 16 + 2 {
                    // ATYP + DST.ADDR + DST.PORT
                    return Err(insuff_bytes());
                }

                let mut ip_bytes = [0u8; 16];
                ip_bytes.copy_from_slice(&buf[1..17]);
                let ip = Ipv6Addr::from(ip_bytes);
                let mut port_bytes = [0u8; 2];
                port_bytes.copy_from_slice(&buf[17..19]);
                let port = u16::from_be_bytes(port_bytes);
                Ok(Self::Ip((ip, port).into()))
            }

            SocksAddrType::DOMAIN => {
                if buf.is_empty() {
                    return Err(insuff_bytes());
                }
                let domain_len = buf[1] as usize;
                if buf.len() < 1 + domain_len + 2 {
                    return Err(insuff_bytes());
                }
                let domain = String::from_utf8((buf[2..domain_len + 2]).to_vec())
                    .map_err(|e| io::Error::other(format!("invalid domain: {e}")))?;
                let mut port_bytes = [0u8; 2];
                (port_bytes).copy_from_slice(&buf[domain_len + 2..domain_len + 4]);
                let port = u16::from_be_bytes(port_bytes);
                Ok(Self::Domain(domain, port))
            }

            _ => Err(io::Error::other("invalid ATYP")),
        }
    }
}

impl TryFrom<SocksAddr> for SocketAddr {
    type Error = io::Error;

    fn try_from(s: SocksAddr) -> Result<Self, Self::Error> {
        match s {
            SocksAddr::Ip(ip) => Ok(ip),
            SocksAddr::Domain(..) => Err(io::Error::other("cannot convert")),
        }
    }
}

#[derive(PartialEq, Eq, Hash, Clone, Copy, Debug, Serialize)]
pub enum Network {
    Tcp,
    Udp,
}

#[derive(PartialEq, Eq, Hash, Clone, Copy, Debug, Serialize)]
pub enum Type {
    Http,
    HttpConnect,
    Socks5,
    #[cfg(feature = "tun")]
    Tun,
    #[cfg(all(target_os = "linux", feature = "tproxy"))]
    Tproxy,
    #[cfg(all(target_os = "linux", feature = "redir"))]
    Redir,
    Tunnel,
    Shadowsocks,
    Anytls,
    Hysteria2,
    Ignore,
}

impl Display for Network {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        f.write_str(match self {
            Network::Tcp => "TCP",
            Network::Udp => "UDP",
        })
    }
}

#[derive(Serialize)]
pub struct Session {
    /// The network type, representing either TCP or UDP.
    pub network: Network,
    /// The type of the inbound connection.
    pub typ: Type,
    /// The socket address of the remote peer of an inbound connection.
    pub source: SocketAddr,
    /// The proxy target address of a proxy connection.
    pub destination: SocksAddr,
    /// The locally resolved IP address of the destination domain.
    pub resolved_ip: Option<IpAddr>,
    /// The packet mark SO_MARK
    pub so_mark: Option<u32>,
    /// The bind interface
    pub iface: Option<OutboundInterface>,
    /// ISO 3166-1 alpha-2 country code from country mmdb. Only for display.
    pub country: Option<String>,
    /// ASN org name from ASN mmdb. Only for display.
    pub asn: Option<String>,
    /// Traffic statistics for intelligent proxy selection
    pub traffic_stats: Option<crate::app::remote_content_manager::TrafficStats>,
    /// Authenticated user name from SS2022 EIH (FAC user_id as string).
    /// Set by the Shadowsocks inbound before dispatch; used for per-user
    /// traffic attribution.
    pub inbound_user: Option<String>,
    /// Local port of the inbound listener which accepted this connection.
    pub inbound_port: u16,
    /// Mihomo-compatible inbound listener name (for example `DEFAULT-MIXED`).
    pub inbound_name: String,
    /// Owning operating-system user/application id, when it can be resolved.
    pub uid: u32,
    /// IP differentiated-services code point (the upper six bits of TOS/TC).
    pub dscp: u8,
    /// Resolved process/package name used by process rules and API metadata.
    pub process: String,
    /// Resolved process executable path, when the platform exposes it.
    pub process_path: String,
    /// Domain obtained from TLS/HTTP/QUIC protocol sniffing. Domain rules use
    /// this in preference to the transport destination, matching Mihomo.
    pub sniff_host: String,
}

impl Session {
    /// Host used by domain-based routing rules. Mihomo exposes a sniffed host
    /// to rules even when `override-destination` is disabled.
    pub fn rule_host(&self) -> Option<&str> {
        if self.sniff_host.is_empty() {
            self.destination.domain()
        } else {
            Some(self.sniff_host.as_str())
        }
    }

    pub fn as_map(&self) -> HashMap<String, Box<dyn ESerialize + Send + Sync>> {
        let mut rv = HashMap::new();
        rv.insert("network".to_string(), Box::new(self.network) as _);
        rv.insert("type".to_string(), Box::new(self.typ) as _);
        rv.insert("sourceIP".to_string(), Box::new(self.source.ip()) as _);
        // Mihomo's tracker metadata contract exposes ports as decimal strings.
        // FlClash's generated Metadata model follows that contract, so numeric
        // JSON values here make every request event fail deserialization.
        rv.insert(
            "sourcePort".to_string(),
            Box::new(self.source.port().to_string()) as _,
        );
        rv.insert("destinationIP".to_string(), {
            let ip = self.resolved_ip.or(self.destination.ip());
            let rv = ip.map(|ip| ip.to_string()).unwrap_or_default();
            Box::new(rv) as _
        });
        rv.insert(
            "destinationPort".to_string(),
            Box::new(self.destination.port().to_string()) as _,
        );
        rv.insert("host".to_string(), Box::new(self.destination.host()) as _);
        rv.insert(
            "sourceGeoIP".to_string(),
            Box::new(Vec::<String>::new()) as _,
        );
        rv.insert(
            "destinationGeoIP".to_string(),
            Box::new(self.country.clone().into_iter().collect::<Vec<_>>()) as _,
        );
        rv.insert("sourceIPASN".to_string(), Box::new(String::new()) as _);
        rv.insert(
            "destinationIPASN".to_string(),
            Box::new(self.asn.clone().unwrap_or_default()) as _,
        );
        rv.insert(
            "remoteDestination".to_string(),
            Box::new(String::new()) as _,
        );
        rv.insert("specialProxy".to_string(), Box::new(String::new()) as _);
        rv.insert("specialRules".to_string(), Box::new(String::new()) as _);
        rv.insert("asn".to_string(), Box::new(self.asn.clone()) as _);
        rv.insert("country".to_string(), Box::new(self.country.clone()) as _);
        rv.insert(
            "traffic_stats".to_string(),
            Box::new(self.traffic_stats.clone()) as _,
        );
        if let Some(ref user) = self.inbound_user {
            rv.insert("inboundUser".to_string(), Box::new(user.clone()) as _);
        }
        rv.insert(
            "inboundPort".to_string(),
            Box::new(self.inbound_port.to_string()) as _,
        );
        rv.insert(
            "inboundName".to_string(),
            Box::new(self.inbound_name.clone()) as _,
        );
        rv.insert("uid".to_string(), Box::new(self.uid) as _);
        rv.insert("dscp".to_string(), Box::new(self.dscp) as _);
        rv.insert("process".to_string(), Box::new(self.process.clone()) as _);
        rv.insert(
            "processPath".to_string(),
            Box::new(self.process_path.clone()) as _,
        );
        rv.insert(
            "sniffHost".to_string(),
            Box::new(self.sniff_host.clone()) as _,
        );
        rv
    }
}

impl Default for Session {
    fn default() -> Self {
        Self {
            network: Network::Tcp,
            typ: Type::Http,
            source: SocketAddr::new(IpAddr::V4(Ipv4Addr::new(0, 0, 0, 0)), 0),
            destination: SocksAddr::any_ipv4(),
            resolved_ip: None,
            so_mark: None,
            iface: None,
            country: None,
            asn: None,
            traffic_stats: None,
            inbound_user: None,
            inbound_port: 0,
            inbound_name: String::new(),
            uid: 0,
            dscp: 0,
            process: String::new(),
            process_path: String::new(),
            sniff_host: String::new(),
        }
    }
}

impl Display for Session {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        match self.resolved_ip {
            Some(ip) => write!(
                f,
                "[{}] {} -> {}[{}]",
                self.network, self.source, self.destination, ip
            ),
            None => write!(
                f,
                "[{}] {} -> {}",
                self.network, self.source, self.destination,
            ),
        }
    }
}

impl Debug for Session {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Session")
            .field("network", &self.network)
            .field("source", &self.source)
            .field("destination", &self.destination)
            .field("packet_mark", &self.so_mark)
            .field("iface", &self.iface)
            .field("country", &self.country)
            .field("asn", &self.asn)
            .field("inbound_port", &self.inbound_port)
            .field("inbound_name", &self.inbound_name)
            .field("uid", &self.uid)
            .field("dscp", &self.dscp)
            .field("process", &self.process)
            .field("process_path", &self.process_path)
            .field("sniff_host", &self.sniff_host)
            .finish()
    }
}

impl Clone for Session {
    fn clone(&self) -> Self {
        Self {
            network: self.network,
            typ: self.typ,
            source: self.source,
            destination: self.destination.clone(),
            resolved_ip: self.resolved_ip,
            so_mark: self.so_mark,
            iface: self.iface.as_ref().cloned(),
            country: self.country.clone(),
            asn: self.asn.clone(),
            traffic_stats: self.traffic_stats.clone(),
            inbound_user: self.inbound_user.clone(),
            inbound_port: self.inbound_port,
            inbound_name: self.inbound_name.clone(),
            uid: self.uid,
            dscp: self.dscp,
            process: self.process.clone(),
            process_path: self.process_path.clone(),
            sniff_host: self.sniff_host.clone(),
        }
    }
}

fn invalid_domain() -> io::Error {
    io::Error::other("invalid domain")
}

fn invalid_atyp() -> io::Error {
    io::Error::other("invalid address type")
}

fn insuff_bytes() -> io::Error {
    io::Error::other("insufficient bytes")
}
