use std::{
    io,
    net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr},
};

use bytes::{BufMut, BytesMut};

use crate::session::SocksAddr;

pub(crate) const MAGIC_ADDRESS: &str = "sp.packet-addr.v2fly.arpa";

pub(crate) fn magic_destination() -> SocksAddr {
    SocksAddr::Domain(MAGIC_ADDRESS.to_owned(), 443)
}

pub(crate) fn encode(address: &SocksAddr, payload: &[u8]) -> io::Result<Vec<u8>> {
    let mut buffer = BytesMut::with_capacity(19 + payload.len());
    match address {
        SocksAddr::Ip(SocketAddr::V4(address)) => {
            buffer.put_u8(0x01);
            buffer.put_slice(&address.ip().octets());
            buffer.put_u16(address.port());
        }
        SocksAddr::Ip(SocketAddr::V6(address)) => {
            buffer.put_u8(0x02);
            buffer.put_slice(&address.ip().octets());
            buffer.put_u16(address.port());
        }
        SocksAddr::Domain(domain, _) => {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                format!("packetaddr does not support domain destination `{domain}`"),
            ));
        }
    }
    buffer.put_slice(payload);
    Ok(buffer.to_vec())
}

pub(crate) fn decode(packet: &[u8]) -> io::Result<(SocksAddr, &[u8])> {
    let (address, address_len) = match packet.first().copied() {
        Some(0x01) if packet.len() >= 7 => {
            let ip = Ipv4Addr::new(packet[1], packet[2], packet[3], packet[4]);
            let port = u16::from_be_bytes([packet[5], packet[6]]);
            (SocksAddr::Ip(SocketAddr::new(IpAddr::V4(ip), port)), 7)
        }
        Some(0x02) if packet.len() >= 19 => {
            let mut octets = [0; 16];
            octets.copy_from_slice(&packet[1..17]);
            let port = u16::from_be_bytes([packet[17], packet[18]]);
            (
                SocksAddr::Ip(SocketAddr::new(
                    IpAddr::V6(Ipv6Addr::from(octets)),
                    port,
                )),
                19,
            )
        }
        Some(0x01) | Some(0x02) => {
            return Err(io::Error::new(
                io::ErrorKind::UnexpectedEof,
                "truncated packetaddr address",
            ));
        }
        Some(family) => {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                format!("unsupported packetaddr address family {family:#04x}"),
            ));
        }
        None => {
            return Err(io::Error::new(
                io::ErrorKind::UnexpectedEof,
                "empty packetaddr packet",
            ));
        }
    };
    Ok((address, &packet[address_len..]))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn roundtrips_ipv4_and_ipv6() {
        for address in [
            SocksAddr::Ip("1.1.1.1:53".parse().unwrap()),
            SocksAddr::Ip("[2001:db8::1]:5353".parse().unwrap()),
        ] {
            let encoded = encode(&address, b"dns-query").unwrap();
            let (decoded, payload) = decode(&encoded).unwrap();
            assert_eq!(decoded, address);
            assert_eq!(payload, b"dns-query");
        }
    }

    #[test]
    fn rejects_domain_and_truncated_address() {
        assert!(encode(&SocksAddr::Domain("example.com".into(), 53), b"x").is_err());
        assert!(decode(&[0x01, 127]).is_err());
    }
}
