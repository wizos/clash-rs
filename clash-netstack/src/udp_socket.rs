use crate::{Packet, packet::IpPacket};
use etherparse::PacketBuilder;
use log::trace;
use smoltcp::{
    iface::{Config, Interface, PollIngressSingleResult, SocketHandle, SocketSet},
    phy::{
        ChecksumCapabilities, Device, DeviceCapabilities, Medium, RxToken, TxToken,
    },
    socket::raw,
    time::Instant as SmolInstant,
    wire::{
        HardwareAddress, IpAddress, IpCidr, IpProtocol, UdpPacket as SmolUdpPacket,
        UdpRepr,
    },
};
use std::net::SocketAddr;
use tokio::sync::mpsc;

// IPv6's 16-bit payload length excludes the 40-byte base header.
const RAW_PACKET_CAPACITY: usize = u16::MAX as usize + 40;

pub struct UdpPacket {
    pub data: Packet,
    /// src of the packet
    pub local_addr: SocketAddr,
    /// dst of the packet
    pub remote_addr: SocketAddr,
    pub dscp: u8,
}
impl std::fmt::Debug for UdpPacket {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("UdpPacket")
            .field("local_addr", &self.local_addr)
            .field("remote_addr", &self.remote_addr)
            .field("data_len", &self.data().len())
            .finish()
    }
}

impl<T> From<(T, SocketAddr, SocketAddr)> for UdpPacket
where
    T: Into<Packet>,
{
    fn from((data, local_addr, remote_addr): (T, SocketAddr, SocketAddr)) -> Self {
        UdpPacket {
            data: data.into(),
            local_addr,
            remote_addr,
            dscp: 0,
        }
    }
}

impl UdpPacket {
    pub fn data(&self) -> &[u8] {
        self.data.data()
    }
}

pub struct UdpSocket {
    inbound: mpsc::Receiver<Packet>,
    outbound: mpsc::Sender<Packet>,
}

impl UdpSocket {
    pub fn new(
        inbound: mpsc::Receiver<Packet>,
        outbound: mpsc::Sender<Packet>,
    ) -> Self {
        Self { inbound, outbound }
    }

    pub fn split(self) -> (SplitRead, SplitWrite) {
        let read = SplitRead {
            recv: self.inbound,
            processor: UdpIngressProcessor::new(),
        };
        let write = SplitWrite {
            send: self.outbound,
        };
        (read, write)
    }
}

pub struct SplitRead {
    recv: mpsc::Receiver<Packet>,
    processor: UdpIngressProcessor,
}

impl SplitRead {
    pub async fn recv(&mut self) -> Option<UdpPacket> {
        while let Some(packet) = self.recv.recv().await {
            if let Some(datagram) = self.processor.process(packet) {
                return Some(datagram);
            }
        }
        None
    }
}

/// Runs UDP packets through smoltcp's IP ingress path while exposing raw
/// datagrams to clash-rs. A raw socket is intentional here: a transparent TUN
/// proxy must accept every destination port, while a normal smoltcp UDP socket
/// must bind one concrete local port.
struct UdpIngressProcessor {
    iface: Interface,
    device: UdpIngressDevice,
    sockets: SocketSet<'static>,
    raw_socket: SocketHandle,
}

impl UdpIngressProcessor {
    fn new() -> Self {
        let mut device = UdpIngressDevice::new();
        let mut config = Config::new(HardwareAddress::Ip);
        config.random_seed = rand::random();
        let mut iface = Interface::new(config, &mut device, SmolInstant::now());
        iface.set_any_ip(true);
        iface.update_ip_addrs(|ip_addrs| {
            let _ = ip_addrs.push(IpCidr::new(
                smoltcp::wire::Ipv4Address::new(10, 0, 0, 1).into(),
                24,
            ));
            let _ = ip_addrs.push(IpCidr::new(
                smoltcp::wire::Ipv6Address::new(0x0, 0xfac, 0, 0, 0, 0, 0, 1).into(),
                64,
            ));
        });
        iface
            .routes_mut()
            .add_default_ipv4_route(smoltcp::wire::Ipv4Address::new(10, 0, 0, 1))
            .expect("failed to add UDP IPv4 route");
        iface
            .routes_mut()
            .add_default_ipv6_route(smoltcp::wire::Ipv6Address::new(
                0x0, 0xfac, 0, 0, 0, 0, 0, 1,
            ))
            .expect("failed to add UDP IPv6 route");

        // Ingress is processed one packet at a time, so one raw packet slot is
        // sufficient. The payload storage still accepts the largest valid IP
        // packet after IPv4 reassembly.
        let rx_buffer = raw::PacketBuffer::new(
            vec![raw::PacketMetadata::EMPTY; 1],
            vec![0; RAW_PACKET_CAPACITY],
        );
        let tx_buffer = raw::PacketBuffer::new(Vec::new(), Vec::new());
        let socket =
            raw::Socket::new(None, Some(IpProtocol::Udp), rx_buffer, tx_buffer);
        let mut sockets = SocketSet::new(Vec::new());
        let raw_socket = sockets.add(socket);

        Self {
            iface,
            device,
            sockets,
            raw_socket,
        }
    }

    fn process(&mut self, packet: Packet) -> Option<UdpPacket> {
        let dscp = IpPacket::new_checked(packet.data()).ok()?.dscp();
        self.device.replace(packet);

        let now = SmolInstant::now();
        while !matches!(
            self.iface
                .poll_ingress_single(now, &mut self.device, &mut self.sockets),
            PollIngressSingleResult::None
        ) {}

        let socket = self.sockets.get_mut::<raw::Socket>(self.raw_socket);
        let packet = match socket.recv() {
            Ok(packet) => packet,
            Err(_) => return None,
        };

        parse_udp_datagram(packet, dscp)
    }
}

fn parse_udp_datagram(packet: &[u8], dscp: u8) -> Option<UdpPacket> {
    let ip_packet = IpPacket::new_checked(packet).ok()?;
    let src_ip = ip_packet.src_addr();
    let dst_ip = ip_packet.dst_addr();
    let (src_smol, dst_smol) = smoltcp_ip_addresses(&ip_packet);
    let udp_packet = SmolUdpPacket::new_checked(ip_packet.payload()).ok()?;

    // A raw socket receives the packet before smoltcp's UDP socket dispatch.
    // Validate the UDP checksum explicitly so the adapter cannot pass a packet
    // that the normal smoltcp UDP path would reject.
    UdpRepr::parse(
        &udp_packet,
        &src_smol,
        &dst_smol,
        &ChecksumCapabilities::default(),
    )
    .ok()?;

    let local_addr = SocketAddr::new(src_ip, udp_packet.src_port());
    let remote_addr = SocketAddr::new(dst_ip, udp_packet.dst_port());

    trace!("created UDP datagram for {local_addr} <-> {remote_addr}");
    Some(UdpPacket {
        data: Packet::new(udp_packet.payload().to_vec()),
        local_addr,
        remote_addr,
        dscp,
    })
}

fn smoltcp_ip_addresses(packet: &IpPacket<&[u8]>) -> (IpAddress, IpAddress) {
    match packet {
        IpPacket::Ipv4(packet) => {
            (packet.src_addr().into(), packet.dst_addr().into())
        }
        IpPacket::Ipv6(packet) => {
            (packet.src_addr().into(), packet.dst_addr().into())
        }
    }
}

struct UdpIngressDevice {
    packet: Option<Packet>,
    capabilities: DeviceCapabilities,
}

impl UdpIngressDevice {
    fn new() -> Self {
        let mut capabilities = DeviceCapabilities::default();
        capabilities.max_transmission_unit = RAW_PACKET_CAPACITY;
        capabilities.medium = Medium::Ip;
        Self {
            packet: None,
            capabilities,
        }
    }

    fn replace(&mut self, packet: Packet) {
        debug_assert!(self.packet.is_none());
        self.packet = Some(packet);
    }
}

impl Device for UdpIngressDevice {
    type RxToken<'a> = UdpRxToken;
    type TxToken<'a> = UdpTxToken;

    fn receive(
        &mut self,
        _timestamp: SmolInstant,
    ) -> Option<(Self::RxToken<'_>, Self::TxToken<'_>)> {
        self.packet
            .take()
            .map(|packet| (UdpRxToken(packet), UdpTxToken))
    }

    fn transmit(&mut self, _timestamp: SmolInstant) -> Option<Self::TxToken<'_>> {
        Some(UdpTxToken)
    }

    fn capabilities(&self) -> DeviceCapabilities {
        self.capabilities.clone()
    }
}

struct UdpRxToken(Packet);

impl RxToken for UdpRxToken {
    fn consume<R, F>(self, f: F) -> R
    where
        F: FnOnce(&[u8]) -> R,
    {
        f(self.0.data())
    }
}

struct UdpTxToken;

impl TxToken for UdpTxToken {
    fn consume<R, F>(self, len: usize, f: F) -> R
    where
        F: FnOnce(&mut [u8]) -> R,
    {
        let mut discarded = vec![0; len];
        f(&mut discarded)
    }
}

#[derive(Clone)]
pub struct SplitWrite {
    send: mpsc::Sender<Packet>,
}

impl SplitWrite {
    pub async fn send(&mut self, packet: UdpPacket) -> Result<(), std::io::Error> {
        if packet.data.data().is_empty() {
            return Ok(());
        }

        let builder = match (packet.local_addr, packet.remote_addr) {
            (SocketAddr::V4(src), SocketAddr::V4(dst)) => {
                PacketBuilder::ipv4(src.ip().octets(), dst.ip().octets(), 20)
                    .udp(src.port(), dst.port())
            }
            (SocketAddr::V6(src), SocketAddr::V6(dst)) => {
                PacketBuilder::ipv6(src.ip().octets(), dst.ip().octets(), 20)
                    .udp(src.port(), dst.port())
            }
            _ => {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::InvalidInput,
                    "UDP socket only supports IPv4 and IPv6",
                ));
            }
        };

        let mut ip_packet_writer =
            Vec::with_capacity(builder.size(packet.data.data().len()));
        builder
            .write(&mut ip_packet_writer, packet.data.data())
            .map_err(std::io::Error::other)?;

        // UDP is inherently unreliable — drop the packet if the outbound
        // channel is full rather than blocking the UDP handler task.
        match self.send.try_send(Packet::new(ip_packet_writer)) {
            Ok(()) => Ok(()),
            Err(mpsc::error::TrySendError::Full(_)) => Ok(()),
            Err(mpsc::error::TrySendError::Closed(_)) => Err(std::io::Error::new(
                std::io::ErrorKind::BrokenPipe,
                "packet outbound channel closed",
            )),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn closed_outbound_channel_is_broken_pipe() {
        let (send, recv) = mpsc::channel(1);
        drop(recv);
        let mut writer = SplitWrite { send };
        let packet = (
            vec![1],
            "127.0.0.1:1000".parse().unwrap(),
            "127.0.0.1:2000".parse().unwrap(),
        )
            .into();

        let error = writer.send(packet).await.unwrap_err();

        assert_eq!(error.kind(), std::io::ErrorKind::BrokenPipe);
    }
}
