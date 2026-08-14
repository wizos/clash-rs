use bytes::{BufMut, Bytes, BytesMut};

pub fn init() {
    let _ = env_logger::builder().is_test(false).try_init();
}

pub fn ipv4_checksum(header: &[u8]) -> u16 {
    let mut sum = 0u32;
    let mut i = 0;
    while i + 1 < header.len() {
        sum += u16::from_be_bytes([header[i], header[i + 1]]) as u32;
        i += 2;
    }
    if i < header.len() {
        sum += (header[i] as u32) << 8;
    }
    while (sum >> 16) != 0 {
        sum = (sum & 0xFFFF) + (sum >> 16);
    }
    !(sum as u16)
}

pub fn tcp_udp_checksum(
    src_ip: [u8; 4],
    dst_ip: [u8; 4],
    proto: u8,
    tcp_udp: &[u8],
) -> u16 {
    let mut sum = 0u32;
    // Pseudo-header
    sum += u16::from_be_bytes([src_ip[0], src_ip[1]]) as u32;
    sum += u16::from_be_bytes([src_ip[2], src_ip[3]]) as u32;
    sum += u16::from_be_bytes([dst_ip[0], dst_ip[1]]) as u32;
    sum += u16::from_be_bytes([dst_ip[2], dst_ip[3]]) as u32;
    sum += proto as u32;
    sum += (tcp_udp.len() as u32) & 0xFFFF;
    // TCP/UDP header and payload
    let mut i = 0;
    while i + 1 < tcp_udp.len() {
        sum += u16::from_be_bytes([tcp_udp[i], tcp_udp[i + 1]]) as u32;
        i += 2;
    }
    if i < tcp_udp.len() {
        sum += (tcp_udp[i] as u32) << 8;
    }
    while (sum >> 16) != 0 {
        sum = (sum & 0xFFFF) + (sum >> 16);
    }
    !(sum as u16)
}

pub fn build_tcp_syn_packet() -> Bytes {
    let src_ip = [1, 1, 1, 1];
    let dst_ip = [2, 2, 2, 2];
    let mut buf = BytesMut::with_capacity(40);
    // IPv4 header (20 bytes)
    buf.put_slice(&[
        0x45, 0x00, 0x00, 40, // Version, IHL, Total Length
        0x00, 0x00, 0x40, 0x00, // ID, Flags/Frag
        0x40, 0x06, 0x00, 0x00, // TTL, Protocol (TCP), Checksum (to fill)
        src_ip[0], src_ip[1], src_ip[2], src_ip[3], dst_ip[0], dst_ip[1], dst_ip[2],
        dst_ip[3],
    ]);
    // TCP header (20 bytes)
    let mut tcp = [
        0x04, 0x00, // Src port 1024
        0x00, 0x50, // Dst port 80
        0x00, 0x00, 0x00, 0x00, // Seq
        0x00, 0x00, 0x00, 0x00, // Ack
        0x50, 0x02, 0x72, 0x10, // Data offset, SYN, window
        0x00, 0x00, // Checksum (to fill)
        0x00, 0x00, // Urgent
    ];
    // Compute TCP checksum
    let tcp_sum = tcp_udp_checksum(src_ip, dst_ip, 6, &tcp);
    tcp[16..18].copy_from_slice(&tcp_sum.to_be_bytes());
    buf.put_slice(&tcp);
    // Compute IPv4 checksum
    let mut ip_hdr = buf[..20].to_vec();
    let ip_sum = ipv4_checksum(&ip_hdr);
    ip_hdr[10..12].copy_from_slice(&ip_sum.to_be_bytes());
    buf[..20].copy_from_slice(&ip_hdr);
    buf.freeze()
}

pub fn build_udp_packet() -> Bytes {
    build_udp_packet_with_payload_dscp(&[], 0)
}

pub fn build_udp_packet_with_payload_dscp(payload: &[u8], dscp: u8) -> Bytes {
    let src_ip = [1, 1, 1, 1];
    let dst_ip = [2, 2, 2, 2];
    let udp_len = 8 + payload.len();
    let total_len = 20 + udp_len;
    assert!(total_len <= u16::MAX as usize);
    assert!(dscp <= 0x3f);

    let mut buf = BytesMut::with_capacity(total_len);
    // IPv4 header (20 bytes)
    buf.put_u8(0x45);
    buf.put_u8(dscp << 2);
    buf.put_u16(total_len as u16);
    buf.put_u16(0);
    buf.put_u16(0x4000);
    buf.put_u8(64);
    buf.put_u8(17);
    buf.put_u16(0);
    buf.put_slice(&src_ip);
    buf.put_slice(&dst_ip);

    let mut udp = BytesMut::with_capacity(udp_len);
    udp.put_u16(5000);
    udp.put_u16(5001);
    udp.put_u16(udp_len as u16);
    udp.put_u16(0);
    udp.put_slice(payload);
    // Compute UDP checksum
    let udp_sum = tcp_udp_checksum(src_ip, dst_ip, 17, &udp);
    udp[6..8].copy_from_slice(&udp_sum.to_be_bytes());
    buf.put_slice(&udp);
    // Compute IPv4 checksum
    let mut ip_hdr = buf[..20].to_vec();
    let ip_sum = ipv4_checksum(&ip_hdr);
    ip_hdr[10..12].copy_from_slice(&ip_sum.to_be_bytes());
    buf[..20].copy_from_slice(&ip_hdr);
    buf.freeze()
}

pub fn build_fragmented_udp_packet(payload: &[u8], dscp: u8) -> Vec<Bytes> {
    const IPV4_FRAGMENT_PAYLOAD: usize = 1480;

    let src_ip = [1, 1, 1, 1];
    let dst_ip = [2, 2, 2, 2];
    let udp_len = 8 + payload.len();
    assert!(udp_len > IPV4_FRAGMENT_PAYLOAD);
    assert!(udp_len <= u16::MAX as usize - 20);
    assert!(dscp <= 0x3f);

    let mut udp = BytesMut::with_capacity(udp_len);
    udp.put_u16(5000);
    udp.put_u16(5001);
    udp.put_u16(udp_len as u16);
    udp.put_u16(0);
    udp.put_slice(payload);
    let udp_sum = tcp_udp_checksum(src_ip, dst_ip, 17, &udp);
    udp[6..8].copy_from_slice(&udp_sum.to_be_bytes());

    udp.chunks(IPV4_FRAGMENT_PAYLOAD)
        .enumerate()
        .map(|(index, fragment)| {
            let offset = index * IPV4_FRAGMENT_PAYLOAD;
            let more_fragments = offset + fragment.len() < udp.len();
            let mut flags_offset = (offset / 8) as u16;
            if more_fragments {
                flags_offset |= 0x2000;
            }

            let total_len = 20 + fragment.len();
            let mut packet = BytesMut::with_capacity(total_len);
            packet.put_u8(0x45);
            packet.put_u8(dscp << 2);
            packet.put_u16(total_len as u16);
            packet.put_u16(0x1234);
            packet.put_u16(flags_offset);
            packet.put_u8(64);
            packet.put_u8(17);
            packet.put_u16(0);
            packet.put_slice(&src_ip);
            packet.put_slice(&dst_ip);
            packet.put_slice(fragment);

            let checksum = ipv4_checksum(&packet[..20]);
            packet[10..12].copy_from_slice(&checksum.to_be_bytes());
            packet.freeze()
        })
        .collect()
}

pub fn build_ipv6_udp_packet(payload: &[u8], dscp: u8) -> Bytes {
    let src_ip = [0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1];
    let dst_ip = [0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 2];
    let udp_len = 8 + payload.len();
    assert!(udp_len <= u16::MAX as usize);
    assert!(dscp <= 0x3f);

    let mut udp = BytesMut::with_capacity(udp_len);
    udp.put_u16(5000);
    udp.put_u16(5001);
    udp.put_u16(udp_len as u16);
    udp.put_u16(0);
    udp.put_slice(payload);
    let checksum = udp_ipv6_checksum(src_ip, dst_ip, &udp);
    udp[6..8].copy_from_slice(&checksum.to_be_bytes());

    let traffic_class = dscp << 2;
    let mut packet = BytesMut::with_capacity(40 + udp_len);
    packet.put_u8(0x60 | (traffic_class >> 4));
    packet.put_u8((traffic_class & 0x0f) << 4);
    packet.put_u16(0);
    packet.put_u16(udp_len as u16);
    packet.put_u8(17);
    packet.put_u8(64);
    packet.put_slice(&src_ip);
    packet.put_slice(&dst_ip);
    packet.put_slice(&udp);
    packet.freeze()
}

fn udp_ipv6_checksum(src_ip: [u8; 16], dst_ip: [u8; 16], udp: &[u8]) -> u16 {
    let mut sum = 0u32;
    for word in src_ip.chunks_exact(2).chain(dst_ip.chunks_exact(2)) {
        sum += u16::from_be_bytes([word[0], word[1]]) as u32;
    }
    sum += ((udp.len() as u32) >> 16) & 0xffff;
    sum += (udp.len() as u32) & 0xffff;
    sum += 17;

    for word in udp.chunks_exact(2) {
        sum += u16::from_be_bytes([word[0], word[1]]) as u32;
    }
    if !udp.len().is_multiple_of(2) {
        sum += (udp[udp.len() - 1] as u32) << 8;
    }
    while sum >> 16 != 0 {
        sum = (sum & 0xffff) + (sum >> 16);
    }

    let checksum = !(sum as u16);
    if checksum == 0 { 0xffff } else { checksum }
}

/// Parse a SYN-ACK packet and return the server's initial sequence number.
pub fn parse_server_isn(syn_ack: &[u8]) -> u32 {
    let ihl = (syn_ack[0] & 0x0F) as usize * 4;
    u32::from_be_bytes(syn_ack[ihl + 4..ihl + 8].try_into().unwrap())
}

/// Extract (seq_num, payload_len) from a raw IPv4/TCP packet.
/// Returns None if the packet is not a valid IPv4/TCP segment.
pub fn parse_tcp_data(pkt: &[u8]) -> Option<(u32, usize)> {
    if pkt.len() < 40 {
        return None;
    }
    if pkt[9] != 0x06 {
        return None; // not TCP
    }
    let ihl = (pkt[0] & 0x0f) as usize * 4;
    if pkt.len() < ihl + 20 {
        return None;
    }
    let tcp = &pkt[ihl..];
    let seq = u32::from_be_bytes([tcp[4], tcp[5], tcp[6], tcp[7]]);
    let data_offset = ((tcp[12] >> 4) as usize) * 4;
    let payload_len = pkt.len().saturating_sub(ihl + data_offset);
    Some((seq, payload_len))
}

/// Build a pure ACK packet with a configurable receive window.
/// src = [1,1,1,1]:1024, dst = [2,2,2,2]:80 — matches build_tcp_syn_packet.
pub fn build_tcp_ack(seq: u32, ack: u32, window: u16) -> Bytes {
    let src_ip = [1u8, 1, 1, 1];
    let dst_ip = [2u8, 2, 2, 2];
    let mut buf = BytesMut::with_capacity(40);
    // IPv4 header
    buf.put_u8(0x45);
    buf.put_u8(0x00);
    buf.put_u16(40);
    buf.put_u16(0x0001);
    buf.put_u16(0x4000);
    buf.put_u8(0x40);
    buf.put_u8(0x06); // TCP
    buf.put_u16(0x0000); // checksum placeholder
    buf.put_slice(&src_ip);
    buf.put_slice(&dst_ip);
    // TCP header
    let tcp_start = buf.len();
    buf.put_u16(1024); // src port
    buf.put_u16(80); // dst port
    buf.put_u32(seq);
    buf.put_u32(ack);
    buf.put_u8(0x50); // data offset = 5
    buf.put_u8(0x10); // ACK flag
    buf.put_u16(window);
    buf.put_u16(0x0000); // checksum placeholder
    buf.put_u16(0x0000); // urgent pointer
    // checksums
    let tcp_sum = tcp_udp_checksum(src_ip, dst_ip, 6, &buf[tcp_start..].to_vec());
    let chk_pos = tcp_start + 16;
    buf[chk_pos..chk_pos + 2].copy_from_slice(&tcp_sum.to_be_bytes());
    let ip_sum = ipv4_checksum(&buf[..20].to_vec());
    buf[10..12].copy_from_slice(&ip_sum.to_be_bytes());
    buf.freeze()
}

/// Build a TCP SYN packet from a custom source port.
/// src = [1,1,1,1]:src_port, dst = [2,2,2,2]:80.
pub fn build_tcp_syn_packet_with_port(src_port: u16) -> Bytes {
    let src_ip = [1u8, 1, 1, 1];
    let dst_ip = [2u8, 2, 2, 2];
    let mut buf = BytesMut::with_capacity(40);
    buf.put_u8(0x45);
    buf.put_u8(0x00);
    buf.put_u16(40);
    buf.put_u16(0x0000);
    buf.put_u16(0x4000);
    buf.put_u8(0x40);
    buf.put_u8(0x06);
    buf.put_u16(0x0000); // IP checksum placeholder
    buf.put_slice(&src_ip);
    buf.put_slice(&dst_ip);
    let tcp_start = buf.len();
    buf.put_u16(src_port);
    buf.put_u16(80);
    buf.put_u32(0); // seq
    buf.put_u32(0); // ack
    buf.put_u8(0x50); // data offset = 5
    buf.put_u8(0x02); // SYN
    buf.put_u16(0x7210);
    buf.put_u16(0x0000); // TCP checksum placeholder
    buf.put_u16(0x0000); // urgent
    let tcp_sum = tcp_udp_checksum(src_ip, dst_ip, 6, &buf[tcp_start..].to_vec());
    let chk_pos = tcp_start + 16;
    buf[chk_pos..chk_pos + 2].copy_from_slice(&tcp_sum.to_be_bytes());
    let ip_sum = ipv4_checksum(&buf[..20].to_vec());
    buf[10..12].copy_from_slice(&ip_sum.to_be_bytes());
    buf.freeze()
}

/// Extract the TCP destination port from an IPv4/TCP packet (= the client's
/// source port on return traffic).
pub fn tcp_dst_port(packet: &[u8]) -> Option<u16> {
    if packet.len() < 24 || packet[9] != 0x06 {
        return None;
    }
    let ihl = (packet[0] & 0x0F) as usize * 4;
    if packet.len() < ihl + 4 {
        return None;
    }
    Some(u16::from_be_bytes([packet[ihl + 2], packet[ihl + 3]]))
}

/// Returns true if the packet has the RST flag set.
pub fn is_rst(packet: &[u8]) -> bool {
    if packet.len() < 20 || packet[9] != 0x06 {
        return false;
    }
    let ihl = (packet[0] & 0x0F) as usize * 4;
    if packet.len() < ihl + 14 {
        return false;
    }
    (packet[ihl + 13] & 0x04) != 0
}

pub fn is_syn_ack(packet: &[u8]) -> bool {
    // IPv4 header: minimum 20 bytes
    if packet.len() < 20 {
        return false;
    }
    let ihl = (packet[0] & 0x0F) as usize * 4;
    if packet.len() < ihl + 14 {
        return false;
    } // TCP header at least 14 bytes after IP

    // Protocol field in IPv4 header (should be 6 for TCP)
    if packet[9] != 0x06 {
        return false;
    }

    // TCP header starts after IPv4 header
    let tcp_offset = ihl;
    // TCP flags are at offset 13 in TCP header (relative to TCP header start)
    let flags = packet[tcp_offset + 13];
    (flags & 0x12) == 0x12 // SYN and ACK bits set
}
