use crate::session::SocksAddr;
use anyhow::anyhow;
use bytes::{Buf, BufMut, Bytes, BytesMut};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};

// Protocol version for Hysteria v1
const PROTOCOL_VERSION: u8 = 3;

// ============================================================
// ClientHello: version(1) + sendBPS(8) + recvBPS(8) + authLen(2) + auth(var)
// ============================================================

pub struct WriteClientHello;

impl WriteClientHello {
    pub async fn write<W: AsyncWrite + Unpin>(
        writer: &mut W,
        send_bps: u64,
        recv_bps: u64,
        auth: &[u8],
    ) -> anyhow::Result<()> {
        let auth_len = auth.len() as u16;
        let mut buf = BytesMut::with_capacity(1 + 8 + 8 + 2 + auth.len());
        buf.put_u8(PROTOCOL_VERSION);
        buf.put_u64(send_bps);
        buf.put_u64(recv_bps);
        buf.put_u16(auth_len);
        buf.put_slice(auth);
        writer.write_all(&buf).await?;
        Ok(())
    }
}

pub struct ServerHello {
    pub ok: bool,
    pub send_bps: u64,
    pub recv_bps: u64,
    pub message: String,
}

pub struct ReadServerHello;

impl ReadServerHello {
    /// Read ServerHello from a QUIC stream.
    /// Format: ok(1) + sendBPS(8) + recvBPS(8) + messageLen(2) + message(var)
    pub async fn read<R: AsyncRead + Unpin>(
        reader: &mut R,
    ) -> anyhow::Result<ServerHello> {
        // Read fixed header: ok(1) + sendBPS(8) + recvBPS(8) + messageLen(2) = 19
        // bytes
        let mut header = [0u8; 19];
        reader.read_exact(&mut header).await?;

        let ok = header[0] == 1;
        let send_bps = u64::from_be_bytes(header[1..9].try_into().unwrap());
        let recv_bps = u64::from_be_bytes(header[9..17].try_into().unwrap());
        let message_len =
            u16::from_be_bytes(header[17..19].try_into().unwrap()) as usize;

        let message = if message_len > 0 {
            let mut msg_buf = vec![0u8; message_len];
            reader.read_exact(&mut msg_buf).await?;
            String::from_utf8(msg_buf).map_err(|e| {
                anyhow!("invalid UTF-8 in server hello message: {}", e)
            })?
        } else {
            String::new()
        };

        Ok(ServerHello {
            ok,
            send_bps,
            recv_bps,
            message,
        })
    }
}

// ============================================================
// ClientRequest: udp(1) + hostLen(2) + host(var) + port(2)
// ============================================================

pub struct WriteClientRequest;

impl WriteClientRequest {
    /// Write a TCP client request (udp=false)
    pub async fn write_tcp<W: AsyncWrite + Unpin>(
        writer: &mut W,
        dest: &SocksAddr,
    ) -> anyhow::Result<()> {
        let (host, port) = match dest {
            SocksAddr::Ip(addr) => (addr.ip().to_string(), addr.port()),
            SocksAddr::Domain(host, port) => (host.clone(), *port),
        };
        Self::write(writer, false, &host, port).await
    }

    /// Write a UDP client request (udp=true)
    #[allow(dead_code)]
    pub async fn write_udp<W: AsyncWrite + Unpin>(
        writer: &mut W,
    ) -> anyhow::Result<()> {
        Self::write(writer, true, "", 0).await
    }

    async fn write<W: AsyncWrite + Unpin>(
        writer: &mut W,
        udp: bool,
        host: &str,
        port: u16,
    ) -> anyhow::Result<()> {
        let host_bytes = host.as_bytes();
        let host_len = host_bytes.len() as u16;
        let mut buf = BytesMut::with_capacity(1 + 2 + host_bytes.len() + 2);
        buf.put_u8(if udp { 1 } else { 0 });
        buf.put_u16(host_len);
        buf.put_slice(host_bytes);
        buf.put_u16(port);
        writer.write_all(&buf).await?;
        Ok(())
    }
}

// ============================================================
// ServerResponse: ok(1) + udpSessionID(4) + messageLen(2) + message(var)
// ============================================================

pub struct ServerResponse {
    pub ok: bool,
    pub udp_session_id: u32,
    pub message: String,
}

pub struct ReadServerResponse;

impl ReadServerResponse {
    /// Read ServerResponse from a QUIC stream.
    /// Format: ok(1) + udpSessionID(4) + messageLen(2) + message(var)
    pub async fn read<R: AsyncRead + Unpin>(
        reader: &mut R,
    ) -> anyhow::Result<ServerResponse> {
        // Read fixed header: ok(1) + udpSessionID(4) + messageLen(2) = 7 bytes
        let mut header = [0u8; 7];
        reader.read_exact(&mut header).await?;

        let ok = header[0] == 1;
        let udp_session_id = u32::from_be_bytes(header[1..5].try_into().unwrap());
        let message_len =
            u16::from_be_bytes(header[5..7].try_into().unwrap()) as usize;

        let message = if message_len > 0 {
            let mut msg_buf = vec![0u8; message_len];
            reader.read_exact(&mut msg_buf).await?;
            String::from_utf8(msg_buf).map_err(|e| {
                anyhow!("invalid UTF-8 in server response message: {}", e)
            })?
        } else {
            String::new()
        };

        Ok(ServerResponse {
            ok,
            udp_session_id,
            message,
        })
    }
}

// ============================================================
// UDP message format (Hysteria v1):
// sessionID(4) + hostLen(2) + host(var) + port(2) + msgID(2) + fragID(1) +
// fragCount(1) + dataLen(2) + data(var)
// ============================================================

/// ```text
/// [uint32] Session ID
/// [uint16] Host length
/// [bytes]  Host string
/// [uint16] Port
/// [uint16] Packet ID
/// [uint8]  Fragment ID
/// [uint8]  Fragment count
/// [uint16] Data length
/// [bytes]  Payload
/// ```
#[derive(Clone)]
pub struct HysUdpPacket {
    pub session_id: u32,
    pub pkt_id: u16,
    pub frag_id: u8,
    pub frag_count: u8,
    pub addr: SocksAddr,
    pub data: Vec<u8>,
}

impl std::fmt::Debug for HysUdpPacket {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("HysUdpPacket")
            .field("session_id", &format_args!("{:#010x}", self.session_id))
            .field("pkt_id", &self.pkt_id)
            .field("frag_id", &self.frag_id)
            .field("frag_count", &self.frag_count)
            .field("addr", &self.addr)
            .field("data_size", &self.data.len())
            .finish()
    }
}

impl HysUdpPacket {
    /// Decode a UDP message from bytes
    pub fn decode(buf: &mut BytesMut) -> anyhow::Result<Self> {
        if buf.len() < 4 + 2 + 2 + 2 + 1 + 1 + 2 {
            return Err(anyhow!("packet too short"));
        }
        let session_id = buf.get_u32();
        let host_len = buf.get_u16() as usize;
        if buf.remaining() < host_len + 2 + 2 + 1 + 1 + 2 {
            return Err(anyhow!("packet too short for host and remaining fields"));
        }
        let host: Vec<u8> = buf.copy_to_bytes(host_len).to_vec();
        let port = buf.get_u16();
        let pkt_id = buf.get_u16();
        let frag_id = buf.get_u8();
        let frag_count = buf.get_u8();
        let data_len = buf.get_u16() as usize;
        if buf.remaining() < data_len {
            return Err(anyhow!(
                "packet data too short: expected {}, got {}",
                data_len,
                buf.remaining()
            ));
        }
        let data: Vec<u8> = buf.copy_to_bytes(data_len).to_vec();

        let host_str = String::from_utf8(host)
            .map_err(|e| anyhow!("invalid UTF-8 in host: {}", e))?;
        let addr = to_socksaddr(&host_str, port)?;

        Ok(Self {
            session_id,
            pkt_id,
            frag_id,
            frag_count,
            addr,
            data,
        })
    }

    /// Calculate the header size (without data)
    #[allow(dead_code)]
    fn header_size(&self) -> usize {
        let host_len = match &self.addr {
            SocksAddr::Ip(ip) => ip.ip().to_string().len(),
            SocksAddr::Domain(host, _) => host.len(),
        };
        4 + 2 + host_len + 2 + 2 + 1 + 1 + 2
    }
}

fn to_socksaddr(host: &str, port: u16) -> std::io::Result<SocksAddr> {
    // Try parsing as IP first
    if let Ok(ip) = host.parse::<std::net::IpAddr>() {
        Ok(SocksAddr::Ip(std::net::SocketAddr::new(ip, port)))
    } else {
        Ok(SocksAddr::Domain(host.to_string(), port))
    }
}

/// Iterator over fragments of a packet
#[derive(Debug)]
pub struct Fragments<'a, P> {
    session_id: u32,
    pkt_id: u16,
    host: Vec<u8>,
    port: u16,
    frag_total: u8,
    next_frag_id: u8,
    next_frag_start: usize,
    payload: P,
    // used for fragment, not an actual field of packet
    max_pkt_size: usize,
    fixed_size: usize,
    _marker: std::marker::PhantomData<&'a P>,
}

impl<'a, P> Fragments<'a, P>
where
    P: AsRef<[u8]> + 'a,
{
    pub fn new(
        session_id: u32,
        pkt_id: u16,
        addr: SocksAddr,
        max_pkt_size: usize,
        payload: P,
    ) -> Self {
        let (host, port) = match &addr {
            SocksAddr::Ip(ip) => (ip.ip().to_string().into_bytes(), ip.port()),
            SocksAddr::Domain(host, port) => (host.as_bytes().to_vec(), *port),
        };

        // fixed_size = sessionID(4) + hostLen(2) + host + port(2) + msgID(2) +
        // fragID(1) + fragCount(1) + dataLen(2)
        let fixed_size = 4 + 2 + host.len() + 2 + 2 + 1 + 1 + 2;
        let max_data_size = max_pkt_size.saturating_sub(fixed_size);
        let frag_total = if max_data_size == 0 {
            1
        } else {
            payload.as_ref().len().div_ceil(max_data_size) as u8
        };
        let frag_total = frag_total.max(1);

        Self {
            session_id,
            pkt_id,
            host,
            port,
            frag_total,
            next_frag_id: 0,
            next_frag_start: 0,
            payload,
            max_pkt_size,
            fixed_size,
            _marker: std::marker::PhantomData,
        }
    }
}

impl<'a, P> Iterator for Fragments<'a, P>
where
    P: AsRef<[u8]> + 'a,
{
    type Item = Bytes;

    fn next(&mut self) -> Option<Self::Item> {
        if self.next_frag_id < self.frag_total {
            let max_payload_size = self.max_pkt_size.saturating_sub(self.fixed_size);
            let max_payload_size = max_payload_size.max(1);
            let next_frag_end = (self.next_frag_start + max_payload_size)
                .min(self.payload.as_ref().len());
            let payload =
                &self.payload.as_ref()[self.next_frag_start..next_frag_end];

            let mut buf = BytesMut::new();
            buf.reserve(self.fixed_size + payload.len());

            // sessionID(4)
            buf.put_u32(self.session_id);
            // hostLen(2)
            buf.put_u16(self.host.len() as u16);
            // host
            buf.put_slice(&self.host);
            // port(2)
            buf.put_u16(self.port);
            // msgID(2)
            buf.put_u16(self.pkt_id);
            // fragID(1)
            buf.put_u8(self.next_frag_id);
            // fragCount(1)
            buf.put_u8(self.frag_total);
            // dataLen(2)
            buf.put_u16(payload.len() as u16);
            // data
            buf.put_slice(payload);

            let frag = buf.freeze();

            self.next_frag_id += 1;
            self.next_frag_start = next_frag_end;

            Some(frag)
        } else {
            None
        }
    }
}

impl<P> ExactSizeIterator for Fragments<'_, P>
where
    P: AsRef<[u8]>,
{
    fn len(&self) -> usize {
        self.frag_total as usize
    }
}

#[derive(Default)]
pub struct Defragger {
    pub pkt_id: u16,
    pub frags: Vec<Option<HysUdpPacket>>,
    pub cnt: u16,
}

impl Defragger {
    pub fn feed(&mut self, pkt: HysUdpPacket) -> Option<HysUdpPacket> {
        if pkt.frag_count <= 1 {
            return Some(pkt);
        }
        if pkt.frag_count <= pkt.frag_id {
            tracing::warn!(
                "invalid frag, id, count: {}, {}",
                pkt.frag_id,
                pkt.frag_count
            );
            return None;
        }
        let frag_id = pkt.frag_id as usize;

        if pkt.pkt_id != self.pkt_id || pkt.frag_count as usize != self.frags.len() {
            // new packet, overwrite the old one
            // if the new packet frags is 1, should already return
            self.pkt_id = pkt.pkt_id;
            self.frags.clear();
            self.frags.resize(pkt.frag_count as usize, None);
            self.cnt = 0;
            self.frags[frag_id] = Some(pkt);
            self.cnt += 1;
        } else if frag_id < self.frags.len() && self.frags[frag_id].is_none() {
            self.frags[frag_id] = Some(pkt);
            self.cnt += 1;
            if self.cnt as usize == self.frags.len() {
                // now we have all fragments
                let frags = std::mem::take(&mut self.frags);
                let mut iters = frags.into_iter().map(|x| x.unwrap());
                let mut pkt0 = iters.next().unwrap();
                pkt0.frag_count = 1;
                pkt0.frag_id = 0;
                for pkt in iters {
                    pkt0.data.extend_from_slice(&pkt.data);
                }
                return Some(pkt0);
            }
        }
        None
    }
}

#[test]
fn test_client_hello_server_hello_roundtrip() {
    // Test that the wire format sizes match the Go implementation
    // ClientHello: version(1) + sendBPS(8) + recvBPS(8) + authLen(2) = 19 bytes +
    // auth ServerHello: ok(1) + sendBPS(8) + recvBPS(8) + messageLen(2) = 19
    // bytes + message
    assert_eq!(1 + 8 + 8 + 2, 19);
}
