//! The KIP control layer: message framing, the X25519 client handshake, the
//! directional session-key derivation, and OpenTCP address encoding.
//!
//! All KIP traffic runs *inside* the AEAD record layer. A message is
//! `"kip" || type(1) || len(2 BE) || payload`. The handshake exchanges a
//! `ClientHello` (timestamp, user hash, nonce, ephemeral X25519 pubkey,
//! features, optional table hint) for a `ServerHello` (echoed nonce, server
//! ephemeral pubkey, selected features), then both sides derive session keys
//! from the ECDH shared secret and rekey the record layer.

use std::{
    net::IpAddr,
    time::{SystemTime, UNIX_EPOCH},
};

use anyhow::{Context, Result, bail};
use hkdf::Hkdf;
use sha2::{Digest, Sha256};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use x25519_dalek::{EphemeralSecret, PublicKey};

use crate::session::SocksAddr;

pub(crate) const KIP_MAGIC: &[u8; 3] = b"kip";

pub(crate) const KIP_TYPE_CLIENT_HELLO: u8 = 0x01;
pub(crate) const KIP_TYPE_SERVER_HELLO: u8 = 0x02;
pub(crate) const KIP_TYPE_OPEN_TCP: u8 = 0x10;
/// Upgrade the tunnel into a native mux carrier (empty payload). Sent once,
/// immediately after the handshake, in place of `OpenTCP`; afterwards the
/// record stream carries mux frames instead of a single relayed connection.
pub(crate) const KIP_TYPE_START_MUX: u8 = 0x11;
/// Upgrade the tunnel into a UDP-over-TCP carrier (empty payload). Sent once,
/// immediately after the handshake, in place of `OpenTCP`.
pub(crate) const KIP_TYPE_START_UOT: u8 = 0x12;

const KIP_FEAT_OPEN_TCP: u32 = 1 << 0;
const KIP_FEAT_MUX: u32 = 1 << 1;
const KIP_FEAT_UOT: u32 = 1 << 2;
const KIP_FEAT_REVERSE: u32 = 1 << 3;
const KIP_FEAT_KEEPALIVE: u32 = 1 << 4;
pub(crate) const KIP_FEAT_ALL: u32 = KIP_FEAT_OPEN_TCP
    | KIP_FEAT_MUX
    | KIP_FEAT_UOT
    | KIP_FEAT_REVERSE
    | KIP_FEAT_KEEPALIVE;

const USER_HASH_SIZE: usize = 8;
const NONCE_SIZE: usize = 16;
const PUB_SIZE: usize = 32;
const KIP_MAX_PAYLOAD: usize = u16::MAX as usize;

const ATYP_IPV4: u8 = 0x01;
const ATYP_DOMAIN: u8 = 0x03;
const ATYP_IPV6: u8 = 0x04;

/// Write a framed KIP message to `w`.
pub(crate) async fn write_message<W>(
    w: &mut W,
    typ: u8,
    payload: &[u8],
) -> Result<()>
where
    W: AsyncWrite + Unpin,
{
    if payload.len() > KIP_MAX_PAYLOAD {
        bail!("sudoku/kip: payload too large: {}", payload.len());
    }
    let payload_len =
        u16::try_from(payload.len()).context("sudoku/kip: payload length")?;
    let mut hdr = [0u8; 6];
    hdr[..3].copy_from_slice(KIP_MAGIC);
    hdr[3] = typ;
    hdr[4..].copy_from_slice(&payload_len.to_be_bytes());
    w.write_all(&hdr)
        .await
        .context("sudoku/kip: write header")?;
    if !payload.is_empty() {
        w.write_all(payload)
            .await
            .context("sudoku/kip: write payload")?;
    }
    Ok(())
}

/// Read a framed KIP message from `r`, returning `(type, payload)`.
pub(crate) async fn read_message<R>(r: &mut R) -> Result<(u8, Vec<u8>)>
where
    R: AsyncRead + Unpin,
{
    let mut hdr = [0u8; 6];
    r.read_exact(&mut hdr)
        .await
        .context("sudoku/kip: read header")?;
    if &hdr[..3] != KIP_MAGIC {
        bail!("sudoku/kip: bad magic");
    }
    let typ = hdr[3];
    let n = u16::from_be_bytes([hdr[4], hdr[5]]) as usize;
    if n > KIP_MAX_PAYLOAD {
        bail!("sudoku/kip: invalid payload length: {n}");
    }
    let mut payload = vec![0u8; n];
    if n > 0 {
        r.read_exact(&mut payload)
            .await
            .context("sudoku/kip: read payload")?;
    }
    Ok((typ, payload))
}

/// Derive the 8-byte user hash from the private key, or the PSK as fallback
/// (`kipUserHashFromPrivateKey`).
fn user_hash(private_key: &[u8], psk: &str) -> [u8; USER_HASH_SIZE] {
    let mut out = [0u8; USER_HASH_SIZE];
    let digest = if !private_key.is_empty() {
        Sha256::digest(private_key)
    } else {
        Sha256::digest(psk.trim().as_bytes())
    };
    out.copy_from_slice(&digest[..USER_HASH_SIZE]);
    out
}

fn encode_client_hello(
    user_hash: &[u8; USER_HASH_SIZE],
    nonce: &[u8; NONCE_SIZE],
    client_pub: &[u8; PUB_SIZE],
    features: u32,
    table_hint: Option<u32>,
) -> Vec<u8> {
    let ts = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0);
    let mut b = Vec::with_capacity(8 + USER_HASH_SIZE + NONCE_SIZE + PUB_SIZE + 8);
    b.extend_from_slice(&ts.to_be_bytes());
    b.extend_from_slice(user_hash);
    b.extend_from_slice(nonce);
    b.extend_from_slice(client_pub);
    b.extend_from_slice(&features.to_be_bytes());
    if let Some(hint) = table_hint {
        b.extend_from_slice(&hint.to_be_bytes());
    }
    b
}

struct ServerHello {
    nonce: [u8; NONCE_SIZE],
    server_pub: [u8; PUB_SIZE],
    selected_feats: u32,
}

fn decode_server_hello(payload: &[u8]) -> Result<ServerHello> {
    let want = NONCE_SIZE + PUB_SIZE + 4;
    if payload.len() != want {
        bail!("sudoku/kip: server hello bad len: {}", payload.len());
    }
    let mut nonce = [0u8; NONCE_SIZE];
    let mut server_pub = [0u8; PUB_SIZE];
    nonce.copy_from_slice(&payload[..NONCE_SIZE]);
    server_pub.copy_from_slice(&payload[NONCE_SIZE..NONCE_SIZE + PUB_SIZE]);
    let selected_feats = u32::from_be_bytes(
        payload[NONCE_SIZE + PUB_SIZE..]
            .try_into()
            .expect("len checked"),
    );
    Ok(ServerHello {
        nonce,
        server_pub,
        selected_feats,
    })
}

/// HKDF-Expand of `prk` (no extract) into 32 bytes with `info`. Matches Go's
/// `hkdf.Expand(sha256.New, prk, info, 32)`.
fn hkdf_expand_32(prk: &[u8], info: &[u8]) -> [u8; 32] {
    let hk = Hkdf::<Sha256>::from_prk(prk).expect("prk length valid for sha256");
    let mut okm = [0u8; 32];
    hk.expand(info, &mut okm)
        .expect("32 bytes is within hkdf limit");
    okm
}

/// `derivePSKDirectionalBases`: `SHA256(psk)` → HKDF-Expand per direction.
pub(crate) fn derive_psk_bases(psk: &str) -> ([u8; 32], [u8; 32]) {
    let sum = Sha256::digest(psk.as_bytes());
    let c2s = hkdf_expand_32(&sum, b"sudoku-psk-c2s");
    let s2c = hkdf_expand_32(&sum, b"sudoku-psk-s2c");
    (c2s, s2c)
}

/// `deriveSessionDirectionalBases`: HKDF-Extract(salt=SHA256(psk),
/// ikm=shared||nonce) then Expand per direction.
pub(crate) fn derive_session_bases(
    psk: &str,
    shared: &[u8],
    nonce: &[u8; NONCE_SIZE],
) -> ([u8; 32], [u8; 32]) {
    let sum = Sha256::digest(psk.as_bytes());
    let mut ikm = Vec::with_capacity(shared.len() + NONCE_SIZE);
    ikm.extend_from_slice(shared);
    ikm.extend_from_slice(nonce);
    let (prk, _) = Hkdf::<Sha256>::extract(Some(&sum), &ikm);
    let c2s = hkdf_expand_32(&prk, b"sudoku-session-c2s");
    let s2c = hkdf_expand_32(&prk, b"sudoku-session-s2c");
    (c2s, s2c)
}

/// The result of a completed handshake: the new session directional bases.
pub(crate) struct HandshakeOutcome {
    pub(crate) session_c2s: [u8; 32],
    pub(crate) session_s2c: [u8; 32],
    #[allow(dead_code)]
    pub(crate) selected_feats: u32,
}

/// Run the KIP client handshake over an established (record-wrapped) stream.
/// Returns the derived session keys for the caller to rekey the record layer.
pub(crate) async fn client_handshake<S>(
    stream: &mut S,
    psk: &str,
    private_key: &[u8],
    table_hint: Option<u32>,
) -> Result<HandshakeOutcome>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    let ephemeral = EphemeralSecret::random();
    let client_pub = PublicKey::from(&ephemeral);

    let mut nonce = [0u8; NONCE_SIZE];
    getrandom::fill(&mut nonce).context("sudoku/kip: nonce rng")?;

    let uh = user_hash(private_key, psk);
    let hello = encode_client_hello(
        &uh,
        &nonce,
        client_pub.as_bytes(),
        KIP_FEAT_ALL,
        table_hint,
    );
    write_message(stream, KIP_TYPE_CLIENT_HELLO, &hello)
        .await
        .context("sudoku/kip: write ClientHello")?;
    stream.flush().await.ok();

    let (typ, payload) = read_message(stream)
        .await
        .context("sudoku/kip: read ServerHello")?;
    if typ != KIP_TYPE_SERVER_HELLO {
        bail!("sudoku/kip: unexpected handshake message type: {typ}");
    }
    let sh = decode_server_hello(&payload)?;
    if sh.nonce != nonce {
        bail!("sudoku/kip: handshake nonce mismatch");
    }

    let peer_pub = PublicKey::from(sh.server_pub);
    let shared = ephemeral.diffie_hellman(&peer_pub);
    let (session_c2s, session_s2c) =
        derive_session_bases(psk, shared.as_bytes(), &nonce);

    Ok(HandshakeOutcome {
        session_c2s,
        session_s2c,
        selected_feats: sh.selected_feats,
    })
}

/// Encode a target as a SOCKS5-style address (`atyp || addr || port BE`),
/// matching `protocol.WriteAddress`.
pub(crate) fn encode_address(target: &SocksAddr) -> Result<Vec<u8>> {
    let mut buf = Vec::with_capacity(1 + 16 + 2);
    match target {
        SocksAddr::Ip(addr) => match addr.ip() {
            IpAddr::V4(v4) => {
                buf.push(ATYP_IPV4);
                buf.extend_from_slice(&v4.octets());
            }
            IpAddr::V6(v6) => {
                buf.push(ATYP_IPV6);
                buf.extend_from_slice(&v6.octets());
            }
        },
        SocksAddr::Domain(host, _) => {
            if host.len() > 255 {
                bail!("sudoku/kip: domain too long");
            }
            buf.push(ATYP_DOMAIN);
            buf.push(host.len() as u8);
            buf.extend_from_slice(host.as_bytes());
        }
    }
    buf.extend_from_slice(&target.port().to_be_bytes());
    Ok(buf)
}

/// Write an OpenTCP request for `target` over the (record-wrapped) stream.
pub(crate) async fn write_open_tcp<W>(w: &mut W, target: &SocksAddr) -> Result<()>
where
    W: AsyncWrite + Unpin,
{
    let addr = encode_address(target)?;
    write_message(w, KIP_TYPE_OPEN_TCP, &addr)
        .await
        .context("sudoku/kip: write OpenTCP")?;
    w.flush().await.ok();
    Ok(())
}

/// Write the `StartMux` control message (empty payload) that upgrades the
/// tunnel into a native mux carrier, sent once immediately after the handshake.
pub(crate) async fn write_start_mux<W>(w: &mut W) -> Result<()>
where
    W: AsyncWrite + Unpin,
{
    write_message(w, KIP_TYPE_START_MUX, &[])
        .await
        .context("sudoku/kip: write StartMux")?;
    w.flush().await.ok();
    Ok(())
}

#[cfg(test)]
mod tests {
    use std::net::SocketAddr;

    use super::*;

    #[tokio::test]
    async fn message_payload_respects_the_u16_wire_boundary() {
        let payload = vec![0x5a; KIP_MAX_PAYLOAD];
        let (mut writer, mut reader) = tokio::io::duplex(KIP_MAX_PAYLOAD + 6);
        write_message(&mut writer, KIP_TYPE_OPEN_TCP, &payload)
            .await
            .unwrap();
        let (typ, decoded) = read_message(&mut reader).await.unwrap();
        assert_eq!(typ, KIP_TYPE_OPEN_TCP);
        assert_eq!(decoded, payload);

        let mut sink = tokio::io::sink();
        assert!(
            write_message(
                &mut sink,
                KIP_TYPE_OPEN_TCP,
                &vec![0; KIP_MAX_PAYLOAD + 1]
            )
            .await
            .is_err()
        );
    }

    #[test]
    fn encode_address_ipv4() {
        let target = SocksAddr::Ip("1.2.3.4:443".parse::<SocketAddr>().unwrap());
        let buf = encode_address(&target).unwrap();
        assert_eq!(buf, vec![ATYP_IPV4, 1, 2, 3, 4, 0x01, 0xbb]);
    }

    #[test]
    fn encode_address_ipv6() {
        let target = SocksAddr::Ip("[::1]:80".parse::<SocketAddr>().unwrap());
        let buf = encode_address(&target).unwrap();
        assert_eq!(buf[0], ATYP_IPV6);
        assert_eq!(buf.len(), 1 + 16 + 2);
        assert_eq!(&buf[17..], &[0x00, 0x50]);
    }

    #[test]
    fn encode_address_domain() {
        let target = SocksAddr::Domain("example.com".to_string(), 8080);
        let buf = encode_address(&target).unwrap();
        assert_eq!(buf[0], ATYP_DOMAIN);
        assert_eq!(buf[1] as usize, "example.com".len());
        assert_eq!(&buf[2..2 + 11], b"example.com");
        assert_eq!(&buf[2 + 11..], &[0x1f, 0x90]);
    }

    #[test]
    fn encode_address_rejects_overlong_domain() {
        let target = SocksAddr::Domain("a".repeat(256), 1);
        assert!(encode_address(&target).is_err());
    }

    #[test]
    fn psk_bases_are_deterministic_and_directional() {
        let (c2s_a, s2c_a) = derive_psk_bases("secret");
        let (c2s_b, s2c_b) = derive_psk_bases("secret");
        assert_eq!(c2s_a, c2s_b);
        assert_eq!(s2c_a, s2c_b);
        assert_ne!(c2s_a, s2c_a);
        let (c2s_c, _) = derive_psk_bases("other");
        assert_ne!(c2s_a, c2s_c);
    }

    #[test]
    fn session_bases_match_for_shared_secret() {
        let nonce = [7u8; NONCE_SIZE];
        let shared = [0x42u8; 32];
        let (c2s_a, s2c_a) = derive_session_bases("psk", &shared, &nonce);
        let (c2s_b, s2c_b) = derive_session_bases("psk", &shared, &nonce);
        assert_eq!(c2s_a, c2s_b);
        assert_eq!(s2c_a, s2c_b);
        assert_ne!(c2s_a, s2c_a);
        // A different shared secret yields different bases.
        let (c2s_c, _) = derive_session_bases("psk", &[0x43u8; 32], &nonce);
        assert_ne!(c2s_a, c2s_c);
    }

    #[test]
    fn user_hash_prefers_private_key_then_psk() {
        let with_key = user_hash(b"private", "psk");
        let without_key = user_hash(b"", "psk");
        assert_ne!(with_key, without_key);
        assert_eq!(without_key, user_hash(b"", " psk "));
    }
}
