//! Full-stack interop test: a fake Sudoku server built from the same internal
//! primitives the client uses, exercised end-to-end through [`super::connect`].
//!
//! The fake server runs the mirror of the client stack — obfuscation (decode
//! the client uplink / encode the client downlink), the AEAD record layer with
//! swapped directional bases, the KIP `ClientHello`/`ServerHello` X25519
//! handshake, then reads the `OpenTCP` request and echoes the relayed bytes.
//! A passing round-trip proves every layer lines up byte-for-byte.

use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::{TcpListener, TcpStream},
};
use x25519_dalek::{EphemeralSecret, PublicKey};

use crate::{proxy::AnyStream, session::SocksAddr};

use super::{
    SudokuOutboundConfig, connect,
    kip::{
        self, KIP_TYPE_CLIENT_HELLO, KIP_TYPE_OPEN_TCP, KIP_TYPE_SERVER_HELLO,
        KIP_TYPE_START_MUX, KIP_TYPE_START_UOT, derive_psk_bases,
        derive_session_bases, read_message, write_message,
    },
    obfs::ObfsStream,
    record::{AeadMethod, RecordStream},
    table,
};

const KEY: &str = "interop-test-key";
const TABLE_TYPE: &str = "prefer_entropy";

async fn connect_for_test(
    config: &SudokuOutboundConfig,
    target: &SocksAddr,
) -> anyhow::Result<AnyStream> {
    let raw = TcpStream::connect((config.server.as_str(), config.port)).await?;
    connect(config, target, Box::new(raw)).await
}

fn config(port: u16, method: AeadMethod) -> SudokuOutboundConfig {
    config_with(port, method, true)
}

fn config_with(
    port: u16,
    method: AeadMethod,
    pure_downlink: bool,
) -> SudokuOutboundConfig {
    SudokuOutboundConfig {
        server: "127.0.0.1".to_string(),
        port,
        key: KEY.to_string(),
        aead_method: method,
        table_type: TABLE_TYPE.to_string(),
        custom_patterns: vec![String::new()],
        padding_min: 0,
        padding_max: 0,
        pure_downlink,
        session_mux: false,
        http_mask_mode: super::HttpMaskMode::Disabled,
        http_mask_tls: false,
        http_mask_host: String::new(),
        http_mask_path_root: String::new(),
        http_mask_multiplex: "off".to_owned(),
    }
}

fn config_mux(port: u16, method: AeadMethod) -> SudokuOutboundConfig {
    SudokuOutboundConfig {
        session_mux: true,
        ..config_with(port, method, true)
    }
}

fn config_masked(
    port: u16,
    method: AeadMethod,
    path_root: &str,
) -> SudokuOutboundConfig {
    SudokuOutboundConfig {
        http_mask_mode: super::HttpMaskMode::Legacy,
        http_mask_host: format!("127.0.0.1:{port}"),
        http_mask_path_root: path_root.to_string(),
        ..config_with(port, method, true)
    }
}

/// Read and discard a masking HTTP/1.1 request header from `sock` byte-by-byte
/// (so no Sudoku stream bytes are over-read), asserting a valid request line
/// and a `\r\n\r\n` terminator. Returns the request line for further
/// assertions.
async fn consume_http_header(sock: &mut TcpStream) -> String {
    let mut header: Vec<u8> = Vec::new();
    let mut one = [0u8; 1];
    loop {
        sock.read_exact(&mut one)
            .await
            .expect("read mask header byte");
        header.push(one[0]);
        if header.ends_with(b"\r\n\r\n") {
            break;
        }
        assert!(header.len() < 64 * 1024, "mask header too large");
    }
    let text = String::from_utf8(header).expect("ascii mask header");
    let line = text.lines().next().expect("request line").to_string();
    assert!(
        line.ends_with(" HTTP/1.1"),
        "unexpected request line: {line:?}"
    );
    assert!(
        [
            "GET ", "POST ", "HEAD ", "PUT ", "DELETE ", "OPTIONS ", "PATCH "
        ]
        .iter()
        .any(|m| line.starts_with(m)),
        "invalid masked method: {line:?}"
    );
    line
}

/// Mirror the client stack (obfuscation + record with swapped bases) and run
/// the KIP `ClientHello`/`ServerHello` X25519 handshake, returning the rekeyed
/// record stream positioned to read the next control message (`OpenTCP` or
/// `StartUoT`). Shared by the TCP and UoT fake servers.
async fn server_handshake(
    sock: TcpStream,
    method: AeadMethod,
    downlink_packed: bool,
) -> RecordStream<ObfsStream<TcpStream>> {
    // Server obfuscation: decode the client's (pure) uplink, encode its
    // downlink with the pure or packed codec to match the client's read path.
    let tables =
        table::new_directional_table(KEY, TABLE_TYPE, "").expect("server table");
    let obfs = ObfsStream::new(
        sock,
        tables.downlink,
        tables.uplink,
        0,
        0,
        downlink_packed,
        false,
    );

    // Record layer with swapped directional bases (server send = s2c).
    let (psk_c2s, psk_s2c) = derive_psk_bases(KEY);
    let mut rec =
        RecordStream::new(obfs, method, &psk_s2c, &psk_c2s).expect("server record");

    // --- KIP ClientHello ---
    let (typ, payload) = read_message(&mut rec).await.expect("read ClientHello");
    assert_eq!(typ, KIP_TYPE_CLIENT_HELLO);
    // ts(8) | user_hash(8) | nonce(16) | client_pub(32) | features(4)
    assert_eq!(payload.len(), 8 + 8 + 16 + 32 + 4);
    let mut nonce = [0u8; 16];
    nonce.copy_from_slice(&payload[16..32]);
    let mut client_pub = [0u8; 32];
    client_pub.copy_from_slice(&payload[32..64]);

    // --- ServerHello + ECDH ---
    let server_secret = EphemeralSecret::random();
    let server_pub = PublicKey::from(&server_secret);
    let shared = server_secret.diffie_hellman(&PublicKey::from(client_pub));
    let (session_c2s, session_s2c) =
        derive_session_bases(KEY, shared.as_bytes(), &nonce);

    let mut hello = Vec::with_capacity(16 + 32 + 4);
    hello.extend_from_slice(&nonce);
    hello.extend_from_slice(server_pub.as_bytes());
    hello.extend_from_slice(&kip::KIP_FEAT_ALL.to_be_bytes()); // selected features
    write_message(&mut rec, KIP_TYPE_SERVER_HELLO, &hello)
        .await
        .expect("write ServerHello");
    rec.flush().await.expect("flush ServerHello");

    rec.rekey(&session_s2c, &session_c2s).expect("server rekey");
    rec
}

/// Accept one connection and mirror the client stack, asserting the handshake
/// fields and `OpenTCP` address, then echo all relayed bytes.
async fn run_fake_server(
    listener: TcpListener,
    method: AeadMethod,
    expected_addr: Vec<u8>,
    downlink_packed: bool,
) {
    let (sock, _) = listener.accept().await.expect("accept");
    let mut rec = server_handshake(sock, method, downlink_packed).await;

    // --- OpenTCP request ---
    let (typ, addr) = read_message(&mut rec).await.expect("read OpenTCP");
    assert_eq!(typ, KIP_TYPE_OPEN_TCP);
    assert_eq!(addr, expected_addr, "OpenTCP address mismatch");

    // --- echo relayed bytes ---
    let mut buf = vec![0u8; 16 * 1024];
    loop {
        match rec.read(&mut buf).await {
            Ok(0) | Err(_) => break,
            Ok(n) => {
                if rec.write_all(&buf[..n]).await.is_err() {
                    break;
                }
                let _ = rec.flush().await;
            }
        }
    }
}

/// Like [`run_fake_server`] but first consumes a legacy HTTP-mask request
/// header (asserting its `path-root` when one is configured) before running the
/// raw Sudoku handshake and echoing relayed bytes.
async fn run_fake_masked_server(
    listener: TcpListener,
    method: AeadMethod,
    expected_addr: Vec<u8>,
    expected_path_root: Option<&str>,
) {
    let (mut sock, _) = listener.accept().await.expect("accept");
    let line = consume_http_header(&mut sock).await;
    if let Some(root) = expected_path_root {
        let path = line.split(' ').nth(1).expect("request path");
        assert!(
            path.starts_with(&format!("/{root}/")),
            "masked path {path:?} missing path-root /{root}/"
        );
    }

    let mut rec = server_handshake(sock, method, false).await;

    let (typ, addr) = read_message(&mut rec).await.expect("read OpenTCP");
    assert_eq!(typ, KIP_TYPE_OPEN_TCP);
    assert_eq!(addr, expected_addr, "OpenTCP address mismatch");

    let mut buf = vec![0u8; 16 * 1024];
    loop {
        match rec.read(&mut buf).await {
            Ok(0) | Err(_) => break,
            Ok(n) => {
                if rec.write_all(&buf[..n]).await.is_err() {
                    break;
                }
                let _ = rec.flush().await;
            }
        }
    }
}

/// Full-stack TCP relay with legacy HTTP masking enabled: the client prefixes a
/// fake HTTP request header, the fake server consumes it (validating the
/// `path-root`) and then relays over the raw Sudoku stack.
#[tokio::test]
async fn legacy_http_mask_full_stack_round_trip() {
    let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind");
    let port = listener.local_addr().expect("addr").port();

    let method = AeadMethod::ChaCha20Poly1305;
    let target = SocksAddr::Domain("masked.example".to_string(), 8443);
    let expected_addr = kip::encode_address(&target).expect("encode addr");
    let server = tokio::spawn(run_fake_masked_server(
        listener,
        method,
        expected_addr,
        Some("aabbcc"),
    ));

    let cfg = config_masked(port, method, "aabbcc");
    let mut stream = connect_for_test(&cfg, &target)
        .await
        .expect("masked client connect");

    let payload = b"legacy http-masked sudoku relay".to_vec();
    stream.write_all(&payload).await.expect("client write");
    stream.flush().await.expect("client flush");

    let mut got = vec![0u8; payload.len()];
    stream.read_exact(&mut got).await.expect("client read echo");
    assert_eq!(got, payload);

    drop(stream);
    let _ = server.await;
}

/// Accept one connection, run the handshake, read the `StartUoT` preface, then
/// echo each UoT datagram frame verbatim (the received destination address is
/// reflected back as the reply's source address).
async fn run_fake_uot_server(
    listener: TcpListener,
    method: AeadMethod,
    expected_addr: Vec<u8>,
) {
    let (sock, _) = listener.accept().await.expect("accept");
    let mut rec = server_handshake(sock, method, false).await;

    // --- StartUoT preface (empty payload) ---
    let (typ, payload) = read_message(&mut rec).await.expect("read StartUoT");
    assert_eq!(typ, KIP_TYPE_START_UOT);
    assert!(payload.is_empty(), "StartUoT carries no payload");

    // --- echo UoT datagrams ---
    loop {
        let mut header = [0u8; 4];
        if rec.read_exact(&mut header).await.is_err() {
            break;
        }
        let addr_len = u16::from_be_bytes([header[0], header[1]]) as usize;
        let payload_len = u16::from_be_bytes([header[2], header[3]]) as usize;
        let mut addr = vec![0u8; addr_len];
        let mut body = vec![0u8; payload_len];
        if rec.read_exact(&mut addr).await.is_err()
            || rec.read_exact(&mut body).await.is_err()
        {
            break;
        }
        assert_eq!(addr, expected_addr, "UoT destination address mismatch");

        // Reflect the frame back with the destination echoed as the source.
        if rec.write_all(&header).await.is_err()
            || rec.write_all(&addr).await.is_err()
            || rec.write_all(&body).await.is_err()
        {
            break;
        }
        let _ = rec.flush().await;
    }
}

async fn round_trip(method: AeadMethod, payload: Vec<u8>) {
    round_trip_mode(method, payload, true).await;
}

async fn round_trip_mode(method: AeadMethod, payload: Vec<u8>, pure_downlink: bool) {
    let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind");
    let port = listener.local_addr().expect("addr").port();

    let target = SocksAddr::Domain("example.com".to_string(), 443);
    let expected_addr = kip::encode_address(&target).expect("encode addr");

    let server = tokio::spawn(run_fake_server(
        listener,
        method,
        expected_addr,
        !pure_downlink,
    ));

    let cfg = config_with(port, method, pure_downlink);
    let mut stream = connect_for_test(&cfg, &target)
        .await
        .expect("client connect");

    stream.write_all(&payload).await.expect("client write");
    stream.flush().await.expect("client flush");

    let mut got = vec![0u8; payload.len()];
    stream.read_exact(&mut got).await.expect("client read echo");
    assert_eq!(got, payload);

    drop(stream);
    let _ = server.await;
}

#[tokio::test]
async fn chacha_full_stack_round_trip_small() {
    round_trip(
        AeadMethod::ChaCha20Poly1305,
        b"hello sudoku interop".to_vec(),
    )
    .await;
}

#[tokio::test]
async fn chacha_full_stack_round_trip_near_mtu() {
    round_trip(
        AeadMethod::ChaCha20Poly1305,
        (0..1400u32).map(|i| (i * 7) as u8).collect(),
    )
    .await;
}

#[tokio::test]
async fn aes_gcm_full_stack_round_trip() {
    round_trip(
        AeadMethod::Aes128Gcm,
        (0..3000u32).map(|i| i as u8).collect(),
    )
    .await;
}

/// Full-stack TCP relay with `enable-pure-downlink: false`: the fake server
/// encodes the downlink with the 6-bit packed codec and the client decodes it,
/// while the uplink stays pure. Exercises small and near-MTU payloads.
#[tokio::test]
async fn packed_downlink_full_stack_round_trip() {
    round_trip_mode(
        AeadMethod::ChaCha20Poly1305,
        b"packed downlink over the full sudoku stack".to_vec(),
        false,
    )
    .await;
    round_trip_mode(
        AeadMethod::Aes128Gcm,
        (0..1400u32).map(|i| (i * 7) as u8).collect(),
        false,
    )
    .await;
}

// --- native mux (multiplex: on) ---

const MUX_FRAME_OPEN: u8 = 0x01;
const MUX_FRAME_DATA: u8 = 0x02;
const MUX_FRAME_CLOSE: u8 = 0x03;
const MUX_HEADER_LEN: usize = 1 + 4 + 4;

fn mux_frame(frame_type: u8, stream_id: u32, payload: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(MUX_HEADER_LEN + payload.len());
    out.push(frame_type);
    out.extend_from_slice(&stream_id.to_be_bytes());
    out.extend_from_slice(&(payload.len() as u32).to_be_bytes());
    out.extend_from_slice(payload);
    out
}

/// Accept one connection, run the handshake, read the `StartMux` preface, then
/// run a minimal mux server that echoes each stream's `Data` back on the same
/// stream id and mirrors its `Close`. A single accepted connection proves the
/// client multiplexes every stream over one shared tunnel.
async fn run_fake_mux_server(listener: TcpListener, method: AeadMethod) {
    let (sock, _) = listener.accept().await.expect("accept");
    let mut rec = server_handshake(sock, method, false).await;

    let (typ, payload) = read_message(&mut rec).await.expect("read StartMux");
    assert_eq!(typ, KIP_TYPE_START_MUX);
    assert!(payload.is_empty(), "StartMux carries no payload");

    let mut raw: Vec<u8> = Vec::new();
    let mut buf = vec![0u8; 16 * 1024];
    loop {
        // Drain all complete frames currently buffered.
        while raw.len() >= MUX_HEADER_LEN {
            let len = u32::from_be_bytes([raw[5], raw[6], raw[7], raw[8]]) as usize;
            let need = MUX_HEADER_LEN + len;
            if raw.len() < need {
                break;
            }
            let frame_type = raw[0];
            let sid = u32::from_be_bytes([raw[1], raw[2], raw[3], raw[4]]);
            let data = raw[MUX_HEADER_LEN..need].to_vec();
            raw.drain(..need);
            match frame_type {
                // Open registers the stream; nothing is sent back until data.
                MUX_FRAME_OPEN => {}
                MUX_FRAME_DATA => {
                    if !data.is_empty()
                        && (rec
                            .write_all(&mux_frame(MUX_FRAME_DATA, sid, &data))
                            .await
                            .is_err()
                            || rec.flush().await.is_err())
                    {
                        return;
                    }
                }
                MUX_FRAME_CLOSE => {
                    let _ =
                        rec.write_all(&mux_frame(MUX_FRAME_CLOSE, sid, &[])).await;
                    let _ = rec.flush().await;
                }
                _ => {}
            }
        }
        match rec.read(&mut buf).await {
            Ok(0) | Err(_) => break,
            Ok(n) => raw.extend_from_slice(&buf[..n]),
        }
    }
}

/// With `multiplex: on` two concurrent connections to the same server must ride
/// one shared tunnel (the fake server accepts a single connection) and each
/// logical stream must relay independently.
#[tokio::test]
async fn mux_full_stack_multiplexes_streams() {
    let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind");
    let port = listener.local_addr().expect("addr").port();

    let method = AeadMethod::ChaCha20Poly1305;
    let server = tokio::spawn(run_fake_mux_server(listener, method));

    let cfg = config_mux(port, method);
    let t1 = SocksAddr::Domain("one.example".to_string(), 443);
    let t2 = SocksAddr::Domain("two.example".to_string(), 80);

    let mut s1 = connect_for_test(&cfg, &t1).await.expect("mux connect 1");
    let mut s2 = connect_for_test(&cfg, &t2).await.expect("mux connect 2");

    // Interleave writes across both streams and read each echo back.
    s1.write_all(b"stream one payload").await.expect("write s1");
    s1.flush().await.expect("flush s1");
    s2.write_all(b"stream two").await.expect("write s2");
    s2.flush().await.expect("flush s2");

    let mut g1 = vec![0u8; b"stream one payload".len()];
    s1.read_exact(&mut g1).await.expect("read s1");
    assert_eq!(&g1, b"stream one payload");

    let mut g2 = vec![0u8; b"stream two".len()];
    s2.read_exact(&mut g2).await.expect("read s2");
    assert_eq!(&g2, b"stream two");

    // A larger payload on a reused stream exercises multi-record framing.
    let big: Vec<u8> = (0..4096u32).map(|i| (i * 5) as u8).collect();
    s1.write_all(&big).await.expect("write s1 big");
    s1.flush().await.expect("flush s1 big");
    let mut got_big = vec![0u8; big.len()];
    s1.read_exact(&mut got_big).await.expect("read s1 big");
    assert_eq!(got_big, big);

    // The mux session lingers in the reuse registry after both streams drop, so
    // the tunnel stays open; abort the server rather than awaiting an EOF.
    drop(s1);
    drop(s2);
    server.abort();
}

/// Drive one or more UDP-over-TCP datagrams through the full stack against the
/// UoT fake server and assert each reply payload matches what was sent.
async fn uot_round_trip(
    method: AeadMethod,
    target: SocksAddr,
    datagrams: Vec<Vec<u8>>,
) {
    let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind");
    let port = listener.local_addr().expect("addr").port();

    let expected_addr = kip::encode_address(&target).expect("encode addr");
    let server = tokio::spawn(run_fake_uot_server(listener, method, expected_addr));

    let cfg = config(port, method);
    let raw = TcpStream::connect((cfg.server.as_str(), cfg.port))
        .await
        .expect("uot dial");
    let stream = super::uot::start(&cfg, Box::new(raw))
        .await
        .expect("uot connect");
    let (mut reader, mut writer) = tokio::io::split(stream);

    for datagram in &datagrams {
        super::uot::write_packet(&mut writer, &target, datagram)
            .await
            .expect("uot send");
        let (source, got) = super::uot::read_packet(&mut reader)
            .await
            .expect("uot recv");
        assert_eq!(source, target, "UoT source address mismatch");
        assert_eq!(&got, datagram, "UoT echo payload mismatch");
    }

    drop(reader);
    drop(writer);
    let _ = server.await;
}

#[tokio::test]
async fn chacha_uot_round_trip_ipv4() {
    let target = SocksAddr::Ip("8.8.8.8:53".parse().unwrap());
    uot_round_trip(
        AeadMethod::ChaCha20Poly1305,
        target,
        vec![b"dns query datagram".to_vec()],
    )
    .await;
}

#[tokio::test]
async fn aes_gcm_uot_round_trip_domain_multi() {
    // Several datagrams on one association exercise frame boundaries, plus a
    // near-MTU payload to cover a multi-record body.
    let target = SocksAddr::Domain("example.com".to_string(), 5353);
    let datagrams = vec![
        b"first".to_vec(),
        Vec::new(),
        (0..1400u32).map(|i| (i * 3) as u8).collect(),
        b"last".to_vec(),
    ];
    uot_round_trip(AeadMethod::Aes128Gcm, target, datagrams).await;
}
