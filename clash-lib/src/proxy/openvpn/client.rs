use std::{fmt, io, sync::Arc, time::Duration};

use rustls::{
    RootCertStore,
    client::{
        WebPkiServerVerifier, danger::ServerCertVerifier,
        verify_server_cert_signed_by_trust_anchor,
    },
    crypto::WebPkiSupportedAlgorithms,
    pki_types::{CertificateDer, ServerName, UnixTime},
    server::ParsedCertificate,
};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt, DuplexStream},
    sync::Mutex,
    time::Instant,
};
use tokio_rustls::client::TlsStream;

use crate::common::tls::build_tls_client_config;

use super::{
    config::{ClientConfig, Proto},
    control::{ControlChannel, PacketIo, PacketMux},
    data::DataChannel,
    key_method::{KeyMethod2Record, derive_client_key_material},
    packet::{Opcode, SessionId},
    push::PushReply,
    tls_crypt::TlsCrypt,
};

const HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(30);
const RETRANSMIT_DELAY: Duration = Duration::from_secs(1);
const PING_PACKET: [u8; 16] = [
    0x2a, 0x18, 0x7b, 0xf3, 0x64, 0x1e, 0xb4, 0xcb, 0x07, 0xed, 0x2d, 0x0a, 0x98,
    0x1f, 0xc7, 0x48,
];

pub(super) struct Client {
    config: Arc<ClientConfig>,
    mux: Arc<PacketMux>,
    control: Arc<ControlChannel>,
    data: Mutex<Option<DataChannel>>,
    tls: Mutex<Option<TlsStream<DuplexStream>>>,
    write_lock: Mutex<()>,
    last_send: Mutex<Instant>,
    last_receive: Mutex<Instant>,
}

impl Client {
    pub(super) fn new(
        config: Arc<ClientConfig>,
        io: Arc<dyn PacketIo>,
    ) -> io::Result<Arc<Self>> {
        let crypt = config
            .tls_crypt_key
            .as_deref()
            .map(|key| TlsCrypt::new(key, true))
            .transpose()?;
        let mux = PacketMux::new(io);
        let control = ControlChannel::new(mux.clone(), crypt, SessionId::random());
        Ok(Arc::new(Self {
            config,
            mux,
            control,
            data: Mutex::new(None),
            tls: Mutex::new(None),
            write_lock: Mutex::new(()),
            last_send: Mutex::new(Instant::now()),
            last_receive: Mutex::new(Instant::now()),
        }))
    }

    pub(super) async fn handshake(&self) -> io::Result<PushReply> {
        tokio::time::timeout(HANDSHAKE_TIMEOUT, self.handshake_inner())
            .await
            .map_err(|_| {
                io::Error::new(
                    io::ErrorKind::TimedOut,
                    "openvpn handshake timed out",
                )
            })?
    }

    async fn handshake_inner(&self) -> io::Result<PushReply> {
        self.control.send_reset().await?;
        loop {
            let packet = if self.config.proto == Proto::Udp {
                match tokio::time::timeout(RETRANSMIT_DELAY, self.control.read())
                    .await
                {
                    Ok(result) => result?,
                    Err(_) => {
                        self.control.retransmit_pending().await?;
                        continue;
                    }
                }
            } else {
                self.control.read().await?
            };
            match packet.opcode {
                Opcode::ControlHardResetServerV2 => {
                    self.control.send_ack().await?;
                    break;
                }
                Opcode::ControlHardResetServerV1 => {
                    return Err(invalid(
                        "openvpn server selected unsupported key method 1",
                    ));
                }
                _ => {}
            }
        }

        let tls_config = self.tls_config()?;
        let server_name = ServerName::try_from(self.config.remote_host.clone())
            .map_err(|error| {
                invalid(format!("invalid openvpn TLS server name: {error}"))
            })?;
        let transport = self
            .control
            .open_tls_transport(self.config.proto == Proto::Udp);
        let mut tls = tokio_rustls::TlsConnector::from(tls_config)
            .connect(server_name, transport)
            .await
            .map_err(|error| invalid(format!("openvpn TLS handshake: {error}")))?;

        let client_record = KeyMethod2Record::new_client(
            self.config.proto,
            self.config.cipher,
            self.config.auth,
            self.config.comp_lzo,
            self.config.username.as_deref().unwrap_or_default().trim(),
            self.config.password.as_deref().unwrap_or_default(),
        );
        tls.write_all(&client_record.marshal_client()).await?;
        tls.flush().await?;
        let server_record = read_server_key_method(&mut tls).await?;
        let mut sources = client_record.sources.clone();
        sources.server = server_record.sources.server;
        let keys = derive_client_key_material(
            &sources,
            self.control.local_session(),
            self.control.remote_session().await,
            self.config.cipher.key_len(),
        )?;

        tls.write_all(b"PUSH_REQUEST\0").await?;
        tls.flush().await?;
        let push = read_push_reply(&mut tls).await?;
        *self.data.lock().await = Some(DataChannel::new(
            keys,
            self.config.cipher,
            self.config.auth,
            push.peer_id,
        )?);
        *self.last_send.lock().await = Instant::now();
        *self.last_receive.lock().await = Instant::now();
        *self.tls.lock().await = Some(tls);
        Ok(push)
    }

    pub(super) async fn write_ip_packet(&self, packet: &[u8]) -> io::Result<()> {
        self.write_data_packet(packet, true).await
    }

    pub(super) async fn write_ping(&self) -> io::Result<()> {
        self.write_data_packet(&PING_PACKET, false).await
    }

    async fn write_data_packet(
        &self,
        packet: &[u8],
        compress: bool,
    ) -> io::Result<()> {
        let _write = self.write_lock.lock().await;
        let framed;
        let packet = if compress && self.config.comp_lzo {
            framed = encode_lzo_uncompressed(packet);
            framed.as_slice()
        } else {
            packet
        };
        let encrypted = self
            .data
            .lock()
            .await
            .as_mut()
            .ok_or_else(|| invalid("openvpn data channel is not ready"))?
            .encrypt(packet)?;
        self.mux.write(&encrypted).await?;
        *self.last_send.lock().await = Instant::now();
        Ok(())
    }

    pub(super) async fn read_ip_packet(&self) -> io::Result<Vec<u8>> {
        loop {
            let encrypted = self.mux.read_data().await?;
            let plain = match self
                .data
                .lock()
                .await
                .as_mut()
                .ok_or_else(|| invalid("openvpn data channel is not ready"))?
                .decrypt(&encrypted)
            {
                Ok(plain) => plain,
                Err(_) => continue,
            };
            *self.last_receive.lock().await = Instant::now();
            if plain == PING_PACKET {
                continue;
            }
            return if self.config.comp_lzo {
                decode_lzo(&plain)
            } else {
                Ok(plain)
            };
        }
    }

    pub(super) async fn since_send(&self) -> Duration {
        self.last_send.lock().await.elapsed()
    }

    pub(super) async fn since_receive(&self) -> Duration {
        self.last_receive.lock().await.elapsed()
    }

    pub(super) async fn close(&self) -> io::Result<()> {
        self.tls.lock().await.take();
        self.mux.close().await
    }

    fn tls_config(&self) -> io::Result<Arc<rustls::ClientConfig>> {
        let mut roots = RootCertStore::empty();
        for certificate in rustls_pemfile::certs(&mut self.config.ca.as_bytes()) {
            roots
                .add(certificate.map_err(|error| {
                    invalid(format!("invalid openvpn CA: {error}"))
                })?)
                .map_err(|error| invalid(format!("invalid openvpn CA: {error}")))?;
        }
        let verifier = Arc::new(ChainOnlyVerifier::new(roots)?);
        build_tls_client_config(
            verifier,
            self.config.cert.as_deref(),
            self.config.key.as_deref(),
        )
        .map(Arc::new)
    }
}

async fn read_server_key_method(
    tls: &mut TlsStream<DuplexStream>,
) -> io::Result<KeyMethod2Record> {
    let mut buffer = Vec::new();
    let mut chunk = [0u8; 4096];
    loop {
        let length = tls.read(&mut chunk).await?;
        if length == 0 {
            return Err(io::Error::from(io::ErrorKind::UnexpectedEof));
        }
        buffer.extend_from_slice(&chunk[..length]);
        match KeyMethod2Record::parse_server(&buffer) {
            Ok(record) => return Ok(record),
            Err(error)
                if error.kind() == io::ErrorKind::UnexpectedEof
                    && buffer.len() < 128 * 1024 => {}
            Err(error) => return Err(error),
        }
    }
}

async fn read_push_reply(
    tls: &mut TlsStream<DuplexStream>,
) -> io::Result<PushReply> {
    let mut buffer = Vec::new();
    let mut chunk = [0u8; 4096];
    loop {
        let length = tls.read(&mut chunk).await?;
        if length == 0 {
            return Err(io::Error::from(io::ErrorKind::UnexpectedEof));
        }
        buffer.extend_from_slice(&chunk[..length]);
        if buffer.contains(&0)
            || buffer.windows(10).any(|value| value == b"PUSH_REPLY")
        {
            let end = buffer
                .iter()
                .position(|value| *value == 0)
                .unwrap_or(buffer.len());
            if let Ok(reply) =
                PushReply::parse(&String::from_utf8_lossy(&buffer[..end]))
            {
                return Ok(reply);
            }
        }
        if buffer.len() > 128 * 1024 {
            return Err(invalid("openvpn PUSH_REPLY exceeds 128 KiB"));
        }
    }
}

fn encode_lzo_uncompressed(packet: &[u8]) -> Vec<u8> {
    let mut output = Vec::with_capacity(packet.len() + 1);
    output.push(0xfa);
    output.extend_from_slice(packet);
    output
}

fn decode_lzo(packet: &[u8]) -> io::Result<Vec<u8>> {
    match packet.split_first() {
        Some((0xfa, payload)) => Ok(payload.to_vec()),
        Some((0x66, [])) => Ok(Vec::new()),
        Some((0x66, payload)) => {
            // OpenVPN's tun payload is an IPv4/IPv6 packet, whose maximum
            // encoded length is bounded by the protocol's 16-bit length.
            let mut output = vec![0u8; u16::MAX as usize];
            let length = lzokay::decompress::decompress(payload, &mut output)
                .map_err(|error| invalid(format!("openvpn LZO decode: {error}")))?;
            output.truncate(length);
            Ok(output)
        }
        _ => Err(invalid("invalid openvpn comp-lzo framing")),
    }
}

#[derive(Debug)]
struct ChainOnlyVerifier {
    roots: RootCertStore,
    algorithms: WebPkiSupportedAlgorithms,
    signatures: Arc<WebPkiServerVerifier>,
}

impl ChainOnlyVerifier {
    fn new(roots: RootCertStore) -> io::Result<Self> {
        let algorithms = rustls::crypto::CryptoProvider::get_default()
            .ok_or_else(|| invalid("rustls crypto provider is not installed"))?
            .signature_verification_algorithms;
        let signatures = WebPkiServerVerifier::builder(Arc::new(roots.clone()))
            .build()
            .map_err(|error| {
                invalid(format!("openvpn certificate verifier: {error}"))
            })?;
        Ok(Self {
            roots,
            algorithms,
            signatures,
        })
    }
}

impl ServerCertVerifier for ChainOnlyVerifier {
    fn verify_server_cert(
        &self,
        end_entity: &CertificateDer<'_>,
        intermediates: &[CertificateDer<'_>],
        _server_name: &ServerName<'_>,
        _ocsp_response: &[u8],
        now: UnixTime,
    ) -> Result<rustls::client::danger::ServerCertVerified, rustls::Error> {
        verify_server_cert_signed_by_trust_anchor(
            &ParsedCertificate::try_from(end_entity)?,
            &self.roots,
            intermediates,
            now,
            self.algorithms.all,
        )?;
        Ok(rustls::client::danger::ServerCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        signature: &rustls::DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        self.signatures
            .verify_tls12_signature(message, cert, signature)
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        signature: &rustls::DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        self.signatures
            .verify_tls13_signature(message, cert, signature)
    }

    fn supported_verify_schemes(&self) -> Vec<rustls::SignatureScheme> {
        self.algorithms.supported_schemes()
    }
}

impl fmt::Debug for Client {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("OpenVpnClient")
            .field("server", &self.config.remote_host)
            .finish()
    }
}

fn invalid(message: impl Into<String>) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, message.into())
}

#[cfg(test)]
mod tests {
    use std::{io, sync::Arc, time::Duration};

    use async_trait::async_trait;
    use rustls::pki_types::{CertificateDer, PrivateKeyDer};
    use tokio::{
        io::{AsyncReadExt, AsyncWriteExt},
        sync::{Mutex, mpsc},
    };

    use super::{Client, decode_lzo, encode_lzo_uncompressed};
    use crate::proxy::openvpn::{
        config::{Auth, Cipher, ClientConfig, Proto},
        control::{ControlChannel, PacketIo, PacketMux},
        data::DataChannel,
        key_method::{KeyMaterial, KeyMethod2Record, derive_client_key_material},
        packet::{Opcode, SessionId},
        tls_crypt::TlsCrypt,
    };

    struct MemoryIo {
        receiver: Mutex<mpsc::Receiver<Vec<u8>>>,
        sender: mpsc::Sender<Vec<u8>>,
    }

    #[async_trait]
    impl PacketIo for MemoryIo {
        async fn read_packet(&self) -> io::Result<Vec<u8>> {
            self.receiver
                .lock()
                .await
                .recv()
                .await
                .ok_or_else(|| io::Error::from(io::ErrorKind::BrokenPipe))
        }

        async fn write_packet(&self, packet: &[u8]) -> io::Result<()> {
            self.sender
                .send(packet.to_vec())
                .await
                .map_err(|_| io::Error::from(io::ErrorKind::BrokenPipe))
        }
    }

    fn memory_pair() -> (Arc<MemoryIo>, Arc<MemoryIo>) {
        let (client_tx, server_rx) = mpsc::channel(256);
        let (server_tx, client_rx) = mpsc::channel(256);
        (
            Arc::new(MemoryIo {
                receiver: Mutex::new(client_rx),
                sender: client_tx,
            }),
            Arc::new(MemoryIo {
                receiver: Mutex::new(server_rx),
                sender: server_tx,
            }),
        )
    }

    async fn read_client_key_method<T>(tls: &mut T) -> KeyMethod2Record
    where
        T: tokio::io::AsyncRead + Unpin,
    {
        let mut buffer = Vec::new();
        let mut chunk = [0u8; 4096];
        loop {
            let length = tls.read(&mut chunk).await.unwrap();
            assert_ne!(length, 0);
            buffer.extend_from_slice(&chunk[..length]);
            match KeyMethod2Record::parse_client(&buffer) {
                Ok(record) => return record,
                Err(error) if error.kind() == io::ErrorKind::UnexpectedEof => {}
                Err(error) => panic!("invalid client key method record: {error}"),
            }
        }
    }

    #[test]
    fn lzo_uncompressed_frame_round_trip() {
        let frame = encode_lzo_uncompressed(b"IP packet");
        assert_eq!(decode_lzo(&frame).unwrap(), b"IP packet");
    }

    #[test]
    fn lzo_compressed_frame_decodes_and_rejects_malformed_data() {
        // A 512-byte zero block produced by lzo1x_1. This is the raw LZO1X
        // block carried after OpenVPN's 0x66 comp-lzo marker.
        let mut frame = vec![0x66, 0x12, 0, 0x20, 0, 0xdf, 0, 0, 0x11, 0, 0];
        assert_eq!(decode_lzo(&frame).unwrap(), vec![0; 512]);
        frame.truncate(4);
        assert!(decode_lzo(&frame).is_err());
    }

    #[tokio::test]
    async fn full_tls_crypt_handshake_and_bidirectional_data_channel() {
        crate::setup_default_crypto_provider();
        let rcgen::CertifiedKey { cert, signing_key } =
            rcgen::generate_simple_self_signed(vec!["vpn.example.com".to_owned()])
                .unwrap();
        let tls_crypt_key: Vec<u8> = (0..=255).collect();
        let config = Arc::new(ClientConfig {
            remote_host: "vpn.example.com".to_owned(),
            remote_port: 1194,
            proto: Proto::Udp,
            cipher: Cipher::Aes256Gcm,
            auth: Auth::Sha256,
            comp_lzo: true,
            ca: cert.pem(),
            cert: None,
            key: None,
            tls_crypt_key: Some(tls_crypt_key.clone()),
            username: Some("user".to_owned()),
            password: Some("password".to_owned()),
            ping_interval: Duration::ZERO,
            ping_restart: Duration::ZERO,
        });
        let (client_io, server_io) = memory_pair();
        let client = Client::new(config, client_io).unwrap();

        let server_mux = PacketMux::new(server_io);
        let server_control = ControlChannel::new(
            server_mux.clone(),
            Some(TlsCrypt::new(&tls_crypt_key, false).unwrap()),
            SessionId(*b"server01"),
        );
        let server_cert = CertificateDer::from(cert.der().to_vec());
        let server_key =
            PrivateKeyDer::try_from(signing_key.serialize_der()).unwrap();
        let tls_server = Arc::new(
            rustls::ServerConfig::builder()
                .with_no_client_auth()
                .with_single_cert(vec![server_cert], server_key)
                .unwrap(),
        );

        let server = tokio::spawn(async move {
            let reset = server_control.read().await.unwrap();
            assert_eq!(reset.opcode, Opcode::ControlHardResetClientV2);
            server_control
                .send(Opcode::ControlHardResetServerV2, &[])
                .await
                .unwrap();

            let transport = server_control.open_tls_transport(true);
            let mut tls = tokio_rustls::TlsAcceptor::from(tls_server)
                .accept(transport)
                .await
                .unwrap();
            let client_record = read_client_key_method(&mut tls).await;
            assert_eq!(client_record.username, "user");
            assert_eq!(client_record.password, "password");
            assert!(client_record.options.contains("cipher AES-256-GCM"));

            let server_record = KeyMethod2Record::new_server("server-options");
            tls.write_all(&server_record.marshal_server())
                .await
                .unwrap();
            tls.flush().await.unwrap();

            let mut sources = client_record.sources.clone();
            sources.server = server_record.sources.server;
            let client_keys = derive_client_key_material(
                &sources,
                server_control.remote_session().await,
                server_control.local_session(),
                Cipher::Aes256Gcm.key_len(),
            )
            .unwrap();
            let server_keys = KeyMaterial {
                send_cipher_key: client_keys.recv_cipher_key,
                send_hmac_key: client_keys.recv_hmac_key,
                recv_cipher_key: client_keys.send_cipher_key,
                recv_hmac_key: client_keys.send_hmac_key,
            };
            let mut data =
                DataChannel::new(server_keys, Cipher::Aes256Gcm, Auth::Sha256, 7)
                    .unwrap();

            let mut request = [0u8; 13];
            tls.read_exact(&mut request).await.unwrap();
            assert_eq!(&request, b"PUSH_REQUEST\0");
            tls.write_all(b"PUSH_REPLY,ifconfig 10.8.0.2 255.255.255.0,peer-id 7\0")
                .await
                .unwrap();
            tls.flush().await.unwrap();

            let packet = server_mux.read_data().await.unwrap();
            let plain = data.decrypt(&packet).unwrap();
            assert_eq!(decode_lzo(&plain).unwrap(), b"client IP packet");

            let compressed = [0x66, 0x12, 0, 0x20, 0, 0xdf, 0, 0, 0x11, 0, 0];
            server_mux
                .write(&data.encrypt(&compressed).unwrap())
                .await
                .unwrap();
        });

        let push = client.handshake().await.unwrap();
        assert_eq!(push.peer_id, 7);
        client.write_ip_packet(b"client IP packet").await.unwrap();
        assert_eq!(client.read_ip_packet().await.unwrap(), vec![0; 512]);
        server.await.unwrap();
    }
}
