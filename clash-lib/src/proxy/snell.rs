use std::{
    collections::HashMap,
    fmt::Debug,
    io,
    net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr},
    pin::Pin,
    sync::Arc,
    task::{Context, Poll},
};

use aes_gcm::Aes128Gcm;
use argon2::{Algorithm, Argon2, Params, Version};
use async_trait::async_trait;
use chacha20poly1305::ChaCha20Poly1305;
use erased_serde::Serialize as ErasedSerialize;
use futures::{Sink, SinkExt, Stream};
use tokio::io::{
    AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, ReadHalf, WriteHalf,
};
use tokio_util::sync::PollSender;

use crate::{
    Error,
    app::{
        dispatcher::{
            BoxedChainedDatagram, BoxedChainedStream, ChainedDatagram,
            ChainedDatagramWrapper, ChainedStream, ChainedStreamWrapper,
        },
        dns::ThreadSafeDNSResolver,
    },
    common::{crypto::AeadCipherHelper, errors::new_io_error},
    impl_default_connector,
    proxy::{
        AnyStream, ConnectorType, DialWithConnector, HandlerCommonOptions,
        OutboundHandler, OutboundType, PlainProxyAPIResponse,
        datagram::UdpPacket,
        transport::Transport,
        utils::{GLOBAL_DIRECT_CONNECTOR, RemoteConnector},
    },
    session::{Session, SocksAddr},
};

const VERSION_1: u8 = 1;
const VERSION_2: u8 = 2;
const VERSION_3: u8 = 3;
const VERSION_4: u8 = 4;
const VERSION_5: u8 = 5;
const WIRE_VERSION: u8 = 1;
const COMMAND_CONNECT: u8 = 1;
const COMMAND_CONNECT_V2: u8 = 5;
const COMMAND_UDP: u8 = 6;
const COMMAND_TUNNEL: u8 = 0;
const COMMAND_ERROR: u8 = 2;
const MAX_PAYLOAD: usize = 0x3fff;
const SALT_SIZE: usize = 16;
const TAG_SIZE: usize = 16;
const NONCE_SIZE: usize = 12;
const V4_HEADER_SIZE: usize = 7;

pub struct HandlerOptions {
    pub name: String,
    pub common_opts: HandlerCommonOptions,
    pub server: String,
    pub port: u16,
    pub psk: String,
    pub udp: bool,
    pub version: u8,
    pub reuse: bool,
    pub obfs: Option<Box<dyn Transport>>,
}

pub struct Handler {
    opts: HandlerOptions,
    connector: tokio::sync::RwLock<Option<Arc<dyn RemoteConnector>>>,
}

impl Handler {
    pub fn new(mut opts: HandlerOptions) -> Result<Self, Error> {
        if opts.server.is_empty() || opts.port == 0 || opts.psk.is_empty() {
            return Err(Error::InvalidConfig(format!(
                "snell {} requires server, port and psk",
                opts.name
            )));
        }
        if opts.version == 0 {
            opts.version = VERSION_1;
        }
        if opts.version == VERSION_5 {
            // Snell v5 servers are backward-compatible with the v4 wire format.
            opts.version = VERSION_4;
        }
        if !matches!(opts.version, VERSION_1..=VERSION_4) {
            return Err(Error::InvalidConfig(format!(
                "snell {} has unsupported version {}",
                opts.name, opts.version
            )));
        }
        if opts.udp && opts.version < VERSION_3 {
            return Err(Error::InvalidConfig(format!(
                "snell version {} does not support UDP",
                opts.version
            )));
        }
        Ok(Self {
            opts,
            connector: Default::default(),
        })
    }

    async fn open_raw_stream(
        &self,
        connector: &dyn RemoteConnector,
        sess: &Session,
        resolver: ThreadSafeDNSResolver,
    ) -> io::Result<AnyStream> {
        let mut stream = connector
            .connect_stream(
                resolver,
                &self.opts.server,
                self.opts.port,
                sess.iface.as_ref(),
                #[cfg(target_os = "linux")]
                sess.so_mark,
            )
            .await?;
        if let Some(obfs) = self.opts.obfs.as_ref() {
            stream = obfs.proxy_stream(stream).await?;
        }
        Ok(stream)
    }

    async fn open_tcp_tunnel(
        &self,
        connector: &dyn RemoteConnector,
        sess: &Session,
        resolver: ThreadSafeDNSResolver,
    ) -> io::Result<AnyStream> {
        let raw = self.open_raw_stream(connector, sess, resolver).await?;
        let mut stream =
            wrap_encrypted_stream(raw, self.opts.psk.clone(), self.opts.version);
        let host = sess.destination.host();
        if host.len() > u8::MAX as usize {
            return Err(new_io_error("snell target host is too long"));
        }
        let command = if self.opts.version == VERSION_2
            || self.opts.version == VERSION_4 && self.opts.reuse
        {
            COMMAND_CONNECT_V2
        } else {
            COMMAND_CONNECT
        };
        let mut request = Vec::with_capacity(6 + host.len());
        request.extend_from_slice(&[WIRE_VERSION, command, 0, host.len() as u8]);
        request.extend_from_slice(host.as_bytes());
        request.extend_from_slice(&sess.destination.port().to_be_bytes());
        stream.write_all(&request).await?;
        stream.flush().await?;
        read_reply(&mut stream).await?;
        Ok(stream)
    }

    async fn open_udp_tunnel(
        &self,
        connector: &dyn RemoteConnector,
        sess: &Session,
        resolver: ThreadSafeDNSResolver,
    ) -> io::Result<SnellDatagram> {
        let raw = self.open_raw_stream(connector, sess, resolver).await?;
        let (reader, writer) = tokio::io::split(raw);
        let mut encoder =
            Encoder::new(writer, self.opts.psk.clone(), self.opts.version);
        let mut decoder =
            Decoder::new(reader, self.opts.psk.clone(), self.opts.version);
        encoder.write_frame(&[WIRE_VERSION, COMMAND_UDP, 0]).await?;
        let reply = decoder
            .read_frame()
            .await?
            .ok_or_else(|| new_io_error("snell UDP tunnel closed before reply"))?;
        parse_reply(&reply)?;
        Ok(SnellDatagram::new(encoder, decoder, sess))
    }
}

impl_default_connector!(Handler);

impl Debug for Handler {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("Snell")
            .field("name", &self.opts.name)
            .field("version", &self.opts.version)
            .finish()
    }
}

#[async_trait]
impl OutboundHandler for Handler {
    fn name(&self) -> &str {
        &self.opts.name
    }

    fn server_name(&self) -> Option<&str> {
        Some(&self.opts.server)
    }

    fn proto(&self) -> OutboundType {
        OutboundType::Snell
    }

    async fn support_udp(&self) -> bool {
        self.opts.udp
    }

    async fn connect_stream(
        &self,
        sess: &Session,
        resolver: ThreadSafeDNSResolver,
    ) -> io::Result<BoxedChainedStream> {
        let connector = self.connector.read().await;
        self.connect_stream_with_connector(
            sess,
            resolver,
            connector
                .as_ref()
                .unwrap_or(&GLOBAL_DIRECT_CONNECTOR.clone())
                .as_ref(),
        )
        .await
    }

    async fn connect_datagram(
        &self,
        sess: &Session,
        resolver: ThreadSafeDNSResolver,
    ) -> io::Result<BoxedChainedDatagram> {
        let connector = self.connector.read().await;
        self.connect_datagram_with_connector(
            sess,
            resolver,
            connector
                .as_ref()
                .unwrap_or(&GLOBAL_DIRECT_CONNECTOR.clone())
                .as_ref(),
        )
        .await
    }

    async fn support_connector(&self) -> ConnectorType {
        ConnectorType::All
    }

    async fn connect_stream_with_connector(
        &self,
        sess: &Session,
        resolver: ThreadSafeDNSResolver,
        connector: &dyn RemoteConnector,
    ) -> io::Result<BoxedChainedStream> {
        let stream = self.open_tcp_tunnel(connector, sess, resolver).await?;
        let stream = ChainedStreamWrapper::new(stream);
        stream.append_to_chain(self.name()).await;
        Ok(Box::new(stream))
    }

    async fn connect_datagram_with_connector(
        &self,
        sess: &Session,
        resolver: ThreadSafeDNSResolver,
        connector: &dyn RemoteConnector,
    ) -> io::Result<BoxedChainedDatagram> {
        if !self.opts.udp {
            return Err(new_io_error("snell UDP is disabled"));
        }
        let datagram = self.open_udp_tunnel(connector, sess, resolver).await?;
        let datagram = ChainedDatagramWrapper::new(datagram);
        datagram.append_to_chain(self.name()).await;
        Ok(Box::new(datagram))
    }

    fn try_as_plain_handler(&self) -> Option<&dyn PlainProxyAPIResponse> {
        Some(self)
    }
}

#[async_trait]
impl PlainProxyAPIResponse for Handler {
    async fn as_map(&self) -> HashMap<String, Box<dyn ErasedSerialize + Send>> {
        HashMap::from([
            ("server".to_owned(), Box::new(self.opts.server.clone()) as _),
            ("port".to_owned(), Box::new(self.opts.port) as _),
            ("udp".to_owned(), Box::new(self.opts.udp) as _),
            ("version".to_owned(), Box::new(self.opts.version) as _),
        ])
    }
}

fn wrap_encrypted_stream(raw: AnyStream, psk: String, version: u8) -> AnyStream {
    let (raw_reader, raw_writer) = tokio::io::split(raw);
    let (client, relay) = tokio::io::duplex(128 * 1024);
    let (mut plain_reader, mut plain_writer) = tokio::io::split(relay);
    let write_psk = psk.clone();

    tokio::spawn(async move {
        let mut encoder = Encoder::new(raw_writer, write_psk, version);
        let mut buffer = vec![0u8; MAX_PAYLOAD];
        loop {
            match plain_reader.read(&mut buffer).await {
                Ok(0) => {
                    let _ = encoder.finish().await;
                    break;
                }
                Ok(size) => {
                    if encoder.write_frame(&buffer[..size]).await.is_err() {
                        break;
                    }
                }
                Err(_) => break,
            }
        }
    });
    tokio::spawn(async move {
        let mut decoder = Decoder::new(raw_reader, psk, version);
        loop {
            match decoder.read_frame().await {
                Ok(Some(data)) => {
                    if plain_writer.write_all(&data).await.is_err() {
                        break;
                    }
                }
                Ok(None) | Err(_) => break,
            }
        }
        let _ = plain_writer.shutdown().await;
    });
    Box::new(client)
}

enum Cipher {
    Aes(Aes128Gcm),
    ChaCha(ChaCha20Poly1305),
}

struct CipherState {
    cipher: Cipher,
    nonce: [u8; NONCE_SIZE],
}

impl CipherState {
    fn new(psk: &str, salt: &[u8], version: u8) -> io::Result<Self> {
        let key = derive_key(psk, salt)?;
        let cipher = if version == VERSION_1 {
            Cipher::ChaCha(ChaCha20Poly1305::new_with_slice(&key))
        } else {
            Cipher::Aes(Aes128Gcm::new_with_slice(&key[..16]))
        };
        Ok(Self {
            cipher,
            nonce: [0; NONCE_SIZE],
        })
    }

    fn seal(&mut self, plaintext: &[u8]) -> Vec<u8> {
        let mut output = vec![0u8; plaintext.len() + TAG_SIZE];
        output[..plaintext.len()].copy_from_slice(plaintext);
        match &self.cipher {
            Cipher::Aes(cipher) => {
                cipher.encrypt_in_place_with_slice(&self.nonce, &[], &mut output)
            }
            Cipher::ChaCha(cipher) => {
                cipher.encrypt_in_place_with_slice(&self.nonce, &[], &mut output)
            }
        }
        increment_nonce(&mut self.nonce);
        output
    }

    fn open(&mut self, ciphertext: &mut Vec<u8>) -> io::Result<()> {
        if ciphertext.len() < TAG_SIZE {
            return Err(new_io_error("snell ciphertext is too short"));
        }
        let result = match &self.cipher {
            Cipher::Aes(cipher) => {
                cipher.decrypt_in_place_with_slice(&self.nonce, &[], ciphertext)
            }
            Cipher::ChaCha(cipher) => {
                cipher.decrypt_in_place_with_slice(&self.nonce, &[], ciphertext)
            }
        };
        increment_nonce(&mut self.nonce);
        result.map_err(|_| new_io_error("snell authentication failed"))?;
        ciphertext.truncate(ciphertext.len() - TAG_SIZE);
        Ok(())
    }
}

fn derive_key(psk: &str, salt: &[u8]) -> io::Result<[u8; 32]> {
    let params = Params::new(8, 3, 1, Some(32))
        .map_err(|error| new_io_error(format!("snell Argon2 params: {error}")))?;
    let argon = Argon2::new(Algorithm::Argon2id, Version::V0x13, params);
    let mut key = [0u8; 32];
    argon
        .hash_password_into(psk.as_bytes(), salt, &mut key)
        .map_err(|error| new_io_error(format!("snell Argon2: {error}")))?;
    Ok(key)
}

fn increment_nonce(nonce: &mut [u8; NONCE_SIZE]) {
    for byte in nonce {
        *byte = byte.wrapping_add(1);
        if *byte != 0 {
            break;
        }
    }
}

struct Encoder<W> {
    writer: W,
    psk: String,
    version: u8,
    cipher: Option<CipherState>,
    first_frame: bool,
}

impl<W: AsyncWrite + Unpin> Encoder<W> {
    fn new(writer: W, psk: String, version: u8) -> Self {
        Self {
            writer,
            psk,
            version,
            cipher: None,
            first_frame: true,
        }
    }

    async fn init(&mut self) -> io::Result<()> {
        if self.cipher.is_none() {
            let mut salt = [0u8; SALT_SIZE];
            rand::fill(&mut salt);
            self.writer.write_all(&salt).await?;
            self.cipher = Some(CipherState::new(&self.psk, &salt, self.version)?);
        }
        Ok(())
    }

    async fn write_frame(&mut self, payload: &[u8]) -> io::Result<()> {
        if payload.len() > MAX_PAYLOAD {
            return Err(new_io_error("snell frame is too large"));
        }
        self.init().await?;
        let cipher = self.cipher.as_mut().expect("initialized above");
        if self.version >= VERSION_4 {
            let padding_len = if self.first_frame && !payload.is_empty() {
                rand::random_range(0x100..0x200)
            } else {
                0
            };
            let header = [
                VERSION_4,
                0,
                0,
                (padding_len >> 8) as u8,
                padding_len as u8,
                (payload.len() >> 8) as u8,
                payload.len() as u8,
            ];
            self.writer.write_all(&cipher.seal(&header)).await?;
            if !payload.is_empty() {
                let mut encrypted = cipher.seal(payload);
                let mut padding = vec![0u8; padding_len];
                rand::fill(&mut padding[..]);
                swap_padding(&mut padding, &mut encrypted);
                self.writer.write_all(&padding).await?;
                self.writer.write_all(&encrypted).await?;
            }
        } else {
            self.writer
                .write_all(&cipher.seal(&(payload.len() as u16).to_be_bytes()))
                .await?;
            if !payload.is_empty() {
                self.writer.write_all(&cipher.seal(payload)).await?;
            }
        }
        self.first_frame = false;
        self.writer.flush().await
    }

    async fn finish(&mut self) -> io::Result<()> {
        self.write_frame(&[]).await?;
        self.writer.shutdown().await
    }
}

struct Decoder<R> {
    reader: R,
    psk: String,
    version: u8,
    cipher: Option<CipherState>,
}

impl<R: AsyncRead + Unpin> Decoder<R> {
    fn new(reader: R, psk: String, version: u8) -> Self {
        Self {
            reader,
            psk,
            version,
            cipher: None,
        }
    }

    async fn init(&mut self) -> io::Result<()> {
        if self.cipher.is_none() {
            let mut salt = [0u8; SALT_SIZE];
            self.reader.read_exact(&mut salt).await?;
            self.cipher = Some(CipherState::new(&self.psk, &salt, self.version)?);
        }
        Ok(())
    }

    async fn read_frame(&mut self) -> io::Result<Option<Vec<u8>>> {
        self.init().await?;
        let cipher = self.cipher.as_mut().expect("initialized above");
        if self.version >= VERSION_4 {
            let mut encrypted_header = vec![0u8; V4_HEADER_SIZE + TAG_SIZE];
            self.reader.read_exact(&mut encrypted_header).await?;
            cipher.open(&mut encrypted_header)?;
            if encrypted_header.len() != V4_HEADER_SIZE
                || encrypted_header[0] != VERSION_4
            {
                return Err(new_io_error("snell v4 frame header is invalid"));
            }
            let padding_len =
                u16::from_be_bytes([encrypted_header[3], encrypted_header[4]])
                    as usize;
            let payload_len =
                u16::from_be_bytes([encrypted_header[5], encrypted_header[6]])
                    as usize;
            if payload_len == 0 {
                if padding_len != 0 {
                    return Err(new_io_error("snell v4 zero frame has padding"));
                }
                return Ok(None);
            }
            if payload_len > MAX_PAYLOAD || padding_len > MAX_PAYLOAD {
                return Err(new_io_error("snell v4 frame is too large"));
            }
            let mut frame = vec![0u8; padding_len + payload_len + TAG_SIZE];
            self.reader.read_exact(&mut frame).await?;
            let (padding, encrypted) = frame.split_at_mut(padding_len);
            swap_padding(padding, encrypted);
            let mut encrypted = encrypted.to_vec();
            cipher.open(&mut encrypted)?;
            Ok(Some(encrypted))
        } else {
            let mut encrypted_len = vec![0u8; 2 + TAG_SIZE];
            self.reader.read_exact(&mut encrypted_len).await?;
            cipher.open(&mut encrypted_len)?;
            let payload_len =
                u16::from_be_bytes([encrypted_len[0], encrypted_len[1]]) as usize;
            if payload_len == 0 {
                return Ok(None);
            }
            if payload_len > MAX_PAYLOAD {
                return Err(new_io_error("snell frame is too large"));
            }
            let mut encrypted = vec![0u8; payload_len + TAG_SIZE];
            self.reader.read_exact(&mut encrypted).await?;
            cipher.open(&mut encrypted)?;
            Ok(Some(encrypted))
        }
    }
}

fn swap_padding(padding: &mut [u8], encrypted: &mut [u8]) {
    let limit = padding.len().min(encrypted.len());
    for index in (0..limit).step_by(2) {
        std::mem::swap(&mut padding[index], &mut encrypted[index]);
    }
}

async fn read_reply(stream: &mut AnyStream) -> io::Result<()> {
    let command = stream.read_u8().await?;
    if command == COMMAND_TUNNEL {
        return Ok(());
    }
    if command != COMMAND_ERROR {
        return Err(new_io_error(format!(
            "snell server returned unsupported command {command}"
        )));
    }
    let code = stream.read_u8().await?;
    let length = stream.read_u8().await? as usize;
    let mut message = vec![0u8; length];
    stream.read_exact(&mut message).await?;
    Err(new_io_error(format!(
        "snell server error {code}: {}",
        String::from_utf8_lossy(&message)
    )))
}

fn parse_reply(reply: &[u8]) -> io::Result<()> {
    match reply.first().copied() {
        Some(COMMAND_TUNNEL) => Ok(()),
        Some(COMMAND_ERROR) if reply.len() >= 3 => {
            let length = reply[2] as usize;
            let message = reply.get(3..3 + length).unwrap_or_default();
            Err(new_io_error(format!(
                "snell server error {}: {}",
                reply[1],
                String::from_utf8_lossy(message)
            )))
        }
        Some(command) => Err(new_io_error(format!(
            "snell server returned unsupported command {command}"
        ))),
        None => Err(new_io_error("snell server returned an empty reply")),
    }
}

type SnellEncoder = Encoder<WriteHalf<AnyStream>>;
type SnellDecoder = Decoder<ReadHalf<AnyStream>>;

struct SnellDatagram {
    send_tx: PollSender<UdpPacket>,
    recv_rx: tokio::sync::mpsc::Receiver<UdpPacket>,
    workers: Vec<tokio::task::JoinHandle<()>>,
}

impl SnellDatagram {
    fn new(
        mut encoder: SnellEncoder,
        mut decoder: SnellDecoder,
        sess: &Session,
    ) -> Self {
        let (send_tx, mut send_rx) = tokio::sync::mpsc::channel::<UdpPacket>(32);
        let (recv_tx, recv_rx) = tokio::sync::mpsc::channel::<UdpPacket>(32);
        let local_source = SocksAddr::from(sess.source);
        let inbound_user = sess.inbound_user.clone();

        let write_worker = tokio::spawn(async move {
            while let Some(packet) = send_rx.recv().await {
                let request =
                    match encode_udp_request(&packet.dst_addr, &packet.data) {
                        Ok(request) => request,
                        Err(error) => {
                            tracing::debug!("snell UDP encode failed: {error}");
                            continue;
                        }
                    };
                if encoder.write_frame(&request).await.is_err() {
                    break;
                }
            }
            let _ = encoder.finish().await;
        });
        let read_worker = tokio::spawn(async move {
            loop {
                let frame = match decoder.read_frame().await {
                    Ok(Some(frame)) => frame,
                    Ok(None) | Err(_) => break,
                };
                let (source, data) = match decode_udp_response(&frame) {
                    Ok(response) => response,
                    Err(error) => {
                        tracing::debug!("snell UDP decode failed: {error}");
                        continue;
                    }
                };
                if recv_tx
                    .send(UdpPacket {
                        data,
                        src_addr: source,
                        dst_addr: local_source.clone(),
                        inbound_user: inbound_user.clone(),
                    })
                    .await
                    .is_err()
                {
                    break;
                }
            }
        });
        Self {
            send_tx: PollSender::new(send_tx),
            recv_rx,
            workers: vec![write_worker, read_worker],
        }
    }
}

impl Drop for SnellDatagram {
    fn drop(&mut self) {
        for worker in &self.workers {
            worker.abort();
        }
    }
}

impl Sink<UdpPacket> for SnellDatagram {
    type Error = io::Error;

    fn poll_ready(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<Result<(), Self::Error>> {
        self.send_tx
            .poll_ready_unpin(cx)
            .map_err(|_| new_io_error("snell UDP send channel closed"))
    }

    fn start_send(
        mut self: Pin<&mut Self>,
        item: UdpPacket,
    ) -> Result<(), Self::Error> {
        self.send_tx
            .start_send_unpin(item)
            .map_err(|_| new_io_error("snell UDP send channel closed"))
    }

    fn poll_flush(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<Result<(), Self::Error>> {
        self.send_tx
            .poll_flush_unpin(cx)
            .map_err(|_| new_io_error("snell UDP send channel flush failed"))
    }

    fn poll_close(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<Result<(), Self::Error>> {
        self.send_tx
            .poll_close_unpin(cx)
            .map_err(|_| new_io_error("snell UDP send channel close failed"))
    }
}

impl Stream for SnellDatagram {
    type Item = UdpPacket;

    fn poll_next(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<Option<Self::Item>> {
        self.recv_rx.poll_recv(cx)
    }
}

fn encode_udp_request(target: &SocksAddr, payload: &[u8]) -> io::Result<Vec<u8>> {
    let mut request = Vec::with_capacity(21 + payload.len());
    request.push(1);
    match target {
        SocksAddr::Domain(host, port) => {
            if host.len() > u8::MAX as usize {
                return Err(new_io_error("snell UDP target host is too long"));
            }
            request.push(host.len() as u8);
            request.extend_from_slice(host.as_bytes());
            request.extend_from_slice(&port.to_be_bytes());
        }
        SocksAddr::Ip(SocketAddr::V4(address)) => {
            request.extend_from_slice(&[0, 4]);
            request.extend_from_slice(&address.ip().octets());
            request.extend_from_slice(&address.port().to_be_bytes());
        }
        SocksAddr::Ip(SocketAddr::V6(address)) => {
            request.extend_from_slice(&[0, 6]);
            request.extend_from_slice(&address.ip().octets());
            request.extend_from_slice(&address.port().to_be_bytes());
        }
    }
    if request.len() + payload.len() > MAX_PAYLOAD {
        return Err(new_io_error("snell UDP packet is too large"));
    }
    request.extend_from_slice(payload);
    Ok(request)
}

fn decode_udp_response(frame: &[u8]) -> io::Result<(SocksAddr, Vec<u8>)> {
    let (source, offset) = match frame.first().copied() {
        Some(4) if frame.len() >= 7 => {
            let ip = Ipv4Addr::new(frame[1], frame[2], frame[3], frame[4]);
            let port = u16::from_be_bytes([frame[5], frame[6]]);
            (SocketAddr::new(IpAddr::V4(ip), port), 7)
        }
        Some(6) if frame.len() >= 19 => {
            let mut octets = [0u8; 16];
            octets.copy_from_slice(&frame[1..17]);
            let port = u16::from_be_bytes([frame[17], frame[18]]);
            (
                SocketAddr::new(IpAddr::V6(Ipv6Addr::from(octets)), port),
                19,
            )
        }
        _ => return Err(new_io_error("snell UDP response address is invalid")),
    };
    Ok((SocksAddr::from(source), frame[offset..].to_vec()))
}

#[cfg(test)]
mod tests {
    use super::*;

    async fn codec_roundtrip(version: u8) {
        let (left, right) = tokio::io::duplex(128 * 1024);
        let mut encoder = Encoder::new(left, "secret".to_owned(), version);
        let mut decoder = Decoder::new(right, "secret".to_owned(), version);
        encoder.write_frame(b"hello snell").await.unwrap();
        assert_eq!(decoder.read_frame().await.unwrap().unwrap(), b"hello snell");
        encoder.finish().await.unwrap();
        assert!(decoder.read_frame().await.unwrap().is_none());
    }

    #[tokio::test]
    async fn v1_chacha_codec_roundtrip() {
        codec_roundtrip(VERSION_1).await;
    }

    #[tokio::test]
    async fn v3_aes_codec_roundtrip() {
        codec_roundtrip(VERSION_3).await;
    }

    #[tokio::test]
    async fn v4_padded_codec_roundtrip() {
        codec_roundtrip(VERSION_4).await;
    }

    #[test]
    fn udp_address_frames_match_mihomo_format() {
        let request = encode_udp_request(
            &SocksAddr::Domain("example.com".to_owned(), 53),
            b"dns",
        )
        .unwrap();
        assert_eq!(
            request,
            [&[1, 11][..], b"example.com", &[0, 53], b"dns",].concat()
        );
        let (source, payload) =
            decode_udp_response(&[4, 8, 8, 8, 8, 0, 53, 1, 2]).unwrap();
        assert_eq!(source, "8.8.8.8:53".parse::<SocketAddr>().unwrap().into());
        assert_eq!(payload, vec![1, 2]);
    }
}
