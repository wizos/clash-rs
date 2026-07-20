use std::{
    io,
    pin::Pin,
    sync::{Arc, Mutex},
    task::{Context as TaskContext, Poll},
    time::{SystemTime, UNIX_EPOCH},
};

use bytes::{Buf, BufMut, BytesMut};
use digest::Digest;
use futures::ready;
use hmac::{Hmac, Mac, digest::KeyInit};
use rand::Rng;
use sha1::Sha1;
use shadowsocks::{
    context::Context,
    crypto::v1::openssl_bytes_to_key,
    relay::tcprelay::crypto_io::{
        CryptoRead, CryptoStream, CryptoWrite, StreamType,
    },
};
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};

use crate::proxy::AnyStream;

const AUTH_SHA1_V4_SALT: &[u8] = b"auth_sha1_v4";
const MAX_FRAME_LENGTH: usize = 8192;
const MAX_DATA_LENGTH: usize = 8100;

#[derive(Debug)]
pub(crate) enum SsrProtocol {
    AuthSha1V4(AuthSha1V4Context),
    AuthAes128(AuthAes128Context),
    AuthChain(AuthChainContext),
}

#[derive(Clone, Debug)]
pub(crate) enum SsrUdpProtocol {
    PassThrough,
    AuthAes128 {
        digest: AuthAes128Digest,
        protocol_key: Vec<u8>,
        user_id: [u8; 4],
        user_key: Vec<u8>,
    },
    AuthChain {
        protocol_key: Vec<u8>,
        user_id: [u8; 4],
        user_key: Vec<u8>,
    },
}

impl SsrUdpProtocol {
    pub(crate) fn encode(&self, packet: &mut BytesMut) {
        match self {
            Self::PassThrough => {}
            Self::AuthAes128 {
                digest,
                user_id,
                user_key,
                ..
            } => {
                packet.put_slice(user_id);
                let tag = digest.hmac(user_key, packet);
                packet.put_slice(&tag[..4]);
            }
            Self::AuthChain {
                protocol_key,
                user_id,
                user_key,
            } => encode_auth_chain_packet(packet, protocol_key, user_id, user_key),
        }
    }

    pub(crate) fn decode<'a>(
        &self,
        packet: &'a mut [u8],
    ) -> io::Result<&'a mut [u8]> {
        match self {
            Self::PassThrough => Ok(packet),
            Self::AuthAes128 {
                digest,
                protocol_key,
                ..
            } => {
                if packet.len() < 4 {
                    return Err(io::Error::new(
                        io::ErrorKind::InvalidData,
                        "SSR auth_aes128 UDP packet is too short",
                    ));
                }
                let data_length = packet.len() - 4;
                let expected = digest.hmac(protocol_key, &packet[..data_length]);
                if packet[data_length..] != expected[..4] {
                    return Err(io::Error::new(
                        io::ErrorKind::InvalidData,
                        "SSR auth_aes128 UDP packet MAC mismatch",
                    ));
                }
                Ok(&mut packet[..data_length])
            }
            Self::AuthChain {
                protocol_key,
                user_key,
                ..
            } => decode_auth_chain_packet(packet, protocol_key, user_key),
        }
    }
}

impl SsrProtocol {
    pub(crate) fn auth_sha1_v4() -> Self {
        Self::AuthSha1V4(AuthSha1V4Context::new())
    }

    pub(crate) fn auth_aes128_md5(
        param: Option<String>,
        obfs_overhead: usize,
    ) -> Self {
        Self::AuthAes128(AuthAes128Context::new(
            AuthAes128Digest::Md5,
            param.as_deref().unwrap_or_default(),
            obfs_overhead + 9,
        ))
    }

    pub(crate) fn auth_aes128_sha1(
        param: Option<String>,
        obfs_overhead: usize,
    ) -> Self {
        Self::AuthAes128(AuthAes128Context::new(
            AuthAes128Digest::Sha1,
            param.as_deref().unwrap_or_default(),
            obfs_overhead + 9,
        ))
    }

    pub(crate) fn auth_chain_a(param: Option<String>, obfs_overhead: usize) -> Self {
        Self::AuthChain(AuthChainContext::new(
            AuthChainVariant::A,
            param.as_deref().unwrap_or_default(),
            obfs_overhead + 4,
        ))
    }

    pub(crate) fn auth_chain_b(param: Option<String>, obfs_overhead: usize) -> Self {
        Self::AuthChain(AuthChainContext::new(
            AuthChainVariant::B,
            param.as_deref().unwrap_or_default(),
            obfs_overhead + 4,
        ))
    }

    pub(crate) fn wrap_stream(
        &self,
        context: Arc<Context>,
        stream: AnyStream,
        method: shadowsocks::crypto::CipherKind,
        cipher_key: &[u8],
        password: &str,
    ) -> AnyStream {
        match self {
            Self::AuthSha1V4(auth_context) => {
                let protocol_key = if cipher_key.is_empty() {
                    let mut key = vec![0u8; 16];
                    openssl_bytes_to_key(password.as_bytes(), &mut key);
                    key
                } else {
                    cipher_key.to_vec()
                };
                let cipher = CryptoStream::from_stream(
                    context.as_ref(),
                    stream,
                    StreamType::Client,
                    method,
                    cipher_key,
                );
                let iv = cipher.sent_nonce().to_vec();
                Box::new(AuthSha1V4Stream::new(
                    context,
                    cipher,
                    protocol_key,
                    iv,
                    auth_context.next(),
                ))
            }
            Self::AuthAes128(auth_context) => {
                let protocol_key = protocol_key(cipher_key, password);
                let cipher = CryptoStream::from_stream(
                    context.as_ref(),
                    stream,
                    StreamType::Client,
                    method,
                    cipher_key,
                );
                let iv = cipher.sent_nonce().to_vec();
                let user_key = auth_context
                    .user_key
                    .clone()
                    .unwrap_or_else(|| protocol_key.clone());
                Box::new(AuthAes128Stream::new(
                    context,
                    cipher,
                    protocol_key,
                    iv,
                    auth_context.auth.next(),
                    auth_context.user_id,
                    user_key,
                    auth_context.digest,
                    auth_context.overhead,
                ))
            }
            Self::AuthChain(auth_context) => {
                let protocol_key = protocol_key(cipher_key, password);
                let cipher = CryptoStream::from_stream(
                    context.as_ref(),
                    stream,
                    StreamType::Client,
                    method,
                    cipher_key,
                );
                let iv = cipher.sent_nonce().to_vec();
                let user_key = auth_context
                    .user_key
                    .clone()
                    .unwrap_or_else(|| protocol_key.clone());
                Box::new(AuthChainStream::new(
                    context,
                    cipher,
                    protocol_key,
                    iv,
                    auth_context.auth.next(),
                    auth_context.user_id,
                    user_key,
                    auth_context.variant,
                    auth_context.overhead,
                ))
            }
        }
    }

    pub(crate) fn udp_protocol(
        &self,
        cipher_key: &[u8],
        password: &str,
    ) -> SsrUdpProtocol {
        match self {
            Self::AuthSha1V4(_) => SsrUdpProtocol::PassThrough,
            Self::AuthAes128(context) => {
                let protocol_key = protocol_key(cipher_key, password);
                SsrUdpProtocol::AuthAes128 {
                    digest: context.digest,
                    user_id: context.user_id,
                    user_key: context
                        .user_key
                        .clone()
                        .unwrap_or_else(|| protocol_key.clone()),
                    protocol_key,
                }
            }
            Self::AuthChain(context) => {
                let protocol_key = protocol_key(cipher_key, password);
                SsrUdpProtocol::AuthChain {
                    user_id: context.user_id,
                    user_key: context
                        .user_key
                        .clone()
                        .unwrap_or_else(|| protocol_key.clone()),
                    protocol_key,
                }
            }
        }
    }
}

fn protocol_key(cipher_key: &[u8], password: &str) -> Vec<u8> {
    if cipher_key.is_empty() {
        let mut key = vec![0u8; 16];
        openssl_bytes_to_key(password.as_bytes(), &mut key);
        key
    } else {
        cipher_key.to_vec()
    }
}

#[derive(Debug)]
pub(crate) struct AuthSha1V4Context {
    state: Mutex<AuthState>,
}

#[derive(Debug, Default)]
struct AuthState {
    client_id: [u8; 4],
    connection_id: u32,
}

#[derive(Clone, Copy, Debug)]
struct ConnectionAuth {
    client_id: [u8; 4],
    connection_id: u32,
}

impl AuthSha1V4Context {
    fn new() -> Self {
        Self {
            state: Mutex::new(AuthState::default()),
        }
    }

    fn next(&self) -> ConnectionAuth {
        let mut state = self.state.lock().expect("SSR auth state poisoned");
        if state.connection_id > 0xff00_0000 || state.connection_id == 0 {
            rand::rng().fill_bytes(&mut state.client_id);
            state.connection_id = rand::random::<u32>() & 0x00ff_ffff;
        }
        state.connection_id = state.connection_id.wrapping_add(1);
        ConnectionAuth {
            client_id: state.client_id,
            connection_id: state.connection_id,
        }
    }
}

#[derive(Clone, Copy, Debug)]
pub(crate) enum AuthAes128Digest {
    Md5,
    Sha1,
}

impl AuthAes128Digest {
    fn salt(self) -> &'static str {
        match self {
            Self::Md5 => "auth_aes128_md5",
            Self::Sha1 => "auth_aes128_sha1",
        }
    }

    fn digest(self, data: &[u8]) -> Vec<u8> {
        match self {
            Self::Md5 => md5::Md5::digest(data).to_vec(),
            Self::Sha1 => Sha1::digest(data).to_vec(),
        }
    }

    fn hmac(self, key: &[u8], data: &[u8]) -> Vec<u8> {
        match self {
            Self::Md5 => {
                let mut mac = Hmac::<md5::Md5>::new_from_slice(key)
                    .expect("HMAC accepts any key size");
                mac.update(data);
                mac.finalize().into_bytes().to_vec()
            }
            Self::Sha1 => hmac_sha1(key, data).to_vec(),
        }
    }
}

#[derive(Debug)]
pub(crate) struct AuthAes128Context {
    auth: AuthSha1V4Context,
    digest: AuthAes128Digest,
    user_id: [u8; 4],
    user_key: Option<Vec<u8>>,
    overhead: usize,
}

impl AuthAes128Context {
    fn new(digest: AuthAes128Digest, param: &str, overhead: usize) -> Self {
        let mut user_id = [0u8; 4];
        let mut user_key = None;
        let mut parts = param.split(':');
        if let (Some(id), Some(password)) = (parts.next(), parts.next()) {
            if let Ok(id) = id.parse::<u32>() {
                user_id = id.to_le_bytes();
                user_key = Some(digest.digest(password.as_bytes()));
            }
        }
        if user_key.is_none() {
            rand::rng().fill_bytes(&mut user_id);
        }
        Self {
            auth: AuthSha1V4Context::new(),
            digest,
            user_id,
            user_key,
            overhead,
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum AuthChainVariant {
    A,
    B,
}

impl AuthChainVariant {
    fn salt(self) -> &'static str {
        match self {
            Self::A => "auth_chain_a",
            Self::B => "auth_chain_b",
        }
    }
}

#[derive(Debug)]
pub(crate) struct AuthChainContext {
    auth: AuthSha1V4Context,
    variant: AuthChainVariant,
    user_id: [u8; 4],
    user_key: Option<Vec<u8>>,
    overhead: usize,
}

impl AuthChainContext {
    fn new(variant: AuthChainVariant, param: &str, overhead: usize) -> Self {
        let mut user_id = [0u8; 4];
        let mut user_key = None;
        let mut parts = param.split(':');
        if let (Some(id), Some(password)) = (parts.next(), parts.next()) {
            if let Ok(id) = id.parse::<u32>() {
                user_id = id.to_le_bytes();
                user_key = Some(password.as_bytes().to_vec());
            }
        }
        if user_key.is_none() {
            rand::rng().fill_bytes(&mut user_id);
        }
        Self {
            auth: AuthSha1V4Context::new(),
            variant,
            user_id,
            user_key,
            overhead,
        }
    }
}

struct AuthSha1V4Stream {
    context: Arc<Context>,
    inner: CryptoStream<AnyStream>,
    key: Vec<u8>,
    iv: Vec<u8>,
    auth: ConnectionAuth,
    auth_header_sent: bool,
    read_encoded: BytesMut,
    read_decoded: BytesMut,
    write_encoded: BytesMut,
    write_pos: usize,
    write_committed: usize,
}

impl AuthSha1V4Stream {
    fn new(
        context: Arc<Context>,
        inner: CryptoStream<AnyStream>,
        key: Vec<u8>,
        iv: Vec<u8>,
        auth: ConnectionAuth,
    ) -> Self {
        Self {
            context,
            inner,
            key,
            iv,
            auth,
            auth_header_sent: false,
            read_encoded: BytesMut::new(),
            read_decoded: BytesMut::new(),
            write_encoded: BytesMut::new(),
            write_pos: 0,
            write_committed: 0,
        }
    }

    fn encode(&mut self, source: &[u8]) {
        let mut remaining = source;
        if !self.auth_header_sent {
            let data_length = initial_data_length(remaining);
            self.pack_auth_data(&remaining[..data_length]);
            remaining = &remaining[data_length..];
            self.auth_header_sent = true;
        }
        while remaining.len() > MAX_DATA_LENGTH {
            self.pack_data(&remaining[..MAX_DATA_LENGTH]);
            remaining = &remaining[MAX_DATA_LENGTH..];
        }
        if !remaining.is_empty() {
            self.pack_data(remaining);
        }
    }

    fn pack_auth_data(&mut self, data: &[u8]) {
        let random_length = random_padding_length(12 + data.len());
        let prefix_length = if random_length < 128 { 1 } else { 3 };
        let frame_length =
            2 + 4 + prefix_length + random_length + 12 + data.len() + 10;
        let frame_start = self.write_encoded.len();

        let mut crc_data =
            Vec::with_capacity(2 + AUTH_SHA1_V4_SALT.len() + self.key.len());
        crc_data.extend_from_slice(&(frame_length as u16).to_be_bytes());
        crc_data.extend_from_slice(AUTH_SHA1_V4_SALT);
        crc_data.extend_from_slice(&self.key);
        self.write_encoded
            .put_slice(&(frame_length as u16).to_be_bytes());
        self.write_encoded.put_u32_le(crc32fast::hash(&crc_data));
        put_random_padding(&mut self.write_encoded, random_length);
        self.write_encoded.put_u32_le(unix_timestamp());
        self.write_encoded.put_slice(&self.auth.client_id);
        self.write_encoded.put_u32_le(self.auth.connection_id);
        self.write_encoded.put_slice(data);

        let mut hmac_key = Vec::with_capacity(self.iv.len() + self.key.len());
        hmac_key.extend_from_slice(&self.iv);
        hmac_key.extend_from_slice(&self.key);
        let tag = hmac_sha1(&hmac_key, &self.write_encoded[frame_start + 10..]);
        self.write_encoded.put_slice(&tag[..10]);
        debug_assert_eq!(self.write_encoded.len() - frame_start, frame_length);
    }

    fn pack_data(&mut self, data: &[u8]) {
        let random_length = random_padding_length(data.len());
        let prefix_length = if random_length < 128 { 1 } else { 3 };
        let frame_length = 2 + 2 + prefix_length + random_length + data.len() + 4;
        let frame_start = self.write_encoded.len();

        self.write_encoded.put_u16(frame_length as u16);
        let length_crc =
            crc32fast::hash(&self.write_encoded[frame_start..frame_start + 2]);
        self.write_encoded.put_u16_le(length_crc as u16);
        put_random_padding(&mut self.write_encoded, random_length);
        self.write_encoded.put_slice(data);
        let checksum = adler32(&self.write_encoded[frame_start..]);
        self.write_encoded.put_u32_le(checksum);
        debug_assert_eq!(self.write_encoded.len() - frame_start, frame_length);
    }

    fn decode_available(&mut self) -> io::Result<()> {
        while self.read_encoded.len() > 4 {
            let expected_crc = crc32fast::hash(&self.read_encoded[..2]) as u16;
            let actual_crc = u16::from_le_bytes(
                self.read_encoded[2..4].try_into().expect("two-byte CRC"),
            );
            if expected_crc != actual_crc {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "SSR auth_sha1_v4 frame CRC32 mismatch",
                ));
            }

            let frame_length = u16::from_be_bytes(
                self.read_encoded[..2].try_into().expect("two-byte length"),
            ) as usize;
            if !(7..MAX_FRAME_LENGTH).contains(&frame_length) {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "SSR auth_sha1_v4 frame length is invalid",
                ));
            }
            if frame_length > self.read_encoded.len() {
                break;
            }
            let frame = &self.read_encoded[..frame_length];
            let expected_adler = adler32(&frame[..frame_length - 4]);
            let actual_adler = u32::from_le_bytes(
                frame[frame_length - 4..]
                    .try_into()
                    .expect("four-byte Adler32"),
            );
            if expected_adler != actual_adler {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "SSR auth_sha1_v4 frame Adler32 mismatch",
                ));
            }
            let data_offset = if frame[4] < 255 {
                frame[4] as usize + 4
            } else {
                if frame_length < 7 {
                    return Err(io::Error::new(
                        io::ErrorKind::InvalidData,
                        "SSR auth_sha1_v4 extended padding is truncated",
                    ));
                }
                u16::from_be_bytes(frame[5..7].try_into().expect("two-byte padding"))
                    as usize
                    + 4
            };
            if data_offset > frame_length - 4 {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "SSR auth_sha1_v4 padding exceeds frame length",
                ));
            }
            self.read_decoded
                .put_slice(&frame[data_offset..frame_length - 4]);
            self.read_encoded.advance(frame_length);
        }
        Ok(())
    }

    fn poll_drain_write(
        &mut self,
        cx: &mut TaskContext<'_>,
    ) -> Poll<io::Result<()>> {
        while self.write_pos < self.write_encoded.len() {
            let written = ready!(
                Pin::new(&mut self.inner)
                    .poll_write_encrypted(cx, &self.write_encoded[self.write_pos..])
            )
            .map_err(io::Error::from)?;
            if written == 0 {
                return Poll::Ready(Err(io::Error::from(io::ErrorKind::WriteZero)));
            }
            self.write_pos += written;
        }
        Poll::Ready(Ok(()))
    }
}

impl AsyncRead for AuthSha1V4Stream {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut TaskContext<'_>,
        output: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        loop {
            if !this.read_decoded.is_empty() {
                let length = this.read_decoded.len().min(output.remaining());
                output.put_slice(&this.read_decoded.split_to(length));
                return Poll::Ready(Ok(()));
            }

            this.decode_available()?;
            if !this.read_decoded.is_empty() {
                continue;
            }

            let mut scratch = [0u8; MAX_FRAME_LENGTH];
            let mut encrypted = ReadBuf::new(&mut scratch);
            ready!(Pin::new(&mut this.inner).poll_read_decrypted(
                cx,
                this.context.as_ref(),
                &mut encrypted,
            ))
            .map_err(io::Error::from)?;
            if encrypted.filled().is_empty() {
                if this.read_encoded.is_empty() {
                    return Poll::Ready(Ok(()));
                }
                return Poll::Ready(Err(io::Error::from(
                    io::ErrorKind::UnexpectedEof,
                )));
            }
            this.read_encoded.put_slice(encrypted.filled());
        }
    }
}

impl AsyncWrite for AuthSha1V4Stream {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut TaskContext<'_>,
        source: &[u8],
    ) -> Poll<io::Result<usize>> {
        let this = self.get_mut();
        if source.is_empty() {
            return Poll::Ready(Ok(0));
        }
        if this.write_committed > 0 {
            ready!(this.poll_drain_write(cx))?;
            let committed = this.write_committed;
            this.write_encoded.clear();
            this.write_pos = 0;
            this.write_committed = 0;
            return Poll::Ready(Ok(committed));
        }

        this.write_encoded.clear();
        this.write_pos = 0;
        this.write_committed = source.len();
        this.encode(source);
        ready!(this.poll_drain_write(cx))?;
        let committed = this.write_committed;
        this.write_encoded.clear();
        this.write_pos = 0;
        this.write_committed = 0;
        Poll::Ready(Ok(committed))
    }

    fn poll_flush(
        self: Pin<&mut Self>,
        cx: &mut TaskContext<'_>,
    ) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        ready!(this.poll_drain_write(cx))?;
        this.write_encoded.clear();
        this.write_pos = 0;
        this.write_committed = 0;
        this.inner.poll_flush(cx).map_err(io::Error::from)
    }

    fn poll_shutdown(
        self: Pin<&mut Self>,
        cx: &mut TaskContext<'_>,
    ) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        ready!(this.poll_drain_write(cx))?;
        this.inner.poll_shutdown(cx).map_err(io::Error::from)
    }
}

struct AuthAes128Stream {
    context: Arc<Context>,
    inner: CryptoStream<AnyStream>,
    key: Vec<u8>,
    iv: Vec<u8>,
    auth: ConnectionAuth,
    user_id: [u8; 4],
    user_key: Vec<u8>,
    digest: AuthAes128Digest,
    overhead: usize,
    auth_header_sent: bool,
    pack_id: u32,
    recv_id: u32,
    read_encoded: BytesMut,
    read_decoded: BytesMut,
    write_encoded: BytesMut,
    write_pos: usize,
    write_committed: usize,
}

impl AuthAes128Stream {
    #[allow(clippy::too_many_arguments)]
    fn new(
        context: Arc<Context>,
        inner: CryptoStream<AnyStream>,
        key: Vec<u8>,
        iv: Vec<u8>,
        auth: ConnectionAuth,
        user_id: [u8; 4],
        user_key: Vec<u8>,
        digest: AuthAes128Digest,
        overhead: usize,
    ) -> Self {
        Self {
            context,
            inner,
            key,
            iv,
            auth,
            user_id,
            user_key,
            digest,
            overhead,
            auth_header_sent: false,
            pack_id: 1,
            recv_id: 1,
            read_encoded: BytesMut::new(),
            read_decoded: BytesMut::new(),
            write_encoded: BytesMut::new(),
            write_pos: 0,
            write_committed: 0,
        }
    }

    fn encode(&mut self, source: &[u8]) {
        let full_data_length = source.len();
        let mut remaining = source;
        if !self.auth_header_sent {
            let data_length = initial_data_length(remaining);
            self.pack_auth_data(&remaining[..data_length]);
            remaining = &remaining[data_length..];
            self.auth_header_sent = true;
        }
        while remaining.len() > MAX_DATA_LENGTH {
            self.pack_data(&remaining[..MAX_DATA_LENGTH], full_data_length);
            remaining = &remaining[MAX_DATA_LENGTH..];
        }
        if !remaining.is_empty() {
            self.pack_data(remaining, full_data_length);
        }
    }

    fn pack_auth_data(&mut self, data: &[u8]) {
        if data.is_empty() {
            return;
        }
        let random_length = if data.len() > 400 {
            rand::random_range(0..512)
        } else {
            rand::random_range(0..1024)
        };
        let frame_length = 7 + 4 + 16 + 4 + random_length + data.len() + 4;
        let frame_start = self.write_encoded.len();
        let mut mac_key = Vec::with_capacity(self.iv.len() + self.key.len());
        mac_key.extend_from_slice(&self.iv);
        mac_key.extend_from_slice(&self.key);

        self.write_encoded.put_u8(rand::random());
        let check = self
            .digest
            .hmac(&mac_key, &self.write_encoded[frame_start..]);
        self.write_encoded.put_slice(&check[..6]);
        self.write_encoded.put_slice(&self.user_id);

        let mut auth_block = [0u8; 16];
        auth_block[..4].copy_from_slice(&unix_timestamp().to_le_bytes());
        auth_block[4..8].copy_from_slice(&self.auth.client_id);
        auth_block[8..12].copy_from_slice(&self.auth.connection_id.to_le_bytes());
        auth_block[12..14].copy_from_slice(&(frame_length as u16).to_le_bytes());
        auth_block[14..16].copy_from_slice(&(random_length as u16).to_le_bytes());
        encrypt_auth_aes_block(&mut auth_block, &self.user_key, self.digest.salt());
        self.write_encoded.put_slice(&auth_block);

        let user_tag = self
            .digest
            .hmac(&mac_key, &self.write_encoded[frame_start + 7..]);
        self.write_encoded.put_slice(&user_tag[..4]);
        put_random_bytes(&mut self.write_encoded, random_length);
        self.write_encoded.put_slice(data);
        let final_tag = self
            .digest
            .hmac(&self.user_key, &self.write_encoded[frame_start..]);
        self.write_encoded.put_slice(&final_tag[..4]);
        debug_assert_eq!(self.write_encoded.len() - frame_start, frame_length);
    }

    fn pack_data(&mut self, data: &[u8], full_data_length: usize) {
        let random_length = auth_aes_data_padding_length(
            data.len(),
            full_data_length,
            self.overhead,
        );
        let prefix_length = if random_length < 128 { 1 } else { 3 };
        let frame_length = 2 + 2 + prefix_length + random_length + data.len() + 4;
        let frame_start = self.write_encoded.len();
        let mut mac_key = self.user_key.clone();
        mac_key.extend_from_slice(&self.pack_id.to_le_bytes());
        self.pack_id = self.pack_id.wrapping_add(1);

        self.write_encoded.put_u16_le(frame_length as u16);
        let length_tag = self
            .digest
            .hmac(&mac_key, &self.write_encoded[frame_start..]);
        self.write_encoded.put_slice(&length_tag[..2]);
        put_random_padding_le(&mut self.write_encoded, random_length);
        self.write_encoded.put_slice(data);
        let final_tag = self
            .digest
            .hmac(&mac_key, &self.write_encoded[frame_start..]);
        self.write_encoded.put_slice(&final_tag[..4]);
        debug_assert_eq!(self.write_encoded.len() - frame_start, frame_length);
    }

    fn decode_available(&mut self) -> io::Result<()> {
        while self.read_encoded.len() > 4 {
            let mut mac_key = self.user_key.clone();
            mac_key.extend_from_slice(&self.recv_id.to_le_bytes());
            let expected_length_tag =
                self.digest.hmac(&mac_key, &self.read_encoded[..2]);
            if self.read_encoded[2..4] != expected_length_tag[..2] {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "SSR auth_aes128 frame length MAC mismatch",
                ));
            }

            let frame_length = u16::from_le_bytes(
                self.read_encoded[..2].try_into().expect("two-byte length"),
            ) as usize;
            if !(7..MAX_FRAME_LENGTH).contains(&frame_length) {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "SSR auth_aes128 frame length is invalid",
                ));
            }
            if frame_length > self.read_encoded.len() {
                break;
            }
            let frame = &self.read_encoded[..frame_length];
            let expected_tag =
                self.digest.hmac(&mac_key, &frame[..frame_length - 4]);
            if frame[frame_length - 4..] != expected_tag[..4] {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "SSR auth_aes128 frame MAC mismatch",
                ));
            }
            let data_offset = if frame[4] < 255 {
                frame[4] as usize + 4
            } else {
                if frame_length < 7 {
                    return Err(io::Error::new(
                        io::ErrorKind::InvalidData,
                        "SSR auth_aes128 extended padding is truncated",
                    ));
                }
                u16::from_le_bytes(frame[5..7].try_into().expect("two-byte padding"))
                    as usize
                    + 4
            };
            if data_offset > frame_length - 4 {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "SSR auth_aes128 padding exceeds frame length",
                ));
            }
            self.read_decoded
                .put_slice(&frame[data_offset..frame_length - 4]);
            self.read_encoded.advance(frame_length);
            self.recv_id = self.recv_id.wrapping_add(1);
        }
        Ok(())
    }

    fn poll_drain_write(
        &mut self,
        cx: &mut TaskContext<'_>,
    ) -> Poll<io::Result<()>> {
        while self.write_pos < self.write_encoded.len() {
            let written = ready!(
                Pin::new(&mut self.inner)
                    .poll_write_encrypted(cx, &self.write_encoded[self.write_pos..])
            )
            .map_err(io::Error::from)?;
            if written == 0 {
                return Poll::Ready(Err(io::Error::from(io::ErrorKind::WriteZero)));
            }
            self.write_pos += written;
        }
        Poll::Ready(Ok(()))
    }
}

impl AsyncRead for AuthAes128Stream {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut TaskContext<'_>,
        output: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        loop {
            if !this.read_decoded.is_empty() {
                let length = this.read_decoded.len().min(output.remaining());
                output.put_slice(&this.read_decoded.split_to(length));
                return Poll::Ready(Ok(()));
            }
            this.decode_available()?;
            if !this.read_decoded.is_empty() {
                continue;
            }

            let mut scratch = [0u8; MAX_FRAME_LENGTH];
            let mut encrypted = ReadBuf::new(&mut scratch);
            ready!(Pin::new(&mut this.inner).poll_read_decrypted(
                cx,
                this.context.as_ref(),
                &mut encrypted,
            ))
            .map_err(io::Error::from)?;
            if encrypted.filled().is_empty() {
                if this.read_encoded.is_empty() {
                    return Poll::Ready(Ok(()));
                }
                return Poll::Ready(Err(io::Error::from(
                    io::ErrorKind::UnexpectedEof,
                )));
            }
            this.read_encoded.put_slice(encrypted.filled());
        }
    }
}

impl AsyncWrite for AuthAes128Stream {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut TaskContext<'_>,
        source: &[u8],
    ) -> Poll<io::Result<usize>> {
        let this = self.get_mut();
        if source.is_empty() {
            return Poll::Ready(Ok(0));
        }
        if this.write_committed > 0 {
            ready!(this.poll_drain_write(cx))?;
            let committed = this.write_committed;
            this.write_encoded.clear();
            this.write_pos = 0;
            this.write_committed = 0;
            return Poll::Ready(Ok(committed));
        }

        this.write_encoded.clear();
        this.write_pos = 0;
        this.write_committed = source.len();
        this.encode(source);
        ready!(this.poll_drain_write(cx))?;
        let committed = this.write_committed;
        this.write_encoded.clear();
        this.write_pos = 0;
        this.write_committed = 0;
        Poll::Ready(Ok(committed))
    }

    fn poll_flush(
        self: Pin<&mut Self>,
        cx: &mut TaskContext<'_>,
    ) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        ready!(this.poll_drain_write(cx))?;
        this.write_encoded.clear();
        this.write_pos = 0;
        this.write_committed = 0;
        this.inner.poll_flush(cx).map_err(io::Error::from)
    }

    fn poll_shutdown(
        self: Pin<&mut Self>,
        cx: &mut TaskContext<'_>,
    ) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        ready!(this.poll_drain_write(cx))?;
        this.inner.poll_shutdown(cx).map_err(io::Error::from)
    }
}

struct AuthChainStream {
    context: Arc<Context>,
    inner: CryptoStream<AnyStream>,
    protocol_key: Vec<u8>,
    iv: Vec<u8>,
    auth: ConnectionAuth,
    user_id: [u8; 4],
    user_key: Vec<u8>,
    variant: AuthChainVariant,
    overhead: usize,
    data_sizes: Vec<usize>,
    data_sizes2: Vec<usize>,
    auth_header_sent: bool,
    pack_id: u32,
    recv_id: u32,
    last_client_hash: [u8; 16],
    last_server_hash: [u8; 16],
    encrypter: Option<Rc4Cipher>,
    decrypter: Option<Rc4Cipher>,
    read_encoded: BytesMut,
    read_decoded: BytesMut,
    write_encoded: BytesMut,
    write_pos: usize,
    write_committed: usize,
}

impl AuthChainStream {
    #[allow(clippy::too_many_arguments)]
    fn new(
        context: Arc<Context>,
        inner: CryptoStream<AnyStream>,
        protocol_key: Vec<u8>,
        iv: Vec<u8>,
        auth: ConnectionAuth,
        user_id: [u8; 4],
        user_key: Vec<u8>,
        variant: AuthChainVariant,
        overhead: usize,
    ) -> Self {
        let (data_sizes, data_sizes2) = if variant == AuthChainVariant::B {
            auth_chain_b_data_sizes(&protocol_key)
        } else {
            (Vec::new(), Vec::new())
        };
        Self {
            context,
            inner,
            protocol_key,
            iv,
            auth,
            user_id,
            user_key,
            variant,
            overhead,
            data_sizes,
            data_sizes2,
            auth_header_sent: false,
            pack_id: 1,
            recv_id: 1,
            last_client_hash: [0; 16],
            last_server_hash: [0; 16],
            encrypter: None,
            decrypter: None,
            read_encoded: BytesMut::new(),
            read_decoded: BytesMut::new(),
            write_encoded: BytesMut::new(),
            write_pos: 0,
            write_committed: 0,
        }
    }

    fn encode(&mut self, source: &[u8]) {
        let mut remaining = source;
        if !self.auth_header_sent {
            let data_length = initial_data_length(remaining);
            self.pack_auth_data(&remaining[..data_length]);
            remaining = &remaining[data_length..];
            self.auth_header_sent = true;
        }
        while remaining.len() > 2800 {
            self.pack_data(&remaining[..2800]);
            remaining = &remaining[2800..];
        }
        if !remaining.is_empty() {
            self.pack_data(remaining);
        }
    }

    fn pack_auth_data(&mut self, data: &[u8]) {
        let frame_start = self.write_encoded.len();
        put_random_bytes(&mut self.write_encoded, 4);
        let mut mac_key =
            Vec::with_capacity(self.iv.len() + self.protocol_key.len());
        mac_key.extend_from_slice(&self.iv);
        mac_key.extend_from_slice(&self.protocol_key);
        self.last_client_hash =
            hmac_md5(&mac_key, &self.write_encoded[frame_start..]);
        self.write_encoded.put_slice(&self.last_client_hash[..8]);

        let rc4_key = auth_chain_rc4_key(&self.user_key, &self.last_client_hash);
        self.encrypter = Some(Rc4Cipher::new(&rc4_key));
        self.decrypter = Some(Rc4Cipher::new(&rc4_key));

        let encoded_user_id = u32::from_le_bytes(self.user_id)
            ^ u32::from_le_bytes(
                self.last_client_hash[8..12]
                    .try_into()
                    .expect("four-byte hash part"),
            );
        self.write_encoded.put_u32_le(encoded_user_id);

        let mut auth_block = [0u8; 16];
        auth_block[..4].copy_from_slice(&unix_timestamp().to_le_bytes());
        auth_block[4..8].copy_from_slice(&self.auth.client_id);
        auth_block[8..12].copy_from_slice(&self.auth.connection_id.to_le_bytes());
        auth_block[12..14].copy_from_slice(&(self.overhead as u16).to_le_bytes());
        encrypt_auth_aes_block(&mut auth_block, &self.user_key, self.variant.salt());
        self.write_encoded.put_slice(&auth_block);

        self.last_server_hash =
            hmac_md5(&self.user_key, &self.write_encoded[frame_start + 12..]);
        self.write_encoded.put_slice(&self.last_server_hash[..4]);
        self.pack_data(data);
    }

    fn pack_data(&mut self, data: &[u8]) {
        let mut encrypted = data.to_vec();
        self.encrypter
            .as_mut()
            .expect("auth_chain RC4 initialized by auth header")
            .apply(&mut encrypted);

        let mut mac_key = self.user_key.clone();
        mac_key.extend_from_slice(&self.pack_id.to_le_bytes());
        self.pack_id = self.pack_id.wrapping_add(1);
        let encoded_length = data.len() as u16
            ^ u16::from_le_bytes(
                self.last_client_hash[14..16]
                    .try_into()
                    .expect("two-byte hash part"),
            );
        let mut random =
            XorShift128Plus::from_bin_and_length(&self.last_client_hash, data.len());
        let random_length = auth_chain_padding_length(
            self.variant,
            data.len(),
            self.overhead,
            &self.data_sizes,
            &self.data_sizes2,
            &mut random,
        );
        let frame_start = self.write_encoded.len();
        self.write_encoded.put_u16_le(encoded_length);
        put_auth_chain_mixed_data(
            &mut self.write_encoded,
            &encrypted,
            random_length,
            &mut random,
        );
        self.last_client_hash =
            hmac_md5(&mac_key, &self.write_encoded[frame_start..]);
        self.write_encoded.put_slice(&self.last_client_hash[..2]);
    }

    fn decode_available(&mut self) -> io::Result<()> {
        while self.read_encoded.len() > 4 {
            let encoded_length = u16::from_le_bytes(
                self.read_encoded[..2].try_into().expect("two-byte length"),
            );
            let data_length = (encoded_length
                ^ u16::from_le_bytes(
                    self.last_server_hash[14..16]
                        .try_into()
                        .expect("two-byte hash part"),
                )) as usize;
            let mut random = XorShift128Plus::from_bin_and_length(
                &self.last_server_hash,
                data_length,
            );
            let random_length = auth_chain_padding_length(
                self.variant,
                data_length,
                self.overhead,
                &self.data_sizes,
                &self.data_sizes2,
                &mut random,
            );
            let payload_length =
                data_length.checked_add(random_length).ok_or_else(|| {
                    io::Error::new(
                        io::ErrorKind::InvalidData,
                        "SSR auth_chain frame length overflow",
                    )
                })?;
            if payload_length >= 4096 {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "SSR auth_chain frame length is invalid",
                ));
            }
            let frame_length = payload_length + 4;
            if self.read_encoded.len() < frame_length {
                break;
            }

            let mut mac_key = self.user_key.clone();
            mac_key.extend_from_slice(&self.recv_id.to_le_bytes());
            let server_hash =
                hmac_md5(&mac_key, &self.read_encoded[..payload_length + 2]);
            if self.read_encoded[payload_length + 2..frame_length]
                != server_hash[..2]
            {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "SSR auth_chain frame MAC mismatch",
                ));
            }
            self.last_server_hash = server_hash;

            let data_start = 2 + if data_length > 0 && random_length > 0 {
                auth_chain_random_start(random_length, &mut random)
            } else {
                0
            };
            let data_end = data_start + data_length;
            if data_end > payload_length + 2 {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "SSR auth_chain random padding exceeds frame length",
                ));
            }
            let mut decoded = self.read_encoded[data_start..data_end].to_vec();
            self.decrypter
                .as_mut()
                .ok_or_else(|| {
                    io::Error::new(
                        io::ErrorKind::InvalidData,
                        "SSR auth_chain response arrived before auth header",
                    )
                })?
                .apply(&mut decoded);
            if self.recv_id == 1 {
                if decoded.len() < 2 {
                    return Err(io::Error::new(
                        io::ErrorKind::InvalidData,
                        "SSR auth_chain first response frame is too short",
                    ));
                }
                self.read_decoded.put_slice(&decoded[2..]);
            } else {
                self.read_decoded.put_slice(&decoded);
            }
            self.recv_id = self.recv_id.wrapping_add(1);
            self.read_encoded.advance(frame_length);
        }
        Ok(())
    }

    fn poll_drain_write(
        &mut self,
        cx: &mut TaskContext<'_>,
    ) -> Poll<io::Result<()>> {
        while self.write_pos < self.write_encoded.len() {
            let written = ready!(
                Pin::new(&mut self.inner)
                    .poll_write_encrypted(cx, &self.write_encoded[self.write_pos..])
            )
            .map_err(io::Error::from)?;
            if written == 0 {
                return Poll::Ready(Err(io::Error::from(io::ErrorKind::WriteZero)));
            }
            self.write_pos += written;
        }
        Poll::Ready(Ok(()))
    }
}

impl AsyncRead for AuthChainStream {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut TaskContext<'_>,
        output: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        loop {
            if !this.read_decoded.is_empty() {
                let length = this.read_decoded.len().min(output.remaining());
                output.put_slice(&this.read_decoded.split_to(length));
                return Poll::Ready(Ok(()));
            }
            this.decode_available()?;
            if !this.read_decoded.is_empty() {
                continue;
            }

            let mut scratch = [0u8; MAX_FRAME_LENGTH];
            let mut encrypted = ReadBuf::new(&mut scratch);
            ready!(Pin::new(&mut this.inner).poll_read_decrypted(
                cx,
                this.context.as_ref(),
                &mut encrypted,
            ))
            .map_err(io::Error::from)?;
            if encrypted.filled().is_empty() {
                if this.read_encoded.is_empty() {
                    return Poll::Ready(Ok(()));
                }
                return Poll::Ready(Err(io::Error::from(
                    io::ErrorKind::UnexpectedEof,
                )));
            }
            this.read_encoded.put_slice(encrypted.filled());
        }
    }
}

impl AsyncWrite for AuthChainStream {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut TaskContext<'_>,
        source: &[u8],
    ) -> Poll<io::Result<usize>> {
        let this = self.get_mut();
        if source.is_empty() {
            return Poll::Ready(Ok(0));
        }
        if this.write_committed > 0 {
            ready!(this.poll_drain_write(cx))?;
            let committed = this.write_committed;
            this.write_encoded.clear();
            this.write_pos = 0;
            this.write_committed = 0;
            return Poll::Ready(Ok(committed));
        }

        this.write_encoded.clear();
        this.write_pos = 0;
        this.write_committed = source.len();
        this.encode(source);
        ready!(this.poll_drain_write(cx))?;
        let committed = this.write_committed;
        this.write_encoded.clear();
        this.write_pos = 0;
        this.write_committed = 0;
        Poll::Ready(Ok(committed))
    }

    fn poll_flush(
        self: Pin<&mut Self>,
        cx: &mut TaskContext<'_>,
    ) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        ready!(this.poll_drain_write(cx))?;
        this.write_encoded.clear();
        this.write_pos = 0;
        this.write_committed = 0;
        this.inner.poll_flush(cx).map_err(io::Error::from)
    }

    fn poll_shutdown(
        self: Pin<&mut Self>,
        cx: &mut TaskContext<'_>,
    ) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        ready!(this.poll_drain_write(cx))?;
        this.inner.poll_shutdown(cx).map_err(io::Error::from)
    }
}

#[derive(Clone, Debug)]
struct Rc4Cipher {
    state: [u8; 256],
    x: u8,
    y: u8,
}

impl Rc4Cipher {
    fn new(key: &[u8]) -> Self {
        assert!(!key.is_empty(), "RC4 key must not be empty");
        let mut state = [0u8; 256];
        for (index, value) in state.iter_mut().enumerate() {
            *value = index as u8;
        }
        let mut key_index = 0usize;
        let mut state_index = 0u8;
        for index in 0..256 {
            state_index = state_index
                .wrapping_add(state[index])
                .wrapping_add(key[key_index]);
            state.swap(index, state_index as usize);
            key_index += 1;
            if key_index == key.len() {
                key_index = 0;
            }
        }
        Self { state, x: 0, y: 0 }
    }

    fn apply(&mut self, data: &mut [u8]) {
        for byte in data {
            self.x = self.x.wrapping_add(1);
            self.y = self.y.wrapping_add(self.state[self.x as usize]);
            self.state.swap(self.x as usize, self.y as usize);
            let index = self.state[self.x as usize]
                .wrapping_add(self.state[self.y as usize]);
            *byte ^= self.state[index as usize];
        }
    }
}

#[derive(Clone, Copy, Debug, Default)]
struct XorShift128Plus {
    state: [u64; 2],
}

impl XorShift128Plus {
    fn from_bin(data: &[u8]) -> Self {
        let mut seed = [0u8; 16];
        let length = data.len().min(seed.len());
        seed[..length].copy_from_slice(&data[..length]);
        Self {
            state: [
                u64::from_le_bytes(seed[..8].try_into().expect("eight-byte seed")),
                u64::from_le_bytes(seed[8..].try_into().expect("eight-byte seed")),
            ],
        }
    }

    fn from_bin_and_length(data: &[u8], length: usize) -> Self {
        let mut seed = [0u8; 16];
        let copy_length = data.len().min(seed.len());
        seed[..copy_length].copy_from_slice(&data[..copy_length]);
        seed[..2].copy_from_slice(&(length as u16).to_le_bytes());
        let mut random = Self::from_bin(&seed);
        for _ in 0..4 {
            random.next();
        }
        random
    }

    fn next(&mut self) -> u64 {
        let mut x = self.state[0];
        let y = self.state[1];
        self.state[0] = y;
        x ^= x << 23;
        x ^= y ^ (x >> 17) ^ (y >> 26);
        self.state[1] = x;
        x.wrapping_add(y)
    }
}

fn auth_chain_b_data_sizes(key: &[u8]) -> (Vec<usize>, Vec<usize>) {
    let mut random = XorShift128Plus::from_bin(key);
    let mut first = Vec::new();
    for _ in 0..random.next() % 8 + 4 {
        first.push((random.next() % 2340 % 2040 % 1440) as usize);
    }
    first.sort_unstable();

    let mut second = Vec::new();
    for _ in 0..random.next() % 16 + 8 {
        second.push((random.next() % 2340 % 2040 % 1440) as usize);
    }
    second.sort_unstable();
    (first, second)
}

fn auth_chain_padding_length(
    variant: AuthChainVariant,
    data_length: usize,
    overhead: usize,
    data_sizes: &[usize],
    data_sizes2: &[usize],
    random: &mut XorShift128Plus,
) -> usize {
    match variant {
        AuthChainVariant::A => {
            if data_length > 1440 {
                return 0;
            }
            auth_chain_fallback_padding(data_length, random)
        }
        AuthChainVariant::B => {
            if data_length >= 1440 {
                return 0;
            }
            let wanted = data_length.saturating_add(overhead);
            let position = data_sizes.partition_point(|size| *size < wanted);
            let final_position =
                position + (random.next() % data_sizes.len() as u64) as usize;
            if final_position < data_sizes.len() {
                return data_sizes[final_position]
                    .saturating_sub(data_length)
                    .saturating_sub(overhead);
            }

            let position = data_sizes2.partition_point(|size| *size < wanted);
            let final_position =
                position + (random.next() % data_sizes2.len() as u64) as usize;
            if final_position < data_sizes2.len() {
                return data_sizes2[final_position]
                    .saturating_sub(data_length)
                    .saturating_sub(overhead);
            }
            if final_position < position + data_sizes2.len() - 1 {
                return 0;
            }
            auth_chain_fallback_padding(data_length, random)
        }
    }
}

fn auth_chain_fallback_padding(
    data_length: usize,
    random: &mut XorShift128Plus,
) -> usize {
    if data_length > 1300 {
        (random.next() % 31) as usize
    } else if data_length > 900 {
        (random.next() % 127) as usize
    } else if data_length > 400 {
        (random.next() % 521) as usize
    } else {
        (random.next() % 1021) as usize
    }
}

fn auth_chain_random_start(
    random_length: usize,
    random: &mut XorShift128Plus,
) -> usize {
    if random_length == 0 {
        0
    } else {
        (random.next() % 8_589_934_609 % random_length as u64) as usize
    }
}

fn put_auth_chain_mixed_data(
    buffer: &mut BytesMut,
    data: &[u8],
    random_length: usize,
    random: &mut XorShift128Plus,
) {
    if data.is_empty() {
        put_random_bytes(buffer, random_length);
    } else if random_length > 0 {
        let start = auth_chain_random_start(random_length, random);
        put_random_bytes(buffer, start);
        buffer.put_slice(data);
        put_random_bytes(buffer, random_length - start);
    } else {
        buffer.put_slice(data);
    }
}

fn auth_chain_rc4_key(user_key: &[u8], hash: &[u8]) -> [u8; 16] {
    use base64::Engine as _;

    let password = format!(
        "{}{}",
        base64::engine::general_purpose::STANDARD.encode(user_key),
        base64::engine::general_purpose::STANDARD.encode(hash),
    );
    let mut key = [0u8; 16];
    openssl_bytes_to_key(password.as_bytes(), &mut key);
    key
}

fn hmac_md5(key: &[u8], data: &[u8]) -> [u8; 16] {
    let mut mac =
        Hmac::<md5::Md5>::new_from_slice(key).expect("HMAC accepts any key size");
    mac.update(data);
    mac.finalize().into_bytes().into()
}

fn encode_auth_chain_packet(
    packet: &mut BytesMut,
    protocol_key: &[u8],
    user_id: &[u8; 4],
    user_key: &[u8],
) {
    let mut auth_data = [0u8; 3];
    rand::rng().fill_bytes(&mut auth_data);
    let hash = hmac_md5(protocol_key, &auth_data);
    let mut random = XorShift128Plus::from_bin(&hash);
    let random_length = (random.next() % 127) as usize;
    let rc4_key = auth_chain_rc4_key(user_key, &hash);
    Rc4Cipher::new(&rc4_key).apply(packet);
    put_random_bytes(packet, random_length);
    packet.put_slice(&auth_data);
    packet.put_u32_le(
        u32::from_le_bytes(*user_id)
            ^ u32::from_le_bytes(hash[..4].try_into().expect("four-byte hash")),
    );
    let tag = hmac_md5(user_key, packet);
    packet.put_u8(tag[0]);
}

fn decode_auth_chain_packet<'a>(
    packet: &'a mut [u8],
    protocol_key: &[u8],
    user_key: &[u8],
) -> io::Result<&'a mut [u8]> {
    if packet.len() < 9 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "SSR auth_chain UDP packet is too short",
        ));
    }
    let tag_position = packet.len() - 1;
    let tag = hmac_md5(user_key, &packet[..tag_position]);
    if packet[tag_position] != tag[0] {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "SSR auth_chain UDP packet MAC mismatch",
        ));
    }
    let trailer_start = packet.len() - 8;
    let hash = hmac_md5(protocol_key, &packet[trailer_start..tag_position]);
    let mut random = XorShift128Plus::from_bin(&hash);
    let random_length = (random.next() % 127) as usize;
    let data_length =
        packet.len().checked_sub(8 + random_length).ok_or_else(|| {
            io::Error::new(
                io::ErrorKind::InvalidData,
                "SSR auth_chain UDP random padding exceeds packet length",
            )
        })?;
    let rc4_key = auth_chain_rc4_key(user_key, &hash);
    Rc4Cipher::new(&rc4_key).apply(&mut packet[..data_length]);
    Ok(&mut packet[..data_length])
}

fn auth_aes_data_padding_length(
    data_length: usize,
    full_data_length: usize,
    overhead: usize,
) -> usize {
    if full_data_length >= 32 * 1024 - overhead {
        return 0;
    }
    let reverse_length = 1460isize - data_length as isize - 9;
    if reverse_length == 0 {
        return 0;
    }
    if reverse_length < 0 {
        if reverse_length > -1460 {
            return random_below((reverse_length + 1460) as usize);
        }
        return rand::random_range(0..32);
    }
    random_below(reverse_length as usize)
}

fn random_below(maximum: usize) -> usize {
    if maximum == 0 {
        0
    } else {
        rand::random_range(0..maximum)
    }
}

fn put_random_padding_le(buffer: &mut BytesMut, length: usize) {
    if length < 128 {
        buffer.put_u8((length + 1) as u8);
    } else {
        buffer.put_u8(255);
        buffer.put_u16_le((length + 3) as u16);
    }
    put_random_bytes(buffer, length);
}

fn put_random_bytes(buffer: &mut BytesMut, length: usize) {
    let start = buffer.len();
    buffer.resize(start + length, 0);
    rand::rng().fill_bytes(&mut buffer[start..]);
}

fn encrypt_auth_aes_block(block: &mut [u8; 16], user_key: &[u8], salt: &str) {
    use aes::cipher::{BlockCipherEncrypt, KeyInit};
    use base64::Engine as _;

    let password = format!(
        "{}{}",
        base64::engine::general_purpose::STANDARD.encode(user_key),
        salt,
    );
    let mut key = [0u8; 16];
    openssl_bytes_to_key(password.as_bytes(), &mut key);
    let cipher = aes::Aes128::new_from_slice(&key).expect("valid AES-128 key");
    let mut encrypted = aes::cipher::Block::<aes::Aes128>::default();
    encrypted.copy_from_slice(block);
    cipher.encrypt_block(&mut encrypted);
    block.copy_from_slice(&encrypted);
}

fn initial_data_length(data: &[u8]) -> usize {
    let head_size = if data.len() < 2 {
        30
    } else {
        match data[0] & 7 {
            1 => 7,
            4 => 19,
            3 => 4 + data[1] as usize,
            _ => 30,
        }
    };
    data.len().min(head_size + rand::random_range(0..32))
}

fn random_padding_length(data_length: usize) -> usize {
    if data_length > 1200 {
        0
    } else if data_length > 400 {
        rand::random_range(0..256)
    } else {
        rand::random_range(0..512)
    }
}

fn put_random_padding(buffer: &mut BytesMut, length: usize) {
    if length < 128 {
        buffer.put_u8((length + 1) as u8);
    } else {
        buffer.put_u8(255);
        buffer.put_u16((length + 3) as u16);
    }
    let start = buffer.len();
    buffer.resize(start + length, 0);
    rand::rng().fill_bytes(&mut buffer[start..]);
}

fn unix_timestamp() -> u32 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs() as u32
}

fn hmac_sha1(key: &[u8], data: &[u8]) -> [u8; 20] {
    let mut mac =
        Hmac::<Sha1>::new_from_slice(key).expect("HMAC accepts any key size");
    mac.update(data);
    mac.finalize().into_bytes().into()
}

fn adler32(data: &[u8]) -> u32 {
    const MOD_ADLER: u32 = 65_521;
    let mut a = 1u32;
    let mut b = 0u32;
    for byte in data {
        a = (a + *byte as u32) % MOD_ADLER;
        b = (b + a) % MOD_ADLER;
    }
    (b << 16) | a
}

#[cfg(test)]
mod tests {
    use super::*;

    fn auth_aes_stream(digest: AuthAes128Digest) -> AuthAes128Stream {
        let context = Context::new_shared(shadowsocks::config::ServerType::Local);
        let (client, _server) = tokio::io::duplex(16 * 1024);
        let cipher = CryptoStream::from_stream(
            context.as_ref(),
            Box::new(client) as AnyStream,
            StreamType::Client,
            shadowsocks::crypto::CipherKind::NONE,
            &[],
        );
        AuthAes128Stream::new(
            context,
            cipher,
            b"0123456789abcdef".to_vec(),
            b"fixed-iv".to_vec(),
            ConnectionAuth {
                client_id: [1, 2, 3, 4],
                connection_id: 7,
            },
            1234u32.to_le_bytes(),
            digest.digest(b"per-user-password"),
            digest,
            9,
        )
    }

    fn auth_chain_stream(variant: AuthChainVariant) -> AuthChainStream {
        let context = Context::new_shared(shadowsocks::config::ServerType::Local);
        let (client, _server) = tokio::io::duplex(16 * 1024);
        let cipher = CryptoStream::from_stream(
            context.as_ref(),
            Box::new(client) as AnyStream,
            StreamType::Client,
            shadowsocks::crypto::CipherKind::NONE,
            &[],
        );
        AuthChainStream::new(
            context,
            cipher,
            b"0123456789abcdef".to_vec(),
            b"fixed-iv".to_vec(),
            ConnectionAuth {
                client_id: [1, 2, 3, 4],
                connection_id: 7,
            },
            1234u32.to_le_bytes(),
            b"per-user-password".to_vec(),
            variant,
            4,
        )
    }

    #[test]
    fn adler32_matches_standard_vector() {
        assert_eq!(adler32(b"Wikipedia"), 0x11e6_0398);
    }

    #[test]
    fn auth_sha1_v4_data_frames_round_trip() {
        let context = Context::new_shared(shadowsocks::config::ServerType::Local);
        let (client, _server) = tokio::io::duplex(4096);
        let cipher = CryptoStream::from_stream(
            context.as_ref(),
            Box::new(client) as AnyStream,
            StreamType::Client,
            shadowsocks::crypto::CipherKind::NONE,
            &[],
        );
        let mut stream = AuthSha1V4Stream::new(
            context,
            cipher,
            b"0123456789abcdef".to_vec(),
            Vec::new(),
            ConnectionAuth {
                client_id: [1, 2, 3, 4],
                connection_id: 7,
            },
        );
        let payload = b"response payload";
        stream.pack_data(payload);
        stream.read_encoded.extend_from_slice(&stream.write_encoded);
        stream.decode_available().unwrap();
        assert_eq!(stream.read_decoded.as_ref(), payload);
    }

    #[test]
    fn auth_sha1_v4_auth_header_has_valid_crc_and_hmac() {
        let context = Context::new_shared(shadowsocks::config::ServerType::Local);
        let (client, _server) = tokio::io::duplex(4096);
        let cipher = CryptoStream::from_stream(
            context.as_ref(),
            Box::new(client) as AnyStream,
            StreamType::Client,
            shadowsocks::crypto::CipherKind::NONE,
            &[],
        );
        let key = b"0123456789abcdef".to_vec();
        let iv = b"fixed-iv".to_vec();
        let mut stream = AuthSha1V4Stream::new(
            context,
            cipher,
            key.clone(),
            iv.clone(),
            ConnectionAuth {
                client_id: [1, 2, 3, 4],
                connection_id: 7,
            },
        );
        stream.pack_auth_data(b"\x01\x7f\x00\x00\x01\x00\x50");
        let frame = &stream.write_encoded;
        let frame_length =
            u16::from_be_bytes(frame[..2].try_into().unwrap()) as usize;
        assert_eq!(frame_length, frame.len());

        let mut crc_data = frame[..2].to_vec();
        crc_data.extend_from_slice(AUTH_SHA1_V4_SALT);
        crc_data.extend_from_slice(&key);
        assert_eq!(
            u32::from_le_bytes(frame[2..6].try_into().unwrap()),
            crc32fast::hash(&crc_data),
        );
        let mut hmac_key = iv;
        hmac_key.extend_from_slice(&key);
        let tag = hmac_sha1(&hmac_key, &frame[10..frame.len() - 10]);
        assert_eq!(&frame[frame.len() - 10..], &tag[..10]);
    }

    #[test]
    fn auth_aes128_protocol_param_derives_user_credentials() {
        let md5 = AuthAes128Context::new(
            AuthAes128Digest::Md5,
            "1234:per-user-password:ignored",
            9,
        );
        assert_eq!(md5.user_id, 1234u32.to_le_bytes());
        assert_eq!(
            md5.user_key.unwrap(),
            AuthAes128Digest::Md5.digest(b"per-user-password"),
        );

        let sha1 = AuthAes128Context::new(
            AuthAes128Digest::Sha1,
            "4321:per-user-password",
            9,
        );
        assert_eq!(sha1.user_id, 4321u32.to_le_bytes());
        assert_eq!(
            sha1.user_key.unwrap(),
            AuthAes128Digest::Sha1.digest(b"per-user-password"),
        );
    }

    #[test]
    fn auth_aes128_data_frames_round_trip_for_both_digests() {
        for digest in [AuthAes128Digest::Md5, AuthAes128Digest::Sha1] {
            let mut stream = auth_aes_stream(digest);
            let payload = b"response payload";
            stream.pack_data(payload, payload.len());
            stream.read_encoded.extend_from_slice(&stream.write_encoded);
            stream.decode_available().unwrap();
            assert_eq!(stream.read_decoded.as_ref(), payload);
        }
    }

    #[test]
    fn auth_aes128_auth_header_hmacs_and_encrypted_lengths_are_valid() {
        use aes::cipher::{BlockCipherDecrypt, KeyInit};
        use base64::Engine as _;

        for digest in [AuthAes128Digest::Md5, AuthAes128Digest::Sha1] {
            let mut stream = auth_aes_stream(digest);
            let target = b"\x01\x7f\x00\x00\x01\x00\x50";
            stream.pack_auth_data(target);
            let frame = &stream.write_encoded;
            let mut mac_key = stream.iv.clone();
            mac_key.extend_from_slice(&stream.key);
            assert_eq!(&frame[1..7], &digest.hmac(&mac_key, &frame[..1])[..6],);
            assert_eq!(&frame[7..11], &stream.user_id);
            assert_eq!(&frame[27..31], &digest.hmac(&mac_key, &frame[7..27])[..4],);
            assert_eq!(
                &frame[frame.len() - 4..],
                &digest.hmac(&stream.user_key, &frame[..frame.len() - 4])[..4],
            );

            let password = format!(
                "{}{}",
                base64::engine::general_purpose::STANDARD.encode(&stream.user_key),
                digest.salt(),
            );
            let mut key = [0u8; 16];
            openssl_bytes_to_key(password.as_bytes(), &mut key);
            let cipher =
                aes::Aes128::new_from_slice(&key).expect("valid AES-128 key");
            let mut block = aes::cipher::Block::<aes::Aes128>::default();
            block.copy_from_slice(&frame[11..27]);
            cipher.decrypt_block(&mut block);
            assert_eq!(&block[4..8], &[1, 2, 3, 4]);
            assert_eq!(u32::from_le_bytes(block[8..12].try_into().unwrap()), 7);
            assert_eq!(
                u16::from_le_bytes(block[12..14].try_into().unwrap()) as usize,
                frame.len(),
            );
            let random_length =
                u16::from_le_bytes(block[14..16].try_into().unwrap()) as usize;
            assert_eq!(frame.len(), 35 + random_length + target.len());
        }
    }

    #[test]
    fn auth_aes128_udp_request_and_response_macs_match_mihomo_layout() {
        for digest in [AuthAes128Digest::Md5, AuthAes128Digest::Sha1] {
            let protocol_key = b"0123456789abcdef".to_vec();
            let user_key = digest.digest(b"per-user-password");
            let protocol = SsrUdpProtocol::AuthAes128 {
                digest,
                protocol_key: protocol_key.clone(),
                user_id: 1234u32.to_le_bytes(),
                user_key: user_key.clone(),
            };

            let mut request = BytesMut::from(&b"address-and-payload"[..]);
            protocol.encode(&mut request);
            assert_eq!(&request[19..23], &1234u32.to_le_bytes());
            assert_eq!(&request[23..], &digest.hmac(&user_key, &request[..23])[..4],);

            let mut response = b"address-and-response".to_vec();
            let tag = digest.hmac(&protocol_key, &response);
            response.extend_from_slice(&tag[..4]);
            assert_eq!(
                protocol.decode(&mut response).unwrap(),
                b"address-and-response",
            );
            let last = response.len() - 1;
            response[last] ^= 1;
            assert!(protocol.decode(&mut response).is_err());
        }
    }

    #[test]
    fn rc4_matches_rfc_6229_compatible_vector() {
        let mut plaintext = b"Plaintext".to_vec();
        Rc4Cipher::new(b"Key").apply(&mut plaintext);
        assert_eq!(
            plaintext,
            [0xbb, 0xf3, 0x16, 0xe8, 0xd9, 0x40, 0xaf, 0x0a, 0xd3],
        );
        Rc4Cipher::new(b"Key").apply(&mut plaintext);
        assert_eq!(plaintext, b"Plaintext");
    }

    #[test]
    fn xorshift128plus_matches_fixed_seed_vector() {
        let seed = [
            0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b,
            0x0c, 0x0d, 0x0e, 0x0f,
        ];
        let mut random = XorShift128Plus::from_bin(&seed);
        assert_eq!(random.next(), 0x9917_d894_9493_1393);
        assert_eq!(random.next(), 0x8d0b_d2af_ca7e_b0af);
        assert_eq!(random.next(), 0x5051_3634_0cf1_299f);
    }

    #[test]
    fn auth_chain_auth_and_data_frames_match_mihomo_layout() {
        use aes::cipher::{BlockCipherDecrypt, KeyInit};
        use base64::Engine as _;

        for variant in [AuthChainVariant::A, AuthChainVariant::B] {
            let mut stream = auth_chain_stream(variant);
            let target = b"\x01\x7f\x00\x00\x01\x00\x50";
            stream.pack_auth_data(target);
            let frame = &stream.write_encoded;

            let mut mac_key = stream.iv.clone();
            mac_key.extend_from_slice(&stream.protocol_key);
            let initial_hash = hmac_md5(&mac_key, &frame[..4]);
            assert_eq!(&frame[4..12], &initial_hash[..8]);
            assert_eq!(
                u32::from_le_bytes(frame[12..16].try_into().unwrap()),
                u32::from_le_bytes(stream.user_id)
                    ^ u32::from_le_bytes(initial_hash[8..12].try_into().unwrap()),
            );
            assert_eq!(
                &frame[32..36],
                &hmac_md5(&stream.user_key, &frame[12..32])[..4]
            );

            let password = format!(
                "{}{}",
                base64::engine::general_purpose::STANDARD.encode(&stream.user_key),
                variant.salt(),
            );
            let mut auth_key = [0u8; 16];
            openssl_bytes_to_key(password.as_bytes(), &mut auth_key);
            let cipher =
                aes::Aes128::new_from_slice(&auth_key).expect("valid AES-128 key");
            let mut block = aes::cipher::Block::<aes::Aes128>::default();
            block.copy_from_slice(&frame[16..32]);
            cipher.decrypt_block(&mut block);
            assert_eq!(&block[4..8], &[1, 2, 3, 4]);
            assert_eq!(u32::from_le_bytes(block[8..12].try_into().unwrap()), 7);
            assert_eq!(u16::from_le_bytes(block[12..14].try_into().unwrap()), 4);
            assert_eq!(u16::from_le_bytes(block[14..16].try_into().unwrap()), 0);

            let data_frame = &frame[36..];
            let encoded_length =
                u16::from_le_bytes(data_frame[..2].try_into().unwrap());
            assert_eq!(
                encoded_length
                    ^ u16::from_le_bytes(initial_hash[14..16].try_into().unwrap()),
                target.len() as u16,
            );
            let mut random =
                XorShift128Plus::from_bin_and_length(&initial_hash, target.len());
            let random_length = auth_chain_padding_length(
                variant,
                target.len(),
                stream.overhead,
                &stream.data_sizes,
                &stream.data_sizes2,
                &mut random,
            );
            let data_start = 2 + auth_chain_random_start(random_length, &mut random);
            let mut decrypted =
                data_frame[data_start..data_start + target.len()].to_vec();
            Rc4Cipher::new(&auth_chain_rc4_key(&stream.user_key, &initial_hash))
                .apply(&mut decrypted);
            assert_eq!(decrypted, target);
            let mut data_mac_key = stream.user_key.clone();
            data_mac_key.extend_from_slice(&1u32.to_le_bytes());
            assert_eq!(
                &data_frame[data_frame.len() - 2..],
                &hmac_md5(&data_mac_key, &data_frame[..data_frame.len() - 2],)[..2],
            );
        }
    }

    #[test]
    fn auth_chain_decodes_server_frames_for_both_padding_variants() {
        for variant in [AuthChainVariant::A, AuthChainVariant::B] {
            let mut stream = auth_chain_stream(variant);
            stream.pack_auth_data(b"client request");
            let response = b"server response";
            let mut server_plaintext = b"\x00\x00".to_vec();
            server_plaintext.extend_from_slice(response);
            let mut encrypted = server_plaintext.clone();
            let mut initial_mac_key = stream.iv.clone();
            initial_mac_key.extend_from_slice(&stream.protocol_key);
            let initial_client_hash =
                hmac_md5(&initial_mac_key, &stream.write_encoded[..4]);
            Rc4Cipher::new(&auth_chain_rc4_key(
                &stream.user_key,
                &initial_client_hash,
            ))
            .apply(&mut encrypted);

            let last_server_hash = stream.last_server_hash;
            let mut random = XorShift128Plus::from_bin_and_length(
                &last_server_hash,
                encrypted.len(),
            );
            let random_length = auth_chain_padding_length(
                variant,
                encrypted.len(),
                stream.overhead,
                &stream.data_sizes,
                &stream.data_sizes2,
                &mut random,
            );
            let mut frame = BytesMut::new();
            frame.put_u16_le(
                encrypted.len() as u16
                    ^ u16::from_le_bytes(
                        last_server_hash[14..16].try_into().unwrap(),
                    ),
            );
            put_auth_chain_mixed_data(
                &mut frame,
                &encrypted,
                random_length,
                &mut random,
            );
            let mut mac_key = stream.user_key.clone();
            mac_key.extend_from_slice(&1u32.to_le_bytes());
            let tag = hmac_md5(&mac_key, &frame);
            frame.put_slice(&tag[..2]);

            stream.read_encoded = frame;
            stream.decode_available().unwrap();
            assert_eq!(stream.read_decoded.as_ref(), response);
        }
    }

    #[test]
    fn auth_chain_udp_request_and_response_match_mihomo_layout() {
        let protocol_key = b"0123456789abcdef".to_vec();
        let user_id = 1234u32.to_le_bytes();
        let user_key = b"per-user-password".to_vec();
        let protocol = SsrUdpProtocol::AuthChain {
            protocol_key: protocol_key.clone(),
            user_id,
            user_key: user_key.clone(),
        };
        let plaintext = b"address-and-payload";
        let mut request = BytesMut::from(&plaintext[..]);
        protocol.encode(&mut request);
        let tag_position = request.len() - 1;
        assert_eq!(
            request[tag_position],
            hmac_md5(&user_key, &request[..tag_position])[0]
        );
        let trailer_start = request.len() - 8;
        let auth_data = &request[trailer_start..trailer_start + 3];
        let request_hash = hmac_md5(&protocol_key, auth_data);
        let mut random = XorShift128Plus::from_bin(&request_hash);
        let random_length = (random.next() % 127) as usize;
        assert_eq!(request.len(), plaintext.len() + random_length + 8);
        assert_eq!(
            u32::from_le_bytes(
                request[trailer_start + 3..trailer_start + 7]
                    .try_into()
                    .unwrap(),
            ),
            u32::from_le_bytes(user_id)
                ^ u32::from_le_bytes(request_hash[..4].try_into().unwrap()),
        );
        let mut decoded_request = request[..plaintext.len()].to_vec();
        Rc4Cipher::new(&auth_chain_rc4_key(&user_key, &request_hash))
            .apply(&mut decoded_request);
        assert_eq!(decoded_request, plaintext);

        let response_plaintext = b"address-and-response";
        let response_trailer = b"trailer";
        let response_hash = hmac_md5(&protocol_key, response_trailer);
        let mut random = XorShift128Plus::from_bin(&response_hash);
        let response_padding = (random.next() % 127) as usize;
        let mut response = response_plaintext.to_vec();
        Rc4Cipher::new(&auth_chain_rc4_key(&user_key, &response_hash))
            .apply(&mut response);
        response.resize(response.len() + response_padding, 0);
        response.extend_from_slice(response_trailer);
        let response_tag = hmac_md5(&user_key, &response)[0];
        response.push(response_tag);
        assert_eq!(protocol.decode(&mut response).unwrap(), response_plaintext);
    }
}
