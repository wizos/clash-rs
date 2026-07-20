use std::{fmt::Debug, pin::Pin, task::Poll, time::SystemTime};

use aes::cipher::KeyIvInit as _;
use aes_gcm::Aes128Gcm;
use bytes::{Buf, BufMut, BytesMut};
use chacha20poly1305::ChaCha20Poly1305;
use futures::ready;

use md5::Md5;
use sha3::{
    Shake128, Shake128Reader,
    digest::{ExtendableOutput, XofReader},
};
use tokio::io::{AsyncRead, AsyncWrite, AsyncWriteExt};

use crate::{
    common::{
        crypto::{self, AeadCipherHelper},
        errors::map_io_error,
        utils,
    },
    proxy::vmess::vmess_impl::MAX_CHUNK_SIZE,
    session::SocksAddr,
};

use super::{
    CHUNK_SIZE, COMMAND_MUX, COMMAND_TCP, COMMAND_UDP, OPTION_AUTHENTICATED_LENGTH,
    OPTION_CHUNK_MASKING, OPTION_CHUNK_STREAM, OPTION_GLOBAL_PADDING,
    SECURITY_AES_128_CFB, SECURITY_AES_128_GCM, SECURITY_CHACHA20_POLY1305,
    SECURITY_NONE, Security, VERSION,
    cipher::{AeadCipher, VmessSecurity},
    header,
    kdf::{
        self, KDF_SALT_CONST_AEAD_RESP_HEADER_LEN_IV,
        KDF_SALT_CONST_AEAD_RESP_HEADER_LEN_KEY,
        KDF_SALT_CONST_AEAD_RESP_HEADER_PAYLOAD_IV,
        KDF_SALT_CONST_AEAD_RESP_HEADER_PAYLOAD_KEY,
    },
    user::ID,
};

pub struct VmessStream<S> {
    stream: S,
    aead_read_cipher: Option<AeadCipher>,
    aead_write_cipher: Option<AeadCipher>,
    dst: SocksAddr,
    id: ID,
    req_body_iv: Vec<u8>,
    req_body_key: Vec<u8>,
    resp_body_iv: Vec<u8>,
    resp_body_key: Vec<u8>,
    resp_v: u8,
    security: u8,
    is_aead: bool,
    is_udp: bool,
    is_xudp: bool,
    options: u8,
    chunk_stream: bool,
    chunk_masking: bool,
    global_padding: bool,
    authenticated_length: bool,
    read_length_cipher: Option<AeadCipher>,
    write_length_cipher: Option<AeadCipher>,
    read_length_generator: Option<Shake128Reader>,
    write_length_generator: Option<Shake128Reader>,
    legacy_read_cipher: Option<cfb_mode::BufDecryptor<aes::Aes128>>,
    legacy_write_cipher: Option<cfb_mode::BufEncryptor<aes::Aes128>>,

    read_state: ReadState,
    read_pos: usize,
    read_buf: BytesMut,

    write_state: WriteState,
    write_buf: BytesMut,
}

impl<S> Debug for VmessStream<S> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("VmessStream")
            .field("dst", &self.dst)
            .field("is_aead", &self.is_aead)
            .field("is_udp", &self.is_udp)
            .finish()
    }
}

enum ReadState {
    AeadWaitingHeaderSize,
    AeadWaitingHeader(usize),
    StreamWaitingLength,
    StreamWaitingData { wire_size: usize, data_size: usize },
    StreamFlushingData(usize),
    Raw,
    Eof,
}

enum WriteState {
    BuildingData,
    FlushingData(usize, (usize, usize)),
}

use crate::common::io::{ReadExactBase, ReadExt};

impl<S: AsyncRead + Unpin> ReadExactBase for VmessStream<S> {
    type I = S;

    fn decompose(&mut self) -> (&mut Self::I, &mut BytesMut, &mut usize) {
        (&mut self.stream, &mut self.read_buf, &mut self.read_pos)
    }
}

impl<S> VmessStream<S>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    pub(crate) async fn new(
        stream: S,
        id: &ID,
        dst: &SocksAddr,
        security: &Security,
        is_aead: bool,
        is_udp: bool,
        is_xudp: bool,
        global_padding: bool,
        authenticated_length: bool,
    ) -> std::io::Result<VmessStream<S>> {
        let mut rand_bytes = [0u8; 33];
        utils::rand_fill(&mut rand_bytes[..]);
        let req_body_iv = rand_bytes[0..16].to_vec();
        let req_body_key = rand_bytes[16..32].to_vec();
        let resp_v = rand_bytes[32];

        let (resp_body_key, resp_body_iv) = if is_aead {
            (
                utils::sha256(req_body_key.as_slice())[0..16].to_vec(),
                utils::sha256(req_body_iv.as_slice())[0..16].to_vec(),
            )
        } else {
            (
                utils::md5(req_body_key.as_slice()),
                utils::md5(req_body_iv.as_slice()),
            )
        };

        let (aead_read_cipher, aead_write_cipher) = match *security {
            SECURITY_NONE => (None, None),
            SECURITY_AES_128_GCM => {
                let write_cipher = VmessSecurity::Aes128Gcm(
                    Aes128Gcm::new_with_slice(&req_body_key),
                );
                let write_cipher = AeadCipher::new(&req_body_iv, write_cipher);
                let reader_cipher = VmessSecurity::Aes128Gcm(
                    Aes128Gcm::new_with_slice(&resp_body_key),
                );
                let read_cipher = AeadCipher::new(&resp_body_iv, reader_cipher);
                (Some(read_cipher), Some(write_cipher))
            }
            SECURITY_CHACHA20_POLY1305 => {
                let mut key = [0u8; 32];
                key[..16].copy_from_slice(&utils::md5(&req_body_key));
                let tmp = utils::md5(&key[..16]);
                key[16..].copy_from_slice(&tmp);

                let write_cipher = VmessSecurity::ChaCha20Poly1305(
                    ChaCha20Poly1305::new_with_slice(&key),
                );
                let write_cipher = AeadCipher::new(&req_body_iv, write_cipher);

                let mut key = [0u8; 32];
                key[..16].copy_from_slice(&utils::md5(&resp_body_key));
                let tmp = utils::md5(&key[..16]);
                key[16..].copy_from_slice(&tmp);

                let reader_cipher = VmessSecurity::ChaCha20Poly1305(
                    ChaCha20Poly1305::new_with_slice(&key),
                );
                let read_cipher = AeadCipher::new(&resp_body_iv, reader_cipher);

                (Some(read_cipher), Some(write_cipher))
            }
            SECURITY_AES_128_CFB => (None, None),
            _ => {
                return Err(std::io::Error::other("unsupported security"));
            }
        };

        let encrypted_body =
            matches!(*security, SECURITY_AES_128_GCM | SECURITY_CHACHA20_POLY1305);
        let legacy_body = *security == SECURITY_AES_128_CFB;
        let chunk_stream = encrypted_body
            || legacy_body
            || (*security == SECURITY_NONE && is_udp && !is_xudp);
        let chunk_masking = encrypted_body;
        let global_padding = encrypted_body && global_padding;
        let authenticated_length = encrypted_body && authenticated_length;
        let mut options = if chunk_stream { OPTION_CHUNK_STREAM } else { 0 };
        if chunk_masking {
            options |= OPTION_CHUNK_MASKING;
        }
        if global_padding {
            options |= OPTION_GLOBAL_PADDING;
        }
        if authenticated_length {
            options |= OPTION_AUTHENTICATED_LENGTH;
        }

        let (read_length_cipher, write_length_cipher) = if authenticated_length {
            (
                Some(new_authenticated_length_cipher(
                    *security,
                    &req_body_key,
                    &req_body_iv,
                )?),
                Some(new_authenticated_length_cipher(
                    *security,
                    &req_body_key,
                    &req_body_iv,
                )?),
            )
        } else {
            (None, None)
        };
        let read_length_generator = (global_padding || chunk_masking)
            .then(|| new_length_generator(&resp_body_iv));
        let write_length_generator = (global_padding || chunk_masking)
            .then(|| new_length_generator(&req_body_iv));
        let legacy_read_cipher = legacy_body
            .then(|| {
                cfb_mode::BufDecryptor::<aes::Aes128>::new_from_slices(
                    &resp_body_key,
                    &resp_body_iv,
                )
            })
            .transpose()
            .map_err(|error| std::io::Error::other(error.to_string()))?;
        let legacy_write_cipher = legacy_body
            .then(|| {
                cfb_mode::BufEncryptor::<aes::Aes128>::new_from_slices(
                    &req_body_key,
                    &req_body_iv,
                )
            })
            .transpose()
            .map_err(|error| std::io::Error::other(error.to_string()))?;

        let mut stream = Self {
            stream,
            aead_read_cipher,
            aead_write_cipher,
            dst: dst.to_owned(),
            id: id.to_owned(),
            req_body_iv,
            req_body_key,
            resp_body_iv,
            resp_body_key,
            resp_v,
            security: *security,
            is_aead,
            is_udp,
            is_xudp,
            options,
            chunk_stream,
            chunk_masking,
            global_padding,
            authenticated_length,
            read_length_cipher,
            write_length_cipher,
            read_length_generator,
            write_length_generator,
            legacy_read_cipher,
            legacy_write_cipher,

            read_state: ReadState::AeadWaitingHeaderSize,
            read_pos: 0,
            read_buf: BytesMut::new(),

            write_state: WriteState::BuildingData,
            write_buf: BytesMut::new(),
        };

        stream.send_handshake_request().await?;

        Ok(stream)
    }
}

impl<S> VmessStream<S>
where
    S: AsyncWrite + Unpin,
{
    async fn send_handshake_request(&mut self) -> std::io::Result<()> {
        use hmac::{Hmac, Mac};
        type HmacMd5 = Hmac<Md5>;
        let &mut Self {
            ref mut stream,
            ref req_body_key,
            ref req_body_iv,
            ref resp_v,
            ref security,
            ref dst,
            ref is_aead,
            ref is_udp,
            ref is_xudp,
            ref options,
            ref id,
            ..
        } = self;

        let now = SystemTime::now()
            .duration_since(SystemTime::UNIX_EPOCH)
            .expect("check your system clock")
            .as_secs();

        let mut mbuf = BytesMut::new();

        if !is_aead {
            use hmac::KeyInit;
            let mut mac = HmacMd5::new_from_slice(id.uuid.as_bytes())
                .expect("key len expected to be 16");
            mac.update(now.to_be_bytes().as_slice());
            mbuf.put_slice(&mac.finalize().into_bytes());
        }

        let mut buf = BytesMut::new();
        buf.put_u8(VERSION);
        buf.put_slice(req_body_iv);
        buf.put_slice(req_body_key);
        buf.put_u8(*resp_v);
        buf.put_u8(*options);

        let p = utils::rand_range(0..16);
        buf.put_u8((p << 4) as u8 | security);

        buf.put_u8(0);

        if *is_xudp {
            buf.put_u8(COMMAND_MUX);
        } else if *is_udp {
            buf.put_u8(COMMAND_UDP);
        } else {
            buf.put_u8(COMMAND_TCP);
        }

        if !*is_xudp {
            dst.write_to_buf_vmess(&mut buf);
        }

        if p > 0 {
            let mut padding = vec![0u8; p as usize];
            utils::rand_fill(&mut padding[..]);
            buf.put_slice(&padding);
        }

        let sum = const_fnv1a_hash::fnv1a_hash_32(&buf, None);
        buf.put_slice(&sum.to_be_bytes());

        if !is_aead {
            let mut data = buf.to_vec();
            crypto::aes_cfb_encrypt(
                &id.cmd_key[..],
                &hash_timestamp(now)[..],
                &mut data,
            )
            .map_err(map_io_error)?;

            mbuf.put_slice(data.as_slice());
            let out = mbuf.freeze();
            stream.write_all(&out).await?;
        } else {
            let out = header::seal_vmess_aead_header(
                id.cmd_key,
                buf.freeze().to_vec(),
                now,
            )
            .map_err(map_io_error)?;
            stream.write_all(&out).await?;
        }

        stream.flush().await?;

        Ok(())
    }
}

impl<S> AsyncRead for VmessStream<S>
where
    S: AsyncRead + Unpin + Send,
{
    fn poll_read(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        buf: &mut tokio::io::ReadBuf<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        loop {
            match self.read_state {
                ReadState::AeadWaitingHeaderSize => {
                    let this = &mut *self;
                    let resp_body_key = this.resp_body_key.clone();
                    let resp_body_iv = this.resp_body_iv.clone();
                    let resp_v = this.resp_v;

                    if !this.is_aead {
                        ready!(this.poll_read_exact(cx, 4))?;
                        let mut buf = this.read_buf.split().freeze().to_vec();
                        if let Some(cipher) = this.legacy_read_cipher.as_mut() {
                            cipher.decrypt(&mut buf);
                        } else {
                            crypto::aes_cfb_decrypt(
                                &resp_body_key,
                                &resp_body_iv,
                                &mut buf,
                            )
                            .map_err(map_io_error)?;
                        }
                        if buf[0] != resp_v {
                            return Poll::Ready(Err(std::io::Error::new(
                                std::io::ErrorKind::InvalidData,
                                "invalid response - non aead invalid resp_v",
                            )));
                        }

                        if buf[2] != 0 {
                            return Poll::Ready(Err(std::io::Error::new(
                                std::io::ErrorKind::InvalidData,
                                "invalid response - dynamic port not supported",
                            )));
                        }

                        this.read_state = if this.chunk_stream {
                            ReadState::StreamWaitingLength
                        } else {
                            ReadState::Raw
                        };
                    } else {
                        ready!(this.poll_read_exact(cx, 18))?;

                        let aead_response_header_length_encryption_key =
                            &kdf::vmess_kdf_1_one_shot(
                                &resp_body_key,
                                KDF_SALT_CONST_AEAD_RESP_HEADER_LEN_KEY,
                            )[..16];
                        let aead_response_header_length_encryption_iv =
                            &kdf::vmess_kdf_1_one_shot(
                                &resp_body_iv,
                                KDF_SALT_CONST_AEAD_RESP_HEADER_LEN_IV,
                            )[..12];

                        let decrypted_response_header_len = crypto::aes_gcm_decrypt(
                            aead_response_header_length_encryption_key,
                            aead_response_header_length_encryption_iv,
                            this.read_buf.split().as_ref(),
                            None,
                        )
                        .map_err(map_io_error)?;

                        if decrypted_response_header_len.len() < 2 {
                            return Err(std::io::Error::new(
                                std::io::ErrorKind::InvalidData,
                                "invalid response header length",
                            ))
                            .into();
                        }

                        this.read_state = ReadState::AeadWaitingHeader(
                            u16::from_be_bytes(
                                decrypted_response_header_len[..2]
                                    .try_into()
                                    .unwrap(),
                            ) as usize,
                        );
                    }
                }

                ReadState::AeadWaitingHeader(header_size) => {
                    let this = &mut *self;
                    ready!(this.poll_read_exact(cx, header_size + 16))?;

                    let resp_body_key = this.resp_body_key.clone();
                    let resp_body_iv = this.resp_body_iv.clone();

                    let aead_response_header_payload_encryption_key =
                        &kdf::vmess_kdf_1_one_shot(
                            &resp_body_key,
                            KDF_SALT_CONST_AEAD_RESP_HEADER_PAYLOAD_KEY,
                        )[..16];
                    let aead_response_header_payload_encryption_iv =
                        &kdf::vmess_kdf_1_one_shot(
                            &resp_body_iv,
                            KDF_SALT_CONST_AEAD_RESP_HEADER_PAYLOAD_IV,
                        )[..12];

                    let buf = crypto::aes_gcm_decrypt(
                        aead_response_header_payload_encryption_key,
                        aead_response_header_payload_encryption_iv,
                        this.read_buf.split().as_ref(),
                        None,
                    )
                    .map_err(map_io_error)?;

                    if buf.len() < 4 {
                        return Poll::Ready(Err(std::io::Error::new(
                            std::io::ErrorKind::InvalidData,
                            "invalid response - header too short",
                        )));
                    }

                    if buf[0] != this.resp_v {
                        return Poll::Ready(Err(std::io::Error::new(
                            std::io::ErrorKind::InvalidData,
                            "invalid response - version mismatch",
                        )));
                    }

                    if buf[2] != 0 {
                        return Poll::Ready(Err(std::io::Error::new(
                            std::io::ErrorKind::InvalidData,
                            "invalid response - dynamic port not supported",
                        )));
                    }

                    this.read_state = if this.chunk_stream {
                        ReadState::StreamWaitingLength
                    } else {
                        ReadState::Raw
                    };
                }

                ReadState::StreamWaitingLength => {
                    let this = &mut *self;
                    let length_header_size =
                        if this.authenticated_length { 2 + 16 } else { 2 };
                    ready!(this.poll_read_exact(cx, length_header_size))?;
                    let mut length_header = this.read_buf.split().freeze().to_vec();
                    if let Some(cipher) = this.legacy_read_cipher.as_mut() {
                        cipher.decrypt(&mut length_header);
                    } else if let Some(cipher) = this.read_length_cipher.as_mut() {
                        cipher.decrypt_inplace(&mut length_header)?;
                    }
                    let mut length =
                        u16::from_be_bytes([length_header[0], length_header[1]]);
                    let padding_length = if this.global_padding {
                        next_length_value(&mut this.read_length_generator)? % 64
                    } else {
                        0
                    } as usize;
                    if this.chunk_masking && !this.authenticated_length {
                        length ^=
                            next_length_value(&mut this.read_length_generator)?;
                    }

                    let body_overhead = this
                        .aead_read_cipher
                        .as_ref()
                        .map(|cipher| cipher.security.overhead_len())
                        .unwrap_or_default();
                    let encoded_length = length as usize;
                    let data_size = if this.authenticated_length {
                        encoded_length
                            .checked_add(body_overhead)
                            .and_then(|length| length.checked_sub(padding_length))
                    } else {
                        encoded_length.checked_sub(padding_length)
                    }
                    .ok_or_else(|| {
                        std::io::Error::new(
                            std::io::ErrorKind::InvalidData,
                            "VMess chunk padding exceeds encoded length",
                        )
                    })?;
                    if data_size == 0 {
                        this.read_state = ReadState::Eof;
                        return Poll::Ready(Ok(()));
                    }
                    let wire_size = data_size + padding_length;
                    if data_size > MAX_CHUNK_SIZE {
                        return Poll::Ready(Err(std::io::Error::new(
                            std::io::ErrorKind::InvalidData,
                            "invalid response - chunk size too large",
                        )));
                    }

                    this.read_state = ReadState::StreamWaitingData {
                        wire_size,
                        data_size,
                    };
                }

                ReadState::StreamWaitingData {
                    wire_size,
                    data_size,
                } => {
                    let this = &mut *self;
                    ready!(this.poll_read_exact(cx, wire_size))?;
                    this.read_buf.truncate(data_size);

                    if let Some(cipher) = this.legacy_read_cipher.as_mut() {
                        cipher.decrypt(&mut this.read_buf);
                        if this.read_buf.len() < 4 {
                            return Poll::Ready(Err(std::io::Error::new(
                                std::io::ErrorKind::InvalidData,
                                "VMess legacy chunk is missing its checksum",
                            )));
                        }
                        let expected = u32::from_be_bytes(
                            this.read_buf[..4].try_into().unwrap(),
                        );
                        let actual = fnv1a32(&this.read_buf[4..]);
                        if expected != actual {
                            return Poll::Ready(Err(std::io::Error::new(
                                std::io::ErrorKind::InvalidData,
                                "VMess legacy chunk checksum mismatch",
                            )));
                        }
                        this.read_buf.advance(4);
                        this.read_state =
                            ReadState::StreamFlushingData(data_size - 4);
                    } else {
                        match this.aead_read_cipher {
                            Some(ref mut cipher) => {
                                cipher.decrypt_inplace(&mut this.read_buf)?;
                                let data_len =
                                    data_size - cipher.security.overhead_len();
                                this.read_buf.truncate(data_len);
                                this.read_state =
                                    ReadState::StreamFlushingData(data_len);
                            }
                            _ => {
                                this.read_state =
                                    ReadState::StreamFlushingData(data_size);
                            }
                        }
                    }
                }

                ReadState::StreamFlushingData(size) => {
                    let to_read = std::cmp::min(buf.remaining(), size);
                    let payload = self.read_buf.split_to(to_read);
                    buf.put_slice(&payload);
                    if to_read < size {
                        // there're unread data, continues in next poll
                        self.read_state =
                            ReadState::StreamFlushingData(size - to_read);
                    } else {
                        // all data consumed, ready to read next chunk
                        self.read_state = ReadState::StreamWaitingLength;
                    }

                    return Poll::Ready(Ok(()));
                }
                ReadState::Raw => {
                    return Pin::new(&mut self.stream).poll_read(cx, buf);
                }
                ReadState::Eof => return Poll::Ready(Ok(())),
            }
        }
    }
}

impl<S> AsyncWrite for VmessStream<S>
where
    S: AsyncWrite + Unpin + Send,
{
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        buf: &[u8],
    ) -> Poll<Result<usize, std::io::Error>> {
        if buf.is_empty() {
            return Poll::Ready(Ok(0));
        }
        if !self.chunk_stream {
            return Pin::new(&mut self.stream).poll_write(cx, buf);
        }
        loop {
            match self.write_state {
                WriteState::BuildingData => {
                    let this = &mut *self;
                    if let Some(cipher) = this.legacy_write_cipher.as_mut() {
                        let consume_len = std::cmp::min(buf.len(), CHUNK_SIZE - 4);
                        this.write_buf.clear();
                        this.write_buf.put_u16((consume_len + 4) as u16);
                        this.write_buf.put_u32(fnv1a32(&buf[..consume_len]));
                        this.write_buf.extend_from_slice(&buf[..consume_len]);
                        cipher.encrypt(&mut this.write_buf);
                        self.write_state = WriteState::FlushingData(
                            consume_len,
                            (this.write_buf.len(), 0),
                        );
                        continue;
                    }
                    let overhead_len = this
                        .aead_write_cipher
                        .as_ref()
                        .map(|cipher| cipher.security.overhead_len())
                        .unwrap_or_default();

                    let max_payload_size = CHUNK_SIZE - overhead_len;
                    let consume_len = std::cmp::min(buf.len(), max_payload_size);
                    let mut body =
                        BytesMut::with_capacity(consume_len + overhead_len);
                    body.put_slice(&buf[..consume_len]);
                    if let Some(ref mut cipher) = this.aead_write_cipher {
                        body.extend_from_slice(
                            vec![0u8; cipher.security.overhead_len()].as_ref(),
                        );
                        cipher.encrypt_inplace(&mut body)?;
                    }

                    let padding_length = if this.global_padding {
                        next_length_value(&mut this.write_length_generator)? % 64
                    } else {
                        0
                    } as usize;
                    this.write_buf.clear();
                    if this.authenticated_length {
                        let encoded_length = body
                            .len()
                            .checked_add(padding_length)
                            .and_then(|length| length.checked_sub(overhead_len))
                            .ok_or_else(|| {
                                std::io::Error::new(
                                    std::io::ErrorKind::InvalidData,
                                    "invalid VMess authenticated chunk length",
                                )
                            })?;
                        let mut length_header = BytesMut::with_capacity(18);
                        length_header.put_u16(encoded_length as u16);
                        length_header.resize(18, 0);
                        this.write_length_cipher
                            .as_mut()
                            .expect("authenticated length cipher must exist")
                            .encrypt_inplace(&mut length_header)?;
                        this.write_buf.extend_from_slice(&length_header);
                    } else {
                        let mut encoded_length =
                            (body.len() + padding_length) as u16;
                        if this.chunk_masking {
                            encoded_length ^=
                                next_length_value(&mut this.write_length_generator)?;
                        }
                        this.write_buf.put_u16(encoded_length);
                    }
                    this.write_buf.extend_from_slice(&body);
                    if padding_length > 0 {
                        let start = this.write_buf.len();
                        this.write_buf.resize(start + padding_length, 0);
                        utils::rand_fill(&mut this.write_buf[start..]);
                    }

                    // ready to write data
                    self.write_state = WriteState::FlushingData(
                        consume_len,
                        (this.write_buf.len(), 0),
                    );
                }

                // consumed is the consumed plaintext length we're going to
                // return to caller. total is total length of
                // the ciphertext data chunk we're going to write to remote.
                // written is the number of ciphertext bytes were written.
                WriteState::FlushingData(consumed, (total, written)) => {
                    let this = &mut *self;

                    // There would be trouble if the caller change the buf upon
                    // pending, but I believe that's not a
                    // usual use case.
                    let nw = ready!(tokio_util::io::poll_write_buf(
                        Pin::new(&mut this.stream),
                        cx,
                        &mut this.write_buf
                    ))?;
                    if nw == 0 {
                        return Err(std::io::Error::new(
                            std::io::ErrorKind::WriteZero,
                            "failed to write whole data",
                        ))
                        .into();
                    }

                    if written + nw >= total {
                        // data chunk written, go to next chunk
                        this.write_state = WriteState::BuildingData;
                        return Poll::Ready(Ok(consumed));
                    }

                    this.write_state =
                        WriteState::FlushingData(consumed, (total, written + nw));
                }
            }
        }
    }

    fn poll_flush(
        self: Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> Poll<Result<(), std::io::Error>> {
        let Self { stream, .. } = self.get_mut();
        Pin::new(stream).poll_flush(cx)
    }

    fn poll_shutdown(
        self: Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> Poll<Result<(), std::io::Error>> {
        let Self { stream, .. } = self.get_mut();
        Pin::new(stream).poll_shutdown(cx)
    }
}

fn new_authenticated_length_cipher(
    security: Security,
    request_key: &[u8],
    request_iv: &[u8],
) -> std::io::Result<AeadCipher> {
    let derived = kdf::vmess_kdf_1_one_shot(request_key, b"auth_len");
    let cipher = match security {
        SECURITY_AES_128_GCM => {
            VmessSecurity::Aes128Gcm(Aes128Gcm::new_with_slice(&derived[..16]))
        }
        SECURITY_CHACHA20_POLY1305 => {
            let mut key = [0u8; 32];
            key[..16].copy_from_slice(&derived[..16]);
            key[16..].copy_from_slice(&utils::md5(&derived[..16]));
            VmessSecurity::ChaCha20Poly1305(ChaCha20Poly1305::new_with_slice(&key))
        }
        _ => {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                "authenticated VMess length requires an AEAD cipher",
            ));
        }
    };
    Ok(AeadCipher::new(request_iv, cipher))
}

fn new_length_generator(iv: &[u8]) -> Shake128Reader {
    let mut shake = Shake128::default();
    sha3::digest::Update::update(&mut shake, iv);
    shake.finalize_xof()
}

fn next_length_value(
    generator: &mut Option<Shake128Reader>,
) -> std::io::Result<u16> {
    let generator = generator.as_mut().ok_or_else(|| {
        std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            "VMess length generator is not initialized",
        )
    })?;
    let mut value = [0; 2];
    generator.read(&mut value);
    Ok(u16::from_be_bytes(value))
}

fn fnv1a32(data: &[u8]) -> u32 {
    let mut hash = 0x811c9dc5u32;
    for byte in data {
        hash ^= *byte as u32;
        hash = hash.wrapping_mul(0x01000193);
    }
    hash
}

fn hash_timestamp(timestamp: u64) -> [u8; 16] {
    use md5::Digest;
    let mut hasher = md5::Md5::new();
    // TODO Why four times?
    hasher.update(timestamp.to_be_bytes());
    hasher.update(timestamp.to_be_bytes());
    hasher.update(timestamp.to_be_bytes());
    hasher.update(timestamp.to_be_bytes());
    hasher.finalize().into()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::proxy::vmess::vmess_impl::user::new_id;

    async fn test_stream(
        security: Security,
        udp: bool,
        xudp: bool,
        global_padding: bool,
        authenticated_length: bool,
    ) -> VmessStream<tokio::io::DuplexStream> {
        let (client, _server) = tokio::io::duplex(4096);
        let uuid =
            uuid::Uuid::parse_str("b831381d-6324-4d53-ad4f-8cda48b30811").unwrap();
        VmessStream::new(
            client,
            &new_id(&uuid),
            &SocksAddr::Domain("example.org".to_owned(), 443),
            &security,
            true,
            udp,
            xudp,
            global_padding,
            authenticated_length,
        )
        .await
        .unwrap()
    }

    #[tokio::test]
    async fn mihomo_aead_options_enable_masking_and_requested_extensions() {
        let standard =
            test_stream(SECURITY_AES_128_GCM, false, false, false, false).await;
        assert!(standard.chunk_stream);
        assert!(standard.chunk_masking);
        assert_eq!(standard.options, OPTION_CHUNK_STREAM | OPTION_CHUNK_MASKING);

        let extended =
            test_stream(SECURITY_AES_128_GCM, false, false, true, true).await;
        assert!(extended.global_padding);
        assert!(extended.authenticated_length);
        assert_eq!(
            extended.options,
            OPTION_CHUNK_STREAM
                | OPTION_CHUNK_MASKING
                | OPTION_GLOBAL_PADDING
                | OPTION_AUTHENTICATED_LENGTH
        );
    }

    #[tokio::test]
    async fn mihomo_none_security_uses_raw_tcp_and_mux_but_chunks_udp() {
        let tcp = test_stream(SECURITY_NONE, false, false, false, false).await;
        assert!(!tcp.chunk_stream);
        assert_eq!(tcp.options, 0);

        let udp = test_stream(SECURITY_NONE, true, false, false, false).await;
        assert!(udp.chunk_stream);
        assert_eq!(udp.options, OPTION_CHUNK_STREAM);

        let xudp = test_stream(SECURITY_NONE, true, true, false, false).await;
        assert!(!xudp.chunk_stream);
        assert_eq!(xudp.options, 0);
    }

    #[tokio::test]
    async fn legacy_cfb_uses_checksum_chunks() {
        let stream =
            test_stream(SECURITY_AES_128_CFB, false, false, true, true).await;
        assert!(stream.chunk_stream);
        assert_eq!(stream.options, OPTION_CHUNK_STREAM);
        assert!(stream.legacy_read_cipher.is_some());
        assert!(stream.legacy_write_cipher.is_some());
        assert_eq!(fnv1a32(b"hello"), 0x4f9f2cab);
    }

    #[test]
    fn shake128_length_mask_matches_go_reference() {
        let iv: Vec<u8> = (0..16).collect();
        let mut generator = Some(new_length_generator(&iv));
        let values = [
            next_length_value(&mut generator).unwrap(),
            next_length_value(&mut generator).unwrap(),
            next_length_value(&mut generator).unwrap(),
            next_length_value(&mut generator).unwrap(),
        ];
        assert_eq!(values, [0x9848, 0x1946, 0xde85, 0xc670]);
    }

    #[test]
    fn authenticated_length_matches_go_reference() {
        let iv: Vec<u8> = (0..16).collect();
        let key: Vec<u8> = (16..32).collect();
        assert_eq!(
            &kdf::vmess_kdf_1_one_shot(&key, b"auth_len")[..16],
            &hex::decode("49d3958e625ef844be78bb41a9df9743").unwrap()
        );

        let mut encrypt =
            new_authenticated_length_cipher(SECURITY_AES_128_GCM, &key, &iv)
                .unwrap();
        let mut encrypted = vec![0x12, 0x34];
        encrypted.resize(18, 0);
        encrypt.encrypt_inplace(&mut encrypted).unwrap();
        assert_eq!(
            hex::encode(&encrypted),
            "ba2ea2fd705bdf80228329c880adba070de6"
        );

        let mut decrypt =
            new_authenticated_length_cipher(SECURITY_AES_128_GCM, &key, &iv)
                .unwrap();
        decrypt.decrypt_inplace(&mut encrypted).unwrap();
        assert_eq!(&encrypted[..2], &[0x12, 0x34]);
    }
}
