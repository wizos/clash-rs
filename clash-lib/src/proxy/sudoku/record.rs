//! The AEAD record layer (`RecordConn`), layered *inside* the obfuscation
//! stream and *outside* the KIP/plaintext.
//!
//! Wire format per record:
//! ```text
//! u16 body_len
//! header[12] = epoch(u32 BE) || seq(u64 BE)   (sent in the clear)
//! ciphertext = AEAD(key=epoch_key, nonce=header, plaintext, aad=header)
//! ```
//! The header doubles as the AEAD nonce and AAD. Per-epoch keys are derived as
//! `HMAC-SHA256(base, "sudoku-record:" || method || epoch_be)`. `method =
//! "none"` disables framing entirely (the stream is passed through verbatim).

use std::{
    cmp::min,
    io,
    pin::Pin,
    task::{Context as TaskContext, Poll},
};

use aes_gcm::{
    Aes128Gcm,
    aead::{Aead as AesAead, KeyInit as AesKeyInit, Payload as AesPayload},
};
use chacha20poly1305::{
    ChaCha20Poly1305,
    aead::{Aead as ChaChaAead, KeyInit as ChaChaKeyInit, Payload as ChaChaPayload},
};
use hmac::{Hmac, KeyInit as HmacKeyInit, Mac};
use sha2::Sha256;
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};

type HmacSha256 = Hmac<Sha256>;

const RECORD_HEADER_SIZE: usize = 12;
const MAX_FRAME_BODY_SIZE: usize = 65535;
const TAG_SIZE: usize = 16;

/// Negotiated AEAD method.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum AeadMethod {
    None,
    Aes128Gcm,
    ChaCha20Poly1305,
}

impl AeadMethod {
    /// Normalise a config string (`""`/`chacha20-poly1305` → ChaCha) matching
    /// `normalizeAEADMethod`.
    pub(crate) fn parse(method: &str) -> anyhow::Result<Self> {
        match method {
            "" | "chacha20-poly1305" => Ok(AeadMethod::ChaCha20Poly1305),
            "aes-128-gcm" => Ok(AeadMethod::Aes128Gcm),
            "none" => Ok(AeadMethod::None),
            other => anyhow::bail!("sudoku: unsupported aead method: {other}"),
        }
    }

    fn label(self) -> &'static str {
        match self {
            AeadMethod::None => "none",
            AeadMethod::Aes128Gcm => "aes-128-gcm",
            AeadMethod::ChaCha20Poly1305 => "chacha20-poly1305",
        }
    }
}

/// A per-epoch AEAD cipher (`aes-128-gcm` or `chacha20-poly1305`).
enum EpochCipher {
    Aes(Box<Aes128Gcm>),
    ChaCha(Box<ChaCha20Poly1305>),
}

impl EpochCipher {
    fn seal(&self, header: &[u8; RECORD_HEADER_SIZE], plain: &[u8]) -> Vec<u8> {
        match self {
            EpochCipher::Aes(cipher) => cipher
                .encrypt(
                    header.into(),
                    AesPayload {
                        msg: plain,
                        aad: header,
                    },
                )
                .expect("sudoku: AES-GCM seal cannot fail"),
            EpochCipher::ChaCha(cipher) => cipher
                .encrypt(
                    header.into(),
                    ChaChaPayload {
                        msg: plain,
                        aad: header,
                    },
                )
                .expect("sudoku: ChaCha20-Poly1305 seal cannot fail"),
        }
    }

    fn open(
        &self,
        header: &[u8; RECORD_HEADER_SIZE],
        cipher: &[u8],
    ) -> io::Result<Vec<u8>> {
        match self {
            EpochCipher::Aes(aead) => aead
                .decrypt(
                    header.into(),
                    AesPayload {
                        msg: cipher,
                        aad: header,
                    },
                )
                .map_err(|_| record_decryption_error()),
            EpochCipher::ChaCha(aead) => aead
                .decrypt(
                    header.into(),
                    ChaChaPayload {
                        msg: cipher,
                        aad: header,
                    },
                )
                .map_err(|_| record_decryption_error()),
        }
    }
}

fn record_decryption_error() -> io::Error {
    io::Error::new(
        io::ErrorKind::InvalidData,
        "sudoku: record decryption failed",
    )
}

/// `HMAC-SHA256(base, "sudoku-record:" || method || epoch_be)`.
fn derive_epoch_key(base: &[u8], epoch: u32, method: AeadMethod) -> [u8; 32] {
    let mut mac = <HmacSha256 as HmacKeyInit>::new_from_slice(base)
        .expect("hmac accepts any key length");
    mac.update(b"sudoku-record:");
    mac.update(method.label().as_bytes());
    mac.update(&epoch.to_be_bytes());
    mac.finalize().into_bytes().into()
}

fn new_cipher(method: AeadMethod, base: &[u8], epoch: u32) -> EpochCipher {
    let key = derive_epoch_key(base, epoch, method);
    match method {
        AeadMethod::Aes128Gcm => EpochCipher::Aes(Box::new(
            <Aes128Gcm as AesKeyInit>::new_from_slice(&key[..16])
                .expect("AES-128 key length is fixed"),
        )),
        AeadMethod::ChaCha20Poly1305 => EpochCipher::ChaCha(Box::new(
            <ChaCha20Poly1305 as ChaChaKeyInit>::new_from_slice(&key)
                .expect("ChaCha20 key length is fixed"),
        )),
        AeadMethod::None => unreachable!("none method has no cipher"),
    }
}

fn random_nonzero_u32() -> u32 {
    loop {
        let mut b = [0u8; 4];
        getrandom::fill(&mut b).expect("system RNG");
        let v = u32::from_be_bytes(b);
        if v != 0 && v != u32::MAX {
            return v;
        }
    }
}

fn random_nonzero_u64() -> u64 {
    loop {
        let mut b = [0u8; 8];
        getrandom::fill(&mut b).expect("system RNG");
        let v = u64::from_be_bytes(b);
        if v != 0 && v != u64::MAX {
            return v;
        }
    }
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum ReadState {
    NeedLen,
    NeedBody(usize),
}

/// A framed AEAD `AsyncRead`/`AsyncWrite` over an inner stream.
pub(crate) struct RecordStream<S> {
    inner: S,
    method: AeadMethod,
    base_send: Vec<u8>,
    base_recv: Vec<u8>,

    send_cipher: Option<(u32, EpochCipher)>,
    recv_cipher: Option<(u32, EpochCipher)>,

    send_epoch: u32,
    send_seq: u64,

    recv_epoch: u32,
    recv_seq: u64,
    recv_initialized: bool,

    // Write staging.
    write_buf: Vec<u8>,
    write_pos: usize,
    write_consumed: usize,

    // Read staging.
    raw: Vec<u8>,
    rstate: ReadState,
    plain: Vec<u8>,
    plain_pos: usize,
    eof: bool,
}

impl<S> RecordStream<S> {
    pub(crate) fn new(
        inner: S,
        method: AeadMethod,
        base_send: &[u8],
        base_recv: &[u8],
    ) -> anyhow::Result<Self> {
        if method != AeadMethod::None
            && (base_send.len() < 32 || base_recv.len() < 32)
        {
            anyhow::bail!("sudoku: record base key must be >= 32 bytes");
        }
        let mut s = Self {
            inner,
            method,
            base_send: base_send.to_vec(),
            base_recv: base_recv.to_vec(),
            send_cipher: None,
            recv_cipher: None,
            send_epoch: 0,
            send_seq: 0,
            recv_epoch: 0,
            recv_seq: 0,
            recv_initialized: false,
            write_buf: Vec::new(),
            write_pos: 0,
            write_consumed: 0,
            raw: Vec::new(),
            rstate: ReadState::NeedLen,
            plain: Vec::new(),
            plain_pos: 0,
            eof: false,
        };
        s.reset_traffic_state();
        Ok(s)
    }

    fn reset_traffic_state(&mut self) {
        self.send_epoch = random_nonzero_u32();
        self.send_seq = random_nonzero_u64();
        self.recv_epoch = 0;
        self.recv_seq = 0;
        self.recv_initialized = false;
    }

    /// Replace the directional base keys and reset counters (post-handshake).
    pub(crate) fn rekey(
        &mut self,
        base_send: &[u8],
        base_recv: &[u8],
    ) -> anyhow::Result<()> {
        if self.method != AeadMethod::None
            && (base_send.len() < 32 || base_recv.len() < 32)
        {
            anyhow::bail!("sudoku: rekey base key must be >= 32 bytes");
        }
        self.base_send = base_send.to_vec();
        self.base_recv = base_recv.to_vec();
        self.reset_traffic_state();
        self.send_cipher = None;
        self.recv_cipher = None;
        self.plain.clear();
        self.plain_pos = 0;
        self.rstate = ReadState::NeedLen;
        self.raw.clear();
        Ok(())
    }

    /// Frame one record carrying `plain[..take]`, returning wire bytes +
    /// consumed.
    fn frame_outgoing(&mut self, plain: &[u8]) -> (Vec<u8>, usize) {
        if self.send_cipher.as_ref().map(|(e, _)| *e) != Some(self.send_epoch) {
            let cipher = new_cipher(self.method, &self.base_send, self.send_epoch);
            self.send_cipher = Some((self.send_epoch, cipher));
        }
        let cipher = &self.send_cipher.as_ref().expect("cipher set above").1;

        let max_plain = MAX_FRAME_BODY_SIZE - RECORD_HEADER_SIZE - TAG_SIZE;
        let take = min(plain.len(), max_plain);

        let mut header = [0u8; RECORD_HEADER_SIZE];
        header[..4].copy_from_slice(&self.send_epoch.to_be_bytes());
        header[4..].copy_from_slice(&self.send_seq.to_be_bytes());
        self.send_seq = self.send_seq.wrapping_add(1);

        let ciphertext = cipher.seal(&header, &plain[..take]);
        let body_len = RECORD_HEADER_SIZE + ciphertext.len();

        let mut frame = Vec::with_capacity(2 + body_len);
        frame.extend_from_slice(&(body_len as u16).to_be_bytes());
        frame.extend_from_slice(&header);
        frame.extend_from_slice(&ciphertext);
        (frame, take)
    }

    fn decode_body(&mut self, body: &[u8]) -> io::Result<()> {
        let header_arr: [u8; RECORD_HEADER_SIZE] = body[..RECORD_HEADER_SIZE]
            .try_into()
            .expect("slice len checked");
        let ciphertext = &body[RECORD_HEADER_SIZE..];
        let epoch = u32::from_be_bytes(header_arr[..4].try_into().unwrap());
        let seq = u64::from_be_bytes(header_arr[4..].try_into().unwrap());

        if self.recv_initialized {
            if epoch < self.recv_epoch {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "sudoku: replayed epoch",
                ));
            }
            if epoch == self.recv_epoch && seq != self.recv_seq {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "sudoku: out of order record",
                ));
            }
            if epoch > self.recv_epoch && epoch - self.recv_epoch > 8 {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "sudoku: epoch jump too large",
                ));
            }
        }

        if self.recv_cipher.as_ref().map(|(e, _)| *e) != Some(epoch) {
            let cipher = new_cipher(self.method, &self.base_recv, epoch);
            self.recv_cipher = Some((epoch, cipher));
        }
        let cipher = &self.recv_cipher.as_ref().expect("cipher set above").1;
        let plaintext = cipher.open(&header_arr, ciphertext)?;

        self.recv_epoch = epoch;
        self.recv_seq = seq.wrapping_add(1);
        self.recv_initialized = true;
        self.plain.extend_from_slice(&plaintext);
        Ok(())
    }

    fn drain_plain(&mut self, dst: &mut ReadBuf<'_>) -> bool {
        if self.plain_pos >= self.plain.len() {
            return false;
        }
        let n = min(dst.remaining(), self.plain.len() - self.plain_pos);
        dst.put_slice(&self.plain[self.plain_pos..self.plain_pos + n]);
        self.plain_pos += n;
        if self.plain_pos >= self.plain.len() {
            self.plain.clear();
            self.plain_pos = 0;
        }
        n > 0
    }
}

impl<S: AsyncWrite + Unpin> AsyncWrite for RecordStream<S> {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut TaskContext<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        let me = self.get_mut();
        if me.method == AeadMethod::None {
            return Pin::new(&mut me.inner).poll_write(cx, buf);
        }
        loop {
            if !me.write_buf.is_empty() {
                while me.write_pos < me.write_buf.len() {
                    match Pin::new(&mut me.inner)
                        .poll_write(cx, &me.write_buf[me.write_pos..])
                    {
                        Poll::Pending => return Poll::Pending,
                        Poll::Ready(Err(e)) => return Poll::Ready(Err(e)),
                        Poll::Ready(Ok(0)) => {
                            return Poll::Ready(Err(io::Error::new(
                                io::ErrorKind::WriteZero,
                                "sudoku: inner stream closed",
                            )));
                        }
                        Poll::Ready(Ok(n)) => me.write_pos += n,
                    }
                }
                me.write_buf.clear();
                me.write_pos = 0;
                let consumed = me.write_consumed;
                me.write_consumed = 0;
                return Poll::Ready(Ok(consumed));
            }
            if buf.is_empty() {
                return Poll::Ready(Ok(0));
            }
            let (frame, consumed) = me.frame_outgoing(buf);
            me.write_buf = frame;
            me.write_pos = 0;
            me.write_consumed = consumed;
        }
    }

    fn poll_flush(
        self: Pin<&mut Self>,
        cx: &mut TaskContext<'_>,
    ) -> Poll<io::Result<()>> {
        Pin::new(&mut self.get_mut().inner).poll_flush(cx)
    }

    fn poll_shutdown(
        self: Pin<&mut Self>,
        cx: &mut TaskContext<'_>,
    ) -> Poll<io::Result<()>> {
        Pin::new(&mut self.get_mut().inner).poll_shutdown(cx)
    }
}

impl<S: AsyncRead + Unpin> AsyncRead for RecordStream<S> {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut TaskContext<'_>,
        dst: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        let me = self.get_mut();
        if me.method == AeadMethod::None {
            return Pin::new(&mut me.inner).poll_read(cx, dst);
        }
        if me.drain_plain(dst) {
            return Poll::Ready(Ok(()));
        }
        if me.eof {
            return Poll::Ready(Ok(()));
        }
        loop {
            let need = match me.rstate {
                ReadState::NeedLen => 2,
                ReadState::NeedBody(body_len) => body_len,
            };
            while me.raw.len() < need {
                let mut tmp = [0u8; 8192];
                let mut rb = ReadBuf::new(&mut tmp);
                match Pin::new(&mut me.inner).poll_read(cx, &mut rb) {
                    Poll::Pending => return Poll::Pending,
                    Poll::Ready(Err(e)) => return Poll::Ready(Err(e)),
                    Poll::Ready(Ok(())) => {
                        let filled = rb.filled();
                        if filled.is_empty() {
                            // Clean EOF only valid at a frame boundary with no
                            // partial data.
                            if me.raw.is_empty() && me.rstate == ReadState::NeedLen {
                                me.eof = true;
                                return Poll::Ready(Ok(()));
                            }
                            return Poll::Ready(Err(io::Error::new(
                                io::ErrorKind::UnexpectedEof,
                                "sudoku: truncated record",
                            )));
                        }
                        me.raw.extend_from_slice(filled);
                    }
                }
            }
            match me.rstate {
                ReadState::NeedLen => {
                    let body_len =
                        u16::from_be_bytes([me.raw[0], me.raw[1]]) as usize;
                    me.raw.drain(..2);
                    if !(RECORD_HEADER_SIZE..=MAX_FRAME_BODY_SIZE)
                        .contains(&body_len)
                    {
                        return Poll::Ready(Err(io::Error::new(
                            io::ErrorKind::InvalidData,
                            "sudoku: bad record body length",
                        )));
                    }
                    me.rstate = ReadState::NeedBody(body_len);
                }
                ReadState::NeedBody(body_len) => {
                    let body: Vec<u8> = me.raw.drain(..body_len).collect();
                    me.rstate = ReadState::NeedLen;
                    me.decode_body(&body)?;
                    if me.drain_plain(dst) {
                        return Poll::Ready(Ok(()));
                    }
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::io::{AsyncReadExt, AsyncWriteExt, duplex};

    async fn round_trip(method: AeadMethod, payload: Vec<u8>) {
        let k1 = [0x11u8; 32];
        let k2 = [0x22u8; 32];
        let (a, b) = duplex(64 * 1024);
        // Client: send=k1, recv=k2. Server: send=k2, recv=k1.
        let mut client = RecordStream::new(a, method, &k1, &k2).unwrap();
        let mut server = RecordStream::new(b, method, &k2, &k1).unwrap();

        let expected = payload.clone();
        let writer = tokio::spawn(async move {
            client.write_all(&payload).await.unwrap();
            client.flush().await.unwrap();
            client.shutdown().await.unwrap();
            client
        });

        let mut got = Vec::new();
        server.read_to_end(&mut got).await.unwrap();
        let _client = writer.await.unwrap();
        assert_eq!(got, expected);
    }

    #[tokio::test]
    async fn chacha_round_trips_small_and_large() {
        round_trip(AeadMethod::ChaCha20Poly1305, b"hello sudoku".to_vec()).await;
        round_trip(
            AeadMethod::ChaCha20Poly1305,
            (0..70_000u32).map(|i| i as u8).collect(),
        )
        .await;
    }

    #[tokio::test]
    async fn aes_round_trips() {
        round_trip(
            AeadMethod::Aes128Gcm,
            (0..4096u32).map(|i| i as u8).collect(),
        )
        .await;
    }

    #[tokio::test]
    async fn none_method_is_passthrough() {
        round_trip(AeadMethod::None, b"plaintext passthrough".to_vec()).await;
    }

    #[tokio::test]
    async fn rekey_changes_keys_and_still_round_trips() {
        let k1 = [0x11u8; 32];
        let k2 = [0x22u8; 32];
        let s1 = [0xaau8; 32];
        let s2 = [0xbbu8; 32];
        let (a, b) = duplex(8192);
        let mut client =
            RecordStream::new(a, AeadMethod::ChaCha20Poly1305, &k1, &k2).unwrap();
        let mut server =
            RecordStream::new(b, AeadMethod::ChaCha20Poly1305, &k2, &k1).unwrap();
        client.rekey(&s1, &s2).unwrap();
        server.rekey(&s2, &s1).unwrap();

        let writer = tokio::spawn(async move {
            client.write_all(b"after rekey").await.unwrap();
            client.flush().await.unwrap();
            client.shutdown().await.unwrap();
        });
        let mut got = Vec::new();
        server.read_to_end(&mut got).await.unwrap();
        writer.await.unwrap();
        assert_eq!(got, b"after rekey");
    }

    #[tokio::test]
    async fn short_base_key_is_rejected() {
        let (a, _b) = duplex(64);
        let err = RecordStream::new(
            a,
            AeadMethod::ChaCha20Poly1305,
            &[0u8; 16],
            &[0u8; 32],
        );
        assert!(err.is_err());
    }
}
