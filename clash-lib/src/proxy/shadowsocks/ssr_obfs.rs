use std::{
    io,
    pin::Pin,
    task::{Context, Poll},
};

use async_trait::async_trait;
use bytes::{Buf, BufMut, BytesMut};
use futures::ready;
use rand::Rng;
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};

use crate::proxy::{AnyStream, transport::Sip003Plugin};

const DEFAULT_USER_AGENT: &str = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) \
                                  AppleWebKit/537.36 (KHTML, like Gecko) \
                                  Chrome/70.0.3538.102 Safari/537.36";
const MAX_HTTP_HEADER_SIZE: usize = 64 * 1024;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum SsrObfsMode {
    HttpSimple,
    HttpPost,
    RandomHead,
    Tls12TicketAuth,
}

#[derive(Debug)]
pub(crate) struct SsrObfsPlugin {
    mode: SsrObfsMode,
    host: String,
    port: u16,
    param: String,
    iv_size: usize,
    key: Vec<u8>,
    client_id: [u8; 32],
}

impl SsrObfsPlugin {
    pub(crate) fn new(
        mode: SsrObfsMode,
        host: String,
        port: u16,
        param: String,
        iv_size: usize,
    ) -> Self {
        Self {
            mode,
            host,
            port,
            param,
            iv_size,
            key: Vec::new(),
            client_id: rand::random(),
        }
    }

    pub(crate) fn new_tls12_ticket(
        host: String,
        param: String,
        key: Vec<u8>,
    ) -> Self {
        Self {
            mode: SsrObfsMode::Tls12TicketAuth,
            host,
            port: 0,
            param,
            iv_size: 0,
            key,
            client_id: rand::random(),
        }
    }
}

#[async_trait]
impl Sip003Plugin for SsrObfsPlugin {
    async fn proxy_stream(&self, stream: AnyStream) -> io::Result<AnyStream> {
        match self.mode {
            SsrObfsMode::HttpSimple | SsrObfsMode::HttpPost => {
                Ok(Box::new(HttpObfsStream::new(
                    stream,
                    self.host.clone(),
                    self.port,
                    self.param.clone(),
                    self.iv_size,
                    self.mode == SsrObfsMode::HttpPost,
                )))
            }
            SsrObfsMode::RandomHead => Ok(Box::new(RandomHeadStream::new(stream))),
            SsrObfsMode::Tls12TicketAuth => Ok(Box::new(Tls12TicketStream::new(
                stream,
                self.host.clone(),
                self.param.clone(),
                self.key.clone(),
                self.client_id,
            ))),
        }
    }
}

struct HttpObfsStream {
    inner: AnyStream,
    host: String,
    port: u16,
    param: String,
    iv_size: usize,
    post: bool,
    read_buf: BytesMut,
    read_header_consumed: bool,
    write_buf: BytesMut,
    write_pos: usize,
    write_committed: usize,
    write_header_sent: bool,
}

impl HttpObfsStream {
    fn new(
        inner: AnyStream,
        host: String,
        port: u16,
        param: String,
        iv_size: usize,
        post: bool,
    ) -> Self {
        Self {
            inner,
            host,
            port,
            param,
            iv_size,
            post,
            read_buf: BytesMut::new(),
            read_header_consumed: false,
            write_buf: BytesMut::new(),
            write_pos: 0,
            write_committed: 0,
            write_header_sent: false,
        }
    }

    fn selected_host_and_headers(&self) -> (String, Option<String>) {
        let (hosts, custom_headers) = match self.param.split_once('#') {
            Some((hosts, headers)) => {
                let headers = headers.replace('\n', "\r\n").replace("\\n", "\r\n");
                (hosts, Some(headers))
            }
            None if !self.param.is_empty() => (self.param.as_str(), None),
            None => (self.host.as_str(), None),
        };
        let hosts = hosts.split(',').collect::<Vec<_>>();
        let host = hosts[rand::random_range(0..hosts.len())].to_owned();
        (host, custom_headers)
    }

    fn build_first_write(&mut self, source: &[u8]) {
        let head_length = self.iv_size + 30;
        let head_data_length = if source.len().saturating_sub(head_length) > 64 {
            head_length + rand::random_range(0..65)
        } else {
            source.len()
        };
        let (head_data, remaining) = source.split_at(head_data_length);
        let (host, custom_headers) = self.selected_host_and_headers();
        let method = if self.post { "POST" } else { "GET" };

        self.write_buf.put_slice(format!("{method} /").as_bytes());
        for byte in head_data {
            self.write_buf.put_slice(format!("%{byte:02x}").as_bytes());
        }
        self.write_buf.put_slice(b" HTTP/1.1\r\nHost: ");
        self.write_buf.put_slice(host.as_bytes());
        if self.port != 80 {
            self.write_buf
                .put_slice(format!(":{}", self.port).as_bytes());
        }
        self.write_buf.put_slice(b"\r\n");

        if let Some(custom_headers) = custom_headers {
            self.write_buf.put_slice(custom_headers.as_bytes());
            self.write_buf.put_slice(b"\r\n\r\n");
        } else {
            self.write_buf.put_slice(b"User-Agent: ");
            self.write_buf.put_slice(DEFAULT_USER_AGENT.as_bytes());
            self.write_buf.put_slice(
                b"\r\nAccept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8\r\nAccept-Language: en-US,en;q=0.8\r\nAccept-Encoding: gzip, deflate\r\n",
            );
            if self.post {
                self.write_buf
                    .put_slice(b"Content-Type: multipart/form-data; boundary=");
                const ALPHANUMERIC: &[u8] =
                    b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789";
                for _ in 0..32 {
                    self.write_buf.put_u8(
                        ALPHANUMERIC[rand::random_range(0..ALPHANUMERIC.len())],
                    );
                }
                self.write_buf.put_slice(b"\r\n");
            }
            self.write_buf
                .put_slice(b"DNT: 1\r\nConnection: keep-alive\r\n\r\n");
        }
        self.write_buf.put_slice(remaining);
    }

    fn poll_drain_write_buf(
        &mut self,
        cx: &mut Context<'_>,
    ) -> Poll<io::Result<()>> {
        while self.write_pos < self.write_buf.len() {
            let written = ready!(
                Pin::new(&mut self.inner)
                    .poll_write(cx, &self.write_buf[self.write_pos..])
            )?;
            if written == 0 {
                return Poll::Ready(Err(io::Error::from(io::ErrorKind::WriteZero)));
            }
            self.write_pos += written;
        }
        Poll::Ready(Ok(()))
    }
}

impl AsyncRead for HttpObfsStream {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        if !this.read_header_consumed {
            loop {
                if let Some(offset) = find_header_end(&this.read_buf) {
                    this.read_buf.advance(offset);
                    this.read_header_consumed = true;
                    break;
                }
                if this.read_buf.len() >= MAX_HTTP_HEADER_SIZE {
                    return Poll::Ready(Err(io::Error::new(
                        io::ErrorKind::InvalidData,
                        "SSR HTTP obfs response header is too large",
                    )));
                }
                let mut scratch = [0u8; 2048];
                let mut read_buf = ReadBuf::new(&mut scratch);
                ready!(Pin::new(&mut this.inner).poll_read(cx, &mut read_buf))?;
                if read_buf.filled().is_empty() {
                    return Poll::Ready(Err(io::Error::from(
                        io::ErrorKind::UnexpectedEof,
                    )));
                }
                this.read_buf.extend_from_slice(read_buf.filled());
            }
        }

        if !this.read_buf.is_empty() {
            let length = this.read_buf.len().min(buf.remaining());
            buf.put_slice(&this.read_buf.split_to(length));
            return Poll::Ready(Ok(()));
        }
        Pin::new(&mut this.inner).poll_read(cx, buf)
    }
}

impl AsyncWrite for HttpObfsStream {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        source: &[u8],
    ) -> Poll<io::Result<usize>> {
        let this = self.get_mut();
        if source.is_empty() {
            return Poll::Ready(Ok(0));
        }

        if this.write_committed > 0 {
            ready!(this.poll_drain_write_buf(cx))?;
            let committed = this.write_committed;
            this.write_buf.clear();
            this.write_pos = 0;
            this.write_committed = 0;
            return Poll::Ready(Ok(committed));
        }

        this.write_buf.clear();
        this.write_pos = 0;
        this.write_committed = source.len();
        if this.write_header_sent {
            this.write_buf.put_slice(source);
        } else {
            this.build_first_write(source);
            this.write_header_sent = true;
        }

        ready!(this.poll_drain_write_buf(cx))?;
        let committed = this.write_committed;
        this.write_buf.clear();
        this.write_pos = 0;
        this.write_committed = 0;
        Poll::Ready(Ok(committed))
    }

    fn poll_flush(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        ready!(this.poll_drain_write_buf(cx))?;
        this.write_buf.clear();
        this.write_pos = 0;
        this.write_committed = 0;
        Pin::new(&mut this.inner).poll_flush(cx)
    }

    fn poll_shutdown(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        ready!(this.poll_drain_write_buf(cx))?;
        Pin::new(&mut this.inner).poll_shutdown(cx)
    }
}

fn find_header_end(data: &[u8]) -> Option<usize> {
    data.windows(4)
        .position(|window| window == b"\r\n\r\n")
        .map(|position| position + 4)
}

struct RandomHeadStream {
    inner: AnyStream,
    random_header: BytesMut,
    random_header_pos: usize,
    first_write_committed: usize,
    header_started: bool,
    response_received: bool,
    pending_payload: BytesMut,
    pending_payload_pos: usize,
}

impl RandomHeadStream {
    fn new(inner: AnyStream) -> Self {
        Self {
            inner,
            random_header: BytesMut::new(),
            random_header_pos: 0,
            first_write_committed: 0,
            header_started: false,
            response_received: false,
            pending_payload: BytesMut::new(),
            pending_payload_pos: 0,
        }
    }

    fn build_random_header(&mut self) {
        let data_length = rand::random_range(4..100);
        self.random_header.resize(data_length + 4, 0);
        rand::rng().fill_bytes(&mut self.random_header[..data_length]);
        let checksum =
            u32::MAX - crc32fast::hash(&self.random_header[..data_length]);
        self.random_header[data_length..].copy_from_slice(&checksum.to_le_bytes());
    }

    fn poll_drain_random_header(
        &mut self,
        cx: &mut Context<'_>,
    ) -> Poll<io::Result<()>> {
        while self.random_header_pos < self.random_header.len() {
            let written = ready!(
                Pin::new(&mut self.inner)
                    .poll_write(cx, &self.random_header[self.random_header_pos..],)
            )?;
            if written == 0 {
                return Poll::Ready(Err(io::Error::from(io::ErrorKind::WriteZero)));
            }
            self.random_header_pos += written;
        }
        Poll::Ready(Ok(()))
    }

    fn poll_drain_pending_payload(
        &mut self,
        cx: &mut Context<'_>,
    ) -> Poll<io::Result<()>> {
        while self.pending_payload_pos < self.pending_payload.len() {
            let written =
                ready!(Pin::new(&mut self.inner).poll_write(
                    cx,
                    &self.pending_payload[self.pending_payload_pos..],
                ))?;
            if written == 0 {
                return Poll::Ready(Err(io::Error::from(io::ErrorKind::WriteZero)));
            }
            self.pending_payload_pos += written;
        }
        self.pending_payload.clear();
        self.pending_payload_pos = 0;
        Poll::Ready(Ok(()))
    }
}

impl AsyncRead for RandomHeadStream {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        if !this.response_received {
            let mut scratch = [0u8; 2048];
            let mut response = ReadBuf::new(&mut scratch);
            ready!(Pin::new(&mut this.inner).poll_read(cx, &mut response))?;
            if response.filled().is_empty() {
                return Poll::Ready(Err(io::Error::from(
                    io::ErrorKind::UnexpectedEof,
                )));
            }
            this.response_received = true;
        }
        ready!(this.poll_drain_pending_payload(cx))?;
        Pin::new(&mut this.inner).poll_read(cx, buf)
    }
}

impl AsyncWrite for RandomHeadStream {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        source: &[u8],
    ) -> Poll<io::Result<usize>> {
        let this = self.get_mut();
        if source.is_empty() {
            return Poll::Ready(Ok(0));
        }

        if this.response_received {
            ready!(this.poll_drain_pending_payload(cx))?;
            return Pin::new(&mut this.inner).poll_write(cx, source);
        }

        if this.first_write_committed > 0 {
            ready!(this.poll_drain_random_header(cx))?;
            let committed = this.first_write_committed;
            this.first_write_committed = 0;
            return Poll::Ready(Ok(committed));
        }

        this.pending_payload.put_slice(source);
        if this.header_started {
            return Poll::Ready(Ok(source.len()));
        }

        this.header_started = true;
        this.first_write_committed = source.len();
        this.build_random_header();
        ready!(this.poll_drain_random_header(cx))?;
        let committed = this.first_write_committed;
        this.first_write_committed = 0;
        Poll::Ready(Ok(committed))
    }

    fn poll_flush(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        ready!(this.poll_drain_random_header(cx))?;
        if this.response_received {
            ready!(this.poll_drain_pending_payload(cx))?;
        }
        Pin::new(&mut this.inner).poll_flush(cx)
    }

    fn poll_shutdown(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        ready!(this.poll_drain_random_header(cx))?;
        if this.response_received {
            ready!(this.poll_drain_pending_payload(cx))?;
        }
        Pin::new(&mut this.inner).poll_shutdown(cx)
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum Tls12TicketState {
    Initial,
    WaitServer,
    SendingFinish,
    Established,
}

struct Tls12TicketStream {
    inner: AnyStream,
    host: String,
    param: String,
    key: Vec<u8>,
    client_id: [u8; 32],
    state: Tls12TicketState,
    send_buffer: BytesMut,
    read_encoded: BytesMut,
    read_decoded: BytesMut,
    wire_buffer: BytesMut,
    wire_position: usize,
    write_committed: usize,
}

impl Tls12TicketStream {
    fn new(
        inner: AnyStream,
        host: String,
        param: String,
        key: Vec<u8>,
        client_id: [u8; 32],
    ) -> Self {
        Self {
            inner,
            host,
            param,
            key,
            client_id,
            state: Tls12TicketState::Initial,
            send_buffer: BytesMut::new(),
            read_encoded: BytesMut::new(),
            read_decoded: BytesMut::new(),
            wire_buffer: BytesMut::new(),
            wire_position: 0,
            write_committed: 0,
        }
    }

    fn hmac(&self, data: &[u8]) -> [u8; 20] {
        use hmac::{Hmac, Mac, digest::KeyInit};
        use sha1::Sha1;

        let mut key = Vec::with_capacity(self.key.len() + self.client_id.len());
        key.extend_from_slice(&self.key);
        key.extend_from_slice(&self.client_id);
        let mut mac =
            Hmac::<Sha1>::new_from_slice(&key).expect("HMAC accepts any key size");
        mac.update(data);
        mac.finalize().into_bytes().into()
    }

    fn selected_host(&self) -> String {
        let mut host = if self.param.is_empty() {
            self.host.as_str()
        } else {
            self.param.as_str()
        };
        if host
            .as_bytes()
            .last()
            .is_some_and(|byte| byte.is_ascii_digit())
        {
            host = "";
        }
        let hosts = host.split(',').collect::<Vec<_>>();
        hosts[rand::random_range(0..hosts.len())].to_owned()
    }

    fn build_client_hello(&mut self) {
        let mut hello = BytesMut::new();
        hello.put_slice(&[3, 3]);
        let auth_start = hello.len();
        hello.put_u32(unix_timestamp());
        put_random_bytes(&mut hello, 18);
        let tag = self.hmac(&hello[auth_start..]);
        hello.put_slice(&tag[..10]);
        hello.put_u8(0x20);
        hello.put_slice(&self.client_id);
        hello.put_slice(&[
            0x00, 0x1c, 0xc0, 0x2b, 0xc0, 0x2f, 0xcc, 0xa9, 0xcc, 0xa8, 0xcc, 0x14,
            0xcc, 0x13, 0xc0, 0x0a, 0xc0, 0x14, 0xc0, 0x09, 0xc0, 0x13, 0x00, 0x9c,
            0x00, 0x35, 0x00, 0x2f, 0x00, 0x0a,
        ]);
        hello.put_slice(&[0x01, 0x00]);

        let host = self.selected_host();
        let mut extensions = BytesMut::new();
        extensions.put_slice(&[0xff, 0x01, 0x00, 0x01, 0x00]);
        put_sni(&mut extensions, &host);
        extensions.put_slice(&[0x00, 0x17, 0x00, 0x00]);
        let ticket_length = 16 * rand::random_range(8..25);
        extensions.put_slice(&[0x00, 0x23]);
        extensions.put_u16(ticket_length as u16);
        put_random_bytes(&mut extensions, ticket_length);
        extensions.put_slice(&[
            0x00, 0x0d, 0x00, 0x16, 0x00, 0x14, 0x06, 0x01, 0x06, 0x03, 0x05, 0x01,
            0x05, 0x03, 0x04, 0x01, 0x04, 0x03, 0x03, 0x01, 0x03, 0x03, 0x02, 0x01,
            0x02, 0x03,
        ]);
        extensions.put_slice(&[0x00, 0x05, 0x00, 0x05, 0x01, 0, 0, 0, 0]);
        extensions.put_slice(&[0x00, 0x12, 0x00, 0x00]);
        extensions.put_slice(&[0x75, 0x50, 0x00, 0x00]);
        extensions.put_slice(&[0x00, 0x0b, 0x00, 0x02, 0x01, 0x00]);
        extensions.put_slice(&[
            0x00, 0x0a, 0x00, 0x06, 0x00, 0x04, 0x00, 0x17, 0x00, 0x18,
        ]);
        hello.put_u16(extensions.len() as u16);
        hello.put_slice(&extensions);

        self.wire_buffer.put_slice(&[0x16, 3, 1]);
        self.wire_buffer.put_u16((hello.len() + 4) as u16);
        self.wire_buffer.put_slice(&[1, 0]);
        self.wire_buffer.put_u16(hello.len() as u16);
        self.wire_buffer.put_slice(&hello);
    }

    fn build_finish(&mut self) {
        self.wire_buffer.clear();
        self.wire_position = 0;
        self.wire_buffer
            .put_slice(&[0x14, 3, 3, 0, 1, 1, 0x16, 3, 3, 0, 0x20]);
        put_random_bytes(&mut self.wire_buffer, 22);
        let tag = self.hmac(&self.wire_buffer);
        self.wire_buffer.put_slice(&tag[..10]);
        self.wire_buffer.put_slice(&self.send_buffer);
        self.send_buffer.clear();
    }

    fn verify_server_handshake(&self, data: &[u8]) -> io::Result<()> {
        if data.len() < 11 + 32 + 1 + 32 {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "SSR tls1.2_ticket_auth server handshake is too short",
            ));
        }
        let first_tag = self.hmac(&data[11..33]);
        let final_tag = self.hmac(&data[..data.len() - 10]);
        if data[33..43] != first_tag[..10]
            || data[data.len() - 10..] != final_tag[..10]
        {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "SSR tls1.2_ticket_auth server handshake HMAC mismatch",
            ));
        }
        Ok(())
    }

    fn encode_application_data(target: &mut BytesMut, mut data: &[u8]) {
        while data.len() > 2048 {
            let length = rand::random_range(100..4196).min(data.len());
            put_tls_application_record(target, &data[..length]);
            data = &data[length..];
        }
        if !data.is_empty() {
            put_tls_application_record(target, data);
        }
    }

    fn decode_application_data(&mut self) -> io::Result<()> {
        while self.read_encoded.len() > 5 {
            if self.read_encoded[..3] != [0x17, 3, 3] {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "SSR tls1.2_ticket_auth application record has invalid magic",
                ));
            }
            let length = u16::from_be_bytes(
                self.read_encoded[3..5]
                    .try_into()
                    .expect("two-byte TLS length"),
            ) as usize;
            if self.read_encoded.len() < 5 + length {
                break;
            }
            self.read_encoded.advance(5);
            self.read_decoded
                .put_slice(&self.read_encoded.split_to(length));
        }
        Ok(())
    }

    fn poll_drain_wire(&mut self, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        while self.wire_position < self.wire_buffer.len() {
            let written = ready!(
                Pin::new(&mut self.inner)
                    .poll_write(cx, &self.wire_buffer[self.wire_position..],)
            )?;
            if written == 0 {
                return Poll::Ready(Err(io::Error::from(io::ErrorKind::WriteZero)));
            }
            self.wire_position += written;
        }
        Poll::Ready(Ok(()))
    }

    fn clear_wire(&mut self) {
        self.wire_buffer.clear();
        self.wire_position = 0;
        self.write_committed = 0;
    }
}

impl AsyncRead for Tls12TicketStream {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        output: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        loop {
            match this.state {
                Tls12TicketState::Initial => {
                    return Poll::Ready(Err(io::Error::new(
                        io::ErrorKind::NotConnected,
                        "SSR tls1.2_ticket_auth read before ClientHello",
                    )));
                }
                Tls12TicketState::WaitServer => {
                    let mut scratch = [0u8; 16 * 1024];
                    let mut handshake = ReadBuf::new(&mut scratch);
                    ready!(Pin::new(&mut this.inner).poll_read(cx, &mut handshake))?;
                    if handshake.filled().is_empty() {
                        return Poll::Ready(Err(io::Error::from(
                            io::ErrorKind::UnexpectedEof,
                        )));
                    }
                    this.verify_server_handshake(handshake.filled())?;
                    this.build_finish();
                    this.state = Tls12TicketState::SendingFinish;
                }
                Tls12TicketState::SendingFinish => {
                    ready!(this.poll_drain_wire(cx))?;
                    this.clear_wire();
                    this.state = Tls12TicketState::Established;
                }
                Tls12TicketState::Established => {
                    if !this.read_decoded.is_empty() {
                        let length = this.read_decoded.len().min(output.remaining());
                        output.put_slice(&this.read_decoded.split_to(length));
                        return Poll::Ready(Ok(()));
                    }
                    this.decode_application_data()?;
                    if !this.read_decoded.is_empty() {
                        continue;
                    }
                    let mut scratch = [0u8; 8192];
                    let mut record = ReadBuf::new(&mut scratch);
                    ready!(Pin::new(&mut this.inner).poll_read(cx, &mut record))?;
                    if record.filled().is_empty() {
                        if this.read_encoded.is_empty() {
                            return Poll::Ready(Ok(()));
                        }
                        return Poll::Ready(Err(io::Error::from(
                            io::ErrorKind::UnexpectedEof,
                        )));
                    }
                    this.read_encoded.put_slice(record.filled());
                }
            }
        }
    }
}

impl AsyncWrite for Tls12TicketStream {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        source: &[u8],
    ) -> Poll<io::Result<usize>> {
        let this = self.get_mut();
        if source.is_empty() {
            return Poll::Ready(Ok(0));
        }
        if this.write_committed > 0 {
            ready!(this.poll_drain_wire(cx))?;
            let committed = this.write_committed;
            this.clear_wire();
            return Poll::Ready(Ok(committed));
        }

        match this.state {
            Tls12TicketState::Initial => {
                Self::encode_application_data(&mut this.send_buffer, source);
                this.build_client_hello();
                this.state = Tls12TicketState::WaitServer;
                this.write_committed = source.len();
                ready!(this.poll_drain_wire(cx))?;
                let committed = this.write_committed;
                this.clear_wire();
                Poll::Ready(Ok(committed))
            }
            Tls12TicketState::WaitServer => {
                Self::encode_application_data(&mut this.send_buffer, source);
                Poll::Ready(Ok(source.len()))
            }
            Tls12TicketState::SendingFinish => {
                ready!(this.poll_drain_wire(cx))?;
                this.clear_wire();
                this.state = Tls12TicketState::Established;
                Self::encode_application_data(&mut this.wire_buffer, source);
                this.write_committed = source.len();
                ready!(this.poll_drain_wire(cx))?;
                let committed = this.write_committed;
                this.clear_wire();
                Poll::Ready(Ok(committed))
            }
            Tls12TicketState::Established => {
                Self::encode_application_data(&mut this.wire_buffer, source);
                this.write_committed = source.len();
                ready!(this.poll_drain_wire(cx))?;
                let committed = this.write_committed;
                this.clear_wire();
                Poll::Ready(Ok(committed))
            }
        }
    }

    fn poll_flush(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        ready!(this.poll_drain_wire(cx))?;
        if this.write_committed > 0 {
            this.clear_wire();
        }
        Pin::new(&mut this.inner).poll_flush(cx)
    }

    fn poll_shutdown(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        ready!(this.poll_drain_wire(cx))?;
        Pin::new(&mut this.inner).poll_shutdown(cx)
    }
}

fn put_sni(buffer: &mut BytesMut, host: &str) {
    let length = host.len() as u16;
    buffer.put_slice(&[0, 0]);
    buffer.put_u16(length + 5);
    buffer.put_u16(length + 3);
    buffer.put_u8(0);
    buffer.put_u16(length);
    buffer.put_slice(host.as_bytes());
}

fn put_tls_application_record(buffer: &mut BytesMut, data: &[u8]) {
    buffer.put_slice(&[0x17, 3, 3]);
    buffer.put_u16(data.len() as u16);
    buffer.put_slice(data);
}

fn put_random_bytes(buffer: &mut BytesMut, length: usize) {
    let start = buffer.len();
    buffer.resize(start + length, 0);
    rand::rng().fill_bytes(&mut buffer[start..]);
}

fn unix_timestamp() -> u32 {
    use std::time::{SystemTime, UNIX_EPOCH};

    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs() as u32
}

#[cfg(test)]
mod tests {
    use tokio::io::{AsyncReadExt, AsyncWriteExt, duplex};

    use super::*;

    fn tls_ticket_hmac(key: &[u8], client_id: &[u8; 32], data: &[u8]) -> [u8; 20] {
        use hmac::{Hmac, Mac, digest::KeyInit};
        use sha1::Sha1;

        let mut hmac_key = Vec::with_capacity(key.len() + client_id.len());
        hmac_key.extend_from_slice(key);
        hmac_key.extend_from_slice(client_id);
        let mut mac = Hmac::<Sha1>::new_from_slice(&hmac_key)
            .expect("HMAC accepts any key size");
        mac.update(data);
        mac.finalize().into_bytes().into()
    }

    #[tokio::test]
    async fn http_simple_encodes_head_and_strips_response_header() {
        let (client, mut server) = duplex(4096);
        let plugin = SsrObfsPlugin::new(
            SsrObfsMode::HttpSimple,
            "server.example".to_owned(),
            8388,
            "cdn.example#X-Test: yes".to_owned(),
            16,
        );
        let mut stream = plugin.proxy_stream(Box::new(client)).await.unwrap();
        let payload = b"\x01\x02\x03encrypted";
        stream.write_all(payload).await.unwrap();

        let mut request = vec![0u8; 2048];
        let length = server.read(&mut request).await.unwrap();
        let request = &request[..length];
        assert!(
            request.starts_with(
                b"GET /%01%02%03%65%6e%63%72%79%70%74%65%64 HTTP/1.1\r\n"
            )
        );
        assert!(
            request
                .windows(22)
                .any(|part| part == b"Host: cdn.example:8388")
        );
        assert!(request.windows(11).any(|part| part == b"X-Test: yes"));

        server
            .write_all(b"HTTP/1.1 200 OK\r\nServer: test\r\n\r\nreply")
            .await
            .unwrap();
        let mut response = [0u8; 5];
        stream.read_exact(&mut response).await.unwrap();
        assert_eq!(&response, b"reply");
    }

    #[tokio::test]
    async fn tls12_ticket_auth_performs_authenticated_bidirectional_handshake() {
        let (client, mut server) = duplex(32 * 1024);
        let key = b"0123456789abcdef".to_vec();
        let plugin = SsrObfsPlugin::new_tls12_ticket(
            "server.example".to_owned(),
            "cdn.example".to_owned(),
            key.clone(),
        );
        let client_id = plugin.client_id;
        let mut stream = plugin.proxy_stream(Box::new(client)).await.unwrap();
        let request = b"encrypted SSR request";
        let response = b"encrypted SSR response";

        let server_task = tokio::spawn(async move {
            let mut record_header = [0u8; 5];
            server.read_exact(&mut record_header).await.unwrap();
            assert_eq!(&record_header[..3], &[0x16, 3, 1]);
            let hello_length =
                u16::from_be_bytes(record_header[3..5].try_into().unwrap()) as usize;
            let mut hello = vec![0u8; hello_length];
            server.read_exact(&mut hello).await.unwrap();
            assert_eq!(hello[0], 1);
            assert!(
                hello
                    .windows(b"cdn.example".len())
                    .any(|window| window == b"cdn.example")
            );
            let hello_tag = tls_ticket_hmac(&key, &client_id, &hello[6..28]);
            assert_eq!(&hello[28..38], &hello_tag[..10]);

            let mut server_handshake = vec![0u8; 76];
            rand::rng().fill_bytes(&mut server_handshake);
            let first_tag =
                tls_ticket_hmac(&key, &client_id, &server_handshake[11..33]);
            server_handshake[33..43].copy_from_slice(&first_tag[..10]);
            let final_tag =
                tls_ticket_hmac(&key, &client_id, &server_handshake[..66]);
            server_handshake[66..].copy_from_slice(&final_tag[..10]);
            server.write_all(&server_handshake).await.unwrap();

            let mut finish = [0u8; 43];
            server.read_exact(&mut finish).await.unwrap();
            assert_eq!(&finish[..11], &[0x14, 3, 3, 0, 1, 1, 0x16, 3, 3, 0, 0x20]);
            let finish_tag = tls_ticket_hmac(&key, &client_id, &finish[..33]);
            assert_eq!(&finish[33..], &finish_tag[..10]);

            let mut application_header = [0u8; 5];
            server.read_exact(&mut application_header).await.unwrap();
            assert_eq!(&application_header[..3], &[0x17, 3, 3]);
            let application_length =
                u16::from_be_bytes(application_header[3..].try_into().unwrap())
                    as usize;
            let mut application_data = vec![0u8; application_length];
            server.read_exact(&mut application_data).await.unwrap();
            assert_eq!(application_data, request);

            let mut encoded_response = BytesMut::new();
            put_tls_application_record(&mut encoded_response, response);
            server.write_all(&encoded_response).await.unwrap();
        });

        stream.write_all(request).await.unwrap();
        let mut decoded_response = vec![0u8; response.len()];
        stream.read_exact(&mut decoded_response).await.unwrap();
        assert_eq!(decoded_response, response);
        server_task.await.unwrap();
    }

    #[tokio::test]
    async fn http_post_adds_boundary_and_keeps_large_payload_tail() {
        let (client, mut server) = duplex(8192);
        let plugin = SsrObfsPlugin::new(
            SsrObfsMode::HttpPost,
            "server.example".to_owned(),
            80,
            String::new(),
            16,
        );
        let mut stream = plugin.proxy_stream(Box::new(client)).await.unwrap();
        let payload = vec![0x42; 256];
        stream.write_all(&payload).await.unwrap();

        let mut request = vec![0u8; 8192];
        let length = server.read(&mut request).await.unwrap();
        let request = &request[..length];
        assert!(request.starts_with(b"POST /"));
        assert!(request.windows(44).any(|part| {
            part == b"Content-Type: multipart/form-data; boundary="
        }));
        let header_end = find_header_end(request).unwrap();
        assert!(!request[header_end..].is_empty());
    }

    #[tokio::test]
    async fn random_head_waits_for_server_reply_before_payload() {
        let (client, mut server) = duplex(4096);
        let plugin = SsrObfsPlugin::new(
            SsrObfsMode::RandomHead,
            String::new(),
            0,
            String::new(),
            0,
        );
        let mut stream = plugin.proxy_stream(Box::new(client)).await.unwrap();
        let payload = b"encrypted shadowsocks payload";
        stream.write_all(payload).await.unwrap();

        let server_task = tokio::spawn(async move {
            let mut header = [0u8; 128];
            let header_length = server.read(&mut header).await.unwrap();
            assert!((8..=103).contains(&header_length));
            let data_length = header_length - 4;
            let checksum = u32::from_le_bytes(
                header[data_length..header_length].try_into().unwrap(),
            );
            assert_eq!(checksum, u32::MAX - crc32fast::hash(&header[..data_length]),);
            server.write_all(b"server-random-head").await.unwrap();
            let mut received = vec![0u8; payload.len()];
            server.read_exact(&mut received).await.unwrap();
            assert_eq!(&received, payload);
            server.write_all(b"response").await.unwrap();
        });

        let mut response = [0u8; 8];
        stream.read_exact(&mut response).await.unwrap();
        assert_eq!(&response, b"response");
        server_task.await.unwrap();
    }
}
