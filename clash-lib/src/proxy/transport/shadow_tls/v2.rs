use std::{
    pin::Pin,
    task::{Context, Poll, ready},
};

use bytes::{BufMut, BytesMut};
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};

use crate::common::io::{ReadExactBase, ReadExt};

use super::prelude::{APPLICATION_DATA, TLS_HEADER_SIZE, TLS_MAJOR, TLS_MINOR};

const MAX_PAYLOAD_SIZE: usize = 1 << 13;

#[derive(Default)]
enum ReadState {
    #[default]
    Header,
    Payload(usize),
    Flush,
}

#[derive(Default)]
enum WriteState {
    #[default]
    Build,
    Flush {
        consumed: usize,
        total: usize,
        written: usize,
    },
}

pub(super) struct Stream<S> {
    raw: S,
    first_auth: Option<[u8; 8]>,
    read_state: ReadState,
    read_buf: BytesMut,
    read_pos: usize,
    write_state: WriteState,
    write_buf: BytesMut,
}

impl<S> Stream<S> {
    pub(super) fn new(raw: S, first_auth: [u8; 8]) -> Self {
        Self {
            raw,
            first_auth: Some(first_auth),
            read_state: ReadState::default(),
            read_buf: BytesMut::new(),
            read_pos: 0,
            write_state: WriteState::default(),
            write_buf: BytesMut::new(),
        }
    }
}

impl<S: AsyncRead + Unpin> ReadExactBase for Stream<S> {
    type I = S;

    fn decompose(&mut self) -> (&mut S, &mut BytesMut, &mut usize) {
        (&mut self.raw, &mut self.read_buf, &mut self.read_pos)
    }
}

impl<S: AsyncRead + Unpin> AsyncRead for Stream<S> {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        output: &mut ReadBuf<'_>,
    ) -> Poll<std::io::Result<()>> {
        let this = self.get_mut();
        loop {
            match this.read_state {
                ReadState::Header => {
                    ready!(this.poll_read_exact(cx, TLS_HEADER_SIZE))?;
                    let header = this.read_buf.split().freeze();
                    if header[0] != APPLICATION_DATA
                        || header[1] != TLS_MAJOR
                        || header[2] != TLS_MINOR.0
                    {
                        return Poll::Ready(Err(std::io::Error::new(
                            std::io::ErrorKind::InvalidData,
                            "invalid ShadowTLS v2 application-data header",
                        )));
                    }
                    let length = u16::from_be_bytes([header[3], header[4]]) as usize;
                    this.read_state = ReadState::Payload(length);
                }
                ReadState::Payload(length) => {
                    ready!(this.poll_read_exact(cx, length))?;
                    this.read_state = ReadState::Flush;
                }
                ReadState::Flush => {
                    let count = output.remaining().min(this.read_buf.len());
                    output.put_slice(&this.read_buf.split_to(count));
                    if this.read_buf.is_empty() {
                        this.read_state = ReadState::Header;
                    }
                    return Poll::Ready(Ok(()));
                }
            }
        }
    }
}

impl<S: AsyncWrite + Unpin> AsyncWrite for Stream<S> {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        input: &[u8],
    ) -> Poll<std::io::Result<usize>> {
        let this = self.get_mut();
        loop {
            match this.write_state {
                WriteState::Build => {
                    let auth_len = usize::from(this.first_auth.is_some()) * 8;
                    let consumed = input.len().min(MAX_PAYLOAD_SIZE - auth_len);
                    this.write_buf
                        .reserve(TLS_HEADER_SIZE + auth_len + consumed);
                    this.write_buf.put_slice(&[
                        APPLICATION_DATA,
                        TLS_MAJOR,
                        TLS_MINOR.0,
                    ]);
                    this.write_buf.put_u16((auth_len + consumed) as u16);
                    if let Some(auth) = this.first_auth.take() {
                        this.write_buf.put_slice(&auth);
                    }
                    this.write_buf.put_slice(&input[..consumed]);
                    this.write_state = WriteState::Flush {
                        consumed,
                        total: this.write_buf.len(),
                        written: 0,
                    };
                }
                WriteState::Flush {
                    consumed,
                    total,
                    written,
                } => {
                    let count = ready!(tokio_util::io::poll_write_buf(
                        Pin::new(&mut this.raw),
                        cx,
                        &mut this.write_buf,
                    ))?;
                    if count == 0 {
                        return Poll::Ready(Err(
                            std::io::ErrorKind::WriteZero.into()
                        ));
                    }
                    if written + count == total {
                        this.write_state = WriteState::Build;
                        return Poll::Ready(Ok(consumed));
                    }
                    this.write_state = WriteState::Flush {
                        consumed,
                        total,
                        written: written + count,
                    };
                }
            }
        }
    }

    fn poll_flush(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<std::io::Result<()>> {
        Pin::new(&mut self.get_mut().raw).poll_flush(cx)
    }

    fn poll_shutdown(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<std::io::Result<()>> {
        Pin::new(&mut self.get_mut().raw).poll_shutdown(cx)
    }
}

#[cfg(test)]
mod tests {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    use super::*;

    #[tokio::test]
    async fn frames_first_auth_and_reassembles_fragmented_response() {
        let (client, mut server) = tokio::io::duplex(256);
        let mut stream = Stream::new(client, *b"12345678");
        stream.write_all(b"query").await.unwrap();

        let mut request = [0; 18];
        server.read_exact(&mut request).await.unwrap();
        assert_eq!(&request[..5], &[0x17, 0x03, 0x03, 0, 13]);
        assert_eq!(&request[5..13], b"12345678");
        assert_eq!(&request[13..], b"query");

        for part in [&[0x17, 0x03][..], &[0x03, 0, 5, b'r', b'e'][..], b"ply"] {
            server.write_all(part).await.unwrap();
            tokio::task::yield_now().await;
        }
        let mut response = [0; 5];
        stream.read_exact(&mut response).await.unwrap();
        assert_eq!(&response, b"reply");
    }
}
