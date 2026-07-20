use std::{
    io,
    pin::Pin,
    sync::Arc,
    task::{Context, Poll},
};

use shadowsocks::{
    config::{ServerConfig, ServerType},
    context::Context as ShadowsocksContext,
    relay::tcprelay::crypto_io::{
        CryptoRead, CryptoStream, CryptoWrite, StreamType,
    },
};
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};

use crate::proxy::{AnyStream, shadowsocks::map_cipher};

use super::SsCipherOptions;

pub(super) struct Stream {
    context: Arc<ShadowsocksContext>,
    crypto: CryptoStream<AnyStream>,
}

impl Stream {
    pub(super) fn new(
        stream: AnyStream,
        options: &SsCipherOptions,
    ) -> io::Result<Self> {
        let method = map_cipher(&options.method)?;
        if method.is_aead_2022() {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "Trojan ss-opts does not support Shadowsocks 2022 ciphers",
            ));
        }
        let config = ServerConfig::new(("127.0.0.1", 1), &options.password, method)
            .map_err(io::Error::other)?;
        let context = ShadowsocksContext::new_shared(ServerType::Local);
        let crypto = CryptoStream::from_stream(
            &context,
            stream,
            StreamType::Client,
            method,
            config.key(),
        );
        Ok(Self { context, crypto })
    }
}

impl AsyncRead for Stream {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buffer: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        Pin::new(&mut this.crypto)
            .poll_read_decrypted(cx, &this.context, buffer)
            .map_err(Into::into)
    }
}

impl AsyncWrite for Stream {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buffer: &[u8],
    ) -> Poll<io::Result<usize>> {
        Pin::new(&mut self.get_mut().crypto)
            .poll_write_encrypted(cx, buffer)
            .map_err(Into::into)
    }

    fn poll_flush(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<io::Result<()>> {
        self.get_mut().crypto.poll_flush(cx).map_err(Into::into)
    }

    fn poll_shutdown(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<io::Result<()>> {
        self.get_mut().crypto.poll_shutdown(cx).map_err(Into::into)
    }
}

#[cfg(test)]
mod tests {
    use futures::future::poll_fn;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    use super::*;

    #[tokio::test]
    async fn interoperates_with_server_crypto_stream_without_address_header() {
        let options = SsCipherOptions {
            method: "aes-128-gcm".to_owned(),
            password: "inner-secret".to_owned(),
        };
        let method = map_cipher(&options.method).unwrap();
        let config =
            ServerConfig::new(("127.0.0.1", 1), &options.password, method).unwrap();
        let (client_io, server_io) = tokio::io::duplex(4096);
        let mut client = Stream::new(Box::new(client_io), &options).unwrap();
        let server_context = ShadowsocksContext::new_shared(ServerType::Server);
        let mut server = CryptoStream::from_stream(
            &server_context,
            server_io,
            StreamType::Server,
            method,
            config.key(),
        );

        client.write_all(b"trojan-header").await.unwrap();
        client.flush().await.unwrap();
        let mut request = [0; 13];
        let mut request_buf = ReadBuf::new(&mut request);
        poll_fn(|cx| {
            Pin::new(&mut server).poll_read_decrypted(
                cx,
                &server_context,
                &mut request_buf,
            )
        })
        .await
        .unwrap();
        assert_eq!(request_buf.filled(), b"trojan-header");

        poll_fn(|cx| Pin::new(&mut server).poll_write_encrypted(cx, b"reply"))
            .await
            .unwrap();
        poll_fn(|cx| server.poll_flush(cx)).await.unwrap();
        let mut response = [0; 5];
        client.read_exact(&mut response).await.unwrap();
        assert_eq!(&response, b"reply");
    }
}
