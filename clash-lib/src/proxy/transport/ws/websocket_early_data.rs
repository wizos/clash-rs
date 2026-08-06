use std::{
    cmp,
    fmt::Debug,
    pin::Pin,
    task::{Poll, Waker},
};

use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use futures::{Future, ready};
use http::{HeaderValue, Request, StatusCode};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio_tungstenite::{
    WebSocketStream,
    tungstenite::{
        handshake::{client::generate_request, derive_accept_key},
        protocol::{Role, WebSocketConfig},
    },
};

use crate::{
    common::errors::{map_io_error, new_io_error},
    proxy::AnyStream,
};

use super::websocket::WebsocketConn;

pub struct WebsocketEarlyDataConn {
    stream: Option<AnyStream>,
    req: Option<Request<()>>,
    stream_future: Option<
        Pin<
            Box<
                dyn std::future::Future<Output = std::io::Result<AnyStream>>
                    + Send
                    + Sync,
            >,
        >,
    >,
    early_waker: Option<Waker>,
    flush_waker: Option<Waker>,
    ws_config: Option<WebSocketConfig>,
    early_data_header_name: String,
    early_data_len: usize,
    early_data_flushed: bool,
}

impl Debug for WebsocketEarlyDataConn {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("WebsocketEarlyDataConn")
            .field("req", &self.req)
            .field("early_waker", &self.early_waker)
            .field("flush_waker", &self.flush_waker)
            .field("ws_config", &self.ws_config)
            .field("early_data_header_name", &self.early_data_header_name)
            .field("early_data_len", &self.early_data_len)
            .field("early_data_flushed", &self.early_data_flushed)
            .finish()
    }
}

impl WebsocketEarlyDataConn {
    pub fn new(
        stream: AnyStream,
        req: Request<()>,
        ws_config: Option<WebSocketConfig>,
        early_data_header_name: String,
        early_data_len: usize,
    ) -> Self {
        Self {
            stream: Some(stream),
            req: Some(req),
            stream_future: None,
            early_waker: None,
            flush_waker: None,
            ws_config,
            early_data_header_name,
            early_data_len,
            early_data_flushed: false,
        }
    }

    fn proxy_stream(
        stream: AnyStream,
        req: Request<()>,
        config: Option<WebSocketConfig>,
    ) -> Pin<
        Box<
            dyn std::future::Future<Output = std::io::Result<AnyStream>>
                + Send
                + Sync,
        >,
    > {
        async fn run(
            mut stream: AnyStream,
            req: Request<()>,
            config: Option<WebSocketConfig>,
        ) -> std::io::Result<AnyStream> {
            let (request, key) = generate_request(req).map_err(map_io_error)?;
            stream.write_all(&request).await?;
            stream.flush().await?;

            let mut response = Vec::with_capacity(1024);
            let header_end = loop {
                if let Some(position) =
                    response.windows(4).position(|v| v == b"\r\n\r\n")
                {
                    break position + 4;
                }
                if response.len() >= MAX_HANDSHAKE_RESPONSE_SIZE {
                    return Err(new_io_error(
                        "websocket handshake response is too large",
                    ));
                }
                let mut buffer = [0_u8; 1024];
                let remaining = MAX_HANDSHAKE_RESPONSE_SIZE - response.len();
                let read_len = cmp::min(buffer.len(), remaining);
                let size = stream.read(&mut buffer[..read_len]).await?;
                if size == 0 {
                    return Err(new_io_error(
                        "websocket server closed during handshake",
                    ));
                }
                response.extend_from_slice(&buffer[..size]);
            };

            validate_response(&response[..header_end], &key)?;
            let tail = response.split_off(header_end);
            let websocket = WebSocketStream::from_partially_read(
                stream,
                tail,
                Role::Client,
                config,
            )
            .await;
            let rv = Box::new(WebsocketConn::from_websocket(websocket));
            Ok(rv)
        }

        Box::pin(run(stream, req, config))
    }
}

const MAX_HANDSHAKE_RESPONSE_SIZE: usize = 64 * 1024;

fn validate_response(response: &[u8], key: &str) -> std::io::Result<()> {
    let mut headers = [httparse::EMPTY_HEADER; 64];
    let mut parsed = httparse::Response::new(&mut headers);
    if !parsed.parse(response).map_err(map_io_error)?.is_complete() {
        return Err(new_io_error("incomplete websocket handshake response"));
    }
    if parsed.code != Some(StatusCode::SWITCHING_PROTOCOLS.as_u16()) {
        return Err(new_io_error(format!(
            "websocket handshake returned status {}",
            parsed.code.unwrap_or_default(),
        )));
    }

    let header = |name: &str| {
        parsed
            .headers
            .iter()
            .find(|header| header.name.eq_ignore_ascii_case(name))
            .and_then(|header| std::str::from_utf8(header.value).ok())
    };
    let upgrade_valid = header("Upgrade")
        .is_some_and(|value| value.eq_ignore_ascii_case("websocket"));
    let connection_valid = header("Connection").is_some_and(|value| {
        value
            .split(',')
            .any(|token| token.trim().eq_ignore_ascii_case("upgrade"))
    });
    let accept_valid = header("Sec-WebSocket-Accept")
        .is_some_and(|value| value.trim() == derive_accept_key(key.as_bytes()));
    if !upgrade_valid || !connection_valid || !accept_valid {
        return Err(new_io_error("invalid websocket handshake response"));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use http::Request;

    #[tokio::test]
    async fn accepts_early_data_response_without_subprotocol_echo() {
        let (client, mut server) = tokio::io::duplex(4096);
        let server_task = tokio::spawn(async move {
            let mut request = vec![0_u8; 2048];
            let size = server.read(&mut request).await.unwrap();
            let request = String::from_utf8_lossy(&request[..size]);
            assert!(request.contains("Sec-WebSocket-Protocol: ZGF0YQ"));
            server
                .write_all(
                    b"HTTP/1.1 101 Switching Protocols\r\n\
Upgrade: websocket\r\n\
Connection: Upgrade\r\n\
Sec-WebSocket-Accept: s3pPLMBiTxaQ9kYGzzhZRbK+xOo=\r\n\r\n",
                )
                .await
                .unwrap();
        });
        let request = Request::builder()
            .method("GET")
            .uri("ws://example.com/")
            .header("Host", "example.com")
            .header("Connection", "Upgrade")
            .header("Upgrade", "websocket")
            .header("Sec-WebSocket-Version", "13")
            .header("Sec-WebSocket-Key", "dGhlIHNhbXBsZSBub25jZQ==")
            .header("Sec-WebSocket-Protocol", "ZGF0YQ")
            .body(())
            .unwrap();

        let result =
            WebsocketEarlyDataConn::proxy_stream(Box::new(client), request, None)
                .await;

        assert!(result.is_ok());
        server_task.await.unwrap();
    }
}

impl AsyncRead for WebsocketEarlyDataConn {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        buf: &mut tokio::io::ReadBuf<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        if !self.early_data_flushed {
            if self.early_waker.is_none() {
                self.as_mut().early_waker = Some(cx.waker().clone());
            }
            return Poll::Pending;
        }
        let pin = self.get_mut();
        match &mut pin.stream {
            None => unreachable!("bad state"),
            Some(s) => Pin::new(s).poll_read(cx, buf),
        }
    }
}

impl AsyncWrite for WebsocketEarlyDataConn {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        buf: &[u8],
    ) -> Poll<Result<usize, std::io::Error>> {
        if !self.early_data_flushed {
            loop {
                match &mut self.as_mut().stream_future {
                    Some(fut) => {
                        let stream = ready!(Pin::new(fut).poll(cx))?;

                        self.as_mut().stream = Some(stream);
                        self.as_mut().early_data_flushed = true;

                        if let Some(w) = self.as_mut().early_waker.take() {
                            w.wake();
                        }
                        if let Some(w) = self.as_mut().flush_waker.take() {
                            w.wake();
                        }
                        return Poll::Ready(Ok(self.as_mut().early_data_len));
                    }
                    _ => {
                        let mut req =
                            self.as_mut().req.take().expect("req must be present");
                        if let Some(v) = req
                            .headers_mut()
                            .get_mut(&self.as_mut().early_data_header_name)
                        {
                            self.as_mut().early_data_len =
                                cmp::min(self.as_mut().early_data_len, buf.len());
                            let header_value = URL_SAFE_NO_PAD
                                .encode(&buf[..self.as_mut().early_data_len]);
                            *v = HeaderValue::from_str(&header_value)
                                .expect("bad header value");
                        }

                        let stream =
                            self.as_mut().stream.take().expect("msg: bad state");
                        let config = self.as_mut().ws_config.take();
                        self.as_mut().stream_future =
                            Some(Self::proxy_stream(stream, req, config));
                    }
                }
            }
        }

        match &mut self.as_mut().stream {
            None => unreachable!("bad state"),
            Some(s) => Pin::new(s).poll_write(cx, buf),
        }
    }

    fn poll_flush(
        mut self: Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> Poll<Result<(), std::io::Error>> {
        if !self.early_data_flushed {
            if self.as_mut().flush_waker.is_none() {
                self.as_mut().flush_waker = Some(cx.waker().clone());
            }
            return Poll::Pending;
        }
        match &mut self.stream {
            None => unreachable!("bad state"),
            Some(s) => Pin::new(s).poll_flush(cx),
        }
    }

    fn poll_shutdown(
        mut self: Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> Poll<Result<(), std::io::Error>> {
        if !self.early_data_flushed {
            ready!(self.as_mut().poll_flush(cx))?;
        }
        let pin = self.get_mut();
        match &mut pin.stream {
            None => unreachable!("bad state"),
            Some(s) => Pin::new(s).poll_shutdown(cx),
        }
    }
}
