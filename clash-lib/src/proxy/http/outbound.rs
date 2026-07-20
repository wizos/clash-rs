use crate::{
    app::{
        dispatcher::{
            BoxedChainedDatagram, BoxedChainedStream, ChainedStream,
            ChainedStreamWrapper,
        },
        dns::ThreadSafeDNSResolver,
    },
    impl_default_connector,
    proxy::{
        AnyStream, ConnectorType, DialWithConnector, HandlerCommonOptions,
        OutboundHandler, OutboundType, PlainProxyAPIResponse,
        transport::Transport,
        utils::{GLOBAL_DIRECT_CONNECTOR, RemoteConnector},
    },
    session::Session,
};
use async_trait::async_trait;
use base64::{Engine, engine::general_purpose::STANDARD};
use erased_serde::Serialize as ErasedSerialize;
use std::{collections::HashMap, fmt::Debug, io, sync::Arc};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tracing::debug;

#[derive(Default)]
pub struct HandlerOptions {
    pub name: String,
    pub common_opts: HandlerCommonOptions,
    pub server: String,
    pub port: u16,
    pub username: Option<String>,
    pub password: Option<String>,
    pub headers: HashMap<String, String>,
    pub tls_client: Option<Box<dyn Transport>>,
}

pub struct Handler {
    opts: HandlerOptions,
    connector: tokio::sync::RwLock<Option<Arc<dyn RemoteConnector>>>,
}

impl_default_connector!(Handler);

impl Handler {
    pub fn new(opts: HandlerOptions) -> Self {
        Self {
            opts,
            connector: tokio::sync::RwLock::new(None),
        }
    }

    async fn connect_tunnel(
        &self,
        mut stream: AnyStream,
        sess: &Session,
    ) -> io::Result<AnyStream> {
        if let Some(tls_client) = self.opts.tls_client.as_ref() {
            stream = tls_client.proxy_stream(stream).await?;
        }

        let destination = sess.destination.to_string();
        let mut headers = HashMap::from([
            ("Host".to_string(), destination.clone()),
            ("User-Agent".to_string(), "clash-rs/0.10".to_string()),
            ("Proxy-Connection".to_string(), "Keep-Alive".to_string()),
        ]);
        headers.extend(self.opts.headers.clone());
        if let (Some(username), Some(password)) =
            (&self.opts.username, &self.opts.password)
            && !username.is_empty()
            && !password.is_empty()
        {
            let auth = STANDARD.encode(format!("{username}:{password}"));
            headers
                .insert("Proxy-Authorization".to_string(), format!("Basic {auth}"));
        }

        let mut request = format!("CONNECT {destination} HTTP/1.1\r\n");
        for (name, value) in headers {
            if name.contains(['\r', '\n']) || value.contains(['\r', '\n']) {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidInput,
                    "HTTP proxy header contains a line break",
                ));
            }
            request.push_str(&name);
            request.push_str(": ");
            request.push_str(&value);
            request.push_str("\r\n");
        }
        request.push_str("\r\n");
        stream.write_all(request.as_bytes()).await?;
        stream.flush().await?;

        let mut response = Vec::with_capacity(256);
        while response.len() < 64 * 1024 {
            let byte = stream.read_u8().await?;
            response.push(byte);
            if response.ends_with(b"\r\n\r\n") {
                break;
            }
        }
        if !response.ends_with(b"\r\n\r\n") {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "HTTP proxy response headers are too large",
            ));
        }
        let status_line = response
            .split(|byte| *byte == b'\n')
            .next()
            .and_then(|line| std::str::from_utf8(line).ok())
            .ok_or_else(|| {
                io::Error::new(
                    io::ErrorKind::InvalidData,
                    "invalid HTTP proxy response",
                )
            })?;
        let status = status_line
            .split_ascii_whitespace()
            .nth(1)
            .and_then(|value| value.parse::<u16>().ok())
            .ok_or_else(|| {
                io::Error::new(
                    io::ErrorKind::InvalidData,
                    "invalid HTTP proxy status",
                )
            })?;
        if status != 200 {
            return Err(io::Error::other(format!(
                "HTTP proxy CONNECT failed with status {status}"
            )));
        }
        Ok(stream)
    }
}

impl Debug for Handler {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("Http")
            .field("name", &self.opts.name)
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
        OutboundType::Http
    }

    async fn support_udp(&self) -> bool {
        false
    }

    async fn connect_stream(
        &self,
        sess: &Session,
        resolver: ThreadSafeDNSResolver,
    ) -> io::Result<BoxedChainedStream> {
        let connector = self.connector.read().await;
        if let Some(connector) = connector.as_ref() {
            debug!("{:?} is connecting via {:?}", self, connector);
        }
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
        _sess: &Session,
        _resolver: ThreadSafeDNSResolver,
    ) -> io::Result<BoxedChainedDatagram> {
        Err(io::Error::other("HTTP CONNECT proxy does not support UDP"))
    }

    async fn support_connector(&self) -> ConnectorType {
        ConnectorType::Tcp
    }

    async fn connect_stream_with_connector(
        &self,
        sess: &Session,
        resolver: ThreadSafeDNSResolver,
        connector: &dyn RemoteConnector,
    ) -> io::Result<BoxedChainedStream> {
        let stream = connector
            .connect_stream(
                resolver,
                &self.opts.server,
                self.opts.port,
                sess.iface.as_ref(),
                #[cfg(target_os = "linux")]
                sess.so_mark,
            )
            .await?;
        let stream = self.connect_tunnel(stream, sess).await?;
        let stream = ChainedStreamWrapper::new(stream);
        stream.append_to_chain(self.name()).await;
        Ok(Box::new(stream))
    }

    fn try_as_plain_handler(&self) -> Option<&dyn PlainProxyAPIResponse> {
        Some(self)
    }
}

#[async_trait]
impl PlainProxyAPIResponse for Handler {
    async fn as_map(&self) -> HashMap<String, Box<dyn ErasedSerialize + Send>> {
        let mut map = HashMap::new();
        map.insert(
            "server".to_string(),
            Box::new(self.opts.server.clone()) as _,
        );
        map.insert("port".to_string(), Box::new(self.opts.port) as _);
        if let Some(username) = &self.opts.username {
            map.insert("username".to_string(), Box::new(username.clone()) as _);
        }
        if self.opts.tls_client.is_some() {
            map.insert("tls".to_string(), Box::new(true) as _);
        }
        map
    }
}
