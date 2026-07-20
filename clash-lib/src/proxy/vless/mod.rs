use self::{
    encryption::ClientInstance as VlessEncryptionClient, stream::VlessStream,
    vision::VisionStream,
};
use super::{
    AnyStream, ConnectorType, DialWithConnector, HandlerCommonOptions,
    OutboundHandler, OutboundType, PlainProxyAPIResponse,
    transport::{Transport, VisionOptions},
    utils::{GLOBAL_DIRECT_CONNECTOR, RemoteConnector},
};
use crate::{
    app::{
        dispatcher::{
            BoxedChainedDatagram, BoxedChainedStream, ChainedDatagram,
            ChainedDatagramWrapper, ChainedStream, ChainedStreamWrapper,
        },
        dns::ThreadSafeDNSResolver,
    },
    impl_default_connector,
    proxy::vless::datagram::OutboundDatagramVless,
    session::Session,
};
use async_trait::async_trait;
use erased_serde::Serialize as ErasedSerialize;
use std::{collections::HashMap, io, sync::Arc};
use tracing::debug;

mod datagram;
pub(crate) mod encryption;
mod stream;
mod vision;

pub struct HandlerOptions {
    pub name: String,
    pub common_opts: HandlerCommonOptions,
    pub server: String,
    pub port: u16,
    pub uuid: String,
    pub udp: bool,
    pub packet_addr: bool,
    pub xudp: bool,
    pub encryption: Option<Arc<VlessEncryptionClient>>,
    pub transport: Option<Box<dyn Transport>>,
    pub tls: Option<Box<dyn Transport>>,
    pub additional_streams: Vec<TransportStreamOptions>,
    pub additional_datagrams: Vec<TransportDatagramOptions>,
    pub flow: Option<String>,
}

pub struct TransportStreamOptions {
    pub server: String,
    pub port: u16,
    pub tls: Option<Box<dyn Transport>>,
}

pub struct TransportDatagramOptions {
    pub server: String,
    pub port: u16,
}

pub struct Handler {
    opts: HandlerOptions,
    connector: tokio::sync::RwLock<Option<Arc<dyn RemoteConnector>>>,
}

impl std::fmt::Debug for Handler {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Vless")
            .field("name", &self.opts.name)
            .finish()
    }
}

impl_default_connector!(Handler);

impl Handler {
    pub fn new(opts: HandlerOptions) -> Self {
        Self {
            opts,
            connector: Default::default(),
        }
    }

    async fn inner_proxy_stream_with_additional(
        &self,
        s: AnyStream,
        additional_streams: Vec<AnyStream>,
        additional_datagrams: Vec<(
            super::AnyOutboundDatagram,
            crate::session::SocksAddr,
            std::net::SocketAddr,
        )>,
        sess: &Session,
        is_udp: bool,
    ) -> io::Result<AnyStream> {
        let (s, vision_opts) = if let Some(tls) = self.opts.tls.as_ref() {
            tls.proxy_stream_spliced(s).await?
        } else {
            (s, None)
        };

        let s = if let Some(transport) = self.opts.transport.as_ref() {
            transport
                .proxy_stream_with_additional_mixed(
                    s,
                    additional_streams,
                    additional_datagrams,
                )
                .await?
        } else {
            debug_assert!(additional_streams.is_empty());
            debug_assert!(additional_datagrams.is_empty());
            s
        };

        let s = if let Some(encryption) = self.opts.encryption.as_ref() {
            encryption.handshake(s).await?
        } else {
            s
        };

        self.wrap_vless_stream(s, sess, is_udp, vision_opts)
    }

    fn wrap_vless_stream(
        &self,
        s: AnyStream,
        sess: &Session,
        is_udp: bool,
        vision_opts: Option<VisionOptions>,
    ) -> io::Result<AnyStream> {
        let destination = if is_udp && self.opts.packet_addr {
            super::packetaddr::magic_destination()
        } else {
            sess.destination.clone()
        };
        let vless_stream = VlessStream::new(
            s,
            &self.opts.uuid,
            &destination,
            is_udp,
            is_udp && self.opts.xudp,
            self.opts.flow.clone(),
        )?;

        if self.opts.flow.as_deref() == Some("xtls-rprx-vision") {
            Ok(Box::new(VisionStream::new(
                Box::new(vless_stream),
                self.opts.uuid.clone(),
                vision_opts,
            )?))
        } else {
            Ok(Box::new(vless_stream))
        }
    }

    async fn open_datagram_transport(
        &self,
        connector: &dyn RemoteConnector,
        sess: &Session,
        resolver: ThreadSafeDNSResolver,
        is_udp: bool,
    ) -> io::Result<AnyStream> {
        if self.opts.tls.is_some() {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "datagram transport must provide its own TLS layer",
            ));
        }
        let transport = self.opts.transport.as_ref().ok_or_else(|| {
            io::Error::new(
                io::ErrorKind::InvalidInput,
                "missing VLESS datagram transport",
            )
        })?;
        let remote_ip = resolver
            .resolve(&self.opts.server, true)
            .await
            .map_err(io::Error::other)?
            .ok_or_else(|| {
                io::Error::new(
                    io::ErrorKind::NotFound,
                    format!("failed to resolve VLESS server {}", self.opts.server),
                )
            })?;
        let remote_addr = std::net::SocketAddr::new(remote_ip, self.opts.port);
        let destination = crate::session::SocksAddr::Domain(
            self.opts.server.clone(),
            self.opts.port,
        );
        let datagram = connector
            .connect_datagram(
                resolver.clone(),
                None,
                destination.clone(),
                sess.iface.as_ref(),
                #[cfg(target_os = "linux")]
                sess.so_mark,
            )
            .await?;
        let additional_streams = self
            .open_additional_streams(connector, sess, resolver.clone())
            .await?;
        let additional_datagrams = self
            .open_additional_datagrams(connector, sess, resolver.clone())
            .await?;
        let stream = transport
            .proxy_datagram_with_additional_mixed(
                datagram,
                destination,
                remote_addr,
                additional_streams,
                additional_datagrams,
            )
            .await?;
        let stream = if let Some(encryption) = self.opts.encryption.as_ref() {
            encryption.handshake(stream).await?
        } else {
            stream
        };
        self.wrap_vless_stream(stream, sess, is_udp, None)
    }

    async fn open_additional_datagrams(
        &self,
        connector: &dyn RemoteConnector,
        sess: &Session,
        resolver: ThreadSafeDNSResolver,
    ) -> io::Result<
        Vec<(
            super::AnyOutboundDatagram,
            crate::session::SocksAddr,
            std::net::SocketAddr,
        )>,
    > {
        let count = self
            .opts
            .transport
            .as_ref()
            .map(|transport| transport.additional_datagrams())
            .unwrap_or_default();
        if self.opts.additional_datagrams.len() != count {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                format!(
                    "VLESS transport requires {count} additional datagrams, but {} \
                     were configured",
                    self.opts.additional_datagrams.len()
                ),
            ));
        }
        let mut additional = Vec::with_capacity(count);
        for options in &self.opts.additional_datagrams {
            let remote_ip = resolver
                .resolve(&options.server, true)
                .await
                .map_err(io::Error::other)?
                .ok_or_else(|| {
                    io::Error::new(
                        io::ErrorKind::NotFound,
                        format!(
                            "failed to resolve VLESS download server {}",
                            options.server
                        ),
                    )
                })?;
            let remote_addr = std::net::SocketAddr::new(remote_ip, options.port);
            let destination = crate::session::SocksAddr::Domain(
                options.server.clone(),
                options.port,
            );
            let datagram = connector
                .connect_datagram(
                    resolver.clone(),
                    None,
                    destination.clone(),
                    sess.iface.as_ref(),
                    #[cfg(target_os = "linux")]
                    sess.so_mark,
                )
                .await?;
            additional.push((datagram, destination, remote_addr));
        }
        Ok(additional)
    }

    async fn open_additional_streams(
        &self,
        connector: &dyn RemoteConnector,
        sess: &Session,
        resolver: ThreadSafeDNSResolver,
    ) -> io::Result<Vec<AnyStream>> {
        let count = self
            .opts
            .transport
            .as_ref()
            .map(|transport| transport.additional_streams())
            .unwrap_or_default();
        if !self.opts.additional_streams.is_empty()
            && self.opts.additional_streams.len() != count
        {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                format!(
                    "VLESS transport requires {count} additional streams, but {} \
                     were configured",
                    self.opts.additional_streams.len()
                ),
            ));
        }
        let mut streams = Vec::with_capacity(count);
        for index in 0..count {
            let configured = self.opts.additional_streams.get(index);
            let server = configured
                .map(|options| options.server.as_str())
                .unwrap_or(self.opts.server.as_str());
            let port = configured
                .map(|options| options.port)
                .unwrap_or(self.opts.port);
            let stream = connector
                .connect_stream(
                    resolver.clone(),
                    server,
                    port,
                    sess.iface.as_ref(),
                    #[cfg(target_os = "linux")]
                    sess.so_mark,
                )
                .await?;
            let tls = configured
                .and_then(|options| options.tls.as_ref())
                .or(self.opts.tls.as_ref());
            streams.push(if let Some(tls) = tls {
                tls.proxy_stream(stream).await?
            } else {
                stream
            });
        }
        Ok(streams)
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
        OutboundType::Vless
    }

    async fn support_udp(&self) -> bool {
        self.opts.udp
    }

    async fn connect_stream(
        &self,
        sess: &Session,
        resolver: ThreadSafeDNSResolver,
    ) -> io::Result<BoxedChainedStream> {
        let dialer = self.connector.read().await;

        if let Some(dialer) = dialer.as_ref() {
            debug!("{:?} is connecting via {:?}", self, dialer);
        }

        self.connect_stream_with_connector(
            sess,
            resolver,
            dialer
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
        let dialer = self.connector.read().await;

        if let Some(dialer) = dialer.as_ref() {
            debug!("{:?} is connecting via {:?}", self, dialer);
        }

        self.connect_datagram_with_connector(
            sess,
            resolver,
            dialer
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
        if self
            .opts
            .transport
            .as_ref()
            .is_some_and(|transport| transport.uses_datagram())
        {
            let s = self
                .open_datagram_transport(connector, sess, resolver, false)
                .await?;
            let chained = ChainedStreamWrapper::new(s);
            chained.append_to_chain(self.name()).await;
            return Ok(Box::new(chained));
        }
        let stream = connector
            .connect_stream(
                resolver.clone(),
                self.opts.server.as_str(),
                self.opts.port,
                sess.iface.as_ref(),
                #[cfg(target_os = "linux")]
                sess.so_mark,
            )
            .await?;
        let additional = self
            .open_additional_streams(connector, sess, resolver.clone())
            .await?;
        let additional_datagrams = self
            .open_additional_datagrams(connector, sess, resolver.clone())
            .await?;
        let s = self
            .inner_proxy_stream_with_additional(
                stream,
                additional,
                additional_datagrams,
                sess,
                false,
            )
            .await?;
        let chained = ChainedStreamWrapper::new(s);
        chained.append_to_chain(self.name()).await;
        Ok(Box::new(chained))
    }

    async fn connect_datagram_with_connector(
        &self,
        sess: &Session,
        resolver: ThreadSafeDNSResolver,
        connector: &dyn RemoteConnector,
    ) -> io::Result<BoxedChainedDatagram> {
        let stream = if self
            .opts
            .transport
            .as_ref()
            .is_some_and(|transport| transport.uses_datagram())
        {
            self.open_datagram_transport(connector, sess, resolver, true)
                .await?
        } else {
            let stream = connector
                .connect_stream(
                    resolver.clone(),
                    self.opts.server.as_str(),
                    self.opts.port,
                    sess.iface.as_ref(),
                    #[cfg(target_os = "linux")]
                    sess.so_mark,
                )
                .await?;
            let additional = self
                .open_additional_streams(connector, sess, resolver.clone())
                .await?;
            let additional_datagrams = self
                .open_additional_datagrams(connector, sess, resolver.clone())
                .await?;
            self.inner_proxy_stream_with_additional(
                stream,
                additional,
                additional_datagrams,
                sess,
                true,
            )
            .await?
        };
        if self.opts.xudp {
            let datagram = super::xudp::OutboundDatagramXudp::new(
                stream,
                sess.destination.clone(),
                sess.source,
            );
            let chained = ChainedDatagramWrapper::new(datagram);
            chained.append_to_chain(self.name()).await;
            Ok(Box::new(chained))
        } else {
            let datagram = OutboundDatagramVless::new(
                stream,
                sess.destination.clone(),
                self.opts.packet_addr,
            );
            let chained = ChainedDatagramWrapper::new(datagram);
            chained.append_to_chain(self.name()).await;
            Ok(Box::new(chained))
        }
    }

    fn try_as_plain_handler(&self) -> Option<&dyn PlainProxyAPIResponse> {
        Some(self as _)
    }
}

#[async_trait]
impl PlainProxyAPIResponse for Handler {
    async fn as_map(&self) -> HashMap<String, Box<dyn ErasedSerialize + Send>> {
        let mut m = HashMap::new();
        m.insert("server".to_owned(), Box::new(self.opts.server.clone()) as _);
        m.insert("port".to_owned(), Box::new(self.opts.port) as _);
        m.insert("uuid".to_owned(), Box::new(self.opts.uuid.clone()) as _);
        if self.opts.tls.is_some() {
            m.insert("tls".to_owned(), Box::new(true) as _);
        }
        m
    }
}

#[cfg(all(test, docker_test))]
mod tests {
    use std::{collections::HashMap, io::Write};

    use super::*;
    use crate::{
        proxy::{
            transport::{TlsClient, WsClient},
            utils::test_utils::{
                Suite,
                docker_utils::{
                    config_helper::test_config_base_dir,
                    consts::*,
                    docker_runner::{
                        DockerTestRunner, DockerTestRunnerBuilder, alloc_docker_port,
                    },
                },
                run_test_suites_and_cleanup,
            },
        },
        tests::initialize,
    };

    const VLESS_WS_TLS_SERVER_CONFIG: &str = r#"{
    "log": {
        "loglevel": "debug"
    },
    "inbounds": [
        {
            "port": 8443,
            "protocol": "vless",
            "settings": {
                "clients": [
                    {
                        "id": "b831381d-6324-4d53-ad4f-8cda48b30811",
                        "level": 0,
                        "email": "love@v2fly.org"
                    }
                ],
                "decryption": "none",
                "fallbacks": [
                    {
                        "dest": 80
                    },
                    {
                        "path": "/websocket",
                        "dest": 1234,
                        "xver": 1
                    }
                ]
            },
            "streamSettings": {
                "network": "tcp",
                "security": "tls",
                "tlsSettings": {
                    "alpn": [
                        "http/1.1"
                    ],
                    "certificates": [
                        {
                            "certificateFile": "/etc/ssl/v2ray/fullchain.pem",
                            "keyFile": "/etc/ssl/v2ray/privkey.pem"
                        }
                    ]
                }
            }
        },
        {
            "port": 1234,
            "listen": "127.0.0.1",
            "protocol": "vless",
            "settings": {
                "clients": [
                    {
                        "id": "b831381d-6324-4d53-ad4f-8cda48b30811",
                        "level": 0,
                        "email": "love@v2fly.org"
                    }
                ],
                "decryption": "none"
            },
            "streamSettings": {
                "network": "ws",
                "security": "none",
                "wsSettings": {
                    "acceptProxyProtocol": true,
                    "path": "/websocket"
                }
            }
        }
    ],
    "outbounds": [
        {
            "protocol": "freedom"
        }
    ]
}"#;

    fn tls_client(alpn: Option<Vec<String>>) -> Option<Box<dyn Transport>> {
        Some(Box::new(
            TlsClient::new(true, "example.org".to_owned(), alpn, None, None, None)
                .expect("failed to create TLS client"),
        ))
    }

    async fn get_ws_runner(host_port: u16) -> anyhow::Result<DockerTestRunner> {
        let test_config_dir = test_config_base_dir();
        let cert = test_config_dir.join("certs/example.org.pem");
        let key = test_config_dir.join("certs/example.org-key.pem");

        let mut tmp = tempfile::NamedTempFile::new()?;
        tmp.write_all(VLESS_WS_TLS_SERVER_CONFIG.as_bytes())?;

        let result = DockerTestRunnerBuilder::new()
            .image(IMAGE_VLESS)
            .host_port(host_port, 8443)
            .mounts(&[
                (tmp.path().to_str().unwrap(), "/etc/v2ray/config.json"),
                (cert.to_str().unwrap(), "/etc/ssl/v2ray/fullchain.pem"),
                (key.to_str().unwrap(), "/etc/ssl/v2ray/privkey.pem"),
            ])
            .build()
            .await;
        drop(tmp);
        result
    }

    #[tokio::test]
    async fn test_vless_ws() -> anyhow::Result<()> {
        initialize();
        let span = tracing::info_span!("test_vless_ws");
        let _enter = span.enter();
        let host_port = alloc_docker_port();
        let ws_client = WsClient::new(
            "".to_owned(),
            8443,
            "/websocket".to_owned(),
            [("Host".to_owned(), "example.org".to_owned())]
                .into_iter()
                .collect::<HashMap<_, _>>(),
            None,
            0,
            "".to_owned(),
        );
        let runner = get_ws_runner(host_port).await?;
        let opts = HandlerOptions {
            name: "test-vless-ws".into(),
            common_opts: Default::default(),
            server: runner.container_ip().unwrap_or(LOCAL_ADDR.to_owned()),
            port: 8443,
            uuid: "b831381d-6324-4d53-ad4f-8cda48b30811".into(),
            udp: true,
            packet_addr: false,
            xudp: false,
            encryption: None,
            tls: tls_client(None),
            transport: Some(Box::new(ws_client)),
            additional_streams: Vec::new(),
            additional_datagrams: Vec::new(),
            flow: None,
        };
        let handler = Arc::new(Handler::new(opts));

        run_test_suites_and_cleanup(handler, runner, Suite::all()).await
    }
}

#[cfg(all(test, docker_test, throughput_test))]
mod e2e {
    use crate::{
        proxy::utils::test_utils::{
            config_helper,
            consts::*,
            docker_runner::{
                DockerTestRunner, DockerTestRunnerBuilder, RunAndCleanup,
            },
            docker_utils::{
                alloc_port, clash_process_e2e_throughput, find_clash_rs_binary,
            },
        },
        tests::initialize,
    };

    // Outer TLS inbound on port 8443; WS fallback on 127.0.0.1:1234
    const CONTAINER_PORT: u16 = 8443;
    const CONTAINER_PORT_XRAY: u16 = 10002;
    const UUID: &str = "b831381d-6324-4d53-ad4f-8cda48b30811";
    const E2E_PAYLOAD_BYTES: usize = 32 * 1024 * 1024; // 32 MB

    const VLESS_WS_TLS_SERVER_CONFIG: &str = r#"{
    "inbounds": [
        {
            "port": 8443,
            "protocol": "vless",
            "settings": {
                "clients": [{"id": "b831381d-6324-4d53-ad4f-8cda48b30811", "level": 0}],
                "decryption": "none",
                "fallbacks": [
                    {"dest": 80},
                    {"path": "/websocket", "dest": 1234, "xver": 1}
                ]
            },
            "streamSettings": {
                "network": "tcp",
                "security": "tls",
                "tlsSettings": {
                    "alpn": ["http/1.1"],
                    "certificates": [{"certificateFile": "/etc/ssl/v2ray/fullchain.pem", "keyFile": "/etc/ssl/v2ray/privkey.pem"}]
                }
            }
        },
        {
            "port": 1234,
            "listen": "127.0.0.1",
            "protocol": "vless",
            "settings": {
                "clients": [{"id": "b831381d-6324-4d53-ad4f-8cda48b30811", "level": 0}],
                "decryption": "none"
            },
            "streamSettings": {
                "network": "ws",
                "security": "none",
                "wsSettings": {"acceptProxyProtocol": true, "path": "/websocket"}
            }
        }
    ],
    "outbounds": [{"protocol": "freedom"}]
}"#;

    async fn get_ws_runner() -> anyhow::Result<DockerTestRunner> {
        let test_config_dir = config_helper::test_config_base_dir();
        let cert = test_config_dir.join("certs/example.org.pem");
        let key = test_config_dir.join("certs/example.org-key.pem");
        let mut tmp = tempfile::NamedTempFile::new()?;
        use std::io::Write as _;
        tmp.write_all(VLESS_WS_TLS_SERVER_CONFIG.as_bytes())?;
        let result = DockerTestRunnerBuilder::new()
            .image(IMAGE_VLESS)
            .no_port()
            .mounts(&[
                (tmp.path().to_str().unwrap(), "/etc/v2ray/config.json"),
                (cert.to_str().unwrap(), "/etc/ssl/v2ray/fullchain.pem"),
                (key.to_str().unwrap(), "/etc/ssl/v2ray/privkey.pem"),
            ])
            .build()
            .await;
        drop(tmp);
        result
    }

    const VLESS_GRPC_SERVER_CONFIG: &str = r#"{
    "inbounds": [{"port": 10002, "listen": "0.0.0.0", "protocol": "vless",
        "settings": {"clients": [{"id": "b831381d-6324-4d53-ad4f-8cda48b30811", "flow": ""}], "decryption": "none"},
        "streamSettings": {"network": "grpc", "security": "tls",
            "tlsSettings": {"certificates": [{"certificateFile": "/etc/ssl/v2ray/fullchain.pem", "keyFile": "/etc/ssl/v2ray/privkey.pem"}]},
            "grpcSettings": {"serviceName": "grpc"}}}],
    "outbounds": [{"protocol": "freedom"}]
}"#;

    const VLESS_H2_SERVER_CONFIG: &str = r#"{
    "inbounds": [{"port": 10002, "listen": "0.0.0.0", "protocol": "vless",
        "settings": {"clients": [{"id": "b831381d-6324-4d53-ad4f-8cda48b30811", "flow": ""}], "decryption": "none"},
        "streamSettings": {"network": "h2", "security": "tls",
            "tlsSettings": {"certificates": [{"certificateFile": "/etc/ssl/v2ray/fullchain.pem", "keyFile": "/etc/ssl/v2ray/privkey.pem"}]},
            "httpSettings": {"host": ["example.org"], "path": "/"}}}],
    "outbounds": [{"protocol": "freedom"}]
}"#;

    async fn get_grpc_runner() -> anyhow::Result<DockerTestRunner> {
        let test_config_dir = config_helper::test_config_base_dir();
        let cert = test_config_dir.join("certs/example.org.pem");
        let key = test_config_dir.join("certs/example.org-key.pem");
        let mut tmp = tempfile::NamedTempFile::new()?;
        use std::io::Write as _;
        tmp.write_all(VLESS_GRPC_SERVER_CONFIG.as_bytes())?;
        let result = DockerTestRunnerBuilder::new()
            .image(IMAGE_XRAY)
            .no_port()
            .mounts(&[
                (tmp.path().to_str().unwrap(), "/etc/xray/config.json"),
                (cert.to_str().unwrap(), "/etc/ssl/v2ray/fullchain.pem"),
                (key.to_str().unwrap(), "/etc/ssl/v2ray/privkey.pem"),
            ])
            .build()
            .await;
        drop(tmp);
        result
    }

    async fn get_h2_runner() -> anyhow::Result<DockerTestRunner> {
        let test_config_dir = config_helper::test_config_base_dir();
        let cert = test_config_dir.join("certs/example.org.pem");
        let key = test_config_dir.join("certs/example.org-key.pem");
        let mut tmp = tempfile::NamedTempFile::new()?;
        use std::io::Write as _;
        tmp.write_all(VLESS_H2_SERVER_CONFIG.as_bytes())?;
        let result = DockerTestRunnerBuilder::new()
            .image(IMAGE_XRAY)
            .no_port()
            .mounts(&[
                (tmp.path().to_str().unwrap(), "/etc/xray/config.json"),
                (cert.to_str().unwrap(), "/etc/ssl/v2ray/fullchain.pem"),
                (key.to_str().unwrap(), "/etc/ssl/v2ray/privkey.pem"),
            ])
            .build()
            .await;
        drop(tmp);
        result
    }

    #[tokio::test]
    async fn e2e_throughput_vless_ws() -> anyhow::Result<()> {
        initialize();
        let socks_port = alloc_port();
        let echo_port = alloc_port();

        let container = get_ws_runner().await?;
        let server = container
            .container_ip()
            .ok_or_else(|| anyhow::anyhow!("vless container has no IP"))?;
        let gateway_ip = container.docker_gateway_ip();

        let mmdb = config_helper::test_config_base_dir()
            .join("Country.mmdb")
            .to_str()
            .unwrap()
            .to_owned();
        let config = format!(
            r#"
socks-port: {socks_port}
bind-address: 127.0.0.1
mmdb: "{mmdb}"
mode: global
log-level: error
proxies:
  - name: proxy
    type: vless
    server: {server}
    port: {port}
    uuid: {uuid}
    udp: false
    tls: true
    skip-cert-verify: true
    network: ws
    ws-opts:
      path: /websocket
      headers:
        Host: example.org
rules:
  - MATCH,proxy
"#,
            socks_port = socks_port,
            mmdb = mmdb,
            server = server,
            port = CONTAINER_PORT,
            uuid = UUID,
        );
        let binary = find_clash_rs_binary();

        container
            .run_and_cleanup(async move {
                clash_process_e2e_throughput(
                    &binary,
                    &config,
                    "vless-ws",
                    socks_port,
                    echo_port,
                    gateway_ip,
                    E2E_PAYLOAD_BYTES,
                )
                .await
                .map(|_| ())
            })
            .await
    }

    #[tokio::test]
    async fn e2e_throughput_vless_tcp() -> anyhow::Result<()> {
        initialize();
        let socks_port = alloc_port();
        let echo_port = alloc_port();

        let container = get_ws_runner().await?;
        let server = container
            .container_ip()
            .ok_or_else(|| anyhow::anyhow!("vless container has no IP"))?;
        let gateway_ip = container.docker_gateway_ip();

        let mmdb = config_helper::test_config_base_dir()
            .join("Country.mmdb")
            .to_str()
            .unwrap()
            .to_owned();
        let config = format!(
            r#"
socks-port: {socks_port}
bind-address: 127.0.0.1
mmdb: "{mmdb}"
mode: global
log-level: error
proxies:
  - name: proxy
    type: vless
    server: {server}
    port: {port}
    uuid: {uuid}
    udp: false
    tls: true
    skip-cert-verify: true
rules:
  - MATCH,proxy
"#,
            socks_port = socks_port,
            mmdb = mmdb,
            server = server,
            port = CONTAINER_PORT,
            uuid = UUID,
        );
        let binary = find_clash_rs_binary();

        container
            .run_and_cleanup(async move {
                clash_process_e2e_throughput(
                    &binary,
                    &config,
                    "vless-tcp",
                    socks_port,
                    echo_port,
                    gateway_ip,
                    E2E_PAYLOAD_BYTES,
                )
                .await
                .map(|_| ())
            })
            .await
    }

    #[tokio::test]
    async fn e2e_throughput_vless_grpc() -> anyhow::Result<()> {
        initialize();
        let socks_port = alloc_port();
        let echo_port = alloc_port();

        let container = get_grpc_runner().await?;
        let server = container
            .container_ip()
            .ok_or_else(|| anyhow::anyhow!("vless container has no IP"))?;
        let gateway_ip = container.docker_gateway_ip();

        let mmdb = config_helper::test_config_base_dir()
            .join("Country.mmdb")
            .to_str()
            .unwrap()
            .to_owned();
        let config = format!(
            r#"
socks-port: {socks_port}
bind-address: 127.0.0.1
mmdb: "{mmdb}"
mode: global
log-level: error
proxies:
  - name: proxy
    type: vless
    server: {server}
    port: {port}
    uuid: {uuid}
    udp: false
    tls: true
    skip-cert-verify: true
    network: grpc
    grpc-opts:
      grpc-service-name: grpc
rules:
  - MATCH,proxy
"#,
            socks_port = socks_port,
            mmdb = mmdb,
            server = server,
            port = CONTAINER_PORT_XRAY,
            uuid = UUID,
        );
        let binary = find_clash_rs_binary();

        container
            .run_and_cleanup(async move {
                clash_process_e2e_throughput(
                    &binary,
                    &config,
                    "vless-grpc",
                    socks_port,
                    echo_port,
                    gateway_ip,
                    E2E_PAYLOAD_BYTES,
                )
                .await
                .map(|_| ())
            })
            .await
    }

    #[tokio::test]
    async fn e2e_throughput_vless_h2() -> anyhow::Result<()> {
        initialize();
        let socks_port = alloc_port();
        let echo_port = alloc_port();

        let container = get_h2_runner().await?;
        let server = container
            .container_ip()
            .ok_or_else(|| anyhow::anyhow!("vless container has no IP"))?;
        let gateway_ip = container.docker_gateway_ip();

        let mmdb = config_helper::test_config_base_dir()
            .join("Country.mmdb")
            .to_str()
            .unwrap()
            .to_owned();
        let config = format!(
            r#"
socks-port: {socks_port}
bind-address: 127.0.0.1
mmdb: "{mmdb}"
mode: global
log-level: error
proxies:
  - name: proxy
    type: vless
    server: {server}
    port: {port}
    uuid: {uuid}
    udp: false
    tls: true
    skip-cert-verify: true
    network: h2
    h2-opts:
      host:
        - example.org
      path: /
rules:
  - MATCH,proxy
"#,
            socks_port = socks_port,
            mmdb = mmdb,
            server = server,
            port = CONTAINER_PORT_XRAY,
            uuid = UUID,
        );
        let binary = find_clash_rs_binary();

        container
            .run_and_cleanup(async move {
                clash_process_e2e_throughput(
                    &binary,
                    &config,
                    "vless-h2",
                    socks_port,
                    echo_port,
                    gateway_ip,
                    E2E_PAYLOAD_BYTES,
                )
                .await
                .map(|_| ())
            })
            .await
    }
}
