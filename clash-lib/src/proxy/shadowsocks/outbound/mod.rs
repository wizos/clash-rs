mod datagram;
mod stream;

use self::{
    datagram::{
        OutboundDatagramShadowsocks, OutboundDatagramShadowsocksR, ShadowsocksUdpIo,
    },
    stream::ShadowSocksStream,
};

use crate::{
    app::{
        dispatcher::{
            BoxedChainedDatagram, BoxedChainedStream, ChainedDatagram,
            ChainedDatagramWrapper, ChainedStream, ChainedStreamWrapper,
        },
        dns::ThreadSafeDNSResolver,
    },
    common::errors::new_io_error,
    impl_default_connector,
    proxy::{
        AnyStream, ConnectorType, DialWithConnector, HandlerCommonOptions,
        OutboundHandler, OutboundType, PlainProxyAPIResponse,
        shadowsocks::{map_cipher, ssr_protocol::SsrProtocol},
        transport::Sip003Plugin,
        uot,
        utils::{GLOBAL_DIRECT_CONNECTOR, RemoteConnector},
    },
    session::Session,
};
use async_trait::async_trait;
use bytes::BytesMut;
use erased_serde::Serialize as ErasedSerialize;
use shadowsocks::{
    ProxyClientStream, ProxySocket, ServerConfig, config::ServerType,
    context::Context, relay::udprelay::proxy_socket::UdpSocketType,
};
use std::{collections::HashMap, fmt::Debug, io, sync::Arc};
use tracing::debug;

pub struct HandlerOptions {
    pub name: String,
    pub common_opts: HandlerCommonOptions,
    pub server: String,
    pub port: u16,
    pub password: String,
    pub cipher: String,
    pub plugin: Option<Box<dyn Sip003Plugin>>,
    pub udp: bool,
    pub udp_over_tcp: bool,
    pub udp_over_tcp_version: u8,
}

pub struct Handler {
    opts: HandlerOptions,
    ctx: Arc<shadowsocks::context::Context>,
    connector: tokio::sync::RwLock<Option<Arc<dyn RemoteConnector>>>,
    outbound_type: OutboundType,
    ssr_protocol: Option<SsrProtocol>,
}

impl_default_connector!(Handler);

impl Debug for Handler {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Shadowsocks")
            .field("name", &self.opts.name)
            .finish()
    }
}

impl Handler {
    pub fn new(opts: HandlerOptions) -> Self {
        Self {
            opts,
            ctx: Context::new_shared(ServerType::Local),
            connector: tokio::sync::RwLock::new(None),
            outbound_type: OutboundType::Shadowsocks,
            ssr_protocol: None,
        }
    }

    pub fn new_shadowsocksr(
        opts: HandlerOptions,
        protocol: Option<SsrProtocol>,
    ) -> Self {
        Self {
            outbound_type: OutboundType::ShadowsocksR,
            ssr_protocol: protocol,
            ..Self::new(opts)
        }
    }

    async fn proxy_stream(
        &self,
        s: AnyStream,
        sess: &Session,
        _resolver: ThreadSafeDNSResolver,
    ) -> std::io::Result<AnyStream> {
        let stream: AnyStream = match &self.opts.plugin {
            Some(plugin) => plugin.proxy_stream(s).await?,
            None => s,
        };

        let cfg = self.server_config()?;

        if let Some(protocol) = &self.ssr_protocol {
            use tokio::io::AsyncWriteExt;

            let mut stream = protocol.wrap_stream(
                self.ctx.clone(),
                stream,
                cfg.method(),
                cfg.key(),
                cfg.password(),
            );
            let mut target = BytesMut::with_capacity(sess.destination.size());
            sess.destination.write_buf(&mut target);
            stream.write_all(&target).await?;
            return Ok(stream);
        }

        let stream = ProxyClientStream::from_stream(
            self.ctx.clone(),
            stream,
            &cfg,
            (sess.destination.host(), sess.destination.port()),
        );

        Ok(Box::new(ShadowSocksStream(stream)))
    }

    fn server_config(&self) -> Result<ServerConfig, io::Error> {
        ServerConfig::new(
            (self.opts.server.to_owned(), self.opts.port),
            self.opts.password.to_owned(),
            map_cipher(self.opts.cipher.as_str())?,
        )
        .map_err(|e| new_io_error(e.to_string()))
    }
}

#[async_trait]
impl OutboundHandler for Handler {
    fn name(&self) -> &str {
        self.opts.name.as_str()
    }

    fn server_name(&self) -> Option<&str> {
        Some(&self.opts.server)
    }

    fn proto(&self) -> OutboundType {
        self.outbound_type
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

        let s = self.proxy_stream(stream, sess, resolver).await?;
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
        if self.opts.udp_over_tcp {
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
            let mut proxy_session = sess.clone();
            proxy_session.destination =
                uot::request_destination(self.opts.udp_over_tcp_version)?;
            let mut stream =
                self.proxy_stream(stream, &proxy_session, resolver).await?;
            if self.opts.udp_over_tcp_version == uot::VERSION {
                use tokio::io::AsyncWriteExt;
                stream
                    .write_all(&uot::encode_connect_request(&sess.destination))
                    .await?;
                stream.flush().await?;
            }
            let datagram =
                uot::ConnectedDatagram::new(stream, sess.destination.clone());
            let chained = ChainedDatagramWrapper::new(datagram);
            chained.append_to_chain(self.name()).await;
            return Ok(Box::new(chained));
        }

        let cfg = self.server_config()?;

        let socket = connector
            .connect_datagram(
                resolver.clone(),
                None,
                (self.opts.server.clone(), self.opts.port).try_into()?,
                sess.iface.as_ref(),
                #[cfg(target_os = "linux")]
                sess.so_mark,
            )
            .await?;

        let server_addr = resolver
            .resolve(&self.opts.server, false)
            .await
            .map_err(|x| {
                new_io_error(format!(
                    "failed to resolve {}: {}",
                    self.opts.server, x
                ))
            })?
            .ok_or(new_io_error(format!(
                "failed to resolve {}",
                self.opts.server
            )))?;
        let remote_addr = (server_addr, self.opts.port).into();

        if let Some(protocol) = &self.ssr_protocol {
            let datagram = OutboundDatagramShadowsocksR::new(
                socket,
                remote_addr,
                self.ctx.clone(),
                cfg.method(),
                cfg.key().to_vec(),
                protocol.udp_protocol(cfg.key(), cfg.password()),
            );
            let chained = ChainedDatagramWrapper::new(datagram);
            chained.append_to_chain(self.name()).await;
            return Ok(Box::new(chained));
        }

        let socket = ProxySocket::from_socket(
            UdpSocketType::Client,
            self.ctx.clone(),
            &cfg,
            ShadowsocksUdpIo::new(socket),
        );
        let d = OutboundDatagramShadowsocks::new(socket, remote_addr);
        let d = ChainedDatagramWrapper::new(d);
        d.append_to_chain(self.name()).await;
        Ok(Box::new(d))
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
        m.insert("cipher".to_owned(), Box::new(self.opts.cipher.clone()) as _);
        m.insert(
            "password".to_owned(),
            Box::new(self.opts.password.clone()) as _,
        );
        if self.opts.plugin.is_some() {
            m.insert("plugin".to_owned(), Box::new(true) as _);
        }
        m
    }
}

#[cfg(test)]
mod uot_tests {
    use std::{net::Ipv4Addr, sync::Arc};

    use futures::{SinkExt, StreamExt};
    use shadowsocks::{
        config::ServerType, context::Context, relay::tcprelay::ProxyServerStream,
    };
    use tokio::io::{AsyncReadExt, AsyncWriteExt, duplex};

    use super::*;
    use crate::{
        proxy::{datagram::UdpPacket, uot, utils::test_utils::noop::NoopResolver},
        session::SocksAddr,
    };

    const PASSWORD: &str = "uot-test-password";
    const CIPHER: &str = "aes-128-gcm";

    async fn round_trip(version: u8) {
        let handler = Handler::new(HandlerOptions {
            name: "ss-uot".to_owned(),
            common_opts: Default::default(),
            server: "example.com".to_owned(),
            port: 443,
            password: PASSWORD.to_owned(),
            cipher: CIPHER.to_owned(),
            plugin: None,
            udp: true,
            udp_over_tcp: true,
            udp_over_tcp_version: version,
        });
        let server_config = handler.server_config().unwrap();
        let method = server_config.method();
        let key = server_config.key().to_vec();
        let destination = SocksAddr::from((Ipv4Addr::new(1, 1, 1, 1), 53));
        let (client, server) = duplex(16 * 1024);

        let expected_destination = destination.clone();
        let server = tokio::spawn(async move {
            let context = Context::new_shared(ServerType::Server);
            let mut stream =
                ProxyServerStream::from_stream(context, server, method, &key);
            let magic = stream.handshake().await.unwrap();
            let expected_magic = if version == uot::VERSION {
                uot::MAGIC_ADDRESS
            } else {
                uot::LEGACY_MAGIC_ADDRESS
            };
            assert_eq!(magic.to_string(), format!("{expected_magic}:0"));
            if version == uot::VERSION {
                assert_eq!(stream.read_u8().await.unwrap(), 1);
                assert_eq!(
                    SocksAddr::read_from(&mut stream).await.unwrap(),
                    expected_destination
                );
            }
            assert_eq!(stream.read_u16().await.unwrap(), 5);
            let mut payload = [0u8; 5];
            stream.read_exact(&mut payload).await.unwrap();
            assert_eq!(&payload, b"query");
            stream.write_u16(5).await.unwrap();
            stream.write_all(b"reply").await.unwrap();
            stream.flush().await.unwrap();
        });

        let proxy_session = Session {
            destination: uot::request_destination(version).unwrap(),
            ..Default::default()
        };
        let resolver = Arc::new(NoopResolver);
        let mut stream = handler
            .proxy_stream(Box::new(client), &proxy_session, resolver)
            .await
            .unwrap();
        if version == uot::VERSION {
            stream
                .write_all(&uot::encode_connect_request(&destination))
                .await
                .unwrap();
        }
        let mut datagram = uot::ConnectedDatagram::new(stream, destination.clone());
        datagram
            .send(UdpPacket {
                data: b"query".to_vec(),
                src_addr: destination.clone(),
                dst_addr: destination.clone(),
                inbound_user: None,
            })
            .await
            .unwrap();
        let reply = datagram.next().await.unwrap();
        assert_eq!(reply.data, b"reply");
        server.await.unwrap();
    }

    #[tokio::test]
    async fn shadowsocks_uot_v1_matches_mihomo() {
        round_trip(uot::LEGACY_VERSION).await;
    }

    #[tokio::test]
    async fn shadowsocks_uot_v2_matches_mihomo() {
        round_trip(uot::VERSION).await;
    }
}

#[cfg(all(test, docker_test))]
mod tests {
    use crate::{
        proxy::{
            transport::*,
            utils::test_utils::{
                Suite,
                config_helper::test_config_base_dir,
                consts::*,
                docker_runner::{
                    DockerTestRunner, DockerTestRunnerBuilder,
                    MultiDockerTestRunner, alloc_docker_port,
                },
                run_test_suites_and_cleanup,
            },
        },
        tests::initialize,
    };

    use super::*;

    const PASSWORD: &str = "FzcLbKs2dY9mhL";
    const CIPHER: &str = "aes-256-gcm";
    const SHADOW_TLS_PASSWORD: &str = "password";

    async fn get_ss_runner(port: u16) -> anyhow::Result<DockerTestRunner> {
        let host = format!("0.0.0.0:{}", port);
        DockerTestRunnerBuilder::new()
            .image(IMAGE_SS_RUST)
            .port(port)
            .entrypoint(&["ssserver"])
            .cmd(&["-s", &host, "-m", CIPHER, "-k", PASSWORD, "-U", "-vvv"])
            .build()
            .await
    }

    async fn get_ss_runner_with_plugin(
        port: u16,
    ) -> anyhow::Result<DockerTestRunner> {
        let test_config_dir = test_config_base_dir();
        let cert = test_config_dir.join("certs/example.org.pem");
        let key = test_config_dir.join("certs/example.org-key.pem");
        let host = format!("0.0.0.0:{}", port);
        DockerTestRunnerBuilder::new()
            .image(IMAGE_SS_RUST)
            .port(port)
            .entrypoint(&["ssserver"])
            .cmd(&[
                "-s",
                &host,
                "-m",
                CIPHER,
                "-k",
                PASSWORD,
                "-U",
                "-vvv",
                "--plugin",
                "v2ray-plugin",
                "--plugin-opts",
                "server;tls;host=example.org;mux=0",
            ])
            .mounts(&[
                (
                    cert.to_str().unwrap(),
                    "/root/.acme.sh/example.org/fullchain.cer",
                ),
                (
                    key.to_str().unwrap(),
                    "/root/.acme.sh/example.org/example.org.key",
                ),
            ])
            .build()
            .await
    }

    #[tokio::test]
    async fn test_ss_plain() -> anyhow::Result<()> {
        initialize();
        let port = alloc_docker_port();
        let container = get_ss_runner(port).await?;

        let opts = HandlerOptions {
            name: "test-ss".to_owned(),
            common_opts: Default::default(),
            server: container.container_ip().unwrap_or(LOCAL_ADDR.to_owned()),
            port,
            password: PASSWORD.to_owned(),
            cipher: CIPHER.to_owned(),
            plugin: Default::default(),
            udp: false,
            udp_over_tcp: false,
            udp_over_tcp_version: uot::LEGACY_VERSION,
        };

        let handler = Arc::new(Handler::new(opts));
        handler
            .register_connector(GLOBAL_DIRECT_CONNECTOR.clone())
            .await;
        run_test_suites_and_cleanup(handler, container, Suite::all()).await
    }

    async fn get_shadowtls_runner(
        ss_ip: Option<String>,
        ss_port: u16,
        stls_port: u16,
    ) -> anyhow::Result<DockerTestRunner> {
        // Use host.docker.internal to access SS server running in another
        // container via host port mapping
        let ss_server_env = format!(
            "SERVER={}:{}",
            ss_ip.unwrap_or("host.docker.internal".to_owned()),
            ss_port
        );
        let listen_env = format!("LISTEN=0.0.0.0:{}", stls_port);
        let password = format!("PASSWORD={}", SHADOW_TLS_PASSWORD);
        DockerTestRunnerBuilder::new()
            .image(IMAGE_SHADOW_TLS)
            .env(&[
                "MODE=server",
                // the port that we need to fill in the config
                &listen_env,
                // shadowsocks server addr
                &ss_server_env,
                "TLS=www.feishu.cn:443",
                &password,
                "V3=1",
            ])
            // .cmd(&["-s", "0.0.0.0:10002", "-m", CIPHER, "-k", PASSWORD, "-U"])
            .port(stls_port)
            .build()
            .await
    }

    #[tokio::test]
    async fn test_shadowtls() -> anyhow::Result<()> {
        initialize();
        // the real port that used for communication
        let shadow_tls_port = alloc_docker_port();
        // not important, you can assign any port that is not conflict with
        // others
        let ss_port = alloc_docker_port();

        let container1 = get_ss_runner(ss_port).await?;

        let container2 = get_shadowtls_runner(
            container1.container_ip(),
            ss_port,
            shadow_tls_port,
        )
        .await?;

        let client =
            Shadowtls::new("www.feishu.cn".to_owned(), "password".to_owned(), true);
        let opts = HandlerOptions {
            name: "test-shadowtls".to_owned(),
            common_opts: Default::default(),
            server: container2.container_ip().unwrap_or(LOCAL_ADDR.to_owned()),
            port: shadow_tls_port,
            password: PASSWORD.to_owned(),
            cipher: CIPHER.to_owned(),
            plugin: Some(Box::new(client)),
            udp: false,
            udp_over_tcp: false,
            udp_over_tcp_version: uot::LEGACY_VERSION,
        };
        let handler: Arc<dyn OutboundHandler> = Arc::new(Handler::new(opts));
        // we need to store all the runners in a container, to make sure all of
        // them can be destroyed after the test
        let mut chained = MultiDockerTestRunner::default();
        chained.add_with_runner(container1);
        chained.add_with_runner(container2);
        // currently, shadow-tls does't support udp proxy
        // see: https://github.com/ihciah/shadow-tls/issues/54
        run_test_suites_and_cleanup(handler, chained, Suite::tcp_tests()).await
    }

    async fn get_obfs_runner(
        ss_ip: Option<String>,
        ss_port: u16,
        obfs_port: u16,
        mode: SimpleOBFSMode,
    ) -> anyhow::Result<DockerTestRunner> {
        let ss_server_env = format!(
            "{}:{}",
            ss_ip.unwrap_or("host.docker.internal".to_owned()),
            ss_port
        );
        let port = format!("{}", obfs_port);
        let mode = match mode {
            SimpleOBFSMode::Http => "http",
            SimpleOBFSMode::Tls => "tls",
        };
        DockerTestRunnerBuilder::new()
            .image(IMAGE_OBFS)
            .cmd(&[
                "obfs-server",
                "-p",
                &port,
                "--obfs",
                mode,
                "-r",
                &ss_server_env,
                "-vv",
            ])
            .port(obfs_port)
            .build()
            .await
    }

    async fn test_ss_obfs_inner(mode: SimpleOBFSMode) -> anyhow::Result<()> {
        let obfs_port = alloc_docker_port();
        let ss_port = alloc_docker_port();

        let container1 = get_ss_runner(ss_port).await?;
        let container2 =
            get_obfs_runner(container1.container_ip(), ss_port, obfs_port, mode)
                .await?;

        let host = "www.bing.com".to_owned();
        let plugin = match mode {
            SimpleOBFSMode::Http => {
                Box::new(SimpleObfsHttp::new(host, ss_port)) as _
            }
            SimpleOBFSMode::Tls => Box::new(SimpleObfsTLS::new(host)) as _,
        };
        let opts = HandlerOptions {
            name: "test-obfs".to_owned(),
            common_opts: Default::default(),
            server: container2.container_ip().unwrap_or(LOCAL_ADDR.to_owned()),
            port: obfs_port,
            password: PASSWORD.to_owned(),
            cipher: CIPHER.to_owned(),
            plugin: Some(plugin),
            udp: false,
            udp_over_tcp: false,
            udp_over_tcp_version: uot::LEGACY_VERSION,
        };

        let handler: Arc<dyn OutboundHandler> = Arc::new(Handler::new(opts));
        let mut chained = MultiDockerTestRunner::default();
        chained.add_with_runner(container1);
        chained.add_with_runner(container2);
        run_test_suites_and_cleanup(handler, chained, Suite::tcp_tests()).await
    }

    #[tokio::test]
    async fn test_ss_obfs_http() -> anyhow::Result<()> {
        initialize();
        test_ss_obfs_inner(SimpleOBFSMode::Http).await
    }

    #[tokio::test]
    async fn test_ss_obfs_tls() -> anyhow::Result<()> {
        initialize();
        test_ss_obfs_inner(SimpleOBFSMode::Tls).await
    }

    #[tokio::test]
    async fn test_ss_v2ray_plugin() -> anyhow::Result<()> {
        initialize();
        let ss_port = alloc_docker_port();
        let container = get_ss_runner_with_plugin(ss_port).await?;
        let host = "example.org".to_owned();
        let plugin = V2rayWsClient::try_new(
            host,
            ss_port,
            "/".to_owned(),
            Default::default(),
            true,
            true,
            false,
        )?;
        let opts = HandlerOptions {
            name: "test-obfs".to_owned(),
            common_opts: Default::default(),
            server: container.container_ip().unwrap_or(LOCAL_ADDR.to_owned()),
            port: ss_port,
            password: PASSWORD.to_owned(),
            cipher: CIPHER.to_owned(),
            plugin: Some(Box::new(plugin)),
            udp: false,
            udp_over_tcp: false,
            udp_over_tcp_version: uot::LEGACY_VERSION,
        };

        let handler: Arc<dyn OutboundHandler> = Arc::new(Handler::new(opts));
        run_test_suites_and_cleanup(handler, container, Suite::tcp_tests()).await
    }
}

// ── E2E throughput tests
// ────────────────────────────────────────────────────── These start clash-rs
// as a subprocess and exercise the full stack:   test client → SOCKS5 inbound →
// dispatcher → SS outbound   → docker proxy server → echo server → back
//
// Ports are allocated dynamically so all tests can run in parallel — no
// #[serial_test::serial] needed.
// Gate: --cfg docker_test --cfg throughput_test (see proxy-throughput.yml)
#[cfg(all(test, docker_test, throughput_test))]
mod e2e {
    use crate::{
        proxy::utils::test_utils::{
            config_helper,
            consts::*,
            docker_runner::{
                DockerTestRunner, DockerTestRunnerBuilder, MultiDockerTestRunner,
                RunAndCleanup,
            },
            docker_utils::{
                alloc_port, clash_process_e2e_throughput, find_clash_rs_binary,
            },
        },
        tests::initialize,
    };

    use crate::proxy::transport::SimpleOBFSMode;

    const PASSWORD: &str = "FzcLbKs2dY9mhL";
    const CIPHER: &str = "aes-256-gcm";
    const SHADOW_TLS_PASSWORD: &str = "password";

    const E2E_PAYLOAD_BYTES: usize = 32 * 1024 * 1024; // 32 MB

    async fn get_ss_runner(port: u16) -> anyhow::Result<DockerTestRunner> {
        let host = format!("0.0.0.0:{}", port);
        DockerTestRunnerBuilder::new()
            .image(IMAGE_SS_RUST)
            .no_port()
            .entrypoint(&["ssserver"])
            .cmd(&["-s", &host, "-m", CIPHER, "-k", PASSWORD, "-U", "-vvv"])
            .build()
            .await
    }

    async fn get_ss_runner_with_plugin(
        port: u16,
    ) -> anyhow::Result<DockerTestRunner> {
        use crate::proxy::utils::test_utils::config_helper::test_config_base_dir;
        let test_config_dir = test_config_base_dir();
        let cert = test_config_dir.join("certs/example.org.pem");
        let key = test_config_dir.join("certs/example.org-key.pem");
        let host = format!("0.0.0.0:{}", port);
        DockerTestRunnerBuilder::new()
            .image(IMAGE_SS_RUST)
            .no_port()
            .entrypoint(&["ssserver"])
            .cmd(&[
                "-s",
                &host,
                "-m",
                CIPHER,
                "-k",
                PASSWORD,
                "-U",
                "-vvv",
                "--plugin",
                "v2ray-plugin",
                "--plugin-opts",
                "server;tls;host=example.org;mux=0",
            ])
            .mounts(&[
                (
                    cert.to_str().unwrap(),
                    "/root/.acme.sh/example.org/fullchain.cer",
                ),
                (
                    key.to_str().unwrap(),
                    "/root/.acme.sh/example.org/example.org.key",
                ),
            ])
            .build()
            .await
    }

    async fn get_shadowtls_runner(
        ss_ip: Option<String>,
        ss_port: u16,
        stls_port: u16,
    ) -> anyhow::Result<DockerTestRunner> {
        let ss_server_env = format!(
            "SERVER={}:{}",
            ss_ip.unwrap_or("host.docker.internal".to_owned()),
            ss_port
        );
        let listen_env = format!("LISTEN=0.0.0.0:{}", stls_port);
        let password = format!("PASSWORD={}", SHADOW_TLS_PASSWORD);
        DockerTestRunnerBuilder::new()
            .image(IMAGE_SHADOW_TLS)
            .no_port()
            .env(&[
                "MODE=server",
                &listen_env,
                &ss_server_env,
                "TLS=www.feishu.cn:443",
                &password,
                "V3=1",
            ])
            .build()
            .await
    }

    async fn get_obfs_runner(
        ss_ip: Option<String>,
        ss_port: u16,
        obfs_port: u16,
        mode: SimpleOBFSMode,
    ) -> anyhow::Result<DockerTestRunner> {
        let ss_server_env = format!(
            "{}:{}",
            ss_ip.unwrap_or("host.docker.internal".to_owned()),
            ss_port
        );
        let port = format!("{}", obfs_port);
        let mode_str = match mode {
            SimpleOBFSMode::Http => "http",
            SimpleOBFSMode::Tls => "tls",
        };
        DockerTestRunnerBuilder::new()
            .image(IMAGE_OBFS)
            .no_port()
            .cmd(&[
                "obfs-server",
                "-p",
                &port,
                "--obfs",
                mode_str,
                "-r",
                &ss_server_env,
                "-vv",
            ])
            .build()
            .await
    }

    fn ss_base_config(
        server: &str,
        port: u16,
        socks_port: u16,
        extra_plugin_yaml: &str,
    ) -> String {
        let mmdb = config_helper::test_config_base_dir()
            .join("Country.mmdb")
            .to_str()
            .unwrap()
            .to_owned();
        format!(
            r#"
socks-port: {socks_port}
bind-address: 127.0.0.1
mmdb: "{mmdb}"
mode: global
log-level: error
proxies:
  - name: proxy
    type: ss
    server: {server}
    port: {port}
    cipher: {cipher}
    password: {password}
    udp: false
{extra}
rules:
  - MATCH,proxy
"#,
            socks_port = socks_port,
            mmdb = mmdb,
            server = server,
            port = port,
            cipher = CIPHER,
            password = PASSWORD,
            extra = extra_plugin_yaml,
        )
    }

    #[tokio::test]
    async fn e2e_throughput_ss_plain() -> anyhow::Result<()> {
        initialize();
        let container_port = alloc_port();
        let socks_port = alloc_port();
        let echo_port = alloc_port();

        let container = get_ss_runner(container_port).await?;
        let server = container.container_ip().unwrap_or(LOCAL_ADDR.to_owned());
        let gateway_ip = container.docker_gateway_ip();
        let config = ss_base_config(&server, container_port, socks_port, "");
        let binary = find_clash_rs_binary();

        container
            .run_and_cleanup(async move {
                clash_process_e2e_throughput(
                    &binary,
                    &config,
                    "ss-plain",
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
    async fn e2e_throughput_ss_plain_netem() -> anyhow::Result<()> {
        initialize();
        let container_port = alloc_port();
        let socks_port = alloc_port();
        let echo_port = alloc_port();

        let container = get_ss_runner(container_port).await?;
        container.apply_netem(50, 1.0).await?;
        let server = container.container_ip().unwrap_or(LOCAL_ADDR.to_owned());
        let gateway_ip = container.docker_gateway_ip();
        let config = ss_base_config(&server, container_port, socks_port, "");
        let binary = find_clash_rs_binary();

        container
            .run_and_cleanup(async move {
                clash_process_e2e_throughput(
                    &binary,
                    &config,
                    "ss-plain-netem",
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
    async fn e2e_throughput_ss_obfs_http() -> anyhow::Result<()> {
        initialize();
        let ss_port = alloc_port();
        let obfs_port = alloc_port();
        let socks_port = alloc_port();
        let echo_port = alloc_port();

        let c1 = get_ss_runner(ss_port).await?;
        let c1_ip = c1.container_ip();
        let c2 =
            match get_obfs_runner(c1_ip, ss_port, obfs_port, SimpleOBFSMode::Http)
                .await
            {
                Ok(c) => c,
                Err(e) => {
                    c1.cleanup().await.ok();
                    return Err(e);
                }
            };
        let server = c2.container_ip().unwrap_or(LOCAL_ADDR.to_owned());
        let gateway_ip = c2.docker_gateway_ip();

        let plugin_yaml = r#"    plugin: obfs
    plugin-opts:
      mode: http
      host: www.bing.com"#;
        let config = ss_base_config(&server, obfs_port, socks_port, plugin_yaml);
        let binary = find_clash_rs_binary();

        let mut chained = MultiDockerTestRunner::default();
        chained.add_with_runner(c1);
        chained.add_with_runner(c2);
        chained
            .run_and_cleanup(async move {
                clash_process_e2e_throughput(
                    &binary,
                    &config,
                    "ss-obfs-http",
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
    async fn e2e_throughput_ss_obfs_tls() -> anyhow::Result<()> {
        initialize();
        let ss_port = alloc_port();
        let obfs_port = alloc_port();
        let socks_port = alloc_port();
        let echo_port = alloc_port();

        let c1 = get_ss_runner(ss_port).await?;
        let c1_ip = c1.container_ip();
        let c2 =
            match get_obfs_runner(c1_ip, ss_port, obfs_port, SimpleOBFSMode::Tls)
                .await
            {
                Ok(c) => c,
                Err(e) => {
                    c1.cleanup().await.ok();
                    return Err(e);
                }
            };
        let server = c2.container_ip().unwrap_or(LOCAL_ADDR.to_owned());
        let gateway_ip = c2.docker_gateway_ip();

        let plugin_yaml = r#"    plugin: obfs
    plugin-opts:
      mode: tls
      host: www.bing.com"#;
        let config = ss_base_config(&server, obfs_port, socks_port, plugin_yaml);
        let binary = find_clash_rs_binary();

        let mut chained = MultiDockerTestRunner::default();
        chained.add_with_runner(c1);
        chained.add_with_runner(c2);
        chained
            .run_and_cleanup(async move {
                clash_process_e2e_throughput(
                    &binary,
                    &config,
                    "ss-obfs-tls",
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
    async fn e2e_throughput_ss_v2ray_plugin() -> anyhow::Result<()> {
        initialize();
        let ss_port = alloc_port();
        let socks_port = alloc_port();
        let echo_port = alloc_port();

        let container = get_ss_runner_with_plugin(ss_port).await?;
        let server = container.container_ip().unwrap_or(LOCAL_ADDR.to_owned());
        let gateway_ip = container.docker_gateway_ip();

        let plugin_yaml = r#"    plugin: v2ray-plugin
    plugin-opts:
      mode: websocket
      tls: true
      host: example.org
      skip-cert-verify: true
      path: /"#;
        let config = ss_base_config(&server, ss_port, socks_port, plugin_yaml);
        let binary = find_clash_rs_binary();

        container
            .run_and_cleanup(async move {
                clash_process_e2e_throughput(
                    &binary,
                    &config,
                    "ss-v2ray-plugin-ws-tls",
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
    async fn e2e_throughput_ss_shadowtls() -> anyhow::Result<()> {
        initialize();
        let ss_port = alloc_port();
        let stls_port = alloc_port();
        let socks_port = alloc_port();
        let echo_port = alloc_port();

        let c1 = get_ss_runner(ss_port).await?;
        let c1_ip = c1.container_ip();
        let c2 = match get_shadowtls_runner(c1_ip, ss_port, stls_port).await {
            Ok(c) => c,
            Err(e) => {
                c1.cleanup().await.ok();
                return Err(e);
            }
        };
        let server = c2.container_ip().unwrap_or(LOCAL_ADDR.to_owned());
        let gateway_ip = c2.docker_gateway_ip();

        let plugin_yaml = r#"    plugin: shadow-tls
    plugin-opts:
      host: www.feishu.cn
      password: password
      version: 3"#;
        let config = ss_base_config(&server, stls_port, socks_port, plugin_yaml);
        let binary = find_clash_rs_binary();

        let mut chained = MultiDockerTestRunner::default();
        chained.add_with_runner(c1);
        chained.add_with_runner(c2);
        chained
            .run_and_cleanup(async move {
                clash_process_e2e_throughput(
                    &binary,
                    &config,
                    "ss-shadow-tls-v3",
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
