use std::{collections::HashMap, io, net::IpAddr, sync::Arc};

use async_trait::async_trait;
use bytes::Bytes;
use erased_serde::Serialize as ErasedSerialize;
use rand::seq::IndexedRandom;
use tokio::sync::OnceCell;

use crate::{
    app::{
        dispatcher::{
            BoxedChainedDatagram, BoxedChainedStream, ChainedDatagram,
            ChainedDatagramWrapper, ChainedStream, ChainedStreamWrapper,
        },
        dns::ThreadSafeDNSResolver,
    },
    common::errors::{map_io_error, new_io_error},
    impl_default_connector,
    proxy::{
        ConnectorType, DialWithConnector, HandlerCommonOptions, OutboundHandler,
        OutboundType, PlainProxyAPIResponse,
        utils::{GLOBAL_DIRECT_CONNECTOR, RemoteConnector},
        wg::{
            device::{DeviceManager, VirtualIpDevice},
            events::PortProtocol,
        },
    },
    session::{Session, SocksAddr},
};

use super::{
    client::Client,
    config::{ClientConfig, Proto},
    io::{TcpPacketIo, UdpPacketIo},
};

pub struct HandlerOptions {
    pub name: String,
    pub common_opts: HandlerCommonOptions,
    pub config: Arc<ClientConfig>,
    pub mtu: u16,
    pub udp: bool,
    pub remote_dns_resolve: bool,
    pub dns: Vec<String>,
}

struct Inner {
    device_manager: Arc<DeviceManager>,
    _client: Arc<Client>,
    _tasks: Vec<tokio::task::JoinHandle<()>>,
}

pub struct Handler {
    opts: HandlerOptions,
    inner: OnceCell<Inner>,
    connector: tokio::sync::RwLock<Option<Arc<dyn RemoteConnector>>>,
}

impl Handler {
    pub fn new(opts: HandlerOptions) -> Self {
        Self {
            opts,
            inner: OnceCell::new(),
            connector: Default::default(),
        }
    }

    async fn initialize_inner(
        &self,
        resolver: ThreadSafeDNSResolver,
        sess: &Session,
        connector: &dyn RemoteConnector,
    ) -> io::Result<&Inner> {
        self.inner
            .get_or_try_init(|| async {
                let destination = self
                    .opts
                    .config
                    .remote_host
                    .parse::<IpAddr>()
                    .map(|ip| {
                        SocksAddr::Ip((ip, self.opts.config.remote_port).into())
                    })
                    .unwrap_or_else(|_| {
                        SocksAddr::Domain(
                            self.opts.config.remote_host.clone(),
                            self.opts.config.remote_port,
                        )
                    });
                let packet_io: Arc<dyn super::control::PacketIo> =
                    match self.opts.config.proto {
                        Proto::Tcp => TcpPacketIo::new(
                            connector
                                .connect_stream(
                                    resolver.clone(),
                                    &self.opts.config.remote_host,
                                    self.opts.config.remote_port,
                                    sess.iface.as_ref(),
                                    #[cfg(target_os = "linux")]
                                    sess.so_mark,
                                )
                                .await?,
                        ),
                        Proto::Udp => UdpPacketIo::new(
                            connector
                                .connect_datagram(
                                    resolver.clone(),
                                    None,
                                    destination.clone(),
                                    sess.iface.as_ref(),
                                    #[cfg(target_os = "linux")]
                                    sess.so_mark,
                                )
                                .await?,
                            destination,
                        ),
                    };
                let client = Client::new(self.opts.config.clone(), packet_io)?;
                let push = client.handshake().await?;
                let ipv4 =
                    push.prefixes.iter().find_map(|prefix| match prefix.addr() {
                        IpAddr::V4(address) => Some(address),
                        IpAddr::V6(_) => None,
                    });
                let ipv6 =
                    push.prefixes.iter().find_map(|prefix| match prefix.addr() {
                        IpAddr::V4(_) => None,
                        IpAddr::V6(address) => Some(address),
                    });
                if ipv4.is_none() && ipv6.is_none() {
                    return Err(new_io_error(
                        "openvpn server pushed no tunnel address",
                    ));
                }

                let (outgoing_tx, mut outgoing_rx) =
                    tokio::sync::mpsc::channel::<Bytes>(1024);
                let (incoming_tx, incoming_rx) =
                    tokio::sync::mpsc::channel::<(PortProtocol, Bytes)>(1024);
                let (packet_notifier_tx, packet_notifier_rx) =
                    tokio::sync::mpsc::channel(1024);
                let device = VirtualIpDevice::new(
                    outgoing_tx,
                    incoming_rx,
                    packet_notifier_tx,
                    self.opts.mtu as usize,
                );
                let dns_servers = if self.opts.remote_dns_resolve {
                    self.opts
                        .dns
                        .iter()
                        .map(|server| {
                            server
                                .parse::<IpAddr>()
                                .map(|address| (address, 53).into())
                                .map_err(|error| {
                                    new_io_error(format!(
                                        "invalid openvpn DNS server `{server}`: \
                                         {error}"
                                    ))
                                })
                        })
                        .collect::<io::Result<Vec<_>>>()?
                } else {
                    Vec::new()
                };
                let device_manager = Arc::new(DeviceManager::new(
                    ipv4,
                    ipv6,
                    resolver,
                    dns_servers,
                    packet_notifier_rx,
                ));

                let mut tasks = Vec::new();
                let manager = device_manager.clone();
                tasks.push(tokio::spawn(async move {
                    manager.poll_sockets(device).await;
                }));
                let upload = client.clone();
                tasks.push(tokio::spawn(async move {
                    while let Some(packet) = outgoing_rx.recv().await {
                        if upload.write_ip_packet(&packet).await.is_err() {
                            break;
                        }
                    }
                }));
                let download = client.clone();
                tasks.push(tokio::spawn(async move {
                    while let Ok(packet) = download.read_ip_packet().await {
                        let protocol = ip_protocol(&packet);
                        if incoming_tx.send((protocol, packet.into())).await.is_err()
                        {
                            break;
                        }
                    }
                }));
                if !self.opts.config.ping_interval.is_zero() {
                    let keepalive = client.clone();
                    let interval = self.opts.config.ping_interval;
                    tasks.push(tokio::spawn(async move {
                        let mut ticker = tokio::time::interval(interval);
                        loop {
                            ticker.tick().await;
                            if keepalive.since_send().await >= interval
                                && keepalive.write_ping().await.is_err()
                            {
                                break;
                            }
                        }
                    }));
                }
                if !self.opts.config.ping_restart.is_zero() {
                    let watchdog = client.clone();
                    let timeout = self.opts.config.ping_restart;
                    tasks.push(tokio::spawn(async move {
                        let mut ticker = tokio::time::interval(timeout);
                        loop {
                            ticker.tick().await;
                            if watchdog.since_receive().await >= timeout {
                                let _ = watchdog.close().await;
                                break;
                            }
                        }
                    }));
                }

                Ok(Inner {
                    device_manager,
                    _client: client,
                    _tasks: tasks,
                })
            })
            .await
    }

    async fn resolve_target(
        &self,
        sess: &Session,
        resolver: ThreadSafeDNSResolver,
        inner: &Inner,
    ) -> io::Result<IpAddr> {
        if self.opts.remote_dns_resolve
            && sess.destination.is_domain()
            && !self.opts.dns.is_empty()
        {
            let server = self
                .opts
                .dns
                .choose(&mut rand::rng())
                .expect("checked non-empty DNS list")
                .parse::<IpAddr>()
                .map_err(|error| {
                    new_io_error(format!("invalid openvpn DNS server: {error}"))
                })?;
            inner
                .device_manager
                .look_up_dns(&sess.destination.host(), (server, 53).into())
                .await
                .ok_or_else(|| new_io_error("openvpn remote DNS resolution failed"))
        } else {
            resolver
                .resolve(&sess.destination.host(), false)
                .await
                .map_err(map_io_error)?
                .ok_or_else(|| new_io_error("invalid openvpn target address"))
        }
    }
}

impl std::fmt::Debug for Handler {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("OpenVPN")
            .field("name", &self.opts.name)
            .finish()
    }
}

impl_default_connector!(Handler);

#[async_trait]
impl OutboundHandler for Handler {
    fn name(&self) -> &str {
        &self.opts.name
    }

    fn server_name(&self) -> Option<&str> {
        Some(&self.opts.config.remote_host)
    }

    fn proto(&self) -> OutboundType {
        OutboundType::OpenVpn
    }

    async fn support_udp(&self) -> bool {
        self.opts.udp
    }

    async fn connect_stream(
        &self,
        sess: &Session,
        resolver: ThreadSafeDNSResolver,
    ) -> io::Result<BoxedChainedStream> {
        let connector = self.connector.read().await;
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
        sess: &Session,
        resolver: ThreadSafeDNSResolver,
    ) -> io::Result<BoxedChainedDatagram> {
        let connector = self.connector.read().await;
        self.connect_datagram_with_connector(
            sess,
            resolver,
            connector
                .as_ref()
                .unwrap_or(&GLOBAL_DIRECT_CONNECTOR.clone())
                .as_ref(),
        )
        .await
    }

    async fn support_connector(&self) -> ConnectorType {
        match self.opts.config.proto {
            Proto::Tcp => ConnectorType::Tcp,
            Proto::Udp => ConnectorType::All,
        }
    }

    async fn connect_stream_with_connector(
        &self,
        sess: &Session,
        resolver: ThreadSafeDNSResolver,
        connector: &dyn RemoteConnector,
    ) -> io::Result<BoxedChainedStream> {
        let inner = self
            .initialize_inner(resolver.clone(), sess, connector)
            .await?;
        let address = self.resolve_target(sess, resolver, inner).await?;
        let stream = inner
            .device_manager
            .new_tcp_socket((address, sess.destination.port()).into())
            .await?;
        let stream = ChainedStreamWrapper::new(stream);
        stream.append_to_chain(self.name()).await;
        Ok(Box::new(stream))
    }

    async fn connect_datagram_with_connector(
        &self,
        sess: &Session,
        resolver: ThreadSafeDNSResolver,
        connector: &dyn RemoteConnector,
    ) -> io::Result<BoxedChainedDatagram> {
        if !self.opts.udp {
            return Err(new_io_error("openvpn UDP is disabled"));
        }
        let inner = self.initialize_inner(resolver, sess, connector).await?;
        let datagram = inner.device_manager.new_udp_socket().await;
        let datagram = ChainedDatagramWrapper::new(datagram);
        datagram.append_to_chain(self.name()).await;
        Ok(Box::new(datagram))
    }

    fn try_as_plain_handler(&self) -> Option<&dyn PlainProxyAPIResponse> {
        Some(self)
    }
}

#[async_trait]
impl PlainProxyAPIResponse for Handler {
    async fn as_map(&self) -> HashMap<String, Box<dyn ErasedSerialize + Send>> {
        HashMap::from([
            (
                "server".to_owned(),
                Box::new(self.opts.config.remote_host.clone()) as _,
            ),
            (
                "port".to_owned(),
                Box::new(self.opts.config.remote_port) as _,
            ),
            ("udp".to_owned(), Box::new(self.opts.udp) as _),
        ])
    }
}

fn ip_protocol(packet: &[u8]) -> PortProtocol {
    match packet.first().map(|byte| byte >> 4) {
        Some(4) if packet.get(9) == Some(&17) => PortProtocol::Udp,
        Some(6) if packet.get(6) == Some(&17) => PortProtocol::Udp,
        _ => PortProtocol::Tcp,
    }
}
