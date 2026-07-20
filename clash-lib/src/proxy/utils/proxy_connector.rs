use async_trait::async_trait;
use std::{
    fmt::Debug,
    net::SocketAddr,
    sync::{Arc, LazyLock},
};
use tracing::trace;

use super::{new_tcp_stream, new_udp_socket};
use crate::{
    app::{
        dispatcher::{
            ChainedDatagram, ChainedDatagramWrapper, ChainedStream,
            ChainedStreamWrapper,
        },
        dns::ThreadSafeDNSResolver,
        net::OutboundInterface,
    },
    common::errors::new_io_error,
    proxy::{
        AnyOutboundDatagram, AnyOutboundHandler, AnyStream,
        direct::datagram::OutboundDatagramImpl,
    },
    session::{Network, Session, SocksAddr, Type},
};
use std::sync::atomic::{AtomicBool, Ordering};

/// allows a proxy to get a connection to a remote server
#[async_trait]
pub trait RemoteConnector: Send + Sync + Debug {
    /// Returns an owned connector with the same routing chain.
    ///
    /// Most transports only need the connector while establishing their first
    /// socket. Split HTTP tunnels (for example Sudoku HTTP mask), however, must
    /// open additional sockets after the logical stream has been returned.
    fn clone_connector(&self) -> Arc<dyn RemoteConnector>;

    async fn connect_stream(
        &self,
        resolver: ThreadSafeDNSResolver,
        address: &str,
        port: u16,
        iface: Option<&OutboundInterface>,
        #[cfg(target_os = "linux")] packet_mark: Option<u32>,
    ) -> std::io::Result<AnyStream>;

    async fn connect_datagram(
        &self,
        resolver: ThreadSafeDNSResolver,
        src: Option<SocketAddr>,
        destination: SocksAddr,
        iface: Option<&OutboundInterface>,
        #[cfg(target_os = "linux")] packet_mark: Option<u32>,
    ) -> std::io::Result<AnyOutboundDatagram>;
}

#[derive(Debug)]
pub struct DirectConnector;

static TCP_CONCURRENT: AtomicBool = AtomicBool::new(false);

pub fn set_tcp_concurrent(enabled: bool) {
    TCP_CONCURRENT.store(enabled, Ordering::Relaxed);
}

pub async fn resolve_and_connect_tcp(
    resolver: ThreadSafeDNSResolver,
    address: &str,
    port: u16,
    iface: Option<&OutboundInterface>,
    #[cfg(target_os = "linux")] so_mark: Option<u32>,
) -> std::io::Result<tokio::net::TcpStream> {
    if let Ok(ip) = address.parse::<std::net::IpAddr>() {
        return new_tcp_stream(
            (ip, port).into(),
            iface,
            #[cfg(target_os = "linux")]
            so_mark,
        )
        .await;
    }

    if !TCP_CONCURRENT.load(Ordering::Relaxed) {
        let ip = resolver
            .resolve(address, false)
            .await
            .map_err(|error| new_io_error(format!("can't resolve dns: {error}")))?
            .ok_or_else(|| new_io_error("no dns result"))?;
        return new_tcp_stream(
            (ip, port).into(),
            iface,
            #[cfg(target_os = "linux")]
            so_mark,
        )
        .await;
    }

    let (v4, v6) = tokio::join!(
        resolver.resolve_v4(address, false),
        resolver.resolve_v6(address, false),
    );
    let v4 = v4.ok().flatten().map(std::net::IpAddr::V4);
    let v6 = v6.ok().flatten().map(std::net::IpAddr::V6);
    match (v4, v6) {
        (Some(v4), Some(v6)) => {
            let first = new_tcp_stream(
                (v4, port).into(),
                iface,
                #[cfg(target_os = "linux")]
                so_mark,
            );
            let second = new_tcp_stream(
                (v6, port).into(),
                iface,
                #[cfg(target_os = "linux")]
                so_mark,
            );
            tokio::pin!(first, second);
            tokio::select! {
                result = &mut first => match result {
                    Ok(stream) => Ok(stream),
                    Err(first_error) => second.await.map_err(|second_error| {
                        new_io_error(format!(
                            "concurrent TCP dial failed: {first_error}; {second_error}"
                        ))
                    }),
                },
                result = &mut second => match result {
                    Ok(stream) => Ok(stream),
                    Err(second_error) => first.await.map_err(|first_error| {
                        new_io_error(format!(
                            "concurrent TCP dial failed: {first_error}; {second_error}"
                        ))
                    }),
                },
            }
        }
        (Some(ip), None) | (None, Some(ip)) => {
            new_tcp_stream(
                (ip, port).into(),
                iface,
                #[cfg(target_os = "linux")]
                so_mark,
            )
            .await
        }
        (None, None) => Err(new_io_error("no dns result")),
    }
}

impl DirectConnector {
    pub fn new() -> Self {
        Self
    }
}

pub static GLOBAL_DIRECT_CONNECTOR: LazyLock<Arc<dyn RemoteConnector>> =
    LazyLock::new(global_direct_connector);

fn global_direct_connector() -> Arc<dyn RemoteConnector> {
    Arc::new(DirectConnector::new())
}

#[async_trait]
impl RemoteConnector for DirectConnector {
    fn clone_connector(&self) -> Arc<dyn RemoteConnector> {
        Arc::new(Self::new())
    }

    async fn connect_stream(
        &self,
        resolver: ThreadSafeDNSResolver,
        address: &str,
        port: u16,
        iface: Option<&OutboundInterface>,
        #[cfg(target_os = "linux")] so_mark: Option<u32>,
    ) -> std::io::Result<AnyStream> {
        resolve_and_connect_tcp(
            resolver,
            address,
            port,
            iface,
            #[cfg(target_os = "linux")]
            so_mark,
        )
        .await
        .map(|x| Box::new(x) as _)
    }

    async fn connect_datagram(
        &self,
        resolver: ThreadSafeDNSResolver,
        src: Option<SocketAddr>,
        destination: SocksAddr,
        iface: Option<&OutboundInterface>,
        #[cfg(target_os = "linux")] so_mark: Option<u32>,
    ) -> std::io::Result<AnyOutboundDatagram> {
        let dgram = new_udp_socket(
            src,
            iface,
            #[cfg(target_os = "linux")]
            so_mark,
            destination
                .ip()
                .map(|ip| SocketAddr::new(ip, destination.port())),
        )
        .await
        .map(|x| OutboundDatagramImpl::new(x, resolver))?;

        let dgram = ChainedDatagramWrapper::new(dgram);
        Ok(Box::new(dgram))
    }
}

pub struct ProxyConnector {
    proxy: AnyOutboundHandler,
    connector: Arc<dyn RemoteConnector>,
}

impl ProxyConnector {
    pub fn new(
        proxy: AnyOutboundHandler,
        connector: Box<dyn RemoteConnector>,
    ) -> Self {
        Self {
            proxy,
            connector: Arc::from(connector),
        }
    }
}

impl Debug for ProxyConnector {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ProxyConnector")
            .field("proxy", &self.proxy.name())
            .finish()
    }
}

#[async_trait]
impl RemoteConnector for ProxyConnector {
    fn clone_connector(&self) -> Arc<dyn RemoteConnector> {
        Arc::new(Self {
            proxy: self.proxy.clone(),
            connector: self.connector.clone(),
        })
    }

    async fn connect_stream(
        &self,
        resolver: ThreadSafeDNSResolver,
        address: &str,
        port: u16,
        iface: Option<&OutboundInterface>,
        #[cfg(target_os = "linux")] so_mark: Option<u32>,
    ) -> std::io::Result<AnyStream> {
        let sess = Session {
            network: Network::Tcp,
            typ: Type::Ignore,
            destination: SocksAddr::Domain(address.to_owned(), port),
            iface: iface.cloned(),
            #[cfg(target_os = "linux")]
            so_mark,
            ..Default::default()
        };

        trace!(
            "proxy connector `{}` connecting to {}:{}",
            self.proxy.name(),
            address,
            port
        );

        let s = self
            .proxy
            .connect_stream_with_connector(&sess, resolver, self.connector.as_ref())
            .await?;

        let stream = ChainedStreamWrapper::new(s);
        stream.append_to_chain(self.proxy.name()).await;
        Ok(Box::new(stream))
    }

    async fn connect_datagram(
        &self,
        resolver: ThreadSafeDNSResolver,
        _src: Option<SocketAddr>,
        destination: SocksAddr,
        iface: Option<&OutboundInterface>,
        #[cfg(target_os = "linux")] so_mark: Option<u32>,
    ) -> std::io::Result<AnyOutboundDatagram> {
        let sess = Session {
            network: Network::Udp,
            typ: Type::Ignore,
            iface: iface.cloned(),
            destination: destination.clone(),
            #[cfg(target_os = "linux")]
            so_mark,
            ..Default::default()
        };
        let s = self
            .proxy
            .connect_datagram_with_connector(
                &sess,
                resolver,
                self.connector.as_ref(),
            )
            .await?;

        let stream = ChainedDatagramWrapper::new(s);
        stream.append_to_chain(self.proxy.name()).await;
        Ok(Box::new(stream))
    }
}
