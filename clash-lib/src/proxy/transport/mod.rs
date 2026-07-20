#[cfg(feature = "shadowsocks")]
mod gost_websocket;
mod grpc;
mod h2;
mod reality;
#[cfg(feature = "shadowsocks")]
mod restls;
#[cfg(feature = "shadowsocks")]
mod shadow_tls;
mod simple_obfs;
#[cfg(feature = "shadowsocks")]
mod sip003;
pub mod splice_tls;
mod tls;
#[cfg(feature = "shadowsocks")]
mod v2ray;
mod ws;
mod xhttp;

#[cfg(feature = "shadowsocks")]
pub use gost_websocket::GostWsClient;
pub use grpc::Client as GrpcClient;
pub use h2::{Client as H2Client, Http2Stream};
pub use reality::Client as RealityClient;
#[cfg(feature = "shadowsocks")]
pub use restls::Client as RestlsClient;
#[cfg(feature = "shadowsocks")]
pub use shadow_tls::Client as Shadowtls;
#[cfg(feature = "shadowsocks")]
pub use simple_obfs::{SimpleOBFSMode, SimpleOBFSOption};
pub use simple_obfs::{SimpleObfsHttp, SimpleObfsTLS};
#[cfg(feature = "shadowsocks")]
pub use sip003::Plugin as Sip003Plugin;
pub use splice_tls::VisionOptions;
pub(crate) use tls::build_rustls_client_config_with_optional_ech;
pub use tls::{Client as TlsClient, EchOptions as TlsEchOptions};
#[cfg(feature = "shadowsocks")]
pub use v2ray::{V2RayOBFSOption, V2rayWsClient};
pub use ws::Client as WsClient;
pub use xhttp::{
    Client as XHttpClient, ClientConfig as XHttpClientConfig,
    DownloadConfig as XHttpDownloadConfig, H3TlsConfig as XHttpH3TlsConfig,
    ReuseConfig as XHttpReuseConfig,
};

#[async_trait::async_trait]
pub trait Transport: Send + Sync {
    /// Whether this transport runs over a UDP datagram socket instead of a
    /// pre-connected byte stream. XHTTP HTTP/3 uses this path so QUIC can still
    /// traverse a configured outbound connector.
    fn uses_datagram(&self) -> bool {
        false
    }

    fn additional_datagrams(&self) -> usize {
        0
    }

    /// Number of additional, independently wrapped streams required by this
    /// transport. Most transports only use the primary stream. XHTTP over
    /// HTTP/1.1 uses one extra stream so download and upload can stay active at
    /// the same time without bypassing the configured connector/TLS stack.
    fn additional_streams(&self) -> usize {
        0
    }

    async fn proxy_stream(
        &self,
        stream: super::AnyStream,
    ) -> std::io::Result<super::AnyStream>;

    async fn proxy_stream_with_additional(
        &self,
        stream: super::AnyStream,
        additional: Vec<super::AnyStream>,
    ) -> std::io::Result<super::AnyStream> {
        debug_assert!(additional.is_empty());
        self.proxy_stream(stream).await
    }

    /// Like `proxy_stream_with_additional`, but also exposes independently
    /// connected datagram sockets. XHTTP needs this when the primary request
    /// uses HTTP/2 while `download-settings.alpn` selects HTTP/3.
    async fn proxy_stream_with_additional_mixed(
        &self,
        stream: super::AnyStream,
        additional_streams: Vec<super::AnyStream>,
        additional_datagrams: Vec<(
            super::AnyOutboundDatagram,
            crate::session::SocksAddr,
            std::net::SocketAddr,
        )>,
    ) -> std::io::Result<super::AnyStream> {
        debug_assert!(additional_datagrams.is_empty());
        self.proxy_stream_with_additional(stream, additional_streams)
            .await
    }

    async fn proxy_datagram(
        &self,
        _datagram: super::AnyOutboundDatagram,
        _destination: crate::session::SocksAddr,
        _remote_addr: std::net::SocketAddr,
    ) -> std::io::Result<super::AnyStream> {
        Err(std::io::Error::new(
            std::io::ErrorKind::Unsupported,
            "transport does not support datagram sockets",
        ))
    }

    async fn proxy_datagram_with_additional(
        &self,
        datagram: super::AnyOutboundDatagram,
        destination: crate::session::SocksAddr,
        remote_addr: std::net::SocketAddr,
        additional: Vec<(
            super::AnyOutboundDatagram,
            crate::session::SocksAddr,
            std::net::SocketAddr,
        )>,
    ) -> std::io::Result<super::AnyStream> {
        debug_assert!(additional.is_empty());
        self.proxy_datagram(datagram, destination, remote_addr)
            .await
    }

    /// Datagram-primary counterpart of
    /// `proxy_stream_with_additional_mixed`. XHTTP uses it for an HTTP/3
    /// upload connection and an HTTP/1.1 or HTTP/2 download connection.
    async fn proxy_datagram_with_additional_mixed(
        &self,
        datagram: super::AnyOutboundDatagram,
        destination: crate::session::SocksAddr,
        remote_addr: std::net::SocketAddr,
        additional_streams: Vec<super::AnyStream>,
        additional_datagrams: Vec<(
            super::AnyOutboundDatagram,
            crate::session::SocksAddr,
            std::net::SocketAddr,
        )>,
    ) -> std::io::Result<super::AnyStream> {
        debug_assert!(additional_streams.is_empty());
        self.proxy_datagram_with_additional(
            datagram,
            destination,
            remote_addr,
            additional_datagrams,
        )
        .await
    }

    /// Like `proxy_stream`, but additionally returns a `VisionOptions` for
    /// transports that support XTLS-splice (Reality).  The default
    /// implementation delegates to `proxy_stream` and returns `None`,
    /// meaning no splice is available.
    async fn proxy_stream_spliced(
        &self,
        stream: super::AnyStream,
    ) -> std::io::Result<(super::AnyStream, Option<VisionOptions>)> {
        Ok((self.proxy_stream(stream).await?, None))
    }
}
#[cfg(feature = "utls")]
mod browser_tls;
