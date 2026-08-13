use async_trait::async_trait;
use std::net::SocketAddr;
use tokio::net::{TcpListener, TcpStream};
use tracing::warn;

use super::utils::{ToCanonical, apply_tcp_options};

pub async fn accept_tcp_stream(
    listener: &TcpListener,
    allow_lan: bool,
) -> std::io::Result<(TcpStream, SocketAddr)> {
    loop {
        let (socket, source) = listener.accept().await?;
        let source = source.to_canonical();
        let local = match socket.local_addr() {
            Ok(local) => local.to_canonical(),
            Err(error) => {
                warn!("discarding TCP connection without local address: {error}");
                continue;
            }
        };
        if !allow_lan && source.ip() != local.ip() {
            warn!("Connection from {source} is not allowed");
            continue;
        }
        if let Err(error) = apply_tcp_options(&socket) {
            warn!(
                "discarding TCP connection while applying socket options: {error}"
            );
            continue;
        }
        return Ok((socket, source));
    }
}

#[async_trait]
pub trait InboundHandlerTrait: Sync + Send {
    /// support tcp or not
    fn handle_tcp(&self) -> bool;
    /// support udp or not
    fn handle_udp(&self) -> bool;
    async fn listen_tcp(&self) -> std::io::Result<()>;
    async fn listen_udp(&self) -> std::io::Result<()>;
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn accepts_connections_after_an_earlier_client_disconnects() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let first = TcpStream::connect(address).await.unwrap();
        let (first_accepted, first_source) =
            accept_tcp_stream(&listener, false).await.unwrap();

        assert_eq!(first_accepted.peer_addr().unwrap(), first_source);
        drop(first_accepted);
        drop(first);

        let second = TcpStream::connect(address).await.unwrap();
        let (accepted, source) = accept_tcp_stream(&listener, false).await.unwrap();

        assert_eq!(accepted.peer_addr().unwrap(), source);
        assert_eq!(source, second.local_addr().unwrap());
    }
}
