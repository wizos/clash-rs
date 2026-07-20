use std::io;

use async_smux::MuxBuilder;
use async_trait::async_trait;
use tracing::debug;

use crate::proxy::{AnyStream, transport::Transport};

use super::{V2RayOBFSOption, V2rayWsClient};

/// GOST's SIP003 WebSocket plugin uses the same WebSocket/TLS handshake as
/// Mihomo's VMess transport, followed by SMUX when `mux` is enabled.
pub struct GostWsClient {
    websocket: V2rayWsClient,
    mux: bool,
}

impl TryFrom<V2RayOBFSOption> for GostWsClient {
    type Error = io::Error;

    fn try_from(options: V2RayOBFSOption) -> Result<Self, Self::Error> {
        let mux = options.mux;
        let websocket = V2rayWsClient::try_new_with_tls(
            options.host,
            options.port,
            options.path,
            options.headers,
            options.tls,
            options.skip_cert_verify,
            false,
            options.fingerprint,
            options.ech,
            options.certificate.as_deref(),
            options.private_key.as_deref(),
        )?;
        Ok(Self { websocket, mux })
    }
}

#[async_trait]
impl Transport for GostWsClient {
    async fn proxy_stream(&self, stream: AnyStream) -> io::Result<AnyStream> {
        let stream = self.websocket.proxy_stream(stream).await?;
        if !self.mux {
            return Ok(stream);
        }
        let (mux, _acceptor, worker) =
            MuxBuilder::client().with_connection(stream).build();
        tokio::spawn(async move {
            if let Err(error) = worker.await {
                debug!("gost-plugin smux worker stopped: {error}");
            }
        });
        Ok(Box::new(mux.connect().map_err(io::Error::other)?))
    }
}
