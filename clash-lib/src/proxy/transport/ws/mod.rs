use async_trait::async_trait;
use http::{Request, StatusCode, Uri};
use std::{collections::HashMap, io, net::Ipv6Addr};
use tokio_tungstenite::{
    client_async_with_config,
    tungstenite::{handshake::client::generate_key, protocol::WebSocketConfig},
};

use super::Transport;
use crate::{common::errors::map_io_error, proxy::AnyStream};

mod websocket;
mod websocket_early_data;

pub use websocket::WebsocketConn;
pub use websocket_early_data::WebsocketEarlyDataConn;

pub struct Client {
    server: String,
    port: u16,
    path: String,
    headers: HashMap<String, String>,
    ws_config: Option<WebSocketConfig>,
    max_early_data: usize,
    early_data_header_name: String,
}

impl Client {
    pub fn new(
        server: String,
        port: u16,
        path: String,
        headers: HashMap<String, String>,
        ws_config: Option<WebSocketConfig>,
        max_early_data: usize,
        early_data_header_name: String,
    ) -> Self {
        let (path, max_early_data, early_data_header_name) =
            path_early_data(path, max_early_data, early_data_header_name);
        Self {
            server,
            port,
            path,
            headers,
            ws_config,
            max_early_data,
            early_data_header_name,
        }
    }

    fn req(&self) -> io::Result<Request<()>> {
        let authority = if self.server.parse::<Ipv6Addr>().is_ok() {
            format!("[{}]:{}", self.server, self.port)
        } else {
            format!("{}:{}", self.server, self.port)
        };
        let path = if self.path.starts_with('/') {
            self.path.clone()
        } else {
            format!("/{}", self.path)
        };
        let uri = Uri::builder()
            .scheme("ws")
            .authority(authority.as_str())
            .path_and_query(path.as_str())
            .build()
            .map_err(map_io_error)?;
        let mut request = Request::builder()
            .method("GET")
            .header("Connection", "Upgrade")
            .header("Upgrade", "websocket")
            .header("Sec-WebSocket-Version", "13")
            .header("Sec-WebSocket-Key", generate_key())
            .uri(uri);
        for (k, v) in self.headers.iter() {
            request = request.header(k.as_str(), v.as_str());
        }
        if self.max_early_data > 0 {
            // we will replace this field later
            request = request.header(self.early_data_header_name.as_str(), "xxoo");
        }
        request.body(()).map_err(map_io_error)
    }
}

fn path_early_data(
    path: String,
    max_early_data: usize,
    early_data_header_name: String,
) -> (String, usize, String) {
    let Some((base, query)) = path.split_once('?') else {
        return (path, max_early_data, early_data_header_name);
    };
    let parameters =
        url::form_urlencoded::parse(query.as_bytes()).collect::<Vec<_>>();
    let Some(max_early_data) = parameters
        .iter()
        .find(|(name, _)| name == "ed")
        .and_then(|(_, value)| value.parse().ok())
    else {
        return (path, max_early_data, early_data_header_name);
    };
    let query = url::form_urlencoded::Serializer::new(String::new())
        .extend_pairs(parameters.iter().filter(|(name, _)| name != "ed"))
        .finish();
    let path = if query.is_empty() {
        base.to_owned()
    } else {
        format!("{base}?{query}")
    };
    (path, max_early_data, "Sec-WebSocket-Protocol".to_owned())
}

#[async_trait]
impl Transport for Client {
    async fn proxy_stream(&self, stream: AnyStream) -> std::io::Result<AnyStream> {
        let req = self.req()?;
        if self.max_early_data > 0 {
            let early_data_conn = WebsocketEarlyDataConn::new(
                stream,
                req,
                self.ws_config,
                self.early_data_header_name.clone(),
                self.max_early_data,
            );
            Ok(Box::new(early_data_conn))
        } else {
            let (stream, resp) =
                client_async_with_config(req, stream, self.ws_config)
                    .await
                    .map_err(map_io_error)?;

            if resp.status() != StatusCode::SWITCHING_PROTOCOLS {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::InvalidData,
                    "invalid response",
                ));
            }
            Ok(Box::new(WebsocketConn::from_websocket(stream)))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::Client;

    fn client(server: &str, path: &str) -> Client {
        Client::new(
            server.to_owned(),
            80,
            path.to_owned(),
            Default::default(),
            None,
            0,
            String::new(),
        )
    }

    #[test]
    fn request_adds_missing_path_prefix() {
        let request = client("104.17.133.14", "%2F%3Fed%3D2048").req().unwrap();

        assert_eq!(
            request.uri().to_string(),
            "ws://104.17.133.14:80/%2F%3Fed%3D2048"
        );
    }

    #[test]
    fn path_early_data_matches_mihomo_semantics() {
        let client = client("104.17.133.14", "/ws?ed=2048&token=value");
        let request = client.req().unwrap();

        assert_eq!(client.path, "/ws?token=value");
        assert_eq!(client.max_early_data, 2048);
        assert_eq!(client.early_data_header_name, "Sec-WebSocket-Protocol");
        assert_eq!(request.uri().path_and_query().unwrap(), "/ws?token=value");
        assert_eq!(request.headers()["Sec-WebSocket-Protocol"], "xxoo");
    }

    #[test]
    fn invalid_authority_returns_error() {
        assert!(client("invalid host", "/").req().is_err());
    }
}
