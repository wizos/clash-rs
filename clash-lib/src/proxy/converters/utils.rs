use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use http::uri::InvalidUri;

use crate::{
    Error,
    config::proxy::{
        CommonConfigOptions, EchOptions, GrpcOpt, H2Opt, HttpOpt, WsOpt,
    },
    proxy::{
        transport::{self, GrpcClient, H2Client, TlsEchOptions, WsClient},
        vmess::vmess_impl::http::HttpConfig,
    },
};

pub fn tls_ech_options(options: Option<&EchOptions>) -> Option<TlsEchOptions> {
    options
        .filter(|options| options.enable)
        .map(|options| TlsEchOptions {
            config: options.config.clone(),
            query_server_name: options.query_server_name.clone(),
        })
}

pub fn tls_alpn_for_network(
    network: Option<&str>,
    configured: Option<Vec<String>>,
) -> Option<Vec<String>> {
    if matches!(network, Some("ws")) {
        Some(vec!["http/1.1".to_owned()])
    } else {
        configured
    }
}

impl TryFrom<(&WsOpt, &CommonConfigOptions)> for WsClient {
    type Error = std::io::Error;

    fn try_from(pair: (&WsOpt, &CommonConfigOptions)) -> Result<Self, Self::Error> {
        let (x, common) = pair;
        let path = x.path.as_ref().map(|x| x.to_owned()).unwrap_or_default();
        let headers = x.headers.as_ref().map(|x| x.to_owned()).unwrap_or_default();
        let max_early_data = x.max_early_data.unwrap_or_default() as usize;
        let early_data_header_name = x
            .early_data_header_name
            .as_ref()
            .map(|x| x.to_owned())
            .unwrap_or_default();

        let client = transport::WsClient::new(
            common.server.to_owned(),
            common.port,
            path,
            headers,
            None,
            max_early_data,
            early_data_header_name,
        );
        Ok(client)
    }
}

impl From<(&HttpOpt, &CommonConfigOptions)> for HttpConfig {
    fn from((options, common): (&HttpOpt, &CommonConfigOptions)) -> Self {
        Self {
            method: options.method.clone().unwrap_or_else(|| "GET".to_owned()),
            host: common.server.clone(),
            path: options
                .path
                .as_ref()
                .map(|path| path.to_vec())
                .unwrap_or_else(|| vec!["/".to_owned()]),
            headers: options
                .headers
                .as_ref()
                .map(|headers| {
                    headers
                        .iter()
                        .map(|(name, values)| (name.clone(), values.to_vec()))
                        .collect()
                })
                .unwrap_or_default(),
        }
    }
}

impl TryFrom<(Option<String>, &GrpcOpt, &CommonConfigOptions)> for GrpcClient {
    type Error = InvalidUri;

    fn try_from(
        opt: (Option<String>, &GrpcOpt, &CommonConfigOptions),
    ) -> Result<Self, Self::Error> {
        let (sni, x, common) = opt;
        let client = transport::GrpcClient::new(
            sni.as_ref().unwrap_or(&common.server).to_owned(),
            format!("/{}", x.grpc_service_name.as_deref().unwrap_or_default())
                .try_into()?,
        );
        Ok(client)
    }
}

impl TryFrom<(&H2Opt, &CommonConfigOptions)> for H2Client {
    type Error = InvalidUri;

    fn try_from(pair: (&H2Opt, &CommonConfigOptions)) -> Result<Self, Self::Error> {
        let (x, common) = pair;
        let host = x
            .host
            .as_ref()
            .map(|x| x.to_owned())
            .unwrap_or(vec![common.server.to_owned()]);
        let path = x.path.as_ref().map(|x| x.to_owned()).unwrap_or_default();

        Ok(H2Client::new(
            host,
            std::collections::HashMap::new(),
            http::Method::GET,
            path.try_into()?,
        ))
    }
}

pub fn decode_base64_public_key(base64_public_key: &str) -> Result<[u8; 32], Error> {
    URL_SAFE_NO_PAD
        .decode(base64_public_key)
        .map_err(|e| {
            Error::InvalidConfig(format!("reality public-key base64: {e}"))
        })?
        .try_into()
        .map_err(|_| {
            Error::InvalidConfig("reality public-key must decode to 32 bytes".into())
        })
}

pub fn decode_short_id(hex_short_id: &str) -> Result<Vec<u8>, Error> {
    hex::decode(hex_short_id)
        .map_err(|e| Error::InvalidConfig(format!("reality short-id hex: {e}")))
}

#[cfg(test)]
mod tests {
    use super::tls_alpn_for_network;

    #[test]
    fn websocket_requires_http_1_1_alpn() {
        assert_eq!(
            tls_alpn_for_network(
                Some("ws"),
                Some(vec![
                    "h3".to_owned(),
                    "h2".to_owned(),
                    "http/1.1".to_owned(),
                ]),
            ),
            Some(vec!["http/1.1".to_owned()]),
        );
    }
}
