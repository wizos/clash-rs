use crate::{
    config::internal::proxy::OutboundHttp,
    proxy::{
        HandlerCommonOptions,
        http::{HttpOutbound, HttpOutboundOptions},
        transport::TlsClient,
    },
};

impl TryFrom<OutboundHttp> for HttpOutbound {
    type Error = crate::Error;

    fn try_from(value: OutboundHttp) -> Result<Self, Self::Error> {
        (&value).try_into()
    }
}

impl TryFrom<&OutboundHttp> for HttpOutbound {
    type Error = crate::Error;

    fn try_from(config: &OutboundHttp) -> Result<Self, Self::Error> {
        let tls_client = if config.tls {
            Some(Box::new(TlsClient::new_with_fingerprint(
                config.skip_cert_verify,
                config
                    .sni
                    .clone()
                    .unwrap_or_else(|| config.common_opts.server.clone()),
                None,
                None,
                config.fingerprint.clone(),
                config.certificate.as_deref(),
                config.private_key.as_deref(),
            )?) as _)
        } else {
            None
        };
        Ok(HttpOutbound::new(HttpOutboundOptions {
            name: config.common_opts.name.clone(),
            common_opts: HandlerCommonOptions {
                connector: config.common_opts.connect_via.clone(),
                ..Default::default()
            },
            server: config.common_opts.server.clone(),
            port: config.common_opts.port,
            username: config.username.clone(),
            password: config.password.clone(),
            headers: config.headers.clone().unwrap_or_default(),
            tls_client,
        }))
    }
}
