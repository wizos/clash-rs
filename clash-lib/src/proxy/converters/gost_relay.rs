use crate::{
    Error,
    config::internal::proxy::OutboundGostRelay,
    proxy::{
        HandlerCommonOptions,
        gost_relay::{Handler, HandlerOptions},
        transport::TlsClient,
    },
};

impl TryFrom<OutboundGostRelay> for Handler {
    type Error = Error;

    fn try_from(config: OutboundGostRelay) -> Result<Self, Self::Error> {
        let tls = if config.tls {
            Some(TlsClient::new_mihomo(
                config.skip_cert_verify,
                config
                    .sni
                    .clone()
                    .unwrap_or_else(|| config.common_opts.server.clone()),
                None,
                None,
                config.fingerprint.clone(),
                config.client_fingerprint.as_deref(),
                None,
                config.certificate.as_deref(),
                config.private_key.as_deref(),
            )?)
        } else {
            None
        };

        Ok(Handler::new(HandlerOptions {
            name: config.common_opts.name,
            common_opts: HandlerCommonOptions {
                connector: config.common_opts.connect_via,
                ..Default::default()
            },
            server: config.common_opts.server,
            port: config.common_opts.port,
            forward: config.forward,
            udp: config.udp,
            mux: config.mux,
            username: config.username.unwrap_or_default(),
            password: config.password.unwrap_or_default(),
            tls,
        })?)
    }
}
