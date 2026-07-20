use crate::{
    Error,
    config::internal::proxy::OutboundTrustTunnel,
    proxy::{
        HandlerCommonOptions,
        transport::TlsClient,
        trusttunnel::{Handler, HandlerOptions, QuicTlsOptions},
    },
};

impl TryFrom<OutboundTrustTunnel> for Handler {
    type Error = Error;

    fn try_from(config: OutboundTrustTunnel) -> Result<Self, Self::Error> {
        let required_alpn = if config.quic { "h3" } else { "h2" };
        let alpn = config
            .alpn
            .clone()
            .unwrap_or_else(|| vec![required_alpn.to_owned()]);
        if !alpn.iter().any(|protocol| protocol == required_alpn) {
            return Err(Error::InvalidConfig(format!(
                "trusttunnel {} mode requires ALPN `{required_alpn}`",
                if config.quic { "HTTP/3" } else { "HTTP/2" }
            )));
        }
        let sni = config
            .sni
            .clone()
            .unwrap_or_else(|| config.common_opts.server.clone());
        let ech = super::utils::tls_ech_options(config.ech_opts.as_ref());
        let tls = TlsClient::new_mihomo(
            config.skip_cert_verify,
            sni.clone(),
            Some(alpn),
            Some(required_alpn.to_owned()),
            config.fingerprint.clone(),
            config.client_fingerprint.as_deref(),
            ech.clone(),
            config.certificate.as_deref(),
            config.private_key.as_deref(),
        )?;
        let quic_tls = config.quic.then(|| {
            QuicTlsOptions::new(
                sni,
                config.skip_cert_verify,
                config.fingerprint.clone(),
                ech,
                config.certificate.clone(),
                config.private_key.clone(),
            )
        });

        Handler::new(HandlerOptions {
            name: config.common_opts.name,
            common_opts: HandlerCommonOptions {
                connector: config.common_opts.connect_via,
                ..Default::default()
            },
            server: config.common_opts.server,
            port: config.common_opts.port,
            username: config.username.unwrap_or_default(),
            password: config.password.unwrap_or_default(),
            udp: config.udp,
            tls,
            health_check: config.health_check,
            quic: config.quic,
            quic_tls,
            congestion_controller: config.congestion_controller,
            cwnd: config.cwnd,
            bbr_profile: config.bbr_profile,
            max_connections: config.max_connections,
            min_streams: config.min_streams,
            max_streams: config.max_streams,
        })
    }
}
