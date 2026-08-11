use std::time::Duration;

use crate::{
    Error,
    config::internal::proxy::OutboundAnytls,
    proxy::{
        HandlerCommonOptions,
        anytls::{Handler, HandlerOptions},
        transport::TlsClient,
    },
};

const DEFAULT_ALPN: [&str; 2] = ["h2", "http/1.1"];

impl TryFrom<OutboundAnytls> for Handler {
    type Error = crate::Error;

    fn try_from(value: OutboundAnytls) -> Result<Self, Self::Error> {
        (&value).try_into()
    }
}

impl TryFrom<&OutboundAnytls> for Handler {
    type Error = crate::Error;

    fn try_from(s: &OutboundAnytls) -> Result<Self, Self::Error> {
        let skip_cert_verify = s.skip_cert_verify.unwrap_or_default();
        Ok(Handler::new(HandlerOptions {
            name: s.common_opts.name.to_owned(),
            common_opts: HandlerCommonOptions {
                connector: s.common_opts.connect_via.clone(),
                ..Default::default()
            },
            server: s.common_opts.server.to_owned(),
            port: s.common_opts.port,
            password: s.password.clone(),
            udp: s.udp.unwrap_or_default(),
            tls: {
                let client = TlsClient::new_mihomo(
                    skip_cert_verify,
                    s.sni
                        .clone()
                        .unwrap_or_else(|| s.common_opts.server.clone()),
                    s.alpn
                        .clone()
                        .or(Some(DEFAULT_ALPN.map(str::to_owned).to_vec())),
                    None,
                    s.fingerprint.clone(),
                    s.client_fingerprint.as_deref(),
                    super::utils::tls_ech_options(s.ech_opts.as_ref()),
                    s.tls_cert.as_deref(),
                    s.tls_key.as_deref(),
                )?;
                Some(client)
            },
            transport: None,
            idle_session_check_interval: Duration::from_secs(
                s.idle_session_check_interval.unwrap_or_default(),
            ),
            idle_session_timeout: Duration::from_secs(
                s.idle_session_timeout.unwrap_or_default(),
            ),
            min_idle_session: usize::try_from(
                s.min_idle_session.unwrap_or_default(),
            )
            .map_err(|_| {
                Error::InvalidConfig(
                    "anytls min-idle-session exceeds this platform's limit"
                        .to_owned(),
                )
            })?,
        }))
    }
}
