const DEFAULT_ALPN: [&str; 2] = ["h2", "http/1.1"];
const DEFAULT_WS_ALPN: [&str; 1] = ["http/1.1"];

#[cfg(feature = "shadowsocks")]
use crate::proxy::trojan::SsCipherOptions;
use crate::{
    Error,
    config::internal::proxy::OutboundTrojan,
    proxy::{
        HandlerCommonOptions,
        transport::{GrpcClient, RealityClient, TlsClient, Transport, WsClient},
        trojan::{Handler, HandlerOptions},
    },
};

impl TryFrom<OutboundTrojan> for Handler {
    type Error = crate::Error;

    fn try_from(value: OutboundTrojan) -> Result<Self, Self::Error> {
        (&value).try_into()
    }
}

impl TryFrom<&OutboundTrojan> for Handler {
    type Error = crate::Error;

    fn try_from(s: &OutboundTrojan) -> Result<Self, Self::Error> {
        #[cfg(feature = "shadowsocks")]
        let ss_cipher = if let Some(options) = s.ss_opts.as_ref()
            && options.enabled
        {
            let method = options.method.clone().ok_or_else(|| {
                Error::InvalidConfig(
                    "trojan ss-opts.method is required when enabled".to_owned(),
                )
            })?;
            crate::proxy::shadowsocks::map_cipher(&method).map_err(|error| {
                Error::InvalidConfig(format!("invalid trojan ss-opts: {error}"))
            })?;
            Some(SsCipherOptions {
                method,
                password: options.password.clone().ok_or_else(|| {
                    Error::InvalidConfig(
                        "trojan ss-opts.password is required when enabled"
                            .to_owned(),
                    )
                })?,
            })
        } else {
            None
        };
        #[cfg(not(feature = "shadowsocks"))]
        if s.ss_opts.as_ref().is_some_and(|options| options.enabled) {
            return Err(Error::InvalidConfig(
                "trojan ss-opts requires the shadowsocks feature".to_owned(),
            ));
        }

        let skip_cert_verify = s.skip_cert_verify.unwrap_or_default();
        if s.reality_opts.is_some()
            && !matches!(s.network.as_deref(), None | Some("" | "tcp"))
        {
            return Err(Error::InvalidConfig(
                "trojan reality-opts currently require network: tcp".to_owned(),
            ));
        }

        let h = Handler::new(HandlerOptions {
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
                let sni = s
                    .sni
                    .clone()
                    .unwrap_or_else(|| s.common_opts.server.clone());
                let alpn = s.alpn.clone().or(Some({
                    let network = s.network.as_deref();
                    let alpn: &[&str] = if let Some("ws") = network {
                        &DEFAULT_WS_ALPN
                    } else {
                        &DEFAULT_ALPN
                    };
                    alpn.iter().copied().map(str::to_owned).collect()
                }));
                let alpn =
                    super::utils::tls_alpn_for_network(s.network.as_deref(), alpn);
                let client: Box<dyn Transport> =
                    if let Some(reality_opts) = s.reality_opts.as_ref() {
                        let public_key = super::utils::decode_base64_public_key(
                            &reality_opts.public_key,
                        )?;
                        let short_id =
                            super::utils::decode_short_id(&reality_opts.short_id)?;
                        Box::new(RealityClient::new_with_alpn(
                            sni, public_key, short_id, alpn,
                        ))
                    } else {
                        TlsClient::new_mihomo(
                            skip_cert_verify,
                            sni,
                            alpn,
                            None,
                            s.fingerprint.clone(),
                            s.client_fingerprint.as_deref(),
                            super::utils::tls_ech_options(s.ech_opts.as_ref()),
                            s.tls_cert.as_deref(),
                            s.tls_key.as_deref(),
                        )?
                    };
                Some(client)
            },
            transport: s
                .network
                .as_ref()
                .filter(|network| !matches!(network.as_str(), "" | "tcp"))
                .map(|x| match x.as_str() {
                    "ws" => s
                        .ws_opts
                        .as_ref()
                        .map(|x| {
                            let client: WsClient = (x, &s.common_opts)
                                .try_into()
                                .expect("invalid ws_opts");
                            Box::new(client) as _
                        })
                        .ok_or(Error::InvalidConfig(
                            "ws_opts is required for ws".to_owned(),
                        )),
                    "grpc" => s
                        .grpc_opts
                        .as_ref()
                        .map(|x| {
                            let client: GrpcClient =
                                (s.sni.clone(), x, &s.common_opts)
                                    .try_into()
                                    .expect("invalid grpc_opts");
                            Box::new(client) as _
                        })
                        .ok_or(Error::InvalidConfig(
                            "grpc_opts is required for grpc".to_owned(),
                        )),
                    _ => Err(Error::InvalidConfig(format!(
                        "unsupported trojan network: {x}"
                    ))),
                })
                .transpose()?,
            #[cfg(feature = "shadowsocks")]
            ss_cipher,
        });
        Ok(h)
    }
}
