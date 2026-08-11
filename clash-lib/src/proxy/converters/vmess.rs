use crate::{
    Error,
    config::internal::proxy::OutboundVmess,
    proxy::{
        HandlerCommonOptions,
        transport::{
            GrpcClient, H2Client, RealityClient, TlsClient, Transport, WsClient,
        },
        vmess::{Handler, HandlerOptions, vmess_impl::http::HttpConfig},
    },
};

impl TryFrom<OutboundVmess> for Handler {
    type Error = crate::Error;

    fn try_from(value: OutboundVmess) -> Result<Self, Self::Error> {
        (&value).try_into()
    }
}

impl TryFrom<&OutboundVmess> for Handler {
    type Error = crate::Error;

    fn try_from(s: &OutboundVmess) -> Result<Self, Self::Error> {
        let mut packet_addr = s.packet_addr.unwrap_or_default();
        let mut xudp = s.xudp.unwrap_or_default();
        match s.packet_encoding.as_deref() {
            None | Some("") => {}
            Some("packetaddr" | "packet") => {
                packet_addr = true;
                xudp = false;
            }
            Some("xudp") => xudp = true,
            Some(encoding) => {
                return Err(Error::InvalidConfig(format!(
                    "unsupported vmess packet-encoding `{encoding}`"
                )));
            }
        }
        if xudp {
            packet_addr = false;
        }

        if s.reality_opts.is_some()
            && !matches!(s.network.as_deref(), None | Some("" | "tcp"))
        {
            return Err(Error::InvalidConfig(
                "vmess reality-opts currently require network: tcp".to_owned(),
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
            uuid: s.uuid.clone(),
            alter_id: s.alter_id,
            security: s.cipher.clone().unwrap_or_else(|| "auto".to_owned()),
            udp: s.udp.unwrap_or(true),
            packet_addr,
            xudp,
            global_padding: s.global_padding.unwrap_or_default(),
            authenticated_length: s.authenticated_length.unwrap_or_default(),
            transport: s
                .network
                .clone()
                .filter(|network| !matches!(network.as_str(), "" | "tcp"))
                .map(|x| match x.as_str() {
                    "ws" => s
                        .ws_opts
                        .as_ref()
                        .map(|x| {
                            let client: WsClient = (x, &s.common_opts)
                                .try_into()
                                .expect("invalid ws options");
                            Box::new(client) as _
                        })
                        .ok_or(Error::InvalidConfig(
                            "ws_opts is required for ws".to_owned(),
                        )),
                    "http" => s
                        .http_opts
                        .as_ref()
                        .map(|options| {
                            Box::new(HttpConfig::from((options, &s.common_opts)))
                                as _
                        })
                        .ok_or(Error::InvalidConfig(
                            "http_opts is required for http".to_owned(),
                        )),
                    "h2" => s
                        .h2_opts
                        .as_ref()
                        .map(|x| {
                            let client: H2Client = (x, &s.common_opts)
                                .try_into()
                                .expect("invalid h2 options");
                            Box::new(client) as _
                        })
                        .ok_or(Error::InvalidConfig(
                            "h2_opts is required for h2".to_owned(),
                        )),
                    "grpc" => s
                        .grpc_opts
                        .as_ref()
                        .map(|x| {
                            let client: GrpcClient =
                                (s.server_name.clone(), x, &s.common_opts)
                                    .try_into()
                                    .expect("invalid grpc options");
                            Box::new(client) as _
                        })
                        .ok_or(Error::InvalidConfig(
                            "grpc_opts is required for grpc".to_owned(),
                        )),
                    _ => Err(Error::InvalidConfig(format!(
                        "unsupported network: {x}"
                    ))),
                })
                .transpose()?,
            tls: if s.tls.unwrap_or_default() || s.reality_opts.is_some() {
                let alpn = if let Some(alpn) = s.alpn.clone() {
                    Some(alpn)
                } else {
                    s.network
                        .as_ref()
                        .map(|x| match x.as_str() {
                            "" | "tcp" => Ok(vec![]),
                            "ws" => Ok(vec!["http/1.1".to_owned()]),
                            "http" => Ok(vec![]),
                            "h2" | "grpc" => Ok(vec!["h2".to_owned()]),
                            _ => Err(Error::InvalidConfig(format!(
                                "unsupported network: {x}"
                            ))),
                        })
                        .transpose()?
                };
                let alpn =
                    super::utils::tls_alpn_for_network(s.network.as_deref(), alpn);
                let sni = s.server_name.as_ref().map(|x| x.to_owned()).unwrap_or(
                    s.ws_opts
                        .as_ref()
                        .and_then(|x| {
                            x.headers.clone().and_then(|x| x.get("Host").cloned())
                        })
                        .unwrap_or(s.common_opts.server.to_owned()),
                );
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
                            s.skip_cert_verify.unwrap_or_default(),
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
            } else {
                None
            },
        });
        Ok(h)
    }
}
