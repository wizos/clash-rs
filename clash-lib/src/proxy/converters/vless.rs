use crate::{
    Error,
    config::internal::proxy::{
        OutboundVless, XHttpDownloadSettings, XHttpReuseSettings,
    },
    proxy::{
        HandlerCommonOptions,
        transport::{
            GrpcClient, H2Client, RealityClient, TlsClient, Transport, WsClient,
            XHttpClient, XHttpClientConfig, XHttpDownloadConfig, XHttpH3TlsConfig,
            XHttpReuseConfig,
        },
        vless::{
            Handler, HandlerOptions, TransportDatagramOptions,
            TransportStreamOptions,
        },
        vmess::vmess_impl::http::HttpConfig,
    },
};
use std::sync::Arc;
use tracing::warn;

fn xhttp_reuse_config(
    config: Option<&XHttpReuseSettings>,
) -> Option<XHttpReuseConfig> {
    config.map(|config| XHttpReuseConfig {
        max_concurrency: config.max_concurrency.clone(),
        max_connections: config.max_connections.clone(),
        c_max_reuse_times: config.c_max_reuse_times.clone(),
        h_max_request_times: config.h_max_request_times.clone(),
        h_max_reusable_secs: config.h_max_reusable_secs.clone(),
        h_keep_alive_period: config.h_keep_alive_period,
    })
}

fn build_xhttp_download_stream(
    primary: &OutboundVless,
    download: &XHttpDownloadSettings,
) -> Result<(&'static str, TransportStreamOptions), Error> {
    let server = download
        .server
        .clone()
        .unwrap_or_else(|| primary.common_opts.server.clone());
    let port = download.port.unwrap_or(primary.common_opts.port);
    let tls_enabled = download.tls.unwrap_or(primary.tls.unwrap_or_default());
    let alpn = download.alpn.as_ref().or(primary.alpn.as_ref());
    let download_http_version = match alpn.map(Vec::as_slice) {
        Some([protocol]) if protocol == "http/1.1" => "http/1.1",
        Some([protocol]) if protocol == "h3" => "h3",
        _ => "h2",
    };
    if download_http_version == "h3" {
        return Err(Error::InvalidConfig(
            "xhttp HTTP/3 download-settings require a datagram transport".to_owned(),
        ));
    }

    let tls: Option<Box<dyn Transport>> = if !tls_enabled {
        None
    } else if let Some(reality) = download
        .reality_opts
        .as_ref()
        .or(primary.reality_opts.as_ref())
    {
        let public_key =
            super::utils::decode_base64_public_key(&reality.public_key)?;
        let short_id = super::utils::decode_short_id(&reality.short_id)?;
        let sni = download
            .server_name
            .clone()
            .or_else(|| primary.server_name.clone())
            .unwrap_or_else(|| server.clone());
        Some(Box::new(RealityClient::new_with_alpn(
            sni,
            public_key,
            short_id,
            Some(vec![download_http_version.to_owned()]),
        )))
    } else {
        let sni = download
            .server_name
            .clone()
            .or_else(|| primary.server_name.clone())
            .unwrap_or_else(|| server.clone());
        TlsClient::new_mihomo(
            download
                .skip_cert_verify
                .unwrap_or(primary.skip_cert_verify.unwrap_or_default()),
            sni,
            Some(vec![download_http_version.to_owned()]),
            None,
            download
                .fingerprint
                .clone()
                .or_else(|| primary.fingerprint.clone()),
            download
                .client_fingerprint
                .as_deref()
                .or(primary.client_fingerprint.as_deref()),
            super::utils::tls_ech_options(
                download.ech_opts.as_ref().or(primary.ech_opts.as_ref()),
            ),
            download.tls_cert.as_deref().or(primary.tls_cert.as_deref()),
            download.tls_key.as_deref().or(primary.tls_key.as_deref()),
        )
        .map_err(|error| Error::InvalidConfig(error.to_string()))?
        .into()
    };

    Ok((
        download_http_version,
        TransportStreamOptions { server, port, tls },
    ))
}

fn build_xhttp_download_h3(
    primary: &OutboundVless,
    download: &XHttpDownloadSettings,
) -> Result<(XHttpH3TlsConfig, TransportDatagramOptions), Error> {
    let server = download
        .server
        .clone()
        .unwrap_or_else(|| primary.common_opts.server.clone());
    let port = download.port.unwrap_or(primary.common_opts.port);
    if !download.tls.unwrap_or(primary.tls.unwrap_or_default()) {
        return Err(Error::InvalidConfig(
            "xhttp HTTP/3 download-settings require TLS".to_owned(),
        ));
    }
    if download.reality_opts.is_some() || primary.reality_opts.is_some() {
        return Err(Error::InvalidConfig(
            "xhttp HTTP/3 download-settings do not support reality".to_owned(),
        ));
    }
    let sni = download
        .server_name
        .clone()
        .or_else(|| primary.server_name.clone())
        .unwrap_or_else(|| server.clone());
    Ok((
        XHttpH3TlsConfig {
            sni,
            skip_cert_verify: download
                .skip_cert_verify
                .unwrap_or(primary.skip_cert_verify.unwrap_or_default()),
            certificate_fingerprint: download
                .fingerprint
                .clone()
                .or_else(|| primary.fingerprint.clone()),
            ech: super::utils::tls_ech_options(
                download.ech_opts.as_ref().or(primary.ech_opts.as_ref()),
            ),
            tls_cert: download
                .tls_cert
                .clone()
                .or_else(|| primary.tls_cert.clone()),
            tls_key: download.tls_key.clone().or_else(|| primary.tls_key.clone()),
        },
        TransportDatagramOptions { server, port },
    ))
}

impl TryFrom<OutboundVless> for Handler {
    type Error = crate::Error;

    fn try_from(value: OutboundVless) -> Result<Self, Self::Error> {
        (&value).try_into()
    }
}

impl TryFrom<&OutboundVless> for Handler {
    type Error = crate::Error;

    fn try_from(s: &OutboundVless) -> Result<Self, Self::Error> {
        let encryption = crate::proxy::vless::encryption::parse_client_encryption(
            s.encryption.as_deref().unwrap_or_default(),
        )
        .map_err(Error::InvalidConfig)?
        .map(Arc::new);
        let mut packet_addr = s.packet_addr.unwrap_or_default();
        let mut xudp = s.xudp.unwrap_or_default();
        match s.packet_encoding.as_deref() {
            Some("packetaddr" | "packet") => {
                packet_addr = true;
                xudp = false;
            }
            _ => {
                // Mihomo defaults VLESS UDP to XUDP whenever packetaddr is
                // not selected, including for an omitted packet-encoding.
                if !packet_addr {
                    xudp = true;
                }
            }
        }
        if xudp {
            packet_addr = false;
        }

        let skip_cert_verify = s.skip_cert_verify.unwrap_or_default();
        if skip_cert_verify {
            warn!(
                "skipping TLS cert verification for {}",
                s.common_opts.server
            );
        }

        let xhttp_h3 = s.network.as_deref() == Some("xhttp")
            && matches!(
                s.alpn.as_deref(),
                Some([protocol]) if protocol == "h3"
            );
        if xhttp_h3 && !s.tls.unwrap_or_default() {
            return Err(Error::InvalidConfig(
                "xhttp HTTP/3 requires TLS".to_owned(),
            ));
        }
        if xhttp_h3 && s.reality_opts.is_some() {
            return Err(Error::InvalidConfig(
                "xhttp HTTP/3 does not support reality".to_owned(),
            ));
        }

        let tls: Option<Box<dyn Transport>> = if xhttp_h3 {
            None
        } else if let Some(ref reality_opts) = s.reality_opts {
            // vless with reality

            // reality public-key bytes
            let pk_bytes =
                super::utils::decode_base64_public_key(&reality_opts.public_key)?;

            // reality short id bytes
            let short_id = super::utils::decode_short_id(&reality_opts.short_id)?;

            // SNI
            let sni = s
                .server_name
                .clone()
                .unwrap_or_else(|| s.common_opts.server.clone());

            Some(Box::new(RealityClient::new_with_alpn(
                sni,
                pk_bytes,
                short_id,
                s.alpn.clone(),
            )))
        } else {
            // vless without reality
            match s.tls.unwrap_or_default() {
                true => {
                    let alpn = if let Some(alpn) = s.alpn.clone() {
                        Some(alpn)
                    } else {
                        s.network
                            .as_ref()
                            .map(|x| match x.as_str() {
                                "" | "tcp" => Ok(vec![]),
                                "ws" => Ok(vec!["http/1.1".to_owned()]),
                                "http" => Ok(vec![]),
                                "h2" | "grpc" | "xhttp" => Ok(vec!["h2".to_owned()]),
                                _ => Err(Error::InvalidConfig(format!(
                                    "unsupported network: {x}"
                                ))),
                            })
                            .transpose()?
                    };
                    let client = TlsClient::new_mihomo(
                        s.skip_cert_verify.unwrap_or_default(),
                        s.server_name.as_ref().map(|x| x.to_owned()).unwrap_or(
                            s.ws_opts
                                .as_ref()
                                .and_then(|x| {
                                    x.headers.clone().and_then(|x| {
                                        let h = x.get("Host");
                                        h.cloned()
                                    })
                                })
                                .unwrap_or(s.common_opts.server.to_owned()),
                        ),
                        alpn,
                        None,
                        s.fingerprint.clone(),
                        s.client_fingerprint.as_deref(),
                        super::utils::tls_ech_options(s.ech_opts.as_ref()),
                        s.tls_cert.as_deref(),
                        s.tls_key.as_deref(),
                    )?;
                    Some(client)
                }
                false => None,
            }
        };

        let mut additional_streams = Vec::new();
        let mut additional_datagrams = Vec::new();
        Ok(Handler::new(HandlerOptions {
            name: s.common_opts.name.to_owned(),
            common_opts: HandlerCommonOptions {
                connector: s.common_opts.connect_via.clone(),
                ..Default::default()
            },
            server: s.common_opts.server.to_owned(),
            port: s.common_opts.port,
            uuid: s.uuid.clone(),
            udp: s.udp.unwrap_or(true),
            packet_addr,
            xudp,
            encryption,
            transport: s
                .network
                .clone()
                .map(|x| match x.as_str() {
                    "" | "tcp" => Ok(None),
                    "ws" => s
                        .ws_opts
                        .as_ref()
                        .map(|x| {
                            let client: WsClient = (x, &s.common_opts)
                                .try_into()
                                .expect("invalid ws options");
                            Some(Box::new(client) as _)
                        })
                        .ok_or(Error::InvalidConfig(
                            "ws_opts is required for ws".to_owned(),
                        )),
                    "http" => s
                        .http_opts
                        .as_ref()
                        .map(|options| {
                            Some(Box::new(HttpConfig::from((
                                options,
                                &s.common_opts,
                            ))) as _)
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
                            Some(Box::new(client) as _)
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
                            Some(Box::new(client) as _)
                        })
                        .ok_or(Error::InvalidConfig(
                            "grpc_opts is required for grpc".to_owned(),
                        )),
                    "xhttp" => s
                        .xhttp_opts
                        .as_ref()
                        .map(|options| {
                            let mode = options.mode.as_deref().unwrap_or("auto");
                            let effective_mode = if mode == "auto" {
                                if s.reality_opts.is_some() {
                                    if options.download_settings.is_some() {
                                        "stream-up"
                                    } else {
                                        "stream-one"
                                    }
                                } else {
                                    "packet-up"
                                }
                            } else {
                                mode
                            };
                            if effective_mode == "stream-one"
                                && options.download_settings.is_some()
                            {
                                return Err(Error::InvalidConfig(
                                    "xhttp mode `stream-one` cannot be used with \
                                     download-settings"
                                        .to_owned(),
                                ));
                            }
                            let mut download =
                                options.download_settings.as_ref().map(|download| {
                                    XHttpDownloadConfig {
                                        host: download.host.clone().unwrap_or_else(
                                            || {
                                                options.host.clone().unwrap_or_else(
                                                    || s.common_opts.server.clone(),
                                                )
                                            },
                                        ),
                                        path: download.path.clone().unwrap_or_else(
                                            || {
                                                options.path.clone().unwrap_or_else(
                                                    || "/".to_owned(),
                                                )
                                            },
                                        ),
                                        http_version: None,
                                        headers: download
                                            .headers
                                            .clone()
                                            .unwrap_or_else(|| {
                                                options
                                                    .headers
                                                    .clone()
                                                    .unwrap_or_default()
                                            }),
                                        h3_tls: None,
                                        reuse: xhttp_reuse_config(
                                            download.reuse_settings.as_ref(),
                                        ),
                                    }
                                });
                            let http_version = match s.alpn.as_deref() {
                                Some([protocol]) if protocol == "http/1.1" => {
                                    "http/1.1"
                                }
                                Some([protocol]) if protocol == "h3" => "h3",
                                _ => "h2",
                            };
                            if let Some(download_settings) =
                                options.download_settings.as_ref()
                            {
                                let download_http_version = match download_settings
                                    .alpn
                                    .as_deref()
                                {
                                    Some([protocol]) if protocol == "http/1.1" => {
                                        "http/1.1"
                                    }
                                    Some([protocol]) if protocol == "h3" => "h3",
                                    Some(_) => "h2",
                                    None => http_version,
                                };
                                let download_config = download
                                    .as_mut()
                                    .expect("download-settings checked");
                                download_config.http_version =
                                    Some(download_http_version.to_owned());
                                if download_http_version == "h3" {
                                    let (download_tls, datagram_options) =
                                        build_xhttp_download_h3(
                                            s,
                                            download_settings,
                                        )?;
                                    download_config.h3_tls = Some(download_tls);
                                    additional_datagrams.push(datagram_options);
                                } else {
                                    let (built_version, stream_options) =
                                        build_xhttp_download_stream(
                                            s,
                                            download_settings,
                                        )?;
                                    debug_assert_eq!(
                                        download_http_version,
                                        built_version,
                                    );
                                    additional_streams.push(stream_options);
                                }
                            }
                            let client = XHttpClient::new(XHttpClientConfig {
                                host: options
                                    .host
                                    .clone()
                                    .unwrap_or_else(|| s.common_opts.server.clone()),
                                path: options
                                    .path
                                    .clone()
                                    .unwrap_or_else(|| "/".to_owned()),
                                mode: effective_mode.to_owned(),
                                http_version: Some(http_version.to_owned()),
                                method: options.uplink_http_method.clone(),
                                headers: options.headers.clone().unwrap_or_default(),
                                no_grpc_header: options.no_grpc_header,
                                x_padding_bytes: options.x_padding_bytes.clone(),
                                x_padding_obfs_mode: options.x_padding_obfs_mode,
                                x_padding_key: options.x_padding_key.clone(),
                                x_padding_header: options.x_padding_header.clone(),
                                x_padding_placement: options
                                    .x_padding_placement
                                    .clone(),
                                x_padding_method: options.x_padding_method.clone(),
                                session_placement: options.session_placement.clone(),
                                session_key: options.session_key.clone(),
                                seq_placement: options.seq_placement.clone(),
                                seq_key: options.seq_key.clone(),
                                uplink_data_placement: options
                                    .uplink_data_placement
                                    .clone(),
                                uplink_data_key: options.uplink_data_key.clone(),
                                uplink_chunk_size: options.uplink_chunk_size.clone(),
                                sc_max_each_post_bytes: options
                                    .sc_max_each_post_bytes
                                    .clone(),
                                sc_min_posts_interval_ms: options
                                    .sc_min_posts_interval_ms
                                    .clone(),
                                download,
                                h3_tls: xhttp_h3.then(|| XHttpH3TlsConfig {
                                    sni: s.server_name.clone().unwrap_or_else(
                                        || s.common_opts.server.clone(),
                                    ),
                                    skip_cert_verify: s
                                        .skip_cert_verify
                                        .unwrap_or_default(),
                                    certificate_fingerprint: s.fingerprint.clone(),
                                    ech: super::utils::tls_ech_options(
                                        s.ech_opts.as_ref(),
                                    ),
                                    tls_cert: s.tls_cert.clone(),
                                    tls_key: s.tls_key.clone(),
                                }),
                                reuse: xhttp_reuse_config(
                                    options.reuse_settings.as_ref(),
                                ),
                            })
                            .map_err(|error| {
                                Error::InvalidConfig(error.to_string())
                            })?;
                            Ok(Some(Box::new(client) as _))
                        })
                        .ok_or(Error::InvalidConfig(
                            "xhttp_opts is required for xhttp".to_owned(),
                        ))?,
                    _ => Err(Error::InvalidConfig(format!(
                        "unsupported network: {x}"
                    ))),
                })
                .transpose()?
                .flatten(),
            tls,
            additional_streams,
            additional_datagrams,
            flow: s.flow.clone(),
        }))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::internal::proxy::CommonConfigOptions;

    #[test]
    fn test_vless_network_tcp() {
        crate::setup_default_crypto_provider();
        // Test that network: tcp is accepted and results in successful parsing
        let config = OutboundVless {
            common_opts: CommonConfigOptions {
                name: "test-tcp".to_string(),
                server: "example.com".to_string(),
                port: 443,
                ..Default::default()
            },
            uuid: "test-uuid".to_string(),
            udp: Some(true),
            tls: Some(true),
            skip_cert_verify: Some(true),
            server_name: Some("example.com".to_string()),
            network: Some("tcp".to_string()),
            ws_opts: None,
            h2_opts: None,
            grpc_opts: None,
            ..Default::default()
        };

        let handler = Handler::try_from(&config);
        assert!(
            handler.is_ok(),
            "VLess handler with network: tcp should parse successfully"
        );
    }

    #[test]
    fn test_vless_network_none() {
        crate::setup_default_crypto_provider();
        // Test that omitting network field also results in successful parsing
        let config = OutboundVless {
            common_opts: CommonConfigOptions {
                name: "test-none".to_string(),
                server: "example.com".to_string(),
                port: 443,
                ..Default::default()
            },
            uuid: "test-uuid".to_string(),
            udp: Some(true),
            tls: Some(true),
            skip_cert_verify: Some(true),
            server_name: Some("example.com".to_string()),
            network: None,
            ws_opts: None,
            h2_opts: None,
            grpc_opts: None,
            ..Default::default()
        };

        let handler = Handler::try_from(&config);
        assert!(
            handler.is_ok(),
            "VLess handler without network field should parse successfully"
        );
    }

    #[test]
    fn test_vless_network_invalid() {
        crate::setup_default_crypto_provider();
        // Test that invalid network types are rejected
        let config = OutboundVless {
            common_opts: CommonConfigOptions {
                name: "test-invalid".to_string(),
                server: "example.com".to_string(),
                port: 443,
                ..Default::default()
            },
            uuid: "test-uuid".to_string(),
            udp: Some(true),
            tls: Some(true),
            skip_cert_verify: Some(true),
            server_name: Some("example.com".to_string()),
            network: Some("invalid-network".to_string()),
            ws_opts: None,
            h2_opts: None,
            grpc_opts: None,
            ..Default::default()
        };

        let handler = Handler::try_from(&config);
        assert!(
            handler.is_err(),
            "VLess handler with invalid network should fail"
        );
        let err = handler.unwrap_err();
        assert!(
            err.to_string().contains("unsupported network"),
            "Error should mention unsupported network"
        );
    }
}
