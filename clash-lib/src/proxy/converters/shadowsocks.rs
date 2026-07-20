use std::collections::HashMap;

use crate::{
    Error,
    config::internal::proxy::OutboundShadowsocks,
    proxy::{
        HandlerCommonOptions,
        shadowsocks::outbound::{Handler, HandlerOptions},
        transport::{
            GostWsClient, RestlsClient, Shadowtls, SimpleOBFSMode, SimpleOBFSOption,
            SimpleObfsHttp, SimpleObfsTLS, V2RayOBFSOption, V2rayWsClient,
        },
    },
};

impl TryFrom<OutboundShadowsocks> for Handler {
    type Error = crate::Error;

    fn try_from(value: OutboundShadowsocks) -> Result<Self, Self::Error> {
        (&value).try_into()
    }
}

impl TryFrom<&OutboundShadowsocks> for Handler {
    type Error = crate::Error;

    fn try_from(s: &OutboundShadowsocks) -> Result<Self, Self::Error> {
        let udp_over_tcp_version = match s.udp_over_tcp_version {
            0 => crate::proxy::uot::LEGACY_VERSION,
            crate::proxy::uot::LEGACY_VERSION | crate::proxy::uot::VERSION => {
                s.udp_over_tcp_version
            }
            version => {
                return Err(Error::InvalidConfig(format!(
                    "unknown udp-over-tcp protocol version: {version}"
                )));
            }
        };
        let h = Handler::new(HandlerOptions {
            name: s.common_opts.name.to_owned(),
            common_opts: HandlerCommonOptions {
                connector: s.common_opts.connect_via.clone(),
                ..Default::default()
            },
            server: s.common_opts.server.to_owned(),
            port: s.common_opts.port,
            password: s.password.to_owned(),
            cipher: s.cipher.to_owned(),
            plugin: match &s.plugin {
                Some(plugin) => match plugin.as_str() {
                    "obfs" => {
                        tracing::warn!(
                            "simple-obfs is deprecated, please use v2ray-plugin \
                             instead"
                        );
                        let opt: SimpleOBFSOption = s
                            .plugin_opts
                            .clone()
                            .ok_or(Error::InvalidConfig(
                                "plugin_opts is required for plugin obfs".to_owned(),
                            ))?
                            .try_into()?;
                        let plugin = match opt.mode {
                            SimpleOBFSMode::Http => Box::new(SimpleObfsHttp::new(
                                opt.host,
                                s.common_opts.port,
                            ))
                                as _,
                            SimpleOBFSMode::Tls => {
                                Box::new(SimpleObfsTLS::new(opt.host)) as _
                            }
                        };
                        Some(plugin)
                    }
                    "v2ray-plugin" => {
                        let mut opt: V2RayOBFSOption = s
                            .plugin_opts
                            .clone()
                            .ok_or(Error::InvalidConfig(
                                "plugin_opts is required for plugin obfs".to_owned(),
                            ))?
                            .try_into()?;
                        if opt.port == 0 {
                            opt.port = s.common_opts.port;
                        }
                        let plugin = V2rayWsClient::try_from(opt)?;
                        Some(Box::new(plugin) as _)
                    }
                    "gost-plugin" => {
                        let mut opt = parse_websocket_plugin_options(
                            s.plugin_opts.clone().ok_or(Error::InvalidConfig(
                                "plugin_opts is required for gost-plugin".to_owned(),
                            ))?,
                            true,
                        )?;
                        if opt.port == 0 {
                            opt.port = s.common_opts.port;
                        }
                        Some(Box::new(GostWsClient::try_from(opt)?) as _)
                    }
                    "shadow-tls" => {
                        let plugin: Shadowtls = s
                            .plugin_opts
                            .clone()
                            .ok_or(Error::InvalidConfig(
                                "plugin_opts is required for plugin obfs".to_owned(),
                            ))?
                            .try_into()?;
                        let plugin = plugin
                            .with_client_fingerprint(s.client_fingerprint.clone())
                            .map_err(|error| {
                                Error::InvalidConfig(error.to_string())
                            })?;
                        Some(Box::new(plugin) as _)
                    }
                    "restls" => {
                        let options = s.plugin_opts.as_ref().ok_or_else(|| {
                            Error::InvalidConfig(
                                "plugin_opts is required for restls".to_owned(),
                            )
                        })?;
                        let required = |name: &str| {
                            options
                                .get(name)
                                .and_then(serde_yaml::Value::as_str)
                                .map(str::to_owned)
                                .ok_or_else(|| {
                                    Error::InvalidConfig(format!(
                                        "restls plugin option `{name}` is required"
                                    ))
                                })
                        };
                        let plugin = RestlsClient::new(
                            required("host")?,
                            required("password")?,
                            required("version-hint")?,
                            options
                                .get("restls-script")
                                .and_then(serde_yaml::Value::as_str)
                                .map(str::to_owned),
                            s.client_fingerprint.clone(),
                        )
                        .map_err(|error| Error::InvalidConfig(error.to_string()))?;
                        Some(Box::new(plugin) as _)
                    }
                    _ => {
                        return Err(Error::InvalidConfig(format!(
                            "unsupported plugin: {plugin}"
                        )));
                    }
                },
                None => None,
            },
            udp: s.udp,
            udp_over_tcp: s.udp_over_tcp,
            udp_over_tcp_version,
        });
        Ok(h)
    }
}

impl TryFrom<HashMap<String, serde_yaml::Value>> for SimpleOBFSOption {
    type Error = crate::Error;

    fn try_from(
        value: HashMap<String, serde_yaml::Value>,
    ) -> Result<Self, Self::Error> {
        let host = value
            .get("host")
            .and_then(|x| x.as_str())
            .unwrap_or("bing.com");
        let mode = value
            .get("mode")
            .and_then(|x| x.as_str())
            .ok_or(Error::InvalidConfig("obfs mode is required".to_owned()))?;

        match mode {
            "http" => Ok(SimpleOBFSOption {
                mode: SimpleOBFSMode::Http,
                host: host.to_owned(),
            }),
            "tls" => Ok(SimpleOBFSOption {
                mode: SimpleOBFSMode::Tls,
                host: host.to_owned(),
            }),
            _ => Err(Error::InvalidConfig(format!("invalid obfs mode: {mode}"))),
        }
    }
}

impl TryFrom<HashMap<String, serde_yaml::Value>> for V2RayOBFSOption {
    type Error = crate::Error;

    fn try_from(
        value: HashMap<String, serde_yaml::Value>,
    ) -> Result<Self, Self::Error> {
        parse_websocket_plugin_options(value, true)
    }
}

fn parse_websocket_plugin_options(
    value: HashMap<String, serde_yaml::Value>,
    default_mux: bool,
) -> Result<V2RayOBFSOption, Error> {
    let host = value
        .get("host")
        .and_then(|x| x.as_str())
        .unwrap_or("bing.com");
    let mode = value
        .get("mode")
        .and_then(|x| x.as_str())
        .ok_or(Error::InvalidConfig("obfs mode is required".to_owned()))?;

    if mode != "websocket" {
        return Err(Error::InvalidConfig(format!("invalid obfs mode: {mode}")));
    }

    let path = value.get("path").and_then(|x| x.as_str()).unwrap_or("");
    let mux = value
        .get("mux")
        .and_then(|x| x.as_bool())
        .unwrap_or(default_mux);
    let tls = value.get("tls").and_then(|x| x.as_bool()).unwrap_or(false);
    let port = value
        .get("port")
        .and_then(|x| x.as_u64())
        .unwrap_or_default() as u16;
    let skip_cert_verify = value
        .get("skip-cert-verify")
        .and_then(|x| x.as_bool())
        .unwrap_or(false);
    let ech = value
        .get("ech-opts")
        .filter(|value| !value.is_null())
        .map(|value| {
            serde_yaml::from_value::<crate::config::internal::proxy::EchOptions>(
                value.clone(),
            )
            .map_err(|error| {
                Error::InvalidConfig(format!("invalid ech-opts: {error}"))
            })
        })
        .transpose()?;
    for field in ["v2ray-http-upgrade", "v2ray-http-upgrade-fast-open"] {
        if value.get(field).and_then(|x| x.as_bool()).unwrap_or(false) {
            return Err(Error::InvalidConfig(format!(
                "{field} is not implemented for v2ray-plugin"
            )));
        }
    }

    let mut headers = HashMap::new();
    if let Some(h) = value.get("headers")
        && let Some(h) = h.as_mapping()
    {
        for (k, v) in h {
            if let (Some(k), Some(v)) = (k.as_str(), v.as_str()) {
                headers.insert(k.to_owned(), v.to_owned());
            }
        }
    }

    Ok(V2RayOBFSOption {
        mode: mode.to_owned(),
        host: host.to_owned(),
        port,
        path: path.to_owned(),
        tls,
        headers,
        skip_cert_verify,
        mux,
        fingerprint: value
            .get("fingerprint")
            .and_then(|x| x.as_str())
            .map(str::to_owned),
        ech: super::utils::tls_ech_options(ech.as_ref()),
        certificate: value
            .get("certificate")
            .and_then(|x| x.as_str())
            .map(str::to_owned),
        private_key: value
            .get("private-key")
            .and_then(|x| x.as_str())
            .map(str::to_owned),
    })
}

impl TryFrom<HashMap<String, serde_yaml::Value>> for Shadowtls {
    type Error = crate::Error;

    fn try_from(
        value: HashMap<String, serde_yaml::Value>,
    ) -> Result<Self, Self::Error> {
        let host = value
            .get("host")
            .and_then(|x| x.as_str())
            .unwrap_or("bing.com");
        let password = value
            .get("password")
            .and_then(|x| x.as_str().to_owned())
            .ok_or(Error::InvalidConfig("obfs mode is required".to_owned()))?;
        let strict = value
            .get("strict")
            .and_then(|x| x.as_bool())
            .unwrap_or(true);
        let version = value
            .get("version")
            .and_then(|value| value.as_u64())
            .unwrap_or(2);
        let version = u8::try_from(version).map_err(|_| {
            Error::InvalidConfig("shadow-tls version is out of range".to_owned())
        })?;
        if !matches!(version, 1..=3) {
            return Err(Error::InvalidConfig(format!(
                "unsupported shadow-tls version: {version}"
            )));
        }
        let alpn = value
            .get("alpn")
            .map(|value| {
                value
                    .as_sequence()
                    .ok_or_else(|| {
                        Error::InvalidConfig(
                            "shadow-tls alpn must be a list of strings".to_owned(),
                        )
                    })?
                    .iter()
                    .map(|value| {
                        value.as_str().map(str::to_owned).ok_or_else(|| {
                            Error::InvalidConfig(
                                "shadow-tls alpn must contain only strings"
                                    .to_owned(),
                            )
                        })
                    })
                    .collect::<Result<Vec<_>, _>>()
            })
            .transpose()?;

        Ok(Shadowtls::new_with_options(
            host.to_string(),
            password.to_string(),
            strict,
            version,
            alpn,
            value
                .get("skip-cert-verify")
                .and_then(|value| value.as_bool())
                .unwrap_or_default(),
            value
                .get("fingerprint")
                .and_then(|value| value.as_str())
                .map(str::to_owned),
            value
                .get("certificate")
                .and_then(|value| value.as_str())
                .map(str::to_owned),
            value
                .get("private-key")
                .and_then(|value| value.as_str())
                .map(str::to_owned),
        ))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::internal::proxy::CommonConfigOptions;

    fn base_config() -> OutboundShadowsocks {
        OutboundShadowsocks {
            common_opts: CommonConfigOptions {
                name: "ss-test".to_owned(),
                server: "example.com".to_owned(),
                port: 443,
                connect_via: None,
            },
            cipher: "aes-128-gcm".to_owned(),
            password: "secret".to_owned(),
            udp: true,
            plugin: None,
            plugin_opts: None,
            udp_over_tcp: true,
            udp_over_tcp_version: 0,
            client_fingerprint: None,
        }
    }

    #[test]
    fn websocket_plugin_defaults_match_mihomo() {
        let options = parse_websocket_plugin_options(
            serde_yaml::from_str("mode: websocket\ntls: true").unwrap(),
            true,
        )
        .unwrap();
        assert!(options.mux);
        assert_eq!(options.port, 0);
        assert_eq!(options.host, "bing.com");
    }

    #[test]
    fn websocket_plugin_accepts_mihomo_ech_options() {
        let options = parse_websocket_plugin_options(
            serde_yaml::from_str(
                "mode: websocket\ntls: true\nech-opts:\n  enable: true\n  \
                 query-server-name: ech.example\n",
            )
            .unwrap(),
            true,
        )
        .unwrap();

        assert_eq!(
            options.ech.unwrap().query_server_name.as_deref(),
            Some("ech.example"),
        );
    }

    #[test]
    fn shadowsocks_uot_versions_are_validated() {
        let mut config = base_config();
        assert!(Handler::try_from(&config).is_ok());
        config.udp_over_tcp_version = 2;
        assert!(Handler::try_from(&config).is_ok());
        config.udp_over_tcp_version = 3;
        assert!(Handler::try_from(&config).is_err());
    }

    #[test]
    fn irrelevant_client_fingerprint_is_not_rejected() {
        let mut config = base_config();
        config.client_fingerprint = Some("chrome".to_owned());
        assert!(Handler::try_from(&config).is_ok());
    }

    #[test]
    fn shadow_tls_v2_accepts_browser_client_fingerprint() {
        let mut config = base_config();
        config.client_fingerprint = Some("chrome".to_owned());
        config.plugin = Some("shadow-tls".to_owned());
        config.plugin_opts = Some(
            serde_yaml::from_str(
                "host: example.com\npassword: shadow-secret\nversion: 2\n",
            )
            .unwrap(),
        );
        assert!(Handler::try_from(&config).is_ok());
    }

    #[test]
    fn shadow_tls_v3_rejects_unsupported_browser_session_id() {
        let mut config = base_config();
        config.client_fingerprint = Some("chrome".to_owned());
        config.plugin = Some("shadow-tls".to_owned());
        config.plugin_opts = Some(
            serde_yaml::from_str(
                "host: example.com\npassword: shadow-secret\nversion: 3\n",
            )
            .unwrap(),
        );
        let error = Handler::try_from(&config).err().unwrap().to_string();
        assert!(error.contains("session-id callback"), "{error}");
    }

    #[test]
    fn restls_accepts_complete_mihomo_tls13_options() {
        let mut config = base_config();
        config.client_fingerprint = Some("chrome".to_owned());
        config.plugin = Some("restls".to_owned());
        config.plugin_opts = Some(
            serde_yaml::from_str(
                "host: www.microsoft.com\npassword: restls-secret\nversion-hint: \
                 tls13\nrestls-script: 300?100<1,400~100,350~100\n",
            )
            .unwrap(),
        );
        assert!(Handler::try_from(&config).is_ok());
    }

    #[test]
    fn restls_accepts_mihomo_tls12_options() {
        let mut config = base_config();
        config.client_fingerprint = Some("firefox".to_owned());
        config.plugin = Some("restls".to_owned());
        config.plugin_opts = Some(
            serde_yaml::from_str(
                "host: vscode.dev\npassword: restls-secret\nversion-hint: tls12\n",
            )
            .unwrap(),
        );
        assert!(Handler::try_from(&config).is_ok());
    }

    #[test]
    fn restls_rejects_missing_or_invalid_required_options() {
        let mut config = base_config();
        config.plugin = Some("restls".to_owned());
        config.plugin_opts = Some(
            serde_yaml::from_str("host: example.com\nversion-hint: tls13\n")
                .unwrap(),
        );
        assert!(Handler::try_from(&config).is_err());

        config.plugin_opts = Some(
            serde_yaml::from_str(
                "host: example.com\npassword: secret\nversion-hint: tls14\n",
            )
            .unwrap(),
        );
        assert!(Handler::try_from(&config).is_err());
    }
}
