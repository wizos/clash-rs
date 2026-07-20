use crate::{
    Error,
    config::internal::proxy::OutboundShadowsocksR,
    proxy::{
        HandlerCommonOptions,
        shadowsocks::{
            map_cipher,
            outbound::{Handler, HandlerOptions},
            ssr_obfs::{SsrObfsMode, SsrObfsPlugin},
            ssr_protocol::SsrProtocol,
        },
    },
};
use shadowsocks::crypto::{CipherCategory, v1::openssl_bytes_to_key};

impl TryFrom<OutboundShadowsocksR> for Handler {
    type Error = Error;

    fn try_from(config: OutboundShadowsocksR) -> Result<Self, Self::Error> {
        let obfs_name = config.obfs.to_ascii_lowercase();
        let obfs_overhead = match obfs_name.as_str() {
            "tls1.2_ticket_auth"
            | "tls12_ticket_auth"
            | "tls1.2-ticket-auth"
            | "tls1.2_ticket_fastauth"
            | "tls12_ticket_fastauth"
            | "tls1.2-ticket-fastauth" => 5,
            _ => 0,
        };
        let protocol = match config.protocol.to_ascii_lowercase().as_str() {
            "origin" => None,
            "auth_sha1_v4" | "auth-sha1-v4" => Some(SsrProtocol::auth_sha1_v4()),
            "auth_aes128_md5" | "auth-aes128-md5" => {
                Some(SsrProtocol::auth_aes128_md5(
                    config.protocol_param.clone(),
                    obfs_overhead,
                ))
            }
            "auth_aes128_sha1" | "auth-aes128-sha1" => {
                Some(SsrProtocol::auth_aes128_sha1(
                    config.protocol_param.clone(),
                    obfs_overhead,
                ))
            }
            "auth_chain_a" | "auth-chain-a" => Some(SsrProtocol::auth_chain_a(
                config.protocol_param.clone(),
                obfs_overhead,
            )),
            "auth_chain_b" | "auth-chain-b" => Some(SsrProtocol::auth_chain_b(
                config.protocol_param.clone(),
                obfs_overhead,
            )),
            _ => {
                return Err(Error::InvalidConfig(format!(
                    "SSR protocol `{}` is not supported yet",
                    config.protocol
                )));
            }
        };
        let cipher = match config.cipher.as_str() {
            "dummy" => "none".to_owned(),
            _ => config.cipher,
        };
        let method = map_cipher(&cipher)
            .map_err(|error| Error::InvalidConfig(error.to_string()))?;
        if !matches!(
            method.category(),
            CipherCategory::Stream | CipherCategory::None
        ) {
            return Err(Error::InvalidConfig(format!(
                "SSR cipher `{cipher}` is not a stream or dummy cipher"
            )));
        }
        let key_length = if method.category() == CipherCategory::None {
            16
        } else {
            method.key_len()
        };
        let mut ssr_key = vec![0u8; key_length];
        openssl_bytes_to_key(config.password.as_bytes(), &mut ssr_key);
        let plugin = match obfs_name.as_str() {
            "plain" => None,
            "http_simple" | "http-simple" => Some(Box::new(SsrObfsPlugin::new(
                SsrObfsMode::HttpSimple,
                config.common_opts.server.clone(),
                config.common_opts.port,
                config.obfs_param.clone().unwrap_or_default(),
                method.iv_len(),
            )) as _),
            "http_post" | "http-post" => Some(Box::new(SsrObfsPlugin::new(
                SsrObfsMode::HttpPost,
                config.common_opts.server.clone(),
                config.common_opts.port,
                config.obfs_param.clone().unwrap_or_default(),
                method.iv_len(),
            )) as _),
            "random_head" | "random-head" => Some(Box::new(SsrObfsPlugin::new(
                SsrObfsMode::RandomHead,
                config.common_opts.server.clone(),
                config.common_opts.port,
                config.obfs_param.clone().unwrap_or_default(),
                0,
            )) as _),
            "tls1.2_ticket_auth"
            | "tls12_ticket_auth"
            | "tls1.2-ticket-auth"
            | "tls1.2_ticket_fastauth"
            | "tls12_ticket_fastauth"
            | "tls1.2-ticket-fastauth" => {
                Some(Box::new(SsrObfsPlugin::new_tls12_ticket(
                    config.common_opts.server.clone(),
                    config.obfs_param.clone().unwrap_or_default(),
                    ssr_key,
                )) as _)
            }
            _ => {
                return Err(Error::InvalidConfig(format!(
                    "SSR obfs `{}` is not supported yet",
                    config.obfs
                )));
            }
        };

        Ok(Handler::new_shadowsocksr(
            HandlerOptions {
                name: config.common_opts.name,
                common_opts: HandlerCommonOptions {
                    connector: config.common_opts.connect_via,
                    ..Default::default()
                },
                server: config.common_opts.server,
                port: config.common_opts.port,
                password: config.password,
                cipher,
                plugin,
                udp: config.udp,
                udp_over_tcp: false,
                udp_over_tcp_version: 0,
            },
            protocol,
        ))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        config::internal::proxy::CommonConfigOptions,
        proxy::{OutboundHandler, OutboundType},
    };

    fn config(protocol: &str, obfs: &str) -> OutboundShadowsocksR {
        OutboundShadowsocksR {
            common_opts: CommonConfigOptions {
                name: "ssr-origin".to_owned(),
                server: "example.com".to_owned(),
                port: 8388,
                connect_via: None,
            },
            cipher: "aes-128-cfb".to_owned(),
            password: "secret".to_owned(),
            obfs: obfs.to_owned(),
            obfs_param: None,
            protocol: protocol.to_owned(),
            protocol_param: None,
            udp: true,
        }
    }

    #[tokio::test]
    async fn accepts_wire_compatible_origin_plain() {
        let handler = Handler::try_from(config("origin", "plain")).unwrap();
        assert!(matches!(handler.proto(), OutboundType::ShadowsocksR));
        assert!(handler.support_udp().await);
    }

    #[test]
    fn accepts_origin_obfs_modes() {
        for obfs in ["plain", "http_simple", "http_post", "random_head"] {
            Handler::try_from(config("origin", obfs)).unwrap();
        }
    }

    #[test]
    fn accepts_auth_sha1_v4() {
        Handler::try_from(config("auth_sha1_v4", "plain")).unwrap();
    }

    #[test]
    fn accepts_auth_aes128_modes() {
        for protocol in ["auth_aes128_md5", "auth_aes128_sha1"] {
            let mut config = config(protocol, "plain");
            config.protocol_param = Some("1234:per-user-password".to_owned());
            Handler::try_from(config).unwrap();
        }
    }

    #[test]
    fn accepts_auth_chain_modes() {
        for protocol in ["auth_chain_a", "auth_chain_b"] {
            let mut config = config(protocol, "plain");
            config.protocol_param = Some("1234:per-user-password".to_owned());
            Handler::try_from(config).unwrap();
        }
    }

    #[test]
    fn accepts_tls12_ticket_obfs_aliases() {
        for obfs in [
            "tls1.2_ticket_auth",
            "tls12_ticket_auth",
            "tls1.2-ticket-auth",
            "tls1.2_ticket_fastauth",
            "tls12_ticket_fastauth",
            "tls1.2-ticket-fastauth",
        ] {
            Handler::try_from(config("auth_aes128_sha1", obfs)).unwrap();
        }
    }

    #[test]
    fn rejects_modes_that_need_unimplemented_ssr_wrappers() {
        assert!(Handler::try_from(config("auth_chain_c", "plain")).is_err());
    }
}
