use std::{sync::Arc, time::Duration};

use crate::{
    Error,
    config::internal::proxy::OutboundOpenvpn,
    proxy::{
        HandlerCommonOptions,
        openvpn::{ClientConfig, Handler, HandlerOptions},
    },
};

impl TryFrom<OutboundOpenvpn> for Handler {
    type Error = Error;

    fn try_from(value: OutboundOpenvpn) -> Result<Self, Self::Error> {
        (&value).try_into()
    }
}

impl TryFrom<&OutboundOpenvpn> for Handler {
    type Error = Error;

    fn try_from(value: &OutboundOpenvpn) -> Result<Self, Self::Error> {
        let config = ClientConfig::new(
            value.common_opts.server.clone(),
            value.common_opts.port,
            value.proto.as_deref(),
            value.dev.as_deref(),
            value.cipher.as_deref(),
            value.auth.as_deref(),
            value.comp_lzo.as_deref(),
            value.ca.clone(),
            value.cert.clone(),
            value.key.clone(),
            value.tls_crypt.as_deref(),
            value.username.clone(),
            value.password.clone(),
            Duration::from_secs(value.ping.unwrap_or_default()),
            Duration::from_secs(value.ping_restart.unwrap_or_default()),
        )
        .map_err(|error| Error::InvalidConfig(error.to_string()))?;
        Ok(Handler::new(HandlerOptions {
            name: value.common_opts.name.clone(),
            common_opts: HandlerCommonOptions {
                connector: value.common_opts.connect_via.clone(),
                ..Default::default()
            },
            config: Arc::new(config),
            mtu: value.mtu.unwrap_or(1500),
            // Mihomo exposes the YAML field for compatibility but always
            // advertises OpenVPN as UDP-capable after creating the L3 tunnel.
            udp: true,
            remote_dns_resolve: value.remote_dns_resolve.unwrap_or_default(),
            dns: value.dns.clone().unwrap_or_default(),
        }))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        config::internal::proxy::CommonConfigOptions,
        proxy::{OutboundHandler, OutboundType},
    };

    fn config() -> OutboundOpenvpn {
        let rcgen::CertifiedKey { cert, .. } =
            rcgen::generate_simple_self_signed(vec!["localhost".to_owned()])
                .unwrap();
        OutboundOpenvpn {
            common_opts: CommonConfigOptions {
                name: "mihomo-openvpn".to_owned(),
                server: "vpn.example.com".to_owned(),
                port: 1194,
                connect_via: Some("upstream-proxy".to_owned()),
            },
            proto: Some("udp4".to_owned()),
            dev: Some("tun".to_owned()),
            cipher: Some("AES-256-GCM".to_owned()),
            auth: Some("SHA256".to_owned()),
            comp_lzo: Some("adaptive".to_owned()),
            ca: cert.pem(),
            username: Some("user".to_owned()),
            password: Some("password".to_owned()),
            mtu: Some(1400),
            udp: Some(false),
            remote_dns_resolve: Some(true),
            dns: Some(vec!["1.1.1.1".to_owned()]),
            ..Default::default()
        }
    }

    #[tokio::test]
    async fn converts_complete_mihomo_config_and_always_supports_udp() {
        let handler = Handler::try_from(config()).unwrap();
        assert_eq!(handler.name(), "mihomo-openvpn");
        assert!(matches!(handler.proto(), OutboundType::OpenVpn));
        assert!(handler.support_udp().await);
    }

    #[test]
    fn openvpn_api_type_uses_mihomo_spelling() {
        assert_eq!(
            serde_json::to_string(&OutboundType::OpenVpn).unwrap(),
            "\"OpenVPN\"",
        );
    }
}
