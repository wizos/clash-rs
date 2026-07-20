use crate::{
    Error,
    config::internal::proxy::OutboundSnell,
    proxy::{
        HandlerCommonOptions,
        snell::{Handler, HandlerOptions},
        transport::{SimpleObfsHttp, SimpleObfsTLS, Transport},
    },
};

impl TryFrom<OutboundSnell> for Handler {
    type Error = Error;

    fn try_from(config: OutboundSnell) -> Result<Self, Self::Error> {
        let obfs: Option<Box<dyn Transport>> = match config.obfs_opts {
            Some(opts) if opts.mode.eq_ignore_ascii_case("http") => {
                Some(Box::new(SimpleObfsHttp::new(
                    opts.host.unwrap_or_else(|| "bing.com".to_owned()),
                    config.common_opts.port,
                )))
            }
            Some(opts) if opts.mode.eq_ignore_ascii_case("tls") => {
                Some(Box::new(SimpleObfsTLS::new(
                    opts.host.unwrap_or_else(|| "bing.com".to_owned()),
                )))
            }
            Some(opts) if !opts.mode.is_empty() => {
                return Err(Error::InvalidConfig(format!(
                    "snell {} unsupported obfs mode `{}`",
                    config.common_opts.name, opts.mode
                )));
            }
            _ => None,
        };

        Handler::new(HandlerOptions {
            name: config.common_opts.name,
            common_opts: HandlerCommonOptions {
                connector: config.common_opts.connect_via,
                ..Default::default()
            },
            server: config.common_opts.server,
            port: config.common_opts.port,
            psk: config.psk,
            udp: config.udp,
            version: config.version,
            reuse: config.reuse,
            obfs,
        })
    }
}
