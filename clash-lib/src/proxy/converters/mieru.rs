use crate::{
    Error,
    config::internal::proxy::OutboundMieru,
    proxy::{
        HandlerCommonOptions,
        mieru::{Handler, HandlerOptions},
    },
};

impl TryFrom<OutboundMieru> for Handler {
    type Error = Error;

    fn try_from(config: OutboundMieru) -> Result<Self, Self::Error> {
        Handler::new(HandlerOptions {
            name: config.name,
            common_opts: HandlerCommonOptions {
                connector: config.connect_via,
                ..Default::default()
            },
            server: config.server,
            port: config.port,
            port_range: config.port_range,
            transport: config.transport,
            udp: config.udp,
            username: config.username,
            password: config.password,
            multiplexing: config.multiplexing,
            handshake_mode: config.handshake_mode,
            traffic_pattern: config.traffic_pattern,
        })
    }
}
