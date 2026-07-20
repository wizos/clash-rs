use std::sync::Arc;

use tracing::debug;

use crate::{
    app::{dispatcher::Dispatcher, net::outbound_interface_snapshot},
    session::{Network, Session, Type},
};

pub(crate) async fn handle_inbound_stream(
    stream: watfaq_netstack::TcpStream,

    dispatcher: Arc<Dispatcher>,
    so_mark: Option<u32>,
) {
    let sess = Session {
        network: Network::Tcp,
        typ: Type::Tun,
        source: stream.local_addr(),
        destination: stream.remote_addr().into(),
        dscp: stream.dscp(),
        iface: outbound_interface_snapshot().await.inspect(|x| {
            debug!(
                "selecting outbound interface: {:?} for tun TCP connection",
                x
            );
        }),
        so_mark,
        ..Default::default()
    };

    debug!("new tun TCP session assigned: {}", sess);
    dispatcher.dispatch_stream(sess, Box::new(stream)).await;
}
