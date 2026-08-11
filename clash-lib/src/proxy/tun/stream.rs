use std::{net::IpAddr, sync::Arc};

use tracing::debug;

use crate::{
    app::{
        dispatcher::Dispatcher, dns::ThreadSafeDNSResolver,
        net::outbound_interface_snapshot,
    },
    proxy::{dns::relay_tcp, tun::datagram::should_hijack_dns},
    session::{Network, Session, Type},
};

pub(crate) async fn handle_inbound_stream(
    stream: watfaq_netstack::TcpStream,
    dispatcher: Arc<Dispatcher>,
    resolver: ThreadSafeDNSResolver,
    so_mark: Option<u32>,
    dns_hijack: bool,
    dns_hijack_targets: Vec<IpAddr>,
) {
    if should_hijack_dns(
        dns_hijack,
        &dns_hijack_targets,
        Some(stream.remote_addr().ip()),
        stream.remote_addr().port(),
    ) {
        debug!("hijacking TUN TCP DNS connection: {}", stream.remote_addr());
        relay_tcp(stream, resolver).await;
        return;
    }

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
