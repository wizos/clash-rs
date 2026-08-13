use std::{
    fmt::Debug,
    io,
    net::SocketAddr,
    ops::{Deref, DerefMut, Sub},
    pin::Pin,
    sync::{Arc, Mutex},
    task::{Context, Poll},
    time::{Duration, Instant},
};

use quinn::{AsyncUdpSocket, Runtime, TokioRuntime, UdpPoller, udp::Transmit};

use crate::proxy::{
    converters::hysteria::PortGenerator, utils::bind_protected_udp_socket,
};

struct HopState {
    prev_conn: Option<Arc<dyn AsyncUdpSocket>>,
    cur_conn: Arc<dyn AsyncUdpSocket>,
    last: Instant,
    new_hop_port: u16,
}

/// A udp socket hopper, it can hop to a new port when the time interval is
/// greater than interval
///
/// https://v2.hysteria.network/docs/advanced/Port-Hopping/
pub struct UdpHop {
    /// (prev_conn, cur_conn, last, new_hop_port)
    state: Mutex<HopState>,
    /// The default port is the initial port when this quic connect connects to
    /// the server.
    init_port: u16,
    /// generate new port used to hop
    port_range: PortGenerator,
    /// interval to hop
    interval: Duration,
}

impl UdpHop {
    const DEFAULT_INTERVAL: Duration = Duration::from_secs(30);

    pub fn new(
        port: u16,
        port_range: PortGenerator,
        interval: Option<Duration>,
    ) -> io::Result<Self> {
        let socket =
            bind_protected_udp_socket(SocketAddr::new([0, 0, 0, 0].into(), 0))?;

        let state = HopState {
            prev_conn: None,
            cur_conn: TokioRuntime.wrap_udp_socket(socket)?,
            last: Instant::now(),
            new_hop_port: port,
        }
        .into();

        Ok(UdpHop {
            state,
            init_port: port,
            port_range,
            interval: interval.unwrap_or(Self::DEFAULT_INTERVAL),
        })
    }

    fn hop(&self) -> u16 {
        let mut lock = self.state.lock().unwrap();
        let HopState {
            prev_conn,
            cur_conn,
            last,
            new_hop_port,
        } = lock.deref_mut();

        let now = Instant::now();
        let to_hop = now.sub(*last) > self.interval;

        if to_hop && prev_conn.is_none() {
            *last = now;
            tracing::trace!("port hopping");

            bind_protected_udp_socket(SocketAddr::new([0, 0, 0, 0].into(), 0))
                .and_then(|udp| TokioRuntime.wrap_udp_socket(udp))
                .map(|new_conn| {
                    *new_hop_port = self.port_range.get();
                    *prev_conn = Some(std::mem::replace(cur_conn, new_conn));
                })
                .unwrap_or_else(|e| {
                    tracing::error!("port hopping err {}", e);
                });
        }
        *new_hop_port
    }

    fn get_conn(
        &self,
    ) -> (Option<Arc<dyn AsyncUdpSocket>>, Arc<dyn AsyncUdpSocket>) {
        let lock = self.state.lock().unwrap();
        let HopState {
            prev_conn,
            cur_conn,
            ..
        } = lock.deref();
        (prev_conn.clone(), cur_conn.clone())
    }

    fn drop_prcv_conn(&self) {
        let mut lock = self.state.lock().unwrap();
        lock.deref_mut().prev_conn.take();
    }
}

impl Debug for UdpHop {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("UdpHop").finish()
    }
}

impl AsyncUdpSocket for UdpHop {
    fn create_io_poller(self: Arc<Self>) -> Pin<Box<dyn UdpPoller>> {
        let cur = self.get_conn().1;
        cur.create_io_poller()
    }

    fn try_send(&self, transmit: &Transmit) -> io::Result<()> {
        let port = self.hop();

        let cur = self.get_conn().1;

        unsafe {
            let prt = transmit as *const Transmit as *mut Transmit;
            (*prt).destination.set_port(port);
        }

        cur.try_send(transmit)
    }

    fn poll_recv(
        &self,
        cx: &mut Context,
        bufs: &mut [io::IoSliceMut<'_>],
        meta: &mut [quinn::udp::RecvMeta],
    ) -> Poll<io::Result<usize>> {
        let (prev_io, io) = self.get_conn();

        let (len, should_drop) = match prev_io {
            Some(ref prev_io) => match prev_io.poll_recv(cx, bufs, meta) {
                Poll::Ready(Ok(len)) => (len, false),
                Poll::Ready(Err(e)) => {
                    tracing::trace!("poll prev conn err {}", e);
                    match e.kind() {
                        io::ErrorKind::TimedOut => return Poll::Ready(Err(e)),
                        _ => (0, true),
                    }
                }
                Poll::Pending => {
                    tracing::trace!("poll prev conn pending");
                    (0, false)
                }
            },
            None => (0, true),
        };

        if should_drop {
            self.drop_prcv_conn();
        }
        meta.iter_mut()
            .take(len)
            .for_each(|m| m.addr.set_port(self.init_port));

        match io.poll_recv(cx, bufs, &mut meta[len..]) {
            Poll::Pending => {
                if len > 0 {
                    Poll::Ready(Ok(len))
                } else {
                    Poll::Pending
                }
            }
            Poll::Ready(Ok(res)) => {
                meta.iter_mut()
                    .skip(len)
                    .take(res)
                    .for_each(|m| m.addr.set_port(self.init_port));
                Poll::Ready(Ok(len + res))
            }
            Poll::Ready(Err(e)) => {
                tracing::trace!("poll cur conn err {}", e);
                Poll::Ready(Err(e))
            }
        }
    }

    fn local_addr(&self) -> io::Result<std::net::SocketAddr> {
        self.get_conn().1.local_addr()
    }

    fn may_fragment(&self) -> bool {
        self.get_conn().1.may_fragment()
    }
}
