use std::{
    io,
    sync::{
        Arc, Weak,
        atomic::{AtomicBool, AtomicU8, AtomicU32, Ordering},
    },
    time::Duration,
};

use bytes::{BufMut, BytesMut};
use sha2::{Digest, Sha256};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    sync::{Mutex, mpsc},
    time::Instant,
};
use tokio_util::sync::CancellationToken;
use tracing::{debug, warn};

use super::{
    CMD_ALERT, CMD_FIN, CMD_HEART_REQUEST, CMD_HEART_RESPONSE, CMD_PSH,
    CMD_SERVER_SETTINGS, CMD_SETTINGS, CMD_SYN, CMD_SYN_ACK,
    CMD_UPDATE_PADDING_SCHEME, CMD_WASTE, Handler,
    padding::{PaddingFactory, SharedPadding, new_shared_padding, write_padded},
};
use crate::{proxy::AnyStream, session::SocksAddr};

const DUPLEX_BUFFER_SIZE: usize = 64 * 1024;
const RELAY_BUFFER_SIZE: usize = 16 * 1024;
const STREAM_CLOSE_TIMEOUT: Duration = Duration::from_secs(30);
const SYN_ACK_TIMEOUT: Duration = Duration::from_secs(3);

pub(super) struct Pool {
    idle: Mutex<Vec<IdleSession>>,
    padding: SharedPadding,
    check_interval: Duration,
    timeout: Duration,
    min_idle: usize,
    cleanup_started: AtomicBool,
    closed: AtomicBool,
    cancellation: CancellationToken,
}

pub(super) struct IdleSession {
    stream: AnyStream,
    next_stream_id: u32,
    idle_since: Instant,
    padding: SharedPadding,
    packet_counter: Arc<AtomicU32>,
    peer_version: Arc<AtomicU8>,
}

impl Pool {
    pub(super) fn new(
        check_interval: Duration,
        timeout: Duration,
        min_idle: usize,
    ) -> Arc<Self> {
        Arc::new(Self {
            idle: Mutex::new(Vec::new()),
            padding: new_shared_padding(),
            check_interval: normalize_duration(check_interval),
            timeout: normalize_duration(timeout),
            min_idle,
            cleanup_started: AtomicBool::new(false),
            closed: AtomicBool::new(false),
            cancellation: CancellationToken::new(),
        })
    }

    pub(super) async fn take(self: &Arc<Self>) -> Option<IdleSession> {
        self.start_cleanup();
        self.idle.lock().await.pop()
    }

    async fn put(self: &Arc<Self>, mut session: IdleSession) {
        if self.closed.load(Ordering::Acquire) {
            return;
        }
        session.idle_since = Instant::now();
        self.idle.lock().await.push(session);
    }

    fn start_cleanup(self: &Arc<Self>) {
        if self
            .cleanup_started
            .compare_exchange(false, true, Ordering::AcqRel, Ordering::Acquire)
            .is_err()
        {
            return;
        }
        let pool = Arc::downgrade(self);
        let cancellation = self.cancellation.clone();
        let interval = self.check_interval;
        tokio::spawn(async move {
            loop {
                tokio::select! {
                    _ = cancellation.cancelled() => return,
                    _ = tokio::time::sleep(interval) => {
                        let Some(pool) = pool.upgrade() else {
                            return;
                        };
                        pool.cleanup().await;
                    }
                }
            }
        });
    }

    async fn cleanup(&self) {
        let now = Instant::now();
        let expiration = now.checked_sub(self.timeout).unwrap_or(now);
        let mut idle = self.idle.lock().await;
        let fresh = idle
            .iter()
            .filter(|session| session.idle_since >= expiration)
            .count();
        let mut expired_to_keep = self.min_idle.saturating_sub(fresh);

        // Mihomo retains the newest expired sessions when min-idle-session
        // requires a floor and refreshes their idle timestamp.
        for session in idle.iter_mut().rev() {
            if session.idle_since < expiration && expired_to_keep > 0 {
                session.idle_since = now;
                expired_to_keep -= 1;
            }
        }
        idle.retain(|session| session.idle_since >= expiration);
    }

    pub(super) fn close(&self) {
        self.closed.store(true, Ordering::Release);
        self.cancellation.cancel();
        if let Ok(mut idle) = self.idle.try_lock() {
            idle.clear();
        }
    }
}

fn normalize_duration(duration: Duration) -> Duration {
    if duration <= Duration::from_secs(5) {
        Duration::from_secs(30)
    } else {
        duration
    }
}

pub(super) async fn open_new(
    mut stream: AnyStream,
    password: &str,
    name: &str,
    destination: &SocksAddr,
    pool: Option<Arc<Pool>>,
) -> io::Result<AnyStream> {
    let stream_id = 1;
    let password = Sha256::digest(password.as_bytes());
    let padding = pool
        .as_ref()
        .map(|pool| pool.padding.clone())
        .unwrap_or_else(new_shared_padding);
    let padding_factory = padding.read().await.clone();
    let settings = format!(
        "v=2\nclient=clash-rs/{}\npadding-md5={}",
        env!("CLASH_VERSION_OVERRIDE"),
        padding_factory.md5()
    );
    let mut address = BytesMut::new();
    destination.write_buf(&mut address);

    // AnyTLS packet zero is the authentication prefix. Mihomo writes it as a
    // distinct TLS application record before starting the framed session.
    let authentication_padding = padding_factory.authentication_padding_size();
    let mut authentication = BytesMut::with_capacity(34 + authentication_padding);
    authentication.put_slice(password.as_slice());
    authentication.put_u16(authentication_padding as u16);
    authentication.resize(authentication.len() + authentication_padding, 0);
    stream.write_all(&authentication).await?;

    // Mihomo buffers SETTINGS and SYN until the first PSH (the destination)
    // and applies packet-one padding to the combined payload.
    let mut handshake = BytesMut::new();
    handshake.extend_from_slice(&Handler::encode_frame(
        CMD_SETTINGS,
        0,
        settings.as_bytes(),
    )?);
    handshake.extend_from_slice(&Handler::encode_frame(CMD_SYN, stream_id, &[])?);
    handshake
        .extend_from_slice(&Handler::encode_frame(CMD_PSH, stream_id, &address)?);
    let packet_counter = Arc::new(AtomicU32::new(0));
    write_padded(&mut stream, handshake, &padding, packet_counter.as_ref()).await?;
    stream.flush().await?;

    start_active(
        IdleSession {
            stream,
            next_stream_id: 2,
            idle_since: Instant::now(),
            padding,
            packet_counter,
            peer_version: Arc::new(AtomicU8::new(0)),
        },
        stream_id,
        name,
        pool,
        false,
    )
}

pub(super) async fn open_existing(
    mut session: IdleSession,
    name: &str,
    destination: &SocksAddr,
    pool: Arc<Pool>,
) -> io::Result<AnyStream> {
    let stream_id = session.next_stream_id;
    let require_syn_ack =
        stream_id >= 2 && session.peer_version.load(Ordering::Acquire) >= 2;
    session.next_stream_id = session
        .next_stream_id
        .checked_add(1)
        .ok_or_else(|| io::Error::other("AnyTLS stream id exhausted"))?;
    let mut address = BytesMut::new();
    destination.write_buf(&mut address);
    let mut opening = Handler::encode_frame(CMD_SYN, stream_id, &[])?;
    opening.extend_from_slice(&Handler::encode_frame(CMD_PSH, stream_id, &address)?);
    write_padded(
        &mut session.stream,
        opening,
        &session.padding,
        session.packet_counter.as_ref(),
    )
    .await?;
    session.stream.flush().await?;
    start_active(session, stream_id, name, Some(pool), require_syn_ack)
}

fn start_active(
    session: IdleSession,
    stream_id: u32,
    name: &str,
    pool: Option<Arc<Pool>>,
    require_syn_ack: bool,
) -> io::Result<AnyStream> {
    let IdleSession {
        stream,
        next_stream_id,
        padding,
        packet_counter,
        peer_version,
        ..
    } = session;
    let (remote_read, remote_write) = tokio::io::split(stream);
    let (app_stream, relay_stream) = tokio::io::duplex(DUPLEX_BUFFER_SIZE);
    let (relay_read, relay_write) = tokio::io::split(relay_stream);
    let cancellation = CancellationToken::new();
    let (control_tx, control_rx) = mpsc::unbounded_channel();

    let writer = tokio::spawn(write_loop(
        remote_write,
        relay_read,
        stream_id,
        control_rx,
        cancellation.clone(),
        name.to_owned(),
        padding.clone(),
        packet_counter.clone(),
    ));
    let reader = tokio::spawn(read_loop(
        remote_read,
        relay_write,
        stream_id,
        control_tx,
        cancellation.clone(),
        name.to_owned(),
        padding.clone(),
        peer_version.clone(),
        require_syn_ack,
    ));

    tokio::spawn(recycle_session(
        writer,
        reader,
        next_stream_id,
        padding,
        packet_counter,
        peer_version,
        pool.as_ref().map(Arc::downgrade),
        cancellation,
    ));
    Ok(Box::new(app_stream))
}

type RemoteWriteHalf = tokio::io::WriteHalf<AnyStream>;
type RemoteReadHalf = tokio::io::ReadHalf<AnyStream>;

async fn write_loop(
    mut remote: RemoteWriteHalf,
    mut relay: tokio::io::ReadHalf<tokio::io::DuplexStream>,
    stream_id: u32,
    mut control: mpsc::UnboundedReceiver<(u8, u32, Vec<u8>)>,
    cancellation: CancellationToken,
    name: String,
    padding: SharedPadding,
    packet_counter: Arc<AtomicU32>,
) -> io::Result<RemoteWriteHalf> {
    let mut buffer = vec![0u8; RELAY_BUFFER_SIZE];
    loop {
        tokio::select! {
            biased;
            _ = cancellation.cancelled() => return Ok(remote),
            Some((command, id, data)) = control.recv() => {
                let frame = Handler::encode_frame(command, id, &data)?;
                if let Err(error) = write_padded(
                    &mut remote,
                    frame,
                    &padding,
                    packet_counter.as_ref(),
                ).await {
                    cancellation.cancel();
                    return Err(error);
                }
                remote.flush().await?;
            }
            result = relay.read(&mut buffer) => {
                let read = match result {
                    Ok(read) => read,
                    Err(error) => {
                        cancellation.cancel();
                        return Err(error);
                    }
                };
                if read == 0 {
                    let frame = Handler::encode_frame(CMD_FIN, stream_id, &[])?;
                    write_padded(
                        &mut remote,
                        frame,
                        &padding,
                        packet_counter.as_ref(),
                    ).await?;
                    remote.flush().await?;
                    tokio::select! {
                        _ = cancellation.cancelled() => return Ok(remote),
                        _ = tokio::time::sleep(STREAM_CLOSE_TIMEOUT) => {
                            cancellation.cancel();
                            return Err(io::Error::new(
                                io::ErrorKind::TimedOut,
                                "AnyTLS peer did not close stream after FIN",
                            ));
                        }
                    }
                }
                let frame = Handler::encode_frame(
                    CMD_PSH,
                    stream_id,
                    &buffer[..read],
                )?;
                if let Err(error) = write_padded(
                    &mut remote,
                    frame,
                    &padding,
                    packet_counter.as_ref(),
                ).await {
                    debug!("anytls {name} send PSH failed: {error}");
                    cancellation.cancel();
                    return Err(error);
                }
            }
        }
    }
}

async fn read_loop(
    mut remote: RemoteReadHalf,
    mut relay: tokio::io::WriteHalf<tokio::io::DuplexStream>,
    stream_id: u32,
    control: mpsc::UnboundedSender<(u8, u32, Vec<u8>)>,
    cancellation: CancellationToken,
    name: String,
    padding: SharedPadding,
    peer_version: Arc<AtomicU8>,
    require_syn_ack: bool,
) -> io::Result<RemoteReadHalf> {
    let syn_ack_deadline = require_syn_ack.then(|| Instant::now() + SYN_ACK_TIMEOUT);
    let mut waiting_for_syn_ack = require_syn_ack;
    loop {
        let frame = async {
            if waiting_for_syn_ack {
                tokio::select! {
                    frame = Handler::read_frame(&mut remote) => frame,
                    _ = tokio::time::sleep_until(
                        syn_ack_deadline.expect("SYNACK deadline must exist")
                    ) => Err(io::Error::new(
                        io::ErrorKind::TimedOut,
                        format!("AnyTLS stream {stream_id} did not receive SYNACK"),
                    )),
                }
            } else {
                Handler::read_frame(&mut remote).await
            }
        }
        .await;
        let (command, id, data) = match frame {
            Ok(frame) => frame,
            Err(error) => {
                cancellation.cancel();
                return Err(error);
            }
        };
        match command {
            CMD_PSH if id == stream_id => {
                if let Err(error) = relay.write_all(&data).await {
                    cancellation.cancel();
                    return Err(error);
                }
            }
            CMD_FIN if id == stream_id => {
                let _ = relay.shutdown().await;
                cancellation.cancel();
                return Ok(remote);
            }
            CMD_ALERT => {
                let message = String::from_utf8_lossy(&data);
                warn!("anytls {name} alert: {message}");
                cancellation.cancel();
                return Err(io::Error::other(format!(
                    "AnyTLS server alert: {message}"
                )));
            }
            CMD_HEART_REQUEST => {
                let _ = control.send((CMD_HEART_RESPONSE, id, Vec::new()));
            }
            CMD_SYN_ACK if id == stream_id => {
                if !data.is_empty() {
                    let message = String::from_utf8_lossy(&data);
                    cancellation.cancel();
                    return Err(io::Error::other(format!(
                        "AnyTLS stream {stream_id} rejected: {message}"
                    )));
                }
                waiting_for_syn_ack = false;
            }
            CMD_UPDATE_PADDING_SCHEME if !data.is_empty() => {
                match PaddingFactory::new(&data) {
                    Ok(factory) => {
                        debug!(
                            "anytls {name} updated padding scheme to {}",
                            factory.md5()
                        );
                        *padding.write().await = Arc::new(factory);
                    }
                    Err(error) => {
                        warn!(
                            "anytls {name} rejected invalid padding scheme: {error}"
                        );
                    }
                }
            }
            CMD_SERVER_SETTINGS if !data.is_empty() => {
                if let Some(version) = parse_setting(&data, "v")
                    .and_then(|version| version.parse::<u8>().ok())
                {
                    peer_version.store(version, Ordering::Release);
                }
            }
            CMD_WASTE | CMD_SYN | CMD_SYN_ACK | CMD_SETTINGS
            | CMD_HEART_RESPONSE | CMD_SERVER_SETTINGS => {}
            _ => {}
        }
    }
}

async fn recycle_session(
    writer: tokio::task::JoinHandle<io::Result<RemoteWriteHalf>>,
    reader: tokio::task::JoinHandle<io::Result<RemoteReadHalf>>,
    next_stream_id: u32,
    padding: SharedPadding,
    packet_counter: Arc<AtomicU32>,
    peer_version: Arc<AtomicU8>,
    pool: Option<Weak<Pool>>,
    cancellation: CancellationToken,
) {
    let (writer, reader) = tokio::join!(writer, reader);
    cancellation.cancel();
    let (Ok(Ok(writer)), Ok(Ok(reader))) = (writer, reader) else {
        return;
    };
    let stream = reader.unsplit(writer);
    let Some(pool) = pool.and_then(|pool| pool.upgrade()) else {
        return;
    };
    pool.put(IdleSession {
        stream,
        next_stream_id,
        idle_since: Instant::now(),
        padding,
        packet_counter,
        peer_version,
    })
    .await;
}

fn parse_setting<'a>(data: &'a [u8], requested: &str) -> Option<&'a str> {
    let text = std::str::from_utf8(data).ok()?;
    text.split('\n').find_map(|line| {
        let (key, value) = line.split_once('=')?;
        (key == requested).then_some(value)
    })
}

#[cfg(test)]
mod tests {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    use super::*;

    async fn read_frame(stream: &mut tokio::io::DuplexStream) -> (u8, u32, Vec<u8>) {
        loop {
            let command = stream.read_u8().await.unwrap();
            let id = stream.read_u32().await.unwrap();
            let length = stream.read_u16().await.unwrap() as usize;
            let mut data = vec![0u8; length];
            stream.read_exact(&mut data).await.unwrap();
            if command != CMD_WASTE {
                return (command, id, data);
            }
        }
    }

    #[tokio::test]
    async fn cleanup_preserves_configured_minimum() {
        let pool = Pool::new(Duration::from_secs(60), Duration::from_secs(6), 1);
        for id in 1..=2 {
            let (stream, _peer) = tokio::io::duplex(64);
            pool.idle.lock().await.push(IdleSession {
                stream: Box::new(stream),
                next_stream_id: id,
                idle_since: Instant::now() - Duration::from_secs(7),
                padding: pool.padding.clone(),
                packet_counter: Arc::new(AtomicU32::new(0)),
                peer_version: Arc::new(AtomicU8::new(0)),
            });
        }
        pool.cleanup().await;
        let idle = pool.idle.lock().await;
        assert_eq!(idle.len(), 1);
        assert_eq!(idle[0].next_stream_id, 2);
    }

    #[test]
    fn small_intervals_use_mihomo_defaults() {
        assert_eq!(normalize_duration(Duration::ZERO), Duration::from_secs(30));
        assert_eq!(
            normalize_duration(Duration::from_secs(5)),
            Duration::from_secs(30)
        );
        assert_eq!(
            normalize_duration(Duration::from_secs(6)),
            Duration::from_secs(6)
        );
    }

    #[tokio::test]
    async fn closed_stream_reuses_authenticated_session() {
        const UPDATED_SCHEME: &[u8] = b"stop=0";
        let pool = Pool::new(Duration::from_secs(60), Duration::from_secs(60), 0);
        let first_destination =
            SocksAddr::try_from(("first.example".to_owned(), 443)).unwrap();
        let second_destination =
            SocksAddr::try_from(("second.example".to_owned(), 80)).unwrap();
        let (client, mut server) = tokio::io::duplex(16 * 1024);

        let expected_first = first_destination.clone();
        let expected_second = second_destination.clone();
        let server_task = tokio::spawn(async move {
            let mut password = [0u8; 32];
            server.read_exact(&mut password).await.unwrap();
            assert_eq!(password.as_slice(), Sha256::digest(b"secret").as_slice());
            let padding_length = server.read_u16().await.unwrap() as usize;
            assert_eq!(padding_length, 30);
            let mut authentication_padding = vec![0u8; padding_length];
            server
                .read_exact(&mut authentication_padding)
                .await
                .unwrap();
            assert!(authentication_padding.iter().all(|byte| *byte == 0));

            let (command, id, _) = read_frame(&mut server).await;
            assert_eq!((command, id), (CMD_SETTINGS, 0));
            let (command, id, data) = read_frame(&mut server).await;
            assert_eq!((command, id, data.len()), (CMD_SYN, 1, 0));
            let (command, id, data) = read_frame(&mut server).await;
            assert_eq!((command, id), (CMD_PSH, 1));
            assert_eq!(
                SocksAddr::try_from(data.as_slice()).unwrap(),
                expected_first
            );

            Handler::write_frame(
                &mut server,
                CMD_UPDATE_PADDING_SCHEME,
                0,
                UPDATED_SCHEME,
            )
            .await
            .unwrap();
            Handler::write_frame(&mut server, CMD_SERVER_SETTINGS, 0, b"v=2")
                .await
                .unwrap();
            Handler::write_frame(&mut server, CMD_FIN, 1, &[])
                .await
                .unwrap();
            server.flush().await.unwrap();

            // A reused session starts directly with stream id 2. Receiving
            // another password hash here would make this assertion fail.
            let (command, id, data) = read_frame(&mut server).await;
            assert_eq!((command, id, data.len()), (CMD_SYN, 2, 0));
            let (command, id, data) = read_frame(&mut server).await;
            assert_eq!((command, id), (CMD_PSH, 2));
            assert_eq!(
                SocksAddr::try_from(data.as_slice()).unwrap(),
                expected_second
            );
            Handler::write_frame(&mut server, CMD_SYN_ACK, 2, &[])
                .await
                .unwrap();
            Handler::write_frame(&mut server, CMD_FIN, 2, &[])
                .await
                .unwrap();
            server.flush().await.unwrap();
        });

        let mut first = open_new(
            Box::new(client),
            "secret",
            "test",
            &first_destination,
            Some(pool.clone()),
        )
        .await
        .unwrap();
        let mut eof = [0u8; 1];
        assert_eq!(first.read(&mut eof).await.unwrap(), 0);

        let idle = tokio::time::timeout(Duration::from_secs(1), async {
            loop {
                if let Some(session) = pool.take().await {
                    break session;
                }
                tokio::task::yield_now().await;
            }
        })
        .await
        .unwrap();
        assert_eq!(
            idle.padding.read().await.md5(),
            PaddingFactory::new(UPDATED_SCHEME).unwrap().md5()
        );
        assert_eq!(idle.peer_version.load(Ordering::Acquire), 2);
        let mut second =
            open_existing(idle, "test", &second_destination, pool.clone())
                .await
                .unwrap();
        assert_eq!(second.read(&mut eof).await.unwrap(), 0);
        server_task.await.unwrap();
    }

    #[tokio::test]
    async fn missing_syn_ack_discards_v2_session() {
        let pool = Pool::new(Duration::from_secs(60), Duration::from_secs(60), 0);
        let destination =
            SocksAddr::try_from(("second.example".to_owned(), 443)).unwrap();
        let (client, mut server) = tokio::io::duplex(16 * 1024);
        let idle = IdleSession {
            stream: Box::new(client),
            next_stream_id: 2,
            idle_since: Instant::now(),
            padding: pool.padding.clone(),
            packet_counter: Arc::new(AtomicU32::new(1)),
            peer_version: Arc::new(AtomicU8::new(2)),
        };

        let mut application =
            open_existing(idle, "test", &destination, pool.clone())
                .await
                .unwrap();
        let (command, id, _) = read_frame(&mut server).await;
        assert_eq!((command, id), (CMD_SYN, 2));
        let (command, id, _) = read_frame(&mut server).await;
        assert_eq!((command, id), (CMD_PSH, 2));

        let mut byte = [0u8; 1];
        let read = tokio::time::timeout(
            Duration::from_secs(4),
            application.read(&mut byte),
        )
        .await
        .expect("SYNACK deadline should close the application stream")
        .unwrap();
        assert_eq!(read, 0);
        tokio::task::yield_now().await;
        assert!(pool.take().await.is_none());
    }
}
