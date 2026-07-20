//! Sudoku native session multiplexing (`multiplex: on`).
//!
//! When multiplexing is enabled the client brings up a single Sudoku tunnel
//! (obfuscation + AEAD record + KIP handshake), sends the `StartMux` control
//! message, and then runs a lightweight stream-multiplexing protocol directly
//! over the record stream. Every proxied TCP connection becomes a logical
//! stream on the shared tunnel instead of a fresh handshake.
//!
//! ## Frame format (over the record stream, after `StartMux`)
//!
//! ```text
//! type(1) | streamID(u32 BE) | len(u32 BE) | payload
//! ```
//!
//! * `Open` (0x01) — payload is the SOCKS5-style destination address; opens a
//!   new logical stream. Client-initiated ids start at 1 and never reuse 0.
//! * `Data` (0x02) — payload is stream bytes. An empty `Data` on stream 0 is a
//!   keepalive (ignored by the peer since stream 0 is never allocated).
//! * `Close` (0x03) — half-closes the sender's write side (EOF to the peer).
//! * `Reset` (0x04) — aborts a stream with an optional message.
//!
//! ## Session model
//!
//! Mirroring the AnyTLS session layer, each mux tunnel is one live connection
//! driven by two background tasks: a writer owning the transport's write half
//! (framing control/data commands and the keepalive) and a reader owning the
//! read half (demultiplexing inbound `Data` to each stream's bounded channel
//! and dropping a stream's sender on `Close`/`Reset` so its reader sees EOF). A
//! new outbound connection opens another stream on an existing session for the
//! same config when one has a free slot ([`MAX_STREAMS_PER_SESSION`]);
//! otherwise it does a fresh handshake. Idle sessions stay registered for reuse
//! until an idle TTL. UDP still rides its own dedicated `StartUoT` tunnel (see
//! [`super::uot`]), matching upstream's `DialUDPOverTCP`.

use std::{
    collections::{HashMap, VecDeque},
    io,
    pin::Pin,
    sync::{
        Arc, Mutex,
        atomic::{AtomicBool, AtomicU32, Ordering},
    },
    task::{Context as TaskContext, Poll, Waker},
    time::{Duration, Instant},
};

use anyhow::{Result, anyhow};
use tokio::{
    io::{
        AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, ReadBuf, ReadHalf,
        WriteHalf,
    },
    sync::{Notify, mpsc, oneshot},
    time::{Interval, MissedTickBehavior, interval_at},
};

use crate::{proxy::AnyStream, session::SocksAddr};

use super::{SudokuOutboundConfig, kip};

const MUX_FRAME_OPEN: u8 = 0x01;
const MUX_FRAME_DATA: u8 = 0x02;
const MUX_FRAME_CLOSE: u8 = 0x03;
const MUX_FRAME_RESET: u8 = 0x04;

/// `type(1) | streamID(4) | len(4)`.
const MUX_HEADER_LEN: usize = 1 + 4 + 4;
/// Hard cap on a single frame's payload; a longer length is a protocol error.
const MUX_MAX_FRAME_SIZE: usize = 256 * 1024;
/// Largest `Data` payload emitted per frame (a larger write is chunked).
const MUX_MAX_DATA_PAYLOAD: usize = 128 * 1024;
/// Idle interval after which the writer emits a stream-0 keepalive `Data`.
const MUX_KEEPALIVE_INTERVAL: Duration = Duration::from_secs(15);

/// Maximum logical streams multiplexed concurrently on one session before a
/// fresh tunnel is opened. Because the session's single reader stalls all of
/// its streams while one stream's bounded inbound buffer is full, this caps the
/// fan-out (and head-of-line coupling) a slow consumer can impose.
const MAX_STREAMS_PER_SESSION: u32 = 8;
/// Bounded depth (frames) of each per-stream inbound channel.
const STREAM_RECV_CAP: usize = 16;
/// Bounded depth of the shared outbound write channel feeding the session
/// writer.
const SESSION_WRITE_CAP: usize = 64;
/// How long a session with no open streams stays registered for reuse.
const SESSION_IDLE_TTL: Duration = Duration::from_secs(30);
/// Cap on live sessions tracked per config key.
const SESSION_POOL_MAX: usize = 8;

/// Append a mux frame (`type | streamID | len | payload`) to `out`.
fn push_frame(out: &mut Vec<u8>, frame_type: u8, stream_id: u32, payload: &[u8]) {
    out.reserve(MUX_HEADER_LEN + payload.len());
    out.push(frame_type);
    out.extend_from_slice(&stream_id.to_be_bytes());
    out.extend_from_slice(&(payload.len() as u32).to_be_bytes());
    out.extend_from_slice(payload);
}

/// Control message from a logical stream to its session writer. Unbounded (low
/// volume) so `Close` can be queued synchronously from `Drop`.
enum Ctrl {
    /// Open a new stream to `addr` (SOCKS5-encoded): the writer allocates the
    /// next id, registers `data` for inbound payloads, writes the `Open` frame,
    /// and replies the id.
    Open {
        addr: Vec<u8>,
        data: mpsc::Sender<Vec<u8>>,
        reply: oneshot::Sender<io::Result<u32>>,
    },
    /// Send this stream's `Close` (our write half-close); keep routing inbound.
    Fin { sid: u32 },
    /// The stream was dropped: stop routing inbound to it.
    Close { sid: u32 },
}

/// One application write on a stream, framed by the writer as `Data`.
struct WriteMsg {
    sid: u32,
    data: Vec<u8>,
}

/// State shared between a session's reader task, writer task and streams.
struct SessionShared {
    /// Open streams: id → inbound payload sender. Dropping a sender (on
    /// `Close`/`Reset`) gives that stream's reader EOF.
    streams: Mutex<HashMap<u32, mpsc::Sender<Vec<u8>>>>,
    /// Set when the connection is unusable (transport died / protocol error).
    broken: AtomicBool,
    /// Wakers of streams whose `poll_write` found the bounded channel full.
    write_wakers: Mutex<Vec<Waker>>,
    /// Notified when the writer exits so the reader stops and tears down.
    closing: Notify,
}

impl SessionShared {
    fn wake_writers(&self) {
        for waker in self
            .write_wakers
            .lock()
            .expect("sudoku mux write wakers")
            .drain(..)
        {
            waker.wake();
        }
    }

    fn mark_broken(&self) {
        self.broken.store(true, Ordering::Release);
    }

    fn is_broken(&self) -> bool {
        self.broken.load(Ordering::Acquire)
    }

    /// Mark broken and drop every stream sender so all readers see EOF.
    fn tear_down_streams(&self) {
        self.mark_broken();
        self.streams.lock().expect("sudoku mux streams").clear();
        self.wake_writers();
    }
}

/// A handle to a live mux session: the channels into its writer, shared
/// liveness state, the count of open streams and when it last went idle. Held
/// by every stream and (for reuse) by the per-config registry; the session
/// shuts down and the connection closes once the last handle is dropped.
struct SessionHandle {
    ctrl: mpsc::UnboundedSender<Ctrl>,
    writes: mpsc::Sender<WriteMsg>,
    shared: Arc<SessionShared>,
    active: AtomicU32,
    idle_since: Mutex<Option<Instant>>,
}

impl SessionHandle {
    /// Whether this session is still usable for a new stream.
    fn alive(&self) -> bool {
        if self.shared.is_broken() {
            return false;
        }
        if self.active.load(Ordering::Acquire) == 0
            && let Some(since) =
                *self.idle_since.lock().expect("sudoku mux idle_since")
        {
            return since.elapsed() <= SESSION_IDLE_TTL;
        }
        true
    }

    /// Try to reserve a stream slot. Clears the idle marker on idle→busy.
    fn reserve_slot(&self) -> bool {
        let mut cur = self.active.load(Ordering::Acquire);
        loop {
            if cur >= MAX_STREAMS_PER_SESSION || self.shared.is_broken() {
                return false;
            }
            match self.active.compare_exchange_weak(
                cur,
                cur + 1,
                Ordering::AcqRel,
                Ordering::Acquire,
            ) {
                Ok(_) => {
                    *self.idle_since.lock().expect("sudoku mux idle_since") = None;
                    return true;
                }
                Err(actual) => cur = actual,
            }
        }
    }

    /// Release a stream slot; record the idle instant when the last one closes.
    fn release_slot(&self) {
        if self.active.fetch_sub(1, Ordering::AcqRel) == 1 {
            *self.idle_since.lock().expect("sudoku mux idle_since") =
                Some(Instant::now());
        }
    }
}

/// Per-config-key registry of live mux sessions: a new connection first tries
/// to open another stream on an existing session before a fresh tunnel
/// handshake. Broken and idle-expired sessions are evicted on access.
static SESSION_REGISTRY: Mutex<Option<HashMap<String, Vec<Arc<SessionHandle>>>>> =
    Mutex::new(None);

/// A registry key that groups sessions sharing an identical tunnel config.
fn session_key(config: &SudokuOutboundConfig) -> String {
    format!(
        "{}|{}|{}|{:?}|{}|{:?}|{}|{}|{}|{:?}|{}|{}|{}|{}",
        config.server,
        config.port,
        config.key,
        config.aead_method,
        config.table_type,
        config.custom_patterns,
        config.padding_min,
        config.padding_max,
        config.pure_downlink,
        config.http_mask_mode,
        config.http_mask_tls,
        config.http_mask_host,
        config.http_mask_path_root,
        config.http_mask_multiplex,
    )
}

/// Find a live registered session for `key` with a free stream slot and reserve
/// it, evicting broken/idle-expired entries. `None` means a new session is
/// needed.
fn take_reusable(key: &str) -> Option<Arc<SessionHandle>> {
    let mut guard = SESSION_REGISTRY.lock().expect("sudoku mux registry");
    let map = guard.as_mut()?;
    let list = map.get_mut(key)?;
    list.retain(|handle| handle.alive());
    let mut chosen = None;
    for handle in list.iter() {
        if handle.reserve_slot() {
            chosen = Some(handle.clone());
            break;
        }
    }
    if list.is_empty() {
        map.remove(key);
    }
    chosen
}

/// Register a freshly-created session for reuse, bounded by
/// [`SESSION_POOL_MAX`].
fn register_session(key: String, handle: Arc<SessionHandle>) {
    let mut guard = SESSION_REGISTRY.lock().expect("sudoku mux registry");
    let map = guard.get_or_insert_with(HashMap::new);
    let list = map.entry(key).or_default();
    list.retain(|handle| handle.alive());
    if list.len() < SESSION_POOL_MAX {
        list.push(handle);
    }
}

/// Spawn the writer and reader tasks driving a new session over `inner` (the
/// record stream with `StartMux` already sent) and return its handle with one
/// stream slot pre-reserved for the opener.
fn spawn_session(inner: AnyStream) -> Arc<SessionHandle> {
    let (ctrl_tx, ctrl_rx) = mpsc::unbounded_channel();
    let (write_tx, write_rx) = mpsc::channel(SESSION_WRITE_CAP);
    let shared = Arc::new(SessionShared {
        streams: Mutex::new(HashMap::new()),
        broken: AtomicBool::new(false),
        write_wakers: Mutex::new(Vec::new()),
        closing: Notify::new(),
    });
    let handle = Arc::new(SessionHandle {
        ctrl: ctrl_tx,
        writes: write_tx,
        shared: shared.clone(),
        active: AtomicU32::new(1),
        idle_since: Mutex::new(None),
    });
    let (rd, wr) = tokio::io::split(inner);
    let mut keepalive = interval_at(
        tokio::time::Instant::now() + MUX_KEEPALIVE_INTERVAL,
        MUX_KEEPALIVE_INTERVAL,
    );
    keepalive.set_missed_tick_behavior(MissedTickBehavior::Skip);
    let writer = SessionWriter {
        wr,
        out: VecDeque::new(),
        next_id: 1,
        ctrl_rx,
        write_rx,
        keepalive,
        last_write: Instant::now(),
        shared: shared.clone(),
    };
    let reader = SessionReader {
        rd,
        read_raw: Vec::new(),
        shared,
    };
    tokio::spawn(writer.run());
    tokio::spawn(reader.run());
    handle
}

/// Open a new logical stream to `addr` (SOCKS5-encoded) on `handle`.
async fn open_on(handle: &Arc<SessionHandle>, addr: Vec<u8>) -> Result<MuxStream> {
    if handle.shared.is_broken() {
        anyhow::bail!("sudoku mux: session broken");
    }
    let (data_tx, data_rx) = mpsc::channel(STREAM_RECV_CAP);
    let (reply_tx, reply_rx) = oneshot::channel();
    handle
        .ctrl
        .send(Ctrl::Open {
            addr,
            data: data_tx,
            reply: reply_tx,
        })
        .map_err(|_| anyhow!("sudoku mux: session closed"))?;
    let sid = reply_rx
        .await
        .map_err(|_| anyhow!("sudoku mux: session closed"))??;
    Ok(MuxStream {
        sid,
        data_rx,
        writes: handle.writes.clone(),
        handle: handle.clone(),
        shared: handle.shared.clone(),
        leftover: Vec::new(),
        leftover_pos: 0,
        eof: false,
        fin_sent: false,
    })
}

/// Connect through a multiplexed Sudoku tunnel to `target`: open another stream
/// on a live session for this config if one has a free slot, otherwise bring up
/// a fresh tunnel (handshake + `StartMux`) and open the first stream on it.
pub(super) async fn connect(
    config: &SudokuOutboundConfig,
    target: &SocksAddr,
    raw: AnyStream,
) -> Result<AnyStream> {
    let addr = kip::encode_address(target)?;
    let key = session_key(config);

    // Reuse path: open another stream on an existing session. On failure the
    // session just broke; release the reserved slot and open a fresh tunnel.
    if let Some(handle) = take_reusable(&key) {
        match open_on(&handle, addr.clone()).await {
            Ok(stream) => {
                drop(raw);
                return Ok(Box::new(stream));
            }
            Err(_) => handle.release_slot(),
        }
    }

    let mut inner = super::establish_session(config, raw).await?;
    kip::write_start_mux(&mut inner).await?;
    let handle = spawn_session(inner);
    register_session(key, handle.clone());
    let stream = open_on(&handle, addr).await?;
    Ok(Box::new(stream))
}

/// The writer task of one mux session: owns the transport's write half and the
/// stream-id counter, serialising every stream's writes and control frames into
/// the record stream, plus the idle keepalive. Runs until the transport write
/// dies or the last [`SessionHandle`] is dropped (closing the command
/// channels).
struct SessionWriter {
    wr: WriteHalf<AnyStream>,
    /// Frames pending write to the transport.
    out: VecDeque<u8>,
    /// Next stream id to assign (monotonic; never 0).
    next_id: u32,
    ctrl_rx: mpsc::UnboundedReceiver<Ctrl>,
    write_rx: mpsc::Receiver<WriteMsg>,
    keepalive: Interval,
    last_write: Instant,
    shared: Arc<SessionShared>,
}

impl SessionWriter {
    async fn run(mut self) {
        let mut ctrl_open = true;
        let mut write_open = true;
        loop {
            if self.flush_out().await.is_err() {
                break;
            }
            if !ctrl_open && !write_open {
                break;
            }
            tokio::select! {
                biased;
                ctrl = self.ctrl_rx.recv(), if ctrl_open => match ctrl {
                    Some(c) => self.handle_ctrl(c),
                    None => ctrl_open = false,
                },
                msg = self.write_rx.recv(), if write_open => {
                    self.shared.wake_writers();
                    match msg {
                        Some(m) => self.handle_write(m),
                        None => write_open = false,
                    }
                }
                _ = self.keepalive.tick() => {
                    if self.last_write.elapsed() >= MUX_KEEPALIVE_INTERVAL {
                        // Stream 0 is never allocated; peers ignore Data for it.
                        let mut frame = Vec::with_capacity(MUX_HEADER_LEN);
                        push_frame(&mut frame, MUX_FRAME_DATA, 0, &[]);
                        self.enqueue(frame);
                    }
                }
            }
        }
        let _ = self.wr.shutdown().await;
        self.shared.tear_down_streams();
        self.shared.closing.notify_waiters();
    }

    fn enqueue(&mut self, frame: Vec<u8>) {
        self.out.extend(frame);
        self.last_write = Instant::now();
    }

    /// Write all queued bytes to the transport, then flush. Marks broken on
    /// error.
    async fn flush_out(&mut self) -> io::Result<()> {
        if self.out.is_empty() {
            return Ok(());
        }
        let bytes: Vec<u8> = self.out.drain(..).collect();
        if let Err(e) = self.wr.write_all(&bytes).await {
            self.shared.mark_broken();
            return Err(e);
        }
        self.wr
            .flush()
            .await
            .inspect_err(|_| self.shared.mark_broken())
    }

    fn handle_ctrl(&mut self, ctrl: Ctrl) {
        match ctrl {
            Ctrl::Open { addr, data, reply } => {
                let sid = self.alloc_id();
                self.shared
                    .streams
                    .lock()
                    .expect("sudoku mux streams")
                    .insert(sid, data);
                let mut frame = Vec::with_capacity(MUX_HEADER_LEN + addr.len());
                push_frame(&mut frame, MUX_FRAME_OPEN, sid, &addr);
                self.enqueue(frame);
                let _ = reply.send(Ok(sid));
            }
            Ctrl::Fin { sid } => {
                if self
                    .shared
                    .streams
                    .lock()
                    .expect("sudoku mux streams")
                    .contains_key(&sid)
                {
                    let mut frame = Vec::with_capacity(MUX_HEADER_LEN);
                    push_frame(&mut frame, MUX_FRAME_CLOSE, sid, &[]);
                    self.enqueue(frame);
                }
            }
            Ctrl::Close { sid } => {
                self.shared
                    .streams
                    .lock()
                    .expect("sudoku mux streams")
                    .remove(&sid);
            }
        }
    }

    /// Frame one application write as `Data`(s) for its stream, dropping it if
    /// the stream has since closed.
    fn handle_write(&mut self, msg: WriteMsg) {
        if !self
            .shared
            .streams
            .lock()
            .expect("sudoku mux streams")
            .contains_key(&msg.sid)
        {
            return;
        }
        let mut pos = 0;
        while pos < msg.data.len() {
            let take = (msg.data.len() - pos).min(MUX_MAX_DATA_PAYLOAD);
            let mut frame = Vec::with_capacity(MUX_HEADER_LEN + take);
            push_frame(
                &mut frame,
                MUX_FRAME_DATA,
                msg.sid,
                &msg.data[pos..pos + take],
            );
            self.enqueue(frame);
            pos += take;
        }
    }

    fn alloc_id(&mut self) -> u32 {
        let id = self.next_id;
        self.next_id = self.next_id.wrapping_add(1);
        if self.next_id == 0 {
            self.next_id = 1;
        }
        id
    }
}

/// The reader task of one mux session: owns the transport's read half and
/// demultiplexes inbound frames, routing each `Data` payload to its stream's
/// bounded channel and dropping a stream's sender on `Close`/`Reset` so its
/// reader sees EOF. Exits on transport EOF/error or when the writer signals
/// closing, then tears down all streams.
struct SessionReader {
    rd: ReadHalf<AnyStream>,
    /// Raw bytes read from the transport not yet parsed into frames.
    read_raw: Vec<u8>,
    shared: Arc<SessionShared>,
}

impl SessionReader {
    async fn run(mut self) {
        let mut buf = vec![0u8; 16 * 1024];
        loop {
            if !self.parse().await {
                break;
            }
            tokio::select! {
                biased;
                _ = self.shared.closing.notified() => break,
                res = self.rd.read(&mut buf) => match res {
                    Ok(0) | Err(_) => break,
                    Ok(n) => self.read_raw.extend_from_slice(&buf[..n]),
                },
            }
        }
        self.shared.tear_down_streams();
    }

    /// Deliver `data` to a stream's channel (awaiting capacity), dropping the
    /// stream if its receiver is gone. Takes `shared` (not `&self`) so the
    /// future stays `Send`.
    async fn deliver(shared: &SessionShared, sid: u32, data: Vec<u8>) {
        let tx = shared
            .streams
            .lock()
            .expect("sudoku mux streams")
            .get(&sid)
            .cloned();
        let Some(tx) = tx else {
            return; // unknown/closed stream: drop the payload
        };
        if tx.reserve().await.map(|p| p.send(data)).is_err() {
            shared
                .streams
                .lock()
                .expect("sudoku mux streams")
                .remove(&sid);
        }
    }

    /// Parse complete frames from `read_raw`, routing payloads to streams.
    /// Returns `false` if the session must shut down (protocol error).
    async fn parse(&mut self) -> bool {
        loop {
            if self.read_raw.len() < MUX_HEADER_LEN {
                return true;
            }
            let frame_type = self.read_raw[0];
            let sid = u32::from_be_bytes([
                self.read_raw[1],
                self.read_raw[2],
                self.read_raw[3],
                self.read_raw[4],
            ]);
            let len = u32::from_be_bytes([
                self.read_raw[5],
                self.read_raw[6],
                self.read_raw[7],
                self.read_raw[8],
            ]) as usize;
            if len > MUX_MAX_FRAME_SIZE {
                return false;
            }
            let need = MUX_HEADER_LEN + len;
            if self.read_raw.len() < need {
                return true;
            }
            let data: Vec<u8> = self.read_raw[MUX_HEADER_LEN..need].to_vec();
            self.read_raw.drain(..need);

            match frame_type {
                // An empty Data (e.g. the stream-0 keepalive) carries no bytes.
                MUX_FRAME_DATA => {
                    if !data.is_empty() {
                        Self::deliver(&self.shared, sid, data).await;
                    }
                }
                // Close/Reset both end this stream: drop its sender for EOF.
                MUX_FRAME_CLOSE | MUX_FRAME_RESET => {
                    self.shared
                        .streams
                        .lock()
                        .expect("sudoku mux streams")
                        .remove(&sid);
                }
                // The client never accepts server-opened streams (reverse mode is
                // not supported); ignore rather than killing the session.
                MUX_FRAME_OPEN => {}
                _ => return false,
            }
        }
    }
}

/// A logical stream multiplexed on a Sudoku mux session: reads pull this
/// stream's demultiplexed `Data` payloads from a bounded channel filled by the
/// reader; writes hand `Data` units to the writer over a bounded
/// (backpressured) channel; shutdown/drop queue this stream's `Close` and free
/// its slot, leaving the connection up for its other streams.
struct MuxStream {
    sid: u32,
    data_rx: mpsc::Receiver<Vec<u8>>,
    writes: mpsc::Sender<WriteMsg>,
    handle: Arc<SessionHandle>,
    shared: Arc<SessionShared>,
    leftover: Vec<u8>,
    leftover_pos: usize,
    eof: bool,
    fin_sent: bool,
}

impl Drop for MuxStream {
    fn drop(&mut self) {
        if !self.fin_sent {
            let _ = self.handle.ctrl.send(Ctrl::Fin { sid: self.sid });
            self.fin_sent = true;
        }
        let _ = self.handle.ctrl.send(Ctrl::Close { sid: self.sid });
        self.handle.release_slot();
    }
}

impl AsyncRead for MuxStream {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut TaskContext<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        loop {
            if this.leftover_pos < this.leftover.len() {
                let n = buf.remaining().min(this.leftover.len() - this.leftover_pos);
                buf.put_slice(
                    &this.leftover[this.leftover_pos..this.leftover_pos + n],
                );
                this.leftover_pos += n;
                return Poll::Ready(Ok(()));
            }
            if this.eof {
                return Poll::Ready(Ok(()));
            }
            match this.data_rx.poll_recv(cx) {
                Poll::Ready(Some(data)) => {
                    this.leftover = data;
                    this.leftover_pos = 0;
                }
                Poll::Ready(None) => {
                    this.eof = true;
                    return Poll::Ready(Ok(()));
                }
                Poll::Pending => return Poll::Pending,
            }
        }
    }
}

impl AsyncWrite for MuxStream {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut TaskContext<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        let this = self.get_mut();
        if this.shared.is_broken() {
            return Poll::Ready(Err(io::ErrorKind::BrokenPipe.into()));
        }
        if buf.is_empty() {
            return Poll::Ready(Ok(0));
        }
        let take = buf.len().min(MUX_MAX_DATA_PAYLOAD);
        match this.writes.try_send(WriteMsg {
            sid: this.sid,
            data: buf[..take].to_vec(),
        }) {
            Ok(()) => Poll::Ready(Ok(take)),
            Err(mpsc::error::TrySendError::Full(_)) => {
                this.shared
                    .write_wakers
                    .lock()
                    .expect("sudoku mux write wakers")
                    .push(cx.waker().clone());
                Poll::Pending
            }
            Err(mpsc::error::TrySendError::Closed(_)) => {
                Poll::Ready(Err(io::ErrorKind::BrokenPipe.into()))
            }
        }
    }

    fn poll_flush(
        self: Pin<&mut Self>,
        _cx: &mut TaskContext<'_>,
    ) -> Poll<io::Result<()>> {
        // Accepted writes are owned by the session writer, which flushes the
        // transport each loop iteration; the stream itself has nothing to flush.
        Poll::Ready(Ok(()))
    }

    fn poll_shutdown(
        self: Pin<&mut Self>,
        _cx: &mut TaskContext<'_>,
    ) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        if !this.fin_sent {
            this.fin_sent = true;
            // `Close` half-closes only this stream; the session stays up.
            let _ = this.handle.ctrl.send(Ctrl::Fin { sid: this.sid });
        }
        Poll::Ready(Ok(()))
    }
}
