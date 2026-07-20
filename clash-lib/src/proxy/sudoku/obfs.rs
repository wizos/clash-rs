//! The Sudoku obfuscation stream layer (pure uplink + pure / packed downlink).
//!
//! This is the *outermost* (on-wire) layer. Plaintext bytes from the AEAD
//! record layer are expanded on write into four "hint" wire-bytes each (plus
//! optional padding), and contracted on read by collecting hint bytes four at a
//! time and looking up the packed key. Padding bytes are recognised as
//! non-hint bytes and skipped.
//!
//! Two downlink codecs exist. The *pure* (one byte → four hints) codec is
//! symmetric and used for both directions when `enable-pure-downlink` is set.
//! When it is disabled the server sends the bandwidth-optimised *packed*
//! downlink instead: ciphertext bits are regrouped MSB-first into 6-bit groups,
//! each mapped to one hint byte (`ByteLayout::group_byte`), with residual bits
//! flushed as a final group followed by a `pad_marker` that resets the reader's
//! bit buffer. The forward client always writes the pure uplink; only its read
//! path switches to the packed decoder. The `write_packed` flag exists so the
//! interop fake server can produce a real packed downlink stream.

use std::{
    cmp::min,
    io,
    pin::Pin,
    task::{Context as TaskContext, Poll},
};

use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};

use super::{
    rng::SudokuRand,
    table::{Table, pack_hint_bytes},
};

/// The 24 permutations of four hint positions, in the reference order. Which
/// permutation is used per byte does not affect decoding (the decoder sorts the
/// four hints) but is reproduced so a captured uplink matches the Go client.
#[rustfmt::skip]
const PERM4: [[usize; 4]; 24] = [
    [0, 1, 2, 3], [0, 1, 3, 2], [0, 2, 1, 3], [0, 2, 3, 1], [0, 3, 1, 2], [0, 3, 2, 1],
    [1, 0, 2, 3], [1, 0, 3, 2], [1, 2, 0, 3], [1, 2, 3, 0], [1, 3, 0, 2], [1, 3, 2, 0],
    [2, 0, 1, 3], [2, 0, 3, 1], [2, 1, 0, 3], [2, 1, 3, 0], [2, 3, 0, 1], [2, 3, 1, 0],
    [3, 0, 1, 2], [3, 0, 2, 1], [3, 1, 0, 2], [3, 1, 2, 0], [3, 2, 0, 1], [3, 2, 1, 0],
];

const PROB_ONE: u64 = 1u64 << 32;

/// Clamp `[p_min, p_max]` to `[0, 100]` and pick a per-connection padding
/// probability threshold in fixed-point (`prob_one == 100%`). Matches
/// `pickPaddingThreshold`.
fn pick_padding_threshold(
    rng: &mut SudokuRand,
    mut p_min: i32,
    mut p_max: i32,
) -> u64 {
    p_min = p_min.clamp(0, 100);
    if p_max < p_min {
        p_max = p_min;
    }
    p_max = p_max.min(100);
    let min_t = p_min as u64 * PROB_ONE / 100;
    let max_t = p_max as u64 * PROB_ONE / 100;
    if max_t <= min_t {
        return min_t;
    }
    let u = rng.uint32() as u64;
    min_t + ((u * (max_t - min_t)) >> 32)
}

/// Encode `plain` into Sudoku hint bytes (with optional padding) using `table`.
/// Faithful port of `encodeSudokuPayload`.
fn encode_payload(
    out: &mut Vec<u8>,
    table: &Table,
    rng: &mut SudokuRand,
    threshold: u64,
    plain: &[u8],
) {
    out.clear();
    if plain.is_empty() {
        return;
    }
    let pads = table.padding_pool();
    let pad_len = pads.len();

    if threshold == 0 {
        for &b in plain {
            let puzzles = &table.encode_table[b as usize];
            let puzzle = &puzzles[rng.intn(puzzles.len())];
            let perm = &PERM4[rng.intn(PERM4.len())];
            out.push(puzzle[perm[0]]);
            out.push(puzzle[perm[1]]);
            out.push(puzzle[perm[2]]);
            out.push(puzzle[perm[3]]);
        }
        return;
    }

    if threshold >= PROB_ONE {
        for &b in plain {
            out.push(pads[rng.intn(pad_len)]);
            let puzzles = &table.encode_table[b as usize];
            let puzzle = &puzzles[rng.intn(puzzles.len())];
            let perm = &PERM4[rng.intn(PERM4.len())];
            for &idx in perm {
                out.push(pads[rng.intn(pad_len)]);
                out.push(puzzle[idx]);
            }
        }
        out.push(pads[rng.intn(pad_len)]);
        return;
    }

    for &b in plain {
        if (rng.uint32() as u64) < threshold {
            out.push(pads[rng.intn(pad_len)]);
        }
        let puzzles = &table.encode_table[b as usize];
        let puzzle = &puzzles[rng.intn(puzzles.len())];
        let perm = &PERM4[rng.intn(PERM4.len())];
        for &idx in perm {
            if (rng.uint32() as u64) < threshold {
                out.push(pads[rng.intn(pad_len)]);
            }
            out.push(puzzle[idx]);
        }
    }
    if (rng.uint32() as u64) < threshold {
        out.push(pads[rng.intn(pad_len)]);
    }
}

/// Append `group`'s wire byte to `out`, optionally prefixed by one padding byte
/// per the padding threshold. Faithful port of `appendPackedGroup`.
fn append_packed_group(
    out: &mut Vec<u8>,
    table: &Table,
    rng: &mut SudokuRand,
    threshold: u64,
    group: u8,
) {
    let pool = &table.layout.packed_padding_pool;
    if threshold != 0 && (rng.uint32() as u64) < threshold {
        out.push(pool[rng.intn(pool.len())]);
    }
    out.push(table.layout.group_byte(group));
}

/// Encode `plain` into the packed (6-bit group) downlink representation using
/// `table`. Faithful port of `PackedConn.Write` (+ its residual `Flush`): each
/// call is self-contained — residual bits are flushed as a final group followed
/// by the `pad_marker`, so the decoder recovers exactly `plain.len()` bytes.
fn encode_packed_payload(
    out: &mut Vec<u8>,
    table: &Table,
    rng: &mut SudokuRand,
    threshold: u64,
    plain: &[u8],
) {
    out.clear();
    if plain.is_empty() {
        return;
    }
    let pool_len = table.layout.packed_padding_pool.len();
    let pad_marker = table.layout.pad_marker;

    let mut bit_buf: u64 = 0;
    let mut bit_count: u32 = 0;

    // Protected prefix: interleave forced padding among the first few groups so
    // the head of the stream does not begin with a run of bare hint bytes.
    let limit = min(plain.len(), PACKED_PROTECTED_PREFIX_BYTES);
    for _ in 0..(1 + rng.intn(2)) {
        out.push(table.layout.packed_padding_pool[rng.intn(pool_len)]);
    }
    let mut gap = 1 + rng.intn(2);
    let mut effective = 0;
    for &b in &plain[..limit] {
        bit_buf = (bit_buf << 8) | b as u64;
        bit_count += 8;
        while bit_count >= 6 {
            bit_count -= 6;
            let group = (bit_buf >> bit_count) as u8;
            bit_buf &= (1u64 << bit_count) - 1;
            append_packed_group(out, table, rng, threshold, group);
        }
        effective += 1;
        if effective >= gap {
            out.push(table.layout.packed_padding_pool[rng.intn(pool_len)]);
            effective = 0;
            gap = 1 + rng.intn(2);
        }
    }

    for &b in &plain[limit..] {
        if threshold != 0 && (rng.uint32() as u64) < threshold {
            out.push(table.layout.packed_padding_pool[rng.intn(pool_len)]);
        }
        bit_buf = (bit_buf << 8) | b as u64;
        bit_count += 8;
        while bit_count >= 6 {
            bit_count -= 6;
            let group = (bit_buf >> bit_count) as u8;
            bit_buf &= (1u64 << bit_count) - 1;
            append_packed_group(out, table, rng, threshold, group);
        }
    }

    if bit_count > 0 {
        let group = (bit_buf << (6 - bit_count)) as u8;
        append_packed_group(out, table, rng, threshold, group);
        out.push(pad_marker);
    }

    if threshold != 0 && (rng.uint32() as u64) < threshold {
        out.push(table.layout.packed_padding_pool[rng.intn(pool_len)]);
    }
}

/// The number of leading payload bytes covered by the packed protected prefix.
const PACKED_PROTECTED_PREFIX_BYTES: usize = 14;

/// An `AsyncRead`/`AsyncWrite` view applying the Sudoku obfuscation: writes are
/// expanded into hint bytes via `uplink`, reads collect hint bytes four at a
/// time and decode via `downlink`.
pub(crate) struct ObfsStream<S> {
    inner: S,
    uplink: Table,
    downlink: Table,
    rng: SudokuRand,
    threshold: u64,
    /// Encode writes with the packed (6-bit) codec instead of the pure codec.
    write_packed: bool,
    /// Decode reads with the packed (6-bit) codec instead of the pure codec.
    read_packed: bool,

    // Write staging.
    write_buf: Vec<u8>,
    write_pos: usize,
    write_consumed: usize,

    // Read staging.
    raw: Vec<u8>,
    hint_buf: [u8; 4],
    hint_count: usize,
    // Packed-read bit accumulator (MSB-first).
    read_bit_buf: u64,
    read_bits: u32,
    plain: Vec<u8>,
    plain_pos: usize,
    eof: bool,
}

impl<S> ObfsStream<S> {
    pub(crate) fn new(
        inner: S,
        uplink: Table,
        downlink: Table,
        padding_min: i32,
        padding_max: i32,
        write_packed: bool,
        read_packed: bool,
    ) -> Self {
        let mut rng = SudokuRand::from_os();
        let threshold = pick_padding_threshold(&mut rng, padding_min, padding_max);
        Self {
            inner,
            uplink,
            downlink,
            rng,
            threshold,
            write_packed,
            read_packed,
            write_buf: Vec::with_capacity(4096),
            write_pos: 0,
            write_consumed: 0,
            raw: Vec::new(),
            hint_buf: [0; 4],
            hint_count: 0,
            read_bit_buf: 0,
            read_bits: 0,
            plain: Vec::new(),
            plain_pos: 0,
            eof: false,
        }
    }

    /// Decode all complete plaintext bytes available in `chunk` into
    /// `self.plain`.
    fn decode_into_plain(&mut self, chunk: &[u8]) -> io::Result<()> {
        if self.read_packed {
            return self.decode_packed_into_plain(chunk);
        }
        let layout = &self.downlink.layout;
        for &b in chunk {
            if !layout.hint_table[b as usize] {
                continue;
            }
            self.hint_buf[self.hint_count] = b;
            self.hint_count += 1;
            if self.hint_count != 4 {
                continue;
            }
            self.hint_count = 0;
            let key = pack_hint_bytes(
                self.hint_buf[0],
                self.hint_buf[1],
                self.hint_buf[2],
                self.hint_buf[3],
            );
            match self.downlink.decode_map.get(&key) {
                Some(&val) => self.plain.push(val),
                None => {
                    return Err(io::Error::new(
                        io::ErrorKind::InvalidData,
                        "sudoku: INVALID_SUDOKU_MAP_MISS",
                    ));
                }
            }
        }
        Ok(())
    }

    /// Decode packed (6-bit group) downlink bytes from `chunk`. Non-hint bytes
    /// are skipped; the `pad_marker` flushes the residual-bit accumulator.
    /// Faithful port of `PackedConn.Read`'s byte-at-a-time path.
    fn decode_packed_into_plain(&mut self, chunk: &[u8]) -> io::Result<()> {
        let layout = &self.downlink.layout;
        for &b in chunk {
            if !layout.hint_table[b as usize] {
                if b == layout.pad_marker {
                    self.read_bit_buf = 0;
                    self.read_bits = 0;
                }
                continue;
            }
            let (group, ok) = layout.decode_packed_group(b);
            if !ok {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "sudoku: INVALID_SUDOKU_MAP_MISS",
                ));
            }
            self.read_bit_buf = (self.read_bit_buf << 6) | group as u64;
            self.read_bits += 6;
            if self.read_bits >= 8 {
                self.read_bits -= 8;
                let val = (self.read_bit_buf >> self.read_bits) as u8;
                self.plain.push(val);
                self.read_bit_buf &= (1u64 << self.read_bits) - 1;
            }
        }
        Ok(())
    }

    fn drain_plain(&mut self, dst: &mut ReadBuf<'_>) -> bool {
        if self.plain_pos >= self.plain.len() {
            return false;
        }
        let n = min(dst.remaining(), self.plain.len() - self.plain_pos);
        dst.put_slice(&self.plain[self.plain_pos..self.plain_pos + n]);
        self.plain_pos += n;
        if self.plain_pos >= self.plain.len() {
            self.plain.clear();
            self.plain_pos = 0;
        }
        n > 0
    }
}

impl<S: AsyncWrite + Unpin> AsyncWrite for ObfsStream<S> {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut TaskContext<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        let me = self.get_mut();
        loop {
            if !me.write_buf.is_empty() {
                while me.write_pos < me.write_buf.len() {
                    match Pin::new(&mut me.inner)
                        .poll_write(cx, &me.write_buf[me.write_pos..])
                    {
                        Poll::Pending => return Poll::Pending,
                        Poll::Ready(Err(e)) => return Poll::Ready(Err(e)),
                        Poll::Ready(Ok(0)) => {
                            return Poll::Ready(Err(io::Error::new(
                                io::ErrorKind::WriteZero,
                                "sudoku: inner stream closed",
                            )));
                        }
                        Poll::Ready(Ok(n)) => me.write_pos += n,
                    }
                }
                me.write_buf.clear();
                me.write_pos = 0;
                let consumed = me.write_consumed;
                me.write_consumed = 0;
                return Poll::Ready(Ok(consumed));
            }
            if buf.is_empty() {
                return Poll::Ready(Ok(0));
            }
            // Bound the work per write so a single huge buffer does not balloon.
            let take = min(buf.len(), 16 * 1024);
            let mut staged = std::mem::take(&mut me.write_buf);
            if me.write_packed {
                encode_packed_payload(
                    &mut staged,
                    &me.uplink,
                    &mut me.rng,
                    me.threshold,
                    &buf[..take],
                );
            } else {
                encode_payload(
                    &mut staged,
                    &me.uplink,
                    &mut me.rng,
                    me.threshold,
                    &buf[..take],
                );
            }
            me.write_buf = staged;
            me.write_pos = 0;
            me.write_consumed = take;
        }
    }

    fn poll_flush(
        self: Pin<&mut Self>,
        cx: &mut TaskContext<'_>,
    ) -> Poll<io::Result<()>> {
        Pin::new(&mut self.get_mut().inner).poll_flush(cx)
    }

    fn poll_shutdown(
        self: Pin<&mut Self>,
        cx: &mut TaskContext<'_>,
    ) -> Poll<io::Result<()>> {
        Pin::new(&mut self.get_mut().inner).poll_shutdown(cx)
    }
}

impl<S: AsyncRead + Unpin> AsyncRead for ObfsStream<S> {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut TaskContext<'_>,
        dst: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        let me = self.get_mut();
        loop {
            if me.drain_plain(dst) {
                return Poll::Ready(Ok(()));
            }
            if me.eof {
                return Poll::Ready(Ok(()));
            }
            let mut tmp = [0u8; 8192];
            let mut rb = ReadBuf::new(&mut tmp);
            match Pin::new(&mut me.inner).poll_read(cx, &mut rb) {
                Poll::Pending => return Poll::Pending,
                Poll::Ready(Err(e)) => return Poll::Ready(Err(e)),
                Poll::Ready(Ok(())) => {
                    let filled = rb.filled();
                    if filled.is_empty() {
                        me.eof = true;
                        return Poll::Ready(Ok(()));
                    }
                    me.raw.clear();
                    me.raw.extend_from_slice(filled);
                    let chunk = std::mem::take(&mut me.raw);
                    let res = me.decode_into_plain(&chunk);
                    me.raw = chunk;
                    res?;
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::proxy::sudoku::table::new_directional_table;
    use tokio::io::{AsyncReadExt, AsyncWriteExt, duplex};

    async fn obfs_round_trip(mode: &str, pad: i32, payload: Vec<u8>) {
        // A writes with its uplink; B must decode with the same table, so B's
        // decode (downlink) table is built from A's uplink preference.
        let ta = new_directional_table("obfs-key", mode, "").unwrap();
        let tb = new_directional_table("obfs-key", mode, "").unwrap();
        let (a, b) = duplex(256 * 1024);
        let mut writer =
            ObfsStream::new(a, ta.uplink, ta.downlink, pad, pad, false, false);
        let mut reader =
            ObfsStream::new(b, tb.downlink, tb.uplink, pad, pad, false, false);

        let expected = payload.clone();
        let w = tokio::spawn(async move {
            writer.write_all(&payload).await.unwrap();
            writer.flush().await.unwrap();
            writer.shutdown().await.unwrap();
        });
        let mut got = Vec::new();
        reader.read_to_end(&mut got).await.unwrap();
        w.await.unwrap();
        assert_eq!(got, expected);
    }

    #[tokio::test]
    async fn entropy_round_trips_without_padding() {
        obfs_round_trip("prefer_entropy", 0, b"the quick brown fox".to_vec()).await;
        obfs_round_trip(
            "prefer_entropy",
            0,
            (0..2048u32).map(|i| i as u8).collect(),
        )
        .await;
    }

    #[tokio::test]
    async fn ascii_round_trips_with_full_padding() {
        // padding 100% exercises the always-pad branch; padding bytes are
        // non-hint and must be skipped on decode.
        obfs_round_trip("prefer_ascii", 100, b"padded payload here".to_vec()).await;
    }

    /// A packed (6-bit) downlink writer feeding a packed reader, mirroring the
    /// server→client direction when `enable-pure-downlink` is disabled.
    async fn packed_round_trip(mode: &str, pad: i32, payload: Vec<u8>) {
        let ta = new_directional_table("obfs-key", mode, "").unwrap();
        let tb = new_directional_table("obfs-key", mode, "").unwrap();
        let (a, b) = duplex(256 * 1024);
        // Server: writes the packed downlink table, reads the pure uplink table.
        let mut writer =
            ObfsStream::new(a, ta.downlink, ta.uplink, pad, pad, true, false);
        // Client: writes the pure uplink table, reads the packed downlink table.
        let mut reader =
            ObfsStream::new(b, tb.uplink, tb.downlink, pad, pad, false, true);

        let expected = payload.clone();
        let w = tokio::spawn(async move {
            writer.write_all(&payload).await.unwrap();
            writer.flush().await.unwrap();
            writer.shutdown().await.unwrap();
        });
        let mut got = Vec::new();
        reader.read_to_end(&mut got).await.unwrap();
        w.await.unwrap();
        assert_eq!(got, expected);
    }

    #[tokio::test]
    async fn packed_entropy_round_trips() {
        packed_round_trip("prefer_entropy", 0, b"packed downlink payload".to_vec())
            .await;
        packed_round_trip(
            "prefer_entropy",
            0,
            (0..2048u32).map(|i| i as u8).collect(),
        )
        .await;
    }

    #[tokio::test]
    async fn packed_round_trips_with_padding_and_ascii() {
        // Padding interleaves non-hint bytes among the 6-bit groups; the reader
        // must skip them and honour the residual-flush marker.
        packed_round_trip("prefer_ascii", 100, b"padded packed payload".to_vec())
            .await;
        packed_round_trip(
            "prefer_entropy",
            40,
            (0..1500u32).map(|i| (i * 5) as u8).collect(),
        )
        .await;
    }

    #[test]
    fn padding_threshold_clamps_range() {
        let mut rng = SudokuRand::new(1);
        assert_eq!(pick_padding_threshold(&mut rng, 0, 0), 0);
        assert_eq!(pick_padding_threshold(&mut rng, 100, 100), PROB_ONE);
        assert_eq!(pick_padding_threshold(&mut rng, -5, 0), 0);
        let t = pick_padding_threshold(&mut rng, 0, 100);
        assert!(t <= PROB_ONE);
    }
}
