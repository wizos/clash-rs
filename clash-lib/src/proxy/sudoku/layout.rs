//! Byte layouts: how a `(value, position)` hint or a padding byte maps onto an
//! actual wire byte for each obfuscation "look".
//!
//! Three layouts exist, all sharing the same 288-grid table but differing only
//! in which concrete bytes carry the four hints:
//!
//! * **ascii** — hints are printable bytes with bit `0x40` set (`@`–`~`, with
//!   `0x7F` remapped to `\n`); padding is `0x20..=0x3F`. Produces text-like
//!   traffic.
//! * **entropy** — hints avoid the `0x90` mask bits, spreading across the byte
//!   range for a high-entropy look; padding is a fixed 16-byte high/low pool.
//! * **custom** — an 8-symbol `x`/`p`/`v` bit-position pattern (2 `x`, 2 `p`, 4
//!   `v`) chooses which bits mark a hint, carry the 2-bit value, and carry the
//!   4-bit position. Padding is the high-popcount bytes the pattern produces.

use anyhow::{Result, bail};

/// Resolved wire layout for one traffic direction.
pub(crate) struct ByteLayout {
    /// Layout name (`ascii`/`entropy`/`custom`); retained for table-hint parity
    /// with the reference even though the single-table baseline never reads it.
    #[allow(dead_code)]
    pub(crate) name: String,
    /// Per-`(value, position)` hint byte: `encode_hint[val & 3][pos & 15]`.
    encode_hint: [[u8; 16]; 4],
    /// Which wire bytes are recognised as hint bytes (everything else is
    /// padding to be skipped on decode).
    pub(crate) hint_table: [bool; 256],
    /// Padding-byte pool (never overlaps `hint_table`).
    pub(crate) padding_pool: Vec<u8>,
    /// The 6-bit "packed" downlink codec: `encode_group[group & 0x3F]` is the
    /// wire byte carrying a 6-bit group; `decode_group[b]` / `group_valid[b]`
    /// invert it for hint bytes.
    encode_group: [u8; 64],
    decode_group: [u8; 256],
    group_valid: [bool; 256],
    /// The single reserved byte that flushes the packed reader's bit buffer
    /// (residual-bit boundary marker). Recognised as non-hint.
    pub(crate) pad_marker: u8,
    /// Padding pool used by the packed codec: `padding_pool` minus `pad_marker`
    /// (the marker never doubles as ordinary padding).
    pub(crate) packed_padding_pool: Vec<u8>,
}

impl ByteLayout {
    /// Whether this layout is the printable "ascii" look (used for table-hint
    /// compatibility checks in the reference; kept for parity).
    #[allow(dead_code)]
    pub(crate) fn is_ascii(&self) -> bool {
        self.name == "ascii"
    }

    /// The wire byte carrying grid value `val` (`0..=3`, i.e. cell value `-1`)
    /// at cell position `pos` (`0..=15`).
    pub(crate) fn hint_byte(&self, val: u8, pos: u8) -> u8 {
        self.encode_hint[(val & 0x03) as usize][(pos & 0x0F) as usize]
    }

    /// The wire byte carrying the 6-bit packed `group`.
    pub(crate) fn group_byte(&self, group: u8) -> u8 {
        self.encode_group[(group & 0x3F) as usize]
    }

    /// Decode a wire byte back to its 6-bit group; the bool is `false` when the
    /// byte is not a valid packed hint.
    pub(crate) fn decode_packed_group(&self, b: u8) -> (u8, bool) {
        (self.decode_group[b as usize], self.group_valid[b as usize])
    }
}

/// Build the packed padding pool (`padding_pool` minus `pad_marker`), falling
/// back to the marker itself if that leaves the pool empty. Matches
/// `NewPackedConn`'s pool construction.
fn packed_pool(padding_pool: &[u8], pad_marker: u8) -> Vec<u8> {
    let mut pool: Vec<u8> = padding_pool
        .iter()
        .copied()
        .filter(|&b| b != pad_marker)
        .collect();
    if pool.is_empty() {
        pool.push(pad_marker);
    }
    pool
}

/// Resolve a single-direction layout. `mode` is a per-direction preference
/// (`prefer_ascii` / `prefer_entropy`); a non-empty `custom_pattern` selects
/// the custom layout when entropy is preferred.
pub(crate) fn resolve_layout(
    mode: &str,
    custom_pattern: &str,
) -> Result<ByteLayout> {
    match mode.to_ascii_lowercase().as_str() {
        "ascii" | "prefer_ascii" => return Ok(ascii_layout()),
        "entropy" | "prefer_entropy" | "" => {}
        other => bail!("sudoku: invalid ascii mode: {other}"),
    }
    if !custom_pattern.trim().is_empty() {
        return custom_layout(custom_pattern);
    }
    Ok(entropy_layout())
}

fn ascii_layout() -> ByteLayout {
    let padding: Vec<u8> = (0..32).map(|i| 0x20 + i as u8).collect();

    let mut encode_hint = [[0u8; 16]; 4];
    for (val, row) in encode_hint.iter_mut().enumerate() {
        for (pos, slot) in row.iter_mut().enumerate() {
            let mut b = 0x40 | ((val as u8) << 4) | pos as u8;
            if b == 0x7F {
                b = b'\n';
            }
            *slot = b;
        }
    }

    let mut hint_table = [false; 256];
    let mut decode_group = [0u8; 256];
    let mut group_valid = [false; 256];
    for b in 0..256usize {
        let wire = b as u8;
        if wire & 0x40 == 0x40 {
            hint_table[b] = true;
            decode_group[b] = wire & 0x3F;
            group_valid[b] = true;
        }
    }
    hint_table[b'\n' as usize] = true;
    decode_group[b'\n' as usize] = 0x3F;
    group_valid[b'\n' as usize] = true;

    let mut encode_group = [0u8; 64];
    for (group, slot) in encode_group.iter_mut().enumerate() {
        let mut b = 0x40 | group as u8;
        if b == 0x7F {
            b = b'\n';
        }
        *slot = b;
    }

    let pad_marker = 0x3F;
    ByteLayout {
        name: "ascii".to_string(),
        encode_hint,
        hint_table,
        packed_padding_pool: packed_pool(&padding, pad_marker),
        padding_pool: padding,
        encode_group,
        decode_group,
        group_valid,
        pad_marker,
    }
}

fn entropy_layout() -> ByteLayout {
    let mut padding = Vec::with_capacity(16);
    for i in 0..8u8 {
        padding.push(0x80 + i);
        padding.push(0x10 + i);
    }

    let mut encode_hint = [[0u8; 16]; 4];
    for (val, row) in encode_hint.iter_mut().enumerate() {
        for (pos, slot) in row.iter_mut().enumerate() {
            *slot = ((val as u8) << 5) | pos as u8;
        }
    }

    let mut encode_group = [0u8; 64];
    for (group, slot) in encode_group.iter_mut().enumerate() {
        let v = group as u8;
        *slot = ((v & 0x30) << 1) | (v & 0x0F);
    }

    let mut hint_table = [false; 256];
    let mut decode_group = [0u8; 256];
    let mut group_valid = [false; 256];
    for b in 0..256usize {
        let wire = b as u8;
        if wire & 0x90 != 0 {
            continue;
        }
        hint_table[b] = true;
        decode_group[b] = ((wire >> 1) & 0x30) | (wire & 0x0F);
        group_valid[b] = true;
    }

    let pad_marker = 0x80;
    ByteLayout {
        name: "entropy".to_string(),
        encode_hint,
        hint_table,
        packed_padding_pool: packed_pool(&padding, pad_marker),
        padding_pool: padding,
        encode_group,
        decode_group,
        group_valid,
        pad_marker,
    }
}

fn custom_layout(pattern: &str) -> Result<ByteLayout> {
    let cleaned: String = pattern.trim().replace(' ', "").to_ascii_lowercase();
    if cleaned.len() != 8 {
        bail!(
            "sudoku: custom table must have 8 symbols, got {}",
            cleaned.len()
        );
    }

    let mut x_bits = Vec::new();
    let mut p_bits = Vec::new();
    let mut v_bits = Vec::new();
    for (i, c) in cleaned.chars().enumerate() {
        let bit = 7 - i as u8;
        match c {
            'x' => x_bits.push(bit),
            'p' => p_bits.push(bit),
            'v' => v_bits.push(bit),
            other => bail!("sudoku: invalid char {other:?} in custom table"),
        }
    }
    if x_bits.len() != 2 || p_bits.len() != 2 || v_bits.len() != 4 {
        bail!("sudoku: custom table must contain exactly 2 x, 2 p, 4 v");
    }

    let mut x_mask = 0u8;
    for &b in &x_bits {
        x_mask |= 1 << b;
    }

    let encode_bits = |val: u8, pos: u8, drop_x: i32| -> u8 {
        let mut out = x_mask;
        if drop_x >= 0 {
            out &= !(1 << x_bits[drop_x as usize]);
        }
        if val & 0x02 != 0 {
            out |= 1 << p_bits[0];
        }
        if val & 0x01 != 0 {
            out |= 1 << p_bits[1];
        }
        for (i, &bit) in v_bits.iter().enumerate() {
            if (pos >> (3 - i as u8)) & 0x01 == 1 {
                out |= 1 << bit;
            }
        }
        out
    };

    let mut padding_set = [false; 256];
    let mut padding = Vec::new();
    for drop in 0..x_bits.len() as i32 {
        for val in 0..4u8 {
            for pos in 0..16u8 {
                let b = encode_bits(val, pos, drop);
                if b.count_ones() >= 5 && !padding_set[b as usize] {
                    padding_set[b as usize] = true;
                    padding.push(b);
                }
            }
        }
    }
    padding.sort_unstable();
    if padding.is_empty() {
        bail!("sudoku: custom table produced empty padding pool");
    }

    let mut encode_hint = [[0u8; 16]; 4];
    for (val, row) in encode_hint.iter_mut().enumerate() {
        for (pos, slot) in row.iter_mut().enumerate() {
            *slot = encode_bits(val as u8, pos as u8, -1);
        }
    }

    let mut encode_group = [0u8; 64];
    for (group, slot) in encode_group.iter_mut().enumerate() {
        let val = (group as u8 >> 4) & 0x03;
        let pos = group as u8 & 0x0F;
        *slot = encode_bits(val, pos, -1);
    }

    let mut hint_table = [false; 256];
    let mut decode_group = [0u8; 256];
    let mut group_valid = [false; 256];
    for b in 0..256usize {
        let wire = b as u8;
        if wire & x_mask != x_mask {
            continue;
        }
        hint_table[b] = true;

        let mut val = 0u8;
        if wire & (1 << p_bits[0]) != 0 {
            val |= 0x02;
        }
        if wire & (1 << p_bits[1]) != 0 {
            val |= 0x01;
        }
        let mut pos = 0u8;
        for (i, &bit) in v_bits.iter().enumerate() {
            if wire & (1 << bit) != 0 {
                pos |= 1 << (3 - i as u8);
            }
        }
        decode_group[b] = (val << 4) | pos;
        group_valid[b] = true;
    }

    let pad_marker = padding[0];
    Ok(ByteLayout {
        name: format!("custom({cleaned})"),
        encode_hint,
        hint_table,
        packed_padding_pool: packed_pool(&padding, pad_marker),
        padding_pool: padding,
        encode_group,
        decode_group,
        group_valid,
        pad_marker,
    })
}
