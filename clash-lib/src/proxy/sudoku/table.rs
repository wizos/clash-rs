//! The obfuscation table: a key-seeded assignment of grids to byte values plus
//! the encode/decode maps derived from it.
//!
//! Construction (matching the reference `newSingleDirectionTable`):
//! 1. `seed = BE_u64(SHA256(key)[:8])`, build a [`GoRand`] from it.
//! 2. Shuffle a copy of all 288 grids with `GoRand::shuffle`.
//! 3. For byte value `b` (0..256) take `shuffledGrids[b]` and, for every
//!    ascending 4-position combination that *uniquely* identifies that grid,
//!    record the four hint wire-bytes as an encoding of `b`, and map their
//!    sorted-packed `u32` key back to `b` for decoding.
//!
//! Directional modes (`up_ascii_down_entropy` etc.) build two tables from the
//! same key — one per direction — sharing the same shuffled-grid assignment but
//! differing in [`ByteLayout`].

use std::collections::HashMap;

use anyhow::Result;
use sha2::{Digest, Sha256};

use super::{
    grid::{HintPart, all_grids, has_unique_match, hint_positions},
    layout::{ByteLayout, resolve_layout},
    rng::GoRand,
};

/// A single-direction obfuscation table.
pub(crate) struct Table {
    /// `encode_table[b]` lists every valid 4-hint encoding of byte `b`.
    pub(crate) encode_table: Vec<Vec<[u8; 4]>>,
    /// Sorted-packed four-hint key → plaintext byte.
    pub(crate) decode_map: HashMap<u32, u8>,
    pub(crate) layout: ByteLayout,
    /// Table fingerprint advertised in the ClientHello table hint; unused by
    /// the single-table baseline but retained for multi-table parity.
    #[allow(dead_code)]
    hint: u32,
}

impl Table {
    pub(crate) fn padding_pool(&self) -> &[u8] {
        &self.layout.padding_pool
    }

    #[allow(dead_code)]
    pub(crate) fn hint(&self) -> u32 {
        self.hint
    }
}

/// A built directional table pair. For symmetric modes `uplink` and `downlink`
/// are byte-identical (built from the same layout).
pub(crate) struct DirectionalTable {
    pub(crate) uplink: Table,
    pub(crate) downlink: Table,
}

/// `ASCIIMode` — the preferred layout per direction (uplink = client→server).
struct AsciiMode {
    uplink: &'static str,
    downlink: &'static str,
}

impl AsciiMode {
    fn canonical(&self) -> String {
        if self.uplink == "ascii" && self.downlink == "ascii" {
            "prefer_ascii".to_string()
        } else if self.uplink == "entropy" && self.downlink == "entropy" {
            "prefer_entropy".to_string()
        } else {
            format!("up_{}_down_{}", self.uplink, self.downlink)
        }
    }

    fn uplink_preference(&self) -> &'static str {
        single_direction_preference(self.uplink)
    }

    fn downlink_preference(&self) -> &'static str {
        single_direction_preference(self.downlink)
    }
}

fn single_direction_preference(token: &str) -> &'static str {
    if token == "ascii" {
        "prefer_ascii"
    } else {
        "prefer_entropy"
    }
}

fn parse_ascii_mode(mode: &str) -> Result<AsciiMode> {
    let raw = mode.trim().to_ascii_lowercase();
    match raw.as_str() {
        "" | "entropy" | "prefer_entropy" => {
            return Ok(AsciiMode {
                uplink: "entropy",
                downlink: "entropy",
            });
        }
        "ascii" | "prefer_ascii" => {
            return Ok(AsciiMode {
                uplink: "ascii",
                downlink: "ascii",
            });
        }
        _ => {}
    }

    let stripped = raw
        .strip_prefix("up_")
        .ok_or_else(|| anyhow::anyhow!("sudoku: invalid ascii mode: {mode}"))?;
    let (up, down) = stripped
        .split_once("_down_")
        .ok_or_else(|| anyhow::anyhow!("sudoku: invalid ascii mode: {mode}"))?;
    Ok(AsciiMode {
        uplink: normalize_token(up)?,
        downlink: normalize_token(down)?,
    })
}

fn normalize_token(token: &str) -> Result<&'static str> {
    match token.trim().to_ascii_lowercase().as_str() {
        "ascii" | "prefer_ascii" => Ok("ascii"),
        "entropy" | "prefer_entropy" | "" => Ok("entropy"),
        _ => Err(anyhow::anyhow!("sudoku: invalid ascii mode token: {token}")),
    }
}

fn custom_pattern_for_token(token: &str, custom_pattern: &str) -> String {
    if token == "entropy" {
        custom_pattern.to_string()
    } else {
        String::new()
    }
}

/// `tableHintFingerprint`: a 32-bit identifier negotiated during the handshake
/// so a multi-table server can pick the matching table.
fn table_hint_fingerprint(
    key: &str,
    mode: &str,
    uplink_pattern: &str,
    downlink_pattern: &str,
) -> u32 {
    let joined = [
        "sudoku-table-hint",
        key,
        mode,
        &uplink_pattern.trim().to_ascii_lowercase(),
        &downlink_pattern.trim().to_ascii_lowercase(),
    ]
    .join("\x00");
    let sum = Sha256::digest(joined.as_bytes());
    u32::from_be_bytes([sum[0], sum[1], sum[2], sum[3]])
}

/// Pack four hint bytes into a `u32` after sorting them ascending (so the four
/// hints decode regardless of their on-wire permutation). Matches
/// `packHintBytes`.
pub(crate) fn pack_hint_bytes(
    mut h0: u8,
    mut h1: u8,
    mut h2: u8,
    mut h3: u8,
) -> u32 {
    if h0 > h1 {
        core::mem::swap(&mut h0, &mut h1);
    }
    if h2 > h3 {
        core::mem::swap(&mut h2, &mut h3);
    }
    if h0 > h2 {
        core::mem::swap(&mut h0, &mut h2);
    }
    if h1 > h3 {
        core::mem::swap(&mut h1, &mut h3);
    }
    if h1 > h2 {
        core::mem::swap(&mut h1, &mut h2);
    }
    (h0 as u32) << 24 | (h1 as u32) << 16 | (h2 as u32) << 8 | (h3 as u32)
}

fn build_single_direction(
    key: &str,
    mode: &str,
    custom_pattern: &str,
) -> Result<Table> {
    let layout = resolve_layout(mode, custom_pattern)?;

    let grids = all_grids();
    let mut hasher = Sha256::new();
    hasher.update(key.as_bytes());
    let digest = hasher.finalize();
    let seed = i64::from_be_bytes([
        digest[0], digest[1], digest[2], digest[3], digest[4], digest[5], digest[6],
        digest[7],
    ]);
    let mut rng = GoRand::new(seed);

    let mut shuffled = grids.clone();
    rng.shuffle(shuffled.len(), |i, j| shuffled.swap(i, j));

    let positions = hint_positions();
    let mut encode_table: Vec<Vec<[u8; 4]>> = vec![Vec::new(); 256];
    let mut decode_map: HashMap<u32, u8> = HashMap::new();

    for byte_val in 0..256usize {
        let target = &shuffled[byte_val];
        for combo in &positions {
            let mut raw_parts = [HintPart { val: 0, pos: 0 }; 4];
            for (i, &pos) in combo.iter().enumerate() {
                raw_parts[i] = HintPart {
                    val: target[pos as usize],
                    pos,
                };
            }
            if !has_unique_match(&grids, &raw_parts) {
                continue;
            }
            let mut hints = [0u8; 4];
            for (i, p) in raw_parts.iter().enumerate() {
                hints[i] = layout.hint_byte(p.val - 1, p.pos);
            }
            encode_table[byte_val].push(hints);
            let key = pack_hint_bytes(hints[0], hints[1], hints[2], hints[3]);
            decode_map.insert(key, byte_val as u8);
        }
    }

    Ok(Table {
        encode_table,
        decode_map,
        layout,
        hint: 0,
    })
}

/// Build the directional table pair for `key` / `mode` / optional
/// `custom_pattern`.
pub(crate) fn new_directional_table(
    key: &str,
    mode: &str,
    custom_pattern: &str,
) -> Result<DirectionalTable> {
    let ascii_mode = parse_ascii_mode(mode)?;
    let uplink_pattern = custom_pattern_for_token(ascii_mode.uplink, custom_pattern);
    let downlink_pattern =
        custom_pattern_for_token(ascii_mode.downlink, custom_pattern);
    let hint = table_hint_fingerprint(
        key,
        &ascii_mode.canonical(),
        &uplink_pattern,
        &downlink_pattern,
    );

    let mut uplink = build_single_direction(
        key,
        ascii_mode.uplink_preference(),
        &uplink_pattern,
    )?;
    uplink.hint = hint;

    if ascii_mode.uplink == ascii_mode.downlink {
        let downlink = build_single_direction(
            key,
            ascii_mode.uplink_preference(),
            &uplink_pattern,
        )?;
        let mut downlink = downlink;
        downlink.hint = hint;
        return Ok(DirectionalTable { uplink, downlink });
    }

    let mut downlink = build_single_direction(
        key,
        ascii_mode.downlink_preference(),
        &downlink_pattern,
    )?;
    downlink.hint = hint;
    Ok(DirectionalTable { uplink, downlink })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn assert_round_trips(table: &Table) {
        for byte_val in 0u16..256 {
            let encodings = &table.encode_table[byte_val as usize];
            assert!(
                !encodings.is_empty(),
                "byte {byte_val} has no encoding in the table"
            );
            for hints in encodings {
                // Every hint byte must be recognised as a hint (not padding).
                for &h in hints {
                    assert!(
                        table.layout.hint_table[h as usize],
                        "hint byte {h} not marked in hint_table"
                    );
                }
                let key = pack_hint_bytes(hints[0], hints[1], hints[2], hints[3]);
                assert_eq!(table.decode_map.get(&key), Some(&(byte_val as u8)));
                // Sorting is order-independent: a permutation decodes the same.
                let key_perm =
                    pack_hint_bytes(hints[3], hints[1], hints[0], hints[2]);
                assert_eq!(key_perm, key);
            }
        }
    }

    #[test]
    fn entropy_table_round_trips_every_byte() {
        let t = new_directional_table("a-test-key", "prefer_entropy", "").unwrap();
        assert_round_trips(&t.uplink);
        assert_round_trips(&t.downlink);
    }

    #[test]
    fn ascii_table_round_trips_every_byte() {
        let t = new_directional_table("a-test-key", "prefer_ascii", "").unwrap();
        assert_round_trips(&t.uplink);
        // ascii encodings use the `0x40`-set printable bytes, with `0x7F`
        // remapped to `\n`.
        for byte_val in 0u16..256 {
            for hints in &t.uplink.encode_table[byte_val as usize] {
                for &h in hints {
                    assert!(
                        (0x40..=0x7e).contains(&h) || h == b'\n',
                        "ascii hint {h} out of range"
                    );
                }
            }
        }
    }

    #[test]
    fn directional_table_round_trips_both_directions() {
        let t = new_directional_table("k", "up_ascii_down_entropy", "").unwrap();
        assert_round_trips(&t.uplink);
        assert_round_trips(&t.downlink);
    }

    #[test]
    fn table_is_deterministic_per_key() {
        let a = new_directional_table("same-key", "prefer_entropy", "").unwrap();
        let b = new_directional_table("same-key", "prefer_entropy", "").unwrap();
        assert_eq!(a.uplink.decode_map, b.uplink.decode_map);
        assert_eq!(a.uplink.hint, b.uplink.hint);
        let c = new_directional_table("other-key", "prefer_entropy", "").unwrap();
        assert_ne!(a.uplink.decode_map, c.uplink.decode_map);
    }

    #[test]
    fn invalid_mode_is_rejected() {
        assert!(new_directional_table("k", "down_bogus", "").is_err());
        assert!(new_directional_table("k", "up_ascii_down_bogus", "").is_err());
    }
}
