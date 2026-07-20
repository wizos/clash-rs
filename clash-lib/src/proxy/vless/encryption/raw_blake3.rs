//! BLAKE3 derive-key context hashing for arbitrary bytes.
//!
//! The public Rust API intentionally accepts UTF-8 contexts, while the Go API
//! accepts a string that may contain arbitrary bytes. VLESS encryption uses
//! random protocol records as contexts, so it needs the raw-byte form exposed
//! by BLAKE3's C API as `blake3_hasher_init_derive_key_raw`.

use blake3::{Hasher, hazmat::HasherExt};

const BLOCK_LEN: usize = 64;
const CHUNK_LEN: usize = 1024;
const CHUNK_START: u8 = 1 << 0;
const CHUNK_END: u8 = 1 << 1;
const PARENT: u8 = 1 << 2;
const ROOT: u8 = 1 << 3;
const DERIVE_KEY_CONTEXT: u8 = 1 << 5;

const IV: [u32; 8] = [
    0x6A09E667, 0xBB67AE85, 0x3C6EF372, 0xA54FF53A, 0x510E527F, 0x9B05688C,
    0x1F83D9AB, 0x5BE0CD19,
];

const MSG_SCHEDULE: [[usize; 16]; 7] = [
    [0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15],
    [2, 6, 3, 10, 7, 0, 4, 13, 1, 11, 12, 5, 9, 14, 15, 8],
    [3, 4, 10, 12, 13, 2, 7, 14, 6, 5, 9, 0, 11, 15, 8, 1],
    [10, 7, 12, 9, 14, 3, 13, 15, 4, 0, 11, 2, 5, 8, 1, 6],
    [12, 13, 9, 11, 15, 10, 14, 8, 7, 2, 5, 3, 0, 1, 6, 4],
    [9, 14, 11, 5, 8, 12, 15, 1, 13, 3, 0, 10, 2, 6, 4, 7],
    [11, 15, 5, 0, 1, 9, 8, 6, 14, 10, 2, 12, 3, 4, 7, 13],
];

#[derive(Clone)]
struct Output {
    cv: [u32; 8],
    block: [u8; BLOCK_LEN],
    block_len: u8,
    counter: u64,
    flags: u8,
}

impl Output {
    fn chaining_value(&self) -> [u8; 32] {
        let state = compress(
            &self.cv,
            &self.block,
            self.block_len,
            self.counter,
            self.flags,
        );
        words_to_bytes_32(&state[..8])
    }

    fn root_hash(&self) -> [u8; 32] {
        let state =
            compress(&self.cv, &self.block, self.block_len, 0, self.flags | ROOT);
        words_to_bytes_32(&state[..8])
    }
}

/// Equivalent to BLAKE3's raw derive-key constructor followed by hashing the
/// key material. This is safe for random binary contexts and byte-for-byte
/// compatible with Go's `blake3.DeriveKey(out, string(context), material)`.
pub(super) fn derive_key(context: &[u8], key_material: &[u8]) -> [u8; 32] {
    let context_key = context_output(context).root_hash();
    let mut hasher = Hasher::new_from_context_key(&context_key);
    hasher.update(key_material);
    *hasher.finalize().as_bytes()
}

fn context_output(input: &[u8]) -> Output {
    let mut nodes: Vec<Output> = if input.is_empty() {
        vec![chunk_output(&[], 0)]
    } else {
        input
            .chunks(CHUNK_LEN)
            .enumerate()
            .map(|(counter, chunk)| chunk_output(chunk, counter as u64))
            .collect()
    };

    while nodes.len() > 1 {
        let mut parents = Vec::with_capacity(nodes.len().div_ceil(2));
        let mut iter = nodes.into_iter();
        while let Some(left) = iter.next() {
            if let Some(right) = iter.next() {
                parents.push(parent_output(
                    left.chaining_value(),
                    right.chaining_value(),
                ));
            } else {
                parents.push(left);
            }
        }
        nodes = parents;
    }
    nodes.pop().expect("at least one BLAKE3 chunk")
}

fn chunk_output(chunk: &[u8], counter: u64) -> Output {
    debug_assert!(chunk.len() <= CHUNK_LEN);
    let mut cv = IV;
    let block_count = chunk.len().div_ceil(BLOCK_LEN).max(1);
    for block_index in 0..block_count {
        let start = block_index * BLOCK_LEN;
        let end = chunk.len().min(start + BLOCK_LEN);
        let mut block = [0u8; BLOCK_LEN];
        block[..end - start].copy_from_slice(&chunk[start..end]);
        let mut flags = DERIVE_KEY_CONTEXT;
        if block_index == 0 {
            flags |= CHUNK_START;
        }
        if block_index + 1 == block_count {
            flags |= CHUNK_END;
            return Output {
                cv,
                block,
                block_len: (end - start) as u8,
                counter,
                flags,
            };
        }
        let state = compress(&cv, &block, BLOCK_LEN as u8, counter, flags);
        cv.copy_from_slice(&state[..8]);
    }
    unreachable!("block_count is always non-zero")
}

fn parent_output(left: [u8; 32], right: [u8; 32]) -> Output {
    let mut block = [0u8; BLOCK_LEN];
    block[..32].copy_from_slice(&left);
    block[32..].copy_from_slice(&right);
    Output {
        cv: IV,
        block,
        block_len: BLOCK_LEN as u8,
        counter: 0,
        flags: DERIVE_KEY_CONTEXT | PARENT,
    }
}

fn compress(
    cv: &[u32; 8],
    block: &[u8; BLOCK_LEN],
    block_len: u8,
    counter: u64,
    flags: u8,
) -> [u32; 16] {
    let mut message = [0u32; 16];
    for (word, bytes) in message.iter_mut().zip(block.chunks_exact(4)) {
        *word = u32::from_le_bytes(bytes.try_into().expect("four-byte word"));
    }
    let mut state = [
        cv[0],
        cv[1],
        cv[2],
        cv[3],
        cv[4],
        cv[5],
        cv[6],
        cv[7],
        IV[0],
        IV[1],
        IV[2],
        IV[3],
        counter as u32,
        (counter >> 32) as u32,
        block_len as u32,
        flags as u32,
    ];
    for schedule in MSG_SCHEDULE {
        round(&mut state, &message, &schedule);
    }
    for index in 0..8 {
        state[index] ^= state[index + 8];
        state[index + 8] ^= cv[index];
    }
    state
}

fn round(state: &mut [u32; 16], message: &[u32; 16], schedule: &[usize; 16]) {
    g(
        state,
        0,
        4,
        8,
        12,
        message[schedule[0]],
        message[schedule[1]],
    );
    g(
        state,
        1,
        5,
        9,
        13,
        message[schedule[2]],
        message[schedule[3]],
    );
    g(
        state,
        2,
        6,
        10,
        14,
        message[schedule[4]],
        message[schedule[5]],
    );
    g(
        state,
        3,
        7,
        11,
        15,
        message[schedule[6]],
        message[schedule[7]],
    );
    g(
        state,
        0,
        5,
        10,
        15,
        message[schedule[8]],
        message[schedule[9]],
    );
    g(
        state,
        1,
        6,
        11,
        12,
        message[schedule[10]],
        message[schedule[11]],
    );
    g(
        state,
        2,
        7,
        8,
        13,
        message[schedule[12]],
        message[schedule[13]],
    );
    g(
        state,
        3,
        4,
        9,
        14,
        message[schedule[14]],
        message[schedule[15]],
    );
}

#[allow(clippy::too_many_arguments)]
fn g(state: &mut [u32; 16], a: usize, b: usize, c: usize, d: usize, x: u32, y: u32) {
    state[a] = state[a].wrapping_add(state[b]).wrapping_add(x);
    state[d] = (state[d] ^ state[a]).rotate_right(16);
    state[c] = state[c].wrapping_add(state[d]);
    state[b] = (state[b] ^ state[c]).rotate_right(12);
    state[a] = state[a].wrapping_add(state[b]).wrapping_add(y);
    state[d] = (state[d] ^ state[a]).rotate_right(8);
    state[c] = state[c].wrapping_add(state[d]);
    state[b] = (state[b] ^ state[c]).rotate_right(7);
}

fn words_to_bytes_32(words: &[u32]) -> [u8; 32] {
    let mut bytes = [0u8; 32];
    for (word, output) in words.iter().zip(bytes.chunks_exact_mut(4)) {
        output.copy_from_slice(&word.to_le_bytes());
    }
    bytes
}

#[cfg(test)]
mod tests {
    use super::derive_key;

    #[test]
    fn utf8_contexts_match_public_blake3_api_across_tree_boundaries() {
        let contexts = [
            String::new(),
            "VLESS".to_owned(),
            "中文 context".to_owned(),
            "x".repeat(1023),
            "x".repeat(1024),
            "x".repeat(1025),
            "x".repeat(4097),
        ];
        for context in contexts {
            assert_eq!(
                derive_key(context.as_bytes(), b"key material"),
                blake3::derive_key(&context, b"key material"),
            );
        }
    }

    #[test]
    fn invalid_utf8_context_matches_mihomo_go_vector() {
        let context = [0x00, 0x7f, 0x80, 0xff, 0xc3, 0x28];
        assert_eq!(
            hex::encode(derive_key(&context, b"VLESS key material")),
            "6ca5b032b4435f2f97aaea91d6f8d40d13c2aba606bff4c702e922f969ae6ce8",
        );
    }
}
