//! Random-number generators the Sudoku obfuscation layer depends on.
//!
//! Two distinct generators are needed for byte-exact interop with the reference
//! implementation:
//!
//! 1. [`GoRand`] — a faithful port of Go's `math/rand` additive
//!    lagged-Fibonacci source. The table builder seeds it from
//!    `SHA256(key)[:8]` and shuffles the 288 valid 4×4 grids with it, so the
//!    grid → byte assignment (and therefore the whole obfuscation table) only
//!    matches the server if this generator reproduces Go's output exactly. Only
//!    the `Seed` / `Uint64` / `Int63` core plus `Shuffle` (via `int31n`, the
//!    only branch reachable for `n = 288`) are ported.
//! 2. [`SudokuRand`] — the lightweight xorshift+ generator used at runtime to
//!    pick per-byte grid encodings, hint permutations and padding. Its output
//!    is not protocol-critical (the decoder sorts the four hint bytes and skips
//!    padding), but it is ported faithfully so a recorded uplink stream is
//!    bit-identical to the Go client's.

use super::rng_cooked::RNG_COOKED;

const RNG_LEN: usize = 607;
const RNG_TAP: usize = 273;
const INT32_MAX: i32 = i32::MAX;
const RNG_MASK: u64 = (1 << 63) - 1;

/// `x[n+1] = 48271 * x[n] mod (2**31 - 1)` (Go's `seedrand`).
fn seedrand(mut x: i32) -> i32 {
    const A: i32 = 48271;
    const Q: i32 = 44488;
    const R: i32 = 3399;
    let hi = x / Q;
    let lo = x % Q;
    x = A * lo - R * hi;
    if x < 0 {
        x += INT32_MAX;
    }
    x
}

/// A faithful port of Go's `math/rand` additive lagged-Fibonacci `rngSource`
/// wrapped with the `Rand` helpers the Sudoku table builder uses.
pub(crate) struct GoRand {
    tap: usize,
    feed: usize,
    vec: [i64; RNG_LEN],
}

impl GoRand {
    /// Equivalent to `rand.New(rand.NewSource(seed))`.
    pub(crate) fn new(seed: i64) -> Self {
        let mut rng = GoRand {
            tap: 0,
            feed: RNG_LEN - RNG_TAP,
            vec: [0; RNG_LEN],
        };
        rng.seed(seed);
        rng
    }

    fn seed(&mut self, mut seed: i64) {
        self.tap = 0;
        self.feed = RNG_LEN - RNG_TAP;

        seed %= INT32_MAX as i64;
        if seed < 0 {
            seed += INT32_MAX as i64;
        }
        if seed == 0 {
            seed = 89482311;
        }

        let mut x = seed as i32;
        let mut i: i32 = -20;
        while i < RNG_LEN as i32 {
            x = seedrand(x);
            if i >= 0 {
                let mut u = (x as i64) << 40;
                x = seedrand(x);
                u ^= (x as i64) << 20;
                x = seedrand(x);
                u ^= x as i64;
                u ^= RNG_COOKED[i as usize];
                self.vec[i as usize] = u;
            }
            i += 1;
        }
    }

    fn uint64(&mut self) -> u64 {
        if self.tap == 0 {
            self.tap = RNG_LEN;
        }
        self.tap -= 1;
        if self.feed == 0 {
            self.feed = RNG_LEN;
        }
        self.feed -= 1;
        let x = self.vec[self.feed].wrapping_add(self.vec[self.tap]);
        self.vec[self.feed] = x;
        x as u64
    }

    fn int63(&mut self) -> i64 {
        (self.uint64() & RNG_MASK) as i64
    }

    /// `Rand.Uint32` = `uint32(Int63() >> 31)`.
    fn uint32(&mut self) -> u32 {
        (self.int63() >> 31) as u32
    }

    /// `Rand.int31n` (Lemire-style rejection). Used by `Shuffle` for `n` that
    /// fit in an `i32`, which is always the case for the 288-grid shuffle.
    fn int31n(&mut self, n: i32) -> i32 {
        let nn = n as u32;
        let mut v = self.uint32();
        let mut prod = (v as u64) * (nn as u64);
        let mut low = prod as u32;
        if low < nn {
            let thresh = nn.wrapping_neg() % nn;
            while low < thresh {
                v = self.uint32();
                prod = (v as u64) * (nn as u64);
                low = prod as u32;
            }
        }
        (prod >> 32) as i32
    }

    /// Faithful port of `Rand.Shuffle` for `n` within `i32` range (Fisher-Yates
    /// using `int31n`). The `n > 1<<31-1` branch is unreachable here.
    pub(crate) fn shuffle(&mut self, n: usize, mut swap: impl FnMut(usize, usize)) {
        let mut i = n as i32 - 1;
        while i > 0 {
            let j = self.int31n(i + 1);
            swap(i as usize, j as usize);
            i -= 1;
        }
    }
}

/// The runtime xorshift+ generator (`sudokuRand`) used to pick grid encodings,
/// hint permutations and padding bytes. Not protocol-critical, but ported so a
/// captured stream is byte-identical to the Go client's.
pub(crate) struct SudokuRand {
    state: u64,
    cached: u32,
    have_cached: bool,
}

impl SudokuRand {
    pub(crate) fn new(seed: i64) -> Self {
        let mut state = seed as u64;
        if state == 0 {
            state = 0x9e37_79b9_7f4a_7c15;
        }
        SudokuRand {
            state,
            cached: 0,
            have_cached: false,
        }
    }

    /// Seed from the OS RNG, matching `newSeededRand`.
    pub(crate) fn from_os() -> Self {
        let mut b = [0u8; 8];
        getrandom::fill(&mut b).expect("sudoku: system RNG unavailable");
        Self::new(i64::from_be_bytes(b))
    }

    pub(crate) fn uint64(&mut self) -> u64 {
        self.have_cached = false;
        let mut x = self.state;
        x ^= x >> 12;
        x ^= x << 25;
        x ^= x >> 27;
        self.state = x;
        x.wrapping_mul(0x2545_f491_4f6c_dd1d)
    }

    pub(crate) fn uint32(&mut self) -> u32 {
        if self.have_cached {
            self.have_cached = false;
            return self.cached;
        }
        let v = self.uint64();
        self.cached = v as u32;
        self.have_cached = true;
        (v >> 32) as u32
    }

    /// `Intn` via the fixed-point multiply-shift used by the reference code.
    pub(crate) fn intn(&mut self, n: usize) -> usize {
        if n <= 1 {
            return 0;
        }
        let u = self.uint32() as u64;
        ((u * n as u64) >> 32) as usize
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn go_rand_int63_matches_reference_seed_one() {
        // Golden value: Go's `rand.New(rand.NewSource(1)).Int63()` is a fixed
        // constant; reproducing it anchors the lagged-Fibonacci port to Go.
        let mut r = GoRand::new(1);
        assert_eq!(r.int63(), 5577006791947779410);
    }

    #[test]
    fn go_rand_is_deterministic_for_a_seed() {
        let order_a = {
            let mut r = GoRand::new(0x0123_4567_89ab_cdef);
            let mut v = (0..16).collect::<Vec<usize>>();
            r.shuffle(v.len(), |i, j| v.swap(i, j));
            v
        };
        let order_b = {
            let mut r = GoRand::new(0x0123_4567_89ab_cdef);
            let mut v = (0..16).collect::<Vec<usize>>();
            r.shuffle(v.len(), |i, j| v.swap(i, j));
            v
        };
        assert_eq!(order_a, order_b);
        // A shuffle of distinct elements stays a permutation.
        let mut sorted = order_a.clone();
        sorted.sort_unstable();
        assert_eq!(sorted, (0..16).collect::<Vec<usize>>());
    }

    #[test]
    fn sudoku_rand_intn_in_range_and_deterministic() {
        let mut r1 = SudokuRand::new(42);
        let mut r2 = SudokuRand::new(42);
        for _ in 0..1000 {
            let a = r1.intn(288);
            let b = r2.intn(288);
            assert_eq!(a, b);
            assert!(a < 288);
        }
        assert_eq!(SudokuRand::new(7).intn(1), 0);
        assert_eq!(SudokuRand::new(7).intn(0), 0);
    }
}
