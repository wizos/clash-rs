//! 4×4 Sudoku grids and the hint-position combinatorics the table builder uses.
//!
//! A *grid* is a solved 4×4 Latin square with 2×2 box constraints; there are
//! exactly 288 of them. The obfuscation table assigns one grid to each of the
//! 256 byte values (after a key-seeded shuffle) and encodes a byte as four
//! "hints" — cell `(value, position)` pairs — chosen so the four pairs uniquely
//! identify the grid among all 288.

/// A solved 4×4 grid in row-major order; cells hold values `1..=4`.
pub(crate) type Grid = [u8; 16];

/// Generate all 288 valid 4×4 Sudoku grids via backtracking, in the same order
/// as the reference `GenerateAllGrids` (depth-first, trying `1..=4` per cell).
pub(crate) fn all_grids() -> Vec<Grid> {
    let mut grids = Vec::with_capacity(288);
    let mut g: Grid = [0; 16];
    backtrack(0, &mut g, &mut grids);
    grids
}

fn backtrack(idx: usize, g: &mut Grid, grids: &mut Vec<Grid>) {
    if idx == 16 {
        grids.push(*g);
        return;
    }
    let row = idx / 4;
    let col = idx % 4;
    let br = (row / 2) * 2;
    let bc = (col / 2) * 2;
    for num in 1u8..=4 {
        let mut valid = true;
        for i in 0..4 {
            if g[row * 4 + i] == num || g[i * 4 + col] == num {
                valid = false;
                break;
            }
        }
        if valid {
            'box_check: for r in 0..2 {
                for c in 0..2 {
                    if g[(br + r) * 4 + (bc + c)] == num {
                        valid = false;
                        break 'box_check;
                    }
                }
            }
        }
        if valid {
            g[idx] = num;
            backtrack(idx + 1, g, grids);
            g[idx] = 0;
        }
    }
}

/// One hint: a grid value `1..=4` at a cell position `0..16`.
#[derive(Clone, Copy)]
pub(crate) struct HintPart {
    pub(crate) val: u8,
    pub(crate) pos: u8,
}

/// All `C(16,4) = 1820` ascending 4-position combinations, in the reference
/// order (nested `a<b<c<d` loops).
pub(crate) fn hint_positions() -> Vec<[u8; 4]> {
    let mut positions = Vec::with_capacity(1820);
    for a in 0..13u8 {
        for b in (a + 1)..14 {
            for c in (b + 1)..15 {
                for d in (c + 1)..16 {
                    positions.push([a, b, c, d]);
                }
            }
        }
    }
    positions
}

/// Whether exactly one grid matches all four `(val, pos)` hints — the condition
/// for a hint set to be a usable, unambiguous encoding.
pub(crate) fn has_unique_match(grids: &[Grid], parts: &[HintPart; 4]) -> bool {
    let mut count = 0;
    for g in grids {
        let mut matched = true;
        for p in parts {
            if g[p.pos as usize] != p.val {
                matched = false;
                break;
            }
        }
        if matched {
            count += 1;
            if count > 1 {
                return false;
            }
        }
    }
    count == 1
}
