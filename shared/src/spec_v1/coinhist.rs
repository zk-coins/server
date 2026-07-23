//! Coin-history SMT — leaf/node hashing + empty-subtree ladder (§1.7.6).
//!
//! Full path-insertion / sibling-storage machinery for arbitrary trees is out
//! of scope for P1-A. The empty-tree first-insert helper is provided for
//! test-vector generation (every sibling is then a precomputed empty subtree).

use std::sync::OnceLock;

use super::encoding::{hc, HcInput};
use super::tags::{TAG_COINHIST_LEAF, TAG_COINHIST_NODE};
use zkcoins_program::hash::HashDigest;

/// Leaf state of a coin-history SMT entry.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u8)]
pub enum CoinHistState {
    Absent = 0,
    Admitted = 1,
    Spent = 2,
}

/// `H'_leaf(s) = Hc("CoinHist/Leaf", SmallNumeric(s))`.
pub fn coinhist_leaf_hash(state: CoinHistState) -> HashDigest {
    hc(
        TAG_COINHIST_LEAF,
        &[HcInput::SmallNumeric(state as u64)],
    )
    .expect("state in {0,1,2}")
}

/// `H'_node(i, l, r) = Hc("CoinHist/Node", SmallNumeric(i), Digest(l), Digest(r))`.
///
/// Level 0 = leaf, level 256 = root.
pub fn coinhist_node_hash(level: u32, left: HashDigest, right: HashDigest) -> HashDigest {
    hc(
        TAG_COINHIST_NODE,
        &[
            HcInput::SmallNumeric(level as u64),
            HcInput::Digest(left),
            HcInput::Digest(right),
        ],
    )
    .expect("level ≤ 256")
}

/// The 257 empty-subtree constants:
/// `E'_0 = coinhist_leaf_hash(Absent)`;
/// `E'_i = coinhist_node_hash(i, E'_{i-1}, E'_{i-1})` for `i in 1..=256`.
pub fn coinhist_empty_subtree_roots() -> &'static [HashDigest; 257] {
    static ROOTS: OnceLock<[HashDigest; 257]> = OnceLock::new();
    ROOTS.get_or_init(|| {
        let mut roots = [zkcoins_program::hash::ZERO_HASH; 257];
        roots[0] = coinhist_leaf_hash(CoinHistState::Absent);
        for i in 1..=256 {
            roots[i] = coinhist_node_hash(i as u32, roots[i - 1], roots[i - 1]);
        }
        roots
    })
}

/// Empty coin-history root `E'_256`.
pub fn coinhist_empty_root() -> HashDigest {
    coinhist_empty_subtree_roots()[256]
}

/// Bit `b` of a 32-byte big-endian key: bit 255 = MSB of byte 0, bit 0 = LSB of byte 31.
fn key_bit(key_be: &[u8; 32], b: u32) -> bool {
    debug_assert!(b < 256);
    let byte_index = (255 - b) / 8;
    let bit_in_byte = b % 8; // 0 = LSB of that byte
    (key_be[byte_index as usize] >> bit_in_byte) & 1 == 1
}

/// Coin-history root after inserting **exactly one** leaf into an otherwise
/// empty tree. Every sibling along the path is the precomputed empty-subtree
/// constant — no general sibling storage required.
///
/// Intended for test / vector generation (empty-tree genesis insert). Not a
/// general multi-insert API.
pub fn coinhist_root_after_first_insert(key_be: &[u8; 32], state: CoinHistState) -> HashDigest {
    let empty = coinhist_empty_subtree_roots();
    let mut cur = coinhist_leaf_hash(state);
    for lvl in 1..=256u32 {
        let bit = key_bit(key_be, lvl - 1);
        let sibling = empty[(lvl - 1) as usize];
        let (left, right) = if bit {
            // bit 1 ⇒ child is RIGHT, sibling is LEFT
            (sibling, cur)
        } else {
            // bit 0 ⇒ child is LEFT, sibling is RIGHT
            (cur, sibling)
        };
        cur = coinhist_node_hash(lvl, left, right);
    }
    cur
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn empty_root_deterministic_and_base() {
        assert_eq!(coinhist_empty_root(), coinhist_empty_root());
        assert_eq!(
            coinhist_empty_subtree_roots()[0],
            coinhist_leaf_hash(CoinHistState::Absent)
        );
        assert_eq!(coinhist_empty_root(), coinhist_empty_subtree_roots()[256]);
    }

    #[test]
    fn three_leaf_states_distinct() {
        let a = coinhist_leaf_hash(CoinHistState::Absent);
        let b = coinhist_leaf_hash(CoinHistState::Admitted);
        let c = coinhist_leaf_hash(CoinHistState::Spent);
        assert_ne!(a, b);
        assert_ne!(b, c);
        assert_ne!(a, c);
    }

    #[test]
    fn first_insert_sensitive_to_key_and_state() {
        let k1 = [0u8; 32];
        let mut k2 = [0u8; 32];
        k2[31] = 1;
        let r1 = coinhist_root_after_first_insert(&k1, CoinHistState::Admitted);
        let r2 = coinhist_root_after_first_insert(&k2, CoinHistState::Admitted);
        assert_ne!(r1, r2);
        let r3 = coinhist_root_after_first_insert(&k1, CoinHistState::Spent);
        assert_ne!(r1, r3);
    }

    #[test]
    fn key_bit_msb_lsb() {
        let mut key = [0u8; 32];
        key[0] = 0x80; // bit 255 set
        assert!(key_bit(&key, 255));
        assert!(!key_bit(&key, 254));
        key = [0u8; 32];
        key[31] = 0x01; // bit 0 set
        assert!(key_bit(&key, 0));
        assert!(!key_bit(&key, 1));
    }
}
