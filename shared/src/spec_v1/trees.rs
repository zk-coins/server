//! Poseidon Merkle tree family for `ocr` / `inr` (§1.7.5).

use super::encoding::{hc, HcInput};
use super::tags::{
    TAG_COINS_ROOT_LEAF, TAG_COINS_ROOT_NODE, TAG_NULLIFIERS_ROOT_LEAF, TAG_NULLIFIERS_ROOT_NODE,
};
use zkcoins_program::hash::{HashDigest, ZERO_HASH};

/// Which Merkle domain (`CoinsRoot` or `NullifiersRoot`).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum TreeKind {
    CoinsRoot,
    NullifiersRoot,
}

impl TreeKind {
    fn leaf_tag(self) -> &'static str {
        match self {
            TreeKind::CoinsRoot => TAG_COINS_ROOT_LEAF,
            TreeKind::NullifiersRoot => TAG_NULLIFIERS_ROOT_LEAF,
        }
    }

    fn node_tag(self) -> &'static str {
        match self {
            TreeKind::CoinsRoot => TAG_COINS_ROOT_NODE,
            TreeKind::NullifiersRoot => TAG_NULLIFIERS_ROOT_NODE,
        }
    }
}

/// `Lᵢ = Hc("<T>/Leaf", Digest(v))`.
pub fn leaf_hash(kind: TreeKind, v: HashDigest) -> HashDigest {
    hc(kind.leaf_tag(), &[HcInput::Digest(v)]).expect("digest input is fixed-width")
}

/// Empty-leaf padding: `L_⊥ = Hc("<T>/Leaf", Digest(ZERO_HASH))` — the
/// all-zero 256-bit digest input (`0₂₅₆`), **not** the small-numeric `0`.
pub fn empty_leaf_hash(kind: TreeKind) -> HashDigest {
    leaf_hash(kind, ZERO_HASH)
}

/// `P = Hc("<T>/Node", Digest(l), Digest(r))`.
pub fn node_hash(kind: TreeKind, l: HashDigest, r: HashDigest) -> HashDigest {
    hc(
        kind.node_tag(),
        &[HcInput::Digest(l), HcInput::Digest(r)],
    )
    .expect("digest inputs are fixed-width")
}

/// Poseidon Merkle root over `leaves` (§1.7.5).
///
/// - empty list → `empty_leaf_hash(kind)`
/// - else leaf-hash each entry, pad with `empty_leaf_hash` to the next power
///   of two, then pairwise `node_hash` until one remains.
pub fn merkle_root(kind: TreeKind, leaves: &[HashDigest]) -> HashDigest {
    if leaves.is_empty() {
        return empty_leaf_hash(kind);
    }
    let pad = empty_leaf_hash(kind);
    let mut level: Vec<HashDigest> = leaves.iter().copied().map(|v| leaf_hash(kind, v)).collect();
    let target = level.len().next_power_of_two();
    level.resize(target, pad);
    while level.len() > 1 {
        let mut next = Vec::with_capacity(level.len() / 2);
        for pair in level.chunks_exact(2) {
            next.push(node_hash(kind, pair[0], pair[1]));
        }
        level = next;
    }
    level[0]
}

#[cfg(test)]
mod tests {
    use super::*;
    use plonky2::field::types::Field;

    #[test]
    fn empty_root_is_empty_leaf() {
        assert_eq!(
            merkle_root(TreeKind::CoinsRoot, &[]),
            empty_leaf_hash(TreeKind::CoinsRoot)
        );
        assert_eq!(
            merkle_root(TreeKind::NullifiersRoot, &[]),
            empty_leaf_hash(TreeKind::NullifiersRoot)
        );
        assert_ne!(
            empty_leaf_hash(TreeKind::CoinsRoot),
            empty_leaf_hash(TreeKind::NullifiersRoot)
        );
    }

    #[test]
    fn single_leaf_is_leaf_hash() {
        let v = ZERO_HASH;
        // one leaf, already power of two — root is leaf_hash only (no node)
        assert_eq!(
            merkle_root(TreeKind::CoinsRoot, &[v]),
            leaf_hash(TreeKind::CoinsRoot, v)
        );
    }

    #[test]
    fn two_leaves_combine_once() {
        let a = leaf_hash(TreeKind::CoinsRoot, ZERO_HASH);
        let mut b_d = ZERO_HASH;
        b_d.elements[0] = zkcoins_program::F::from_canonical_u64(1);
        let b = leaf_hash(TreeKind::CoinsRoot, b_d);
        let root = merkle_root(TreeKind::CoinsRoot, &[ZERO_HASH, b_d]);
        assert_eq!(root, node_hash(TreeKind::CoinsRoot, a, b));
    }
}
