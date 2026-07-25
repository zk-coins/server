//! Coin-history SMT — leaf/node hashing, empty-subtree ladder, and stateful tree (§1.7.6).

use std::collections::HashMap;
use std::sync::OnceLock;

use super::encoding::{hc, HcInput};
use super::error::SpecError;
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
    hc(TAG_COINHIST_LEAF, &[HcInput::SmallNumeric(state as u64)]).expect("state in {0,1,2}")
}

/// `H'_node(i, l, r) = Hc("CoinHist/Node", SmallNumeric(i), Digest(l), Digest(r))`.
///
/// Level 0 = leaf, level 256 = root. Levels `> 256` are rejected.
pub fn coinhist_node_hash(
    level: u32,
    left: HashDigest,
    right: HashDigest,
) -> Result<HashDigest, SpecError> {
    if level > 256 {
        return Err(SpecError::CoinHistLevelOutOfRange { level });
    }
    Ok(hc(
        TAG_COINHIST_NODE,
        &[
            HcInput::SmallNumeric(level as u64),
            HcInput::Digest(left),
            HcInput::Digest(right),
        ],
    )
    .expect("level ≤ 256 and digests are well-formed"))
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
            roots[i] = coinhist_node_hash(i as u32, roots[i - 1], roots[i - 1])
                .expect("level in 1..=256 by construction");
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
        cur = coinhist_node_hash(lvl, left, right).expect("level in 1..=256 by construction");
    }
    cur
}

/// A 256-level Merkle proof for one `coin_id` (either inclusion at its
/// current state, or non-inclusion when the state is `Absent`).
/// `siblings` is bottom-to-top: `siblings[0]` is the level-1 sibling
/// (leaf-adjacent), `siblings[255]` is the level-256 sibling (root-adjacent)
/// — same bottom-to-top convention as `coinhist_root_after_first_insert`
/// and the section 1.7.5 wire `inclusion_proof` layout.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CoinHistProof {
    pub state: CoinHistState,
    /// Always exactly 256 entries for a well-formed proof.
    pub siblings: Vec<HashDigest>,
}

impl CoinHistProof {
    /// Recompute the root from this proof and check it against `root`.
    pub fn verify(&self, coin_id: &[u8; 32], root: HashDigest) -> bool {
        if self.siblings.len() != 256 {
            return false;
        }
        let mut cur = coinhist_leaf_hash(self.state);
        for lvl in 1..=256u32 {
            let bit = key_bit(coin_id, lvl - 1);
            let sibling = self.siblings[(lvl - 1) as usize];
            let (l, r) = if bit { (sibling, cur) } else { (cur, sibling) };
            cur = coinhist_node_hash(lvl, l, r).expect("level in 1..=256 by construction");
        }
        cur == root
    }
}

/// Stateful per-account coin-history SMT (section 1.7.6, section 2.1 clauses 2(b)/8).
pub struct CoinHistTree {
    leaves: HashMap<[u8; 32], CoinHistState>,
}

impl CoinHistTree {
    pub fn new() -> Self {
        Self {
            leaves: HashMap::new(),
        }
    }

    /// `0 -> 1`. Errors if the coin is already admitted or already spent
    /// (an admit must start from `Absent`).
    pub fn admit(&mut self, coin_id: [u8; 32]) -> Result<(), SpecError> {
        match self.leaves.get(&coin_id) {
            None => {
                self.leaves.insert(coin_id, CoinHistState::Admitted);
                Ok(())
            }
            Some(CoinHistState::Admitted) => Err(SpecError::CoinAlreadyAdmitted { coin_id }),
            Some(CoinHistState::Spent) => Err(SpecError::CoinAlreadySpent { coin_id }),
            Some(CoinHistState::Absent) => {
                unreachable!(
                    "CoinHistState::Absent is never stored as a map value \
                     (it is the implicit not-present state)"
                )
            }
        }
    }

    /// `1 -> 2`. Errors if the coin was never admitted, or already spent.
    pub fn spend(&mut self, coin_id: [u8; 32]) -> Result<(), SpecError> {
        match self.leaves.get(&coin_id) {
            Some(CoinHistState::Admitted) => {
                self.leaves.insert(coin_id, CoinHistState::Spent);
                Ok(())
            }
            Some(CoinHistState::Spent) => Err(SpecError::CoinAlreadySpent { coin_id }),
            Some(CoinHistState::Absent) | None => Err(SpecError::CoinNotAdmitted { coin_id }),
        }
    }

    pub fn root(&self) -> HashDigest {
        let occupied: Vec<(&[u8; 32], CoinHistState)> =
            self.leaves.iter().map(|(k, &v)| (k, v)).collect();
        build_subtree(&occupied, 0)
    }

    /// Proof for `coin_id` at its CURRENT state (Absent/Admitted/Spent).
    pub fn prove(&self, coin_id: [u8; 32]) -> CoinHistProof {
        let occupied: Vec<(&[u8; 32], CoinHistState)> =
            self.leaves.iter().map(|(k, &v)| (k, v)).collect();
        let mut siblings = Vec::with_capacity(256);
        build_subtree_with_path(&occupied, 0, &coin_id, &mut siblings);
        let state = self
            .leaves
            .get(&coin_id)
            .copied()
            .unwrap_or(CoinHistState::Absent);
        CoinHistProof { state, siblings }
    }

    /// Non-inclusion proof: errors if `coin_id` is actually present
    /// (Admitted or Spent) — this function proves absence, not presence.
    pub fn non_inclusion(&self, coin_id: [u8; 32]) -> Result<CoinHistProof, SpecError> {
        let proof = self.prove(coin_id);
        if proof.state != CoinHistState::Absent {
            return Err(SpecError::CoinNotAbsent { coin_id });
        }
        Ok(proof)
    }
}

impl Default for CoinHistTree {
    fn default() -> Self {
        Self::new()
    }
}

/// `depth_from_root`: 0 at the root (about to decide bit 255), 256 at the
/// leaf (all bits decided). `H'_node` level = `256 - depth_from_root`.
fn build_subtree(occupied: &[(&[u8; 32], CoinHistState)], depth_from_root: u32) -> HashDigest {
    if occupied.is_empty() {
        return coinhist_empty_subtree_roots()[(256 - depth_from_root) as usize];
    }
    if depth_from_root == 256 {
        debug_assert_eq!(
            occupied.len(),
            1,
            "distinct keys can't collide at full depth"
        );
        return coinhist_leaf_hash(occupied[0].1);
    }
    let bit_index = 255 - depth_from_root;
    let mut left = Vec::new();
    let mut right = Vec::new();
    for &(k, s) in occupied {
        if key_bit(k, bit_index) {
            right.push((k, s));
        } else {
            left.push((k, s));
        }
    }
    let l = build_subtree(&left, depth_from_root + 1);
    let r = build_subtree(&right, depth_from_root + 1);
    coinhist_node_hash(256 - depth_from_root, l, r).expect("level in 1..=256 by construction")
}

/// Same recursion as `build_subtree`, but also appends the sibling along
/// the path to `target_key` into `path_out` (bottom-to-top order — pushes
/// happen while unwinding, so the deepest level's sibling is pushed first).
///
/// When the target's remaining path enters an empty subtree, the rest of the
/// siblings are filled with the precomputed empty-subtree constants so that
/// proofs always have exactly 256 entries (required by [`CoinHistProof::verify`]).
fn build_subtree_with_path(
    occupied: &[(&[u8; 32], CoinHistState)],
    depth_from_root: u32,
    target_key: &[u8; 32],
    path_out: &mut Vec<HashDigest>,
) -> HashDigest {
    if occupied.is_empty() {
        // Fill remaining empty-path siblings bottom-to-top: empty[0] .. empty[255-d].
        let empty = coinhist_empty_subtree_roots();
        for i in 0..(256 - depth_from_root) {
            path_out.push(empty[i as usize]);
        }
        return empty[(256 - depth_from_root) as usize];
    }
    if depth_from_root == 256 {
        return coinhist_leaf_hash(occupied[0].1);
    }
    let bit_index = 255 - depth_from_root;
    let mut left = Vec::new();
    let mut right = Vec::new();
    for &(k, s) in occupied {
        if key_bit(k, bit_index) {
            right.push((k, s));
        } else {
            left.push((k, s));
        }
    }
    let target_bit = key_bit(target_key, bit_index);
    if target_bit {
        let sibling = build_subtree(&left, depth_from_root + 1);
        let right_root = build_subtree_with_path(&right, depth_from_root + 1, target_key, path_out);
        path_out.push(sibling);
        coinhist_node_hash(256 - depth_from_root, sibling, right_root)
            .expect("level in 1..=256 by construction")
    } else {
        let left_root = build_subtree_with_path(&left, depth_from_root + 1, target_key, path_out);
        let sibling = build_subtree(&right, depth_from_root + 1);
        path_out.push(sibling);
        coinhist_node_hash(256 - depth_from_root, left_root, sibling)
            .expect("level in 1..=256 by construction")
    }
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

    fn coin_id(tag: u8) -> [u8; 32] {
        let mut id = [0u8; 32];
        id[0] = tag;
        id[31] = tag.wrapping_mul(3);
        id
    }

    #[test]
    fn admit_then_spend_transitions() {
        let mut tree = CoinHistTree::new();
        let id = coin_id(1);
        tree.admit(id).expect("admit");
        tree.spend(id).expect("spend");
        let proof = tree.prove(id);
        assert_eq!(proof.state, CoinHistState::Spent);
        assert!(proof.verify(&id, tree.root()));
    }

    #[test]
    fn spend_before_admit_is_rejected() {
        let mut tree = CoinHistTree::new();
        let id = coin_id(2);
        let err = tree.spend(id).expect_err("must reject");
        assert_eq!(err, SpecError::CoinNotAdmitted { coin_id: id });
    }

    #[test]
    fn non_inclusion_for_absent_coin() {
        // Fresh tree
        let tree = CoinHistTree::new();
        let id = coin_id(3);
        let proof = tree.non_inclusion(id).expect("absent");
        assert_eq!(proof.state, CoinHistState::Absent);
        assert!(proof.verify(&id, tree.root()));
        assert_eq!(tree.root(), coinhist_empty_root());

        // Tree with other coins admitted
        let mut tree = CoinHistTree::new();
        tree.admit(coin_id(10)).expect("admit other");
        tree.admit(coin_id(11)).expect("admit other");
        let proof = tree.non_inclusion(id).expect("absent");
        assert_eq!(proof.state, CoinHistState::Absent);
        assert!(proof.verify(&id, tree.root()));
    }

    #[test]
    fn non_inclusion_rejects_present_coin() {
        let mut tree = CoinHistTree::new();
        let id = coin_id(4);
        tree.admit(id).expect("admit");
        let err = tree.non_inclusion(id).expect_err("must reject");
        assert_eq!(err, SpecError::CoinNotAbsent { coin_id: id });
    }

    #[test]
    fn single_admit_matches_first_insert_helper() {
        let id = coin_id(5);
        let mut tree = CoinHistTree::new();
        tree.admit(id).expect("admit");
        assert_eq!(
            tree.root(),
            coinhist_root_after_first_insert(&id, CoinHistState::Admitted)
        );
    }

    #[test]
    fn tampered_proof_fails_verify() {
        let mut tree = CoinHistTree::new();
        let id = coin_id(6);
        tree.admit(id).expect("admit");
        let root = tree.root();
        let mut proof = tree.prove(id);
        assert!(proof.verify(&id, root));

        // Flip claimed state
        proof.state = CoinHistState::Spent;
        assert!(!proof.verify(&id, root));

        // Restore state, flip a sibling
        let mut proof = tree.prove(id);
        use plonky2::field::types::Field;
        proof.siblings[0].elements[0] += zkcoins_program::F::ONE;
        assert!(!proof.verify(&id, root));
    }

    #[test]
    fn double_admit_rejected() {
        let mut tree = CoinHistTree::new();
        let id = coin_id(7);
        tree.admit(id).expect("admit");
        assert_eq!(
            tree.admit(id).expect_err("second admit"),
            SpecError::CoinAlreadyAdmitted { coin_id: id }
        );
    }

    #[test]
    fn double_spend_rejected() {
        let mut tree = CoinHistTree::new();
        let id = coin_id(8);
        tree.admit(id).expect("admit");
        tree.spend(id).expect("spend");
        assert_eq!(
            tree.spend(id).expect_err("second spend"),
            SpecError::CoinAlreadySpent { coin_id: id }
        );
    }

    #[test]
    fn coinhist_node_hash_rejects_level_above_256() {
        let left = coinhist_leaf_hash(CoinHistState::Absent);
        let right = coinhist_leaf_hash(CoinHistState::Admitted);
        let err = coinhist_node_hash(257, left, right).expect_err("level 257");
        assert_eq!(err, SpecError::CoinHistLevelOutOfRange { level: 257 });
        // Boundary still accepted.
        assert!(coinhist_node_hash(256, left, right).is_ok());
        assert!(coinhist_node_hash(0, left, right).is_ok());
    }

    #[test]
    fn admit_on_spent_coin_returns_already_spent() {
        let mut tree = CoinHistTree::new();
        let id = coin_id(9);
        tree.admit(id).expect("admit");
        tree.spend(id).expect("spend");
        assert_eq!(
            tree.admit(id).expect_err("re-admit after spend"),
            SpecError::CoinAlreadySpent { coin_id: id }
        );
    }
}
