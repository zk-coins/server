#[cfg(test)]
use bitcoin::bip32::{ChildNumber, Xpriv, Xpub};
use bitcoin::hashes::Hash;
#[cfg(test)]
use bitcoin::secp256k1::PublicKey;
use serde::{Deserialize, Serialize};
use shared::commitment::Commitment;
#[cfg(test)]
use shared::SECP256K1;
use sqlx::PgPool;
use std::collections::HashMap;
use zkcoins_program::circuit::main::MMR_PROOF_PATH_LEN;
use zkcoins_program::hash::{digest_from_bytes, hash_concat, HashDigest, ZERO_HASH};
use zkcoins_program::merkle::merkle_mountain_range::MerkleMountainRange;
#[cfg(test)]
use zkcoins_program::merkle::merkle_mountain_range::MMRProof;
use zkcoins_program::merkle::sparse_merkle_tree::SparseMerkleTree;
#[cfg(test)]
use zkcoins_program::merkle::sparse_merkle_tree::InclusionProof;

use crate::db;

/// Defensive upper bound on the [`derive_num_pubkeys_from_smt`] loop.
///
/// The MVP faucet bumps `num_pubkeys` once per `/api/mint`, a feature-
/// gated low-frequency endpoint. One million successful mints is several
/// orders of magnitude above the deployment envelope (closed test
/// environment, hand-driven mints), so a loop that exceeds the bound is
/// a structural bug — either the SMT was corrupted to contain millions
/// of synthetic minting pubkeys, or the caller passed an Xpriv that
/// shadows another wallet's branch. Panic rather than return a poisoned
/// `u32`: the safe response to a state we cannot reason about is to
/// stop, not to keep minting.
#[cfg(test)]
const DERIVE_NUM_PUBKEYS_LOOP_BOUND: u32 = 1_000_000;

/// Derive the minting account's `num_pubkeys` from SMT membership.
///
/// The faucet generates a fresh BIP-32 child pubkey for each mint
/// (`pk_n = generate_public_key(xpriv, n)`) and the scanner inserts
/// `key = sha256(pk_n.serialize())` into the SMT once the on-chain
/// inscription lands. The count of successful mints is therefore the
/// length of the prefix `pk_0, pk_1, …` whose keys are all present in
/// the SMT — equivalently, the smallest `n` whose key is absent.
///
/// Walks `n = 0, 1, 2, …`, deriving each pubkey and checking SMT
/// membership via [`SparseMerkleTree::get`] (the cheapest membership
/// primitive — O(1) `HashMap::get` on the leaf table, no proof
/// reconstruction). Returns the first miss.
///
/// Replaces the pre-Phase-D `minting_meta.num_pubkeys` counter as the
/// single source of truth: the SMT is already authoritative for "which
/// minting commitments landed on-chain" (the scanner is the only writer
/// and `state.update`'s `smt.insert` is idempotent on same key + same
/// value), so collapsing the counter into it removes the desync class
/// documented in zk-coins/node#89 by construction. The startup
/// invariant check that compared the two values is now a tautology and
/// has been removed.
///
/// **Loop bound.** Capped at [`DERIVE_NUM_PUBKEYS_LOOP_BOUND`]; an
/// overrun panics. See the constant's docs for the rationale.
#[cfg(test)]
pub(crate) fn derive_num_pubkeys_from_smt(xpriv: &Xpriv, smt: &SparseMerkleTree) -> u32 {
    derive_num_pubkeys_from_smt_with_bound(xpriv, smt, DERIVE_NUM_PUBKEYS_LOOP_BOUND)
}

/// Bound-parametrised inner of [`derive_num_pubkeys_from_smt`].
///
/// Exposed at `pub(crate)` so the test suite can exercise the loop-
/// bound panic branch with a tiny bound (millions of real BIP-32
/// derivations + Poseidon SMT inserts is several minutes of wall time;
/// the bound branch is the same regardless of the constant). Production
/// callers MUST use the wrapper above with [`DERIVE_NUM_PUBKEYS_LOOP_BOUND`].
#[cfg(test)]
pub(crate) fn derive_num_pubkeys_from_smt_with_bound(
    xpriv: &Xpriv,
    smt: &SparseMerkleTree,
    bound: u32,
) -> u32 {
    let xpub = Xpub::from_priv(&SECP256K1, xpriv);
    let mut n: u32 = 0;
    loop {
        let pk: PublicKey = xpub
            .derive_pub(&SECP256K1, &[ChildNumber::Normal { index: n }])
            .expect("BIP-32 unhardened derivation cannot fail for u32 indices")
            .public_key;
        let key: [u8; 32] = bitcoin::hashes::sha256::Hash::hash(&pk.serialize()).to_byte_array();
        if smt.get(&key).is_none() {
            return n;
        }
        if n >= bound {
            panic!(
                "derive_num_pubkeys_from_smt: SMT contains more than {} consecutive minting pubkeys; \
                 the loop bound is a safety net for a state we cannot reason about",
                bound
            );
        }
        n += 1;
    }
}

/// State stores both a Sparse Merkle Tree (for individual commitments)
/// and a Merkle Mountain Range (for accumulating SMT roots).
#[derive(Debug, Serialize, Deserialize)]
pub struct State {
    /// The Sparse Merkle Tree to store individual commitments
    pub(crate) smt: SparseMerkleTree,
    /// The Merkle Mountain Range to accumulate SMT roots
    pub(crate) mmr: MerkleMountainRange,
    /// Maps previous MMR roots to (SMT root, leaf index) pairs
    pub(crate) root_indices: HashMap<HashDigest, (HashDigest, usize)>,
    /// The previous MMR root
    pub(crate) prev_mmr_root: HashDigest,
}

/// Error type for `State::load_from_pg`. Distinguishes database errors
/// (connectivity, schema mismatch) from on-disk-blob corruption
/// (bincode rejected the SMT or MMR payload) so the bootstrap caller
/// can react accordingly.
#[derive(Debug)]
pub enum LoadStateError {
    /// The Postgres call itself failed (connect, query, decode).
    Db(sqlx::Error),
    /// The SMT/MMR bincode blob in Postgres could not be deserialized.
    Deserialize(bincode::Error),
}

impl std::fmt::Display for LoadStateError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            LoadStateError::Db(e) => write!(f, "database error: {}", e),
            LoadStateError::Deserialize(e) => write!(f, "state blob deserialize: {}", e),
        }
    }
}

impl std::error::Error for LoadStateError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            LoadStateError::Db(e) => Some(e),
            LoadStateError::Deserialize(e) => Some(e),
        }
    }
}

impl From<sqlx::Error> for LoadStateError {
    fn from(e: sqlx::Error) -> Self {
        LoadStateError::Db(e)
    }
}

impl From<bincode::Error> for LoadStateError {
    fn from(e: bincode::Error) -> Self {
        LoadStateError::Deserialize(e)
    }
}

impl State {
    /// Creates a new state with an empty SMT of the default depth and an empty MMR.
    pub(crate) fn new() -> Self {
        State {
            smt: SparseMerkleTree::new(),
            mmr: MerkleMountainRange::new(),
            root_indices: HashMap::new(),
            prev_mmr_root: ZERO_HASH,
        }
    }

    /// Updates the state by inserting a set of commitments into the SMT,
    /// then appending a new leaf to the MMR that combines the new SMT root
    /// and the previous MMR root.
    ///
    /// Returns the new MMR root.
    ///
    /// After a successful call, the freshly-inserted `root_indices`
    /// entry is uniquely identifiable as
    /// `(self.prev_mmr_root, self.root_indices[&self.prev_mmr_root])`
    /// — the function writes `self.prev_mmr_root` and inserts using the
    /// same value as the map key, in that order, immediately before
    /// `self.mmr.append`. Callers that need to persist this entry
    /// (Phase C: `db::insert_root_index`) read it back from `self`
    /// rather than threading a pool into this synchronous method, which
    /// would force every test caller to grow a Postgres dependency.
    pub(crate) fn update(&mut self, commitments: &[Commitment]) -> Result<HashDigest, &'static str> {
        // 1. Insert all commitments into the SMT
        for commitment in commitments {
            // Use the public key as the key for the tree (hashed)
            let key_bytes = commitment.public_key.serialize();
            let key: [u8; 32] = bitcoin::hashes::sha256::Hash::hash(&key_bytes).to_byte_array();

            // The SMT value is the canonical Poseidon combiner of the
            // commitment's two halves:
            //
            //     smt_value = hash_concat(asth, ocr)
            //
            // That is exactly what the in-circuit gadget reconstructs in
            // `CommitmentMerkleProofs::commitment()`
            // (`program-plonky2/src/inputs.rs`) and feeds back into the
            // SMT inclusion check. Any other value here surfaces as the
            // server-side `prove_account_update_*` failing on the second
            // send from an account (the first end-to-end test that
            // exercises a non-initial proof is
            // `second_send_succeeds_without_prev_commitment_pubkey_field`,
            // added in PR #132).
            //
            // The protocol ships two on-the-wire shapes for
            // `Commitment.message`, and both must produce the canonical
            // SMT value:
            //
            //   * 64 bytes — wallet wire format
            //     (`zk-coins/app/rust/client/src/lib.rs::create_commitment`,
            //     mirrored by `TestWallet::sign_commit` in
            //     `node/tests/api_remote.rs`): raw concatenation
            //     `asth_bytes || ocr_bytes`. The Schnorr signature is
            //     over `sha256(message)` (see `Commitment::verify` in
            //     `shared/src/commitment.rs`), but the SMT value MUST
            //     ignore that signature digest and reconstruct the
            //     canonical Poseidon combiner over the two halves.
            //   * 32 bytes — mint flow (`ClientAccount::create_commitment`
            //     in `shared/src/lib.rs`): the already-canonical
            //     `digest_to_bytes(hash_concat(asth, ocr))`. Round-trips
            //     through `digest_from_bytes` and recovers the same
            //     canonical `hash_concat(asth, ocr)` digest the 64-byte
            //     path produces — so the two forms agree on the SMT
            //     entry, by construction.
            //
            // Any other length is a test-only fixture (existing
            // `state_tests.rs` uses arbitrary byte slices to exercise
            // the surrounding state machinery); production callers
            // never produce that shape, so we preserve the legacy
            // sha256-fallback path via `get_account_state_hash` rather
            // than forcing a tests-only refactor. The SMT value on
            // that path is opaque but consistent — fine for the test
            // surface, never reached by deployed code.
            let smt_value = if commitment.message.len() == 64 {
                let mut ash_bytes = [0u8; 32];
                let mut ocr_bytes = [0u8; 32];
                ash_bytes.copy_from_slice(&commitment.message[..32]);
                ocr_bytes.copy_from_slice(&commitment.message[32..]);
                let ash = digest_from_bytes(&ash_bytes);
                let ocr = digest_from_bytes(&ocr_bytes);
                hash_concat(&ash, &ocr)
            } else {
                let message_bytes = commitment.get_account_state_hash();
                digest_from_bytes(&message_bytes)
            };

            // Update the SMT with the canonical commitment value.
            self.smt.insert(key, smt_value)?;
        }

        // 2. Get the current SMT root
        let smt_root = self.smt.root();

        // 3. Create a new leaf that combines the SMT root and previous MMR
        // root. Uses Poseidon `hash_concat` (architectural invariant:
        // Poseidon everywhere in Merkle structures). Replaces the
        // SP1-era SHA256.
        //
        // The previous MMR root is recorded in its *extended* form
        // (`mmr.root_extended(MMR_PROOF_PATH_LEN)`) because every
        // downstream consumer — the public output of a Plonky2 proof
        // (`commitment_history_root` in `ProofData`), the in-circuit
        // CMP sibling (`commitment_root_mmr_sibling`), and the
        // `root_indices` lookup at the next AccountUpdate — works in
        // the extended representation that the circuit's fixed-depth
        // invariant demands. Using the natural root anywhere along
        // that chain produces a hash that the circuit can't reconcile
        // with the public input, surfacing as a witness-partition
        // conflict at prove time.
        let prev_mmr_root = self.mmr.root_extended(MMR_PROOF_PATH_LEN);
        self.prev_mmr_root = prev_mmr_root;

        let leaf = hash_concat(&smt_root, &prev_mmr_root);

        let leaf_index = self.mmr.leaf_count();
        self.root_indices
            .insert(prev_mmr_root, (smt_root, leaf_index));

        // 4. Append the new leaf to the MMR
        self.mmr.append(leaf);

        // 5. Return the new MMR root
        Ok(self.mmr.root())
    }

    /// Gets an inclusion proof for a leaf in the MMR that was created with the given previous MMR root.
    #[cfg(test)]
    pub(crate) fn get_mmr_inclusion_proof(
        &self,
        prev_mmr_root: HashDigest,
    ) -> Result<(HashDigest, MMRProof), &'static str> {
        match self.root_indices.get(&prev_mmr_root) {
            Some(&(smt_root, index)) => self.mmr.get_proof(index).map(|proof| (smt_root, proof)),
            None => Err("Couldn't find MMR inclusion proof"),
        }
    }

    /// Gets an inclusion proof for a specific commitment in the SMT,
    /// along with an inclusion proof of the current SMT root in the MMR.
    #[cfg(test)]
    pub(crate) fn get_commitment_proof(
        &self,
        public_key: &PublicKey,
    ) -> Result<(HashDigest, InclusionProof, HashDigest, MMRProof), &'static str> {
        let key_bytes = public_key.serialize();
        let key: [u8; 32] = bitcoin::hashes::sha256::Hash::hash(&key_bytes).to_byte_array();

        let (smt_proof, commitment) = self.smt.generate_inclusion_proof(&key)?;

        let smt_root = self.smt.root();

        let leaf_count = self.mmr.leaf_count();
        if leaf_count == 0 {
            return Err("MMR leaf count = 0");
        }
        let latest_leaf_index = leaf_count - 1;

        let mmr_proof = self.mmr.get_proof(latest_leaf_index)?;

        Ok((commitment, smt_proof, smt_root, mmr_proof))
    }

    /// Load the SMT and MMR blobs from Postgres and rebuild a `State`,
    /// then rehydrate `root_indices` and `prev_mmr_root` from the
    /// dedicated `mmr_root_index` table (migration `0004`).
    ///
    /// Phase C of the state-layer hardening series. Before this code
    /// landed, `root_indices` was treated as a pure runtime memoization
    /// and silently reset to empty on every restart — which broke any
    /// account whose latest proof referenced a `commitment_history_root`
    /// produced before the restart (`get_mmr_inclusion_proof` returned
    /// `Err`, `/api/mint` surfaced 422 `Unable to get mmr inclusion
    /// proof for the previous root`). The map is now persisted per
    /// successful `update()` and rebuilt here.
    ///
    /// `prev_mmr_root` is restored from the highest-`leaf_index` entry
    /// in the loaded map — that entry's KEY is precisely the value the
    /// last successful `update()` wrote to `self.prev_mmr_root`
    /// (`update` inserts using `prev_mmr_root` as the key and the
    /// current `leaf_count` as the leaf_index, in that order, immediately
    /// before `mmr.append`). On a fresh database the table is empty,
    /// `root_indices` stays empty, and `prev_mmr_root` stays
    /// `ZERO_HASH` exactly like `State::new`.
    pub async fn load_from_pg(pool: &PgPool) -> Result<Self, LoadStateError> {
        let mut state = Self::new();
        if let Some(data) = db::load_smt(pool).await? {
            state.smt = bincode::deserialize(&data)?;
        }
        if let Some(data) = db::load_mmr(pool).await? {
            state.mmr = bincode::deserialize(&data)?;
        }
        let entries = db::load_root_indices(pool).await?;
        // The DB ORDER BY leaf_index means `entries` is monotonic; the
        // last element is the one whose KEY is the most recently written
        // `prev_mmr_root`. Drain it in order, capturing the last KEY as
        // we go so we don't have to re-scan the assembled HashMap.
        let mut last_key: Option<HashDigest> = None;
        for (prev_root, smt_root, leaf_index) in entries {
            // `leaf_index` is a `u64` from Postgres, non-negative by the
            // load query's filter. The production target is 64-bit
            // (Linux x86_64 / aarch64), so the cast to `usize` is
            // infallible.
            let leaf_usize = leaf_index as usize;
            state.root_indices.insert(prev_root, (smt_root, leaf_usize));
            last_key = Some(prev_root);
        }
        if let Some(prev) = last_key {
            state.prev_mmr_root = prev;
        }
        Ok(state)
    }

    /// Apply `commitments` via [`State::update`] and capture the
    /// snapshot tuple required to feed `db::persist_state_tx` on the
    /// async side without holding the state lock across the await.
    ///
    /// Returns `(new_mmr_root, smt_bytes, mmr_bytes, root_index_entry)`:
    /// * `new_mmr_root` is the value [`State::update`] returns (the
    ///   root of the MMR after the new leaf was appended).
    /// * `smt_bytes` / `mmr_bytes` are the bincode blobs that go into
    ///   the `smt_state` / `mmr_state` singleton rows.
    /// * `root_index_entry` is the freshly-inserted
    ///   `(prev_mmr_root, smt_root, leaf_index)` triple — recovered
    ///   from the live `root_indices` map under the same lock so the
    ///   caller does not need to repeat [`State::update`]'s internal
    ///   bookkeeping. `None` only on a serialize-side bincode error
    ///   propagated from [`Self::serialize_for_persist`].
    ///
    /// This helper exists so the scanner-callback (`main.rs`) and the
    /// new Phase-E synchronous in-process integration in
    /// [`crate::router::mint_handler`] share a single source of truth
    /// for "what bytes must I hand to `persist_state_tx` after a
    /// successful update?". Both callers acquire the state lock, run
    /// this method, drop the lock, then await `persist_state_tx` with
    /// the returned tuple — keeping the `std::sync::Mutex` off the
    /// `.await` while still letting `update` and `serialize_for_persist`
    /// observe a consistent snapshot.
    #[allow(clippy::type_complexity)]
    pub(crate) fn update_and_snapshot_for_persist(
        &mut self,
        commitments: &[Commitment],
    ) -> Result<
        (
            HashDigest,
            Vec<u8>,
            Vec<u8>,
            Option<(HashDigest, HashDigest, usize)>,
        ),
        &'static str,
    > {
        let new_root = self.update(commitments)?;
        let root_index_entry = self
            .root_indices
            .get(&self.prev_mmr_root)
            .copied()
            .map(|(smt_root, leaf_index)| (self.prev_mmr_root, smt_root, leaf_index));
        let (smt_bytes, mmr_bytes) = self
            .serialize_for_persist()
            .map_err(|_| "state serialize_for_persist failed (bincode)")?;
        Ok((new_root, smt_bytes, mmr_bytes, root_index_entry))
    }

    /// Serialize the SMT and MMR to bincode blobs for `persist_state_tx`.
    ///
    /// Returned tuple is `(smt_bytes, mmr_bytes)`. The caller is
    /// expected to hand these straight to `db::persist_state_tx`
    /// together with the corresponding block hash.
    ///
    /// `bincode::serialize` on these structures is infallible in
    /// practice (no `Serialize` impl in the SMT/MMR trees returns Err),
    /// but the error path is propagated as a `bincode::Error` rather
    /// than panicked over so a future schema change that introduces a
    /// fallible branch surfaces as a recoverable error.
    pub(crate) fn serialize_for_persist(&self) -> Result<(Vec<u8>, Vec<u8>), bincode::Error> {
        let smt_bytes = bincode::serialize(&self.smt)?;
        let mmr_bytes = bincode::serialize(&self.mmr)?;
        Ok((smt_bytes, mmr_bytes))
    }
}

#[cfg(test)]
#[path = "state_tests.rs"]
mod tests;
