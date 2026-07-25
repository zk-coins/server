//! Network parameter tuple + SHA-256 identifier (§3.6).

use sha2::{Digest, Sha256};

use super::error::SpecError;

/// The pinned network-parameter tuple (section 3.6). `circuit_digest_c` and
/// `circuit_digest_c_balance` do not exist yet as real values (they come
/// from a later chunk that compiles the actual circuits, P1-D/P1-D2) —
/// they are typed 32-byte fields populated by config/tests here.
///
/// All fields are private so construction can only go through
/// [`NetworkParams::new`], which enforces tag-length and finality
/// invariants.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct NetworkParams {
    network_tag: String,
    circuit_digest_c: [u8; 32],
    circuit_digest_c_balance: [u8; 32],
    activation_height: u64,
    finality_confirmations: u8,
    bootstrap_pubkey: [u8; 32],
}

impl NetworkParams {
    /// Validates: `network_tag` fits in a `u8` length prefix (≤ 255 bytes
    /// UTF-8), and `finality_confirmations == 6` (the spec pins this as a
    /// fixed protocol constant, not a configurable value — reject anything
    /// else rather than silently normalising it).
    pub fn new(
        network_tag: String,
        circuit_digest_c: [u8; 32],
        circuit_digest_c_balance: [u8; 32],
        activation_height: u64,
        finality_confirmations: u8,
        bootstrap_pubkey: [u8; 32],
    ) -> Result<Self, SpecError> {
        if network_tag.len() > u8::MAX as usize {
            return Err(SpecError::NetworkTagTooLong {
                len: network_tag.len(),
            });
        }
        if finality_confirmations != 6 {
            return Err(SpecError::InvalidFinalityConfirmations {
                value: finality_confirmations,
            });
        }
        Ok(Self {
            network_tag,
            circuit_digest_c,
            circuit_digest_c_balance,
            activation_height,
            finality_confirmations,
            bootstrap_pubkey,
        })
    }

    /// Test-only backdoor that bypasses `new()` validation so defense-in-depth
    /// paths in `canonical_encoding` can be exercised.
    #[cfg(test)]
    fn new_unchecked_for_test(
        network_tag: String,
        circuit_digest_c: [u8; 32],
        circuit_digest_c_balance: [u8; 32],
        activation_height: u64,
        finality_confirmations: u8,
        bootstrap_pubkey: [u8; 32],
    ) -> Self {
        Self {
            network_tag,
            circuit_digest_c,
            circuit_digest_c_balance,
            activation_height,
            finality_confirmations,
            bootstrap_pubkey,
        }
    }

    pub fn network_tag(&self) -> &str {
        &self.network_tag
    }

    pub fn circuit_digest_c(&self) -> [u8; 32] {
        self.circuit_digest_c
    }

    pub fn circuit_digest_c_balance(&self) -> [u8; 32] {
        self.circuit_digest_c_balance
    }

    pub fn activation_height(&self) -> u64 {
        self.activation_height
    }

    pub fn finality_confirmations(&self) -> u8 {
        self.finality_confirmations
    }

    pub fn bootstrap_pubkey(&self) -> [u8; 32] {
        self.bootstrap_pubkey
    }

    /// Canonical byte string (section 3.6) — what the SHA-256 identifier is over.
    ///
    /// Fail-loud if the tag length cannot fit in a `u8` prefix. Unreachable
    /// for values constructed via [`NetworkParams::new`], but treated as a
    /// soundness defect class for §3.6 cross-node agreement.
    pub fn canonical_encoding(&self) -> Result<Vec<u8>, SpecError> {
        let tag_bytes = self.network_tag.as_bytes();
        let tag_len = u8::try_from(tag_bytes.len()).map_err(|_| SpecError::NetworkTagTooLong {
            len: tag_bytes.len(),
        })?;
        let mut out = Vec::with_capacity(1 + tag_bytes.len() + 32 + 32 + 8 + 1 + 32);
        out.push(tag_len);
        out.extend_from_slice(tag_bytes);
        out.extend_from_slice(&self.circuit_digest_c);
        out.extend_from_slice(&self.circuit_digest_c_balance);
        out.extend_from_slice(&self.activation_height.to_be_bytes());
        out.push(self.finality_confirmations);
        out.extend_from_slice(&self.bootstrap_pubkey);
        Ok(out)
    }

    /// `SHA-256(canonical_encoding())`.
    pub fn identifier(&self) -> Result<[u8; 32], SpecError> {
        let enc = self.canonical_encoding()?;
        let dig = Sha256::digest(enc);
        let mut out = [0u8; 32];
        out.copy_from_slice(&dig);
        Ok(out)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn fixture_digest(label: &[u8]) -> [u8; 32] {
        Sha256::digest(label).into()
    }

    fn fixture_params() -> NetworkParams {
        NetworkParams::new(
            "zkCoins/v1/test-vector/network-tag".to_string(),
            fixture_digest(b"zkCoins/v1/test-vector/circuit-digest-c"),
            fixture_digest(b"zkCoins/v1/test-vector/circuit-digest-c-balance"),
            42,
            6,
            fixture_digest(b"zkCoins/v1/test-vector/bootstrap-pubkey"),
        )
        .expect("fixture is valid")
    }

    #[test]
    fn canonical_encoding_layout_and_length() {
        let p = fixture_params();
        let enc = p.canonical_encoding().expect("valid tag");
        let tag = p.network_tag().as_bytes();
        let expected_len = 1 + tag.len() + 32 + 32 + 8 + 1 + 32;
        assert_eq!(enc.len(), expected_len);

        // Field layout hand-check
        assert_eq!(enc[0], tag.len() as u8);
        assert_eq!(&enc[1..1 + tag.len()], tag);
        let mut off = 1 + tag.len();
        assert_eq!(&enc[off..off + 32], &p.circuit_digest_c());
        off += 32;
        assert_eq!(&enc[off..off + 32], &p.circuit_digest_c_balance());
        off += 32;
        assert_eq!(&enc[off..off + 8], &p.activation_height().to_be_bytes());
        off += 8;
        assert_eq!(enc[off], 6);
        off += 1;
        assert_eq!(&enc[off..off + 32], &p.bootstrap_pubkey());
    }

    #[test]
    fn identifier_deterministic_and_sensitive_to_each_field() {
        let base = fixture_params();
        let id = base.identifier().expect("valid");
        assert_eq!(id, base.identifier().expect("valid"));

        // tag
        let p = NetworkParams::new(
            "zkCoins/v1/test-vector/network-tag-OTHER".to_string(),
            base.circuit_digest_c(),
            base.circuit_digest_c_balance(),
            base.activation_height(),
            6,
            base.bootstrap_pubkey(),
        )
        .expect("valid");
        assert_ne!(p.identifier().expect("valid"), id);

        // circuit_digest_c
        let p = NetworkParams::new(
            base.network_tag().to_string(),
            fixture_digest(b"zkCoins/v1/test-vector/circuit-digest-c-OTHER"),
            base.circuit_digest_c_balance(),
            base.activation_height(),
            6,
            base.bootstrap_pubkey(),
        )
        .expect("valid");
        assert_ne!(p.identifier().expect("valid"), id);

        // circuit_digest_c_balance
        let p = NetworkParams::new(
            base.network_tag().to_string(),
            base.circuit_digest_c(),
            fixture_digest(b"zkCoins/v1/test-vector/circuit-digest-c-balance-OTHER"),
            base.activation_height(),
            6,
            base.bootstrap_pubkey(),
        )
        .expect("valid");
        assert_ne!(p.identifier().expect("valid"), id);

        // activation_height
        let p = NetworkParams::new(
            base.network_tag().to_string(),
            base.circuit_digest_c(),
            base.circuit_digest_c_balance(),
            43,
            6,
            base.bootstrap_pubkey(),
        )
        .expect("valid");
        assert_ne!(p.identifier().expect("valid"), id);

        // bootstrap_pubkey
        let p = NetworkParams::new(
            base.network_tag().to_string(),
            base.circuit_digest_c(),
            base.circuit_digest_c_balance(),
            base.activation_height(),
            6,
            fixture_digest(b"zkCoins/v1/test-vector/bootstrap-pubkey-OTHER"),
        )
        .expect("valid");
        assert_ne!(p.identifier().expect("valid"), id);
    }

    #[test]
    fn new_rejects_non_six_finality() {
        let err = NetworkParams::new("tag".to_string(), [0u8; 32], [0u8; 32], 0, 5, [0u8; 32])
            .expect_err("must reject");
        assert_eq!(err, SpecError::InvalidFinalityConfirmations { value: 5 });
    }

    #[test]
    fn new_rejects_tag_over_255_accepts_exactly_255() {
        let too_long = "a".repeat(256);
        let err = NetworkParams::new(too_long, [0u8; 32], [0u8; 32], 0, 6, [0u8; 32])
            .expect_err("must reject");
        assert_eq!(err, SpecError::NetworkTagTooLong { len: 256 });

        let exactly = "b".repeat(255);
        let ok = NetworkParams::new(exactly, [0u8; 32], [0u8; 32], 0, 6, [0u8; 32])
            .expect("255-byte tag is valid");
        assert_eq!(ok.network_tag().len(), 255);
        assert_eq!(ok.canonical_encoding().expect("valid")[0], 255);
    }

    #[test]
    fn canonical_encoding_rejects_overlong_tag_via_unchecked_ctor() {
        let overlong = NetworkParams::new_unchecked_for_test(
            "c".repeat(256),
            [0u8; 32],
            [0u8; 32],
            0,
            6,
            [0u8; 32],
        );
        let err = overlong
            .canonical_encoding()
            .expect_err("must reject overlong tag");
        assert_eq!(err, SpecError::NetworkTagTooLong { len: 256 });
        let id_err = overlong.identifier().expect_err("identifier propagates");
        assert_eq!(id_err, SpecError::NetworkTagTooLong { len: 256 });
    }
}
