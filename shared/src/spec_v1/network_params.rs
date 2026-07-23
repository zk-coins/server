//! Network parameter tuple + SHA-256 identifier (§3.6).

use sha2::{Digest, Sha256};

use super::error::SpecError;

/// The pinned network-parameter tuple (section 3.6). `circuit_digest_c` and
/// `circuit_digest_c_balance` do not exist yet as real values (they come
/// from a later chunk that compiles the actual circuits, P1-D/P1-D2) —
/// they are typed 32-byte fields populated by config/tests here.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct NetworkParams {
    pub network_tag: String,
    pub circuit_digest_c: [u8; 32],
    pub circuit_digest_c_balance: [u8; 32],
    pub activation_height: u64,
    pub finality_confirmations: u8,
    pub bootstrap_pubkey: [u8; 32],
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

    /// Canonical byte string (section 3.6) — what the SHA-256 identifier is over.
    pub fn canonical_encoding(&self) -> Vec<u8> {
        let tag_bytes = self.network_tag.as_bytes();
        let mut out = Vec::with_capacity(1 + tag_bytes.len() + 32 + 32 + 8 + 1 + 32);
        out.push(tag_bytes.len() as u8);
        out.extend_from_slice(tag_bytes);
        out.extend_from_slice(&self.circuit_digest_c);
        out.extend_from_slice(&self.circuit_digest_c_balance);
        out.extend_from_slice(&self.activation_height.to_be_bytes());
        out.push(self.finality_confirmations);
        out.extend_from_slice(&self.bootstrap_pubkey);
        out
    }

    /// `SHA-256(canonical_encoding())`.
    pub fn identifier(&self) -> [u8; 32] {
        let dig = Sha256::digest(self.canonical_encoding());
        let mut out = [0u8; 32];
        out.copy_from_slice(&dig);
        out
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
        let enc = p.canonical_encoding();
        let tag = p.network_tag.as_bytes();
        let expected_len = 1 + tag.len() + 32 + 32 + 8 + 1 + 32;
        assert_eq!(enc.len(), expected_len);

        // Field layout hand-check
        assert_eq!(enc[0], tag.len() as u8);
        assert_eq!(&enc[1..1 + tag.len()], tag);
        let mut off = 1 + tag.len();
        assert_eq!(&enc[off..off + 32], &p.circuit_digest_c);
        off += 32;
        assert_eq!(&enc[off..off + 32], &p.circuit_digest_c_balance);
        off += 32;
        assert_eq!(&enc[off..off + 8], &p.activation_height.to_be_bytes());
        off += 8;
        assert_eq!(enc[off], 6);
        off += 1;
        assert_eq!(&enc[off..off + 32], &p.bootstrap_pubkey);
    }

    #[test]
    fn identifier_deterministic_and_sensitive_to_each_field() {
        let base = fixture_params();
        let id = base.identifier();
        assert_eq!(id, base.identifier());

        // tag
        let mut p = base.clone();
        p.network_tag = "zkCoins/v1/test-vector/network-tag-OTHER".to_string();
        assert_ne!(p.identifier(), id);

        // circuit_digest_c
        let mut p = base.clone();
        p.circuit_digest_c = fixture_digest(b"zkCoins/v1/test-vector/circuit-digest-c-OTHER");
        assert_ne!(p.identifier(), id);

        // circuit_digest_c_balance
        let mut p = base.clone();
        p.circuit_digest_c_balance =
            fixture_digest(b"zkCoins/v1/test-vector/circuit-digest-c-balance-OTHER");
        assert_ne!(p.identifier(), id);

        // activation_height
        let mut p = base.clone();
        p.activation_height = 43;
        assert_ne!(p.identifier(), id);

        // bootstrap_pubkey
        let mut p = base.clone();
        p.bootstrap_pubkey = fixture_digest(b"zkCoins/v1/test-vector/bootstrap-pubkey-OTHER");
        assert_ne!(p.identifier(), id);
    }

    #[test]
    fn new_rejects_non_six_finality() {
        let err = NetworkParams::new(
            "tag".to_string(),
            [0u8; 32],
            [0u8; 32],
            0,
            5,
            [0u8; 32],
        )
        .expect_err("must reject");
        assert_eq!(
            err,
            SpecError::InvalidFinalityConfirmations { value: 5 }
        );
    }

    #[test]
    fn new_rejects_tag_over_255_accepts_exactly_255() {
        let too_long = "a".repeat(256);
        let err = NetworkParams::new(
            too_long,
            [0u8; 32],
            [0u8; 32],
            0,
            6,
            [0u8; 32],
        )
        .expect_err("must reject");
        assert_eq!(err, SpecError::NetworkTagTooLong { len: 256 });

        let exactly = "b".repeat(255);
        let ok = NetworkParams::new(
            exactly,
            [0u8; 32],
            [0u8; 32],
            0,
            6,
            [0u8; 32],
        )
        .expect("255-byte tag is valid");
        assert_eq!(ok.network_tag.len(), 255);
        assert_eq!(ok.canonical_encoding()[0], 255);
    }
}
