//! Bootstrap Manifest V1 (BMF1) codec and verifying checks (§4.3 / §7.7).
//!
//! ## Framing (single source)
//!
//! [`write_framed_body`] is the **only** place that lays out
//! `network … expires_at`. Both [`serialize`] (full BMF1: magic ‖ version ‖
//! body ‖ sig) and [`bootstrap_message`] (SHA-256 of domain tag ‖ body) call
//! it. They cannot drift: there is no second encoder for the signed body.
//!
//! ```text
//! serialize := magic "BMF1" ‖ version 0x01 ‖ body ‖ manifest_sig
//! body      := network … expires_at   (same order/widths as the wire)
//! bootstrap_message := SHA-256("zkCoins/v1/BootstrapManifest" ‖ body)
//! manifest_id       := SHA-256(serialize(…))   // includes magic/version/sig
//! ```
//!
//! ## Trust anchor
//!
//! Verification uses **only** the network-parameter pin
//! [`NetworkParams::bootstrap_pubkey`](super::network_params::NetworkParams::bootstrap_pubkey)
//! (or an explicit x-only key passed in by a caller that already took it
//! from that pin). A key from the manifest, env, or operator config is
//! never accepted as the authority.
//!
//! ## Signing
//!
//! [`sign_bootstrap_manifest`] is the sole production sign path. It
//! reuses [`bootstrap_message`] / [`serialize`] (same framing as verify)
//! and **fail-closes** when the secret key does not derive to the
//! caller-supplied `expected_bootstrap_pubkey` — so a tool cannot emit
//! an artifact the node would later reject under the pin.

use bitcoin::secp256k1::{Keypair, Message, Secp256k1, SecretKey, XOnlyPublicKey};
use sha2::{Digest, Sha256};

use super::error::{BootstrapStringField, BootstrapUrlKind, SpecError};
use super::tags::{
    NETWORK_TAG_MAINNET, NETWORK_TAG_REGTEST, NETWORK_TAG_TESTNET, TAG_BOOTSTRAP_MANIFEST,
};

/// ASCII magic of `serialize(BootstrapManifestV1)`.
pub const BMF1_MAGIC: &[u8; 4] = b"BMF1";
/// Sole accepted version byte.
pub const BMF1_VERSION: u8 = 0x01;
/// Normative protocol version string on the wire.
pub const BOOTSTRAP_PROTOCOL_VERSION: &str = "v1";
/// §4.3 / §7.7 URL length upper bound (bytes).
pub const MAX_BOOTSTRAP_URL_LEN: usize = 2048;

/// Signed per-network bootstrap infrastructure (§4.3 `BootstrapManifestV1`).
///
/// Payload is **global and account-independent** only: seed relays, blob
/// stores, operator trust-list IDs, lifetime, and the BIP-340 signature.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct BootstrapManifestV1 {
    /// Exactly one of `mainnet` | `testnet` | `regtest`.
    pub network: String,
    /// Exactly `"v1"`.
    pub protocol_version: String,
    /// Seed Nostr relays (≥ 1).
    pub seed_relays: Vec<String>,
    /// Blossom base URLs (≥ 1).
    pub blob_stores: Vec<String>,
    /// Operator trust-list x-only pubkeys (≥ 1).
    pub operator_ids: Vec<[u8; 32]>,
    /// Unix seconds.
    pub issued_at: u64,
    /// Unix seconds.
    pub expires_at: u64,
    /// BIP-340 signature over [`bootstrap_message`].
    pub manifest_sig: [u8; 64],
}

/// Wall clock for the expiry check — **not** a silent sentinel.
///
/// [`ManifestClock::Unavailable`] skips **only** `expires_at < now`.
/// Signature, network, and protocol checks still run.
/// [`ManifestClock::UnixSeconds`]`(0)` is a real time (epoch) and is **not**
/// the same as "no clock".
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ManifestClock {
    /// No usable wall clock was supplied — omit the expiry check only.
    Unavailable,
    /// Unix seconds for `expires_at < now`.
    UnixSeconds(u64),
}

/// Inputs for [`verify_bootstrap_manifest`] (destructured at the call site).
///
/// Bundled so clippy's `too_many_arguments` gate stays clear and a new
/// field is a compile error at every construction site.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct VerifyBootstrapManifest<'a> {
    /// Pinned network-parameter `bootstrap_pubkey` (x-only, 32 bytes).
    /// **Must** come from the frozen parameter set — never from the manifest.
    pub pinned_bootstrap_pubkey: &'a [u8; 32],
    /// Verifier's network label (`mainnet` | `testnet` | `regtest`).
    pub expected_network: &'a str,
    /// Verifier's protocol version (v1: always [`BOOTSTRAP_PROTOCOL_VERSION`]).
    pub expected_protocol_version: &'a str,
    /// Optional wall clock; see [`ManifestClock`].
    pub clock: ManifestClock,
}

/// Unsigned body fields for [`sign_bootstrap_manifest`].
///
/// `manifest_sig` is produced by the sign path; callers never supply it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct BootstrapManifestBody {
    /// Exactly one of `mainnet` | `testnet` | `regtest`.
    pub network: String,
    /// Exactly `"v1"`.
    pub protocol_version: String,
    /// Seed Nostr relays (≥ 1).
    pub seed_relays: Vec<String>,
    /// Blossom base URLs (≥ 1).
    pub blob_stores: Vec<String>,
    /// Operator trust-list x-only pubkeys (≥ 1).
    pub operator_ids: Vec<[u8; 32]>,
    /// Unix seconds.
    pub issued_at: u64,
    /// Unix seconds.
    pub expires_at: u64,
}

/// Inputs for [`sign_bootstrap_manifest`] (destructured at the call site).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SignBootstrapManifest<'a> {
    /// 32-byte secp256k1 secret. Never log or display.
    pub secret_key: &'a [u8; 32],
    /// Expected network-parameter pin (x-only). Must equal the key
    /// derived from `secret_key` or signing aborts with
    /// [`SpecError::BootstrapPubkeyMismatch`].
    pub expected_bootstrap_pubkey: &'a [u8; 32],
}

// ---------------------------------------------------------------------------
// Single framing source
// ---------------------------------------------------------------------------

/// Write the signed body: `network … expires_at` in wire framing.
///
/// **Sole encoder** for the bytes that enter both `serialize` (after
/// magic/version, before sig) and `bootstrap_message` (after the domain
/// tag). Callers must not re-implement this layout.
fn write_framed_body(m: &BootstrapManifestV1, out: &mut Vec<u8>) -> Result<(), SpecError> {
    write_u8_len_str(&m.network, out)?;
    write_u8_len_str(&m.protocol_version, out)?;

    write_u16_count(m.seed_relays.len(), out, "seed_relay_count")?;
    for url in &m.seed_relays {
        write_u32_len_url(url, out)?;
    }

    write_u16_count(m.blob_stores.len(), out, "blob_store_count")?;
    for url in &m.blob_stores {
        write_u32_len_url(url, out)?;
    }

    write_u16_count(m.operator_ids.len(), out, "operator_id_count")?;
    for op in &m.operator_ids {
        out.extend_from_slice(op);
    }

    out.extend_from_slice(&m.issued_at.to_be_bytes());
    out.extend_from_slice(&m.expires_at.to_be_bytes());
    Ok(())
}

fn write_u8_len_str(s: &str, out: &mut Vec<u8>) -> Result<(), SpecError> {
    let bytes = s.as_bytes();
    let len =
        u8::try_from(bytes.len()).map_err(|_| SpecError::NetworkTagTooLong { len: bytes.len() })?;
    out.push(len);
    out.extend_from_slice(bytes);
    Ok(())
}

fn write_u16_count(count: usize, out: &mut Vec<u8>, _label: &'static str) -> Result<(), SpecError> {
    let n = u16::try_from(count).map_err(|_| SpecError::ByteStringTooLong { len: count })?;
    out.extend_from_slice(&n.to_be_bytes());
    Ok(())
}

/// Write a URL length prefix. Caller must have run [`validate_structure`]
/// (lengths `1..=2048`); this only frames.
fn write_u32_len_url(url: &str, out: &mut Vec<u8>) -> Result<(), SpecError> {
    let bytes = url.as_bytes();
    let len = u32::try_from(bytes.len())
        .map_err(|_| SpecError::ByteStringTooLong { len: bytes.len() })?;
    out.extend_from_slice(&len.to_be_bytes());
    out.extend_from_slice(bytes);
    Ok(())
}

/// Structural bounds shared by encode and (post-decode) verify.
fn validate_structure(m: &BootstrapManifestV1) -> Result<(), SpecError> {
    validate_closed_network(&m.network)?;
    if m.protocol_version != BOOTSTRAP_PROTOCOL_VERSION {
        return Err(SpecError::BootstrapProtocolVersionInvalid {
            got: m.protocol_version.clone(),
        });
    }
    if m.seed_relays.is_empty() {
        return Err(SpecError::BootstrapSeedRelayCountZero);
    }
    if m.blob_stores.is_empty() {
        return Err(SpecError::BootstrapBlobStoreCountZero);
    }
    if m.operator_ids.is_empty() {
        return Err(SpecError::BootstrapOperatorIdCountZero);
    }
    for (index, url) in m.seed_relays.iter().enumerate() {
        check_url(BootstrapUrlKind::SeedRelay, index, url)?;
    }
    for (index, url) in m.blob_stores.iter().enumerate() {
        check_url(BootstrapUrlKind::BlobStore, index, url)?;
    }
    // Degenerate lifetime: expires before it is issued. Rejected
    // structurally (not only under a clock) so an unclocked verifier
    // cannot accept a never-valid advertisement. Spec requires rejecting
    // `expires_at < now` when a clock is available; `issued_at > expires_at`
    // is a stronger, always-true form of that defect.
    if m.issued_at > m.expires_at {
        return Err(SpecError::BootstrapIssuedAfterExpiry {
            issued_at: m.issued_at,
            expires_at: m.expires_at,
        });
    }
    Ok(())
}

fn check_url(which: BootstrapUrlKind, index: usize, url: &str) -> Result<(), SpecError> {
    let len = url.len();
    if len == 0 {
        return Err(SpecError::BootstrapUrlEmpty { which, index });
    }
    if len > MAX_BOOTSTRAP_URL_LEN {
        return Err(SpecError::BootstrapUrlTooLong { which, index, len });
    }
    Ok(())
}

/// Closed §4.3 / §7.3 network labels — bare strings, not `zkCoins/v1/…` tags.
fn validate_closed_network(network: &str) -> Result<(), SpecError> {
    if network.is_empty() {
        return Err(SpecError::NetworkEmpty);
    }
    let bytes = network.as_bytes();
    if bytes == network_label_of(NETWORK_TAG_MAINNET)
        || bytes == network_label_of(NETWORK_TAG_TESTNET)
        || bytes == network_label_of(NETWORK_TAG_REGTEST)
    {
        return Ok(());
    }
    Err(SpecError::NetworkUnknown {
        network: network.to_string(),
    })
}

fn network_label_of(tag: &'static [u8]) -> &'static [u8] {
    match tag.rsplit(|b| *b == b'/').next() {
        Some(label) if !label.is_empty() => label,
        _ => unreachable!(
            "NETWORK_TAG_* constants are b\"zkCoins/v1/<label>\" with a non-empty label"
        ),
    }
}

// ---------------------------------------------------------------------------
// Public codec
// ---------------------------------------------------------------------------

/// `serialize(BootstrapManifestV1)` — full BMF1 frame including `manifest_sig`.
pub fn serialize(m: &BootstrapManifestV1) -> Result<Vec<u8>, SpecError> {
    validate_structure(m)?;
    let mut out = Vec::new();
    out.extend_from_slice(BMF1_MAGIC);
    out.push(BMF1_VERSION);
    write_framed_body(m, &mut out)?;
    out.extend_from_slice(&m.manifest_sig);
    Ok(out)
}

/// Decode a complete BMF1 frame. Rejects bad magic/version, bounds,
/// non-UTF-8, wrong fixed widths (via truncation), and trailing bytes.
pub fn deserialize(bytes: &[u8]) -> Result<BootstrapManifestV1, SpecError> {
    let mut cur = bytes;

    let magic = read_exact(&mut cur, 4, "magic")?;
    let mut magic_arr = [0u8; 4];
    magic_arr.copy_from_slice(magic);
    if &magic_arr != BMF1_MAGIC {
        return Err(SpecError::BootstrapMagicInvalid { got: magic_arr });
    }

    let version = read_exact(&mut cur, 1, "version")?[0];
    if version != BMF1_VERSION {
        return Err(SpecError::BootstrapVersionInvalid { got: version });
    }

    let network = read_u8_len_utf8(&mut cur, BootstrapStringField::Network)?;
    validate_closed_network(&network)?;

    let protocol_version = read_u8_len_utf8(&mut cur, BootstrapStringField::ProtocolVersion)?;
    if protocol_version != BOOTSTRAP_PROTOCOL_VERSION {
        return Err(SpecError::BootstrapProtocolVersionInvalid {
            got: protocol_version,
        });
    }

    let seed_relay_count = read_u16(&mut cur, "seed_relay_count")? as usize;
    if seed_relay_count == 0 {
        return Err(SpecError::BootstrapSeedRelayCountZero);
    }
    let mut seed_relays = Vec::with_capacity(seed_relay_count);
    for index in 0..seed_relay_count {
        seed_relays.push(read_u32_len_url(
            &mut cur,
            BootstrapUrlKind::SeedRelay,
            index,
        )?);
    }

    let blob_store_count = read_u16(&mut cur, "blob_store_count")? as usize;
    if blob_store_count == 0 {
        return Err(SpecError::BootstrapBlobStoreCountZero);
    }
    let mut blob_stores = Vec::with_capacity(blob_store_count);
    for index in 0..blob_store_count {
        blob_stores.push(read_u32_len_url(
            &mut cur,
            BootstrapUrlKind::BlobStore,
            index,
        )?);
    }

    let operator_id_count = read_u16(&mut cur, "operator_id_count")? as usize;
    if operator_id_count == 0 {
        return Err(SpecError::BootstrapOperatorIdCountZero);
    }
    let mut operator_ids = Vec::with_capacity(operator_id_count);
    for index in 0..operator_id_count {
        let raw = read_exact(&mut cur, 32, "op_pubkey")?;
        let mut pk = [0u8; 32];
        pk.copy_from_slice(raw);
        // index kept in the loop for stable framing; unused beyond bounds.
        let _ = index;
        operator_ids.push(pk);
    }

    let issued_raw = read_exact(&mut cur, 8, "issued_at")?;
    let mut issued_be = [0u8; 8];
    issued_be.copy_from_slice(issued_raw);
    let issued_at = u64::from_be_bytes(issued_be);

    let expires_raw = read_exact(&mut cur, 8, "expires_at")?;
    let mut expires_be = [0u8; 8];
    expires_be.copy_from_slice(expires_raw);
    let expires_at = u64::from_be_bytes(expires_be);

    let sig_raw = read_exact(&mut cur, 64, "manifest_sig")?;
    let mut manifest_sig = [0u8; 64];
    manifest_sig.copy_from_slice(sig_raw);

    if !cur.is_empty() {
        return Err(SpecError::BootstrapTrailingBytes {
            remaining: cur.len(),
        });
    }

    let m = BootstrapManifestV1 {
        network,
        protocol_version,
        seed_relays,
        blob_stores,
        operator_ids,
        issued_at,
        expires_at,
        manifest_sig,
    };
    // issued_at > expires_at rejected here so decode alone never yields a
    // degenerate lifetime (same rule as encode-side validate_structure).
    if m.issued_at > m.expires_at {
        return Err(SpecError::BootstrapIssuedAfterExpiry {
            issued_at: m.issued_at,
            expires_at: m.expires_at,
        });
    }
    Ok(m)
}

/// `bootstrap_message = H("zkCoins/v1/BootstrapManifest" ‖ body)` where
/// `body` is the framed `network … expires_at` from [`write_framed_body`].
///
/// Recomputed from **decoded fields**, never by slicing input bytes.
pub fn bootstrap_message(m: &BootstrapManifestV1) -> Result<[u8; 32], SpecError> {
    validate_structure(m)?;
    let mut preimage = Vec::with_capacity(TAG_BOOTSTRAP_MANIFEST.len() + 256);
    preimage.extend_from_slice(TAG_BOOTSTRAP_MANIFEST);
    write_framed_body(m, &mut preimage)?;
    let dig = Sha256::digest(&preimage);
    let mut out = [0u8; 32];
    out.copy_from_slice(&dig);
    Ok(out)
}

/// `manifest_id = SHA-256(serialize(BootstrapManifestV1))` — full frame
/// including `manifest_sig`.
pub fn manifest_id(m: &BootstrapManifestV1) -> Result<[u8; 32], SpecError> {
    let bytes = serialize(m)?;
    let dig = Sha256::digest(&bytes);
    let mut out = [0u8; 32];
    out.copy_from_slice(&dig);
    Ok(out)
}

/// Trust-anchor verification (§7.7 four steps, in order).
///
/// 1. Use `pinned_bootstrap_pubkey` from the frozen parameter set (caller).
/// 2. Recompute [`bootstrap_message`] from decoded fields.
/// 3. BIP-340-verify `manifest_sig` under that pin.
/// 4. Reject on signature failure, network / protocol mismatch, or
///    `expires_at < now` when a clock is available.
pub fn verify_bootstrap_manifest(
    m: &BootstrapManifestV1,
    VerifyBootstrapManifest {
        pinned_bootstrap_pubkey,
        expected_network,
        expected_protocol_version,
        clock,
    }: VerifyBootstrapManifest<'_>,
) -> Result<(), SpecError> {
    // Structural bounds first (counts, URLs, closed network, protocol, lifetime).
    validate_structure(m)?;

    // Step 2: recompute preimage from fields (not wire slices).
    let msg = bootstrap_message(m)?;

    // Step 3: BIP-340 under the **pinned** key only.
    let secp = Secp256k1::verification_only();
    let xonly = XOnlyPublicKey::from_slice(pinned_bootstrap_pubkey.as_slice())
        .map_err(|_| SpecError::BootstrapSignatureInvalid)?;
    let message = Message::from_digest(msg);
    let sig = bitcoin::secp256k1::schnorr::Signature::from_slice(&m.manifest_sig)
        .map_err(|_| SpecError::BootstrapSignatureInvalid)?;
    secp.verify_schnorr(&sig, &message, &xonly)
        .map_err(|_| SpecError::BootstrapSignatureInvalid)?;

    // Step 4: network / protocol / expiry.
    if m.network != expected_network {
        return Err(SpecError::BootstrapNetworkMismatch {
            expected: expected_network.to_string(),
            actual: m.network.clone(),
        });
    }
    if m.protocol_version != expected_protocol_version {
        return Err(SpecError::BootstrapProtocolVersionMismatch {
            expected: expected_protocol_version.to_string(),
            actual: m.protocol_version.clone(),
        });
    }
    if let ManifestClock::UnixSeconds(now) = clock {
        if m.expires_at < now {
            return Err(SpecError::BootstrapExpired {
                expires_at: m.expires_at,
                now,
            });
        }
    }

    Ok(())
}

/// Sign a §4.3 BootstrapManifest under the network bootstrap secret.
///
/// Order (fail-closed):
/// 1. Parse `secret_key` as a secp256k1 scalar.
/// 2. Derive the BIP-340 x-only public key; require exact equality with
///    `expected_bootstrap_pubkey` (the network pin the node will use).
/// 3. Validate body structure (same rules as encode/verify).
/// 4. BIP-340-sign [`bootstrap_message`] with no aux randomness
///    (deterministic; matches the in-tree test vectors).
///
/// On any error, nothing is returned that could be written as a BMF1
/// artifact. Key bytes never appear in [`SpecError`] display strings.
pub fn sign_bootstrap_manifest(
    body: BootstrapManifestBody,
    SignBootstrapManifest {
        secret_key,
        expected_bootstrap_pubkey,
    }: SignBootstrapManifest<'_>,
) -> Result<BootstrapManifestV1, SpecError> {
    let secp = Secp256k1::new();
    let sk = SecretKey::from_slice(secret_key.as_slice())
        .map_err(|_| SpecError::BootstrapSecretKeyInvalid)?;
    let kp = Keypair::from_secret_key(&secp, &sk);
    let (xonly, _) = kp.x_only_public_key();
    let derived = xonly.serialize();
    if derived.as_slice() != expected_bootstrap_pubkey.as_slice() {
        return Err(SpecError::BootstrapPubkeyMismatch);
    }

    let mut m = BootstrapManifestV1 {
        network: body.network,
        protocol_version: body.protocol_version,
        seed_relays: body.seed_relays,
        blob_stores: body.blob_stores,
        operator_ids: body.operator_ids,
        issued_at: body.issued_at,
        expires_at: body.expires_at,
        manifest_sig: [0u8; 64],
    };
    // Structural bounds before hashing/signing (counts, URLs, network, lifetime).
    validate_structure(&m)?;
    let msg = bootstrap_message(&m)?;
    let sig = secp.sign_schnorr_no_aux_rand(&Message::from_digest(msg), &kp);
    m.manifest_sig = *sig.as_ref();
    Ok(m)
}

/// Sign then [`serialize`] — full BMF1 bytes ready to write to disk.
///
/// Convenience for operator tools: one call that either yields complete
/// verified-domain bytes or an error (no partial frame).
pub fn sign_and_serialize_bootstrap_manifest(
    body: BootstrapManifestBody,
    sign: SignBootstrapManifest<'_>,
) -> Result<Vec<u8>, SpecError> {
    let m = sign_bootstrap_manifest(body, sign)?;
    serialize(&m)
}

// ---------------------------------------------------------------------------
// Cursor helpers
// ---------------------------------------------------------------------------

fn read_exact<'a>(
    cur: &mut &'a [u8],
    n: usize,
    context: &'static str,
) -> Result<&'a [u8], SpecError> {
    if cur.len() < n {
        return Err(SpecError::BootstrapTruncated {
            context,
            needed: n,
            remaining: cur.len(),
        });
    }
    let (head, tail) = cur.split_at(n);
    *cur = tail;
    Ok(head)
}

fn read_u16(cur: &mut &[u8], context: &'static str) -> Result<u16, SpecError> {
    let raw = read_exact(cur, 2, context)?;
    Ok(u16::from_be_bytes([raw[0], raw[1]]))
}

fn read_u8_len_utf8(cur: &mut &[u8], field: BootstrapStringField) -> Result<String, SpecError> {
    let len = read_exact(cur, 1, "string_len")?[0] as usize;
    let raw = read_exact(cur, len, "string_bytes")?;
    let s = std::str::from_utf8(raw).map_err(|e| SpecError::BootstrapInvalidUtf8 {
        field,
        error: e.to_string(),
    })?;
    Ok(s.to_string())
}

fn read_u32_len_url(
    cur: &mut &[u8],
    which: BootstrapUrlKind,
    index: usize,
) -> Result<String, SpecError> {
    let len_raw = read_exact(cur, 4, "url_len")?;
    let len = u32::from_be_bytes([len_raw[0], len_raw[1], len_raw[2], len_raw[3]]) as usize;
    if len == 0 {
        return Err(SpecError::BootstrapUrlEmpty { which, index });
    }
    if len > MAX_BOOTSTRAP_URL_LEN {
        return Err(SpecError::BootstrapUrlTooLong { which, index, len });
    }
    let raw = read_exact(cur, len, "url_bytes")?;
    let field = match which {
        BootstrapUrlKind::SeedRelay => BootstrapStringField::SeedRelay { index },
        BootstrapUrlKind::BlobStore => BootstrapStringField::BlobStore { index },
    };
    let s = std::str::from_utf8(raw).map_err(|e| SpecError::BootstrapInvalidUtf8 {
        field,
        error: e.to_string(),
    })?;
    Ok(s.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;
    use bitcoin::secp256k1::{Keypair, SecretKey};

    fn fixture_sk(label: &[u8]) -> ([u8; 32], [u8; 32]) {
        // Deterministic test key from SHA-256(label), reduced until valid.
        let mut seed = Sha256::digest(label).to_vec();
        let secp = Secp256k1::new();
        loop {
            let mut sk_bytes = [0u8; 32];
            sk_bytes.copy_from_slice(&seed[..32]);
            if let Ok(sk) = SecretKey::from_slice(&sk_bytes) {
                let kp = Keypair::from_secret_key(&secp, &sk);
                let (xonly, _) = kp.x_only_public_key();
                return (sk_bytes, xonly.serialize());
            }
            seed = Sha256::digest(&seed).to_vec();
        }
    }

    fn sample_body() -> BootstrapManifestBody {
        BootstrapManifestBody {
            network: "regtest".to_string(),
            protocol_version: "v1".to_string(),
            seed_relays: vec!["wss://relay.example.com".to_string()],
            blob_stores: vec!["https://blossom.example.com".to_string()],
            operator_ids: vec![[0x11; 32]],
            issued_at: 1_700_000_000,
            expires_at: 1_800_000_000,
        }
    }

    /// Re-sign an already-built struct in place (field-flip tests).
    fn sign_manifest(m: &mut BootstrapManifestV1, sk_bytes: &[u8; 32]) {
        let body = BootstrapManifestBody {
            network: m.network.clone(),
            protocol_version: m.protocol_version.clone(),
            seed_relays: m.seed_relays.clone(),
            blob_stores: m.blob_stores.clone(),
            operator_ids: m.operator_ids.clone(),
            issued_at: m.issued_at,
            expires_at: m.expires_at,
        };
        let secp = Secp256k1::new();
        let sk = SecretKey::from_slice(sk_bytes).expect("test sk");
        let kp = Keypair::from_secret_key(&secp, &sk);
        let (xonly, _) = kp.x_only_public_key();
        let pk = xonly.serialize();
        *m = sign_bootstrap_manifest(
            body,
            SignBootstrapManifest {
                secret_key: sk_bytes,
                expected_bootstrap_pubkey: &pk,
            },
        )
        .expect("re-sign");
    }

    fn sample_unsigned() -> BootstrapManifestV1 {
        let b = sample_body();
        BootstrapManifestV1 {
            network: b.network,
            protocol_version: b.protocol_version,
            seed_relays: b.seed_relays,
            blob_stores: b.blob_stores,
            operator_ids: b.operator_ids,
            issued_at: b.issued_at,
            expires_at: b.expires_at,
            manifest_sig: [0u8; 64],
        }
    }

    fn sample_signed() -> (BootstrapManifestV1, [u8; 32]) {
        let (sk, pk) = fixture_sk(b"zkCoins/v1/test-vector/bootstrap-pubkey");
        let m = sign_bootstrap_manifest(
            sample_body(),
            SignBootstrapManifest {
                secret_key: &sk,
                expected_bootstrap_pubkey: &pk,
            },
        )
        .expect("sign");
        (m, pk)
    }

    fn multi_signed() -> (BootstrapManifestV1, [u8; 32]) {
        let (sk, pk) = fixture_sk(b"zkCoins/v1/test-vector/bootstrap-pubkey");
        let m = sign_bootstrap_manifest(
            BootstrapManifestBody {
                network: "testnet".to_string(),
                protocol_version: "v1".to_string(),
                seed_relays: vec![
                    "wss://a.example".to_string(),
                    "wss://b.example".to_string(),
                    "wss://c.example".to_string(),
                ],
                blob_stores: vec![
                    "https://blob1.example".to_string(),
                    "https://blob2.example".to_string(),
                ],
                operator_ids: vec![[0xAAu8; 32], [0xBBu8; 32], [0xCCu8; 32]],
                issued_at: 10,
                expires_at: 20,
            },
            SignBootstrapManifest {
                secret_key: &sk,
                expected_bootstrap_pubkey: &pk,
            },
        )
        .expect("sign multi");
        (m, pk)
    }

    #[test]
    fn sign_path_verifies_under_derived_pin() {
        let (sk, pk) = fixture_sk(b"zkCoins/v1/test-vector/bootstrap-pubkey");
        let bytes = sign_and_serialize_bootstrap_manifest(
            sample_body(),
            SignBootstrapManifest {
                secret_key: &sk,
                expected_bootstrap_pubkey: &pk,
            },
        )
        .expect("sign+ser");
        let m = deserialize(&bytes).expect("de");
        verify_ok(
            &m,
            &pk,
            "regtest",
            ManifestClock::UnixSeconds(1_750_000_000),
        );
        assert_eq!(&bytes[..4], BMF1_MAGIC.as_slice());
    }

    #[test]
    fn sign_path_refuses_pubkey_mismatch() {
        let (sk, _pk) = fixture_sk(b"zkCoins/v1/test-vector/bootstrap-pubkey");
        let (_sk_o, pk_other) = fixture_sk(b"zkCoins/v1/test-vector/bootstrap-pubkey-OTHER");
        let err = sign_bootstrap_manifest(
            sample_body(),
            SignBootstrapManifest {
                secret_key: &sk,
                expected_bootstrap_pubkey: &pk_other,
            },
        )
        .expect_err("mismatch");
        assert_eq!(err, SpecError::BootstrapPubkeyMismatch);
        // Display must not leak key material.
        let msg = err.to_string();
        assert!(!msg.contains(&hex::encode(sk)));
        assert!(!msg.contains(&hex::encode(pk_other)));
    }

    #[test]
    fn sign_path_refuses_invalid_secret() {
        let bad = [0u8; 32]; // zero scalar
        let fake_pk = [0xABu8; 32];
        let err = sign_bootstrap_manifest(
            sample_body(),
            SignBootstrapManifest {
                secret_key: &bad,
                expected_bootstrap_pubkey: &fake_pk,
            },
        )
        .expect_err("zero sk");
        assert_eq!(err, SpecError::BootstrapSecretKeyInvalid);
    }

    fn verify_ok(m: &BootstrapManifestV1, pk: &[u8; 32], network: &str, clock: ManifestClock) {
        verify_bootstrap_manifest(
            m,
            VerifyBootstrapManifest {
                pinned_bootstrap_pubkey: pk,
                expected_network: network,
                expected_protocol_version: BOOTSTRAP_PROTOCOL_VERSION,
                clock,
            },
        )
        .expect("verify");
    }

    #[test]
    fn roundtrip_single_and_multi() {
        for (m, _) in [sample_signed(), multi_signed()] {
            let bytes = serialize(&m).expect("ser");
            let back = deserialize(&bytes).expect("de");
            assert_eq!(back, m);
            let again = serialize(&back).expect("ser2");
            assert_eq!(again, bytes, "encode → decode → encode must be identity");
        }
    }

    #[test]
    fn bootstrap_message_differs_from_manifest_id() {
        let (m, _) = sample_signed();
        let msg = bootstrap_message(&m).expect("msg");
        let id = manifest_id(&m).expect("id");
        assert_ne!(
            msg, id,
            "bootstrap_message hashes domain‖body; manifest_id hashes full serialize including sig"
        );

        // Prove they hash different preimages: body-only vs full frame.
        let mut body = Vec::new();
        body.extend_from_slice(TAG_BOOTSTRAP_MANIFEST);
        write_framed_body(&m, &mut body).expect("body");
        let body_hash = Sha256::digest(&body);
        assert_eq!(msg.as_slice(), body_hash.as_slice());

        let full = serialize(&m).expect("full");
        let full_hash = Sha256::digest(&full);
        assert_eq!(id.as_slice(), full_hash.as_slice());
        assert_ne!(body.as_slice(), full.as_slice());
        // Full frame starts with magic; body preimage starts with domain tag.
        assert_eq!(&full[..4], BMF1_MAGIC.as_slice());
        assert_eq!(
            &body[..TAG_BOOTSTRAP_MANIFEST.len()],
            TAG_BOOTSTRAP_MANIFEST
        );
    }

    /// One row in the body-field flip table: which field name, and how to flip it.
    struct FlipCase {
        field: &'static str,
        flip: fn(&mut BootstrapManifestV1),
    }

    /// Typed body-field flips: each entry mutates **exactly one** named field
    /// of a signed manifest; verify must then fail with
    /// [`SpecError::BootstrapSignatureInvalid`].
    ///
    /// `protocol_version` is typed-closed to `"v1"` and cannot be flipped on
    /// the value — it is covered by
    /// [`protocol_version_wire_bit_flip_invalidates_signature`].
    ///
    /// Coverage inventory (compile-time + table):
    /// - Every `BootstrapManifestV1` field is named in the exhaustive
    ///   destructure below; a new struct field is a compile error until
    ///   acknowledged here (and covered, or explicitly excluded with a note).
    /// - Vector slots are listed by index; fixture lengths are asserted so a
    ///   longer fixture without a new row fails loudly.
    #[test]
    fn signature_binds_every_body_field() {
        let (sk, pk) = fixture_sk(b"zkCoins/v1/test-vector/bootstrap-pubkey");
        let base = {
            let mut m = multi_signed().0;
            m.network = "regtest".to_string();
            // Lifetime window far wider than one LSB: `issued_at ^= 1` and
            // `expires_at ^= 1` each move a timestamp by ±1, so neither can
            // make `issued_at > expires_at`. Both values even so the LSB flip
            // is a pure +1, not a swap across the bound.
            m.issued_at = 1_700_000_000;
            m.expires_at = 1_800_000_000;
            sign_manifest(&mut m, &sk);
            m
        };
        verify_ok(&base, &pk, "regtest", ManifestClock::Unavailable);

        // Compile-time: name every field. `protocol_version` → wire test;
        // `manifest_sig` is the signature itself, not a signed body field.
        let BootstrapManifestV1 {
            network: _,
            protocol_version: _,
            seed_relays: _,
            blob_stores: _,
            operator_ids: _,
            issued_at: _,
            expires_at: _,
            manifest_sig: _,
        } = &base;

        assert_eq!(
            base.seed_relays.len(),
            3,
            "update flip table if fixture grows"
        );
        assert_eq!(
            base.blob_stores.len(),
            2,
            "update flip table if fixture grows"
        );
        assert_eq!(
            base.operator_ids.len(),
            3,
            "update flip table if fixture grows"
        );

        // `fn` pointers — no `Box<dyn Fn…>`; each row is a single-field mutation.
        let cases: &[FlipCase] = &[
            FlipCase {
                field: "network",
                flip: |m| m.network = "testnet".to_string(),
            },
            FlipCase {
                field: "seed_relays[0]",
                flip: |m| m.seed_relays[0].push('X'),
            },
            FlipCase {
                field: "seed_relays[1]",
                flip: |m| m.seed_relays[1].push('Y'),
            },
            FlipCase {
                field: "seed_relays[2]",
                flip: |m| m.seed_relays[2].push('Z'),
            },
            FlipCase {
                field: "blob_stores[0]",
                flip: |m| m.blob_stores[0].push('A'),
            },
            FlipCase {
                field: "blob_stores[1]",
                flip: |m| m.blob_stores[1].push('B'),
            },
            FlipCase {
                field: "operator_ids[0]",
                flip: |m| m.operator_ids[0][0] ^= 0x01,
            },
            FlipCase {
                field: "operator_ids[1]",
                flip: |m| m.operator_ids[1][0] ^= 0x01,
            },
            FlipCase {
                field: "operator_ids[2]",
                flip: |m| m.operator_ids[2][0] ^= 0x01,
            },
            FlipCase {
                field: "issued_at",
                flip: |m| m.issued_at ^= 1,
            },
            FlipCase {
                field: "expires_at",
                flip: |m| m.expires_at ^= 1,
            },
        ];

        for case in cases {
            let mut m = base.clone();
            (case.flip)(&mut m);
            // Isolation: after flipping `field`, restoring only that field
            // must recover the base — proves the row changed nothing else.
            // Closed if/else chain (no dead `other` arm): an unknown field
            // leaves `restored != base` and fails the assert below.
            let mut restored = m.clone();
            if case.field == "network" {
                restored.network = base.network.clone();
            } else if case.field == "seed_relays[0]" {
                restored.seed_relays[0] = base.seed_relays[0].clone();
            } else if case.field == "seed_relays[1]" {
                restored.seed_relays[1] = base.seed_relays[1].clone();
            } else if case.field == "seed_relays[2]" {
                restored.seed_relays[2] = base.seed_relays[2].clone();
            } else if case.field == "blob_stores[0]" {
                restored.blob_stores[0] = base.blob_stores[0].clone();
            } else if case.field == "blob_stores[1]" {
                restored.blob_stores[1] = base.blob_stores[1].clone();
            } else if case.field == "operator_ids[0]" {
                restored.operator_ids[0] = base.operator_ids[0];
            } else if case.field == "operator_ids[1]" {
                restored.operator_ids[1] = base.operator_ids[1];
            } else if case.field == "operator_ids[2]" {
                restored.operator_ids[2] = base.operator_ids[2];
            } else if case.field == "issued_at" {
                restored.issued_at = base.issued_at;
            } else if case.field == "expires_at" {
                restored.expires_at = base.expires_at;
            }
            assert_eq!(
                restored, base,
                "flip of {} must change only that field",
                case.field
            );
            assert_ne!(&m, &base, "flip of {} must change the manifest", case.field);

            let err = verify_bootstrap_manifest(
                &m,
                VerifyBootstrapManifest {
                    pinned_bootstrap_pubkey: &pk,
                    expected_network: "regtest",
                    expected_protocol_version: BOOTSTRAP_PROTOCOL_VERSION,
                    clock: ManifestClock::Unavailable,
                },
            )
            .expect_err(case.field);
            // Body change ⇒ signature over bootstrap_message fails first
            // (before network/protocol mismatch branches can fire).
            assert_eq!(
                err,
                SpecError::BootstrapSignatureInvalid,
                "field {} bit-flip must fail signature, got {err:?}",
                case.field
            );
        }
    }

    /// `protocol_version` is closed to `"v1"` on the typed value, so it cannot
    /// appear in the typed flip table. Cover it on the wire: flip one byte of
    /// the framed signed body at the protocol string and show the original
    /// signature does not verify over the altered preimage
    /// (`IncorrectSignature`).
    #[test]
    fn protocol_version_wire_bit_flip_invalidates_signature() {
        let (sk, pk) = fixture_sk(b"zkCoins/v1/test-vector/bootstrap-pubkey");
        let base = {
            let mut m = multi_signed().0;
            m.network = "regtest".to_string();
            m.issued_at = 1_700_000_000;
            m.expires_at = 1_800_000_000;
            sign_manifest(&mut m, &sk);
            m
        };
        verify_ok(&base, &pk, "regtest", ManifestClock::Unavailable);

        // Preimage = domain tag ‖ framed body; body layout after the tag is
        // net_len‖net‖pv_len‖pv‖… — first byte of "v1" sits at this offset.
        let mut body = Vec::new();
        body.extend_from_slice(TAG_BOOTSTRAP_MANIFEST);
        write_framed_body(&base, &mut body).expect("body");
        let body_pv = TAG_BOOTSTRAP_MANIFEST.len() + 1 + base.network.len() + 1;
        assert_eq!(&body[body_pv..body_pv + 2], b"v1");
        body[body_pv] ^= 0x01;

        let flipped_msg: [u8; 32] = Sha256::digest(&body).into();
        let good_msg = bootstrap_message(&base).expect("msg");
        assert_ne!(
            flipped_msg, good_msg,
            "protocol_version bit must change preimage"
        );

        let secp = Secp256k1::verification_only();
        let xonly = XOnlyPublicKey::from_slice(&pk).unwrap();
        let sig = bitcoin::secp256k1::schnorr::Signature::from_slice(&base.manifest_sig).unwrap();
        assert_eq!(
            secp.verify_schnorr(&sig, &Message::from_digest(flipped_msg), &xonly),
            Err(bitcoin::secp256k1::Error::IncorrectSignature),
            "protocol_version bit-flip must invalidate signature as IncorrectSignature"
        );
    }

    #[test]
    fn foreign_key_is_rejected() {
        let (m, _pk) = sample_signed();
        let (_sk_other, pk_other) = fixture_sk(b"zkCoins/v1/test-vector/bootstrap-pubkey-OTHER");
        let err = verify_bootstrap_manifest(
            &m,
            VerifyBootstrapManifest {
                pinned_bootstrap_pubkey: &pk_other,
                expected_network: "regtest",
                expected_protocol_version: BOOTSTRAP_PROTOCOL_VERSION,
                clock: ManifestClock::Unavailable,
            },
        )
        .expect_err("foreign pin");
        assert_eq!(err, SpecError::BootstrapSignatureInvalid);
    }

    #[test]
    fn wrong_network_rejected_even_when_sig_valid() {
        let (sk, pk) = fixture_sk(b"zkCoins/v1/test-vector/bootstrap-pubkey");
        let mut m = sample_unsigned();
        m.network = "testnet".to_string();
        sign_manifest(&mut m, &sk);
        // Signature is valid for testnet under the pin.
        verify_ok(&m, &pk, "testnet", ManifestClock::Unavailable);
        // mainnet verifier must reject despite valid sig.
        let err = verify_bootstrap_manifest(
            &m,
            VerifyBootstrapManifest {
                pinned_bootstrap_pubkey: &pk,
                expected_network: "mainnet",
                expected_protocol_version: BOOTSTRAP_PROTOCOL_VERSION,
                clock: ManifestClock::Unavailable,
            },
        )
        .expect_err("network");
        assert_eq!(
            err,
            SpecError::BootstrapNetworkMismatch {
                expected: "mainnet".to_string(),
                actual: "testnet".to_string(),
            }
        );
    }

    #[test]
    fn expiry_checked_only_when_clock_present() {
        let (m, pk) = sample_signed();
        // expires_at = 1_800_000_000
        let err = verify_bootstrap_manifest(
            &m,
            VerifyBootstrapManifest {
                pinned_bootstrap_pubkey: &pk,
                expected_network: "regtest",
                expected_protocol_version: BOOTSTRAP_PROTOCOL_VERSION,
                clock: ManifestClock::UnixSeconds(1_800_000_001),
            },
        )
        .expect_err("expired");
        assert_eq!(
            err,
            SpecError::BootstrapExpired {
                expires_at: m.expires_at,
                now: 1_800_000_001,
            }
        );

        // No clock: expiry skipped; signature still checked.
        verify_ok(&m, &pk, "regtest", ManifestClock::Unavailable);

        // UnixSeconds(0) is a real time, not "no clock" — expires_at is far
        // in the future relative to 0, so this succeeds.
        verify_ok(&m, &pk, "regtest", ManifestClock::UnixSeconds(0));
    }

    #[test]
    fn decoder_rejects_each_fault_with_typed_cause() {
        let (m, _) = sample_signed();
        let good = serialize(&m).expect("ser");

        // Wrong magic
        {
            let mut b = good.clone();
            b[0] = b'X';
            let err = deserialize(&b).expect_err("magic");
            assert!(
                matches!(err, SpecError::BootstrapMagicInvalid { .. }),
                "{err:?}"
            );
        }
        // Wrong version
        {
            let mut b = good.clone();
            b[4] = 0x02;
            assert_eq!(
                deserialize(&b).expect_err("version"),
                SpecError::BootstrapVersionInvalid { got: 0x02 }
            );
        }
        // seed_relay_count == 0
        {
            let mut empty = sample_unsigned();
            empty.seed_relays.clear();
            empty.seed_relays.push("x".into()); // will rewrite count by hand
            let mut body = Vec::new();
            body.extend_from_slice(BMF1_MAGIC);
            body.push(BMF1_VERSION);
            write_u8_len_str("regtest", &mut body).unwrap();
            write_u8_len_str("v1", &mut body).unwrap();
            body.extend_from_slice(&0u16.to_be_bytes()); // count 0
                                                         // rest truncated intentionally
            assert_eq!(
                deserialize(&body).expect_err("count0"),
                SpecError::BootstrapSeedRelayCountZero
            );
        }
        // URL length 0
        {
            let mut body = Vec::new();
            body.extend_from_slice(BMF1_MAGIC);
            body.push(BMF1_VERSION);
            write_u8_len_str("regtest", &mut body).unwrap();
            write_u8_len_str("v1", &mut body).unwrap();
            body.extend_from_slice(&1u16.to_be_bytes());
            body.extend_from_slice(&0u32.to_be_bytes()); // url_len 0
            assert_eq!(
                deserialize(&body).expect_err("url0"),
                SpecError::BootstrapUrlEmpty {
                    which: BootstrapUrlKind::SeedRelay,
                    index: 0,
                }
            );
        }
        // URL length 2049
        {
            let mut body = Vec::new();
            body.extend_from_slice(BMF1_MAGIC);
            body.push(BMF1_VERSION);
            write_u8_len_str("regtest", &mut body).unwrap();
            write_u8_len_str("v1", &mut body).unwrap();
            body.extend_from_slice(&1u16.to_be_bytes());
            body.extend_from_slice(&2049u32.to_be_bytes());
            body.extend_from_slice(&vec![b'a'; 2049]);
            assert_eq!(
                deserialize(&body).expect_err("url2049"),
                SpecError::BootstrapUrlTooLong {
                    which: BootstrapUrlKind::SeedRelay,
                    index: 0,
                    len: 2049,
                }
            );
        }
        // Truncated
        {
            let err = deserialize(&good[..good.len() - 10]).expect_err("trunc");
            assert!(
                matches!(err, SpecError::BootstrapTruncated { .. }),
                "{err:?}"
            );
        }
        // Trailing bytes
        {
            let mut b = good.clone();
            b.push(0xFF);
            assert_eq!(
                deserialize(&b).expect_err("trail"),
                SpecError::BootstrapTrailingBytes { remaining: 1 }
            );
        }
        // op_pubkey wrong width (count=1 but only 16 bytes left before timestamps)
        {
            let mut body = Vec::new();
            body.extend_from_slice(BMF1_MAGIC);
            body.push(BMF1_VERSION);
            write_u8_len_str("regtest", &mut body).unwrap();
            write_u8_len_str("v1", &mut body).unwrap();
            body.extend_from_slice(&1u16.to_be_bytes());
            let url = b"wss://x";
            body.extend_from_slice(&(url.len() as u32).to_be_bytes());
            body.extend_from_slice(url);
            body.extend_from_slice(&1u16.to_be_bytes());
            body.extend_from_slice(&(url.len() as u32).to_be_bytes());
            body.extend_from_slice(url);
            body.extend_from_slice(&1u16.to_be_bytes()); // one op
            body.extend_from_slice(&[0u8; 16]); // only 16 of 32
            let err = deserialize(&body).expect_err("op width");
            assert!(
                matches!(
                    err,
                    SpecError::BootstrapTruncated {
                        context: "op_pubkey",
                        needed: 32,
                        remaining: 16
                    }
                ),
                "{err:?}"
            );
        }
        // Non-UTF-8 in network
        {
            let mut body = Vec::new();
            body.extend_from_slice(BMF1_MAGIC);
            body.push(BMF1_VERSION);
            body.push(2);
            body.extend_from_slice(&[0xC3, 0x28]); // invalid UTF-8
            let err = deserialize(&body).expect_err("utf8");
            assert!(
                matches!(err, SpecError::BootstrapInvalidUtf8 { field: BootstrapStringField::Network, .. }),
                "{err:?}"
            );
        }
    }

    #[test]
    fn issued_after_expiry_rejected() {
        let mut m = sample_unsigned();
        m.issued_at = 100;
        m.expires_at = 50;
        let err = serialize(&m).expect_err("ser");
        assert_eq!(
            err,
            SpecError::BootstrapIssuedAfterExpiry {
                issued_at: 100,
                expires_at: 50,
            }
        );
    }

    #[test]
    fn framing_single_source_roundtrip_bytes_stable() {
        let (m, _) = multi_signed();
        let mut body_a = Vec::new();
        write_framed_body(&m, &mut body_a).unwrap();
        let mut body_b = Vec::new();
        write_framed_body(&m, &mut body_b).unwrap();
        assert_eq!(body_a, body_b);

        let full = serialize(&m).unwrap();
        // body is full without magic(4)+version(1)+sig(64)
        assert_eq!(&full[5..full.len() - 64], body_a.as_slice());
    }

    #[test]
    fn closed_network_labels_match_network_tag_suffixes() {
        assert_eq!(network_label_of(NETWORK_TAG_MAINNET), b"mainnet");
        assert_eq!(network_label_of(NETWORK_TAG_TESTNET), b"testnet");
        assert_eq!(network_label_of(NETWORK_TAG_REGTEST), b"regtest");
        validate_closed_network("mainnet").unwrap();
        validate_closed_network("testnet").unwrap();
        validate_closed_network("regtest").unwrap();
        assert!(matches!(
            validate_closed_network("mutinynet"),
            Err(SpecError::NetworkUnknown { .. })
        ));
    }

    // -----------------------------------------------------------------------
    // Structural / decode / verify edge paths
    // -----------------------------------------------------------------------

    #[test]
    fn validate_structure_rejects_bad_protocol_and_empty_lists() {
        let mut m = sample_unsigned();
        m.protocol_version = "v2".into();
        assert!(matches!(
            serialize(&m),
            Err(SpecError::BootstrapProtocolVersionInvalid { .. })
        ));

        let mut m = sample_unsigned();
        m.seed_relays.clear();
        assert_eq!(serialize(&m), Err(SpecError::BootstrapSeedRelayCountZero));

        let mut m = sample_unsigned();
        m.blob_stores.clear();
        assert_eq!(serialize(&m), Err(SpecError::BootstrapBlobStoreCountZero));

        let mut m = sample_unsigned();
        m.operator_ids.clear();
        assert_eq!(serialize(&m), Err(SpecError::BootstrapOperatorIdCountZero));
    }

    #[test]
    fn validate_structure_rejects_empty_and_overlong_url() {
        let mut m = sample_unsigned();
        m.seed_relays[0] = String::new();
        assert_eq!(
            serialize(&m),
            Err(SpecError::BootstrapUrlEmpty {
                which: BootstrapUrlKind::SeedRelay,
                index: 0,
            })
        );

        let mut m = sample_unsigned();
        m.blob_stores[0] = "x".repeat(MAX_BOOTSTRAP_URL_LEN + 1);
        assert_eq!(
            serialize(&m),
            Err(SpecError::BootstrapUrlTooLong {
                which: BootstrapUrlKind::BlobStore,
                index: 0,
                len: MAX_BOOTSTRAP_URL_LEN + 1,
            })
        );
    }

    #[test]
    fn validate_closed_network_rejects_empty() {
        assert_eq!(validate_closed_network(""), Err(SpecError::NetworkEmpty));
    }

    #[test]
    #[should_panic(expected = "NETWORK_TAG_* constants")]
    fn network_label_of_trailing_slash_unreachable() {
        // Tag ending in `/` yields an empty label → unreachable! arm.
        let _ = network_label_of(b"zkCoins/v1/");
    }

    #[test]
    fn deserialize_rejects_bad_protocol_and_empty_counts() {
        // protocol_version != "v1"
        {
            let mut body = Vec::new();
            body.extend_from_slice(BMF1_MAGIC);
            body.push(BMF1_VERSION);
            write_u8_len_str("regtest", &mut body).unwrap();
            write_u8_len_str("v2", &mut body).unwrap();
            assert!(matches!(
                deserialize(&body),
                Err(SpecError::BootstrapProtocolVersionInvalid { got }) if got == "v2"
            ));
        }
        // blob_store_count == 0 (after one valid seed relay)
        {
            let mut body = Vec::new();
            body.extend_from_slice(BMF1_MAGIC);
            body.push(BMF1_VERSION);
            write_u8_len_str("regtest", &mut body).unwrap();
            write_u8_len_str("v1", &mut body).unwrap();
            body.extend_from_slice(&1u16.to_be_bytes());
            let url = b"wss://x";
            body.extend_from_slice(&(url.len() as u32).to_be_bytes());
            body.extend_from_slice(url);
            body.extend_from_slice(&0u16.to_be_bytes()); // blob_store_count = 0
            assert_eq!(
                deserialize(&body).expect_err("blob0"),
                SpecError::BootstrapBlobStoreCountZero
            );
        }
        // operator_id_count == 0
        {
            let mut body = Vec::new();
            body.extend_from_slice(BMF1_MAGIC);
            body.push(BMF1_VERSION);
            write_u8_len_str("regtest", &mut body).unwrap();
            write_u8_len_str("v1", &mut body).unwrap();
            body.extend_from_slice(&1u16.to_be_bytes());
            let url = b"wss://x";
            body.extend_from_slice(&(url.len() as u32).to_be_bytes());
            body.extend_from_slice(url);
            body.extend_from_slice(&1u16.to_be_bytes());
            body.extend_from_slice(&(url.len() as u32).to_be_bytes());
            body.extend_from_slice(url);
            body.extend_from_slice(&0u16.to_be_bytes()); // operator_id_count = 0
            assert_eq!(
                deserialize(&body).expect_err("op0"),
                SpecError::BootstrapOperatorIdCountZero
            );
        }
    }

    #[test]
    fn deserialize_rejects_issued_after_expiry() {
        let mut body = Vec::new();
        body.extend_from_slice(BMF1_MAGIC);
        body.push(BMF1_VERSION);
        write_u8_len_str("regtest", &mut body).unwrap();
        write_u8_len_str("v1", &mut body).unwrap();
        body.extend_from_slice(&1u16.to_be_bytes());
        let url = b"wss://x";
        body.extend_from_slice(&(url.len() as u32).to_be_bytes());
        body.extend_from_slice(url);
        body.extend_from_slice(&1u16.to_be_bytes());
        body.extend_from_slice(&(url.len() as u32).to_be_bytes());
        body.extend_from_slice(url);
        body.extend_from_slice(&1u16.to_be_bytes());
        body.extend_from_slice(&[0x11; 32]);
        body.extend_from_slice(&100u64.to_be_bytes()); // issued_at
        body.extend_from_slice(&50u64.to_be_bytes()); // expires_at < issued
        body.extend_from_slice(&[0u8; 64]); // sig
        assert_eq!(
            deserialize(&body).expect_err("issued>expires"),
            SpecError::BootstrapIssuedAfterExpiry {
                issued_at: 100,
                expires_at: 50,
            }
        );
    }

    #[test]
    fn verify_rejects_protocol_version_mismatch() {
        let (m, pk) = sample_signed();
        let err = verify_bootstrap_manifest(
            &m,
            VerifyBootstrapManifest {
                pinned_bootstrap_pubkey: &pk,
                expected_network: "regtest",
                expected_protocol_version: "v2",
                clock: ManifestClock::Unavailable,
            },
        )
        .expect_err("proto mismatch");
        assert_eq!(
            err,
            SpecError::BootstrapProtocolVersionMismatch {
                expected: "v2".into(),
                actual: "v1".into(),
            }
        );
    }

    #[test]
    fn deserialize_rejects_non_utf8_seed_relay_url() {
        let mut body = Vec::new();
        body.extend_from_slice(BMF1_MAGIC);
        body.push(BMF1_VERSION);
        write_u8_len_str("regtest", &mut body).unwrap();
        write_u8_len_str("v1", &mut body).unwrap();
        body.extend_from_slice(&1u16.to_be_bytes());
        // url_len=2, invalid UTF-8 bytes
        body.extend_from_slice(&2u32.to_be_bytes());
        body.extend_from_slice(&[0xC3, 0x28]);
        let err = deserialize(&body).expect_err("url utf8");
        assert!(
            matches!(
                err,
                SpecError::BootstrapInvalidUtf8 {
                    field: BootstrapStringField::SeedRelay { index: 0 },
                    ..
                }
            ),
            "{err:?}"
        );
    }

    #[test]
    fn deserialize_rejects_non_utf8_blob_store_url() {
        let mut body = Vec::new();
        body.extend_from_slice(BMF1_MAGIC);
        body.push(BMF1_VERSION);
        write_u8_len_str("regtest", &mut body).unwrap();
        write_u8_len_str("v1", &mut body).unwrap();
        body.extend_from_slice(&1u16.to_be_bytes());
        let url = b"wss://x";
        body.extend_from_slice(&(url.len() as u32).to_be_bytes());
        body.extend_from_slice(url);
        body.extend_from_slice(&1u16.to_be_bytes());
        body.extend_from_slice(&2u32.to_be_bytes());
        body.extend_from_slice(&[0xFF, 0xFE]);
        let err = deserialize(&body).expect_err("blob utf8");
        assert!(
            matches!(
                err,
                SpecError::BootstrapInvalidUtf8 {
                    field: BootstrapStringField::BlobStore { index: 0 },
                    ..
                }
            ),
            "{err:?}"
        );
    }
}
