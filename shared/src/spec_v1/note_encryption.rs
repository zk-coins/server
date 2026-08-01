//! Per-coin note keys, NIP44Binary envelope framing, and ZBE blob encryption.
//!
//! Implements §1.1 (x-only lift ECDH, HKDF mapping), §1.3 (per-coin keys +
//! `NIP44Binary` envelope seal/open), and §4.2.1 ZBE
//! (`derive_blob_key` / `zbe_seal` / `zbe_open`).
//!
//! # Scope boundary
//!
//! - **In scope:** ECDH shared secret (both directions), `K_tx` / `K_out` /
//!   `kb`, the UTF-8 `NIP44Binary` envelope preimage (`envelope_seal` /
//!   `envelope_open`), strict `base64url_no_pad`, and full ZBE
//!   ChaCha20-Poly1305 chunk seal/open (§4.2.1 steps 1–5).
//! - **Out of scope (Nostr block):** NIP-44 v2 AEAD + Base64 payload wrapping
//!   of the envelope plaintext; NIP-59 gift-wrap.
//!
//! # Stored-field discipline
//!
//! A wire `ciphertext` / `out_ciphertext` field stores the **UTF-8 of NIP-44's
//! Base64 AEAD payload**, never the decoded AEAD raw bytes and never the
//! binary plaintext `b`. [`envelope_seal`] / [`envelope_open`] operate on the
//! **inner** UTF-8 plaintext that NIP-44 encrypts/decrypts — the
//! `"zkcoins-bin-v1:" ‖ label ‖ ":" ‖ base64url_no_pad(b)` string. Do not feed
//! stored-field bytes into [`envelope_open`].
//!
//! Bundle blobs use a separate path: [`zbe_seal`] / [`zbe_open`] produce and
//! consume the raw ZBE ciphertext whose SHA-256 is `blob_id` (§4.2.1 / §7.4).

use bitcoin::secp256k1::{
    ecdh::shared_secret_point, Keypair, Parity, PublicKey, Secp256k1, SecretKey, XOnlyPublicKey,
};
use chacha20poly1305::{
    aead::{Aead, KeyInit, Payload},
    ChaCha20Poly1305, Key, Nonce,
};
use sha2::{Digest, Sha256};

use super::error::SpecError;
use super::hashes::hkdf_sha256;
use super::tags::{TAG_BLOB_AAD, TAG_BLOB_KEY, TAG_NOTE_KEY, TAG_OUT_KEY};

/// Fixed prefix of every NIP44Binary envelope plaintext (§1.3).
pub const ENVELOPE_PREFIX: &str = "zkcoins-bin-v1:";

/// Call-site label for `out_ciphertext` (`L = 32`).
pub const ENVELOPE_LABEL_K_TX: &str = "K_tx";

/// Call-site label for `CoinProof.ciphertext` (`L = 112`).
pub const ENVELOPE_LABEL_COIN: &str = "coin";

/// Expected binary length for `out_ciphertext` open.
pub const OUT_CIPHERTEXT_LEN: usize = 32;

/// Expected binary length for coin `ciphertext` open (`serialize(Coin)`).
pub const COIN_CIPHERTEXT_LEN: usize = 112;

/// ZBE plaintext chunk size in bytes (§4.2.1 step 2): `CHUNK = 65536`.
pub const ZBE_CHUNK: usize = 65_536;

/// ZBE on-wire magic: ASCII `"ZBE1"` (§4.2.1 step 4).
pub const ZBE_MAGIC: [u8; 4] = *b"ZBE1";

/// Poly1305 tag length in bytes (appended to every sealed chunk).
const ZBE_TAG_LEN: usize = 16;

/// AAD layout (§4.2.1): `"zkCoins/v1/Blob"` + `u32_be(N)` + `u32_be(i)`.
///
/// The prefix length is taken from the tag itself rather than restated as a
/// literal — a hand-written length is a second source of truth that silently
/// misframes every AAD the day the tag changes.
const ZBE_AAD_PREFIX_LEN: usize = TAG_BLOB_AAD.len();
const ZBE_AAD_LEN: usize = ZBE_AAD_PREFIX_LEN + 4 + 4;

/// secp256k1 field prime `p` (big-endian), BIP-340 / §1.1.
const SECP256K1_FIELD_P: [u8; 32] = [
    0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
    0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFE, 0xFF, 0xFF, 0xFC, 0x2F,
];

// ---------------------------------------------------------------------------
// Scalar / x-only validation
// ---------------------------------------------------------------------------

/// Parse a secret scalar in `[1, n)`. Fail-closed with a typed reason.
pub fn parse_scalar(bytes: &[u8]) -> Result<[u8; 32], SpecError> {
    if bytes.len() != 32 {
        return Err(SpecError::ScalarWrongLength {
            actual: bytes.len(),
        });
    }
    let mut arr = [0u8; 32];
    arr.copy_from_slice(bytes);
    if arr.iter().all(|&b| b == 0) {
        return Err(SpecError::ScalarZero);
    }
    // `SecretKey::from_slice` rejects 0 and ≥ n. Zero is already handled so a
    // remaining failure is ≥ n.
    match SecretKey::from_slice(&arr) {
        Ok(_) => Ok(arr),
        Err(_) => Err(SpecError::ScalarOutOfRange),
    }
}

/// Parse a canonical 32-byte BIP-340 x-only public key.
///
/// Rejects wrong length, `x ≥ p`, and off-curve x-coordinates. The point at
/// infinity has **no** 32-byte x-only encoding, so it cannot appear on this path.
pub fn parse_xonly(bytes: &[u8]) -> Result<[u8; 32], SpecError> {
    if bytes.len() != 32 {
        return Err(SpecError::XOnlyWrongLength {
            actual: bytes.len(),
        });
    }
    let mut arr = [0u8; 32];
    arr.copy_from_slice(bytes);
    if arr.as_slice() >= SECP256K1_FIELD_P.as_slice() {
        return Err(SpecError::XOnlyXGeP);
    }
    match XOnlyPublicKey::from_slice(&arr) {
        Ok(_) => Ok(arr),
        Err(_) => Err(SpecError::XOnlyOffCurve),
    }
}

/// BIP-340 x-only public key of `scalar·G` (even-y normalisation).
pub fn xonly_pubkey(scalar: &[u8; 32]) -> Result<[u8; 32], SpecError> {
    let sk_bytes = parse_scalar(scalar)?;
    let secp = Secp256k1::new();
    let sk = SecretKey::from_slice(&sk_bytes).expect("parse_scalar guarantees [1, n)");
    let kp = Keypair::from_secret_key(&secp, &sk);
    let (xonly, _parity) = kp.x_only_public_key();
    Ok(xonly.serialize())
}

// ---------------------------------------------------------------------------
// ECDH (§1.1 / §1.3)
// ---------------------------------------------------------------------------

/// `ECDH(k, P) = x(k · lift_x(P))` — 32-byte big-endian x-coordinate.
///
/// `lift_x` uses the even-y point (BIP-340). The sign ambiguity of the lift is
/// immaterial: `x(k·lift_x(P))` is identical for both candidate points (§1.1).
///
/// Sender: `ss = ecdh_shared_x(esk, IVPK)`.
/// Receiver: `ss = ecdh_shared_x(ivk, epk)` — **must** equal the sender value.
pub fn ecdh_shared_x(scalar: &[u8], peer_xonly: &[u8]) -> Result<[u8; 32], SpecError> {
    let sk_bytes = parse_scalar(scalar)?;
    let xonly_bytes = parse_xonly(peer_xonly)?;
    let sk = SecretKey::from_slice(&sk_bytes).expect("parse_scalar guarantees [1, n)");
    let xonly =
        XOnlyPublicKey::from_slice(&xonly_bytes).expect("parse_xonly guarantees on-curve x");
    // BIP-340 lift_x: even-y representative.
    let pk = PublicKey::from_x_only_public_key(xonly, Parity::Even);
    // Raw (x ‖ y) of k·P — first 32 bytes are the x-coordinate (§1.1).
    let xy = shared_secret_point(&pk, &sk);
    let mut x = [0u8; 32];
    x.copy_from_slice(&xy[..32]);
    Ok(x)
}

/// Sender-side shared secret: `ss = ECDH(esk, IVPK)`.
pub fn shared_secret_sender(esk: &[u8; 32], ivpk: &[u8; 32]) -> Result<[u8; 32], SpecError> {
    ecdh_shared_x(esk, ivpk)
}

/// Receiver-side shared secret: `ss = ECDH(ivk, epk)`.
pub fn shared_secret_receiver(ivk: &[u8; 32], epk: &[u8; 32]) -> Result<[u8; 32], SpecError> {
    ecdh_shared_x(ivk, epk)
}

// ---------------------------------------------------------------------------
// Key derivation (§1.3 / §4.2.1)
// ---------------------------------------------------------------------------

/// `K_tx = HKDF("zkCoins/v1/NoteKey", ss ‖ epk)`.
///
/// `epk` MUST be a canonical x-only encoding. `ss` is the 32-byte ECDH
/// x-coordinate (not re-interpreted as a curve point).
pub fn derive_note_key(ss: &[u8; 32], epk: &[u8; 32]) -> Result<[u8; 32], SpecError> {
    let epk = parse_xonly(epk)?;
    let mut material = [0u8; 64];
    material[..32].copy_from_slice(ss);
    material[32..].copy_from_slice(&epk);
    Ok(hkdf_sha256(TAG_NOTE_KEY, &material))
}

/// `K_out = HKDF("zkCoins/v1/OutKey", ovk ‖ epk)`.
///
/// `ovk` MUST be a scalar in `[1, n)`; `epk` MUST be a canonical x-only key.
pub fn derive_out_key(ovk: &[u8; 32], epk: &[u8; 32]) -> Result<[u8; 32], SpecError> {
    let ovk = parse_scalar(ovk)?;
    let epk = parse_xonly(epk)?;
    let mut material = [0u8; 64];
    material[..32].copy_from_slice(&ovk);
    material[32..].copy_from_slice(&epk);
    Ok(hkdf_sha256(TAG_OUT_KEY, &material))
}

/// `kb = HKDF("zkCoins/v1/BlobKey", K_tx)` — ZBE AEAD key (§4.2.1 step 1).
///
/// This is the single-argument instance of the §1.1 HKDF mapping
/// (`material = K_tx`).
pub fn derive_blob_key(k_tx: &[u8; 32]) -> [u8; 32] {
    hkdf_sha256(TAG_BLOB_KEY, k_tx)
}

// ---------------------------------------------------------------------------
// ZBE — zkCoins Bundle Encryption (§4.2.1 steps 2–5)
// ---------------------------------------------------------------------------

/// `N = ceil(len(P) / CHUNK)`, with `N >= 1` (empty blob ⇒ `N = 1`).
fn zbe_chunk_count(plaintext_len: usize) -> Result<u32, SpecError> {
    let n = if plaintext_len == 0 {
        1usize
    } else {
        plaintext_len.div_ceil(ZBE_CHUNK)
    };
    u32::try_from(n).map_err(|_| SpecError::ZbeTooManyChunks { n })
}

/// `nonce_i = 0x00000000 ‖ u64_be(i)` — 12 bytes (§4.2.1 step 3).
fn zbe_nonce(i: u32) -> [u8; 12] {
    let mut nonce = [0u8; 12];
    nonce[4..].copy_from_slice(&(u64::from(i)).to_be_bytes());
    nonce
}

/// `aad_i = "zkCoins/v1/Blob" ‖ u32_be(N) ‖ u32_be(i)` (§4.2.1 step 3).
fn zbe_aad(n: u32, i: u32) -> [u8; ZBE_AAD_LEN] {
    let mut aad = [0u8; ZBE_AAD_LEN];
    aad[..ZBE_AAD_PREFIX_LEN].copy_from_slice(TAG_BLOB_AAD);
    aad[ZBE_AAD_PREFIX_LEN..ZBE_AAD_PREFIX_LEN + 4].copy_from_slice(&n.to_be_bytes());
    aad[ZBE_AAD_PREFIX_LEN + 4..ZBE_AAD_LEN].copy_from_slice(&i.to_be_bytes());
    aad
}

/// Seal plaintext `P` under `K_tx` as a ZBE ciphertext (§4.2.1 steps 1–5).
///
/// Returns `(ciphertext, blob_id)` where `blob_id = SHA-256(ciphertext)`.
/// Deterministic: the same `(K_tx, P)` always yields the same pair.
pub fn zbe_seal(k_tx: &[u8; 32], plaintext: &[u8]) -> Result<(Vec<u8>, [u8; 32]), SpecError> {
    let n = zbe_chunk_count(plaintext.len())?;
    let kb = derive_blob_key(k_tx);
    let cipher = ChaCha20Poly1305::new(Key::from_slice(&kb));

    // Header: magic ‖ u32_be(N). Body: ∑ (u32_be(len C_i) ‖ C_i).
    let mut ciphertext =
        Vec::with_capacity(4 + 4 + plaintext.len() + (n as usize) * (4 + ZBE_TAG_LEN));
    ciphertext.extend_from_slice(&ZBE_MAGIC);
    ciphertext.extend_from_slice(&n.to_be_bytes());

    for i in 0..n {
        let start = (i as usize) * ZBE_CHUNK;
        let end = core::cmp::min(start + ZBE_CHUNK, plaintext.len());
        let p_i = &plaintext[start..end];
        let nonce_bytes = zbe_nonce(i);
        let nonce = Nonce::from_slice(&nonce_bytes);
        let aad = zbe_aad(n, i);
        // Chunk size ≤ CHUNK; ChaCha20-Poly1305 accepts this bound.
        let c_i = cipher
            .encrypt(
                nonce,
                Payload {
                    msg: p_i,
                    aad: &aad,
                },
            )
            .expect("ZBE chunk size is within ChaCha20-Poly1305 limits");
        let c_len = u32::try_from(c_i.len()).expect("C_i length fits u32 (CHUNK + tag)");
        ciphertext.extend_from_slice(&c_len.to_be_bytes());
        ciphertext.extend_from_slice(&c_i);
    }

    let blob_id: [u8; 32] = Sha256::digest(&ciphertext).into();
    Ok((ciphertext, blob_id))
}

/// Open a ZBE ciphertext under `K_tx` (§4.2.1 decryption).
///
/// Fail-closed: wrong magic, framing errors, trailing bytes, or **any**
/// Poly1305 tag failure abort the whole open. Partially decrypted plaintext
/// is never returned — the `Ok` path only exists after every chunk authenticates,
/// so a caller cannot observe a prefix of successful chunks.
pub fn zbe_open(k_tx: &[u8; 32], ciphertext: &[u8]) -> Result<Vec<u8>, SpecError> {
    // --- Phase 1: pure framing parse (no AEAD, no plaintext) ---------------
    if ciphertext.len() < 8 {
        return Err(SpecError::ZbeTruncated);
    }
    if ciphertext[..4] != ZBE_MAGIC {
        return Err(SpecError::ZbeWrongMagic);
    }
    let n = u32::from_be_bytes(ciphertext[4..8].try_into().expect("slice length is 4"));
    if n == 0 {
        return Err(SpecError::ZbeInvalidChunkCount { n: 0 });
    }

    let mut offset = 8usize;
    let mut sealed_chunks: Vec<&[u8]> = Vec::with_capacity(n as usize);
    for i in 0..n {
        if ciphertext.len() < offset + 4 {
            // Ran out before the i-th length prefix — fewer framed chunks than N.
            return Err(SpecError::ZbeChunkCountMismatch {
                declared: n,
                parsed: i,
            });
        }
        let len = u32::from_be_bytes(
            ciphertext[offset..offset + 4]
                .try_into()
                .expect("slice length is 4"),
        );
        offset += 4;
        let remaining = ciphertext.len() - offset;
        let len_usize = len as usize;
        if len_usize > remaining {
            return Err(SpecError::ZbeChunkLengthOverrun {
                chunk_index: i,
                declared_len: len,
                remaining,
            });
        }
        if len < ZBE_TAG_LEN as u32 {
            return Err(SpecError::ZbeChunkTooShort {
                chunk_index: i,
                len,
            });
        }
        sealed_chunks.push(&ciphertext[offset..offset + len_usize]);
        offset += len_usize;
    }
    if offset != ciphertext.len() {
        return Err(SpecError::ZbeTrailingBytes {
            remaining: ciphertext.len() - offset,
        });
    }
    // At this point `sealed_chunks.len() == n` by construction of the loop.

    // --- Phase 2: authenticate every chunk; only then assemble plaintext -----
    // Each chunk is decrypted into its own `Vec<u8>` and collected via
    // `Result::collect`. The iterator short-circuits on the first
    // `ZbeAuthFailed`, so a concatenated plaintext buffer is not built at all
    // unless every tag verifies. The sole `Ok` return path is
    // `plain_chunks.concat()` after that collection succeeds — a partial
    // plaintext cannot be moved to the caller.
    let kb = derive_blob_key(k_tx);
    let cipher = ChaCha20Poly1305::new(Key::from_slice(&kb));
    let plain_chunks: Result<Vec<Vec<u8>>, SpecError> = sealed_chunks
        .iter()
        .enumerate()
        .map(|(i, c_i)| {
            let i_u32 = i as u32;
            let nonce_bytes = zbe_nonce(i_u32);
            let nonce = Nonce::from_slice(&nonce_bytes);
            let aad = zbe_aad(n, i_u32);
            cipher
                .decrypt(
                    nonce,
                    Payload {
                        msg: c_i,
                        aad: &aad,
                    },
                )
                .map_err(|_| SpecError::ZbeAuthFailed { chunk_index: i_u32 })
        })
        .collect();
    Ok(plain_chunks?.concat())
}

// ---------------------------------------------------------------------------
// base64url_no_pad (RFC 4648 §5, no padding) — strict
// ---------------------------------------------------------------------------

const B64URL_ALPHABET: &[u8; 64] =
    b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";

/// Encode `input` as URL-safe Base64 **without** `=` padding.
pub fn base64url_encode_no_pad(input: &[u8]) -> String {
    let mut out = String::with_capacity(input.len().div_ceil(3) * 4);
    let mut i = 0;
    while i + 3 <= input.len() {
        let n =
            (u32::from(input[i]) << 16) | (u32::from(input[i + 1]) << 8) | u32::from(input[i + 2]);
        out.push(B64URL_ALPHABET[((n >> 18) & 63) as usize] as char);
        out.push(B64URL_ALPHABET[((n >> 12) & 63) as usize] as char);
        out.push(B64URL_ALPHABET[((n >> 6) & 63) as usize] as char);
        out.push(B64URL_ALPHABET[(n & 63) as usize] as char);
        i += 3;
    }
    let rem = input.len() - i;
    if rem == 1 {
        let n = u32::from(input[i]) << 16;
        out.push(B64URL_ALPHABET[((n >> 18) & 63) as usize] as char);
        out.push(B64URL_ALPHABET[((n >> 12) & 63) as usize] as char);
    } else if rem == 2 {
        let n = (u32::from(input[i]) << 16) | (u32::from(input[i + 1]) << 8);
        out.push(B64URL_ALPHABET[((n >> 18) & 63) as usize] as char);
        out.push(B64URL_ALPHABET[((n >> 12) & 63) as usize] as char);
        out.push(B64URL_ALPHABET[((n >> 6) & 63) as usize] as char);
    }
    out
}

fn b64url_decode_digit(b: u8) -> Result<u8, SpecError> {
    match b {
        b'A'..=b'Z' => Ok(b - b'A'),
        b'a'..=b'z' => Ok(b - b'a' + 26),
        b'0'..=b'9' => Ok(b - b'0' + 52),
        b'-' => Ok(62),
        b'_' => Ok(63),
        b'=' => Err(SpecError::Base64UrlPadding),
        b'+' | b'/' => Err(SpecError::Base64UrlStandardAlphabet),
        b' ' | b'\t' | b'\n' | b'\r' => Err(SpecError::Base64UrlWhitespace),
        other => Err(SpecError::Base64UrlInvalidChar {
            ch: char::from(other),
        }),
    }
}

/// Decode a **canonical** base64url-no-pad string.
///
/// Rejects padding `=`, standard alphabet `+/`, whitespace, invalid
/// characters, impossible lengths (`len % 4 == 1`), and any encoding that does
/// not re-encode to the same string bit-for-bit (§1.3 step 3).
pub fn base64url_decode_no_pad(enc: &str) -> Result<Vec<u8>, SpecError> {
    let bytes = enc.as_bytes();
    if bytes.is_empty() {
        return Ok(Vec::new());
    }
    // Character-class gate (typed reasons before the generic non-canonical).
    for &b in bytes {
        let _ = b64url_decode_digit(b)?;
    }
    if bytes.len() % 4 == 1 {
        return Err(SpecError::Base64UrlInvalidLength { len: bytes.len() });
    }

    let mut out = Vec::with_capacity(bytes.len() / 4 * 3 + 2);
    let mut i = 0;
    while i + 4 <= bytes.len() {
        let a = u32::from(b64url_decode_digit(bytes[i])?);
        let b = u32::from(b64url_decode_digit(bytes[i + 1])?);
        let c = u32::from(b64url_decode_digit(bytes[i + 2])?);
        let d = u32::from(b64url_decode_digit(bytes[i + 3])?);
        let n = (a << 18) | (b << 12) | (c << 6) | d;
        out.push(((n >> 16) & 0xff) as u8);
        out.push(((n >> 8) & 0xff) as u8);
        out.push((n & 0xff) as u8);
        i += 4;
    }
    let rem = bytes.len() - i;
    if rem == 2 {
        let a = u32::from(b64url_decode_digit(bytes[i])?);
        let b = u32::from(b64url_decode_digit(bytes[i + 1])?);
        let n = (a << 18) | (b << 12);
        // Trailing 4 bits of the 12-bit group must be zero for canonicity;
        // enforced below via re-encode equality as well.
        out.push(((n >> 16) & 0xff) as u8);
    } else if rem == 3 {
        let a = u32::from(b64url_decode_digit(bytes[i])?);
        let b = u32::from(b64url_decode_digit(bytes[i + 1])?);
        let c = u32::from(b64url_decode_digit(bytes[i + 2])?);
        let n = (a << 18) | (b << 12) | (c << 6);
        out.push(((n >> 16) & 0xff) as u8);
        out.push(((n >> 8) & 0xff) as u8);
    }

    // §1.3: re-encoding MUST equal `enc` bit-for-bit.
    let reenc = base64url_encode_no_pad(&out);
    if reenc != enc {
        return Err(SpecError::Base64UrlNonCanonical);
    }
    Ok(out)
}

// ---------------------------------------------------------------------------
// NIP44Binary envelope (§1.3) — seal / open of the UTF-8 preimage only
// ---------------------------------------------------------------------------

fn validate_envelope_label(label: &str) -> Result<(), SpecError> {
    if label.is_empty() || label.contains(':') {
        return Err(SpecError::EnvelopeInvalidLabel);
    }
    Ok(())
}

/// Build the NIP44Binary **plaintext** (input to NIP-44 v2):
/// `"zkcoins-bin-v1:" ‖ label ‖ ":" ‖ base64url_no_pad(binary)`.
///
/// Returns a UTF-8 `String`. This is **not** the on-wire stored field (that is
/// the UTF-8 of NIP-44's Base64 AEAD payload) and **not** raw AEAD bytes.
pub fn envelope_seal(label: &str, binary: &[u8]) -> Result<String, SpecError> {
    validate_envelope_label(label)?;
    let enc = base64url_encode_no_pad(binary);
    Ok(format!("{ENVELOPE_PREFIX}{label}:{enc}"))
}

/// Open a NIP44Binary **plaintext** under the expected `label` and binary
/// length `L` (fail-closed, §1.3 steps 2–4).
///
/// `plaintext` is the UTF-8 string recovered from NIP-44 decryption — **not**
/// the stored Base64 AEAD field and **not** raw AEAD ciphertext bytes.
pub fn envelope_open(
    plaintext: &str,
    label: &str,
    expected_len: usize,
) -> Result<Vec<u8>, SpecError> {
    validate_envelope_label(label)?;
    if !plaintext.starts_with(ENVELOPE_PREFIX) {
        return Err(SpecError::EnvelopeWrongPrefix);
    }
    let rest = &plaintext[ENVELOPE_PREFIX.len()..];
    let Some((got_label, enc)) = rest.split_once(':') else {
        return Err(SpecError::EnvelopeMissingSeparator);
    };
    if got_label != label {
        return Err(SpecError::EnvelopeWrongLabel {
            expected: label.to_string(),
            actual: got_label.to_string(),
        });
    }
    let binary = base64url_decode_no_pad(enc)?;
    if binary.len() != expected_len {
        return Err(SpecError::EnvelopeWrongBinaryLength {
            expected: expected_len,
            actual: binary.len(),
        });
    }
    Ok(binary)
}

// ---------------------------------------------------------------------------
// Tests — V.10 bit-for-bit + negatives
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use sha2::{Digest, Sha256};

    // V.10 pins
    const V10_ESK: &str = "e577ff9c7f7bda9d942561e81df3ccb1dc7b9b2f354ccf82a9352eb5f7beb889";
    const V10_EPK: &str = "e15129c95c4e7528810d91bdc9312389a1c6466bee0237147540c426926af154";
    const V10_IVPK: &str = "cf8c205c48c67816489375cb1c03f09cee718999b4a97a90e8aef80c72fb6c17";
    const V10_SS: &str = "842f5821fa577c0374ae48e4c5afa887e3e0900df7245370e5675d88466fa05f";
    const V10_K_TX: &str = "8a8874f758261a3f48cff62810e5dd4941d3252f44873313bc3f235e73ba8c48";
    const V10_K_OUT: &str = "f18500b7726bcbce23959db535de50a6c742a74f4a04397add7371e19e0426ef";
    const V10_KB: &str = "fe0533b9cf0eb97a5aa20b080bf70b9be33bed4cb4bf11f58d96718ed659cd86";
    const V10_OUT_PLAIN: &str = "zkcoins-bin-v1:K_tx:ioh091gmGj9Iz_YoEOXdSUHTJS9EhzMTvD8jXnO6jEg";
    const V10_COIN_BYTES: &str = "a1cc00c5a5c0fa499664ca891690c3bde52a4c9326f6794659f8ad1926288790e38121742a22e04e51175eb3e38a66df7e7e691c0041c169bc3a2592696f803d0000000000000000000000003b9aca00da7deb2e2d8ad91a2ec9e2aafc6756b2b11f092c79650ce313658f3a9b2ab7cf";
    const V10_COIN_PLAIN: &str = "zkcoins-bin-v1:coin:ocwAxaXA-kmWZMqJFpDDveUqTJMm9nlGWfitGSYoh5DjgSF0KiLgTlEXXrPjimbffn5pHABBwWm8OiWSaW-APQAAAAAAAAAAAAAAADuaygDafesuLYrZGi7J4qr8Z1aysR8JLHllDOMTZY86myq3zw";

    // V.2-ext recipient keys (V.10 reuses these)
    const V2EXT_IVK: &str = "ae3da9f4b07a7b6af81b549011126c39f0070a58fdedf60c5bd9591d096ba1f0";
    const V2EXT_OVK: &str = "f5d3205dcb3ec239f396dd120f0c71d6551465b33f5cbdb92b1946c415665d5d";

    // Poseidon-dependent pin from V.10 / generated_poseidon_vectors.txt
    const V10_DETECT_TAG: &str = "52f38f5972d4b44ef361fadfd8e5f927f3ec9ed8d34c888435fe91d0ff76ea4c";

    fn parse_hex32(hex_str: &str) -> [u8; 32] {
        let bytes = hex::decode(hex_str).expect("fixture hex");
        <[u8; 32]>::try_from(bytes.as_slice()).expect("32 bytes")
    }

    fn parse_hex(hex_str: &str) -> Vec<u8> {
        hex::decode(hex_str).expect("fixture hex")
    }

    /// secp256k1 group order `n` (big-endian) — test-only rejection fixture.
    const SECP256K1_ORDER_N: [u8; 32] = [
        0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
        0xFE, 0xBA, 0xAE, 0xDC, 0xE6, 0xAF, 0x48, 0xA0, 0x3B, 0xBF, 0xD2, 0x5E, 0x8C, 0xD0, 0x36,
        0x41, 0x41,
    ];

    // -----------------------------------------------------------------------
    // V.10 derivation table — every row
    // -----------------------------------------------------------------------

    /// `int(H(label)) mod n` for a 32-byte SHA-256 digest (at most one subtraction).
    fn sha256_mod_n(label: &[u8]) -> [u8; 32] {
        let h: [u8; 32] = Sha256::digest(label).into();
        if h.as_slice() < SECP256K1_ORDER_N.as_slice() {
            return h;
        }
        // h − n (big-endian); a 256-bit hash is < 2n so one subtraction suffices.
        let mut out = [0u8; 32];
        let mut borrow: u8 = 0;
        for i in (0..32).rev() {
            let (d1, b1) = h[i].overflowing_sub(SECP256K1_ORDER_N[i]);
            let (d2, b2) = d1.overflowing_sub(borrow);
            out[i] = d2;
            borrow = u8::from(b1 || b2);
        }
        assert_eq!(borrow, 0, "SHA-256 digest must be < 2n");
        out
    }

    #[test]
    fn v10_esk_matches_sha256_mod_n_pin() {
        // Formula: int(H("zkCoins/v1/test-vector/esk")) mod n — pinned result.
        let derived = sha256_mod_n(b"zkCoins/v1/test-vector/esk");
        assert_eq!(hex::encode(derived), V10_ESK);
        assert_eq!(parse_scalar(&derived), Ok(derived));
    }

    #[test]
    fn v10_epk_from_esk() {
        let esk = parse_hex32(V10_ESK);
        let epk = xonly_pubkey(&esk).expect("esk → epk");
        assert_eq!(hex::encode(epk), V10_EPK);
    }

    #[test]
    fn v10_ivpk_from_ivk() {
        let ivk = parse_hex32(V2EXT_IVK);
        let ivpk = xonly_pubkey(&ivk).expect("ivk → IVPK");
        assert_eq!(hex::encode(ivpk), V10_IVPK);
    }

    #[test]
    fn v10_ss_sender_direction() {
        let esk = parse_hex32(V10_ESK);
        let ivpk = parse_hex32(V10_IVPK);
        let ss = shared_secret_sender(&esk, &ivpk).expect("sender ECDH");
        assert_eq!(hex::encode(ss), V10_SS);
    }

    #[test]
    fn v10_ss_both_ecdh_directions_agree() {
        let esk = parse_hex32(V10_ESK);
        let epk = parse_hex32(V10_EPK);
        let ivk = parse_hex32(V2EXT_IVK);
        let ivpk = parse_hex32(V10_IVPK);

        let ss_sender = shared_secret_sender(&esk, &ivpk).expect("sender");
        let ss_receiver = shared_secret_receiver(&ivk, &epk).expect("receiver");
        assert_eq!(
            ss_sender, ss_receiver,
            "x(esk·lift_x(IVPK)) must equal x(ivk·lift_x(epk))"
        );
        assert_eq!(hex::encode(ss_sender), V10_SS);
        assert_eq!(hex::encode(ss_receiver), V10_SS);
    }

    #[test]
    fn v10_k_tx() {
        let ss = parse_hex32(V10_SS);
        let epk = parse_hex32(V10_EPK);
        let k_tx = derive_note_key(&ss, &epk).expect("K_tx");
        assert_eq!(hex::encode(k_tx), V10_K_TX);
    }

    #[test]
    fn v10_k_out() {
        let ovk = parse_hex32(V2EXT_OVK);
        let epk = parse_hex32(V10_EPK);
        let k_out = derive_out_key(&ovk, &epk).expect("K_out");
        assert_eq!(hex::encode(k_out), V10_K_OUT);
    }

    #[test]
    fn v10_kb() {
        let k_tx = parse_hex32(V10_K_TX);
        let kb = derive_blob_key(&k_tx);
        assert_eq!(hex::encode(kb), V10_KB);
    }

    #[test]
    fn v10_detect_tag_pinned_poseidon() {
        // Poseidon-dependent: pin from reference / generated vectors, do not re-derive formula.
        let ss = parse_hex32(V10_SS);
        let epk = parse_hex32(V10_EPK);
        let tag = crate::spec_v1::hashes::detect_tag(&ss, &epk);
        let bytes = crate::spec_v1::encoding::digest_to_bytes(&tag);
        assert_eq!(hex::encode(bytes), V10_DETECT_TAG);
    }

    // -----------------------------------------------------------------------
    // Envelope preimages
    // -----------------------------------------------------------------------

    #[test]
    fn v10_out_plain_seal() {
        let k_tx = parse_hex32(V10_K_TX);
        let plain = envelope_seal(ENVELOPE_LABEL_K_TX, &k_tx).expect("seal");
        assert_eq!(plain, V10_OUT_PLAIN);
    }

    #[test]
    fn v10_out_plain_open_recovers_k_tx() {
        let k_tx = parse_hex32(V10_K_TX);
        let opened = envelope_open(V10_OUT_PLAIN, ENVELOPE_LABEL_K_TX, OUT_CIPHERTEXT_LEN)
            .expect("open out_plain");
        assert_eq!(opened.as_slice(), k_tx.as_slice());
    }

    #[test]
    fn v10_coin_plain_seal() {
        let coin_bytes = parse_hex(V10_COIN_BYTES);
        assert_eq!(coin_bytes.len(), COIN_CIPHERTEXT_LEN);
        let plain = envelope_seal(ENVELOPE_LABEL_COIN, &coin_bytes).expect("seal coin");
        assert_eq!(plain, V10_COIN_PLAIN);
    }

    #[test]
    fn v10_coin_plain_open_recovers_coin_bytes() {
        let coin_bytes = parse_hex(V10_COIN_BYTES);
        let opened = envelope_open(V10_COIN_PLAIN, ENVELOPE_LABEL_COIN, COIN_CIPHERTEXT_LEN)
            .expect("open coin_plain");
        assert_eq!(opened, coin_bytes);
    }

    // -----------------------------------------------------------------------
    // V.10 envelope negatives — five cases, five tests, typed reasons
    // -----------------------------------------------------------------------

    #[test]
    fn v10_neg_wrong_prefix() {
        let err = envelope_open(
            "not-zkcoins-bin-v1:K_tx:ioh091gmGj9Iz_YoEOXdSUHTJS9EhzMTvD8jXnO6jEg",
            ENVELOPE_LABEL_K_TX,
            OUT_CIPHERTEXT_LEN,
        )
        .expect_err("wrong prefix");
        assert_eq!(err, SpecError::EnvelopeWrongPrefix);
    }

    #[test]
    fn v10_neg_wrong_label() {
        // out_plain has label "K_tx"; open under "coin".
        let err = envelope_open(V10_OUT_PLAIN, ENVELOPE_LABEL_COIN, OUT_CIPHERTEXT_LEN)
            .expect_err("wrong label");
        assert_eq!(
            err,
            SpecError::EnvelopeWrongLabel {
                expected: "coin".to_string(),
                actual: "K_tx".to_string(),
            }
        );
        // coin_plain under "K_tx".
        let err2 = envelope_open(V10_COIN_PLAIN, ENVELOPE_LABEL_K_TX, COIN_CIPHERTEXT_LEN)
            .expect_err("swapped label");
        assert_eq!(
            err2,
            SpecError::EnvelopeWrongLabel {
                expected: "K_tx".to_string(),
                actual: "coin".to_string(),
            }
        );
    }

    #[test]
    fn v10_neg_noncanonical_base64url() {
        // Padding `=`.
        let with_pad = format!(
            "{ENVELOPE_PREFIX}{ENVELOPE_LABEL_K_TX}:ioh091gmGj9Iz_YoEOXdSUHTJS9EhzMTvD8jXnO6jEg=="
        );
        assert_eq!(
            envelope_open(&with_pad, ENVELOPE_LABEL_K_TX, OUT_CIPHERTEXT_LEN),
            Err(SpecError::Base64UrlPadding)
        );

        // Standard alphabet `+` (replace a `-`/`_` if present; inject `+`).
        let with_plus = format!("{ENVELOPE_PREFIX}{ENVELOPE_LABEL_K_TX}:AAAA+AAA");
        assert_eq!(
            envelope_open(&with_plus, ENVELOPE_LABEL_K_TX, OUT_CIPHERTEXT_LEN),
            Err(SpecError::Base64UrlStandardAlphabet)
        );

        // Standard alphabet `/`.
        let with_slash = format!("{ENVELOPE_PREFIX}{ENVELOPE_LABEL_K_TX}:AAAA/AAA");
        assert_eq!(
            envelope_open(&with_slash, ENVELOPE_LABEL_K_TX, OUT_CIPHERTEXT_LEN),
            Err(SpecError::Base64UrlStandardAlphabet)
        );

        // Whitespace.
        let with_ws = format!("{ENVELOPE_PREFIX}{ENVELOPE_LABEL_K_TX}:AAAA AAAA");
        assert_eq!(
            envelope_open(&with_ws, ENVELOPE_LABEL_K_TX, OUT_CIPHERTEXT_LEN),
            Err(SpecError::Base64UrlWhitespace)
        );

        // Non-canonical trailing bits: encode 1 byte then flip last char's
        // unused low bits without changing the decoded value's high bits —
        // re-encode check rejects.
        // "AA" decodes to one zero byte; "AB" decodes to the same byte 0 but
        // is non-canonical (trailing bits of second char).
        let noncanon = format!("{ENVELOPE_PREFIX}{ENVELOPE_LABEL_K_TX}:AB");
        let err = envelope_open(&noncanon, ENVELOPE_LABEL_K_TX, 1).expect_err("non-canonical");
        assert_eq!(err, SpecError::Base64UrlNonCanonical);
    }

    #[test]
    fn v10_neg_wrong_decoded_length() {
        // Valid out_plain under L=32; demand L=112.
        let err = envelope_open(V10_OUT_PLAIN, ENVELOPE_LABEL_K_TX, COIN_CIPHERTEXT_LEN)
            .expect_err("length");
        assert_eq!(
            err,
            SpecError::EnvelopeWrongBinaryLength {
                expected: 112,
                actual: 32,
            }
        );
        // coin_plain under L=32.
        let err2 = envelope_open(V10_COIN_PLAIN, ENVELOPE_LABEL_COIN, OUT_CIPHERTEXT_LEN)
            .expect_err("length coin");
        assert_eq!(
            err2,
            SpecError::EnvelopeWrongBinaryLength {
                expected: 32,
                actual: 112,
            }
        );
    }

    #[test]
    fn v10_neg_stored_field_is_not_raw_aead() {
        // Discipline: the stored wire field is UTF-8 of NIP-44 Base64 AEAD
        // payload — never raw AEAD bytes and never fed to envelope_open.
        // A raw-looking Base64 AEAD payload string (no envelope prefix) MUST
        // reject as wrong prefix, not silently decode as binary.
        let fake_stored_nip44_payload =
            "Atd/1lOaY9L9s0k3QeY2b0x1y2z3A4B5C6D7E8F9G0H1I2J3K4L5M6N7O8P9Q0R";
        let err = envelope_open(
            fake_stored_nip44_payload,
            ENVELOPE_LABEL_K_TX,
            OUT_CIPHERTEXT_LEN,
        )
        .expect_err("stored AEAD field is not envelope plaintext");
        assert_eq!(err, SpecError::EnvelopeWrongPrefix);
    }

    // -----------------------------------------------------------------------
    // Canonicality of points / scalars
    // -----------------------------------------------------------------------

    #[test]
    fn rejects_scalar_zero() {
        let z = [0u8; 32];
        assert_eq!(parse_scalar(&z), Err(SpecError::ScalarZero));
        assert_eq!(
            ecdh_shared_x(&z, &parse_hex32(V10_IVPK)),
            Err(SpecError::ScalarZero)
        );
    }

    #[test]
    fn rejects_scalar_ge_n() {
        // Group order n itself is ≥ n.
        assert_eq!(
            parse_scalar(&SECP256K1_ORDER_N),
            Err(SpecError::ScalarOutOfRange)
        );
        // n + 0 ... but n is already the boundary; also try all 0xFF.
        let all_ff = [0xFFu8; 32];
        assert_eq!(parse_scalar(&all_ff), Err(SpecError::ScalarOutOfRange));
    }

    #[test]
    fn rejects_scalar_wrong_length() {
        assert_eq!(
            parse_scalar(&[1u8; 31]),
            Err(SpecError::ScalarWrongLength { actual: 31 })
        );
        assert_eq!(
            parse_scalar(&[1u8; 33]),
            Err(SpecError::ScalarWrongLength { actual: 33 })
        );
        assert_eq!(
            parse_scalar(&[]),
            Err(SpecError::ScalarWrongLength { actual: 0 })
        );
    }

    #[test]
    fn rejects_xonly_x_ge_p() {
        // Field prime p itself: x ≥ p.
        assert_eq!(parse_xonly(&SECP256K1_FIELD_P), Err(SpecError::XOnlyXGeP));
        let all_ff = [0xFFu8; 32];
        assert_eq!(parse_xonly(&all_ff), Err(SpecError::XOnlyXGeP));
    }

    #[test]
    fn rejects_xonly_off_curve() {
        // x = 0 is < p but not a valid BIP-340 x-only public key on secp256k1.
        let x0 = [0u8; 32];
        assert_eq!(parse_xonly(&x0), Err(SpecError::XOnlyOffCurve));
        // Deterministic search for another off-curve x < p (small integers).
        let mut second: Option<[u8; 32]> = None;
        for i in 1u8..=255 {
            let mut x = [0u8; 32];
            x[31] = i;
            if matches!(parse_xonly(&x), Err(SpecError::XOnlyOffCurve)) {
                second = Some(x);
                break;
            }
        }
        assert!(
            second.is_some(),
            "expected at least one additional small off-curve x-only encoding"
        );
    }

    #[test]
    fn rejects_xonly_wrong_length() {
        assert_eq!(
            parse_xonly(&[0u8; 31]),
            Err(SpecError::XOnlyWrongLength { actual: 31 })
        );
        assert_eq!(
            parse_xonly(&[0u8; 33]),
            Err(SpecError::XOnlyWrongLength { actual: 33 })
        );
    }

    #[test]
    fn point_at_infinity_has_no_xonly_encoding() {
        // Infinity is not a 32-byte x-only key. Empty / short encodings are
        // wrong-length; there is no SpecError variant for infinity because
        // the x-only path cannot construct it.
        assert_eq!(
            parse_xonly(&[]),
            Err(SpecError::XOnlyWrongLength { actual: 0 })
        );
    }

    // -----------------------------------------------------------------------
    // ZBE §4.2.1 — seal / open, boundaries, negatives
    // -----------------------------------------------------------------------

    /// Test-only fixture key (not a protocol pin).
    fn zbe_test_k_tx() -> [u8; 32] {
        parse_hex32(V10_K_TX)
    }

    /// Parse ZBE framing far enough to read `N` and collect raw `C_i` slices.
    fn zbe_parse_chunks(ct: &[u8]) -> (u32, Vec<Vec<u8>>) {
        assert!(ct.len() >= 8, "header");
        assert_eq!(&ct[..4], &ZBE_MAGIC, "magic");
        let n = u32::from_be_bytes(ct[4..8].try_into().expect("4 bytes"));
        let mut offset = 8usize;
        let mut chunks = Vec::with_capacity(n as usize);
        for _ in 0..n {
            let len =
                u32::from_be_bytes(ct[offset..offset + 4].try_into().expect("4 bytes")) as usize;
            offset += 4;
            chunks.push(ct[offset..offset + len].to_vec());
            offset += len;
        }
        assert_eq!(offset, ct.len(), "no trailing in fixture parse");
        (n, chunks)
    }

    /// Rebuild ciphertext from `N` and chunk ciphertexts.
    fn zbe_frame(n: u32, chunks: &[Vec<u8>]) -> Vec<u8> {
        let mut out = Vec::new();
        out.extend_from_slice(&ZBE_MAGIC);
        out.extend_from_slice(&n.to_be_bytes());
        for c in chunks {
            let len = u32::try_from(c.len()).expect("chunk fits u32");
            out.extend_from_slice(&len.to_be_bytes());
            out.extend_from_slice(c);
        }
        out
    }

    #[test]
    fn zbe_roundtrip_empty_blob_n_eq_1() {
        // Empty P → N = 1, one zero-length plaintext chunk.
        let k = zbe_test_k_tx();
        let (ct, blob_id) = zbe_seal(&k, &[]).expect("seal empty");
        let (n, chunks) = zbe_parse_chunks(&ct);
        assert_eq!(n, 1, "empty blob has N = 1");
        assert_eq!(chunks.len(), 1);
        assert_eq!(
            chunks[0].len(),
            super::ZBE_TAG_LEN,
            "empty P_0 seals to tag-only C_0"
        );
        let opened = zbe_open(&k, &ct).expect("open empty");
        assert_eq!(opened, Vec::<u8>::new());
        assert_eq!(blob_id, <[u8; 32]>::from(Sha256::digest(&ct)));
    }

    #[test]
    fn zbe_roundtrip_one_byte() {
        let k = zbe_test_k_tx();
        let p = [0xABu8];
        let (ct, _) = zbe_seal(&k, &p).expect("seal");
        let (n, _) = zbe_parse_chunks(&ct);
        assert_eq!(n, 1);
        assert_eq!(zbe_open(&k, &ct).expect("open"), p);
    }

    #[test]
    fn zbe_roundtrip_chunk_minus_one() {
        let k = zbe_test_k_tx();
        let p = vec![0x11u8; ZBE_CHUNK - 1];
        let (ct, _) = zbe_seal(&k, &p).expect("seal");
        let (n, _) = zbe_parse_chunks(&ct);
        assert_eq!(n, 1, "CHUNK-1 fits a single chunk");
        assert_eq!(zbe_open(&k, &ct).expect("open"), p);
    }

    #[test]
    fn zbe_roundtrip_exactly_chunk() {
        let k = zbe_test_k_tx();
        let p = vec![0x22u8; ZBE_CHUNK];
        let (ct, _) = zbe_seal(&k, &p).expect("seal");
        let (n, _) = zbe_parse_chunks(&ct);
        assert_eq!(n, 1, "exactly CHUNK is still N = 1");
        assert_eq!(zbe_open(&k, &ct).expect("open"), p);
    }

    #[test]
    fn zbe_roundtrip_chunk_plus_one() {
        let k = zbe_test_k_tx();
        let p = vec![0x33u8; ZBE_CHUNK + 1];
        let (ct, _) = zbe_seal(&k, &p).expect("seal");
        let (n, chunks) = zbe_parse_chunks(&ct);
        assert_eq!(n, 2, "CHUNK+1 forces N = 2");
        assert_eq!(chunks.len(), 2);
        // First chunk: full CHUNK plaintext + tag; second: 1 byte + tag.
        assert_eq!(chunks[0].len(), ZBE_CHUNK + super::ZBE_TAG_LEN);
        assert_eq!(chunks[1].len(), 1 + super::ZBE_TAG_LEN);
        assert_eq!(zbe_open(&k, &ct).expect("open"), p);
    }

    #[test]
    fn zbe_roundtrip_several_full_chunks_plus_remainder() {
        // 3 full chunks + 100-byte remainder → N = 4.
        let k = zbe_test_k_tx();
        let len = 3 * ZBE_CHUNK + 100;
        let p: Vec<u8> = (0..len).map(|i| (i % 251) as u8).collect();
        let (ct, _) = zbe_seal(&k, &p).expect("seal");
        let (n, chunks) = zbe_parse_chunks(&ct);
        assert_eq!(n, 4);
        assert_eq!(chunks.len(), 4);
        assert_eq!(chunks[0].len(), ZBE_CHUNK + super::ZBE_TAG_LEN);
        assert_eq!(chunks[1].len(), ZBE_CHUNK + super::ZBE_TAG_LEN);
        assert_eq!(chunks[2].len(), ZBE_CHUNK + super::ZBE_TAG_LEN);
        assert_eq!(chunks[3].len(), 100 + super::ZBE_TAG_LEN);
        assert_eq!(zbe_open(&k, &ct).expect("open"), p);
    }

    #[test]
    fn zbe_determinism_same_k_tx_and_p() {
        let k = zbe_test_k_tx();
        let p = b"zkCoins ZBE determinism fixture";
        let (ct1, id1) = zbe_seal(&k, p).expect("seal 1");
        let (ct2, id2) = zbe_seal(&k, p).expect("seal 2");
        assert_eq!(ct1, ct2, "ciphertext must be deterministic");
        assert_eq!(id1, id2, "blob_id must be deterministic");
        assert_eq!(id1, <[u8; 32]>::from(Sha256::digest(&ct1)));
    }

    #[test]
    fn zbe_blob_id_is_sha256_of_full_ciphertext() {
        let k = zbe_test_k_tx();
        let p = vec![0x7Eu8; ZBE_CHUNK + 50];
        let (ct, blob_id) = zbe_seal(&k, &p).expect("seal");
        // Includes magic, N, every length prefix and every C_i.
        assert_eq!(blob_id, <[u8; 32]>::from(Sha256::digest(&ct)));
        assert_eq!(&ct[..4], &ZBE_MAGIC);
    }

    #[test]
    fn zbe_swap_chunks_fails_auth() {
        // C_0 ↔ C_1: AAD binds index i, so both tags fail.
        let k = zbe_test_k_tx();
        let p = vec![0x44u8; ZBE_CHUNK + 1];
        let (ct, _) = zbe_seal(&k, &p).expect("seal");
        let (n, mut chunks) = zbe_parse_chunks(&ct);
        assert_eq!(n, 2);
        chunks.swap(0, 1);
        let tampered = zbe_frame(n, &chunks);
        let err = zbe_open(&k, &tampered).expect_err("swapped chunks");
        assert_eq!(err, SpecError::ZbeAuthFailed { chunk_index: 0 });
    }

    #[test]
    fn zbe_truncate_last_chunk_with_n_adjusted_still_fails() {
        // Remove C_1 and rewrite header N to 1. Framing now looks consistent
        // (one chunk, N=1), but C_0 was sealed under aad with N=2, so open
        // under N=1 fails the Poly1305 tag — AAD binds the original total count.
        let k = zbe_test_k_tx();
        let p = vec![0x55u8; ZBE_CHUNK + 1];
        let (ct, _) = zbe_seal(&k, &p).expect("seal");
        let (n, chunks) = zbe_parse_chunks(&ct);
        assert_eq!(n, 2);
        assert_eq!(chunks.len(), 2);
        let truncated = zbe_frame(1, &chunks[..1]);
        let err = zbe_open(&k, &truncated).expect_err("N-adjusted truncation");
        assert_eq!(err, SpecError::ZbeAuthFailed { chunk_index: 0 });
    }

    #[test]
    fn zbe_wrong_key_fails_auth_not_structure() {
        let k = zbe_test_k_tx();
        let p = b"wrong-key probe";
        let (ct, _) = zbe_seal(&k, p).expect("seal");
        let mut wrong = k;
        wrong[0] ^= 0x01;
        let err = zbe_open(&wrong, &ct).expect_err("wrong key");
        assert_eq!(err, SpecError::ZbeAuthFailed { chunk_index: 0 });
        // Structure is intact: magic and N still parse under the right key.
        assert_eq!(zbe_open(&k, &ct).expect("right key"), p);
    }

    #[test]
    fn zbe_wrong_magic_rejected() {
        let k = zbe_test_k_tx();
        let (mut ct, _) = zbe_seal(&k, b"x").expect("seal");
        ct[0] = b'X';
        assert_eq!(zbe_open(&k, &ct), Err(SpecError::ZbeWrongMagic));
    }

    #[test]
    fn zbe_missing_magic_short_input() {
        let k = zbe_test_k_tx();
        assert_eq!(zbe_open(&k, b""), Err(SpecError::ZbeTruncated));
        assert_eq!(zbe_open(&k, b"ZBE"), Err(SpecError::ZbeTruncated));
        assert_eq!(
            zbe_open(&k, b"XXXX\x00\x00\x00\x01"),
            Err(SpecError::ZbeWrongMagic)
        );
    }

    #[test]
    fn zbe_trailing_bytes_rejected() {
        let k = zbe_test_k_tx();
        let (mut ct, _) = zbe_seal(&k, b"trail").expect("seal");
        ct.push(0x00);
        assert_eq!(
            zbe_open(&k, &ct),
            Err(SpecError::ZbeTrailingBytes { remaining: 1 })
        );
    }

    #[test]
    fn zbe_length_overrun_rejected() {
        let k = zbe_test_k_tx();
        let (ct, _) = zbe_seal(&k, b"over").expect("seal");
        // Rewrite first chunk length to claim more bytes than remain.
        let mut bad = ct;
        // After magic(4) + N(4) comes u32_be(len C_0). Inflate it.
        let claimed = u32::MAX;
        bad[8..12].copy_from_slice(&claimed.to_be_bytes());
        let remaining = bad.len() - 12;
        assert_eq!(
            zbe_open(&k, &bad),
            Err(SpecError::ZbeChunkLengthOverrun {
                chunk_index: 0,
                declared_len: claimed,
                remaining,
            })
        );
    }

    #[test]
    fn zbe_n_zero_rejected() {
        let k = zbe_test_k_tx();
        let mut ct = Vec::new();
        ct.extend_from_slice(&ZBE_MAGIC);
        ct.extend_from_slice(&0u32.to_be_bytes());
        assert_eq!(
            zbe_open(&k, &ct),
            Err(SpecError::ZbeInvalidChunkCount { n: 0 })
        );
    }

    #[test]
    fn zbe_chunk_count_mismatch_when_chunks_missing() {
        // N=2 but only one framed chunk present (no N rewrite — raw truncation).
        let k = zbe_test_k_tx();
        let p = vec![0x66u8; ZBE_CHUNK + 1];
        let (ct, _) = zbe_seal(&k, &p).expect("seal");
        let (n, chunks) = zbe_parse_chunks(&ct);
        assert_eq!(n, 2);
        // Keep header N=2 but only emit C_0.
        let mut truncated = Vec::new();
        truncated.extend_from_slice(&ZBE_MAGIC);
        truncated.extend_from_slice(&2u32.to_be_bytes());
        let len = u32::try_from(chunks[0].len()).expect("fits");
        truncated.extend_from_slice(&len.to_be_bytes());
        truncated.extend_from_slice(&chunks[0]);
        assert_eq!(
            zbe_open(&k, &truncated),
            Err(SpecError::ZbeChunkCountMismatch {
                declared: 2,
                parsed: 1,
            })
        );
    }

    // -----------------------------------------------------------------------
    // base64url unit coverage
    // -----------------------------------------------------------------------

    #[test]
    fn base64url_roundtrip_and_empty() {
        assert_eq!(base64url_encode_no_pad(&[]), "");
        assert_eq!(
            base64url_decode_no_pad("").expect("empty"),
            Vec::<u8>::new()
        );
        let data = parse_hex32(V10_K_TX);
        let enc = base64url_encode_no_pad(&data);
        assert_eq!(enc, "ioh091gmGj9Iz_YoEOXdSUHTJS9EhzMTvD8jXnO6jEg");
        assert_eq!(base64url_decode_no_pad(&enc).expect("decode"), data);
    }

    #[test]
    fn base64url_rejects_invalid_length_mod4_eq1() {
        assert_eq!(
            base64url_decode_no_pad("A"),
            Err(SpecError::Base64UrlInvalidLength { len: 1 })
        );
        assert_eq!(
            base64url_decode_no_pad("AAAAA"),
            Err(SpecError::Base64UrlInvalidLength { len: 5 })
        );
    }

    #[test]
    fn envelope_rejects_invalid_label() {
        assert_eq!(
            envelope_seal("", &[0u8; 1]),
            Err(SpecError::EnvelopeInvalidLabel)
        );
        assert_eq!(
            envelope_seal("a:b", &[0u8; 1]),
            Err(SpecError::EnvelopeInvalidLabel)
        );
        assert_eq!(
            envelope_open("zkcoins-bin-v1:a:b:xx", "a:b", 1),
            Err(SpecError::EnvelopeInvalidLabel)
        );
    }

    #[test]
    fn envelope_missing_separator_after_prefix() {
        assert_eq!(
            envelope_open("zkcoins-bin-v1:K_tx", ENVELOPE_LABEL_K_TX, 32),
            Err(SpecError::EnvelopeMissingSeparator)
        );
    }

    #[test]
    fn derive_out_key_rejects_bad_ovk() {
        let epk = parse_hex32(V10_EPK);
        assert_eq!(derive_out_key(&[0u8; 32], &epk), Err(SpecError::ScalarZero));
    }

    #[test]
    fn derive_note_key_rejects_bad_epk() {
        let ss = parse_hex32(V10_SS);
        assert_eq!(
            derive_note_key(&ss, &[0u8; 32]),
            Err(SpecError::XOnlyOffCurve)
        );
    }
}
