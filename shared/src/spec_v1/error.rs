//! Error type for `spec_v1` validation failures (fail-loud, no silent defaults).

use std::fmt;

use super::accumulator::ChainPosition;

/// Protocol-foundation validation / encoding error.
///
/// Every recoverable failure in `spec_v1` returns this type rather than
/// silently clamping, truncating, or substituting a default value.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SpecError {
    /// Asset name longer than 255 bytes.
    NameTooLong { len: usize },
    /// NameConsent / identifier name is empty after §4.3 normalization.
    NameEmpty,
    /// NameConsent `network` field is empty.
    NetworkEmpty,
    /// NameConsent `network` is not in the closed §7.3 set
    /// `{mainnet, testnet, regtest}` (same vocabulary as `zkcoins.network`).
    NetworkUnknown { network: String },
    /// Identifier has no `@` separator (§4.3).
    NameMissingAt,
    /// Identifier has more than one `@` (§4.3).
    NameMultipleAt,
    /// Local part (before `@`) is empty (§4.3).
    NameEmptyLocal,
    /// Domain part (after `@`) is empty (§4.3).
    NameEmptyDomain,
    /// Local part begins with `.` (§4.3).
    NameLocalLeadingDot,
    /// Local part ends with `.` (§4.3).
    NameLocalTrailingDot,
    /// Local part contains consecutive `..` (§4.3).
    NameLocalConsecutiveDots,
    /// Local part contains a character outside `a-z0-9-_.` (§4.3).
    NameLocalInvalidChar { ch: char },
    /// Domain label is empty (§4.3 DNS hostname).
    NameDomainLabelEmpty,
    /// Domain label begins with `-` (§4.3 DNS hostname).
    NameDomainLabelLeadingHyphen,
    /// Domain label ends with `-` (§4.3 DNS hostname).
    NameDomainLabelTrailingHyphen,
    /// Domain label contains a character outside `a-z0-9-` (§4.3 DNS hostname).
    NameDomainLabelInvalidChar { ch: char },
    /// Domain label longer than 63 octets (§4.3 DNS hostname).
    NameDomainLabelTooLong { len: usize },
    /// Domain longer than 253 octets (§4.3 DNS hostname).
    NameDomainTooLong { len: usize },
    /// `AccountState.balances` exceeds `MAX_ACCOUNT_ASSETS`.
    TooManyBalances { count: usize, max: usize },

    /// A balance entry has `amount == 0` (must be omitted).
    ZeroAmountBalance,
    /// Input byte length does not match the expected fixed width.
    WrongLength { expected: usize, actual: usize },
    /// Bech32m HRP is not the expected value.
    Bech32WrongHrp {
        expected: &'static str,
        actual: String,
    },
    /// Bech32m decode failed (checksum / charset / format).
    Bech32DecodeError(String),
    /// Small-numeric value ≥ 2^56 (must use wide/byte-string encoding).
    SmallNumericOutOfRange { value: u64 },
    /// Byte-string length ≥ 2^56 (cannot be represented as a length element).
    ByteStringTooLong { len: usize },
    /// A Poseidon-digest byte limb is `>= GoldilocksField::ORDER` (§1.7.1: every
    /// digest limb MUST be canonical, i.e. reduced mod p).
    NonCanonicalDigestLimb { limb_index: usize, value: u64 },
    /// `serialize(AccountState)` balance entries were not strictly ascending by
    /// `asset_id` (byte order) on the wire (§1.7.4).
    BalancesNotAscending { index: usize },
    /// Inclusion path requested for a position outside the log.
    PositionOutOfRange { position: u64, size: u64 },
    /// Consistency proof requested with `m > n`.
    ConsistencyRangeInvalid { m: u64, n: u64 },
    /// `NetworkParams.network_tag` longer than 255 UTF-8 bytes.
    NetworkTagTooLong { len: usize },
    /// `finality_confirmations` is not the protocol-pinned constant 6.
    InvalidFinalityConfirmations { value: u8 },
    /// Coin-history admit attempted on a non-`Absent` coin.
    CoinAlreadyAdmitted { coin_id: [u8; 32] },
    /// Coin-history spend attempted on a coin that was never admitted.
    CoinNotAdmitted { coin_id: [u8; 32] },
    /// Coin-history spend attempted on an already-spent coin.
    CoinAlreadySpent { coin_id: [u8; 32] },
    /// Non-inclusion proof requested for a coin that is present.
    CoinNotAbsent { coin_id: [u8; 32] },
    /// Nullifier fold invoked with a `ChainPosition` that is not strictly
    /// greater than the last successfully-ordered fold (§3.6 step 4).
    OutOfOrderFold {
        previous: ChainPosition,
        attempted: ChainPosition,
    },
    /// `coinhist_node_hash` level is outside the domain `0..=256`.
    CoinHistLevelOutOfRange { level: u32 },

    // --- BootstrapManifestV1 (BMF1) decode / verify (§4.3 / §7.7) ---
    /// Wire magic is not ASCII `"BMF1"`.
    BootstrapMagicInvalid { got: [u8; 4] },
    /// Wire version byte is not `0x01`.
    BootstrapVersionInvalid { got: u8 },
    /// `seed_relay_count == 0` (must be ≥ 1).
    BootstrapSeedRelayCountZero,
    /// `blob_store_count == 0` (must be ≥ 1).
    BootstrapBlobStoreCountZero,
    /// `operator_id_count == 0` (must be ≥ 1).
    BootstrapOperatorIdCountZero,
    /// A URL length prefix is 0.
    BootstrapUrlEmpty {
        which: BootstrapUrlKind,
        index: usize,
    },
    /// A URL length exceeds the 2048-byte bound.
    BootstrapUrlTooLong {
        which: BootstrapUrlKind,
        index: usize,
        len: usize,
    },
    /// Input ended before a fixed-width or length-prefixed field could be read.
    BootstrapTruncated {
        context: &'static str,
        needed: usize,
        remaining: usize,
    },
    /// Bytes remain after a complete BMF1 frame.
    BootstrapTrailingBytes { remaining: usize },
    /// A length-prefixed string field is not valid UTF-8.
    BootstrapInvalidUtf8 {
        field: BootstrapStringField,
        error: String,
    },
    /// `protocol_version` is not exactly `"v1"`.
    BootstrapProtocolVersionInvalid { got: String },
    /// BIP-340 verification of `manifest_sig` under the pinned key failed.
    BootstrapSignatureInvalid,
    /// Decoded `network` does not match the verifier's network.
    BootstrapNetworkMismatch { expected: String, actual: String },
    /// Decoded `protocol_version` does not match the verifier's version.
    BootstrapProtocolVersionMismatch { expected: String, actual: String },
    /// `expires_at < now` under a provided wall clock.
    BootstrapExpired { expires_at: u64, now: u64 },
    /// `issued_at > expires_at` — degenerate lifetime (rejected structurally).
    BootstrapIssuedAfterExpiry { issued_at: u64, expires_at: u64 },
    /// Secret key bytes are not a valid secp256k1 scalar (sign path).
    ///
    /// Display never includes key material — only that the key was rejected.
    BootstrapSecretKeyInvalid,
    /// Derived x-only public key does not match the caller-supplied pin.
    ///
    /// Fail-closed for the sign path: refuse to emit an artifact the node
    /// would later reject under `bootstrap_pubkey`. Display never includes
    /// key material.
    BootstrapPubkeyMismatch,
    // --- Note encryption / ECDH / NIP44Binary envelope (§1.1 / §1.3) ---
    /// Scalar byte string is not exactly 32 bytes.
    ScalarWrongLength { actual: usize },
    /// Scalar is the zero scalar (not in `[1, n)`).
    ScalarZero,
    /// Scalar is ≥ curve order `n` (not in `[1, n)`).
    ScalarOutOfRange,
    /// x-only public-key encoding is not exactly 32 bytes.
    XOnlyWrongLength { actual: usize },
    /// x-only x-coordinate satisfies `x ≥ p` (secp256k1 field prime).
    XOnlyXGeP,
    /// x-only x-coordinate is `< p` but no curve point has that x (off-curve).
    XOnlyOffCurve,

    /// NIP44Binary plaintext does not start with `zkcoins-bin-v1:`.
    EnvelopeWrongPrefix,
    /// NIP44Binary plaintext label does not match the expected call-site label.
    EnvelopeWrongLabel { expected: String, actual: String },
    /// NIP44Binary plaintext is missing the `label`/`payload` `:` separator.
    EnvelopeMissingSeparator,
    /// Envelope label is empty or contains `:` (not a fixed ASCII token).
    EnvelopeInvalidLabel,
    /// base64url_no_pad payload contains `=` padding.
    Base64UrlPadding,
    /// base64url_no_pad payload uses the standard Base64 alphabet (`+` / `/`).
    Base64UrlStandardAlphabet,
    /// base64url_no_pad payload contains whitespace.
    Base64UrlWhitespace,
    /// base64url_no_pad payload contains a character outside `[A-Za-z0-9\-_]`.
    Base64UrlInvalidChar { ch: char },
    /// base64url_no_pad payload has an impossible length (`len % 4 == 1`).
    Base64UrlInvalidLength { len: usize },
    /// base64url_no_pad payload is non-canonical (re-encode ≠ input).
    Base64UrlNonCanonical,
    /// Decoded NIP44Binary binary length ≠ expected call-site `L`.
    EnvelopeWrongBinaryLength { expected: usize, actual: usize },

    // --- ZBE §4.2.1 (chunked ChaCha20-Poly1305 blob encryption) ---
    /// Ciphertext does not start with ASCII magic `ZBE1`.
    ZbeWrongMagic,
    /// Ciphertext ends before a complete header or chunk frame can be read.
    ZbeTruncated,
    /// Declared chunk count is zero (normative `N >= 1`).
    ZbeInvalidChunkCount { n: u32 },
    /// Declared `N` does not equal the number of complete length-prefixed chunks.
    ZbeChunkCountMismatch { declared: u32, parsed: u32 },
    /// A chunk's `u32_be(len C_i)` exceeds the remaining ciphertext bytes.
    ZbeChunkLengthOverrun {
        chunk_index: u32,
        declared_len: u32,
        remaining: usize,
    },
    /// Bytes remain after the last framed chunk.
    ZbeTrailingBytes { remaining: usize },
    /// Framed chunk shorter than the 16-byte Poly1305 tag.
    ZbeChunkTooShort { chunk_index: u32, len: u32 },
    /// Poly1305 authentication-tag verification failed for chunk `chunk_index`.
    ZbeAuthFailed { chunk_index: u32 },
    /// Plaintext would require more than `u32::MAX` chunks (`N` unencodable).
    ZbeTooManyChunks { n: usize },

    // --- Bundle codecs: CoinProof / SelfDeliveryRecordV1 / BlobLocatorSet (§7.1) ---
    /// Input ended before a fixed-width or length-prefixed field could be read.
    BundleTruncated {
        context: &'static str,
        needed: usize,
        remaining: usize,
    },
    /// A `u32-be` / `u16-be` length prefix exceeds the remaining bytes.
    BundleLengthOverrun {
        context: &'static str,
        declared: u32,
        remaining: usize,
    },
    /// Bytes remain after a complete top-level frame.
    BundleTrailingBytes {
        context: &'static str,
        remaining: usize,
    },
    /// `asset_terms?` presence byte is neither `0x00` nor `0x01`.
    CoinProofPresenceInvalid { got: u8 },
    /// `asset_terms.issuance_version` is outside `{0x01, 0x02}`.
    CoinProofIssuanceVersionInvalid { got: u8 },
    /// Trailing `cap_total`/`terms_salt` presence disagrees with `issuance_version`.
    ///
    /// `cap_fields_present` is what the encoder/struct claimed (or what the
    /// wire still had room for): `true` with version 1, or `false` with
    /// version 2, both malformed per §7.1.
    CoinProofAssetTermsVersionFieldsMismatch {
        issuance_version: u8,
        cap_fields_present: bool,
    },
    /// Self-delivery magic is not ASCII `"SDR1"`.
    SdrMagicInvalid { got: [u8; 4] },
    /// Self-delivery version byte is not `0x01`.
    SdrVersionInvalid { got: u8 },
    /// Self-delivery `record_kind` is outside `{0x01, 0x02, 0x03}`.
    SdrRecordKindInvalid { got: u8 },
    /// `BlobLocatorSet.holder_count == 0` (must be ≥ 1).
    BlobLocatorCountZero,
    /// `holder_count` exceeds the protocol upper bound ([`super::bundle::MAX_BLOB_HOLDERS`]).
    ///
    /// `count` is the **actual** number of holders presented — never clamped to
    /// a wire width. `max` is the normative upper bound so the error names both
    /// the observed size and the limit it violated.
    BlobLocatorCountTooHigh { count: usize, max: usize },
    /// A holder URL length prefix is 0.
    BlobLocatorUrlEmpty { index: usize },
    /// A holder URL length exceeds `MAX_HOLDER_URL_LEN` (2048).
    BlobLocatorUrlTooLong { index: usize, len: usize },
    /// A holder URL is not valid UTF-8.
    BlobLocatorInvalidUtf8 { index: usize },
    /// A holder URL contains a NUL byte (§7.1).
    BlobLocatorUrlContainsNul { index: usize },
}

/// Which bootstrap URL list a length/UTF-8 error refers to.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BootstrapUrlKind {
    SeedRelay,
    BlobStore,
}

impl fmt::Display for BootstrapUrlKind {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::SeedRelay => f.write_str("seed_relay"),
            Self::BlobStore => f.write_str("blob_store"),
        }
    }
}

/// Which length-prefixed UTF-8 field failed to decode.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BootstrapStringField {
    Network,
    ProtocolVersion,
    SeedRelay { index: usize },
    BlobStore { index: usize },
}

impl fmt::Display for BootstrapStringField {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Network => f.write_str("network"),
            Self::ProtocolVersion => f.write_str("protocol_version"),
            Self::SeedRelay { index } => write!(f, "seed_relays[{index}]"),
            Self::BlobStore { index } => write!(f, "blob_stores[{index}]"),
        }
    }
}

impl fmt::Display for SpecError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            SpecError::NameTooLong { len } => {
                write!(f, "asset name too long: {len} bytes (max 255)")
            }
            SpecError::NameEmpty => {
                write!(f, "name is empty after §4.3 normalization")
            }
            SpecError::NetworkEmpty => {
                write!(f, "network field is empty")
            }
            SpecError::NetworkUnknown { network } => {
                write!(
                    f,
                    "network {network:?} is not in the closed set \
                     {{mainnet, testnet, regtest}} (§4.3 / §7.3)"
                )
            }
            SpecError::NameMissingAt => {
                write!(f, "identifier missing '@' separator (§4.3)")
            }
            SpecError::NameMultipleAt => {
                write!(f, "identifier has more than one '@' (§4.3)")
            }
            SpecError::NameEmptyLocal => {
                write!(f, "identifier local part is empty (§4.3)")
            }
            SpecError::NameEmptyDomain => {
                write!(f, "identifier domain is empty (§4.3)")
            }
            SpecError::NameLocalLeadingDot => {
                write!(f, "identifier local part begins with '.' (§4.3)")
            }
            SpecError::NameLocalTrailingDot => {
                write!(f, "identifier local part ends with '.' (§4.3)")
            }
            SpecError::NameLocalConsecutiveDots => {
                write!(f, "identifier local part contains consecutive '..' (§4.3)")
            }
            SpecError::NameLocalInvalidChar { ch } => {
                write!(
                    f,
                    "identifier local part has invalid character {ch:?} (only a-z0-9-_. allowed, §4.3)"
                )
            }
            SpecError::NameDomainLabelEmpty => {
                write!(f, "identifier domain has empty label (§4.3 DNS hostname)")
            }
            SpecError::NameDomainLabelLeadingHyphen => {
                write!(
                    f,
                    "identifier domain label begins with '-' (§4.3 DNS hostname)"
                )
            }
            SpecError::NameDomainLabelTrailingHyphen => {
                write!(
                    f,
                    "identifier domain label ends with '-' (§4.3 DNS hostname)"
                )
            }
            SpecError::NameDomainLabelInvalidChar { ch } => {
                write!(
                    f,
                    "identifier domain label has invalid character {ch:?} (only a-z0-9- allowed, §4.3)"
                )
            }
            SpecError::NameDomainLabelTooLong { len } => {
                write!(
                    f,
                    "identifier domain label too long: {len} octets (max 63, §4.3 DNS hostname)"
                )
            }
            SpecError::NameDomainTooLong { len } => {
                write!(
                    f,
                    "identifier domain too long: {len} octets (max 253, §4.3 DNS hostname)"
                )
            }
            SpecError::TooManyBalances { count, max } => {
                write!(f, "too many balance entries: {count} (max {max})")
            }
            SpecError::ZeroAmountBalance => {
                write!(f, "zero-amount balance entry is forbidden")
            }
            SpecError::WrongLength { expected, actual } => {
                write!(f, "wrong input length: expected {expected}, got {actual}")
            }
            SpecError::Bech32WrongHrp { expected, actual } => {
                write!(f, "bech32m wrong HRP: expected {expected:?}, got {actual:?}")
            }
            SpecError::Bech32DecodeError(msg) => {
                write!(f, "bech32m decode error: {msg}")
            }
            SpecError::SmallNumericOutOfRange { value } => {
                write!(
                    f,
                    "small-numeric value out of range: {value} (must be < 2^56)"
                )
            }
            SpecError::ByteStringTooLong { len } => {
                write!(
                    f,
                    "byte-string length out of range: {len} (must be < 2^56)"
                )
            }
            SpecError::NonCanonicalDigestLimb { limb_index, value } => write!(
                f,
                "non-canonical digest limb {limb_index}: {value:#x} >= p (GoldilocksField::ORDER)"
            ),
            SpecError::BalancesNotAscending { index } => write!(
                f,
                "balances entry {index} is not strictly ascending by asset_id (byte order)"
            ),
            SpecError::PositionOutOfRange { position, size } => write!(
                f,
                "position {position} out of range for log of size {size}"
            ),
            SpecError::ConsistencyRangeInvalid { m, n } => write!(
                f,
                "consistency range invalid: m={m} > n={n}"
            ),
            SpecError::NetworkTagTooLong { len } => {
                write!(f, "network tag too long: {len} bytes (max 255)")
            }
            SpecError::InvalidFinalityConfirmations { value } => write!(
                f,
                "invalid finality_confirmations: {value} (must be 6)"
            ),
            SpecError::CoinAlreadyAdmitted { coin_id } => write!(
                f,
                "coin already admitted: {}",
                hex::encode(coin_id)
            ),
            SpecError::CoinNotAdmitted { coin_id } => write!(
                f,
                "coin not admitted: {}",
                hex::encode(coin_id)
            ),
            SpecError::CoinAlreadySpent { coin_id } => write!(
                f,
                "coin already spent: {}",
                hex::encode(coin_id)
            ),
            SpecError::CoinNotAbsent { coin_id } => write!(
                f,
                "coin not absent: {}",
                hex::encode(coin_id)
            ),
            SpecError::OutOfOrderFold {
                previous,
                attempted,
            } => write!(
                f,
                "out-of-order nullifier fold: attempted chain_pos {:?} is not strictly after previous {:?}",
                attempted, previous
            ),
            SpecError::CoinHistLevelOutOfRange { level } => write!(
                f,
                "coin-history node level out of range: {level} (must be <= 256)"
            ),
            SpecError::BootstrapMagicInvalid { got } => write!(
                f,
                "bootstrap manifest magic invalid: got {:?} (expected ASCII \"BMF1\")",
                String::from_utf8_lossy(got)
            ),
            SpecError::BootstrapVersionInvalid { got } => write!(
                f,
                "bootstrap manifest version invalid: 0x{got:02x} (expected 0x01)"
            ),
            SpecError::BootstrapSeedRelayCountZero => {
                write!(f, "bootstrap manifest seed_relay_count is 0 (must be >= 1)")
            }
            SpecError::BootstrapBlobStoreCountZero => {
                write!(f, "bootstrap manifest blob_store_count is 0 (must be >= 1)")
            }
            SpecError::BootstrapOperatorIdCountZero => {
                write!(
                    f,
                    "bootstrap manifest operator_id_count is 0 (must be >= 1)"
                )
            }
            SpecError::BootstrapUrlEmpty { which, index } => {
                write!(f, "bootstrap manifest {which} URL at index {index} is empty")
            }
            SpecError::BootstrapUrlTooLong {
                which,
                index,
                len,
            } => write!(
                f,
                "bootstrap manifest {which} URL at index {index} is {len} bytes (max 2048)"
            ),
            SpecError::BootstrapTruncated {
                context,
                needed,
                remaining,
            } => write!(
                f,
                "bootstrap manifest truncated at {context}: needed {needed} bytes, have {remaining}"
            ),
            SpecError::BootstrapTrailingBytes { remaining } => write!(
                f,
                "bootstrap manifest has {remaining} trailing byte(s) after a complete frame"
            ),
            SpecError::BootstrapInvalidUtf8 { field, error } => {
                write!(f, "bootstrap manifest {field} is not valid UTF-8: {error}")
            }
            SpecError::BootstrapProtocolVersionInvalid { got } => write!(
                f,
                "bootstrap manifest protocol_version {got:?} is not exactly \"v1\""
            ),
            SpecError::BootstrapSignatureInvalid => {
                write!(
                    f,
                    "bootstrap manifest signature does not verify under the pinned bootstrap_pubkey"
                )
            }
            SpecError::BootstrapNetworkMismatch { expected, actual } => write!(
                f,
                "bootstrap manifest network {actual:?} does not match verifier network {expected:?}"
            ),
            SpecError::BootstrapProtocolVersionMismatch { expected, actual } => write!(
                f,
                "bootstrap manifest protocol_version {actual:?} does not match verifier {expected:?}"
            ),
            SpecError::BootstrapExpired { expires_at, now } => write!(
                f,
                "bootstrap manifest expired: expires_at={expires_at} < now={now}"
            ),
            SpecError::BootstrapIssuedAfterExpiry {
                issued_at,
                expires_at,
            } => write!(
                f,
                "bootstrap manifest issued_at={issued_at} is after expires_at={expires_at} \
                 (degenerate lifetime)"
            ),
            SpecError::BootstrapSecretKeyInvalid => write!(
                f,
                "bootstrap secret key is not a valid secp256k1 scalar — refusing to sign"
            ),
            SpecError::BootstrapPubkeyMismatch => write!(
                f,
                "derived bootstrap public key does not match the supplied bootstrap_pubkey — \
                 refusing to write an artifact the verifier would reject"
            ),
            SpecError::ScalarWrongLength { actual } => {
                write!(f, "scalar wrong length: expected 32, got {actual}")
            }
            SpecError::ScalarZero => {
                write!(f, "scalar is zero (must be in [1, n))")
            }
            SpecError::ScalarOutOfRange => {
                write!(f, "scalar ≥ n (must be in [1, n))")
            }
            SpecError::XOnlyWrongLength { actual } => {
                write!(f, "x-only public key wrong length: expected 32, got {actual}")
            }
            SpecError::XOnlyXGeP => {
                write!(f, "x-only x-coordinate ≥ p (secp256k1 field prime)")
            }
            SpecError::XOnlyOffCurve => {
                write!(f, "x-only x-coordinate is not on secp256k1")
            }
            SpecError::EnvelopeWrongPrefix => {
                write!(f, "NIP44Binary plaintext missing prefix \"zkcoins-bin-v1:\"")
            }
            SpecError::EnvelopeWrongLabel { expected, actual } => {
                write!(
                    f,
                    "NIP44Binary label mismatch: expected {expected:?}, got {actual:?}"
                )
            }
            SpecError::EnvelopeMissingSeparator => {
                write!(f, "NIP44Binary plaintext missing label/payload separator ':'")
            }
            SpecError::EnvelopeInvalidLabel => {
                write!(f, "NIP44Binary label is empty or contains ':'")
            }
            SpecError::Base64UrlPadding => {
                write!(f, "base64url_no_pad rejects '=' padding")
            }
            SpecError::Base64UrlStandardAlphabet => {
                write!(f, "base64url_no_pad rejects standard Base64 alphabet '+/'")
            }
            SpecError::Base64UrlWhitespace => {
                write!(f, "base64url_no_pad rejects whitespace")
            }
            SpecError::Base64UrlInvalidChar { ch } => {
                write!(f, "base64url_no_pad invalid character {ch:?}")
            }
            SpecError::Base64UrlInvalidLength { len } => {
                write!(f, "base64url_no_pad invalid length {len} (len % 4 == 1)")
            }
            SpecError::Base64UrlNonCanonical => {
                write!(f, "base64url_no_pad encoding is non-canonical")
            }
            SpecError::EnvelopeWrongBinaryLength { expected, actual } => {
                write!(
                    f,
                    "NIP44Binary decoded length mismatch: expected {expected}, got {actual}"
                )
            }
            SpecError::ZbeWrongMagic => {
                write!(f, "ZBE ciphertext missing magic \"ZBE1\"")
            }
            SpecError::ZbeTruncated => {
                write!(f, "ZBE ciphertext truncated before complete framing")
            }
            SpecError::ZbeInvalidChunkCount { n } => {
                write!(f, "ZBE invalid chunk count N={n} (must be >= 1)")
            }
            SpecError::ZbeChunkCountMismatch { declared, parsed } => {
                write!(
                    f,
                    "ZBE chunk count mismatch: declared N={declared}, parsed {parsed}"
                )
            }
            SpecError::ZbeChunkLengthOverrun {
                chunk_index,
                declared_len,
                remaining,
            } => write!(
                f,
                "ZBE chunk {chunk_index} length {declared_len} exceeds remaining {remaining} bytes"
            ),
            SpecError::ZbeTrailingBytes { remaining } => {
                write!(f, "ZBE trailing bytes after last chunk: {remaining}")
            }
            SpecError::ZbeChunkTooShort { chunk_index, len } => {
                write!(
                    f,
                    "ZBE chunk {chunk_index} length {len} is shorter than Poly1305 tag (16)"
                )
            }
            SpecError::ZbeAuthFailed { chunk_index } => {
                write!(
                    f,
                    "ZBE Poly1305 authentication failed for chunk {chunk_index}"
                )
            }
            SpecError::ZbeTooManyChunks { n } => {
                write!(f, "ZBE plaintext requires {n} chunks (exceeds u32::MAX)")
            }
            SpecError::BundleTruncated {
                context,
                needed,
                remaining,
            } => write!(
                f,
                "bundle truncated at {context}: needed {needed} bytes, have {remaining}"
            ),
            SpecError::BundleLengthOverrun {
                context,
                declared,
                remaining,
            } => write!(
                f,
                "bundle length prefix at {context}: declared {declared} exceeds remaining {remaining}"
            ),
            SpecError::BundleTrailingBytes {
                context,
                remaining,
            } => write!(
                f,
                "bundle {context} has {remaining} trailing byte(s) after a complete frame"
            ),
            SpecError::CoinProofPresenceInvalid { got } => write!(
                f,
                "CoinProof asset_terms presence byte 0x{got:02x} is not 0x00/0x01"
            ),
            SpecError::CoinProofIssuanceVersionInvalid { got } => write!(
                f,
                "CoinProof asset_terms.issuance_version 0x{got:02x} is not 0x01/0x02"
            ),
            SpecError::CoinProofAssetTermsVersionFieldsMismatch {
                issuance_version,
                cap_fields_present,
            } => write!(
                f,
                "CoinProof asset_terms version/trailing-field mismatch: \
                 issuance_version={issuance_version}, cap_fields_present={cap_fields_present}"
            ),
            SpecError::SdrMagicInvalid { got } => write!(
                f,
                "SelfDeliveryRecordV1 magic invalid: got {:?} (expected ASCII \"SDR1\")",
                String::from_utf8_lossy(got)
            ),
            SpecError::SdrVersionInvalid { got } => write!(
                f,
                "SelfDeliveryRecordV1 version invalid: 0x{got:02x} (expected 0x01)"
            ),
            SpecError::SdrRecordKindInvalid { got } => write!(
                f,
                "SelfDeliveryRecordV1 record_kind invalid: 0x{got:02x} (expected 0x01/0x02/0x03)"
            ),
            SpecError::BlobLocatorCountZero => {
                write!(f, "BlobLocatorSet holder_count is 0 (must be >= 1)")
            }
            SpecError::BlobLocatorCountTooHigh { count, max } => write!(
                f,
                "BlobLocatorSet holder_count {count} exceeds MAX_BLOB_HOLDERS ({max})"
            ),
            SpecError::BlobLocatorUrlEmpty { index } => {
                write!(f, "BlobLocatorSet holder URL at index {index} is empty")
            }
            SpecError::BlobLocatorUrlTooLong { index, len } => write!(
                f,
                "BlobLocatorSet holder URL at index {index} is {len} bytes (max 2048)"
            ),
            SpecError::BlobLocatorInvalidUtf8 { index } => {
                write!(f, "BlobLocatorSet holder URL at index {index} is not valid UTF-8")
            }
            SpecError::BlobLocatorUrlContainsNul { index } => {
                write!(f, "BlobLocatorSet holder URL at index {index} contains a NUL byte")
            }
        }
    }
}

impl std::error::Error for SpecError {}

#[cfg(test)]
mod tests {
    use super::super::accumulator::ChainPosition;
    use super::*;
    use std::error::Error;

    #[test]
    fn bootstrap_url_kind_display() {
        assert_eq!(BootstrapUrlKind::SeedRelay.to_string(), "seed_relay");
        assert_eq!(BootstrapUrlKind::BlobStore.to_string(), "blob_store");
    }

    #[test]
    fn bootstrap_string_field_display() {
        assert_eq!(BootstrapStringField::Network.to_string(), "network");
        assert_eq!(
            BootstrapStringField::ProtocolVersion.to_string(),
            "protocol_version"
        );
        assert_eq!(
            BootstrapStringField::SeedRelay { index: 3 }.to_string(),
            "seed_relays[3]"
        );
        assert_eq!(
            BootstrapStringField::BlobStore { index: 7 }.to_string(),
            "blob_stores[7]"
        );
    }

    #[test]
    fn spec_error_source_is_none_and_dyn_error() {
        let err = SpecError::NameEmpty;
        assert!(err.source().is_none());
        let as_dyn: &dyn Error = &err;
        assert_eq!(as_dyn.to_string(), "name is empty after §4.3 normalization");
        let boxed: Box<dyn Error> = Box::new(SpecError::ScalarZero);
        assert_eq!(boxed.to_string(), "scalar is zero (must be in [1, n))");
        assert!(boxed.source().is_none());
    }

    #[test]
    fn spec_error_clone_eq_debug() {
        let a = SpecError::TooManyBalances { count: 40, max: 32 };
        let b = a.clone();
        assert_eq!(a, b);
        let c = SpecError::TooManyBalances { count: 41, max: 32 };
        assert_ne!(a, c);
        let d = SpecError::ZeroAmountBalance;
        assert_ne!(a, d);
        let debug = format!("{:?}", a);
        assert!(debug.contains("TooManyBalances"));
    }

    #[test]
    fn spec_error_display_all_variants() {
        // Name / network / identifier
        assert_eq!(
            SpecError::NameTooLong { len: 300 }.to_string(),
            "asset name too long: 300 bytes (max 255)"
        );
        assert_eq!(
            SpecError::NameEmpty.to_string(),
            "name is empty after §4.3 normalization"
        );
        assert_eq!(
            SpecError::NetworkEmpty.to_string(),
            "network field is empty"
        );
        assert_eq!(
            SpecError::NetworkUnknown {
                network: "foo".to_string()
            }
            .to_string(),
            "network \"foo\" is not in the closed set {mainnet, testnet, regtest} (§4.3 / §7.3)"
        );
        assert_eq!(
            SpecError::NameMissingAt.to_string(),
            "identifier missing '@' separator (§4.3)"
        );
        assert_eq!(
            SpecError::NameMultipleAt.to_string(),
            "identifier has more than one '@' (§4.3)"
        );
        assert_eq!(
            SpecError::NameEmptyLocal.to_string(),
            "identifier local part is empty (§4.3)"
        );
        assert_eq!(
            SpecError::NameEmptyDomain.to_string(),
            "identifier domain is empty (§4.3)"
        );
        assert_eq!(
            SpecError::NameLocalLeadingDot.to_string(),
            "identifier local part begins with '.' (§4.3)"
        );
        assert_eq!(
            SpecError::NameLocalTrailingDot.to_string(),
            "identifier local part ends with '.' (§4.3)"
        );
        assert_eq!(
            SpecError::NameLocalConsecutiveDots.to_string(),
            "identifier local part contains consecutive '..' (§4.3)"
        );
        assert_eq!(
            SpecError::NameLocalInvalidChar { ch: '!' }.to_string(),
            "identifier local part has invalid character '!' (only a-z0-9-_. allowed, §4.3)"
        );
        assert_eq!(
            SpecError::NameDomainLabelEmpty.to_string(),
            "identifier domain has empty label (§4.3 DNS hostname)"
        );
        assert_eq!(
            SpecError::NameDomainLabelLeadingHyphen.to_string(),
            "identifier domain label begins with '-' (§4.3 DNS hostname)"
        );
        assert_eq!(
            SpecError::NameDomainLabelTrailingHyphen.to_string(),
            "identifier domain label ends with '-' (§4.3 DNS hostname)"
        );
        assert_eq!(
            SpecError::NameDomainLabelInvalidChar { ch: '@' }.to_string(),
            "identifier domain label has invalid character '@' (only a-z0-9- allowed, §4.3)"
        );
        assert_eq!(
            SpecError::NameDomainLabelTooLong { len: 64 }.to_string(),
            "identifier domain label too long: 64 octets (max 63, §4.3 DNS hostname)"
        );
        assert_eq!(
            SpecError::NameDomainTooLong { len: 300 }.to_string(),
            "identifier domain too long: 300 octets (max 253, §4.3 DNS hostname)"
        );

        // Balances / lengths / bech32 / numeric
        assert_eq!(
            SpecError::TooManyBalances { count: 40, max: 32 }.to_string(),
            "too many balance entries: 40 (max 32)"
        );
        assert_eq!(
            SpecError::ZeroAmountBalance.to_string(),
            "zero-amount balance entry is forbidden"
        );
        assert_eq!(
            SpecError::WrongLength {
                expected: 32,
                actual: 16
            }
            .to_string(),
            "wrong input length: expected 32, got 16"
        );
        assert_eq!(
            SpecError::Bech32WrongHrp {
                expected: "zkc",
                actual: "btc".to_string()
            }
            .to_string(),
            "bech32m wrong HRP: expected \"zkc\", got \"btc\""
        );
        assert_eq!(
            SpecError::Bech32DecodeError("checksum failed".to_string()).to_string(),
            "bech32m decode error: checksum failed"
        );
        assert_eq!(
            SpecError::SmallNumericOutOfRange { value: 1u64 << 56 }.to_string(),
            "small-numeric value out of range: 72057594037927936 (must be < 2^56)"
        );
        assert_eq!(
            SpecError::ByteStringTooLong { len: 999 }.to_string(),
            "byte-string length out of range: 999 (must be < 2^56)"
        );
        assert_eq!(
            SpecError::NonCanonicalDigestLimb {
                limb_index: 2,
                value: 0xdeadbeef
            }
            .to_string(),
            "non-canonical digest limb 2: 0xdeadbeef >= p (GoldilocksField::ORDER)"
        );
        assert_eq!(
            SpecError::BalancesNotAscending { index: 5 }.to_string(),
            "balances entry 5 is not strictly ascending by asset_id (byte order)"
        );
        assert_eq!(
            SpecError::PositionOutOfRange {
                position: 10,
                size: 3
            }
            .to_string(),
            "position 10 out of range for log of size 3"
        );
        assert_eq!(
            SpecError::ConsistencyRangeInvalid { m: 8, n: 4 }.to_string(),
            "consistency range invalid: m=8 > n=4"
        );
        assert_eq!(
            SpecError::NetworkTagTooLong { len: 300 }.to_string(),
            "network tag too long: 300 bytes (max 255)"
        );
        assert_eq!(
            SpecError::InvalidFinalityConfirmations { value: 9 }.to_string(),
            "invalid finality_confirmations: 9 (must be 6)"
        );

        // Coin history
        let coin_id = [0xab; 32];
        let coin_hex = hex::encode(coin_id);
        assert_eq!(
            SpecError::CoinAlreadyAdmitted { coin_id }.to_string(),
            format!("coin already admitted: {coin_hex}")
        );
        assert_eq!(
            SpecError::CoinNotAdmitted { coin_id }.to_string(),
            format!("coin not admitted: {coin_hex}")
        );
        assert_eq!(
            SpecError::CoinAlreadySpent { coin_id }.to_string(),
            format!("coin already spent: {coin_hex}")
        );
        assert_eq!(
            SpecError::CoinNotAbsent { coin_id }.to_string(),
            format!("coin not absent: {coin_hex}")
        );
        let previous = ChainPosition {
            height: 1,
            tx_index: 2,
            vin_index: 3,
            member_index: 4,
        };
        let attempted = ChainPosition {
            height: 0,
            tx_index: 0,
            vin_index: 0,
            member_index: 0,
        };
        assert_eq!(
            SpecError::OutOfOrderFold {
                previous,
                attempted
            }
            .to_string(),
            format!(
                "out-of-order nullifier fold: attempted chain_pos {:?} is not strictly after previous {:?}",
                attempted, previous
            )
        );
        assert_eq!(
            SpecError::CoinHistLevelOutOfRange { level: 300 }.to_string(),
            "coin-history node level out of range: 300 (must be <= 256)"
        );

        // Bootstrap
        assert_eq!(
            SpecError::BootstrapMagicInvalid { got: *b"XYZQ" }.to_string(),
            "bootstrap manifest magic invalid: got \"XYZQ\" (expected ASCII \"BMF1\")"
        );
        assert_eq!(
            SpecError::BootstrapVersionInvalid { got: 0x02 }.to_string(),
            "bootstrap manifest version invalid: 0x02 (expected 0x01)"
        );
        assert_eq!(
            SpecError::BootstrapSeedRelayCountZero.to_string(),
            "bootstrap manifest seed_relay_count is 0 (must be >= 1)"
        );
        assert_eq!(
            SpecError::BootstrapBlobStoreCountZero.to_string(),
            "bootstrap manifest blob_store_count is 0 (must be >= 1)"
        );
        assert_eq!(
            SpecError::BootstrapOperatorIdCountZero.to_string(),
            "bootstrap manifest operator_id_count is 0 (must be >= 1)"
        );
        assert_eq!(
            SpecError::BootstrapUrlEmpty {
                which: BootstrapUrlKind::SeedRelay,
                index: 1
            }
            .to_string(),
            "bootstrap manifest seed_relay URL at index 1 is empty"
        );
        assert_eq!(
            SpecError::BootstrapUrlTooLong {
                which: BootstrapUrlKind::BlobStore,
                index: 2,
                len: 3000
            }
            .to_string(),
            "bootstrap manifest blob_store URL at index 2 is 3000 bytes (max 2048)"
        );
        assert_eq!(
            SpecError::BootstrapTruncated {
                context: "header",
                needed: 10,
                remaining: 3
            }
            .to_string(),
            "bootstrap manifest truncated at header: needed 10 bytes, have 3"
        );
        assert_eq!(
            SpecError::BootstrapTrailingBytes { remaining: 4 }.to_string(),
            "bootstrap manifest has 4 trailing byte(s) after a complete frame"
        );
        assert_eq!(
            SpecError::BootstrapInvalidUtf8 {
                field: BootstrapStringField::Network,
                error: "invalid utf-8 sequence".to_string()
            }
            .to_string(),
            "bootstrap manifest network is not valid UTF-8: invalid utf-8 sequence"
        );
        assert_eq!(
            SpecError::BootstrapProtocolVersionInvalid {
                got: "v2".to_string()
            }
            .to_string(),
            "bootstrap manifest protocol_version \"v2\" is not exactly \"v1\""
        );
        assert_eq!(
            SpecError::BootstrapSignatureInvalid.to_string(),
            "bootstrap manifest signature does not verify under the pinned bootstrap_pubkey"
        );
        assert_eq!(
            SpecError::BootstrapNetworkMismatch {
                expected: "mainnet".to_string(),
                actual: "testnet".to_string()
            }
            .to_string(),
            "bootstrap manifest network \"testnet\" does not match verifier network \"mainnet\""
        );
        assert_eq!(
            SpecError::BootstrapProtocolVersionMismatch {
                expected: "v1".to_string(),
                actual: "v0".to_string()
            }
            .to_string(),
            "bootstrap manifest protocol_version \"v0\" does not match verifier \"v1\""
        );
        assert_eq!(
            SpecError::BootstrapExpired {
                expires_at: 100,
                now: 200
            }
            .to_string(),
            "bootstrap manifest expired: expires_at=100 < now=200"
        );
        assert_eq!(
            SpecError::BootstrapIssuedAfterExpiry {
                issued_at: 50,
                expires_at: 40
            }
            .to_string(),
            "bootstrap manifest issued_at=50 is after expires_at=40 (degenerate lifetime)"
        );
        assert_eq!(
            SpecError::BootstrapSecretKeyInvalid.to_string(),
            "bootstrap secret key is not a valid secp256k1 scalar — refusing to sign"
        );
        assert_eq!(
            SpecError::BootstrapPubkeyMismatch.to_string(),
            "derived bootstrap public key does not match the supplied bootstrap_pubkey — \
 refusing to write an artifact the verifier would reject"
        );

        // Note encryption / envelope / base64
        assert_eq!(
            SpecError::ScalarWrongLength { actual: 16 }.to_string(),
            "scalar wrong length: expected 32, got 16"
        );
        assert_eq!(
            SpecError::ScalarZero.to_string(),
            "scalar is zero (must be in [1, n))"
        );
        assert_eq!(
            SpecError::ScalarOutOfRange.to_string(),
            "scalar ≥ n (must be in [1, n))"
        );
        assert_eq!(
            SpecError::XOnlyWrongLength { actual: 33 }.to_string(),
            "x-only public key wrong length: expected 32, got 33"
        );
        assert_eq!(
            SpecError::XOnlyXGeP.to_string(),
            "x-only x-coordinate ≥ p (secp256k1 field prime)"
        );
        assert_eq!(
            SpecError::XOnlyOffCurve.to_string(),
            "x-only x-coordinate is not on secp256k1"
        );
        assert_eq!(
            SpecError::EnvelopeWrongPrefix.to_string(),
            "NIP44Binary plaintext missing prefix \"zkcoins-bin-v1:\""
        );
        assert_eq!(
            SpecError::EnvelopeWrongLabel {
                expected: "foo".to_string(),
                actual: "bar".to_string()
            }
            .to_string(),
            "NIP44Binary label mismatch: expected \"foo\", got \"bar\""
        );
        assert_eq!(
            SpecError::EnvelopeMissingSeparator.to_string(),
            "NIP44Binary plaintext missing label/payload separator ':'"
        );
        assert_eq!(
            SpecError::EnvelopeInvalidLabel.to_string(),
            "NIP44Binary label is empty or contains ':'"
        );
        assert_eq!(
            SpecError::Base64UrlPadding.to_string(),
            "base64url_no_pad rejects '=' padding"
        );
        assert_eq!(
            SpecError::Base64UrlStandardAlphabet.to_string(),
            "base64url_no_pad rejects standard Base64 alphabet '+/'"
        );
        assert_eq!(
            SpecError::Base64UrlWhitespace.to_string(),
            "base64url_no_pad rejects whitespace"
        );
        assert_eq!(
            SpecError::Base64UrlInvalidChar { ch: '%' }.to_string(),
            "base64url_no_pad invalid character '%'"
        );
        assert_eq!(
            SpecError::Base64UrlInvalidLength { len: 5 }.to_string(),
            "base64url_no_pad invalid length 5 (len % 4 == 1)"
        );
        assert_eq!(
            SpecError::Base64UrlNonCanonical.to_string(),
            "base64url_no_pad encoding is non-canonical"
        );
        assert_eq!(
            SpecError::EnvelopeWrongBinaryLength {
                expected: 32,
                actual: 16
            }
            .to_string(),
            "NIP44Binary decoded length mismatch: expected 32, got 16"
        );

        // ZBE
        assert_eq!(
            SpecError::ZbeWrongMagic.to_string(),
            "ZBE ciphertext missing magic \"ZBE1\""
        );
        assert_eq!(
            SpecError::ZbeTruncated.to_string(),
            "ZBE ciphertext truncated before complete framing"
        );
        assert_eq!(
            SpecError::ZbeInvalidChunkCount { n: 0 }.to_string(),
            "ZBE invalid chunk count N=0 (must be >= 1)"
        );
        assert_eq!(
            SpecError::ZbeChunkCountMismatch {
                declared: 3,
                parsed: 2
            }
            .to_string(),
            "ZBE chunk count mismatch: declared N=3, parsed 2"
        );
        assert_eq!(
            SpecError::ZbeChunkLengthOverrun {
                chunk_index: 1,
                declared_len: 100,
                remaining: 10
            }
            .to_string(),
            "ZBE chunk 1 length 100 exceeds remaining 10 bytes"
        );
        assert_eq!(
            SpecError::ZbeTrailingBytes { remaining: 7 }.to_string(),
            "ZBE trailing bytes after last chunk: 7"
        );
        assert_eq!(
            SpecError::ZbeChunkTooShort {
                chunk_index: 0,
                len: 8
            }
            .to_string(),
            "ZBE chunk 0 length 8 is shorter than Poly1305 tag (16)"
        );
        assert_eq!(
            SpecError::ZbeAuthFailed { chunk_index: 4 }.to_string(),
            "ZBE Poly1305 authentication failed for chunk 4"
        );
        assert_eq!(
            SpecError::ZbeTooManyChunks { n: 5000000000 }.to_string(),
            "ZBE plaintext requires 5000000000 chunks (exceeds u32::MAX)"
        );

        // Bundle / CoinProof / SDR / BlobLocator
        assert_eq!(
            SpecError::BundleTruncated {
                context: "coin_proof",
                needed: 20,
                remaining: 5
            }
            .to_string(),
            "bundle truncated at coin_proof: needed 20 bytes, have 5"
        );
        assert_eq!(
            SpecError::BundleLengthOverrun {
                context: "payload",
                declared: 100,
                remaining: 50
            }
            .to_string(),
            "bundle length prefix at payload: declared 100 exceeds remaining 50"
        );
        assert_eq!(
            SpecError::BundleTrailingBytes {
                context: "sdr",
                remaining: 2
            }
            .to_string(),
            "bundle sdr has 2 trailing byte(s) after a complete frame"
        );
        assert_eq!(
            SpecError::CoinProofPresenceInvalid { got: 0x03 }.to_string(),
            "CoinProof asset_terms presence byte 0x03 is not 0x00/0x01"
        );
        assert_eq!(
            SpecError::CoinProofIssuanceVersionInvalid { got: 0x00 }.to_string(),
            "CoinProof asset_terms.issuance_version 0x00 is not 0x01/0x02"
        );
        assert_eq!(
            SpecError::CoinProofAssetTermsVersionFieldsMismatch {
                issuance_version: 1,
                cap_fields_present: true
            }
            .to_string(),
            "CoinProof asset_terms version/trailing-field mismatch: \
 issuance_version=1, cap_fields_present=true"
        );
        assert_eq!(
            SpecError::SdrMagicInvalid { got: *b"XXXX" }.to_string(),
            "SelfDeliveryRecordV1 magic invalid: got \"XXXX\" (expected ASCII \"SDR1\")"
        );
        assert_eq!(
            SpecError::SdrVersionInvalid { got: 0xff }.to_string(),
            "SelfDeliveryRecordV1 version invalid: 0xff (expected 0x01)"
        );
        assert_eq!(
            SpecError::SdrRecordKindInvalid { got: 0x09 }.to_string(),
            "SelfDeliveryRecordV1 record_kind invalid: 0x09 (expected 0x01/0x02/0x03)"
        );
        assert_eq!(
            SpecError::BlobLocatorCountZero.to_string(),
            "BlobLocatorSet holder_count is 0 (must be >= 1)"
        );
        assert_eq!(
            SpecError::BlobLocatorCountTooHigh {
                count: 100,
                max: 16
            }
            .to_string(),
            "BlobLocatorSet holder_count 100 exceeds MAX_BLOB_HOLDERS (16)"
        );
        assert_eq!(
            SpecError::BlobLocatorUrlEmpty { index: 0 }.to_string(),
            "BlobLocatorSet holder URL at index 0 is empty"
        );
        assert_eq!(
            SpecError::BlobLocatorUrlTooLong {
                index: 3,
                len: 4096
            }
            .to_string(),
            "BlobLocatorSet holder URL at index 3 is 4096 bytes (max 2048)"
        );
        assert_eq!(
            SpecError::BlobLocatorInvalidUtf8 { index: 2 }.to_string(),
            "BlobLocatorSet holder URL at index 2 is not valid UTF-8"
        );
        assert_eq!(
            SpecError::BlobLocatorUrlContainsNul { index: 1 }.to_string(),
            "BlobLocatorSet holder URL at index 1 contains a NUL byte"
        );
    }
}
