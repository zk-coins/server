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
