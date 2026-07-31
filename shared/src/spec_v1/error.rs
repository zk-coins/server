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
        }
    }
}

impl std::error::Error for SpecError {}
