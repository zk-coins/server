//! Error type for `spec_v1` validation failures (fail-loud, no silent defaults).

use std::fmt;

/// Protocol-foundation validation / encoding error.
///
/// Every recoverable failure in `spec_v1` returns this type rather than
/// silently clamping, truncating, or substituting a default value.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SpecError {
    /// Asset name longer than 255 bytes.
    NameTooLong { len: usize },
    /// `AccountState.balances` exceeds `MAX_ACCOUNT_ASSETS`.
    TooManyBalances { count: usize, max: usize },
    /// A balance entry has `amount == 0` (must be omitted).
    ZeroAmountBalance,
    /// Input byte length does not match the expected fixed width.
    WrongLength { expected: usize, actual: usize },
    /// Bech32m HRP is not the expected value.
    Bech32WrongHrp { expected: &'static str, actual: String },
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
}

impl fmt::Display for SpecError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            SpecError::NameTooLong { len } => {
                write!(f, "asset name too long: {len} bytes (max 255)")
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
        }
    }
}

impl std::error::Error for SpecError {}
