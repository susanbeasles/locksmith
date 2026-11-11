use core::fmt;

/// Cryptographic and key-unwrapping errors.
///
/// Display and Debug representations intentionally never contain raw key
/// material, shares, ciphertexts, or secret bytes.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum CryptoError {
    /// Context component count exceeded `u16::MAX`.
    ContextTooManyComponents,
    /// A context component exceeded `u16::MAX` bytes.
    ContextComponentTooLarge { index: usize, len: usize },
    /// Secret identifier is empty, exceeds bounds, or contains control/non-graphic bytes.
    InvalidSecretId,
    /// Sealed envelope wire format or version is invalid.
    InvalidEnvelopeFormat,
    /// Sealed envelope carries an unsupported version tag.
    UnsupportedEnvelopeVersion(u8),
    /// Hardware security token challenge-response failed.
    HardwareFailure,
    /// Underlying HKDF expansion failed.
    KeyDerivationFailed,
    /// Cryptographic random number generation failed.
    RngFailure,
    /// AEAD authentication failed (tag, ciphertext, nonce, share, or AAD mismatch).
    AuthenticationFailed,
}

impl fmt::Display for CryptoError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::ContextTooManyComponents => {
                f.write_str("HKDF context component count exceeds u16::MAX")
            }
            Self::ContextComponentTooLarge { index, len } => {
                write!(
                    f,
                    "HKDF context component at index {index} has length {len} exceeding u16::MAX"
                )
            }
            Self::InvalidSecretId => f.write_str("invalid secret identifier"),
            Self::InvalidEnvelopeFormat => f.write_str("invalid sealed secret envelope format"),
            Self::UnsupportedEnvelopeVersion(ver) => {
                write!(f, "unsupported sealed envelope version {ver}")
            }
            Self::HardwareFailure => f.write_str("hardware unwrapper operation failed"),
            Self::KeyDerivationFailed => f.write_str("HKDF-SHA256 key derivation failed"),
            Self::RngFailure => f.write_str("CSPRNG entropy generation failed"),
            Self::AuthenticationFailed => {
                f.write_str("AEAD envelope authentication failed [REDACTED]")
            }
        }
    }
}

impl std::error::Error for CryptoError {}

/// Single-use nonce replay filter errors.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ReplayError {
    /// Filter configuration had zero skew window or zero max capacity.
    InvalidConfiguration,
    /// Request timestamp is older than `now_ms - skew_window_ms`.
    TimestampExpired {
        timestamp_ms: u64,
        now_ms: u64,
        skew_window_ms: u64,
    },
    /// Request timestamp is further ahead than `now_ms + skew_window_ms`.
    TimestampInFuture {
        timestamp_ms: u64,
        now_ms: u64,
        skew_window_ms: u64,
    },
    /// Nonce was already burned within the active freshness window.
    NonceAlreadyBurned,
    /// Active unexpired nonce table is full; failing closed prevents eviction-replay.
    CapacityExceeded { max_entries: usize },
    /// Internal synchronization primitive was poisoned or unavailable.
    StateCorrupted,
}

impl fmt::Display for ReplayError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidConfiguration => f.write_str("invalid replay filter configuration"),
            Self::TimestampExpired {
                timestamp_ms,
                now_ms,
                skew_window_ms,
            } => write!(
                f,
                "nonce timestamp {timestamp_ms} expired relative to {now_ms} (window {skew_window_ms}ms)"
            ),
            Self::TimestampInFuture {
                timestamp_ms,
                now_ms,
                skew_window_ms,
            } => write!(
                f,
                "nonce timestamp {timestamp_ms} exceeds future skew relative to {now_ms} (window {skew_window_ms}ms)"
            ),
            Self::NonceAlreadyBurned => f.write_str("single-use nonce already burned"),
            Self::CapacityExceeded { max_entries } => {
                write!(f, "replay filter active capacity ({max_entries}) exceeded")
            }
            Self::StateCorrupted => f.write_str("replay filter synchronization state corrupted"),
        }
    }
}

impl std::error::Error for ReplayError {}

/// Append-only `BLAKE3` audit ledger errors.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum LedgerError {
    /// Required event field was empty.
    EmptyField { field: &'static str },
    /// Event field exceeded `u16::MAX` bytes.
    FieldTooLarge { field: &'static str, len: usize },
    /// Sequence numbers in verified slice were non-contiguous.
    SequenceDiscontinuity { expected: u64, actual: u64 },
    /// Entry `prev_hash` did not match preceding `entry_hash`.
    PrevHashMismatch { sequence: u64 },
    /// Recomputed `BLAKE3` digest did not match stored `entry_hash`.
    EntryHashTampered { sequence: u64 },
    /// Internal synchronization state was poisoned or corrupted.
    StateCorrupted,
}

impl fmt::Display for LedgerError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::EmptyField { field } => {
                write!(f, "audit ledger field '{field}' must not be empty")
            }
            Self::FieldTooLarge { field, len } => {
                write!(
                    f,
                    "audit ledger field '{field}' length {len} exceeds u16::MAX"
                )
            }
            Self::SequenceDiscontinuity { expected, actual } => write!(
                f,
                "audit ledger sequence discontinuity: expected {expected}, got {actual}"
            ),
            Self::PrevHashMismatch { sequence } => {
                write!(
                    f,
                    "audit ledger prev_hash chain broken at sequence {sequence}"
                )
            }
            Self::EntryHashTampered { sequence } => {
                write!(
                    f,
                    "audit ledger entry_hash tamper detected at sequence {sequence}"
                )
            }
            Self::StateCorrupted => f.write_str("audit ledger synchronization state corrupted"),
        }
    }
}

impl std::error::Error for LedgerError {}
