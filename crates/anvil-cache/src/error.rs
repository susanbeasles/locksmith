use core::fmt;

/// Errors produced when validating untrusted string metadata for terminal or
/// prompt-injection control sequences.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum SanitizeError {
    /// Metadata string was empty.
    EmptyString,
    /// Metadata string exceeded `max` bytes.
    TooLong { len: usize, max: usize },
    /// C0, DEL, or C1 control character encountered.
    ControlCharacter { byte_offset: usize, codepoint: u32 },
    /// ANSI CSI/OSC escape initiator encountered.
    AnsiEscapeSequence { byte_offset: usize },
    /// Invisible Unicode Tag block character (`U+E0000..=U+E007F`) encountered.
    UnicodeTagCharacter { byte_offset: usize, codepoint: u32 },
    /// Bidirectional override/isolate or zero-width formatter encountered.
    BidiOrZeroWidthCharacter { byte_offset: usize, codepoint: u32 },
}

impl fmt::Display for SanitizeError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::EmptyString => f.write_str("metadata string must not be empty"),
            Self::TooLong { len, max } => {
                write!(f, "metadata string length {len} exceeds maximum {max}")
            }
            Self::ControlCharacter {
                byte_offset,
                codepoint,
            } => write!(
                f,
                "control character U+{codepoint:04X} rejected at byte offset {byte_offset}"
            ),
            Self::AnsiEscapeSequence { byte_offset } => write!(
                f,
                "ANSI CSI/OSC escape sequence rejected at byte offset {byte_offset}"
            ),
            Self::UnicodeTagCharacter {
                byte_offset,
                codepoint,
            } => write!(
                f,
                "invisible Unicode tag U+{codepoint:05X} rejected at byte offset {byte_offset}"
            ),
            Self::BidiOrZeroWidthCharacter {
                byte_offset,
                codepoint,
            } => write!(
                f,
                "bidirectional or zero-width character U+{codepoint:04X} rejected at byte offset {byte_offset}"
            ),
        }
    }
}

impl std::error::Error for SanitizeError {}

/// Errors produced by [`crate::store::CacheStore`] and [`crate::seal`].
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum CacheError {
    /// Logical cache key was empty, too long, or contained invalid characters.
    InvalidLogicalKey,
    /// Relative path escaped cache root, traversed `..`, or hit a symlink/mount boundary.
    PathViolation,
    /// Requested cache entry or content blob does not exist.
    NotFound,
    /// Untrusted blob exceeded configured `max_blob_bytes`.
    BlobTooLarge { len: u64, max: u64 },
    /// On-disk metadata record could not be parsed.
    CorruptRecordFormat,
    /// Entry schema version did not match store's configured schema version.
    SchemaVersionMismatch { expected: u32, actual: u32 },
    /// Keyed `BLAKE3` MAC or content digest verification failed.
    IntegrityMismatch,
    /// Cached metadata failed sanitizer checks.
    Sanitize(SanitizeError),
    /// Kernel `memfd` file sealing failed or returned incomplete seals.
    SealFailed,
    /// Underlying filesystem I/O failure.
    IoError,
}

impl From<SanitizeError> for CacheError {
    fn from(value: SanitizeError) -> Self {
        Self::Sanitize(value)
    }
}

impl fmt::Display for CacheError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidLogicalKey => f.write_str("invalid logical cache key"),
            Self::PathViolation => {
                f.write_str("cache path confinement violation (traversal or symlink rejected)")
            }
            Self::NotFound => f.write_str("cache entry not found"),
            Self::BlobTooLarge { len, max } => {
                write!(f, "cache blob size {len} exceeds maximum {max} bytes")
            }
            Self::CorruptRecordFormat => f.write_str("corrupt cache metadata record"),
            Self::SchemaVersionMismatch { expected, actual } => write!(
                f,
                "cache schema version mismatch: expected {expected}, got {actual}"
            ),
            Self::IntegrityMismatch => {
                f.write_str("cache keyed BLAKE3 MAC or content digest mismatch")
            }
            Self::Sanitize(inner) => write!(f, "cache metadata sanitization failed: {inner}"),
            Self::SealFailed => f.write_str("kernel memfd file sealing failed"),
            Self::IoError => f.write_str("cache filesystem I/O error"),
        }
    }
}

impl std::error::Error for CacheError {}
