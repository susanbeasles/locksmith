use core::fmt;

use anvil_core::ReplayError;

/// Errors produced by `anvil-ipc` framing, transport authentication, and
/// attested command verification.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum IpcError {
    /// 4-byte wire magic did not match `"LKSM"`.
    InvalidMagic([u8; 4]),
    /// Wire protocol version byte was unsupported.
    UnsupportedVersion(u8),
    /// Wire message type tag was unrecognized.
    UnknownMessageType(u8),
    /// Declared payload length exceeded `MAX_FRAME_BYTES` (`65_536`).
    FrameTooLarge { declared_len: u32, max_len: usize },
    /// Frame read or write exceeded configured deadline.
    FrameTimeout,
    /// Peer closed stream mid-frame.
    UnexpectedEof,
    /// Peer `AF_VSOCK` CID or Unix `SO_PEERCRED` UID was not allowlisted.
    UnauthorizedPeer { detail: String },
    /// Serialized command envelope was truncated or malformed.
    InvalidEnvelopeFormat,
    /// Envelope `guest_cid` did not match transport-verified peer identity.
    GuestCidMismatch { expected: u32, actual: u32 },
    /// Recomputed `BLAKE3` digest of command payload did not match `command_digest`.
    CommandDigestMismatch,
    /// Constant-time verification of `hardware_signature` failed.
    SignatureVerificationFailed,
    /// Command `sequence_no` did not strictly advance past prior sequence.
    SequenceViolation { last_seen: Option<u64>, actual: u64 },
    /// Nonce freshness or single-use burn check failed.
    Replay(ReplayError),
    /// Underlying socket/transport error.
    IoError(String),
}

impl From<ReplayError> for IpcError {
    fn from(value: ReplayError) -> Self {
        Self::Replay(value)
    }
}

impl fmt::Display for IpcError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidMagic(m) => write!(f, "invalid IPC frame magic: {m:02x?}"),
            Self::UnsupportedVersion(v) => write!(f, "unsupported IPC frame version: {v}"),
            Self::UnknownMessageType(t) => write!(f, "unknown IPC message type: 0x{t:02x}"),
            Self::FrameTooLarge {
                declared_len,
                max_len,
            } => write!(
                f,
                "IPC frame declared payload {declared_len} bytes exceeding hard cap {max_len}"
            ),
            Self::FrameTimeout => f.write_str("IPC frame deadline exceeded"),
            Self::UnexpectedEof => f.write_str("unexpected EOF while reading IPC frame"),
            Self::UnauthorizedPeer { detail } => write!(f, "unauthorized IPC peer: {detail}"),
            Self::InvalidEnvelopeFormat => f.write_str("invalid attested command envelope format"),
            Self::GuestCidMismatch { expected, actual } => write!(
                f,
                "envelope guest_cid {actual} does not match authenticated peer CID {expected}"
            ),
            Self::CommandDigestMismatch => f.write_str("command payload BLAKE3 digest mismatch"),
            Self::SignatureVerificationFailed => {
                f.write_str("attested command signature verification failed")
            }
            Self::SequenceViolation { last_seen, actual } => write!(
                f,
                "non-monotonic command sequence {actual} (last_seen: {last_seen:?})"
            ),
            Self::Replay(err) => write!(f, "command replay rejected: {err}"),
            Self::IoError(msg) => write!(f, "IPC transport I/O error: {msg}"),
        }
    }
}

impl std::error::Error for IpcError {}
