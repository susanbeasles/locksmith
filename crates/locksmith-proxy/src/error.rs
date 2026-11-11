use core::fmt;

use anvil_core::{CryptoError, ReplayError};

/// Policy gate and HTTP canonicalization errors (`PolicyEngine::authorize_egress`).
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum PolicyError {
    /// Claimed workload ID is not registered in the policy engine.
    UnknownWorkload,
    /// Guest CID does not match the registered workload's bound CID.
    GuestCidMismatch { expected: u32, actual: u32 },
    /// No peer X.509 leaf certificate was presented on the mTLS transport.
    MissingClientCertificate,
    /// RFC 8705 SHA-256 certificate thumbprint did not match registered workload identity.
    CertificateThumbprintMismatch,
    /// Target `(sni_hostname, port, method, path)` did not match any static allowlist rule.
    TargetNotAllowed,
    /// HTTP/1.1 request line, path, or version failed RFC 9110/9112 syntax rules.
    MalformedHttpRequest { reason: &'static str },
    /// Missing, duplicate, or SNI-mismatched `Host` header (domain fronting attempt).
    HostSniMismatch,
    /// CR, LF, NUL, obs-fold, or illegal control/header-name bytes detected.
    HeaderSmugglingDetected { reason: &'static str },
    /// Conflicting `Content-Length` + `Transfer-Encoding`, duplicate `Content-Length`, or length mismatch.
    ConflictingFramingHeaders,
    /// Guest supplied `Authorization` or `Proxy-Authorization` when rule mode is `Reject`.
    ForbiddenGuestAuthHeader,
    /// Single-use request nonce failed freshness or burn check.
    Replay(ReplayError),
    /// 2-of-2 hardware-attested secret unwrap failed.
    UnwrapFailed(CryptoError),
    /// Unwrapped secret is shorter than `MIN_INJECTED_SECRET_BYTES`.
    SecretTooShort { min_bytes: usize },
}

impl From<ReplayError> for PolicyError {
    fn from(value: ReplayError) -> Self {
        Self::Replay(value)
    }
}

impl From<CryptoError> for PolicyError {
    fn from(value: CryptoError) -> Self {
        Self::UnwrapFailed(value)
    }
}

impl fmt::Display for PolicyError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::UnknownWorkload => f.write_str("unknown workload identity"),
            Self::GuestCidMismatch { expected, actual } => {
                write!(
                    f,
                    "workload guest CID mismatch: expected {expected}, got {actual}"
                )
            }
            Self::MissingClientCertificate => f.write_str("missing mTLS client certificate"),
            Self::CertificateThumbprintMismatch => {
                f.write_str("RFC 8705 mTLS client certificate SHA-256 thumbprint mismatch")
            }
            Self::TargetNotAllowed => {
                f.write_str("target (sni, port, method, path) denied by egress allowlist")
            }
            Self::MalformedHttpRequest { reason } => {
                write!(f, "malformed HTTP/1.1 request: {reason}")
            }
            Self::HostSniMismatch => f.write_str(
                "HTTP Host header missing, duplicated, or mismatched against verified SNI",
            ),
            Self::HeaderSmugglingDetected { reason } => {
                write!(f, "HTTP header smuggling rejected: {reason}")
            }
            Self::ConflictingFramingHeaders => {
                f.write_str("conflicting or invalid Content-Length / Transfer-Encoding framing")
            }
            Self::ForbiddenGuestAuthHeader => {
                f.write_str("guest-supplied Authorization or Proxy-Authorization header rejected")
            }
            Self::Replay(err) => write!(f, "egress nonce replay rejected: {err}"),
            Self::UnwrapFailed(err) => write!(f, "egress credential unwrap failed: {err}"),
            Self::SecretTooShort { min_bytes } => write!(
                f,
                "unwrapped egress credential shorter than minimum {min_bytes} bytes"
            ),
        }
    }
}

impl std::error::Error for PolicyError {}

/// Outbound TLS splicing and mTLS proxy execution errors.
#[derive(Debug)]
pub enum ProxyError {
    /// Policy authorization failed before dialing upstream.
    Policy(PolicyError),
    /// Verified SNI could not be converted to a valid DNS `ServerName`.
    InvalidServerName,
    /// Outbound TCP or TLS 1.3 handshake/write timed out.
    Timeout,
    /// Upstream HTTP response exceeded size cap or was syntactically invalid.
    MalformedUpstreamResponse { reason: &'static str },
    /// Transport or TLS error (sanitized, never containing secret material).
    TransportError(String),
}

impl From<PolicyError> for ProxyError {
    fn from(value: PolicyError) -> Self {
        Self::Policy(value)
    }
}

impl fmt::Display for ProxyError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Policy(err) => write!(f, "policy gate denied egress: {err}"),
            Self::InvalidServerName => f.write_str("verified SNI is not a valid DNS ServerName"),
            Self::Timeout => f.write_str("outbound TLS splice timed out"),
            Self::MalformedUpstreamResponse { reason } => {
                write!(f, "malformed upstream HTTP response: {reason}")
            }
            Self::TransportError(msg) => write!(f, "TLS proxy transport error: {msg}"),
        }
    }
}

impl std::error::Error for ProxyError {}
