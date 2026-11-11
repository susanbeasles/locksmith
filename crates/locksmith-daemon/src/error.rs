use core::fmt;

use anvil_cache::CacheError;
use anvil_core::{CryptoError, LedgerError, ReplayError};
use anvil_ipc::IpcError;
use locksmith_proxy::ProxyError;

/// Top-level error enum for `locksmith-daemon` initialization, self-test, and runtime.
#[derive(Debug)]
pub enum DaemonError {
    /// Failed to apply OS process hardening (`PR_SET_DUMPABLE(0)`).
    ProcessHardeningFailed(String),
    /// Detected forbidden secret-bearing CLI flag or environment variable.
    /// Intentionally stores ONLY the sanitized flag/variable classification, NEVER the value.
    AmbientSecretViolation { source_kind: &'static str },
    /// Invalid or unrecognized CLI invocation (redacted, never echoes raw values).
    InvalidCliUsage { reason: &'static str },
    /// Deterministic startup KAT (`verify-self`) failed.
    SelfTestFailed { check: &'static str, detail: String },
    /// Cryptographic subsystem failure.
    Crypto(CryptoError),
    /// Replay filter failure.
    Replay(ReplayError),
    /// Audit ledger failure.
    Ledger(LedgerError),
    /// Cache subsystem failure.
    Cache(CacheError),
    /// IPC subsystem failure.
    Ipc(IpcError),
    /// Proxy subsystem failure.
    Proxy(ProxyError),
    /// Runtime I/O or signal setup failure.
    Io(String),
}

impl From<CryptoError> for DaemonError {
    fn from(value: CryptoError) -> Self {
        Self::Crypto(value)
    }
}

impl From<ReplayError> for DaemonError {
    fn from(value: ReplayError) -> Self {
        Self::Replay(value)
    }
}

impl From<LedgerError> for DaemonError {
    fn from(value: LedgerError) -> Self {
        Self::Ledger(value)
    }
}

impl From<CacheError> for DaemonError {
    fn from(value: CacheError) -> Self {
        Self::Cache(value)
    }
}

impl From<IpcError> for DaemonError {
    fn from(value: IpcError) -> Self {
        Self::Ipc(value)
    }
}

impl From<ProxyError> for DaemonError {
    fn from(value: ProxyError) -> Self {
        Self::Proxy(value)
    }
}

impl fmt::Display for DaemonError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::ProcessHardeningFailed(msg) => {
                write!(f, "process hardening failed: {msg}")
            }
            Self::AmbientSecretViolation { source_kind } => {
                write!(
                    f,
                    "ambient secret hygiene violation in {source_kind} [VALUE REDACTED]"
                )
            }
            Self::InvalidCliUsage { reason } => {
                write!(f, "invalid CLI usage: {reason}")
            }
            Self::SelfTestFailed { check, detail } => {
                write!(f, "startup self-test '{check}' failed: {detail}")
            }
            Self::Crypto(err) => write!(f, "crypto error: {err}"),
            Self::Replay(err) => write!(f, "replay error: {err}"),
            Self::Ledger(err) => write!(f, "audit ledger error: {err}"),
            Self::Cache(err) => write!(f, "cache error: {err}"),
            Self::Ipc(err) => write!(f, "ipc error: {err}"),
            Self::Proxy(err) => write!(f, "proxy error: {err}"),
            Self::Io(msg) => write!(f, "daemon runtime I/O error: {msg}"),
        }
    }
}

impl std::error::Error for DaemonError {}
