//! `anvil-ipc`: Bounded `LKSM` binary wire framing, authenticated Linux
//! `AF_VSOCK` CID and `AF_UNIX` `SO_PEERCRED` peer transport, and attested
//! control-plane command envelopes.

pub mod envelope;
pub mod error;
pub mod frame;
pub mod transport;

pub use envelope::{AttestedCommandEnvelope, CommandVerifier};
pub use error::IpcError;
pub use frame::{
    MessageType, WireFrame, FRAME_HEADER_LEN, FRAME_MAGIC, FRAME_VERSION_V1, MAX_FRAME_BYTES,
};
#[cfg(target_os = "linux")]
pub use transport::VsockIpcListener;
pub use transport::{IpcServerConfig, PeerAllowlist, UnixIpcListener, VerifiedPeerIdentity};
