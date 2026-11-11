use std::collections::{BTreeMap, BTreeSet};
use std::future::Future;
use std::path::Path;
use std::time::Duration;

use tokio::net::{UnixListener, UnixStream};

use crate::error::IpcError;
use crate::frame::{read_bounded_frame, write_bounded_frame, WireFrame};

/// Minimum hypervisor-assignable guest CID (`0=hypervisor`, `1=local`, `2=host`).
pub const MIN_GUEST_VSOCK_CID: u32 = 3;
/// Maximum hypervisor-assignable guest CID (`u32::MAX` is reserved `VMADDR_CID_ANY`).
pub const MAX_GUEST_VSOCK_CID: u32 = u32::MAX - 1;

#[inline]
fn is_assignable_guest_cid(cid: u32) -> bool {
    (MIN_GUEST_VSOCK_CID..=MAX_GUEST_VSOCK_CID).contains(&cid)
}

/// Kernel-verified identity of a connected Ring 2 peer.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum VerifiedPeerIdentity {
    /// Linux `AF_VSOCK` microVM peer verified by hypervisor-assigned CID.
    Vsock { cid: u32, port: u32 },
    /// Unix Domain Socket peer verified by kernel `SO_PEERCRED` (`uid`, `gid`, `pid`).
    Unix {
        uid: u32,
        gid: u32,
        pid: Option<i32>,
        mapped_guest_cid: u32,
    },
}

impl VerifiedPeerIdentity {
    /// Returns the guest CID associated with this verified peer.
    #[must_use]
    pub fn effective_guest_cid(&self) -> u32 {
        match *self {
            Self::Vsock { cid, .. } => cid,
            Self::Unix {
                mapped_guest_cid, ..
            } => mapped_guest_cid,
        }
    }
}

/// Static allowlist of authorized `AF_VSOCK` guest CIDs and `AF_UNIX` peer UIDs.
#[derive(Clone, Debug, Default)]
pub struct PeerAllowlist {
    vsock_cids: BTreeSet<u32>,
    unix_uid_to_cid: BTreeMap<u32, u32>,
}

impl PeerAllowlist {
    /// Creates an empty [`PeerAllowlist`].
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Permits a microVM guest CID (`3..=u32::MAX - 1`) over `AF_VSOCK`.
    pub fn allow_vsock_cid(&mut self, guest_cid: u32) {
        if is_assignable_guest_cid(guest_cid) {
            self.vsock_cids.insert(guest_cid);
        }
    }

    /// Permits a local Unix UID over `AF_UNIX` and maps it to an assignable
    /// `mapped_guest_cid` (`3..=u32::MAX - 1`). Reserved CIDs (`0..=2` and
    /// `VMADDR_CID_ANY`) are refused.
    pub fn allow_unix_uid(&mut self, uid: u32, mapped_guest_cid: u32) {
        if is_assignable_guest_cid(mapped_guest_cid) {
            self.unix_uid_to_cid.insert(uid, mapped_guest_cid);
        }
    }

    /// Validates an `AF_VSOCK` peer CID against the allowlist.
    pub fn verify_vsock_peer(&self, cid: u32, port: u32) -> Result<VerifiedPeerIdentity, IpcError> {
        if !is_assignable_guest_cid(cid) || !self.vsock_cids.contains(&cid) {
            return Err(IpcError::UnauthorizedPeer {
                detail: format!("vsock cid {cid} not in allowlist"),
            });
        }
        Ok(VerifiedPeerIdentity::Vsock { cid, port })
    }

    /// Validates a kernel `SO_PEERCRED` Unix peer against the allowlist.
    pub fn verify_unix_peer(
        &self,
        uid: u32,
        gid: u32,
        pid: Option<i32>,
    ) -> Result<VerifiedPeerIdentity, IpcError> {
        let Some(&mapped_guest_cid) = self.unix_uid_to_cid.get(&uid) else {
            return Err(IpcError::UnauthorizedPeer {
                detail: format!("unix uid {uid} not in allowlist"),
            });
        };
        if !is_assignable_guest_cid(mapped_guest_cid) {
            return Err(IpcError::UnauthorizedPeer {
                detail: format!("mapped guest cid {mapped_guest_cid} is reserved"),
            });
        }
        Ok(VerifiedPeerIdentity::Unix {
            uid,
            gid,
            pid,
            mapped_guest_cid,
        })
    }
}

/// Configuration for IPC transport listeners.
#[derive(Clone, Debug)]
pub struct IpcServerConfig {
    pub frame_read_deadline: Duration,
    pub allowlist: PeerAllowlist,
}

/// Unix Domain Socket IPC listener enforcing kernel `SO_PEERCRED` prior to
/// reading wire frames.
pub struct UnixIpcListener {
    listener: UnixListener,
    config: IpcServerConfig,
}

impl UnixIpcListener {
    /// Binds a new Unix Domain Socket listener at `socket_path` and enforces
    /// strict `0600` owner-only socket permissions before accepting traffic.
    pub fn bind(socket_path: &Path, config: IpcServerConfig) -> Result<Self, IpcError> {
        let listener =
            UnixListener::bind(socket_path).map_err(|e| IpcError::IoError(e.to_string()))?;

        #[cfg(unix)]
        {
            use std::os::unix::fs::{FileTypeExt, PermissionsExt};

            let harden_res = (|| -> Result<(), IpcError> {
                std::fs::set_permissions(socket_path, std::fs::Permissions::from_mode(0o600))
                    .map_err(|e| IpcError::IoError(e.to_string()))?;
                let meta = std::fs::symlink_metadata(socket_path)
                    .map_err(|e| IpcError::IoError(e.to_string()))?;
                if !meta.file_type().is_socket() {
                    return Err(IpcError::IoError(
                        "bound Unix IPC path is not a socket".to_owned(),
                    ));
                }
                let mode = meta.permissions().mode() & 0o777;
                if mode != 0o600 {
                    return Err(IpcError::IoError(format!(
                        "failed to enforce 0600 mode on Unix IPC socket (got 0o{mode:o})"
                    )));
                }
                Ok(())
            })();

            if let Err(err) = harden_res {
                drop(listener);
                let _ = std::fs::remove_file(socket_path);
                return Err(err);
            }
        }

        Ok(Self { listener, config })
    }

    /// Accepts a single connection and verifies kernel `SO_PEERCRED` against the
    /// allowlist **before** returning the stream.
    pub async fn accept_verified(&self) -> Result<(UnixStream, VerifiedPeerIdentity), IpcError> {
        let (stream, _addr) = self
            .listener
            .accept()
            .await
            .map_err(|e| IpcError::IoError(e.to_string()))?;

        #[cfg(target_os = "linux")]
        let peer = {
            let ucred = rustix::net::sockopt::get_socket_peercred(&stream)
                .map_err(|e| IpcError::IoError(e.to_string()))?;
            let uid = ucred.uid.as_raw();
            let gid = ucred.gid.as_raw();
            let pid = Some(ucred.pid.as_raw_nonzero().get());
            self.config.allowlist.verify_unix_peer(uid, gid, pid)?
        };

        #[cfg(not(target_os = "linux"))]
        let peer = {
            let cred = stream
                .peer_cred()
                .map_err(|e| IpcError::IoError(e.to_string()))?;
            self.config
                .allowlist
                .verify_unix_peer(cred.uid(), cred.gid(), cred.pid())?
        };

        Ok((stream, peer))
    }

    /// Accepts one connection, enforces `SO_PEERCRED` allowlisting, reads one
    /// bounded [`WireFrame`], dispatches `handler`, and writes the response frame.
    pub async fn accept_and_dispatch_once<H, Fut>(&self, handler: H) -> Result<(), IpcError>
    where
        H: FnOnce(VerifiedPeerIdentity, WireFrame) -> Fut,
        Fut: Future<Output = Result<WireFrame, IpcError>>,
    {
        let (mut stream, peer) = self.accept_verified().await?;
        let request = read_bounded_frame(&mut stream, self.config.frame_read_deadline).await?;
        let response = handler(peer, request).await?;
        write_bounded_frame(&mut stream, &response, self.config.frame_read_deadline).await
    }
}

/// Linux `AF_VSOCK` IPC listener enforcing guest CID allowlists prior to
/// reading wire frames.
#[cfg(target_os = "linux")]
pub struct VsockIpcListener {
    listener: tokio_vsock::VsockListener,
    config: IpcServerConfig,
}

#[cfg(target_os = "linux")]
impl VsockIpcListener {
    /// Binds an `AF_VSOCK` listener on `(cid, port)`.
    pub fn bind(cid: u32, port: u32, config: IpcServerConfig) -> Result<Self, IpcError> {
        let addr = tokio_vsock::VsockAddr::new(cid, port);
        let listener =
            tokio_vsock::VsockListener::bind(addr).map_err(|e| IpcError::IoError(e.to_string()))?;
        Ok(Self { listener, config })
    }

    /// Accepts a single `AF_VSOCK` connection and enforces the guest CID allowlist
    /// **before** returning the stream.
    pub async fn accept_verified(
        &self,
    ) -> Result<(tokio_vsock::VsockStream, VerifiedPeerIdentity), IpcError> {
        let (stream, peer_addr) = self
            .listener
            .accept()
            .await
            .map_err(|e| IpcError::IoError(e.to_string()))?;
        let peer = self
            .config
            .allowlist
            .verify_vsock_peer(peer_addr.cid(), peer_addr.port())?;
        Ok((stream, peer))
    }

    /// Accepts one `AF_VSOCK` connection, verifies guest CID, reads one bounded
    /// [`WireFrame`], dispatches `handler`, and writes the response frame.
    pub async fn accept_and_dispatch_once<H, Fut>(&self, handler: H) -> Result<(), IpcError>
    where
        H: FnOnce(VerifiedPeerIdentity, WireFrame) -> Fut,
        Fut: Future<Output = Result<WireFrame, IpcError>>,
    {
        let (mut stream, peer) = self.accept_verified().await?;
        let request = read_bounded_frame(&mut stream, self.config.frame_read_deadline).await?;
        let response = handler(peer, request).await?;
        write_bounded_frame(&mut stream, &response, self.config.frame_read_deadline).await
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;
    use crate::frame::MessageType;

    #[tokio::test]
    async fn unix_listener_authenticates_current_uid_and_dispatches() {
        let mut dir = std::env::temp_dir();
        let mut rnd = [0u8; 8];
        aws_lc_rs::rand::fill(&mut rnd).unwrap();
        let suffix: String = rnd.iter().map(|b| format!("{b:02x}")).collect();
        dir.push(format!("locksmith-ipc-unit-{suffix}.sock"));

        #[cfg(target_os = "linux")]
        let current_uid = rustix::process::getuid().as_raw();
        #[cfg(not(target_os = "linux"))]
        let current_uid = 0u32;

        let mut allow = PeerAllowlist::new();
        allow.allow_unix_uid(current_uid, 77);

        let listener = UnixIpcListener::bind(
            &dir,
            IpcServerConfig {
                frame_read_deadline: Duration::from_secs(1),
                allowlist: allow,
            },
        )
        .unwrap();

        let sock_path = dir.clone();
        let client_task = tokio::spawn(async move {
            let mut stream = UnixStream::connect(&sock_path).await.unwrap();
            let req = WireFrame {
                msg_type: MessageType::Heartbeat,
                payload: b"hello".to_vec(),
            };
            write_bounded_frame(&mut stream, &req, Duration::from_secs(1))
                .await
                .unwrap();
            read_bounded_frame(&mut stream, Duration::from_secs(1))
                .await
                .unwrap()
        });

        listener
            .accept_and_dispatch_once(|peer, frame| async move {
                assert_eq!(peer.effective_guest_cid(), 77);
                assert_eq!(frame.payload, b"hello");
                Ok(WireFrame {
                    msg_type: MessageType::CommandResponse,
                    payload: b"world".to_vec(),
                })
            })
            .await
            .unwrap();

        let resp = client_task.await.unwrap();
        assert_eq!(resp.payload, b"world");
        let _ = std::fs::remove_file(&dir);
    }
}
