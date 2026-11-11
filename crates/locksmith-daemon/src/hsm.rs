use std::io::{Read, Write};
use std::os::unix::net::UnixStream;
use std::path::{Path, PathBuf};
#[cfg(any(test, feature = "test-hsm"))]
use std::sync::Mutex;
use std::time::Duration;

use anvil_core::unwrap::HardwareUnwrapper;
use anvil_core::CryptoError;
use zeroize::Zeroizing;

const RING0_MAGIC: [u8; 4] = *b"LKR0";
const RING0_REQ_TAG: u8 = 0x01;
const RING0_RESP_TAG: u8 = 0x02;
const MAX_CHALLENGE_LEN: usize = 256;

fn verify_stream_peer_uid(stream: &UnixStream, expected_uid: u32) -> Result<(), CryptoError> {
    #[cfg(target_os = "linux")]
    {
        let ucred = rustix::net::sockopt::get_socket_peercred(stream)
            .map_err(|_| CryptoError::HardwareFailure)?;
        if ucred.uid.as_raw() != expected_uid {
            return Err(CryptoError::HardwareFailure);
        }
    }

    #[cfg(not(target_os = "linux"))]
    {
        let _ = (stream, expected_uid);
    }

    Ok(())
}

pub(crate) fn exchange_ring0_challenge(
    stream: &mut UnixStream,
    expected_peer_uid: u32,
    timeout: Duration,
    challenge: &[u8],
) -> Result<Zeroizing<[u8; 32]>, CryptoError> {
    if challenge.is_empty() || challenge.len() > MAX_CHALLENGE_LEN {
        return Err(CryptoError::HardwareFailure);
    }
    stream
        .set_read_timeout(Some(timeout))
        .map_err(|_| CryptoError::HardwareFailure)?;
    stream
        .set_write_timeout(Some(timeout))
        .map_err(|_| CryptoError::HardwareFailure)?;

    verify_stream_peer_uid(stream, expected_peer_uid)?;

    let chal_len = u16::try_from(challenge.len()).map_err(|_| CryptoError::HardwareFailure)?;
    let mut header = [0u8; 7];
    header[0..4].copy_from_slice(&RING0_MAGIC);
    header[4] = RING0_REQ_TAG;
    header[5..7].copy_from_slice(&chal_len.to_be_bytes());

    stream
        .write_all(&header)
        .map_err(|_| CryptoError::HardwareFailure)?;
    stream
        .write_all(challenge)
        .map_err(|_| CryptoError::HardwareFailure)?;
    stream.flush().map_err(|_| CryptoError::HardwareFailure)?;

    let mut resp_head = [0u8; 5];
    stream
        .read_exact(&mut resp_head)
        .map_err(|_| CryptoError::HardwareFailure)?;
    if resp_head[0..4] != RING0_MAGIC || resp_head[4] != RING0_RESP_TAG {
        return Err(CryptoError::HardwareFailure);
    }

    let mut share = Zeroizing::new([0u8; 32]);
    stream
        .read_exact(&mut *share)
        .map_err(|_| CryptoError::HardwareFailure)?;
    Ok(share)
}

/// Serves `count` Ring 0 HMAC-SHA256 challenge-response requests over an unnamed
/// kernel `UnixStream` socketpair (strictly gated for unit/integration test suites).
#[cfg(any(test, feature = "test-hsm"))]
pub fn serve_ring0_hmac_stream(
    mut stream: UnixStream,
    ring0_secret: Zeroizing<[u8; 32]>,
    expected_client_uid: u32,
    count: usize,
) -> Result<(), CryptoError> {
    use aws_lc_rs::hmac::{Key, HMAC_SHA256};

    verify_stream_peer_uid(&stream, expected_client_uid)?;
    let key = Key::new(HMAC_SHA256, &*ring0_secret);

    for _ in 0..count {
        let mut head = [0u8; 7];
        stream
            .read_exact(&mut head)
            .map_err(|_| CryptoError::HardwareFailure)?;
        if head[0..4] != RING0_MAGIC || head[4] != RING0_REQ_TAG {
            return Err(CryptoError::HardwareFailure);
        }
        let len = u16::from_be_bytes([head[5], head[6]]) as usize;
        if len == 0 || len > MAX_CHALLENGE_LEN {
            return Err(CryptoError::HardwareFailure);
        }
        let mut chal = vec![0u8; len];
        stream
            .read_exact(&mut chal)
            .map_err(|_| CryptoError::HardwareFailure)?;

        let tag = aws_lc_rs::hmac::sign(&key, &chal);
        let mut resp = Zeroizing::new([0u8; 37]);
        resp[0..4].copy_from_slice(&RING0_MAGIC);
        resp[4] = RING0_RESP_TAG;
        resp[5..37].copy_from_slice(tag.as_ref());
        stream
            .write_all(&*resp)
            .map_err(|_| CryptoError::HardwareFailure)?;
        stream.flush().map_err(|_| CryptoError::HardwareFailure)?;
    }

    Ok(())
}

/// Connected in-RAM socketpair Ring 0 hardware unwrapper (strictly gated for tests).
#[cfg(any(test, feature = "test-hsm"))]
pub struct ConnectedRing0StreamUnwrapper {
    stream: Mutex<UnixStream>,
    expected_peer_uid: u32,
    timeout: Duration,
}

#[cfg(any(test, feature = "test-hsm"))]
impl ConnectedRing0StreamUnwrapper {
    #[must_use]
    pub fn new(stream: UnixStream, expected_peer_uid: u32, timeout: Duration) -> Self {
        Self {
            stream: Mutex::new(stream),
            expected_peer_uid,
            timeout,
        }
    }
}

#[cfg(any(test, feature = "test-hsm"))]
impl HardwareUnwrapper for ConnectedRing0StreamUnwrapper {
    fn derive_hardware_share(&self, challenge: &[u8]) -> Result<Zeroizing<[u8; 32]>, CryptoError> {
        let mut guard = self
            .stream
            .lock()
            .map_err(|_| CryptoError::HardwareFailure)?;
        exchange_ring0_challenge(&mut guard, self.expected_peer_uid, self.timeout, challenge)
    }
}

/// Production Ring 0 hardware token client communicating over a kernel
/// `SO_PEERCRED`-verified Unix Domain Socket.
#[derive(Clone, Debug)]
pub struct Ring0UnixHardwareUnwrapper {
    socket_path: PathBuf,
    expected_peer_uid: u32,
    timeout: Duration,
}

impl Ring0UnixHardwareUnwrapper {
    /// Creates a new Ring 0 hardware unwrapper pinned to `socket_path` and `expected_peer_uid`.
    #[must_use]
    pub fn new(socket_path: PathBuf, expected_peer_uid: u32, timeout: Duration) -> Self {
        Self {
            socket_path,
            expected_peer_uid,
            timeout,
        }
    }

    /// Returns the bound Ring 0 Unix socket path.
    #[must_use]
    pub fn socket_path(&self) -> &Path {
        &self.socket_path
    }

    /// Returns the required kernel UID of the Ring 0 responder.
    #[must_use]
    pub fn expected_peer_uid(&self) -> u32 {
        self.expected_peer_uid
    }

    /// Returns the I/O deadline for Ring 0 challenge-response operations.
    #[must_use]
    pub fn timeout(&self) -> Duration {
        self.timeout
    }

    fn connect_and_exchange(&self, challenge: &[u8]) -> Result<Zeroizing<[u8; 32]>, CryptoError> {
        #[cfg(unix)]
        {
            use std::os::unix::fs::FileTypeExt;
            let meta = std::fs::symlink_metadata(&self.socket_path)
                .map_err(|_| CryptoError::HardwareFailure)?;
            if !meta.file_type().is_socket() {
                return Err(CryptoError::HardwareFailure);
            }
        }
        let mut stream =
            UnixStream::connect(&self.socket_path).map_err(|_| CryptoError::HardwareFailure)?;
        exchange_ring0_challenge(&mut stream, self.expected_peer_uid, self.timeout, challenge)
    }
}

impl HardwareUnwrapper for Ring0UnixHardwareUnwrapper {
    fn derive_hardware_share(&self, challenge: &[u8]) -> Result<Zeroizing<[u8; 32]>, CryptoError> {
        if let Ok(handle) = tokio::runtime::Handle::try_current() {
            if matches!(
                handle.runtime_flavor(),
                tokio::runtime::RuntimeFlavor::MultiThread
            ) {
                return tokio::task::block_in_place(|| self.connect_and_exchange(challenge));
            }
        }
        self.connect_and_exchange(challenge)
    }
}
