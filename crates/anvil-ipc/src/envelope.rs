use std::collections::HashMap;
use std::sync::{Arc, Mutex};

use anvil_core::kdf::{derive_subkey, DOMAIN_IPC_ATTEST};
use anvil_core::replay::ReplayFilter;
use aws_lc_rs::constant_time::verify_slices_are_equal;
use zeroize::Zeroizing;

use crate::error::IpcError;
use crate::frame::MAX_FRAME_BYTES;

const ENVELOPE_MAGIC: &[u8; 4] = b"LKCE";
const ENVELOPE_VERSION: u8 = 1;
const ENVELOPE_FIXED_LEN: usize = 4 + 1 + 4 + 8 + 8 + 32 + 32 + 32 + 4;
const CMD_SIG_DOMAIN: &[u8] = b"LOCKSMITH-CMD-SIG-V1";
const IPC_ATTEST_SALT: &[u8] = b"LOCKSMITH-IPC-ATTEST-SALT-V1";

fn derive_guest_attest_subkey(
    root_key: &[u8; 32],
    guest_cid: u32,
) -> Result<Zeroizing<[u8; 32]>, IpcError> {
    let cid_be = guest_cid.to_be_bytes();
    derive_subkey(IPC_ATTEST_SALT, root_key, &[DOMAIN_IPC_ATTEST, &cid_be])
        .map_err(|_| IpcError::SignatureVerificationFailed)
}

fn compute_hardware_signature(
    guest_subkey: &[u8; 32],
    guest_cid: u32,
    sequence_no: u64,
    timestamp_ms: u64,
    nonce: &[u8; 32],
    command_digest: &[u8; 32],
) -> [u8; 32] {
    let mut hasher = blake3::Hasher::new_keyed(guest_subkey);
    hasher.update(CMD_SIG_DOMAIN);
    hasher.update(&guest_cid.to_be_bytes());
    hasher.update(&sequence_no.to_be_bytes());
    hasher.update(&timestamp_ms.to_be_bytes());
    hasher.update(nonce);
    hasher.update(command_digest);
    *hasher.finalize().as_bytes()
}

/// Hardware-attested control-plane command envelope sent by a Ring 2 workload.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AttestedCommandEnvelope {
    pub guest_cid: u32,
    pub sequence_no: u64,
    pub timestamp_ms: u64,
    pub nonce: [u8; 32],
    pub command_digest: [u8; 32],
    pub hardware_signature: [u8; 32],
    pub command_payload: Vec<u8>,
}

impl AttestedCommandEnvelope {
    /// Creates and signs an [`AttestedCommandEnvelope`] using `attestation_root_key`.
    pub fn sign_new(
        attestation_root_key: &[u8; 32],
        guest_cid: u32,
        sequence_no: u64,
        timestamp_ms: u64,
        nonce: [u8; 32],
        command_payload: Vec<u8>,
    ) -> Result<Self, IpcError> {
        if ENVELOPE_FIXED_LEN.saturating_add(command_payload.len()) > MAX_FRAME_BYTES {
            return Err(IpcError::InvalidEnvelopeFormat);
        }
        let command_digest = *blake3::hash(&command_payload).as_bytes();
        let subkey = derive_guest_attest_subkey(attestation_root_key, guest_cid)?;
        let hardware_signature = compute_hardware_signature(
            &subkey,
            guest_cid,
            sequence_no,
            timestamp_ms,
            &nonce,
            &command_digest,
        );

        Ok(Self {
            guest_cid,
            sequence_no,
            timestamp_ms,
            nonce,
            command_digest,
            hardware_signature,
            command_payload,
        })
    }

    /// Encodes the attested command envelope into canonical wire bytes.
    pub fn to_bytes(&self) -> Result<Vec<u8>, IpcError> {
        let total = ENVELOPE_FIXED_LEN
            .checked_add(self.command_payload.len())
            .ok_or(IpcError::InvalidEnvelopeFormat)?;
        if total > MAX_FRAME_BYTES {
            return Err(IpcError::InvalidEnvelopeFormat);
        }
        let payload_len = u32::try_from(self.command_payload.len())
            .map_err(|_| IpcError::InvalidEnvelopeFormat)?;

        let mut out = Vec::with_capacity(total);
        out.extend_from_slice(ENVELOPE_MAGIC);
        out.push(ENVELOPE_VERSION);
        out.extend_from_slice(&self.guest_cid.to_be_bytes());
        out.extend_from_slice(&self.sequence_no.to_be_bytes());
        out.extend_from_slice(&self.timestamp_ms.to_be_bytes());
        out.extend_from_slice(&self.nonce);
        out.extend_from_slice(&self.command_digest);
        out.extend_from_slice(&self.hardware_signature);
        out.extend_from_slice(&payload_len.to_be_bytes());
        out.extend_from_slice(&self.command_payload);
        Ok(out)
    }

    /// Parses an attested command envelope from wire bytes.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, IpcError> {
        if bytes.len() < ENVELOPE_FIXED_LEN || bytes.len() > MAX_FRAME_BYTES {
            return Err(IpcError::InvalidEnvelopeFormat);
        }
        if &bytes[0..4] != ENVELOPE_MAGIC || bytes[4] != ENVELOPE_VERSION {
            return Err(IpcError::InvalidEnvelopeFormat);
        }

        let mut cid_b = [0u8; 4];
        cid_b.copy_from_slice(&bytes[5..9]);
        let guest_cid = u32::from_be_bytes(cid_b);

        let mut seq_b = [0u8; 8];
        seq_b.copy_from_slice(&bytes[9..17]);
        let sequence_no = u64::from_be_bytes(seq_b);

        let mut ts_b = [0u8; 8];
        ts_b.copy_from_slice(&bytes[17..25]);
        let timestamp_ms = u64::from_be_bytes(ts_b);

        let mut nonce = [0u8; 32];
        nonce.copy_from_slice(&bytes[25..57]);

        let mut command_digest = [0u8; 32];
        command_digest.copy_from_slice(&bytes[57..89]);

        let mut hardware_signature = [0u8; 32];
        hardware_signature.copy_from_slice(&bytes[89..121]);

        let mut len_b = [0u8; 4];
        len_b.copy_from_slice(&bytes[121..125]);
        let payload_len = usize::try_from(u32::from_be_bytes(len_b))
            .map_err(|_| IpcError::InvalidEnvelopeFormat)?;

        let expected_total = ENVELOPE_FIXED_LEN
            .checked_add(payload_len)
            .ok_or(IpcError::InvalidEnvelopeFormat)?;
        if bytes.len() != expected_total {
            return Err(IpcError::InvalidEnvelopeFormat);
        }

        Ok(Self {
            guest_cid,
            sequence_no,
            timestamp_ms,
            nonce,
            command_digest,
            hardware_signature,
            command_payload: bytes[ENVELOPE_FIXED_LEN..].to_vec(),
        })
    }
}

/// Verifies attested command envelopes against peer CID, `BLAKE3` payload
/// digest, constant-time hardware signature, replay filter, and monotonic sequence.
pub struct CommandVerifier {
    attestation_root_key: Zeroizing<[u8; 32]>,
    replay_filter: Arc<ReplayFilter>,
    last_sequence_by_cid: Mutex<HashMap<u32, u64>>,
}

impl CommandVerifier {
    /// Creates a new [`CommandVerifier`].
    #[must_use]
    pub fn new(attestation_root_key: [u8; 32], replay_filter: Arc<ReplayFilter>) -> Self {
        Self {
            attestation_root_key: Zeroizing::new(attestation_root_key),
            replay_filter,
            last_sequence_by_cid: Mutex::new(HashMap::new()),
        }
    }

    /// Returns a monotonically non-decreasing epoch millisecond timestamp anchored
    /// to the underlying [`ReplayFilter`]'s `Instant`.
    #[must_use]
    pub fn monotonic_now_ms(&self) -> u64 {
        self.replay_filter.monotonic_now_ms()
    }

    /// Verifies `envelope` against `authenticated_guest_cid` and `now_ms`,
    /// burning its nonce and advancing the guest's sequence watermark.
    pub fn verify_and_accept<'a>(
        &self,
        envelope: &'a AttestedCommandEnvelope,
        authenticated_guest_cid: u32,
        now_ms: u64,
    ) -> Result<&'a [u8], IpcError> {
        if envelope.guest_cid != authenticated_guest_cid {
            return Err(IpcError::GuestCidMismatch {
                expected: authenticated_guest_cid,
                actual: envelope.guest_cid,
            });
        }
        if !(crate::transport::MIN_GUEST_VSOCK_CID..=crate::transport::MAX_GUEST_VSOCK_CID)
            .contains(&envelope.guest_cid)
        {
            return Err(IpcError::UnauthorizedPeer {
                detail: format!("guest cid {} is reserved", envelope.guest_cid),
            });
        }

        let recomputed_digest = *blake3::hash(&envelope.command_payload).as_bytes();
        if verify_slices_are_equal(&recomputed_digest, &envelope.command_digest).is_err() {
            return Err(IpcError::CommandDigestMismatch);
        }

        let subkey = derive_guest_attest_subkey(&self.attestation_root_key, envelope.guest_cid)?;
        let expected_sig = compute_hardware_signature(
            &subkey,
            envelope.guest_cid,
            envelope.sequence_no,
            envelope.timestamp_ms,
            &envelope.nonce,
            &envelope.command_digest,
        );
        if verify_slices_are_equal(&expected_sig, &envelope.hardware_signature).is_err() {
            return Err(IpcError::SignatureVerificationFailed);
        }

        if envelope.sequence_no == u64::MAX {
            return Err(IpcError::SequenceExhausted {
                guest_cid: envelope.guest_cid,
            });
        }

        let mut seq_guard = self
            .last_sequence_by_cid
            .lock()
            .map_err(|_| IpcError::IoError("sequence mutex poisoned".to_owned()))?;

        if let Some(&last_seen) = seq_guard.get(&envelope.guest_cid) {
            if envelope.sequence_no <= last_seen {
                return Err(IpcError::SequenceViolation {
                    last_seen: Some(last_seen),
                    actual: envelope.sequence_no,
                });
            }
        } else if envelope.sequence_no == 0 {
            return Err(IpcError::SequenceViolation {
                last_seen: None,
                actual: 0,
            });
        }

        self.replay_filter
            .check_and_burn(envelope.nonce, envelope.timestamp_ms, now_ms)?;
        seq_guard.insert(envelope.guest_cid, envelope.sequence_no);

        Ok(envelope.command_payload.as_slice())
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;

    #[test]
    fn signs_serializes_and_verifies_attested_command_envelope() {
        let root_key = [0x88; 32];
        let replay = Arc::new(ReplayFilter::with_defaults(128).unwrap());
        let verifier = CommandVerifier::new(root_key, replay);

        let now = 1_762_000_000_000u64;
        let env = AttestedCommandEnvelope::sign_new(
            &root_key,
            12,
            1,
            now,
            [0x11; 32],
            b"rotate-session".to_vec(),
        )
        .unwrap();

        let bytes = env.to_bytes().unwrap();
        let decoded = AttestedCommandEnvelope::from_bytes(&bytes).unwrap();
        let payload = verifier.verify_and_accept(&decoded, 12, now).unwrap();
        assert_eq!(payload, b"rotate-session");

        // Replaying same sequence or tampered payload fails closed
        let mut tampered = AttestedCommandEnvelope::sign_new(
            &root_key,
            12,
            2,
            now,
            [0x22; 32],
            b"rotate-session".to_vec(),
        )
        .unwrap();
        tampered.command_payload[0] ^= 0x01;
        assert_eq!(
            verifier.verify_and_accept(&tampered, 12, now).unwrap_err(),
            IpcError::CommandDigestMismatch
        );
    }
}
