use core::fmt;

use aws_lc_rs::aead::{Aad, LessSafeKey, Nonce, UnboundKey, CHACHA20_POLY1305};
use aws_lc_rs::digest::{digest, SHA256};
use aws_lc_rs::rand::fill as csprng_fill;
use zeroize::Zeroizing;

pub use crate::error::CryptoError;
use crate::kdf::{
    derive_subkey, encode_canonical_info, DOMAIN_UNWRAP_HW_CHALLENGE, DOMAIN_UNWRAP_KEK,
};

/// Current wire version for [`SealedSecretEnvelope`].
pub const ENVELOPE_VERSION_V1: u8 = 1;

/// Maximum permitted length for a `secret_id` identifier.
pub const MAX_SECRET_ID_BYTES: usize = 256;

/// Hard upper bound on `SealedSecretEnvelope::ciphertext_and_tag` (`64 KiB`).
pub const MAX_ENVELOPE_CIPHERTEXT_BYTES: usize = 65_536;

/// Normative hardware challenge IKM label per `SPEC.md` Section 2.3.
pub const HW_CHALLENGE_IKM: &[u8] = b"LOCKSMITH-CHALLENGE";

/// Zeroizing plaintext secret wrapper whose `Debug` and `Display` output are
/// unconditionally redacted.
pub struct SecretBytes(Zeroizing<Vec<u8>>);

impl SecretBytes {
    /// Wraps raw secret bytes inside a zeroizing allocation.
    #[must_use]
    pub fn new(bytes: Vec<u8>) -> Self {
        Self(Zeroizing::new(bytes))
    }

    /// Explicitly exposes the underlying secret slice for outbound TLS injection.
    #[must_use]
    pub fn expose_secret(&self) -> &[u8] {
        self.0.as_slice()
    }

    /// Returns the byte length of the secret.
    #[must_use]
    pub fn len(&self) -> usize {
        self.0.len()
    }

    /// Returns `true` if the secret slice is empty.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }
}

impl fmt::Debug for SecretBytes {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("SecretBytes([REDACTED])")
    }
}

impl fmt::Display for SecretBytes {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("[REDACTED]")
    }
}

/// Host half (Share A) of the 2-of-2 unwrapping split.
pub struct HostShare(Zeroizing<[u8; 32]>);

impl HostShare {
    /// Creates a zeroizing host share from 32 raw bytes.
    #[must_use]
    pub fn from_bytes(bytes: [u8; 32]) -> Self {
        Self(Zeroizing::new(bytes))
    }

    pub(crate) fn expose_bytes(&self) -> &[u8; 32] {
        &self.0
    }
}

impl fmt::Debug for HostShare {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("HostShare([REDACTED])")
    }
}

/// Ring 0 hardware security token trait supplying Share B of the 2-of-2 split.
pub trait HardwareUnwrapper: Send + Sync {
    /// Derives a 32-byte hardware share bound to `challenge`.
    fn derive_hardware_share(&self, challenge: &[u8]) -> Result<Zeroizing<[u8; 32]>, CryptoError>;
}

/// Deterministic software HSM strictly compiled for unit and adversarial test targets.
#[cfg(any(test, feature = "test-hsm"))]
pub struct SoftwareTestHsm {
    master_secret: Zeroizing<[u8; 32]>,
}

#[cfg(any(test, feature = "test-hsm"))]
impl SoftwareTestHsm {
    /// Constructs a deterministic test HSM seeded with `master_secret`.
    #[must_use]
    pub fn new(master_secret: [u8; 32]) -> Self {
        Self {
            master_secret: Zeroizing::new(master_secret),
        }
    }
}

#[cfg(any(test, feature = "test-hsm"))]
impl fmt::Debug for SoftwareTestHsm {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("SoftwareTestHsm([REDACTED])")
    }
}

#[cfg(any(test, feature = "test-hsm"))]
impl HardwareUnwrapper for SoftwareTestHsm {
    fn derive_hardware_share(&self, challenge: &[u8]) -> Result<Zeroizing<[u8; 32]>, CryptoError> {
        derive_subkey(
            b"LOCKSMITH-SOFTWARE-TEST-HSM-V1",
            &*self.master_secret,
            &[b"software-test-hsm-share-v1", challenge],
        )
    }
}

/// Explicit Additional Authenticated Data binding an envelope to a secret ID,
/// policy hash, and authorized guest CID.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct UnwrapAad<'a> {
    pub secret_id: &'a str,
    pub policy_hash: [u8; 32],
    pub guest_cid: u32,
}

impl UnwrapAad<'_> {
    /// Encodes `UnwrapAad` into injective length-prefixed canonical bytes.
    pub fn encode_canonical(&self) -> Result<Vec<u8>, CryptoError> {
        if self.secret_id.is_empty()
            || self.secret_id.len() > MAX_SECRET_ID_BYTES
            || !self.secret_id.bytes().all(|b| (0x21..=0x7E).contains(&b))
        {
            return Err(CryptoError::InvalidSecretId);
        }
        let cid_be = self.guest_cid.to_be_bytes();
        encode_canonical_info(&[
            b"aead-aad-v1",
            self.secret_id.as_bytes(),
            &self.policy_hash,
            &cid_be,
        ])
    }
}

/// ChaCha20-Poly1305 sealed secret envelope bound to 2-of-2 shares and [`UnwrapAad`].
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SealedSecretEnvelope {
    pub version: u8,
    pub hkdf_salt: [u8; 32],
    pub nonce: [u8; 12],
    pub ciphertext_and_tag: Vec<u8>,
}

impl SealedSecretEnvelope {
    const HEADER_LEN: usize = 1 + 32 + 12 + 4;

    /// Serializes the envelope to `[version: 1B || salt: 32B || nonce: 12B || ct_len: u32_be || ct_and_tag]`.
    #[must_use]
    pub fn to_bytes(&self) -> Vec<u8> {
        let ct_len = u32::try_from(self.ciphertext_and_tag.len()).unwrap_or(u32::MAX);
        let mut out = Vec::with_capacity(Self::HEADER_LEN + self.ciphertext_and_tag.len());
        out.push(self.version);
        out.extend_from_slice(&self.hkdf_salt);
        out.extend_from_slice(&self.nonce);
        out.extend_from_slice(&ct_len.to_be_bytes());
        out.extend_from_slice(&self.ciphertext_and_tag);
        out
    }

    /// Parses a serialized [`SealedSecretEnvelope`].
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, CryptoError> {
        if bytes.len() < Self::HEADER_LEN {
            return Err(CryptoError::InvalidEnvelopeFormat);
        }
        let version = bytes[0];
        if version != ENVELOPE_VERSION_V1 {
            return Err(CryptoError::UnsupportedEnvelopeVersion(version));
        }
        let mut hkdf_salt = [0u8; 32];
        hkdf_salt.copy_from_slice(&bytes[1..33]);

        let mut nonce = [0u8; 12];
        nonce.copy_from_slice(&bytes[33..45]);

        let mut len_bytes = [0u8; 4];
        len_bytes.copy_from_slice(&bytes[45..49]);
        let ct_len = usize::try_from(u32::from_be_bytes(len_bytes))
            .map_err(|_| CryptoError::InvalidEnvelopeFormat)?;

        if ct_len < CHACHA20_POLY1305.tag_len() || ct_len > MAX_ENVELOPE_CIPHERTEXT_BYTES {
            return Err(CryptoError::InvalidEnvelopeFormat);
        }
        let expected_total = Self::HEADER_LEN
            .checked_add(ct_len)
            .ok_or(CryptoError::InvalidEnvelopeFormat)?;
        if bytes.len() != expected_total {
            return Err(CryptoError::InvalidEnvelopeFormat);
        }

        Ok(Self {
            version,
            hkdf_salt,
            nonce,
            ciphertext_and_tag: bytes[Self::HEADER_LEN..].to_vec(),
        })
    }
}

/// 2-of-2 secret sealer and unwrapper combining [`HostShare`] with [`HardwareUnwrapper`].
pub struct SecretUnwrapper<H: HardwareUnwrapper> {
    host_share: HostShare,
    hardware: H,
}

impl<H: HardwareUnwrapper> SecretUnwrapper<H> {
    /// Creates a new 2-of-2 secret unwrapper.
    #[must_use]
    pub fn new(host_share: HostShare, hardware: H) -> Self {
        Self {
            host_share,
            hardware,
        }
    }

    fn derive_wrapping_key(
        &self,
        hkdf_salt: &[u8; 32],
        aad: &UnwrapAad<'_>,
        aad_bytes: &[u8],
    ) -> Result<Zeroizing<[u8; 32]>, CryptoError> {
        let aad_digest = digest(&SHA256, aad_bytes);
        let challenge = derive_subkey(
            hkdf_salt,
            HW_CHALLENGE_IKM,
            &[
                DOMAIN_UNWRAP_HW_CHALLENGE,
                hkdf_salt.as_slice(),
                aad_digest.as_ref(),
            ],
        )?;
        let hw_share = self.hardware.derive_hardware_share(&*challenge)?;

        let mut combined_ikm = Zeroizing::new([0u8; 64]);
        combined_ikm[..32].copy_from_slice(self.host_share.expose_bytes());
        combined_ikm[32..64].copy_from_slice(&*hw_share);

        let cid_be = aad.guest_cid.to_be_bytes();
        derive_subkey(
            hkdf_salt,
            &*combined_ikm,
            &[
                DOMAIN_UNWRAP_KEK,
                aad.secret_id.as_bytes(),
                &aad.policy_hash,
                &cid_be,
            ],
        )
    }

    /// Seals `plaintext` under a freshly salted 2-of-2 ChaCha20-Poly1305 key bound to `aad`.
    pub fn seal(
        &self,
        plaintext: &[u8],
        aad: &UnwrapAad<'_>,
    ) -> Result<SealedSecretEnvelope, CryptoError> {
        let mut hkdf_salt = [0u8; 32];
        csprng_fill(&mut hkdf_salt).map_err(|_| CryptoError::RngFailure)?;

        let mut nonce = [0u8; 12];
        csprng_fill(&mut nonce).map_err(|_| CryptoError::RngFailure)?;

        self.seal_with_salt_and_nonce(plaintext, aad, hkdf_salt, nonce)
    }

    fn seal_with_salt_and_nonce(
        &self,
        plaintext: &[u8],
        aad: &UnwrapAad<'_>,
        hkdf_salt: [u8; 32],
        nonce: [u8; 12],
    ) -> Result<SealedSecretEnvelope, CryptoError> {
        let total_ct_len = plaintext
            .len()
            .checked_add(CHACHA20_POLY1305.tag_len())
            .ok_or(CryptoError::InvalidEnvelopeFormat)?;
        if total_ct_len > MAX_ENVELOPE_CIPHERTEXT_BYTES {
            return Err(CryptoError::InvalidEnvelopeFormat);
        }

        let aad_bytes = aad.encode_canonical()?;
        let wrapping_key = self.derive_wrapping_key(&hkdf_salt, aad, &aad_bytes)?;
        let unbound = UnboundKey::new(&CHACHA20_POLY1305, &*wrapping_key)
            .map_err(|_| CryptoError::KeyDerivationFailed)?;
        let aead_key = LessSafeKey::new(unbound);

        let mut ciphertext_and_tag = Vec::with_capacity(total_ct_len);
        ciphertext_and_tag.extend_from_slice(plaintext);

        aead_key
            .seal_in_place_append_tag(
                Nonce::assume_unique_for_key(nonce),
                Aad::from(aad_bytes.as_slice()),
                &mut ciphertext_and_tag,
            )
            .map_err(|_| CryptoError::KeyDerivationFailed)?;

        Ok(SealedSecretEnvelope {
            version: ENVELOPE_VERSION_V1,
            hkdf_salt,
            nonce,
            ciphertext_and_tag,
        })
    }

    /// Unwraps `envelope` iff both shares and `aad` match the original seal parameters.
    pub fn unwrap_envelope(
        &self,
        envelope: &SealedSecretEnvelope,
        aad: &UnwrapAad<'_>,
    ) -> Result<SecretBytes, CryptoError> {
        if envelope.version != ENVELOPE_VERSION_V1 {
            return Err(CryptoError::UnsupportedEnvelopeVersion(envelope.version));
        }
        if envelope.ciphertext_and_tag.len() > MAX_ENVELOPE_CIPHERTEXT_BYTES {
            return Err(CryptoError::InvalidEnvelopeFormat);
        }
        if envelope.ciphertext_and_tag.len() < CHACHA20_POLY1305.tag_len() {
            return Err(CryptoError::AuthenticationFailed);
        }

        let aad_bytes = aad.encode_canonical()?;
        let wrapping_key = self
            .derive_wrapping_key(&envelope.hkdf_salt, aad, &aad_bytes)
            .map_err(|_| CryptoError::AuthenticationFailed)?;
        let unbound = UnboundKey::new(&CHACHA20_POLY1305, &*wrapping_key)
            .map_err(|_| CryptoError::AuthenticationFailed)?;
        let aead_key = LessSafeKey::new(unbound);

        let mut buffer = Zeroizing::new(envelope.ciphertext_and_tag.clone());
        let plaintext_len = aead_key
            .open_in_place(
                Nonce::assume_unique_for_key(envelope.nonce),
                Aad::from(aad_bytes.as_slice()),
                buffer.as_mut_slice(),
            )
            .map_err(|_| CryptoError::AuthenticationFailed)?
            .len();

        for trailing in &mut buffer[plaintext_len..] {
            *trailing = 0;
        }
        buffer.truncate(plaintext_len);

        Ok(SecretBytes(buffer))
    }
}

/// Fixed 32-byte Host Share vector for the deterministic startup Known-Answer Test.
pub const KAT_HOST_SHARE: [u8; 32] = [
    0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f,
    0x20, 0x21, 0x22, 0x23, 0x24, 0x25, 0x26, 0x27, 0x28, 0x29, 0x2a, 0x2b, 0x2c, 0x2d, 0x2e, 0x2f,
];

const KAT_FIXED_HW_SHARE: [u8; 32] = [
    0x50, 0x51, 0x52, 0x53, 0x54, 0x55, 0x56, 0x57, 0x58, 0x59, 0x5a, 0x5b, 0x5c, 0x5d, 0x5e, 0x5f,
    0x60, 0x61, 0x62, 0x63, 0x64, 0x65, 0x66, 0x67, 0x68, 0x69, 0x6a, 0x6b, 0x6c, 0x6d, 0x6e, 0x6f,
];

/// Fixed 32-byte HKDF salt vector for the deterministic startup Known-Answer Test.
pub const KAT_HKDF_SALT: [u8; 32] = [
    0x80, 0x81, 0x82, 0x83, 0x84, 0x85, 0x86, 0x87, 0x88, 0x89, 0x8a, 0x8b, 0x8c, 0x8d, 0x8e, 0x8f,
    0x90, 0x91, 0x92, 0x93, 0x94, 0x95, 0x96, 0x97, 0x98, 0x99, 0x9a, 0x9b, 0x9c, 0x9d, 0x9e, 0x9f,
];

/// Fixed 12-byte ChaCha20-Poly1305 nonce vector for the deterministic startup Known-Answer Test.
pub const KAT_NONCE: [u8; 12] = [
    0xc0, 0xc1, 0xc2, 0xc3, 0xc4, 0xc5, 0xc6, 0xc7, 0xc8, 0xc9, 0xca, 0xcb,
];

/// Fixed `secret_id` for the deterministic startup Known-Answer Test.
pub const KAT_SECRET_ID: &str = "selftest/kat-v1";

/// Fixed `policy_hash` for the deterministic startup Known-Answer Test.
pub const KAT_POLICY_HASH: [u8; 32] = [0x7e; 32];

/// Fixed `guest_cid` for the deterministic startup Known-Answer Test.
pub const KAT_GUEST_CID: u32 = 3;

/// Fixed 32-byte plaintext vector for the deterministic startup Known-Answer Test.
pub const KAT_PLAINTEXT: &[u8; 32] = b"kat-deterministic-secret-vec-v1!";

/// Precomputed RFC 5869 hardware challenge digest (`unwrap-hw-chal-v1`) for the KAT vector.
pub const KAT_EXPECTED_HW_CHALLENGE: [u8; 32] = [
    0x4a, 0x2d, 0x44, 0x9b, 0xe5, 0x00, 0x9b, 0x3c, 0xd1, 0xfc, 0x5c, 0xb3, 0x7c, 0x70, 0x94, 0x3b,
    0x4c, 0xc8, 0x3f, 0x82, 0x7b, 0xcf, 0xf6, 0xba, 0xb5, 0xfe, 0x05, 0xfe, 0x51, 0x23, 0x6c, 0x74,
];

/// Precomputed RFC 5869 2-of-2 AEAD wrapping key (`unwrap-kek-v1`) for the KAT vector.
pub const KAT_EXPECTED_WRAPPING_KEY: [u8; 32] = [
    0x87, 0xd6, 0x21, 0x60, 0x90, 0x54, 0xd2, 0x0a, 0x15, 0xb6, 0x6e, 0x92, 0x40, 0x68, 0x99, 0xc7,
    0xe6, 0x69, 0x5b, 0x26, 0x1b, 0x15, 0xe6, 0x6a, 0x4f, 0x12, 0xf4, 0x19, 0xed, 0x64, 0x75, 0xe9,
];

/// Precomputed RFC 8439 ChaCha20-Poly1305 `ciphertext || tag` (48 bytes) for the KAT vector.
pub const KAT_EXPECTED_CIPHERTEXT_AND_TAG: [u8; 48] = [
    0x9e, 0x34, 0x44, 0x1c, 0xa3, 0xe9, 0x98, 0xab, 0xc6, 0xc2, 0xfd, 0x17, 0x3d, 0xfc, 0x70, 0x46,
    0x13, 0x4a, 0xf9, 0x74, 0x76, 0xd0, 0x90, 0x26, 0xec, 0x27, 0x51, 0xc1, 0x5c, 0x0b, 0xde, 0x88,
    0x38, 0x2f, 0xd2, 0xcc, 0xd9, 0x9a, 0x3b, 0x7e, 0x46, 0xcb, 0x5f, 0x7b, 0xa1, 0xdd, 0x24, 0xe0,
];

/// Deterministic Known-Answer Test [`HardwareUnwrapper`] adapter that accepts **exclusively**
/// [`KAT_EXPECTED_HW_CHALLENGE`] and fails closed (`CryptoError::HardwareFailure`) on all other
/// inputs, preventing use as a general software HSM while exercising [`SecretUnwrapper`] directly.
#[derive(Clone, Copy, Debug)]
pub struct KatChallengeBoundUnwrapper;

impl HardwareUnwrapper for KatChallengeBoundUnwrapper {
    fn derive_hardware_share(&self, challenge: &[u8]) -> Result<Zeroizing<[u8; 32]>, CryptoError> {
        if aws_lc_rs::constant_time::verify_slices_are_equal(challenge, &KAT_EXPECTED_HW_CHALLENGE)
            .is_err()
        {
            return Err(CryptoError::HardwareFailure);
        }
        Ok(Zeroizing::new(KAT_FIXED_HW_SHARE))
    }
}

/// Executes the deterministic Known-Answer Test directly through [`SecretUnwrapper`],
/// verifying exact byte-for-byte equality against [`KAT_EXPECTED_WRAPPING_KEY`] and
/// [`KAT_EXPECTED_CIPHERTEXT_AND_TAG`], plus deterministic tamper rejection, without `test-hsm`.
pub fn verify_deterministic_unwrap_kat() -> Result<SealedSecretEnvelope, CryptoError> {
    use aws_lc_rs::constant_time::verify_slices_are_equal;

    let unwrapper = SecretUnwrapper::new(
        HostShare::from_bytes(KAT_HOST_SHARE),
        KatChallengeBoundUnwrapper,
    );
    let aad = UnwrapAad {
        secret_id: KAT_SECRET_ID,
        policy_hash: KAT_POLICY_HASH,
        guest_cid: KAT_GUEST_CID,
    };
    let aad_bytes = aad.encode_canonical()?;
    let derived_kek = unwrapper.derive_wrapping_key(&KAT_HKDF_SALT, &aad, &aad_bytes)?;
    if verify_slices_are_equal(&*derived_kek, &KAT_EXPECTED_WRAPPING_KEY).is_err() {
        return Err(CryptoError::KeyDerivationFailed);
    }

    let sealed =
        unwrapper.seal_with_salt_and_nonce(KAT_PLAINTEXT, &aad, KAT_HKDF_SALT, KAT_NONCE)?;
    if verify_slices_are_equal(&sealed.ciphertext_and_tag, &KAT_EXPECTED_CIPHERTEXT_AND_TAG)
        .is_err()
    {
        return Err(CryptoError::AuthenticationFailed);
    }

    let wire = sealed.to_bytes();
    let parsed = SealedSecretEnvelope::from_bytes(&wire)?;
    let opened = unwrapper.unwrap_envelope(&parsed, &aad)?;
    if verify_slices_are_equal(opened.expose_secret(), KAT_PLAINTEXT).is_err() {
        return Err(CryptoError::AuthenticationFailed);
    }

    // 1-bit ciphertext tamper must fail closed
    let mut tampered_ct = parsed.clone();
    if let Some(first) = tampered_ct.ciphertext_and_tag.first_mut() {
        *first ^= 0x01;
    }
    if !matches!(
        unwrapper.unwrap_envelope(&tampered_ct, &aad),
        Err(CryptoError::AuthenticationFailed)
    ) {
        return Err(CryptoError::AuthenticationFailed);
    }

    // 1-bit nonce tamper must fail closed
    let mut tampered_nonce = parsed.clone();
    tampered_nonce.nonce[0] ^= 0x01;
    if !matches!(
        unwrapper.unwrap_envelope(&tampered_nonce, &aad),
        Err(CryptoError::AuthenticationFailed)
    ) {
        return Err(CryptoError::AuthenticationFailed);
    }

    // 1-bit salt tamper must fail closed via challenge mismatch -> AuthenticationFailed
    let mut tampered_salt = parsed.clone();
    tampered_salt.hkdf_salt[0] ^= 0x01;
    if !matches!(
        unwrapper.unwrap_envelope(&tampered_salt, &aad),
        Err(CryptoError::AuthenticationFailed)
    ) {
        return Err(CryptoError::AuthenticationFailed);
    }

    // Wrong HostShare must fail closed
    let mut wrong_host_bytes = KAT_HOST_SHARE;
    wrong_host_bytes[0] ^= 0x01;
    let wrong_host_unwrapper = SecretUnwrapper::new(
        HostShare::from_bytes(wrong_host_bytes),
        KatChallengeBoundUnwrapper,
    );
    if !matches!(
        wrong_host_unwrapper.unwrap_envelope(&parsed, &aad),
        Err(CryptoError::AuthenticationFailed)
    ) {
        return Err(CryptoError::AuthenticationFailed);
    }

    Ok(parsed)
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;

    #[test]
    fn seal_and_unwrap_roundtrip_with_both_shares() {
        let host = HostShare::from_bytes([0x11; 32]);
        let hsm = SoftwareTestHsm::new([0x22; 32]);
        let unwrapper = SecretUnwrapper::new(host, hsm);

        let aad = UnwrapAad {
            secret_id: "anthropic/prod-api-key",
            policy_hash: [0xAB; 32],
            guest_cid: 42,
        };
        let raw = b"sk-ant-api03-cleanroom-secret-material";
        let envelope = unwrapper.seal(raw, &aad).unwrap();

        let wire = envelope.to_bytes();
        let decoded = SealedSecretEnvelope::from_bytes(&wire).unwrap();
        assert_eq!(envelope, decoded);

        let opened = unwrapper.unwrap_envelope(&decoded, &aad).unwrap();
        assert_eq!(opened.expose_secret(), raw);
    }

    #[test]
    fn wrong_host_or_hardware_share_fails_authentication() {
        let aad = UnwrapAad {
            secret_id: "github/app-token",
            policy_hash: [0xCD; 32],
            guest_cid: 7,
        };
        let sealer = SecretUnwrapper::new(
            HostShare::from_bytes([0x01; 32]),
            SoftwareTestHsm::new([0x02; 32]),
        );
        let env = sealer.seal(b"ghs_supersecret", &aad).unwrap();

        let wrong_host = SecretUnwrapper::new(
            HostShare::from_bytes([0x99; 32]),
            SoftwareTestHsm::new([0x02; 32]),
        );
        assert_eq!(
            wrong_host.unwrap_envelope(&env, &aad).unwrap_err(),
            CryptoError::AuthenticationFailed
        );

        let wrong_hw = SecretUnwrapper::new(
            HostShare::from_bytes([0x01; 32]),
            SoftwareTestHsm::new([0x99; 32]),
        );
        assert_eq!(
            wrong_hw.unwrap_envelope(&env, &aad).unwrap_err(),
            CryptoError::AuthenticationFailed
        );
    }
}
