use aws_lc_rs::hkdf::{KeyType, Salt, HKDF_SHA256};
use zeroize::Zeroizing;

pub use crate::error::CryptoError;

/// Normative protocol prefix framed at the start of every HKDF `info` buffer.
pub const PROTOCOL_VERSION_TAG: &[u8] = b"LOCKSMITH-V1";

/// Domain-separation tag for 2-of-2 AEAD Key-Encryption Keys.
pub const DOMAIN_UNWRAP_KEK: &[u8] = b"unwrap-kek-v1";
/// Domain-separation tag for Ring 0 hardware token challenge derivation.
pub const DOMAIN_UNWRAP_HW_CHALLENGE: &[u8] = b"unwrap-hw-chal-v1";
/// Domain-separation tag for `anvil-cache` keyed `BLAKE3` MAC keys.
pub const DOMAIN_CACHE_MAC: &[u8] = b"cache-mac-v1";
/// Domain-separation tag for `anvil-ipc` command envelope attestation subkeys.
pub const DOMAIN_IPC_ATTEST: &[u8] = b"ipc-attest-v1";

#[derive(Clone, Copy)]
struct HkdfOutput32;

impl KeyType for HkdfOutput32 {
    fn len(&self) -> usize {
        32
    }
}

/// Encodes `components` into canonical length-prefixed HKDF `info` bytes:
/// `[u16_be(12) || "LOCKSMITH-V1" || u16_be(count) || u16_be(c0.len()) || c0 || ...]`.
pub fn encode_canonical_info(components: &[&[u8]]) -> Result<Vec<u8>, CryptoError> {
    let count_u16 =
        u16::try_from(components.len()).map_err(|_| CryptoError::ContextTooManyComponents)?;
    let proto_len_u16 =
        u16::try_from(PROTOCOL_VERSION_TAG.len()).map_err(|_| CryptoError::KeyDerivationFailed)?;

    let mut total_bytes = 2usize + PROTOCOL_VERSION_TAG.len() + 2usize;
    for (index, comp) in components.iter().enumerate() {
        if u16::try_from(comp.len()).is_err() {
            return Err(CryptoError::ContextComponentTooLarge {
                index,
                len: comp.len(),
            });
        }
        total_bytes = total_bytes
            .checked_add(2usize)
            .and_then(|v| v.checked_add(comp.len()))
            .ok_or(CryptoError::KeyDerivationFailed)?;
    }

    let mut out = Vec::with_capacity(total_bytes);
    out.extend_from_slice(&proto_len_u16.to_be_bytes());
    out.extend_from_slice(PROTOCOL_VERSION_TAG);
    out.extend_from_slice(&count_u16.to_be_bytes());

    for (index, comp) in components.iter().enumerate() {
        let len_u16 =
            u16::try_from(comp.len()).map_err(|_| CryptoError::ContextComponentTooLarge {
                index,
                len: comp.len(),
            })?;
        out.extend_from_slice(&len_u16.to_be_bytes());
        out.extend_from_slice(comp);
    }

    Ok(out)
}

/// Derives a 256-bit subkey via `aws-lc-rs` HKDF-SHA256 using canonical
/// `[u16_be_len || bytes]` framing prefixed with `"LOCKSMITH-V1"`.
pub fn derive_subkey(
    salt: &[u8],
    ikm: &[u8],
    context_components: &[&[u8]],
) -> Result<Zeroizing<[u8; 32]>, CryptoError> {
    let canonical_info = encode_canonical_info(context_components)?;
    let prk = Salt::new(HKDF_SHA256, salt).extract(ikm);
    let info_parts = [canonical_info.as_slice()];
    let okm = prk
        .expand(&info_parts, HkdfOutput32)
        .map_err(|_| CryptoError::KeyDerivationFailed)?;

    let mut subkey = Zeroizing::new([0u8; 32]);
    okm.fill(&mut *subkey)
        .map_err(|_| CryptoError::KeyDerivationFailed)?;
    Ok(subkey)
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;

    #[test]
    fn canonical_info_prefixes_protocol_version_and_lengths() {
        let encoded = encode_canonical_info(&[b"domain", b"ctx"]).unwrap();
        assert_eq!(&encoded[0..2], &(12u16.to_be_bytes()));
        assert_eq!(&encoded[2..14], PROTOCOL_VERSION_TAG);
        assert_eq!(&encoded[14..16], &(2u16.to_be_bytes()));
        assert_eq!(&encoded[16..18], &(6u16.to_be_bytes()));
        assert_eq!(&encoded[18..24], b"domain");
        assert_eq!(&encoded[24..26], &(3u16.to_be_bytes()));
        assert_eq!(&encoded[26..29], b"ctx");
    }

    #[test]
    fn rejects_component_exceeding_u16_max() {
        let oversized = vec![0xAAu8; usize::from(u16::MAX) + 1];
        let err = derive_subkey(b"salt", b"ikm", &[b"ok", oversized.as_slice()]).unwrap_err();
        assert_eq!(
            err,
            CryptoError::ContextComponentTooLarge {
                index: 1,
                len: usize::from(u16::MAX) + 1
            }
        );
    }

    #[test]
    fn deterministic_subkey_derivation_and_salt_sensitivity() {
        let k1 = derive_subkey(b"salt-a", b"ikm-material", &[DOMAIN_CACHE_MAC, b"ns1"]).unwrap();
        let k2 = derive_subkey(b"salt-a", b"ikm-material", &[DOMAIN_CACHE_MAC, b"ns1"]).unwrap();
        let k3 = derive_subkey(b"salt-b", b"ikm-material", &[DOMAIN_CACHE_MAC, b"ns1"]).unwrap();
        assert_eq!(*k1, *k2);
        assert_ne!(*k1, *k3);
    }
}
