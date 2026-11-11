use std::collections::BTreeMap;
use std::io::Read;
use std::path::{Path, PathBuf};

use anvil_core::kdf::{derive_subkey, DOMAIN_CACHE_MAC};
use aws_lc_rs::constant_time::verify_slices_are_equal;
use zeroize::Zeroizing;

use crate::error::CacheError;
use crate::sanitize::validate_metadata_str;
#[cfg(not(target_os = "linux"))]
use crate::seal::open_confined_readonly;
use crate::seal::{seal_and_verify_reader, VerifiedReadOnlyBlob};

const META_MAGIC: &[u8; 4] = b"LKCM";
const META_FORMAT_VERSION: u8 = 1;
const MAX_META_FILE_BYTES: usize = 65_536;
const MAX_LOGICAL_KEY_BYTES: usize = 512;
const CACHE_MAC_DOMAIN: &[u8] = b"LOCKSMITH-CACHE-MAC-V1";

/// Configuration for [`CacheStore`].
#[derive(Clone, Debug)]
pub struct CacheStoreConfig {
    /// Root directory on disk containing `blobs/` and `index/`.
    pub root_dir: PathBuf,
    /// Logical namespace mixed into HKDF subkey derivation.
    pub namespace: String,
    /// Schema version bound into every keyed `BLAKE3` MAC.
    pub schema_version: u32,
    /// Hard cap on blob size in bytes.
    pub max_blob_bytes: u64,
}

/// Verified cache hit bundling the kernel-sealed blob and sanitized metadata.
#[derive(Debug)]
pub struct CacheHit {
    pub blob: VerifiedReadOnlyBlob,
    pub metadata: BTreeMap<String, String>,
    pub schema_version: u32,
}

#[derive(Debug)]
struct ParsedIndexRecord {
    schema_version: u32,
    content_len: u64,
    blake3_root: [u8; 32],
    mac: [u8; 32],
    metadata: BTreeMap<String, String>,
}

fn hex_encode_32(bytes: &[u8; 32]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut out = String::with_capacity(64);
    for &b in bytes {
        out.push(char::from(HEX[usize::from(b >> 4)]));
        out.push(char::from(HEX[usize::from(b & 0x0F)]));
    }
    out
}

fn validate_logical_key(logical_key: &str) -> Result<(), CacheError> {
    if logical_key.is_empty() || logical_key.len() > MAX_LOGICAL_KEY_BYTES {
        return Err(CacheError::InvalidLogicalKey);
    }
    validate_metadata_str(logical_key).map_err(|_| CacheError::InvalidLogicalKey)?;
    if !logical_key.bytes().all(|b| (0x21..=0x7E).contains(&b)) {
        return Err(CacheError::InvalidLogicalKey);
    }
    Ok(())
}

fn compute_keyed_mac(
    mac_key: &[u8; 32],
    logical_key: &str,
    schema_version: u32,
    content_len: u64,
    blake3_root: &[u8; 32],
    metadata: &BTreeMap<String, String>,
) -> Result<[u8; 32], CacheError> {
    let key_len_u16 =
        u16::try_from(logical_key.len()).map_err(|_| CacheError::InvalidLogicalKey)?;
    let meta_count_u16 =
        u16::try_from(metadata.len()).map_err(|_| CacheError::CorruptRecordFormat)?;

    let mut hasher = blake3::Hasher::new_keyed(mac_key);
    hasher.update(CACHE_MAC_DOMAIN);
    hasher.update(&key_len_u16.to_be_bytes());
    hasher.update(logical_key.as_bytes());
    hasher.update(&schema_version.to_be_bytes());
    hasher.update(&content_len.to_be_bytes());
    hasher.update(blake3_root);
    hasher.update(&meta_count_u16.to_be_bytes());

    for (k, v) in metadata {
        let k_len = u16::try_from(k.len()).map_err(|_| CacheError::CorruptRecordFormat)?;
        let v_len = u16::try_from(v.len()).map_err(|_| CacheError::CorruptRecordFormat)?;
        hasher.update(&k_len.to_be_bytes());
        hasher.update(k.as_bytes());
        hasher.update(&v_len.to_be_bytes());
        hasher.update(v.as_bytes());
    }

    Ok(*hasher.finalize().as_bytes())
}

fn serialize_index_record(
    schema_version: u32,
    content_len: u64,
    blake3_root: &[u8; 32],
    mac: &[u8; 32],
    metadata: &BTreeMap<String, String>,
) -> Result<Vec<u8>, CacheError> {
    let meta_count = u16::try_from(metadata.len()).map_err(|_| CacheError::CorruptRecordFormat)?;
    let mut out = Vec::with_capacity(83 + metadata.len() * 32);
    out.extend_from_slice(META_MAGIC);
    out.push(META_FORMAT_VERSION);
    out.extend_from_slice(&schema_version.to_be_bytes());
    out.extend_from_slice(&content_len.to_be_bytes());
    out.extend_from_slice(blake3_root);
    out.extend_from_slice(mac);
    out.extend_from_slice(&meta_count.to_be_bytes());

    for (k, v) in metadata {
        let k_len = u16::try_from(k.len()).map_err(|_| CacheError::CorruptRecordFormat)?;
        let v_len = u16::try_from(v.len()).map_err(|_| CacheError::CorruptRecordFormat)?;
        out.extend_from_slice(&k_len.to_be_bytes());
        out.extend_from_slice(k.as_bytes());
        out.extend_from_slice(&v_len.to_be_bytes());
        out.extend_from_slice(v.as_bytes());
    }
    Ok(out)
}

fn parse_index_record(bytes: &[u8]) -> Result<ParsedIndexRecord, CacheError> {
    const FIXED_HEADER: usize = 4 + 1 + 4 + 8 + 32 + 32 + 2;
    if bytes.len() < FIXED_HEADER {
        return Err(CacheError::CorruptRecordFormat);
    }
    if &bytes[0..4] != META_MAGIC || bytes[4] != META_FORMAT_VERSION {
        return Err(CacheError::CorruptRecordFormat);
    }

    let mut schema_bytes = [0u8; 4];
    schema_bytes.copy_from_slice(&bytes[5..9]);
    let schema_version = u32::from_be_bytes(schema_bytes);

    let mut len_bytes = [0u8; 8];
    len_bytes.copy_from_slice(&bytes[9..17]);
    let content_len = u64::from_be_bytes(len_bytes);

    let mut blake3_root = [0u8; 32];
    blake3_root.copy_from_slice(&bytes[17..49]);

    let mut mac = [0u8; 32];
    mac.copy_from_slice(&bytes[49..81]);

    let mut count_bytes = [0u8; 2];
    count_bytes.copy_from_slice(&bytes[81..83]);
    let count = usize::from(u16::from_be_bytes(count_bytes));

    let mut cursor = FIXED_HEADER;
    let mut metadata = BTreeMap::new();
    for _ in 0..count {
        if cursor + 2 > bytes.len() {
            return Err(CacheError::CorruptRecordFormat);
        }
        let mut kl = [0u8; 2];
        kl.copy_from_slice(&bytes[cursor..cursor + 2]);
        cursor += 2;
        let k_len = usize::from(u16::from_be_bytes(kl));
        if cursor + k_len > bytes.len() {
            return Err(CacheError::CorruptRecordFormat);
        }
        let k_str = std::str::from_utf8(&bytes[cursor..cursor + k_len])
            .map_err(|_| CacheError::CorruptRecordFormat)?;
        validate_metadata_str(k_str)?;
        cursor += k_len;

        if cursor + 2 > bytes.len() {
            return Err(CacheError::CorruptRecordFormat);
        }
        let mut vl = [0u8; 2];
        vl.copy_from_slice(&bytes[cursor..cursor + 2]);
        cursor += 2;
        let v_len = usize::from(u16::from_be_bytes(vl));
        if cursor + v_len > bytes.len() {
            return Err(CacheError::CorruptRecordFormat);
        }
        let v_str = std::str::from_utf8(&bytes[cursor..cursor + v_len])
            .map_err(|_| CacheError::CorruptRecordFormat)?;
        validate_metadata_str(v_str)?;
        cursor += v_len;

        if metadata
            .insert(k_str.to_owned(), v_str.to_owned())
            .is_some()
        {
            return Err(CacheError::CorruptRecordFormat);
        }
    }

    if cursor != bytes.len() {
        return Err(CacheError::CorruptRecordFormat);
    }

    Ok(ParsedIndexRecord {
        schema_version,
        content_len,
        blake3_root,
        mac,
        metadata,
    })
}

/// Hostile-transport content-addressed cache store enforcing keyed `BLAKE3` MAC
/// verification, anchored `openat2` path confinement, and `memfd` sealing.
pub struct CacheStore {
    config: CacheStoreConfig,
    mac_key: Zeroizing<[u8; 32]>,
    #[cfg(target_os = "linux")]
    root_fd: rustix::fd::OwnedFd,
}

impl CacheStore {
    /// Initializes a [`CacheStore`], anchoring a persistent directory descriptor on
    /// `config.root_dir` and deriving a domain-separated `BLAKE3` MAC key from
    /// `master_key` via `anvil-core` canonical HKDF.
    pub fn new(config: CacheStoreConfig, master_key: &[u8; 32]) -> Result<Self, CacheError> {
        validate_metadata_str(&config.namespace)?;
        if config.max_blob_bytes == 0 {
            return Err(CacheError::CorruptRecordFormat);
        }

        if std::fs::symlink_metadata(&config.root_dir).is_err() {
            std::fs::create_dir_all(&config.root_dir).map_err(|_| CacheError::IoError)?;
        }

        #[cfg(target_os = "linux")]
        let root_fd = crate::seal::open_anchor_root_dir(&config.root_dir)?;

        #[cfg(not(target_os = "linux"))]
        {
            let root_meta =
                std::fs::symlink_metadata(&config.root_dir).map_err(|_| CacheError::IoError)?;
            if root_meta.file_type().is_symlink() {
                return Err(CacheError::PathViolation);
            }
            for sub in ["blobs", "index"] {
                let p = config.root_dir.join(sub);
                if std::fs::symlink_metadata(&p).is_err() {
                    std::fs::create_dir(&p).map_err(|_| CacheError::IoError)?;
                }
                let sub_meta = std::fs::symlink_metadata(&p).map_err(|_| CacheError::IoError)?;
                if sub_meta.file_type().is_symlink() || !sub_meta.is_dir() {
                    return Err(CacheError::PathViolation);
                }
            }
        }

        let mac_key = derive_subkey(
            b"LOCKSMITH-ANVIL-CACHE-SALT-V1",
            master_key,
            &[DOMAIN_CACHE_MAC, config.namespace.as_bytes()],
        )
        .map_err(|_| CacheError::IntegrityMismatch)?;

        Ok(Self {
            config,
            mac_key,
            #[cfg(target_os = "linux")]
            root_fd,
        })
    }

    /// Returns the cache root directory path.
    #[must_use]
    pub fn root_dir(&self) -> &Path {
        &self.config.root_dir
    }

    /// Sanitizes `metadata`, writes the content-addressed `<hex>.blob` via confined
    /// atomic `openat2` staging, and writes a keyed `BLAKE3` MAC `<hex>.entry` index record
    /// binding `(logical_key, schema_version, content_len, blake3_root)`.
    pub fn put(
        &self,
        logical_key: &str,
        payload: &[u8],
        metadata: &BTreeMap<String, String>,
    ) -> Result<[u8; 32], CacheError> {
        validate_logical_key(logical_key)?;
        let content_len = u64::try_from(payload.len()).map_err(|_| CacheError::IoError)?;
        if content_len > self.config.max_blob_bytes {
            return Err(CacheError::BlobTooLarge {
                len: content_len,
                max: self.config.max_blob_bytes,
            });
        }

        for (k, v) in metadata {
            validate_metadata_str(k)?;
            validate_metadata_str(v)?;
        }

        let blake3_root = *blake3::hash(payload).as_bytes();
        let mac = compute_keyed_mac(
            &self.mac_key,
            logical_key,
            self.config.schema_version,
            content_len,
            &blake3_root,
            metadata,
        )?;

        let blob_hex = hex_encode_32(&blake3_root);
        let blob_filename = format!("{blob_hex}.blob");

        let key_id = *blake3::hash(logical_key.as_bytes()).as_bytes();
        let key_hex = hex_encode_32(&key_id);
        let entry_filename = format!("{key_hex}.entry");
        let entry_bytes = serialize_index_record(
            self.config.schema_version,
            content_len,
            &blake3_root,
            &mac,
            metadata,
        )?;

        #[cfg(target_os = "linux")]
        {
            // Validate index destination has no planted symlink BEFORE writing blob or entry
            crate::seal::write_confined_atomic_at(&self.root_fd, "blobs", &blob_filename, payload)?;
            crate::seal::write_confined_atomic_at(
                &self.root_fd,
                "index",
                &entry_filename,
                &entry_bytes,
            )?;
        }

        #[cfg(not(target_os = "linux"))]
        {
            for (sub, fname, data) in [
                ("blobs", blob_filename.as_str(), payload),
                ("index", entry_filename.as_str(), entry_bytes.as_slice()),
            ] {
                let sub_path = self.config.root_dir.join(sub);
                let sub_meta =
                    std::fs::symlink_metadata(&sub_path).map_err(|_| CacheError::IoError)?;
                if sub_meta.file_type().is_symlink() {
                    return Err(CacheError::PathViolation);
                }
                let full_path = sub_path.join(fname);
                if let Ok(m) = std::fs::symlink_metadata(&full_path) {
                    if m.file_type().is_symlink() || !m.is_file() {
                        return Err(CacheError::PathViolation);
                    }
                }
                std::fs::write(&full_path, data).map_err(|_| CacheError::IoError)?;
            }
        }

        Ok(blake3_root)
    }

    /// Opens the cached `<hex>.entry` and `<hex>.blob` strictly beneath the anchored
    /// `root_fd`, copies into a kernel-sealed `memfd`, and verifies both the content
    /// `BLAKE3` root and keyed `BLAKE3` MAC before returning [`CacheHit`].
    pub fn get(&self, logical_key: &str) -> Result<CacheHit, CacheError> {
        validate_logical_key(logical_key)?;

        let key_id = *blake3::hash(logical_key.as_bytes()).as_bytes();
        let key_hex = hex_encode_32(&key_id);
        let rel_entry = format!("index/{key_hex}.entry");

        #[cfg(target_os = "linux")]
        let mut entry_file = crate::seal::open_confined_readonly_at(&self.root_fd, &rel_entry)?;
        #[cfg(not(target_os = "linux"))]
        let mut entry_file = open_confined_readonly(&self.config.root_dir, &rel_entry)?;

        let mut raw_entry = Vec::new();
        entry_file
            .by_ref()
            .take((MAX_META_FILE_BYTES + 1) as u64)
            .read_to_end(&mut raw_entry)
            .map_err(|_| CacheError::IoError)?;
        if raw_entry.len() > MAX_META_FILE_BYTES {
            return Err(CacheError::CorruptRecordFormat);
        }

        let record = parse_index_record(&raw_entry)?;
        if record.schema_version != self.config.schema_version {
            return Err(CacheError::SchemaVersionMismatch {
                expected: self.config.schema_version,
                actual: record.schema_version,
            });
        }
        if record.content_len > self.config.max_blob_bytes {
            return Err(CacheError::BlobTooLarge {
                len: record.content_len,
                max: self.config.max_blob_bytes,
            });
        }

        let blob_hex = hex_encode_32(&record.blake3_root);
        let rel_blob = format!("blobs/{blob_hex}.blob");

        #[cfg(target_os = "linux")]
        let blob_file = crate::seal::open_confined_readonly_at(&self.root_fd, &rel_blob)?;
        #[cfg(not(target_os = "linux"))]
        let blob_file = open_confined_readonly(&self.config.root_dir, &rel_blob)?;

        let expected_root = record.blake3_root;
        let expected_len = record.content_len;
        let expected_mac = record.mac;
        let metadata_ref = &record.metadata;
        let schema_version = record.schema_version;

        let sealed_blob = seal_and_verify_reader(
            blob_file,
            self.config.max_blob_bytes,
            |actual_len, actual_root| {
                if actual_len != expected_len {
                    return Err(CacheError::IntegrityMismatch);
                }
                if verify_slices_are_equal(actual_root, &expected_root).is_err() {
                    return Err(CacheError::IntegrityMismatch);
                }

                let recomputed_mac = compute_keyed_mac(
                    &self.mac_key,
                    logical_key,
                    schema_version,
                    actual_len,
                    actual_root,
                    metadata_ref,
                )?;
                if verify_slices_are_equal(&recomputed_mac, &expected_mac).is_err() {
                    return Err(CacheError::IntegrityMismatch);
                }
                Ok(())
            },
        )?;

        #[cfg(target_os = "linux")]
        if !sealed_blob.is_kernel_sealed() {
            return Err(CacheError::SealFailed);
        }

        Ok(CacheHit {
            blob: sealed_blob,
            metadata: record.metadata,
            schema_version,
        })
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;

    fn temp_cache_dir(label: &str) -> PathBuf {
        let mut dir = std::env::temp_dir();
        let mut rand_bytes = [0u8; 8];
        aws_lc_rs::rand::fill(&mut rand_bytes).unwrap();
        let suffix: String = rand_bytes.iter().map(|b| format!("{b:02x}")).collect();
        dir.push(format!("locksmith-cache-unit-{label}-{suffix}"));
        std::fs::create_dir_all(&dir).unwrap();
        dir
    }

    #[test]
    fn put_and_get_roundtrip_verifies_mac_and_metadata() {
        let root = temp_cache_dir("roundtrip");
        let store = CacheStore::new(
            CacheStoreConfig {
                root_dir: root.clone(),
                namespace: "unit-v1".to_owned(),
                schema_version: 1,
                max_blob_bytes: 65_536,
            },
            &[0x7A; 32],
        )
        .unwrap();

        let mut meta = BTreeMap::new();
        meta.insert(
            "content-type".to_owned(),
            "application/octet-stream".to_owned(),
        );
        meta.insert("origin".to_owned(), "ring1-verified".to_owned());

        let payload = b"cleanroom-content-addressed-artifact";
        let root_hash = store
            .put("artifacts/policy-bundle-v1", payload, &meta)
            .unwrap();

        let hit = store.get("artifacts/policy-bundle-v1").unwrap();
        assert_eq!(hit.blob.content_digest(), &root_hash);
        assert_eq!(hit.blob.read_to_vec().unwrap(), payload);
        assert_eq!(hit.metadata, meta);
        assert_eq!(hit.schema_version, 1);

        let _ = std::fs::remove_dir_all(&root);
    }
}
