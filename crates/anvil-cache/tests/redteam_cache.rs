//! Mandatory Phase 3 Adversarial Red-Team Suite (`anvil-cache`).

#![allow(clippy::unwrap_used, clippy::expect_used)]

use std::collections::BTreeMap;
use std::path::PathBuf;

use anvil_cache::sanitize::validate_metadata_str;
use anvil_cache::{CacheError, CacheStore, CacheStoreConfig, SanitizeError};

fn fresh_test_root(name: &str) -> PathBuf {
    let mut dir = std::env::temp_dir();
    let mut entropy = [0u8; 8];
    aws_lc_rs::rand::fill(&mut entropy).unwrap();
    let hex_id: String = entropy.iter().map(|b| format!("{b:02x}")).collect();
    dir.push(format!("locksmith-redteam-cache-{name}-{hex_id}"));
    std::fs::create_dir_all(&dir).unwrap();
    dir
}

#[test]
fn redteam_post_seal_mutation_and_kernel_eperm_toctou_defense() {
    let root = fresh_test_root("toctou");
    let store = CacheStore::new(
        CacheStoreConfig {
            root_dir: root.clone(),
            namespace: "prod-cache".to_owned(),
            schema_version: 1,
            max_blob_bytes: 1_048_576,
        },
        &[0x33; 32],
    )
    .unwrap();

    let original_bytes = b"IMMUTABLE-VERIFIED-POLICY-PAYLOAD-V1";
    let digest = store
        .put("policies/allowlist", original_bytes, &BTreeMap::new())
        .unwrap();

    // Consumer obtains verified sealed handle
    let hit = store.get("policies/allowlist").unwrap();

    // Attacker mutates underlying content-addressed blob on disk AFTER VerifiedReadOnlyBlob is returned
    let hex_digest: String = digest.iter().map(|b| format!("{b:02x}")).collect();
    let disk_blob_path = root.join("blobs").join(format!("{hex_digest}.blob"));
    std::fs::write(&disk_blob_path, b"POISONED-POST-VERIFICATION-BYTES!!!!").unwrap();

    // 1. Existing consumer's VerifiedReadOnlyBlob MUST be 100% unaffected by disk mutation
    assert_eq!(hit.blob.read_to_vec().unwrap(), original_bytes);

    // 2. Subsequent reads from the poisoned disk blob MUST fail closed on BLAKE3 verification
    assert_eq!(
        store.get("policies/allowlist").unwrap_err(),
        CacheError::IntegrityMismatch
    );

    // 3. On Linux, attempting write() or ftruncate() directly on the sealed memfd MUST fail with EPERM
    #[cfg(target_os = "linux")]
    {
        assert!(
            hit.blob.is_kernel_sealed(),
            "Linux host must back VerifiedReadOnlyBlob with a kernel-sealed memfd"
        );
        let sealed_fd = hit.blob.as_sealed_fd().unwrap();
        let write_err = rustix::io::write(sealed_fd, b"X").unwrap_err();
        assert_eq!(
            write_err,
            rustix::io::Errno::PERM,
            "kernel F_SEAL_WRITE must reject direct fd writes with EPERM"
        );

        let trunc_err = rustix::fs::ftruncate(sealed_fd, 0).unwrap_err();
        assert_eq!(
            trunc_err,
            rustix::io::Errno::PERM,
            "kernel F_SEAL_SHRINK/GROW must reject ftruncate with EPERM"
        );

        let seal_err =
            rustix::fs::fcntl_add_seals(sealed_fd, rustix::fs::SealFlags::WRITE).unwrap_err();
        assert_eq!(
            seal_err,
            rustix::io::Errno::PERM,
            "kernel F_SEAL_SEAL must reject further seal modifications with EPERM"
        );
    }

    let _ = std::fs::remove_dir_all(&root);
}

#[test]
fn redteam_key_substitution_swap_attack_fails_closed() {
    let root = fresh_test_root("keyswap");
    let store = CacheStore::new(
        CacheStoreConfig {
            root_dir: root.clone(),
            namespace: "swap-ns".to_owned(),
            schema_version: 2,
            max_blob_bytes: 65_536,
        },
        &[0x44; 32],
    )
    .unwrap();

    let mut meta_a = BTreeMap::new();
    meta_a.insert("role".to_owned(), "readonly".to_owned());
    let mut meta_b = BTreeMap::new();
    meta_b.insert("role".to_owned(), "superadmin".to_owned());

    store
        .put("workload/guest-a/config", b"allow: get /status", &meta_a)
        .unwrap();
    store
        .put("workload/guest-b/config", b"allow: * /admin", &meta_b)
        .unwrap();

    // Locate both valid index files and swap them under each other's logical keys
    let key_id_a: String = blake3::hash(b"workload/guest-a/config")
        .as_bytes()
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect();
    let key_id_b: String = blake3::hash(b"workload/guest-b/config")
        .as_bytes()
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect();

    let meta_path_a = root.join("index").join(format!("{key_id_a}.entry"));
    let meta_path_b = root.join("index").join(format!("{key_id_b}.entry"));

    let raw_a = std::fs::read(&meta_path_a).unwrap();
    let raw_b = std::fs::read(&meta_path_b).unwrap();
    std::fs::write(&meta_path_a, &raw_b).unwrap();
    std::fs::write(&meta_path_b, &raw_a).unwrap();

    assert_eq!(
        store.get("workload/guest-a/config").unwrap_err(),
        CacheError::IntegrityMismatch,
        "swapped valid entry B under logical key A must fail keyed BLAKE3 verification"
    );
    assert_eq!(
        store.get("workload/guest-b/config").unwrap_err(),
        CacheError::IntegrityMismatch,
        "swapped valid entry A under logical key B must fail keyed BLAKE3 verification"
    );

    let _ = std::fs::remove_dir_all(&root);
}

#[test]
fn redteam_symlink_and_path_traversal_escape_rejected() {
    use anvil_cache::seal::{open_confined_readonly, validate_relative_cache_path};

    let root = fresh_test_root("traversal");
    let outside_dir = fresh_test_root("outside-victim");
    let victim_file = outside_dir.join("ring1-secret-canary.txt");
    let victim_canary = b"RING1_HOST_FILE_MUST_NEVER_BE_OVERWRITTEN";
    std::fs::write(&victim_file, victim_canary).unwrap();

    let store = CacheStore::new(
        CacheStoreConfig {
            root_dir: root.clone(),
            namespace: "confine-ns".to_owned(),
            schema_version: 1,
            max_blob_bytes: 65_536,
        },
        &[0x55; 32],
    )
    .unwrap();

    let logical_key = "artifacts/poison-target";
    let payload = b"attacker-controlled-cache-payload";
    let blob_hex: String = blake3::hash(payload)
        .as_bytes()
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect();
    let key_hex: String = blake3::hash(logical_key.as_bytes())
        .as_bytes()
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect();

    #[cfg(unix)]
    {
        use std::os::unix::fs::symlink;

        // 1. Plant symlink at exact content-addressed blob path before CacheStore::put
        let planted_blob_link = root.join("blobs").join(format!("{blob_hex}.blob"));
        symlink(&victim_file, &planted_blob_link).unwrap();

        assert_eq!(
            store
                .put(logical_key, payload, &BTreeMap::new())
                .unwrap_err(),
            CacheError::PathViolation,
            "CacheStore::put must reject symlink at blobs/<hex>.blob with PathViolation"
        );
        assert_eq!(
            std::fs::read(&victim_file).unwrap(),
            victim_canary,
            "CacheStore::put must NEVER follow symlinks or overwrite target files"
        );
        std::fs::remove_file(&planted_blob_link).unwrap();

        // 2. Plant symlink at exact index/<hex>.entry path before CacheStore::put and CacheStore::get
        let planted_entry_link = root.join("index").join(format!("{key_hex}.entry"));
        symlink(&victim_file, &planted_entry_link).unwrap();

        assert_eq!(
            store
                .put(logical_key, payload, &BTreeMap::new())
                .unwrap_err(),
            CacheError::PathViolation,
            "CacheStore::put must reject symlink at index/<hex>.entry with PathViolation"
        );
        assert_eq!(
            store.get(logical_key).unwrap_err(),
            CacheError::PathViolation,
            "CacheStore::get must reject symlink at index/<hex>.entry with PathViolation"
        );
        assert_eq!(std::fs::read(&victim_file).unwrap(), victim_canary);
        std::fs::remove_file(&planted_entry_link).unwrap();

        // 3. Valid put followed by replacing blobs/<hex>.blob with a symlink before CacheStore::get
        store.put(logical_key, payload, &BTreeMap::new()).unwrap();
        let real_blob_path = root.join("blobs").join(format!("{blob_hex}.blob"));
        std::fs::remove_file(&real_blob_path).unwrap();
        symlink(&victim_file, &real_blob_path).unwrap();

        assert_eq!(
            store.get(logical_key).unwrap_err(),
            CacheError::PathViolation,
            "CacheStore::get must reject symlink at blobs/<hex>.blob with PathViolation"
        );
    }

    // 4. Direct confined reader & relative path validator reject traversal and non-safe paths
    for bad_path in [
        "../etc/passwd",
        "blobs/../../etc/passwd",
        "/etc/passwd",
        "blobs/./target.txt",
        "blobs\\target.txt",
        "",
    ] {
        assert_eq!(
            validate_relative_cache_path(bad_path).unwrap_err(),
            CacheError::PathViolation
        );
        assert_eq!(
            open_confined_readonly(&root, bad_path).unwrap_err(),
            CacheError::PathViolation,
            "path '{bad_path}' must fail closed with PathViolation"
        );
    }

    let _ = std::fs::remove_dir_all(&root);
    let _ = std::fs::remove_dir_all(&outside_dir);
}

#[test]
fn redteam_invisible_unicode_tag_and_osc_injection_rejected() {
    let root = fresh_test_root("sanitize");
    let store = CacheStore::new(
        CacheStoreConfig {
            root_dir: root.clone(),
            namespace: "sanitize-ns".to_owned(),
            schema_version: 1,
            max_blob_bytes: 65_536,
        },
        &[0x66; 32],
    )
    .unwrap();

    // Invisible Unicode Tag prompt-injection ("IGNORE" encoded in U+E0049 U+E0047...)
    let unicode_tag_payload = "model-v1\u{E0049}\u{E0047}\u{E004E}\u{E004F}\u{E0052}\u{E0045}";
    assert!(matches!(
        validate_metadata_str(unicode_tag_payload).unwrap_err(),
        SanitizeError::UnicodeTagCharacter { .. }
    ));

    // Terminal title-spoofing OSC sequence
    let osc_payload = "clean-label\x1b]2;root@prod: sudo rm -rf /\x07";
    assert!(matches!(
        validate_metadata_str(osc_payload).unwrap_err(),
        SanitizeError::AnsiEscapeSequence { .. }
    ));

    // Bidirectional Trojan-Source override (RLO U+202E)
    let bidi_payload = "policy-\u{202E}txt.exe";
    assert!(matches!(
        validate_metadata_str(bidi_payload).unwrap_err(),
        SanitizeError::BidiOrZeroWidthCharacter { .. }
    ));

    // CacheStore::put MUST reject poisoned metadata deterministically
    let mut poisoned_meta = BTreeMap::new();
    poisoned_meta.insert("description".to_owned(), unicode_tag_payload.to_owned());
    assert!(matches!(
        store
            .put("models/system-prompt", b"data", &poisoned_meta)
            .unwrap_err(),
        CacheError::Sanitize(SanitizeError::UnicodeTagCharacter { .. })
    ));

    let mut osc_meta = BTreeMap::new();
    osc_meta.insert("terminal-hint".to_owned(), osc_payload.to_owned());
    assert!(matches!(
        store
            .put("models/terminal", b"data", &osc_meta)
            .unwrap_err(),
        CacheError::Sanitize(SanitizeError::AnsiEscapeSequence { .. })
    ));

    let _ = std::fs::remove_dir_all(&root);
}
