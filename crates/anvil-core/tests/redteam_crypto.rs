//! Mandatory Phase 2 Adversarial Red-Team Suite (`anvil-core`).

#![allow(clippy::unwrap_used, clippy::expect_used)]

use std::sync::Arc;
use tokio::sync::Barrier;

use anvil_core::kdf::derive_subkey;
use anvil_core::ledger::{AuditLedger, LedgerEventInput, GENESIS_PREV_HASH};
use anvil_core::replay::{ReplayError, ReplayFilter};
use anvil_core::unwrap::{HostShare, SecretBytes, SecretUnwrapper, SoftwareTestHsm, UnwrapAad};
use anvil_core::CryptoError;

#[test]
fn redteam_tuple_ambiguity_attack_defeated() {
    let salt = b"locksmith-redteam-salt-01";
    let ikm = b"locksmith-redteam-ikm-material-32bytes";

    // Classic boundary shift: ["admin", "read"] vs ["admi", "nread"]
    let key_admin_read = derive_subkey(salt, ikm, &[b"admin", b"read"]).unwrap();
    let key_shifted = derive_subkey(salt, ikm, &[b"admi", b"nread"]).unwrap();
    assert_ne!(
        *key_admin_read, *key_shifted,
        "canonical HKDF framing must separate shifted component boundaries"
    );

    // Empty-component boundary shift: ["a", ""] vs ["", "a"] vs ["a"]
    let key_a_empty = derive_subkey(salt, ikm, &[b"a", b""]).unwrap();
    let key_empty_a = derive_subkey(salt, ikm, &[b"", b"a"]).unwrap();
    let key_single_a = derive_subkey(salt, ikm, &[b"a"]).unwrap();
    assert_ne!(*key_a_empty, *key_empty_a);
    assert_ne!(*key_a_empty, *key_single_a);
    assert_ne!(*key_empty_a, *key_single_a);
}

#[test]
fn redteam_aead_bit_flip_matrix_and_guest_cid_spoofing() {
    let host_share = HostShare::from_bytes([0x5A; 32]);
    let hsm = SoftwareTestHsm::new([0xA5; 32]);
    let unwrapper = SecretUnwrapper::new(host_share, hsm);

    let aad = UnwrapAad {
        secret_id: "openai/prod-bearer",
        policy_hash: [0x33; 32],
        guest_cid: 104,
    };
    let plaintext = b"sk-proj-super-sensitive-cleanroom-token-0123456789";
    let original = unwrapper.seal(plaintext, &aad).unwrap();

    // Verify ciphertext + Poly1305 16-byte tag: flip every single bit across the entire buffer
    assert!(
        original.ciphertext_and_tag.len() == plaintext.len() + 16,
        "ChaCha20-Poly1305 ciphertext_and_tag must include 16-byte authentication tag"
    );
    for byte_idx in 0..original.ciphertext_and_tag.len() {
        for bit in 0..8u8 {
            let mut tampered = original.clone();
            tampered.ciphertext_and_tag[byte_idx] ^= 1u8 << bit;
            let res = unwrapper.unwrap_envelope(&tampered, &aad);
            assert_eq!(
                res.unwrap_err(),
                CryptoError::AuthenticationFailed,
                "ciphertext/tag bit flip at byte {byte_idx} bit {bit} must fail closed"
            );
        }
    }

    // Flip every single bit across the 12-byte ChaCha20-Poly1305 nonce
    for byte_idx in 0..original.nonce.len() {
        for bit in 0..8u8 {
            let mut tampered = original.clone();
            tampered.nonce[byte_idx] ^= 1u8 << bit;
            let res = unwrapper.unwrap_envelope(&tampered, &aad);
            assert_eq!(
                res.unwrap_err(),
                CryptoError::AuthenticationFailed,
                "nonce bit flip at byte {byte_idx} bit {bit} must fail closed"
            );
        }
    }

    // Flip every single bit across the 32-byte HKDF salt
    for byte_idx in 0..original.hkdf_salt.len() {
        for bit in 0..8u8 {
            let mut tampered = original.clone();
            tampered.hkdf_salt[byte_idx] ^= 1u8 << bit;
            let res = unwrapper.unwrap_envelope(&tampered, &aad);
            assert_eq!(
                res.unwrap_err(),
                CryptoError::AuthenticationFailed,
                "hkdf_salt bit flip at byte {byte_idx} bit {bit} must fail closed"
            );
        }
    }

    // AAD spoofing: guest_cid bit flips, policy_hash bit flips, and secret_id substitution
    for bit in 0..32u32 {
        let spoofed_aad = UnwrapAad {
            secret_id: aad.secret_id,
            policy_hash: aad.policy_hash,
            guest_cid: aad.guest_cid ^ (1u32 << bit),
        };
        assert_eq!(
            unwrapper
                .unwrap_envelope(&original, &spoofed_aad)
                .unwrap_err(),
            CryptoError::AuthenticationFailed,
            "guest_cid bit flip {bit} must fail closed"
        );
    }

    let mut spoofed_policy = aad.policy_hash;
    spoofed_policy[0] ^= 0x01;
    let bad_policy_aad = UnwrapAad {
        secret_id: aad.secret_id,
        policy_hash: spoofed_policy,
        guest_cid: aad.guest_cid,
    };
    assert_eq!(
        unwrapper
            .unwrap_envelope(&original, &bad_policy_aad)
            .unwrap_err(),
        CryptoError::AuthenticationFailed
    );

    let bad_id_aad = UnwrapAad {
        secret_id: "openai/staging-bearer",
        policy_hash: aad.policy_hash,
        guest_cid: aad.guest_cid,
    };
    assert_eq!(
        unwrapper
            .unwrap_envelope(&original, &bad_id_aad)
            .unwrap_err(),
        CryptoError::AuthenticationFailed
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 8)]
async fn redteam_concurrent_64_task_double_spend_race() {
    const TASKS: usize = 64;
    let filter = Arc::new(ReplayFilter::with_defaults(1_024).unwrap());
    let barrier = Arc::new(Barrier::new(TASKS));

    let shared_nonce = [0xEE; 32];
    let now_ms = 1_762_000_000_000u64;
    let valid_ts = now_ms - 1_500;

    let mut handles = Vec::with_capacity(TASKS);
    for _ in 0..TASKS {
        let filter_ref = Arc::clone(&filter);
        let barrier_ref = Arc::clone(&barrier);
        handles.push(tokio::spawn(async move {
            barrier_ref.wait().await;
            filter_ref.check_and_burn(shared_nonce, valid_ts, now_ms)
        }));
    }

    let mut ok_count = 0usize;
    let mut burned_err_count = 0usize;
    for handle in handles {
        match handle.await.unwrap() {
            Ok(()) => ok_count += 1,
            Err(ReplayError::NonceAlreadyBurned) => burned_err_count += 1,
            Err(other) => assert_eq!(
                other,
                ReplayError::NonceAlreadyBurned,
                "unexpected replay error under contention"
            ),
        }
    }

    assert_eq!(ok_count, 1, "strictly 1 task may burn a single-use nonce");
    assert_eq!(
        burned_err_count,
        TASKS - 1,
        "all remaining 63 tasks must receive NonceAlreadyBurned"
    );
}

#[test]
fn redteam_secret_redaction_guarantee_and_ledger_tamper_resistance() {
    let raw_secret = b"sk-live-CANARY-SECRET-998877665544332211";
    let canary_str = std::str::from_utf8(raw_secret).unwrap();

    let secret = SecretBytes::new(raw_secret.to_vec());
    let host_share = HostShare::from_bytes(*b"HOST-SHARE-CANARY-0123456789ABCD");
    let hsm = SoftwareTestHsm::new(*b"HW-SHARE-CANARY---0123456789ABCD");

    let debug_secret = format!("{secret:?}");
    let display_secret = format!("{secret}");
    let debug_host = format!("{host_share:?}");
    let debug_hsm = format!("{hsm:?}");

    assert!(!debug_secret.contains(canary_str));
    assert!(!display_secret.contains(canary_str));
    assert!(!debug_secret.contains("CANARY"));
    assert!(!display_secret.contains("CANARY"));
    assert!(!debug_host.contains("CANARY"));
    assert!(!debug_hsm.contains("CANARY"));

    // Verify unwrap failure error strings never echo secret or share bytes
    let unwrapper = SecretUnwrapper::new(host_share, hsm);
    let aad = UnwrapAad {
        secret_id: "stripe/prod",
        policy_hash: [0x77; 32],
        guest_cid: 9,
    };
    let mut env = unwrapper.seal(raw_secret, &aad).unwrap();
    env.ciphertext_and_tag[0] ^= 0xFF;
    let err = unwrapper.unwrap_envelope(&env, &aad).unwrap_err();
    let err_rendered = format!("{err} | {err:?}");
    assert!(!err_rendered.contains("CANARY"));
    assert!(!err_rendered.contains("sk-live"));

    // Verify hash-chained audit ledger detects splicing and prev_hash tampering
    let ledger = AuditLedger::new();
    let first = ledger
        .append(LedgerEventInput {
            timestamp_ms: 10,
            kind: "unwrap.denied",
            actor: "cid:9",
            summary: "authentication failed [REDACTED]",
        })
        .unwrap();
    let mut second = ledger
        .append(LedgerEventInput {
            timestamp_ms: 20,
            kind: "nonce.burn",
            actor: "cid:9",
            summary: "single-use burn ok",
        })
        .unwrap();
    second.prev_hash = GENESIS_PREV_HASH;
    assert!(AuditLedger::verify_slice(&GENESIS_PREV_HASH, &[first, second]).is_err());
}
