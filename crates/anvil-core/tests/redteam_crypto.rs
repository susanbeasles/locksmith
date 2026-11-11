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

#[test]
fn redteam_future_pinned_front_nonce_double_spend_and_monotonic_clock() {
    let filter = ReplayFilter::with_defaults(1_024).unwrap();
    let nonce_future = [0xA1; 32];
    let nonce_victim = [0xB2; 32];

    // Step 1: Attacker pins order.front() with a +30s future-skewed timestamp at t = 100_000
    filter
        .check_and_burn(nonce_future, 130_000, 100_000)
        .unwrap();

    // Step 2: Victim burns nonce_victim with a -30s timestamp at t = 100_000
    filter
        .check_and_burn(nonce_victim, 70_000, 100_000)
        .unwrap();

    // Step 3: Even 45s later (t = 145_000), a nonce burned within the 60s window MUST remain burned
    let nonce_mid = [0xC3; 32];
    filter.check_and_burn(nonce_mid, 100_000, 100_000).unwrap();
    assert_eq!(
        filter
            .check_and_burn(nonce_mid, 145_000, 145_000)
            .unwrap_err(),
        ReplayError::NonceAlreadyBurned,
        "nonce must remain burned across the full 2 * skew_window_ms (60s) window"
    );

    // Step 4: Even after >60s allows re-burn at t = 165_000, expiring the old front entry MUST NOT
    // delete the newly re-burned entry from the active map (future-pinned front double-spend race)
    let filter2 = ReplayFilter::with_defaults(1_024).unwrap();
    filter2
        .check_and_burn(nonce_future, 130_000, 100_000)
        .unwrap();
    filter2
        .check_and_burn(nonce_victim, 70_000, 100_000)
        .unwrap();
    // Advance past 60s from t=100_000 -> t=160_500; re-burn nonce_victim legitimately
    let _ = filter2.check_and_burn(nonce_victim, 160_500, 160_500);
    // Replay identical (nonce_victim, 160_500) 5s later at t = 165_500: MUST fail closed!
    assert_eq!(
        filter2
            .check_and_burn(nonce_victim, 160_500, 165_500)
            .unwrap_err(),
        ReplayError::NonceAlreadyBurned,
        "stale queue entry must never evict a freshly burned nonce (double-spend regression)"
    );

    // Step 5: NTP backward clock jump must never allow replaying an old timestamp/nonce
    let filter_ntp = ReplayFilter::with_defaults(128).unwrap();
    let nonce_ntp = [0xD4; 32];
    filter_ntp
        .check_and_burn(nonce_ntp, 200_000, 200_000)
        .unwrap();
    filter_ntp
        .check_and_burn([0xD5; 32], 270_000, 270_000)
        .unwrap();
    // Simulate wall-clock rewound backward by 69.995 seconds to 200_005
    assert!(
        filter_ntp
            .check_and_burn(nonce_ntp, 200_000, 200_005)
            .is_err(),
        "backward clock jump must clamp to monotonic high-water mark and reject old timestamps"
    );
}

#[test]
fn redteam_oversized_envelope_rejected_and_bounded_ledger_retention() {
    use anvil_core::unwrap::{SealedSecretEnvelope, ENVELOPE_VERSION_V1};

    // 1. Craft a wire envelope declaring 65_537 bytes (> 64 KiB hard cap)
    let oversized_ct_len: u32 = 65_537;
    let mut wire = Vec::with_capacity(49 + oversized_ct_len as usize);
    wire.push(ENVELOPE_VERSION_V1);
    wire.extend_from_slice(&[0x11; 32]);
    wire.extend_from_slice(&[0x22; 12]);
    wire.extend_from_slice(&oversized_ct_len.to_be_bytes());
    wire.resize(49 + oversized_ct_len as usize, 0xAA);

    assert_eq!(
        SealedSecretEnvelope::from_bytes(&wire).unwrap_err(),
        CryptoError::InvalidEnvelopeFormat,
        "SealedSecretEnvelope::from_bytes must reject ciphertexts exceeding 64 KiB"
    );

    // 2. Append 5_000 events to AuditLedger and assert bounded RAM retention + intact chain verification
    let ledger = AuditLedger::new();
    for seq in 0..5_000u64 {
        let e = ledger
            .append(LedgerEventInput {
                timestamp_ms: 1_000_000 + seq,
                kind: "ipc.event",
                actor: "cid:3",
                summary: "bounded retention check",
            })
            .unwrap();
        assert_eq!(e.sequence, seq);
    }

    let snapshot = ledger.entries_snapshot().unwrap();
    assert!(
        snapshot.len() <= 4_096,
        "AuditLedger in-memory retention must be bounded (got {} entries)",
        snapshot.len()
    );
    assert_eq!(snapshot.last().unwrap().sequence, 4_999);
    ledger
        .verify_all()
        .expect("bounded AuditLedger must verify retained chain against anchor hash");
}

#[test]
fn redteam_deterministic_unwrap_kat_and_challenge_bound_adapter() {
    use anvil_core::unwrap::{
        verify_deterministic_unwrap_kat, HardwareUnwrapper, KatChallengeBoundUnwrapper,
        KAT_EXPECTED_CIPHERTEXT_AND_TAG, KAT_EXPECTED_HW_CHALLENGE, KAT_GUEST_CID, KAT_HOST_SHARE,
        KAT_PLAINTEXT, KAT_POLICY_HASH, KAT_SECRET_ID,
    };

    // 1. Deterministic KAT function exercises SecretUnwrapper directly and reproduces exact RFC vector
    let kat_env = verify_deterministic_unwrap_kat().unwrap();
    assert_eq!(
        kat_env.ciphertext_and_tag.as_slice(),
        KAT_EXPECTED_CIPHERTEXT_AND_TAG.as_slice(),
        "KAT envelope ciphertext_and_tag must match precomputed RFC 8439 vector byte-for-byte"
    );

    // 2. Direct SecretUnwrapper::unwrap_envelope with KatChallengeBoundUnwrapper recovers exact plaintext
    let unwrapper = SecretUnwrapper::new(
        HostShare::from_bytes(KAT_HOST_SHARE),
        KatChallengeBoundUnwrapper,
    );
    let kat_aad = UnwrapAad {
        secret_id: KAT_SECRET_ID,
        policy_hash: KAT_POLICY_HASH,
        guest_cid: KAT_GUEST_CID,
    };
    let opened = unwrapper.unwrap_envelope(&kat_env, &kat_aad).unwrap();
    assert_eq!(opened.expose_secret(), KAT_PLAINTEXT);

    // 3. KatChallengeBoundUnwrapper MUST reject every non-KAT challenge so it can NEVER act as a mock HSM
    let adapter = KatChallengeBoundUnwrapper;
    assert!(adapter
        .derive_hardware_share(&KAT_EXPECTED_HW_CHALLENGE)
        .is_ok());
    for bit in 0..256usize {
        let mut wrong_chal = KAT_EXPECTED_HW_CHALLENGE;
        wrong_chal[bit / 8] ^= 1u8 << (bit % 8);
        assert_eq!(
            adapter.derive_hardware_share(&wrong_chal).unwrap_err(),
            CryptoError::HardwareFailure,
            "KatChallengeBoundUnwrapper must fail closed on bit flip {bit}"
        );
    }
    assert_eq!(
        adapter.derive_hardware_share(b"arbitrary").unwrap_err(),
        CryptoError::HardwareFailure
    );
    // Attempting a random seal with KatChallengeBoundUnwrapper must also fail closed
    assert!(unwrapper.seal(b"arbitrary-secret", &kat_aad).is_err());
}

#[test]
fn redteam_explicit_check_and_burn_cannot_poison_monotonic_system_clock() {
    let filter = ReplayFilter::with_defaults(128).unwrap();

    // 1. Burn a real-time nonce via Instant-anchored check_and_burn_system_time
    let sys_t0 = filter.monotonic_now_ms();
    let sys_nonce = [0x51; 32];
    filter
        .check_and_burn_system_time(sys_nonce, sys_t0)
        .unwrap();

    // 2. Call explicit check_and_burn with a far-future synthetic caller timestamp (year ~2255)
    let far_future_ms = 9_000_000_000_000u64;
    filter
        .check_and_burn([0x52; 32], far_future_ms, far_future_ms)
        .unwrap();

    // 3. Previously burned system-time nonce MUST NOT have been prematurely evicted by far_future_ms
    assert_eq!(
        filter
            .check_and_burn_system_time(sys_nonce, sys_t0)
            .unwrap_err(),
        ReplayError::NonceAlreadyBurned,
        "explicit check_and_burn now_ms must never evict live system-time nonces"
    );

    // 4. Subsequent legitimate system-time requests MUST NOT be poisoned with TimestampExpired
    let sys_t1 = filter.monotonic_now_ms();
    assert!(
        filter.check_and_burn_system_time([0x53; 32], sys_t1).is_ok(),
        "explicit check_and_burn now_ms must never poison monotonic_now_ms / check_and_burn_system_time"
    );
}
