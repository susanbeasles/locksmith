use std::io::Cursor;
use std::os::unix::net::UnixStream as StdUnixStream;
use std::time::Duration;

use anvil_cache::sanitize::validate_metadata_str;
use anvil_cache::seal::seal_and_verify_reader;
use anvil_core::kdf::{derive_subkey, DOMAIN_UNWRAP_KEK};
use anvil_core::ledger::{AuditLedger, LedgerEventInput};
use anvil_core::replay::ReplayFilter;
use anvil_core::unwrap::{
    SealedSecretEnvelope, UnwrapAad, ENVELOPE_VERSION_V1, MAX_ENVELOPE_CIPHERTEXT_BYTES,
};
use anvil_core::{CryptoError, ReplayError};
use anvil_ipc::frame::read_bounded_frame;
use anvil_ipc::IpcError;
use aws_lc_rs::aead::{Aad, LessSafeKey, Nonce, UnboundKey, CHACHA20_POLY1305};
use aws_lc_rs::constant_time::verify_slices_are_equal;
use locksmith_proxy::{
    scrub_secret_reflections, OutboundHttpRequest, PolicyError, SCRUB_REPLACEMENT_TOKEN,
};
use tokio::io::AsyncWriteExt;
use zeroize::Zeroizing;

use crate::error::DaemonError;
use crate::harden::{harden_process, is_process_nondumpable};
use crate::hsm::exchange_ring0_challenge;

/// Summary of deterministic startup self-tests (`locksmith-daemon verify-self`).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SelfTestReport {
    pub process_nondumpable: bool,
    pub hkdf_kat_passed: bool,
    pub aead_unwrap_kat_passed: bool,
    pub replay_and_ledger_passed: bool,
    pub cache_seal_and_sanitize_passed: bool,
    pub ipc_frame_guard_passed: bool,
    pub proxy_policy_and_scrubber_passed: bool,
    pub ledger_head_hex: String,
}

fn hex_encode_32(bytes: &[u8; 32]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut out = String::with_capacity(64);
    for &b in bytes {
        out.push(HEX[(b >> 4) as usize] as char);
        out.push(HEX[(b & 0x0F) as usize] as char);
    }
    out
}

fn verify_production_2of2_aead_and_ring0_guards() -> Result<(), DaemonError> {
    let mut ephemeral = Zeroizing::new([0u8; 108]);
    aws_lc_rs::rand::fill(&mut *ephemeral).map_err(|_| CryptoError::RngFailure)?;

    let mut host_share = Zeroizing::new([0u8; 32]);
    host_share.copy_from_slice(&ephemeral[0..32]);
    let mut hw_share = Zeroizing::new([0u8; 32]);
    hw_share.copy_from_slice(&ephemeral[32..64]);
    let mut hkdf_salt = [0u8; 32];
    hkdf_salt.copy_from_slice(&ephemeral[64..96]);
    let mut nonce_bytes = [0u8; 12];
    nonce_bytes.copy_from_slice(&ephemeral[96..108]);

    let aad = UnwrapAad {
        secret_id: "selftest/kat",
        policy_hash: [0x7E; 32],
        guest_cid: 3,
    };
    let canonical_aad = aad.encode_canonical()?;
    let kek = derive_subkey(
        &hkdf_salt,
        &*host_share,
        &[DOMAIN_UNWRAP_KEK, &*hw_share, &canonical_aad],
    )?;

    let kat_plaintext = Zeroizing::new(*b"kat-ephemeral-secret-vector-v1!!");
    let unbound_seal =
        UnboundKey::new(&CHACHA20_POLY1305, &*kek).map_err(|_| CryptoError::KeyDerivationFailed)?;
    let seal_key = LessSafeKey::new(unbound_seal);
    let mut ct = kat_plaintext.to_vec();
    seal_key
        .seal_in_place_append_tag(
            Nonce::assume_unique_for_key(nonce_bytes),
            Aad::from(&canonical_aad),
            &mut ct,
        )
        .map_err(|_| CryptoError::AuthenticationFailed)?;

    let envelope = SealedSecretEnvelope {
        version: ENVELOPE_VERSION_V1,
        hkdf_salt,
        nonce: nonce_bytes,
        ciphertext_and_tag: ct,
    };
    let wire = envelope.to_bytes();
    let parsed = SealedSecretEnvelope::from_bytes(&wire)?;

    // Oversized (> 64 KiB) envelope wire payload must fail closed before unwrapping
    let oversized_len = (MAX_ENVELOPE_CIPHERTEXT_BYTES + 1) as u32;
    let mut oversized_wire = vec![ENVELOPE_VERSION_V1];
    oversized_wire.extend_from_slice(&hkdf_salt);
    oversized_wire.extend_from_slice(&nonce_bytes);
    oversized_wire.extend_from_slice(&oversized_len.to_be_bytes());
    oversized_wire.resize(1 + 32 + 12 + 4 + MAX_ENVELOPE_CIPHERTEXT_BYTES + 1, 0u8);
    if SealedSecretEnvelope::from_bytes(&oversized_wire) != Err(CryptoError::InvalidEnvelopeFormat)
    {
        return Err(DaemonError::SelfTestFailed {
            check: "envelope_size_cap",
            detail: "oversized SealedSecretEnvelope was not rejected".to_owned(),
        });
    }

    // 1-bit ciphertext tamper must fail AEAD authentication
    let mut tampered = parsed.clone().ciphertext_and_tag;
    if let Some(b) = tampered.first_mut() {
        *b ^= 0x01;
    }
    let unbound_tamper =
        UnboundKey::new(&CHACHA20_POLY1305, &*kek).map_err(|_| CryptoError::KeyDerivationFailed)?;
    if LessSafeKey::new(unbound_tamper)
        .open_in_place(
            Nonce::assume_unique_for_key(parsed.nonce),
            Aad::from(&canonical_aad),
            &mut tampered,
        )
        .is_ok()
    {
        return Err(DaemonError::SelfTestFailed {
            check: "aead_tamper_reject",
            detail: "1-bit tampered ChaCha20-Poly1305 ciphertext did not fail closed".to_owned(),
        });
    }

    // Valid open recovers exact plaintext
    let mut opened_buf = Zeroizing::new(parsed.ciphertext_and_tag);
    let unbound_open =
        UnboundKey::new(&CHACHA20_POLY1305, &*kek).map_err(|_| CryptoError::KeyDerivationFailed)?;
    let opened = LessSafeKey::new(unbound_open)
        .open_in_place(
            Nonce::assume_unique_for_key(parsed.nonce),
            Aad::from(&canonical_aad),
            &mut opened_buf,
        )
        .map_err(|_| CryptoError::AuthenticationFailed)?;
    if verify_slices_are_equal(opened, &*kat_plaintext).is_err() {
        return Err(DaemonError::SelfTestFailed {
            check: "aead_2of2_unwrap",
            detail: "decrypted ChaCha20-Poly1305 plaintext mismatch".to_owned(),
        });
    }

    // Production Ring 0 client must enforce SO_PEERCRED UID match and reject closed/rogue peers
    #[cfg(target_os = "linux")]
    {
        let current_uid = rustix::process::getuid().as_raw();
        let (mut client_sock, _server_sock) =
            StdUnixStream::pair().map_err(|e| DaemonError::Io(e.to_string()))?;
        let wrong_uid_res = exchange_ring0_challenge(
            &mut client_sock,
            current_uid.wrapping_add(1),
            Duration::from_millis(200),
            b"LOCKSMITH-CHALLENGE",
        );
        if wrong_uid_res != Err(CryptoError::HardwareFailure) {
            return Err(DaemonError::SelfTestFailed {
                check: "ring0_peercred_guard",
                detail: "Ring 0 SO_PEERCRED UID mismatch did not fail closed".to_owned(),
            });
        }
    }

    Ok(())
}

/// Executes deterministic in-RAM Known-Answer Tests across every Locksmith subsystem
/// without touching the filesystem (compatible with `--read-only` containers) and
/// without compiling any software mock HSM into production binaries.
pub async fn run_self_test() -> Result<SelfTestReport, DaemonError> {
    // 1. OS Process Hardening (PR_SET_DUMPABLE = 0)
    harden_process()?;
    let process_nondumpable = is_process_nondumpable()?;
    if !process_nondumpable {
        return Err(DaemonError::SelfTestFailed {
            check: "pr_set_dumpable",
            detail: "process remained dumpable after harden_process()".to_owned(),
        });
    }

    // 2. Canonical Length-Prefixed HKDF-SHA256 Tuple Separation KAT
    let ikm = Zeroizing::new([0xA5u8; 32]);
    let salt = [0x3Cu8; 32];
    let k1 = derive_subkey(&salt, &*ikm, &[b"unwrap-kek-v1", b"admin", b"read"])?;
    let k2 = derive_subkey(&salt, &*ikm, &[b"unwrap-kek-v1", b"admi", b"nread"])?;
    let k1_repeat = derive_subkey(&salt, &*ikm, &[b"unwrap-kek-v1", b"admin", b"read"])?;
    if verify_slices_are_equal(&*k1, &*k1_repeat).is_err()
        || verify_slices_are_equal(&*k1, &*k2).is_ok()
    {
        return Err(DaemonError::SelfTestFailed {
            check: "hkdf_tuple_separation",
            detail: "canonical HKDF domain separation check failed".to_owned(),
        });
    }

    // 3. Production 2-of-2 ChaCha20-Poly1305 Envelope + Ring 0 SO_PEERCRED Guard KAT
    tokio::task::spawn_blocking(verify_production_2of2_aead_and_ring0_guards)
        .await
        .map_err(|e| DaemonError::Io(e.to_string()))??;

    // 4. Single-Use Nonce Replay Filter (including future-pinned front guard) & Audit Ledger KAT
    let replay = ReplayFilter::with_defaults(16)?;
    let kat_now = 1_762_000_000_000u64;
    // Future-pin queue front (+30s) then burn second nonce (-29s) and verify no premature eviction at +35s
    replay.check_and_burn([0x43; 32], kat_now + 30_000, kat_now)?;
    replay.check_and_burn([0x44; 32], kat_now - 29_000, kat_now)?;
    if replay.check_and_burn([0x44; 32], kat_now + 35_000, kat_now + 35_000)
        != Err(ReplayError::NonceAlreadyBurned)
    {
        return Err(DaemonError::SelfTestFailed {
            check: "replay_filter",
            detail: "future-pinned front allowed premature nonce double-spend".to_owned(),
        });
    }

    let ledger = AuditLedger::new();
    ledger.append(LedgerEventInput {
        timestamp_ms: kat_now,
        kind: "selftest.start",
        actor: "locksmith-daemon",
        summary: "executing deterministic startup KAT suite",
    })?;

    // 5. Cache Kernel memfd Seal (fail-closed on Linux) & Prompt-Injection Metadata Sanitizer KAT
    if validate_metadata_str("clean-cache-metadata-v1").is_err()
        || validate_metadata_str("poison\u{E0041}\x1b]0;spoof\x07").is_ok()
    {
        return Err(DaemonError::SelfTestFailed {
            check: "cache_sanitizer",
            detail: "metadata prompt-injection sanitizer KAT failed".to_owned(),
        });
    }

    let ram_payload = b"locksmith-sealed-ram-kat-blob";
    let expected_digest = *blake3::hash(ram_payload).as_bytes();
    let sealed_blob =
        seal_and_verify_reader(Cursor::new(ram_payload.as_slice()), 1024, |len, d| {
            if len != ram_payload.len() as u64 || d != &expected_digest {
                return Err(anvil_cache::CacheError::IntegrityMismatch);
            }
            Ok(())
        })?;
    #[cfg(target_os = "linux")]
    if !sealed_blob.is_kernel_sealed() {
        return Err(DaemonError::SelfTestFailed {
            check: "cache_memfd_seal",
            detail: "Linux kernel memfd F_ADD_SEALS was not active".to_owned(),
        });
    }
    if sealed_blob.read_to_vec()? != ram_payload {
        return Err(DaemonError::SelfTestFailed {
            check: "cache_memfd_seal",
            detail: "sealed RAM blob roundtrip mismatch".to_owned(),
        });
    }

    // 6. IPC 4 GiB Frame-Bomb Zero-Allocation Guard KAT
    let (mut bomb_tx, mut bomb_rx) = tokio::io::duplex(64);
    let mut forged_header = [0u8; 10];
    forged_header[0..4].copy_from_slice(b"LKSM");
    forged_header[4] = 1;
    forged_header[5] = 1;
    forged_header[6..10].copy_from_slice(&u32::MAX.to_be_bytes());
    bomb_tx
        .write_all(&forged_header)
        .await
        .map_err(|e| DaemonError::Io(e.to_string()))?;
    let ipc_res = read_bounded_frame(&mut bomb_rx, Duration::from_millis(200)).await;
    if !matches!(ipc_res, Err(IpcError::FrameTooLarge { .. })) {
        return Err(DaemonError::SelfTestFailed {
            check: "ipc_frame_bomb_guard",
            detail: "4 GiB forged frame was not rejected with FrameTooLarge".to_owned(),
        });
    }

    // 7. Proxy RFC 9110/9112 Smuggling Rejector & Multi-Alignment Base64 Scrubber KAT
    let smuggled_wire =
        b"POST /v1/messages HTTP/1.1\r\nHost: api.example.com\r\nContent-Length: 2\r\nTransfer-Encoding: chunked\r\n\r\n{}";
    if OutboundHttpRequest::from_wire_bytes(smuggled_wire)
        != Err(PolicyError::ConflictingFramingHeaders)
    {
        return Err(DaemonError::SelfTestFailed {
            check: "proxy_http_canonicalizer",
            detail: "CL+TE smuggling vector was not rejected".to_owned(),
        });
    }

    let canary = b"sk-live-secret-999";
    // Includes raw, 0-mod-3 Base64, 1-mod-3 ("Bearer <canary>"), and 2-mod-3 ("Auth:   <canary>")
    let multi_echo = b"raw=sk-live-secret-999 b0=c2stbGl2ZS1zZWNyZXQtOTk5 b1=QmVhcmVyIHNrLWxpdmUtc2VjcmV0LTk5OQ== b2=QXV0aDogICBzay1saXZlLXNlY3JldC05OTk=";
    let scrubbed = scrub_secret_reflections(multi_echo, canary);
    if scrubbed.windows(canary.len()).any(|w| w == canary)
        || scrubbed
            .windows(b"NrLWxpdmUtc2VjcmV0LTk5O".len())
            .any(|w| w == b"NrLWxpdmUtc2VjcmV0LTk5O")
        || scrubbed
            .windows(b"zay1saXZlLXNlY3JldC05OT".len())
            .any(|w| w == b"zay1saXZlLXNlY3JldC05OT")
        || scrubbed
            .windows(SCRUB_REPLACEMENT_TOKEN.len())
            .filter(|&w| w == SCRUB_REPLACEMENT_TOKEN)
            .count()
            < 4
    {
        return Err(DaemonError::SelfTestFailed {
            check: "proxy_reflection_scrubber",
            detail: "secret reflection scrubber failed raw or 0/1/2-mod-3 Base64 KAT".to_owned(),
        });
    }

    ledger.append(LedgerEventInput {
        timestamp_ms: kat_now + 1,
        kind: "selftest.complete",
        actor: "locksmith-daemon",
        summary: "all 7 startup security invariants verified",
    })?;
    ledger.verify_all()?;
    let head = ledger.head_hash()?;

    Ok(SelfTestReport {
        process_nondumpable,
        hkdf_kat_passed: true,
        aead_unwrap_kat_passed: true,
        replay_and_ledger_passed: true,
        cache_seal_and_sanitize_passed: true,
        ipc_frame_guard_passed: true,
        proxy_policy_and_scrubber_passed: true,
        ledger_head_hex: hex_encode_32(&head),
    })
}
