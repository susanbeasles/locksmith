use std::io::Cursor;
use std::os::unix::net::UnixStream as StdUnixStream;
use std::time::Duration;

use anvil_cache::sanitize::validate_metadata_str;
use anvil_cache::seal::seal_and_verify_reader;
use anvil_core::kdf::derive_subkey;
use anvil_core::ledger::{AuditLedger, LedgerEventInput};
use anvil_core::replay::ReplayFilter;
use anvil_core::unwrap::{HostShare, SecretUnwrapper, UnwrapAad};
use anvil_core::{CryptoError, ReplayError};
use anvil_ipc::frame::read_bounded_frame;
use anvil_ipc::IpcError;
use aws_lc_rs::constant_time::verify_slices_are_equal;
use locksmith_proxy::{
    scrub_secret_reflections, OutboundHttpRequest, PolicyError, SCRUB_REPLACEMENT_TOKEN,
};
use tokio::io::AsyncWriteExt;
use zeroize::Zeroizing;

use crate::error::DaemonError;
use crate::harden::{harden_process, is_process_nondumpable};
use crate::hsm::{serve_ring0_hmac_stream, ConnectedRing0StreamUnwrapper};

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

fn current_effective_uid() -> u32 {
    #[cfg(target_os = "linux")]
    {
        rustix::process::getuid().as_raw()
    }
    #[cfg(not(target_os = "linux"))]
    {
        0
    }
}

/// Executes deterministic in-RAM Known-Answer Tests across every Locksmith subsystem
/// without touching the filesystem (compatible with `--read-only` containers).
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

    // 3. 2-of-2 AEAD Unwrap + Tamper Rejection over in-RAM SO_PEERCRED Ring 0 socketpair
    let mut ephemeral_shares = Zeroizing::new([0u8; 64]);
    aws_lc_rs::rand::fill(&mut *ephemeral_shares).map_err(|_| CryptoError::RngFailure)?;
    let mut host_bytes = [0u8; 32];
    host_bytes.copy_from_slice(&ephemeral_shares[0..32]);
    let mut ring0_bytes = Zeroizing::new([0u8; 32]);
    ring0_bytes.copy_from_slice(&ephemeral_shares[32..64]);

    let (client_sock, server_sock) =
        StdUnixStream::pair().map_err(|e| DaemonError::Io(e.to_string()))?;
    let uid = current_effective_uid();
    // 3 challenges served: 1 for seal(), 1 for tampered unwrap(), 1 for valid unwrap()
    let ring0_thread =
        std::thread::spawn(move || serve_ring0_hmac_stream(server_sock, ring0_bytes, uid, 3));

    let ring0_client = ConnectedRing0StreamUnwrapper::new(client_sock, uid, Duration::from_secs(2));
    let unwrapper = SecretUnwrapper::new(HostShare::from_bytes(host_bytes), ring0_client);
    let kat_plaintext = Zeroizing::new(*b"kat-ephemeral-secret-vector-v1!!");
    let aad = UnwrapAad {
        secret_id: "selftest/kat",
        policy_hash: [0x7E; 32],
        guest_cid: 3,
    };

    let (tampered_res, valid_res) = tokio::task::spawn_blocking(move || {
        let sealed = unwrapper.seal(&*kat_plaintext, &aad)?;
        let mut tampered = sealed.clone();
        if let Some(first) = tampered.ciphertext_and_tag.first_mut() {
            *first ^= 0x01;
        }
        let t_res = unwrapper.unwrap_envelope(&tampered, &aad);
        let v_res = unwrapper.unwrap_envelope(&sealed, &aad)?;
        let ok_eq = verify_slices_are_equal(v_res.expose_secret(), &*kat_plaintext).is_ok();
        Ok::<(Result<_, CryptoError>, bool), CryptoError>((t_res, ok_eq))
    })
    .await
    .map_err(|e| DaemonError::Io(e.to_string()))??;

    let thread_res = ring0_thread
        .join()
        .map_err(|_| DaemonError::SelfTestFailed {
            check: "ring0_socketpair",
            detail: "Ring 0 KAT responder panicked".to_owned(),
        })?;
    thread_res?;

    if tampered_res.err() != Some(CryptoError::AuthenticationFailed) || !valid_res {
        return Err(DaemonError::SelfTestFailed {
            check: "aead_2of2_unwrap",
            detail: "2-of-2 ChaCha20-Poly1305 KAT failed".to_owned(),
        });
    }

    // 4. Single-Use Nonce Replay Filter & Append-Only BLAKE3 Audit Ledger KAT
    let replay = ReplayFilter::with_defaults(16)?;
    let kat_now = 1_762_000_000_000u64;
    replay.check_and_burn([0x44; 32], kat_now, kat_now)?;
    if replay.check_and_burn([0x44; 32], kat_now, kat_now) != Err(ReplayError::NonceAlreadyBurned) {
        return Err(DaemonError::SelfTestFailed {
            check: "replay_filter",
            detail: "duplicate nonce was not rejected".to_owned(),
        });
    }

    let ledger = AuditLedger::new();
    ledger.append(LedgerEventInput {
        timestamp_ms: kat_now,
        kind: "selftest.start",
        actor: "locksmith-daemon",
        summary: "executing deterministic startup KAT suite",
    })?;

    // 5. Cache Kernel memfd Seal & Prompt-Injection Metadata Sanitizer KAT
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

    // 7. Proxy RFC 9110/9112 Smuggling Rejector & Secret Reflection Scrubber KAT
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

    let canary = b"kat-reflection-canary+123/";
    let scrubbed = scrub_secret_reflections(
        b"502 upstream echo: kat-reflection-canary+123/ and a2F0LXJlZmxlY3Rpb24tY2FuYXJ5KzEyMy8=",
        canary,
    );
    if scrubbed
        .windows(canary.len())
        .any(|window| window == canary)
        || !scrubbed
            .windows(SCRUB_REPLACEMENT_TOKEN.len())
            .any(|window| window == SCRUB_REPLACEMENT_TOKEN)
    {
        return Err(DaemonError::SelfTestFailed {
            check: "proxy_reflection_scrubber",
            detail: "secret reflection scrubber failed to redact raw/base64 canary".to_owned(),
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
