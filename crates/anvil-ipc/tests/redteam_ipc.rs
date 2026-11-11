//! Mandatory Phase 4 Adversarial Red-Team Suite (`anvil-ipc`).

#![allow(clippy::unwrap_used, clippy::expect_used)]

use std::path::PathBuf;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::UnixStream;

use anvil_ipc::frame::{parse_frame_header, read_bounded_frame, MAX_FRAME_BYTES};
use anvil_ipc::{IpcError, IpcServerConfig, PeerAllowlist, UnixIpcListener, WireFrame};

fn fresh_socket_path(tag: &str) -> PathBuf {
    let mut path = std::env::temp_dir();
    let mut entropy = [0u8; 8];
    aws_lc_rs::rand::fill(&mut entropy).unwrap();
    let hex_id: String = entropy.iter().map(|b| format!("{b:02x}")).collect();
    path.push(format!("locksmith-rt-ipc-{tag}-{hex_id}.sock"));
    path
}

#[tokio::test]
async fn redteam_4gib_frame_bomb_dos_rejected_before_allocation() {
    // Exact 4 GiB - 1 frame-bomb header: ["LKSM", version=1, msg_type=1, len=0xFFFF_FFFF]
    let bomb_header: [u8; 10] = [b'L', b'K', b'S', b'M', 1, 1, 0xFF, 0xFF, 0xFF, 0xFF];

    // 1. Direct header check rejects u32::MAX prior to any buffer allocation
    assert_eq!(
        parse_frame_header(&bomb_header).unwrap_err(),
        IpcError::FrameTooLarge {
            declared_len: u32::MAX,
            max_len: MAX_FRAME_BYTES,
        }
    );

    // 2. Boundary off-by-one check: MAX_FRAME_BYTES + 1 (65,537) must also fail closed
    let boundary_plus_one: [u8; 10] = [b'L', b'K', b'S', b'M', 1, 1, 0x00, 0x01, 0x00, 0x01];
    assert_eq!(
        parse_frame_header(&boundary_plus_one).unwrap_err(),
        IpcError::FrameTooLarge {
            declared_len: 65_537,
            max_len: MAX_FRAME_BYTES,
        }
    );

    // 3. Live stream check: send 10-byte 4 GiB header and assert immediate FrameTooLarge disconnect
    let (mut attacker, mut server) = tokio::io::duplex(256);
    attacker.write_all(&bomb_header).await.unwrap();

    let err = read_bounded_frame(&mut server, Duration::from_millis(500))
        .await
        .unwrap_err();
    assert_eq!(
        err,
        IpcError::FrameTooLarge {
            declared_len: u32::MAX,
            max_len: MAX_FRAME_BYTES,
        }
    );
}

#[tokio::test]
async fn redteam_slowloris_byte_drip_timeout_teardown() {
    let sock_path = fresh_socket_path("slowloris");

    #[cfg(target_os = "linux")]
    let current_uid = rustix::process::getuid().as_raw();
    #[cfg(not(target_os = "linux"))]
    let current_uid = 0u32;

    let mut allowlist = PeerAllowlist::new();
    allowlist.allow_unix_uid(current_uid, 10);

    let listener = UnixIpcListener::bind(
        &sock_path,
        IpcServerConfig {
            frame_read_deadline: Duration::from_millis(500),
            allowlist,
        },
    )
    .unwrap();

    let connect_path = sock_path.clone();
    let slowloris_client = tokio::spawn(async move {
        let mut stream = UnixStream::connect(&connect_path).await.unwrap();
        // Send only 3 bytes of the 10-byte header and stall well past the 500ms deadline
        stream.write_all(b"LKS").await.unwrap();
        tokio::time::sleep(Duration::from_millis(1_500)).await;
    });

    let started = Instant::now();
    let handler_invocations = Arc::new(AtomicUsize::new(0));
    let counter_ref = Arc::clone(&handler_invocations);

    let res = listener
        .accept_and_dispatch_once(move |_peer, frame: WireFrame| {
            counter_ref.fetch_add(1, Ordering::SeqCst);
            async move { Ok(frame) }
        })
        .await;

    let elapsed = started.elapsed();
    assert_eq!(res.unwrap_err(), IpcError::FrameTimeout);
    assert!(
        elapsed < Duration::from_millis(1_200),
        "slowloris stream must tear down promptly at ~500ms deadline (took {elapsed:?})"
    );
    assert_eq!(handler_invocations.load(Ordering::SeqCst), 0);

    slowloris_client.abort();
    let _ = std::fs::remove_file(&sock_path);
}

#[tokio::test]
async fn redteam_unauthorized_peer_cid_and_uid_dropped_before_handler() {
    // 1. Unauthorized AF_VSOCK CID check (including reserved CID 0, 1, 2 and non-allowlisted guest CID 999)
    let mut allowlist = PeerAllowlist::new();
    allowlist.allow_vsock_cid(42);
    assert!(allowlist.verify_vsock_peer(42, 5000).is_ok());
    for unauthorized_cid in [0u32, 1, 2, 41, 43, 999] {
        assert!(matches!(
            allowlist
                .verify_vsock_peer(unauthorized_cid, 5000)
                .unwrap_err(),
            IpcError::UnauthorizedPeer { .. }
        ));
    }

    // 2. Live Unix Domain Socket SO_PEERCRED rejection when peer UID is NOT in allowlist
    let sock_path = fresh_socket_path("unauth-uid");

    #[cfg(target_os = "linux")]
    let current_uid = rustix::process::getuid().as_raw();
    #[cfg(not(target_os = "linux"))]
    let current_uid = 1000u32;

    // Allowlist ONLY a different UID so current process's kernel SO_PEERCRED UID is unauthorized
    let different_uid = current_uid.wrapping_add(1);
    let mut strict_allowlist = PeerAllowlist::new();
    strict_allowlist.allow_unix_uid(different_uid, 50);

    let listener = UnixIpcListener::bind(
        &sock_path,
        IpcServerConfig {
            frame_read_deadline: Duration::from_millis(500),
            allowlist: strict_allowlist,
        },
    )
    .unwrap();

    let handler_called = Arc::new(AtomicUsize::new(0));
    let handler_called_ref = Arc::clone(&handler_called);

    let connect_path = sock_path.clone();
    let rogue_client = tokio::spawn(async move {
        let mut stream = UnixStream::connect(&connect_path).await.unwrap();
        // Attempt to push a valid-looking frame; server must drop prior to reading or dispatching
        let _ = stream
            .write_all(&[b'L', b'K', b'S', b'M', 1, 4, 0, 0, 0, 0])
            .await;
        let mut buf = [0u8; 16];
        stream.read(&mut buf).await.unwrap_or(0)
    });

    let dispatch_err = listener
        .accept_and_dispatch_once(move |_peer, frame| {
            handler_called_ref.fetch_add(1, Ordering::SeqCst);
            async move { Ok(frame) }
        })
        .await
        .unwrap_err();

    assert!(matches!(dispatch_err, IpcError::UnauthorizedPeer { .. }));
    assert_eq!(
        handler_called.load(Ordering::SeqCst),
        0,
        "command handler MUST NEVER be invoked for an unauthorized peer"
    );
    assert_eq!(
        rogue_client.await.unwrap(),
        0,
        "unauthorized peer socket must observe immediate EOF disconnect"
    );

    let _ = std::fs::remove_file(&sock_path);
}

#[cfg(target_os = "linux")]
fn current_rss_kib() -> u64 {
    let status = std::fs::read_to_string("/proc/self/status").unwrap();
    for line in status.lines() {
        if let Some(rest) = line.strip_prefix("VmRSS:") {
            let digits = rest.split_whitespace().next().unwrap_or("0");
            return digits.parse::<u64>().unwrap_or(0);
        }
    }
    0
}

#[tokio::test]
async fn redteam_socket_permissions_0600_reserved_cid_and_command_verifier_hardening() {
    use anvil_core::replay::ReplayFilter;
    use anvil_ipc::{AttestedCommandEnvelope, CommandVerifier};
    use std::os::unix::fs::PermissionsExt;

    // 1. UnixIpcListener::bind MUST enforce 0600 owner-only socket mode
    let sock_path = fresh_socket_path("perm0600");
    let listener = UnixIpcListener::bind(
        &sock_path,
        IpcServerConfig {
            frame_read_deadline: Duration::from_millis(500),
            allowlist: PeerAllowlist::new(),
        },
    )
    .unwrap();
    let mode = std::fs::symlink_metadata(&sock_path)
        .unwrap()
        .permissions()
        .mode()
        & 0o777;
    assert_eq!(
        mode, 0o600,
        "UnixIpcListener socket permissions must be strictly 0600 (got 0o{mode:o})"
    );
    drop(listener);
    let _ = std::fs::remove_file(&sock_path);

    // 2. PeerAllowlist MUST refuse mapping any Unix UID to reserved CIDs 0, 1, or 2
    for reserved_cid in [0u32, 1, 2] {
        let mut allow = PeerAllowlist::new();
        allow.allow_unix_uid(1000, reserved_cid);
        assert!(
            matches!(
                allow.verify_unix_peer(1000, 1000, Some(42)),
                Err(IpcError::UnauthorizedPeer { .. })
            ),
            "reserved CID {reserved_cid} must never be authorized via Unix UID mapping"
        );
    }

    // 3. CommandVerifier adversarial matrix: u64::MAX exhaustion, signature bit-flip, CID spoof, replay
    let root_key = [0x91; 32];
    let replay = Arc::new(ReplayFilter::with_defaults(256).unwrap());
    let verifier = CommandVerifier::new(root_key, replay);
    let now_ms = 1_762_000_000_000u64;

    let max_seq_env = AttestedCommandEnvelope::sign_new(
        &root_key,
        9,
        u64::MAX,
        now_ms,
        [0x01; 32],
        b"exhaust".to_vec(),
    );
    if let Ok(env) = max_seq_env {
        assert!(
            verifier.verify_and_accept(&env, 9, now_ms).is_err(),
            "sequence_no == u64::MAX must be rejected before poisoning sequence state"
        );
    }

    let valid_env =
        AttestedCommandEnvelope::sign_new(&root_key, 9, 10, now_ms, [0x02; 32], b"status".to_vec())
            .unwrap();
    assert_eq!(
        verifier
            .verify_and_accept(&valid_env, 10, now_ms)
            .unwrap_err(),
        IpcError::GuestCidMismatch {
            expected: 10,
            actual: 9
        }
    );

    let mut sig_flipped = valid_env.clone();
    sig_flipped.hardware_signature[15] ^= 0x01;
    assert_eq!(
        verifier
            .verify_and_accept(&sig_flipped, 9, now_ms)
            .unwrap_err(),
        IpcError::SignatureVerificationFailed
    );

    assert_eq!(
        verifier.verify_and_accept(&valid_env, 9, now_ms).unwrap(),
        b"status"
    );
    // Out-of-order sequence (seq 9 < 10) rejected
    let out_of_order =
        AttestedCommandEnvelope::sign_new(&root_key, 9, 9, now_ms, [0x03; 32], b"rewind".to_vec())
            .unwrap();
    assert!(matches!(
        verifier
            .verify_and_accept(&out_of_order, 9, now_ms)
            .unwrap_err(),
        IpcError::SequenceViolation {
            last_seen: Some(10),
            actual: 9
        }
    ));

    // 4. Verify 500 x 4 GiB frame bombs cause negligible RSS delta (< 16 MiB vs 2 TiB)
    #[cfg(target_os = "linux")]
    {
        let rss_before = current_rss_kib();
        let bomb_header: [u8; 10] = [b'L', b'K', b'S', b'M', 1, 1, 0xFF, 0xFF, 0xFF, 0xFF];
        for _ in 0..500 {
            let (mut tx, mut rx) = tokio::io::duplex(64);
            tx.write_all(&bomb_header).await.unwrap();
            let err = read_bounded_frame(&mut rx, Duration::from_millis(100))
                .await
                .unwrap_err();
            assert!(matches!(err, IpcError::FrameTooLarge { .. }));
        }
        let rss_after = current_rss_kib();
        let delta_kib = rss_after.saturating_sub(rss_before);
        assert!(
            delta_kib < 16_384,
            "500 x 4 GiB frame bombs must not grow RSS (delta={delta_kib} KiB)"
        );
    }
}
