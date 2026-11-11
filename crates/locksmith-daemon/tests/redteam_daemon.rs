//! Mandatory Phase 6 Adversarial & Integration Suite (`locksmith-daemon`).

#![allow(clippy::unwrap_used, clippy::expect_used)]

use std::process::Command;
use std::sync::Arc;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use anvil_core::ledger::AuditLedger;
use anvil_core::replay::ReplayFilter;
use anvil_core::unwrap::{HardwareUnwrapper, HostShare, SecretUnwrapper, SoftwareTestHsm};
use anvil_core::CryptoError;
use anvil_ipc::frame::{read_bounded_frame, write_bounded_frame, MessageType, WireFrame};
use anvil_ipc::{AttestedCommandEnvelope, CommandVerifier, PeerAllowlist};
use locksmith_daemon::{
    harden_process, is_process_nondumpable, BrokerDaemon, DaemonRuntimeConfig,
    Ring0UnixHardwareUnwrapper,
};
use locksmith_proxy::PolicyEngine;
use tokio::net::{UnixListener, UnixStream};
use tokio::sync::watch;

fn unique_temp_dir(label: &str) -> std::path::PathBuf {
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    let dir = std::env::temp_dir().join(format!(
        "locksmith-daemon-test-{label}-{}-{nanos}",
        std::process::id()
    ));
    std::fs::create_dir_all(&dir).unwrap();
    dir
}

#[test]
fn redteam_verify_self_binary_enforces_nondumpable_and_passes_kats() {
    harden_process().unwrap();
    assert!(
        is_process_nondumpable().unwrap(),
        "PR_SET_DUMPABLE(0) must be active in Ring 1 process"
    );

    #[cfg(target_os = "linux")]
    {
        let behavior = rustix::process::dumpable_behavior().unwrap();
        assert_eq!(behavior, rustix::process::DumpableBehavior::NotDumpable);
    }

    let bin = env!("CARGO_BIN_EXE_locksmith-daemon");
    let output = Command::new(bin)
        .env_clear()
        .arg("verify-self")
        .output()
        .unwrap();

    let stdout = String::from_utf8_lossy(&output.stdout);
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        output.status.success(),
        "verify-self exited non-zero: stdout={stdout}, stderr={stderr}"
    );
    assert!(stdout.contains("locksmith-daemon verify-self: OK (nondumpable=true"));
}

#[test]
fn redteam_argv_and_env_secret_smuggling_rejected_with_zero_echo_leak() {
    let bin = env!("CARGO_BIN_EXE_locksmith-daemon");

    // 1. Secret smuggled in CLI argv
    let canary_argv = "sk-live-canary-999111";
    let out_argv = Command::new(bin)
        .env_clear()
        .arg("verify-self")
        .arg(format!("--secret={canary_argv}"))
        .output()
        .unwrap();
    assert!(!out_argv.status.success());
    let combined_argv = format!(
        "{}{}",
        String::from_utf8_lossy(&out_argv.stdout),
        String::from_utf8_lossy(&out_argv.stderr)
    );
    assert!(
        !combined_argv.contains(canary_argv),
        "CLI error output MUST NEVER echo back secret argv values"
    );
    assert!(combined_argv.contains("ambient secret hygiene violation"));

    // 2. Secret smuggled in LOCKSMITH_SECRET environment variable
    let canary_env = "sk-live-canary-999222";
    let out_env = Command::new(bin)
        .env_clear()
        .env("LOCKSMITH_SECRET", canary_env)
        .arg("verify-self")
        .output()
        .unwrap();
    assert!(!out_env.status.success());
    let combined_env = format!(
        "{}{}",
        String::from_utf8_lossy(&out_env.stdout),
        String::from_utf8_lossy(&out_env.stderr)
    );
    assert!(
        !combined_env.contains(canary_env),
        "Daemon error output MUST NEVER echo back secret env values"
    );
    assert!(combined_env.contains("ambient secret hygiene violation"));

    // 3. Ambient provider API key leaked into Ring 1 daemon environment
    let canary_api = "sk-ant-canary-999333";
    let out_api = Command::new(bin)
        .env_clear()
        .env("ANTHROPIC_API_KEY", canary_api)
        .arg("verify-self")
        .output()
        .unwrap();
    assert!(!out_api.status.success());
    let combined_api = format!(
        "{}{}",
        String::from_utf8_lossy(&out_api.stdout),
        String::from_utf8_lossy(&out_api.stderr)
    );
    assert!(!combined_api.contains(canary_api));
    assert!(combined_api.contains("ambient secret hygiene violation"));
}

#[tokio::test]
async fn redteam_ring0_uid_spoofing_and_broker_graceful_shutdown_audit_chain() {
    let dir = unique_temp_dir("ring0-and-shutdown");
    let rogue_ring0_sock = dir.join("rogue-ring0.sock");

    let current_uid = rustix::process::getuid().as_raw();
    let other_uid = current_uid.wrapping_add(1);

    // Spawn a rogue Ring 0 socket listener owned by current_uid while client expects other_uid
    let rogue_listener = UnixListener::bind(&rogue_ring0_sock).unwrap();
    let rogue_server = tokio::spawn(async move {
        if let Ok((mut stream, _)) = rogue_listener.accept().await {
            use tokio::io::AsyncWriteExt;
            let _ = stream.write_all(&[0xAA; 32]).await;
        }
    });

    let unwrapper_client = Ring0UnixHardwareUnwrapper::new(
        rogue_ring0_sock.clone(),
        other_uid,
        Duration::from_secs(1),
    );
    let hsm_res =
        tokio::task::spawn_blocking(move || unwrapper_client.derive_hardware_share(&[0x42; 32]))
            .await
            .unwrap();
    assert_eq!(hsm_res.unwrap_err(), CryptoError::HardwareFailure);
    rogue_server.abort();

    // Exercise BrokerDaemon attested IPC dispatch + clean graceful shutdown + AuditLedger chain
    let ipc_sock = dir.join("broker-ipc.sock");
    let mut allowlist = PeerAllowlist::new();
    allowlist.allow_unix_uid(current_uid, 7);

    let ledger = Arc::new(AuditLedger::new());
    let replay = Arc::new(ReplayFilter::with_defaults(128).unwrap());
    let attest_key = [0x5A; 32];
    let verifier = Arc::new(CommandVerifier::new(attest_key, Arc::clone(&replay)));
    let secret_unwrapper = Arc::new(SecretUnwrapper::new(
        HostShare::from_bytes([0x11; 32]),
        SoftwareTestHsm::new([0x22; 32]),
    ));
    let policy_engine = Arc::new(PolicyEngine::new(
        Vec::new(),
        Arc::clone(&replay),
        secret_unwrapper,
    ));

    let daemon = Arc::new(BrokerDaemon::new(
        DaemonRuntimeConfig {
            ipc_socket_path: ipc_sock.clone(),
            frame_read_deadline: Duration::from_secs(2),
            shutdown_drain_timeout: Duration::from_secs(2),
            peer_allowlist: allowlist,
        },
        Arc::clone(&ledger),
        verifier,
        policy_engine,
    ));

    let (shutdown_tx, shutdown_rx) = watch::channel(false);
    let daemon_runner = Arc::clone(&daemon);
    let server_handle =
        tokio::spawn(async move { daemon_runner.serve_until_shutdown(shutdown_rx).await });

    // Wait briefly for socket bind
    for _ in 0..40 {
        if ipc_sock.exists() {
            break;
        }
        tokio::time::sleep(Duration::from_millis(10)).await;
    }

    let now_ms = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_millis() as u64;

    let mut client = UnixStream::connect(&ipc_sock).await.unwrap();
    let env = AttestedCommandEnvelope::sign_new(
        &attest_key,
        7,
        1,
        now_ms,
        [0x88; 32],
        b"STATUS".to_vec(),
    )
    .unwrap();
    let req_frame = WireFrame {
        msg_type: MessageType::CommandRequest,
        payload: env.to_bytes().unwrap(),
    };
    write_bounded_frame(&mut client, &req_frame, Duration::from_secs(2))
        .await
        .unwrap();
    let resp_frame = read_bounded_frame(&mut client, Duration::from_secs(2))
        .await
        .unwrap();
    assert_eq!(resp_frame.msg_type, MessageType::CommandResponse);
    assert_eq!(resp_frame.payload, b"OK");
    drop(client);

    // Trigger clean shutdown and assert ledger integrity
    shutdown_tx.send(true).unwrap();
    server_handle.await.unwrap().unwrap();

    ledger.verify_all().unwrap();
    let entries = ledger.entries_snapshot().unwrap();
    assert!(entries.iter().any(|e| e.kind == "daemon.start"));
    assert!(entries.iter().any(|e| e.kind == "ipc.command.accepted"));
    assert!(entries.iter().any(|e| e.kind == "daemon.shutdown"));

    let _ = std::fs::remove_dir_all(&dir);
}
