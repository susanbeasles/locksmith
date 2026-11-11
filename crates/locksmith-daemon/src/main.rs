use std::process::ExitCode;
use std::sync::Arc;
use std::time::Duration;

use anvil_core::kdf::{derive_subkey, DOMAIN_IPC_ATTEST};
use anvil_core::ledger::AuditLedger;
use anvil_core::replay::ReplayFilter;
use anvil_core::unwrap::{HostShare, SecretUnwrapper};
use anvil_ipc::{CommandVerifier, PeerAllowlist};
use locksmith_daemon::{
    audit_argv_and_env_hygiene, harden_process, parse_cli_args, run_self_test,
    wait_for_os_shutdown_signal, BrokerDaemon, CliCommand, DaemonError, DaemonRuntimeConfig,
    Ring0UnixHardwareUnwrapper,
};
use locksmith_proxy::PolicyEngine;
use tokio::sync::watch;
use zeroize::Zeroizing;

async fn read_host_share_from_stdin() -> Result<(HostShare, Zeroizing<[u8; 32]>), DaemonError> {
    tokio::task::spawn_blocking(|| {
        use std::io::Read;
        let mut raw = Zeroizing::new([0u8; 32]);
        std::io::stdin().read_exact(&mut *raw).map_err(|_| {
            DaemonError::Io("failed to read 32-byte host share from stdin".to_owned())
        })?;
        let attest_key = derive_subkey(
            b"LOCKSMITH-DAEMON-ATTEST-SALT-V1",
            &*raw,
            &[DOMAIN_IPC_ATTEST, b"broker-root"],
        )?;
        Ok((HostShare::from_bytes(*raw), attest_key))
    })
    .await
    .map_err(|e| DaemonError::Io(e.to_string()))?
}

async fn try_main() -> Result<(), DaemonError> {
    harden_process()?;
    audit_argv_and_env_hygiene(std::env::args_os(), std::env::vars_os())?;
    let cmd = parse_cli_args(std::env::args_os())?;

    match cmd {
        CliCommand::VerifySelf => {
            let report = run_self_test().await?;
            println!(
                "locksmith-daemon verify-self: OK (nondumpable={}, ledger_head={})",
                report.process_nondumpable, report.ledger_head_hex
            );
            Ok(())
        }
        CliCommand::Version => {
            println!("locksmith-daemon {}", env!("CARGO_PKG_VERSION"));
            Ok(())
        }
        CliCommand::Help => {
            println!(
                "Usage: locksmith-daemon <verify-self | serve --ipc-socket <PATH> --ring0-socket <PATH> --host-share-stdin [--policy-file <PATH>] [--ring0-uid <UID>] [--allow-peer-uid <UID>] [--guest-cid <CID>] [--vsock-port <PORT>] [--max-connections <N>] | --version | --help>"
            );
            Ok(())
        }
        CliCommand::Serve {
            ipc_socket,
            ring0_socket,
            ring0_uid,
            allowed_peer_uid,
            mapped_guest_cid,
            policy_file,
            vsock_port,
            max_connections,
        } => {
            let loaded_policy = match policy_file {
                Some(ref p) => Some(locksmith_daemon::load_policy_file(p)?),
                None => None,
            };

            let (host_share, attest_key) = read_host_share_from_stdin().await?;
            let ring0 =
                Ring0UnixHardwareUnwrapper::new(ring0_socket, ring0_uid, Duration::from_secs(3));
            let unwrapper = Arc::new(SecretUnwrapper::new(host_share, ring0));
            let replay = Arc::new(ReplayFilter::with_defaults(4_096)?);
            let ledger = Arc::new(AuditLedger::new());
            let verifier = Arc::new(CommandVerifier::new(*attest_key, Arc::clone(&replay)));

            let mut allowlist = PeerAllowlist::new();
            allowlist.allow_unix_uid(allowed_peer_uid, mapped_guest_cid);

            let (workloads, mtls_pki) = match loaded_policy {
                Some(bundle) => {
                    for cid in bundle.vsock_cids {
                        allowlist.allow_vsock_cid(cid);
                    }
                    for (uid, cid) in bundle.unix_uid_mappings {
                        allowlist.allow_unix_uid(uid, cid);
                    }
                    (bundle.workloads, bundle.mtls_pki)
                }
                None => (Vec::new(), None),
            };

            let policy_engine = Arc::new(PolicyEngine::new(workloads, replay, unwrapper));
            let runtime_cfg = DaemonRuntimeConfig {
                ipc_socket_path: ipc_socket,
                frame_read_deadline: Duration::from_secs(5),
                shutdown_drain_timeout: Duration::from_secs(5),
                peer_allowlist: allowlist,
                max_concurrent_connections: max_connections,
                vsock_listen_port: vsock_port,
            };

            let daemon = match mtls_pki {
                Some(pki) => {
                    let session = Arc::new(locksmith_proxy::MtlsProxySession {
                        tls_server_config: pki.tls_server_config,
                        policy_engine: Arc::clone(&policy_engine),
                        upstream_resolver: Arc::new(locksmith_proxy::SystemDnsResolver),
                        upstream_tls_config: pki.upstream_tls_config,
                        io_timeout: Duration::from_secs(10),
                    });
                    BrokerDaemon::with_mtls_session(
                        runtime_cfg,
                        ledger,
                        verifier,
                        policy_engine,
                        session,
                    )
                }
                None => BrokerDaemon::new(runtime_cfg, ledger, verifier, policy_engine),
            };

            let (shutdown_tx, shutdown_rx) = watch::channel(false);
            tokio::spawn(async move {
                if wait_for_os_shutdown_signal().await.is_ok() {
                    let _ = shutdown_tx.send(true);
                }
            });

            daemon.serve_until_shutdown(shutdown_rx).await
        }
    }
}

#[tokio::main]
async fn main() -> ExitCode {
    match try_main().await {
        Ok(()) => ExitCode::SUCCESS,
        Err(err) => {
            eprintln!("locksmith-daemon error: {err}");
            ExitCode::from(1)
        }
    }
}
