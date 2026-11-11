use std::path::PathBuf;
use std::sync::Arc;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use anvil_cache::sanitize::strip_hostile_metadata;
use anvil_core::ledger::{AuditLedger, LedgerEventInput};
use anvil_core::unwrap::HardwareUnwrapper;
use anvil_ipc::frame::{read_bounded_frame, write_bounded_frame, MessageType, WireFrame};
use anvil_ipc::{
    AttestedCommandEnvelope, CommandVerifier, IpcError, IpcServerConfig, PeerAllowlist,
    UnixIpcListener, VerifiedPeerIdentity,
};
use locksmith_proxy::PolicyEngine;
use tokio::net::UnixStream;
use tokio::sync::watch;
use tokio::task::JoinSet;

use crate::error::DaemonError;

/// Configuration for the Ring 1 `BrokerDaemon` control-plane loop.
#[derive(Clone, Debug)]
pub struct DaemonRuntimeConfig {
    pub ipc_socket_path: PathBuf,
    pub frame_read_deadline: Duration,
    pub shutdown_drain_timeout: Duration,
    pub peer_allowlist: PeerAllowlist,
}

fn current_epoch_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| u64::try_from(d.as_millis()).unwrap_or(u64::MAX))
        .unwrap_or(0)
}

async fn handle_verified_ipc_connection(
    mut stream: UnixStream,
    peer: VerifiedPeerIdentity,
    deadline: Duration,
    verifier: Arc<CommandVerifier>,
    ledger: Arc<AuditLedger>,
) -> Result<(), IpcError> {
    let req_frame = read_bounded_frame(&mut stream, deadline).await?;
    let now_ms = current_epoch_ms();
    let guest_cid = peer.effective_guest_cid();
    let actor = format!("cid:{guest_cid}");

    let resp_frame = match req_frame.msg_type {
        MessageType::Heartbeat => {
            let _ = ledger.append(LedgerEventInput {
                timestamp_ms: now_ms,
                kind: "ipc.heartbeat",
                actor: &actor,
                summary: "heartbeat acknowledged",
            });
            WireFrame {
                msg_type: MessageType::Heartbeat,
                payload: b"PONG".to_vec(),
            }
        }
        MessageType::CommandRequest => {
            let verified_result =
                AttestedCommandEnvelope::from_bytes(&req_frame.payload).and_then(|env| {
                    let seq = env.sequence_no;
                    let payload = verifier
                        .verify_and_accept(&env, guest_cid, now_ms)?
                        .to_vec();
                    Ok((seq, payload))
                });
            match verified_result {
                Ok((seq, cmd_payload)) => {
                    let raw_cmd = String::from_utf8_lossy(&cmd_payload);
                    let clean_cmd = strip_hostile_metadata(&raw_cmd);
                    let summary = if clean_cmd.is_empty() {
                        format!("accepted attested command seq={seq}")
                    } else {
                        let truncated: String = clean_cmd.chars().take(64).collect();
                        format!("accepted attested command seq={seq} op={truncated}")
                    };
                    let _ = ledger.append(LedgerEventInput {
                        timestamp_ms: now_ms,
                        kind: "ipc.command.accepted",
                        actor: &actor,
                        summary: &summary,
                    });
                    WireFrame {
                        msg_type: MessageType::CommandResponse,
                        payload: b"OK".to_vec(),
                    }
                }
                Err(_) => {
                    let _ = ledger.append(LedgerEventInput {
                        timestamp_ms: now_ms,
                        kind: "ipc.command.rejected",
                        actor: &actor,
                        summary: "rejected unverified or replayed command envelope",
                    });
                    WireFrame {
                        msg_type: MessageType::ErrorResponse,
                        payload: b"DENIED".to_vec(),
                    }
                }
            }
        }
        _ => WireFrame {
            msg_type: MessageType::ErrorResponse,
            payload: b"UNEXPECTED_MESSAGE_TYPE".to_vec(),
        },
    };

    write_bounded_frame(&mut stream, &resp_frame, deadline).await
}

/// Ring 1 host credential broker coordinating `anvil-core`, `anvil-ipc`, and `locksmith-proxy`.
pub struct BrokerDaemon<H: HardwareUnwrapper> {
    config: DaemonRuntimeConfig,
    ledger: Arc<AuditLedger>,
    command_verifier: Arc<CommandVerifier>,
    policy_engine: Arc<PolicyEngine<H>>,
}

impl<H: HardwareUnwrapper + Send + Sync + 'static> BrokerDaemon<H> {
    /// Creates a new [`BrokerDaemon`] instance.
    #[must_use]
    pub fn new(
        config: DaemonRuntimeConfig,
        ledger: Arc<AuditLedger>,
        command_verifier: Arc<CommandVerifier>,
        policy_engine: Arc<PolicyEngine<H>>,
    ) -> Self {
        Self {
            config,
            ledger,
            command_verifier,
            policy_engine,
        }
    }

    /// Returns a reference to the append-only [`AuditLedger`].
    #[must_use]
    pub fn ledger(&self) -> &Arc<AuditLedger> {
        &self.ledger
    }

    /// Returns a reference to the [`PolicyEngine`].
    #[must_use]
    pub fn policy_engine(&self) -> &Arc<PolicyEngine<H>> {
        &self.policy_engine
    }

    /// Runs the authenticated IPC control loop until `shutdown_rx` signals `true`,
    /// draining all in-flight tasks cleanly and verifying ledger integrity on exit.
    pub async fn serve_until_shutdown(
        &self,
        mut shutdown_rx: watch::Receiver<bool>,
    ) -> Result<(), DaemonError> {
        let listener = UnixIpcListener::bind(
            &self.config.ipc_socket_path,
            IpcServerConfig {
                frame_read_deadline: self.config.frame_read_deadline,
                allowlist: self.config.peer_allowlist.clone(),
            },
        )?;

        self.ledger.append(LedgerEventInput {
            timestamp_ms: current_epoch_ms(),
            kind: "daemon.start",
            actor: "ring1:broker",
            summary: "bound SO_PEERCRED IPC control socket",
        })?;

        let mut in_flight = JoinSet::new();
        let deadline = self.config.frame_read_deadline;

        loop {
            if *shutdown_rx.borrow() {
                break;
            }

            tokio::select! {
                changed = shutdown_rx.changed() => {
                    if changed.is_err() || *shutdown_rx.borrow() {
                        break;
                    }
                }
                accepted = listener.accept_verified() => {
                    match accepted {
                        Ok((stream, peer)) => {
                            let verifier = Arc::clone(&self.command_verifier);
                            let ledger = Arc::clone(&self.ledger);
                            in_flight.spawn(async move {
                                let _ = handle_verified_ipc_connection(
                                    stream,
                                    peer,
                                    deadline,
                                    verifier,
                                    ledger,
                                ).await;
                            });
                        }
                        Err(IpcError::UnauthorizedPeer { .. }) => {
                            let _ = self.ledger.append(LedgerEventInput {
                                timestamp_ms: current_epoch_ms(),
                                kind: "ipc.peer.rejected",
                                actor: "ring1:broker",
                                summary: "dropped unauthorized Unix peer prior to frame read",
                            });
                        }
                        Err(_) => {}
                    }
                }
            }
        }

        // Drain in-flight connections cleanly within shutdown_drain_timeout
        let _ = tokio::time::timeout(self.config.shutdown_drain_timeout, async {
            while in_flight.join_next().await.is_some() {}
        })
        .await;
        in_flight.abort_all();

        let _ = std::fs::remove_file(&self.config.ipc_socket_path);

        self.ledger.append(LedgerEventInput {
            timestamp_ms: current_epoch_ms(),
            kind: "daemon.shutdown",
            actor: "ring1:broker",
            summary: "drained active sessions and removed IPC socket",
        })?;
        self.ledger.verify_all()?;

        Ok(())
    }
}

/// Awaits OS `SIGINT` or `SIGTERM` for graceful Ring 1 daemon shutdown.
pub async fn wait_for_os_shutdown_signal() -> Result<(), DaemonError> {
    #[cfg(unix)]
    {
        use tokio::signal::unix::{signal, SignalKind};
        let mut sigterm =
            signal(SignalKind::terminate()).map_err(|e| DaemonError::Io(e.to_string()))?;
        tokio::select! {
            res = tokio::signal::ctrl_c() => {
                res.map_err(|e| DaemonError::Io(e.to_string()))
            }
            _ = sigterm.recv() => Ok(())
        }
    }

    #[cfg(not(unix))]
    {
        tokio::signal::ctrl_c()
            .await
            .map_err(|e| DaemonError::Io(e.to_string()))
    }
}
