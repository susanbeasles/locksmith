use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;

use anvil_cache::sanitize::strip_hostile_metadata;
use anvil_core::ledger::{AuditLedger, LedgerEventInput};
use anvil_core::unwrap::HardwareUnwrapper;
use anvil_ipc::frame::{read_bounded_frame, write_bounded_frame, MessageType, WireFrame};
#[cfg(target_os = "linux")]
use anvil_ipc::VsockIpcListener;
use anvil_ipc::{
    AttestedCommandEnvelope, CommandVerifier, IpcError, IpcServerConfig, PeerAllowlist,
    UnixIpcListener, VerifiedPeerIdentity,
};
use locksmith_proxy::{
    handle_mtls_guest_connection, MtlsProxySession, PolicyEngine, SystemDnsResolver,
    UpstreamResolver,
};
use tokio::io::{AsyncRead, AsyncWrite};
use tokio::sync::{watch, Semaphore};
use tokio::task::JoinSet;

use crate::cli::DEFAULT_MAX_CONCURRENT_CONNECTIONS;
use crate::error::DaemonError;

/// Host CID constant (`VMADDR_CID_ANY` = `0xFFFF_FFFF`) used when binding host `AF_VSOCK` listeners.
#[cfg(target_os = "linux")]
const VMADDR_CID_ANY: u32 = u32::MAX;

/// Configuration for the Ring 1 `BrokerDaemon` control-plane and egress splice loop.
#[derive(Clone, Debug)]
pub struct DaemonRuntimeConfig {
    pub ipc_socket_path: PathBuf,
    pub frame_read_deadline: Duration,
    pub shutdown_drain_timeout: Duration,
    pub peer_allowlist: PeerAllowlist,
    pub max_concurrent_connections: usize,
    pub vsock_listen_port: Option<u32>,
}

impl DaemonRuntimeConfig {
    /// Creates a [`DaemonRuntimeConfig`] with conservative production defaults.
    #[must_use]
    pub fn new(ipc_socket_path: PathBuf, peer_allowlist: PeerAllowlist) -> Self {
        Self {
            ipc_socket_path,
            frame_read_deadline: Duration::from_secs(5),
            shutdown_drain_timeout: Duration::from_secs(5),
            peer_allowlist,
            max_concurrent_connections: DEFAULT_MAX_CONCURRENT_CONNECTIONS,
            vsock_listen_port: None,
        }
    }
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

struct IpcConnectionContext<H: HardwareUnwrapper, R: UpstreamResolver> {
    deadline: Duration,
    verifier: Arc<CommandVerifier>,
    ledger: Arc<AuditLedger>,
    policy_engine: Arc<PolicyEngine<H>>,
    mtls_session: Option<Arc<MtlsProxySession<H, R>>>,
}

impl<H: HardwareUnwrapper, R: UpstreamResolver> Clone for IpcConnectionContext<H, R> {
    fn clone(&self) -> Self {
        Self {
            deadline: self.deadline,
            verifier: Arc::clone(&self.verifier),
            ledger: Arc::clone(&self.ledger),
            policy_engine: Arc::clone(&self.policy_engine),
            mtls_session: self.mtls_session.as_ref().map(Arc::clone),
        }
    }
}

async fn handle_verified_ipc_stream<S, H, R>(
    mut stream: S,
    peer: VerifiedPeerIdentity,
    ctx: IpcConnectionContext<H, R>,
) -> Result<(), IpcError>
where
    S: AsyncRead + AsyncWrite + Unpin,
    H: HardwareUnwrapper + 'static,
    R: UpstreamResolver + 'static,
{
    let req_frame = read_bounded_frame(&mut stream, ctx.deadline).await?;
    let now_ms = ctx.verifier.monotonic_now_ms();
    let guest_cid = peer.effective_guest_cid();
    let actor = format!("cid:{guest_cid}");

    match req_frame.msg_type {
        MessageType::Heartbeat => {
            let _ = ctx.ledger.append(LedgerEventInput {
                timestamp_ms: now_ms,
                kind: "ipc.heartbeat",
                actor: &actor,
                summary: "heartbeat acknowledged",
            });
            let resp = WireFrame {
                msg_type: MessageType::Heartbeat,
                payload: b"PONG".to_vec(),
            };
            write_bounded_frame(&mut stream, &resp, ctx.deadline).await
        }
        MessageType::CommandRequest => {
            let verified_result =
                AttestedCommandEnvelope::from_bytes(&req_frame.payload).and_then(|env| {
                    let seq = env.sequence_no;
                    let payload = ctx
                        .verifier
                        .verify_and_accept(&env, guest_cid, now_ms)?
                        .to_vec();
                    Ok((seq, payload))
                });
            let resp = match verified_result {
                Ok((seq, cmd_payload)) => {
                    let raw_cmd = String::from_utf8_lossy(&cmd_payload);
                    let clean_cmd = strip_hostile_metadata(&raw_cmd);
                    let trimmed_op = clean_cmd.trim();
                    let response_payload = match trimmed_op {
                        "AUDIT_HEAD" => {
                            let total = ctx.ledger.total_committed().unwrap_or(0);
                            let head = ctx
                                .ledger
                                .head_hash()
                                .map(|h| hex_encode_32(&h))
                                .unwrap_or_else(|_| "unavailable".to_owned());
                            format!("HEAD seq={total} hash={head}").into_bytes()
                        }
                        "WORKLOAD_COUNT" => {
                            format!("WORKLOADS={}", ctx.policy_engine.workload_count()).into_bytes()
                        }
                        _ => b"OK".to_vec(),
                    };
                    let summary = if trimmed_op.is_empty() {
                        format!("accepted attested command seq={seq}")
                    } else {
                        let truncated: String = trimmed_op.chars().take(64).collect();
                        format!("accepted attested command seq={seq} op={truncated}")
                    };
                    let _ = ctx.ledger.append(LedgerEventInput {
                        timestamp_ms: now_ms,
                        kind: "ipc.command.accepted",
                        actor: &actor,
                        summary: &summary,
                    });
                    WireFrame {
                        msg_type: MessageType::CommandResponse,
                        payload: response_payload,
                    }
                }
                Err(_) => {
                    let _ = ctx.ledger.append(LedgerEventInput {
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
            };
            write_bounded_frame(&mut stream, &resp, ctx.deadline).await
        }
        MessageType::EgressProxyFrame => {
            let Some(session) = ctx.mtls_session else {
                let _ = ctx.ledger.append(LedgerEventInput {
                    timestamp_ms: now_ms,
                    kind: "proxy.egress.unconfigured",
                    actor: &actor,
                    summary: "denied egress frame because mTLS proxy session is unconfigured",
                });
                let resp = WireFrame {
                    msg_type: MessageType::ErrorResponse,
                    payload: b"EGRESS_PROXY_UNCONFIGURED".to_vec(),
                };
                return write_bounded_frame(&mut stream, &resp, ctx.deadline).await;
            };

            let ready = WireFrame {
                msg_type: MessageType::EgressProxyFrame,
                payload: b"READY".to_vec(),
            };
            write_bounded_frame(&mut stream, &ready, ctx.deadline).await?;

            match handle_mtls_guest_connection(&mut stream, guest_cid, &session, now_ms).await {
                Ok(sanitized) => {
                    let summary = format!(
                        "completed egress splice status={} bytes={}",
                        sanitized.status_code,
                        sanitized.body.len()
                    );
                    let _ = ctx.ledger.append(LedgerEventInput {
                        timestamp_ms: ctx.verifier.monotonic_now_ms(),
                        kind: "proxy.egress.completed",
                        actor: &actor,
                        summary: &summary,
                    });
                }
                Err(_) => {
                    let _ = ctx.ledger.append(LedgerEventInput {
                        timestamp_ms: ctx.verifier.monotonic_now_ms(),
                        kind: "proxy.egress.denied",
                        actor: &actor,
                        summary: "rejected or aborted mTLS egress splice",
                    });
                }
            }
            Ok(())
        }
        _ => {
            let resp = WireFrame {
                msg_type: MessageType::ErrorResponse,
                payload: b"UNEXPECTED_MESSAGE_TYPE".to_vec(),
            };
            write_bounded_frame(&mut stream, &resp, ctx.deadline).await
        }
    }
}

/// Ring 1 host credential broker coordinating `anvil-core`, `anvil-ipc`, and `locksmith-proxy`.
pub struct BrokerDaemon<H: HardwareUnwrapper, R: UpstreamResolver = SystemDnsResolver> {
    config: DaemonRuntimeConfig,
    ledger: Arc<AuditLedger>,
    command_verifier: Arc<CommandVerifier>,
    policy_engine: Arc<PolicyEngine<H>>,
    mtls_session: Option<Arc<MtlsProxySession<H, R>>>,
}

impl<H: HardwareUnwrapper + Send + Sync + 'static> BrokerDaemon<H, SystemDnsResolver> {
    /// Creates a new [`BrokerDaemon`] instance without an attached mTLS proxy session.
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
            mtls_session: None,
        }
    }
}

impl<H, R> BrokerDaemon<H, R>
where
    H: HardwareUnwrapper + Send + Sync + 'static,
    R: UpstreamResolver + 'static,
{
    /// Creates a [`BrokerDaemon`] with an active [`MtlsProxySession`] handling
    /// [`MessageType::EgressProxyFrame`] streams.
    #[must_use]
    pub fn with_mtls_session(
        config: DaemonRuntimeConfig,
        ledger: Arc<AuditLedger>,
        command_verifier: Arc<CommandVerifier>,
        policy_engine: Arc<PolicyEngine<H>>,
        mtls_session: Arc<MtlsProxySession<H, R>>,
    ) -> Self {
        Self {
            config,
            ledger,
            command_verifier,
            policy_engine,
            mtls_session: Some(mtls_session),
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

    /// Runs the authenticated IPC control and egress proxy loop until `shutdown_rx`
    /// signals `true`, enforcing a hard semaphore concurrency cap, reaping completed
    /// tasks continuously, and verifying ledger integrity on exit.
    pub async fn serve_until_shutdown(
        &self,
        mut shutdown_rx: watch::Receiver<bool>,
    ) -> Result<(), DaemonError> {
        let ipc_cfg = IpcServerConfig {
            frame_read_deadline: self.config.frame_read_deadline,
            allowlist: self.config.peer_allowlist.clone(),
        };
        let unix_listener = UnixIpcListener::bind(&self.config.ipc_socket_path, ipc_cfg.clone())?;

        #[cfg(target_os = "linux")]
        let vsock_listener = match self.config.vsock_listen_port {
            Some(port) => Some(VsockIpcListener::bind(VMADDR_CID_ANY, port, ipc_cfg)?),
            None => None,
        };

        self.ledger.append(LedgerEventInput {
            timestamp_ms: self.command_verifier.monotonic_now_ms(),
            kind: "daemon.start",
            actor: "ring1:broker",
            summary: "bound authenticated IPC control socket",
        })?;

        let max_conns = self.config.max_concurrent_connections.max(1);
        let conn_semaphore = Arc::new(Semaphore::new(max_conns));
        let mut in_flight: JoinSet<()> = JoinSet::new();
        let base_ctx = IpcConnectionContext {
            deadline: self.config.frame_read_deadline,
            verifier: Arc::clone(&self.command_verifier),
            ledger: Arc::clone(&self.ledger),
            policy_engine: Arc::clone(&self.policy_engine),
            mtls_session: self.mtls_session.as_ref().map(Arc::clone),
        };

        loop {
            if *shutdown_rx.borrow() {
                break;
            }

            #[cfg(target_os = "linux")]
            tokio::select! {
                changed = shutdown_rx.changed() => {
                    if changed.is_err() || *shutdown_rx.borrow() {
                        break;
                    }
                }
                Some(_) = in_flight.join_next(), if !in_flight.is_empty() => {}
                accepted = unix_listener.accept_verified() => {
                    match accepted {
                        Ok((stream, peer)) => {
                            if let Ok(permit) = Arc::clone(&conn_semaphore).try_acquire_owned() {
                                let ctx = base_ctx.clone();
                                in_flight.spawn(async move {
                                    let _permit = permit;
                                    let _ = handle_verified_ipc_stream(stream, peer, ctx).await;
                                });
                            } else {
                                drop(stream);
                                let _ = self.ledger.append(LedgerEventInput {
                                    timestamp_ms: self.command_verifier.monotonic_now_ms(),
                                    kind: "ipc.connection.shed",
                                    actor: "ring1:broker",
                                    summary: "shed excess Unix IPC connection at max concurrency cap",
                                });
                            }
                        }
                        Err(IpcError::UnauthorizedPeer { .. }) => {
                            let _ = self.ledger.append(LedgerEventInput {
                                timestamp_ms: self.command_verifier.monotonic_now_ms(),
                                kind: "ipc.peer.rejected",
                                actor: "ring1:broker",
                                summary: "dropped unauthorized Unix peer prior to frame read",
                            });
                        }
                        Err(_) => {}
                    }
                }
                vsock_accepted = async {
                    match &vsock_listener {
                        Some(vl) => vl.accept_verified().await,
                        None => std::future::pending().await,
                    }
                } => {
                    match vsock_accepted {
                        Ok((stream, peer)) => {
                            if let Ok(permit) = Arc::clone(&conn_semaphore).try_acquire_owned() {
                                let ctx = base_ctx.clone();
                                in_flight.spawn(async move {
                                    let _permit = permit;
                                    let _ = handle_verified_ipc_stream(stream, peer, ctx).await;
                                });
                            } else {
                                drop(stream);
                                let _ = self.ledger.append(LedgerEventInput {
                                    timestamp_ms: self.command_verifier.monotonic_now_ms(),
                                    kind: "ipc.connection.shed",
                                    actor: "ring1:broker",
                                    summary: "shed excess AF_VSOCK connection at max concurrency cap",
                                });
                            }
                        }
                        Err(IpcError::UnauthorizedPeer { .. }) => {
                            let _ = self.ledger.append(LedgerEventInput {
                                timestamp_ms: self.command_verifier.monotonic_now_ms(),
                                kind: "ipc.peer.rejected",
                                actor: "ring1:broker",
                                summary: "dropped unauthorized AF_VSOCK peer prior to frame read",
                            });
                        }
                        Err(_) => {}
                    }
                }
            }

            #[cfg(not(target_os = "linux"))]
            tokio::select! {
                changed = shutdown_rx.changed() => {
                    if changed.is_err() || *shutdown_rx.borrow() {
                        break;
                    }
                }
                Some(_) = in_flight.join_next(), if !in_flight.is_empty() => {}
                accepted = unix_listener.accept_verified() => {
                    match accepted {
                        Ok((stream, peer)) => {
                            if let Ok(permit) = Arc::clone(&conn_semaphore).try_acquire_owned() {
                                let ctx = base_ctx.clone();
                                in_flight.spawn(async move {
                                    let _permit = permit;
                                    let _ = handle_verified_ipc_stream(stream, peer, ctx).await;
                                });
                            } else {
                                drop(stream);
                            }
                        }
                        Err(IpcError::UnauthorizedPeer { .. }) => {
                            let _ = self.ledger.append(LedgerEventInput {
                                timestamp_ms: self.command_verifier.monotonic_now_ms(),
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
            timestamp_ms: self.command_verifier.monotonic_now_ms(),
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
