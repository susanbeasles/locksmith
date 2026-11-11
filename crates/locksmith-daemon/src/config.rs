use std::io::Read;
use std::path::Path;
use std::sync::Arc;

use anvil_core::unwrap::SealedSecretEnvelope;
use locksmith_proxy::{EgressRule, GuestAuthHeaderMode, WorkloadIdentity};
use rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer};
use rustls::server::WebPkiClientVerifier;
use rustls::{ClientConfig, RootCertStore, ServerConfig};
use zeroize::Zeroizing;

use crate::error::DaemonError;

/// Maximum policy configuration file size (`1 MiB`).
pub const MAX_POLICY_FILE_BYTES: usize = 1024 * 1024;

/// Optional TLS 1.3 mTLS server and upstream client configurations parsed from policy file.
pub struct LoadedMtlsPki {
    pub tls_server_config: Arc<ServerConfig>,
    pub upstream_tls_config: Arc<ClientConfig>,
}

/// Validated workloads, peer allowlist extensions, and mTLS PKI loaded from disk.
pub struct LoadedPolicyBundle {
    pub workloads: Vec<WorkloadIdentity>,
    pub vsock_cids: Vec<u32>,
    pub unix_uid_mappings: Vec<(u32, u32)>,
    pub mtls_pki: Option<LoadedMtlsPki>,
}

#[derive(Default)]
struct RawMtlsStanza {
    seen: bool,
    server_cert_der: Option<Vec<u8>>,
    server_key_pkcs8_der: Option<Zeroizing<Vec<u8>>>,
    client_ca_certs_der: Vec<Vec<u8>>,
    upstream_ca_certs_der: Vec<Vec<u8>>,
}

struct PendingWorkload {
    workload_id: Option<String>,
    guest_cid: Option<u32>,
    cert_thumbprint_sha256: Option<[u8; 32]>,
    rules: Vec<EgressRule>,
}

#[derive(Default)]
struct PendingRule {
    sni_hostname: Option<String>,
    port: Option<u16>,
    allowed_methods: Vec<String>,
    path_prefix: Option<String>,
    secret_id: Option<String>,
    sealed_envelope: Option<SealedSecretEnvelope>,
    injection_header_name: Option<String>,
    injection_value_prefix: Option<String>,
    guest_auth_mode: Option<GuestAuthHeaderMode>,
}

impl PendingRule {
    fn into_rule(self) -> Result<EgressRule, DaemonError> {
        let allowed_methods = if self.allowed_methods.is_empty() {
            return Err(DaemonError::InvalidCliUsage {
                reason: "policy [[rule]] missing allowed_methods",
            });
        } else {
            self.allowed_methods
        };
        Ok(EgressRule {
            sni_hostname: self.sni_hostname.ok_or(DaemonError::InvalidCliUsage {
                reason: "policy [[rule]] missing sni_hostname",
            })?,
            port: self.port.ok_or(DaemonError::InvalidCliUsage {
                reason: "policy [[rule]] missing port",
            })?,
            allowed_methods,
            path_prefix: self.path_prefix.ok_or(DaemonError::InvalidCliUsage {
                reason: "policy [[rule]] missing path_prefix",
            })?,
            secret_id: self.secret_id.ok_or(DaemonError::InvalidCliUsage {
                reason: "policy [[rule]] missing secret_id",
            })?,
            sealed_envelope: self.sealed_envelope.ok_or(DaemonError::InvalidCliUsage {
                reason: "policy [[rule]] missing sealed_envelope_hex",
            })?,
            injection_header_name: self.injection_header_name.ok_or(
                DaemonError::InvalidCliUsage {
                    reason: "policy [[rule]] missing injection_header_name",
                },
            )?,
            injection_value_prefix: self.injection_value_prefix.unwrap_or_default(),
            guest_auth_mode: self.guest_auth_mode.ok_or(DaemonError::InvalidCliUsage {
                reason: "policy [[rule]] missing guest_auth_mode ('reject' or 'strip')",
            })?,
        })
    }
}

impl PendingWorkload {
    fn into_workload(self) -> Result<WorkloadIdentity, DaemonError> {
        let guest_cid = self.guest_cid.ok_or(DaemonError::InvalidCliUsage {
            reason: "policy [[workload]] missing guest_cid",
        })?;
        if !(anvil_ipc::transport::MIN_GUEST_VSOCK_CID..=anvil_ipc::transport::MAX_GUEST_VSOCK_CID)
            .contains(&guest_cid)
        {
            return Err(DaemonError::InvalidCliUsage {
                reason: "policy [[workload]] guest_cid is in reserved range",
            });
        }
        Ok(WorkloadIdentity {
            workload_id: self.workload_id.ok_or(DaemonError::InvalidCliUsage {
                reason: "policy [[workload]] missing workload_id",
            })?,
            guest_cid,
            cert_thumbprint_sha256: self.cert_thumbprint_sha256.ok_or(
                DaemonError::InvalidCliUsage {
                    reason: "policy [[workload]] missing cert_thumbprint_sha256",
                },
            )?,
            rules: self.rules,
        })
    }
}

const fn decode_hex_nibble(b: u8) -> Option<u8> {
    match b {
        b'0'..=b'9' => Some(b - b'0'),
        b'a'..=b'f' => Some(b - b'a' + 10),
        b'A'..=b'F' => Some(b - b'A' + 10),
        _ => None,
    }
}

fn decode_hex_vec(hex_str: &str) -> Result<Vec<u8>, DaemonError> {
    let trimmed = hex_str.trim();
    if trimmed.is_empty() || trimmed.len() % 2 != 0 {
        return Err(DaemonError::InvalidCliUsage {
            reason: "invalid hex field length in policy file",
        });
    }
    let mut out = Vec::with_capacity(trimmed.len() / 2);
    let bytes = trimmed.as_bytes();
    let mut i = 0usize;
    while i < bytes.len() {
        let hi = decode_hex_nibble(bytes[i]).ok_or(DaemonError::InvalidCliUsage {
            reason: "non-hex character in policy file",
        })?;
        let lo = decode_hex_nibble(bytes[i + 1]).ok_or(DaemonError::InvalidCliUsage {
            reason: "non-hex character in policy file",
        })?;
        out.push((hi << 4) | lo);
        i += 2;
    }
    Ok(out)
}

fn decode_hex_32(hex_str: &str) -> Result<[u8; 32], DaemonError> {
    let raw = decode_hex_vec(hex_str)?;
    if raw.len() != 32 {
        return Err(DaemonError::InvalidCliUsage {
            reason: "expected exact 32-byte (64-hex) digest in policy file",
        });
    }
    let mut arr = [0u8; 32];
    arr.copy_from_slice(&raw);
    Ok(arr)
}

fn unquote_policy_value(raw: &str) -> Result<String, DaemonError> {
    let trimmed = raw.trim();
    if trimmed.len() >= 2 && trimmed.starts_with('"') && trimmed.ends_with('"') {
        Ok(trimmed[1..trimmed.len() - 1].to_owned())
    } else if trimmed.starts_with('"') || trimmed.ends_with('"') {
        Err(DaemonError::InvalidCliUsage {
            reason: "unterminated quoted string in policy file",
        })
    } else {
        Ok(trimmed.to_owned())
    }
}

fn read_confined_policy_text(path: &Path) -> Result<Zeroizing<String>, DaemonError> {
    #[cfg(target_os = "linux")]
    let file = {
        use rustix::fs::{fstat, openat, FileType, Mode, OFlags, CWD};
        let fd = openat(
            CWD,
            path,
            OFlags::RDONLY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
            Mode::empty(),
        )
        .map_err(|_| DaemonError::Io("failed to open policy file with O_NOFOLLOW".to_owned()))?;
        let st = fstat(&fd)
            .map_err(|_| DaemonError::Io("failed to stat policy file descriptor".to_owned()))?;
        if FileType::from_raw_mode(st.st_mode) != FileType::RegularFile {
            return Err(DaemonError::Io(
                "policy file must be a regular file (not a symlink, socket, or FIFO)".to_owned(),
            ));
        }
        if (st.st_mode & 0o002) != 0 {
            return Err(DaemonError::Io(
                "refusing to load world-writable policy file".to_owned(),
            ));
        }
        let size = u64::try_from(st.st_size)
            .map_err(|_| DaemonError::Io("invalid policy file size".to_owned()))?;
        if size > MAX_POLICY_FILE_BYTES as u64 {
            return Err(DaemonError::Io(
                "policy file exceeds 1 MiB hard cap".to_owned(),
            ));
        }
        std::fs::File::from(fd)
    };

    #[cfg(not(target_os = "linux"))]
    let file = {
        let meta = std::fs::symlink_metadata(path)
            .map_err(|_| DaemonError::Io("failed to stat policy file".to_owned()))?;
        if !meta.file_type().is_file() {
            return Err(DaemonError::Io(
                "policy file must be a regular file".to_owned(),
            ));
        }
        if meta.len() > MAX_POLICY_FILE_BYTES as u64 {
            return Err(DaemonError::Io(
                "policy file exceeds 1 MiB hard cap".to_owned(),
            ));
        }
        std::fs::File::open(path)
            .map_err(|_| DaemonError::Io("failed to open policy file".to_owned()))?
    };

    let mut raw = Zeroizing::new(Vec::new());
    file.take((MAX_POLICY_FILE_BYTES + 1) as u64)
        .read_to_end(&mut raw)
        .map_err(|_| DaemonError::Io("failed reading policy file".to_owned()))?;
    if raw.len() > MAX_POLICY_FILE_BYTES {
        return Err(DaemonError::Io(
            "policy file exceeds 1 MiB hard cap".to_owned(),
        ));
    }
    let s = std::str::from_utf8(&raw)
        .map_err(|_| DaemonError::Io("policy file is not valid UTF-8".to_owned()))?
        .to_owned();
    Ok(Zeroizing::new(s))
}

fn build_mtls_pki(raw: RawMtlsStanza) -> Result<Option<LoadedMtlsPki>, DaemonError> {
    if !raw.seen {
        return Ok(None);
    }
    let server_cert = raw.server_cert_der.ok_or(DaemonError::InvalidCliUsage {
        reason: "[mtls] stanza missing server_cert_der_hex",
    })?;
    let mut server_key = raw
        .server_key_pkcs8_der
        .ok_or(DaemonError::InvalidCliUsage {
            reason: "[mtls] stanza missing server_key_pkcs8_der_hex",
        })?;
    if raw.client_ca_certs_der.is_empty() {
        return Err(DaemonError::InvalidCliUsage {
            reason: "[mtls] stanza requires at least one client_ca_cert_der_hex",
        });
    }
    if raw.upstream_ca_certs_der.is_empty() {
        return Err(DaemonError::InvalidCliUsage {
            reason: "[mtls] stanza requires at least one upstream_ca_cert_der_hex",
        });
    }

    let provider = Arc::new(rustls::crypto::aws_lc_rs::default_provider());

    let mut mesh_roots = RootCertStore::empty();
    for ca in raw.client_ca_certs_der {
        mesh_roots
            .add(CertificateDer::from(ca))
            .map_err(|_| DaemonError::Io("invalid client CA DER in [mtls]".to_owned()))?;
    }
    let client_verifier =
        WebPkiClientVerifier::builder_with_provider(Arc::new(mesh_roots), Arc::clone(&provider))
            .build()
            .map_err(|_| DaemonError::Io("failed building mTLS client verifier".to_owned()))?;

    let key_vec = std::mem::take(&mut *server_key);
    let tls_server_config = Arc::new(
        ServerConfig::builder_with_provider(Arc::clone(&provider))
            .with_protocol_versions(&[&rustls::version::TLS13])
            .map_err(|_| DaemonError::Io("failed locking TLS 1.3 on ServerConfig".to_owned()))?
            .with_client_cert_verifier(client_verifier)
            .with_single_cert(
                vec![CertificateDer::from(server_cert)],
                PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(key_vec)),
            )
            .map_err(|_| DaemonError::Io("invalid server cert/key in [mtls]".to_owned()))?,
    );

    let mut upstream_roots = RootCertStore::empty();
    for ca in raw.upstream_ca_certs_der {
        upstream_roots
            .add(CertificateDer::from(ca))
            .map_err(|_| DaemonError::Io("invalid upstream CA DER in [mtls]".to_owned()))?;
    }
    let upstream_tls_config = Arc::new(
        ClientConfig::builder_with_provider(provider)
            .with_protocol_versions(&[&rustls::version::TLS13])
            .map_err(|_| DaemonError::Io("failed locking TLS 1.3 on ClientConfig".to_owned()))?
            .with_root_certificates(upstream_roots)
            .with_no_client_auth(),
    );

    Ok(Some(LoadedMtlsPki {
        tls_server_config,
        upstream_tls_config,
    }))
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum Section {
    Root,
    Mtls,
    Workload,
    Rule,
}

/// Parses a declarative policy configuration text into a [`LoadedPolicyBundle`].
pub fn parse_policy_str(content: &str) -> Result<LoadedPolicyBundle, DaemonError> {
    let mut section = Section::Root;
    let mut vsock_cids = Vec::new();
    let mut unix_uid_mappings = Vec::new();
    let mut mtls = RawMtlsStanza::default();
    let mut workloads: Vec<WorkloadIdentity> = Vec::new();
    let mut cur_workload: Option<PendingWorkload> = None;
    let mut cur_rule: Option<PendingRule> = None;

    let flush_rule = |cur_r: &mut Option<PendingRule>,
                      cur_w: &mut Option<PendingWorkload>|
     -> Result<(), DaemonError> {
        if let Some(pending_r) = cur_r.take() {
            let built_r = pending_r.into_rule()?;
            let wl = cur_w.as_mut().ok_or(DaemonError::InvalidCliUsage {
                reason: "[[rule]] must appear after a [[workload]] stanza",
            })?;
            wl.rules.push(built_r);
        }
        Ok(())
    };

    for raw_line in content.lines() {
        let trimmed = raw_line.trim();
        if trimmed.is_empty() || trimmed.starts_with('#') {
            continue;
        }
        match trimmed {
            "[mtls]" => {
                flush_rule(&mut cur_rule, &mut cur_workload)?;
                if let Some(wl) = cur_workload.take() {
                    workloads.push(wl.into_workload()?);
                }
                mtls.seen = true;
                section = Section::Mtls;
                continue;
            }
            "[[workload]]" => {
                flush_rule(&mut cur_rule, &mut cur_workload)?;
                if let Some(wl) = cur_workload.take() {
                    workloads.push(wl.into_workload()?);
                }
                cur_workload = Some(PendingWorkload {
                    workload_id: None,
                    guest_cid: None,
                    cert_thumbprint_sha256: None,
                    rules: Vec::new(),
                });
                section = Section::Workload;
                continue;
            }
            "[[rule]]" => {
                flush_rule(&mut cur_rule, &mut cur_workload)?;
                if cur_workload.is_none() {
                    return Err(DaemonError::InvalidCliUsage {
                        reason: "[[rule]] must appear after a [[workload]] stanza",
                    });
                }
                cur_rule = Some(PendingRule::default());
                section = Section::Rule;
                continue;
            }
            _ => {}
        }

        let (raw_k, raw_v) = trimmed
            .split_once('=')
            .ok_or(DaemonError::InvalidCliUsage {
                reason: "policy line missing '=' delimiter",
            })?;
        let key = raw_k.trim();
        let val = unquote_policy_value(raw_v)?;

        match section {
            Section::Root => match key {
                "allow_vsock_cid" => {
                    let cid = val
                        .parse::<u32>()
                        .map_err(|_| DaemonError::InvalidCliUsage {
                            reason: "invalid integer for allow_vsock_cid",
                        })?;
                    if !(anvil_ipc::transport::MIN_GUEST_VSOCK_CID
                        ..=anvil_ipc::transport::MAX_GUEST_VSOCK_CID)
                        .contains(&cid)
                    {
                        return Err(DaemonError::InvalidCliUsage {
                            reason: "allow_vsock_cid in reserved range",
                        });
                    }
                    vsock_cids.push(cid);
                }
                "allow_unix_uid" => {
                    let (u_s, c_s) = val.split_once(':').ok_or(DaemonError::InvalidCliUsage {
                        reason: "allow_unix_uid must have format '<uid>:<guest_cid>'",
                    })?;
                    let uid =
                        u_s.trim()
                            .parse::<u32>()
                            .map_err(|_| DaemonError::InvalidCliUsage {
                                reason: "invalid uid in allow_unix_uid",
                            })?;
                    let cid =
                        c_s.trim()
                            .parse::<u32>()
                            .map_err(|_| DaemonError::InvalidCliUsage {
                                reason: "invalid guest_cid in allow_unix_uid",
                            })?;
                    if !(anvil_ipc::transport::MIN_GUEST_VSOCK_CID
                        ..=anvil_ipc::transport::MAX_GUEST_VSOCK_CID)
                        .contains(&cid)
                    {
                        return Err(DaemonError::InvalidCliUsage {
                            reason: "allow_unix_uid guest_cid in reserved range",
                        });
                    }
                    unix_uid_mappings.push((uid, cid));
                }
                _ => {
                    return Err(DaemonError::InvalidCliUsage {
                        reason: "unrecognized root policy key",
                    });
                }
            },
            Section::Mtls => match key {
                "server_cert_der_hex" => mtls.server_cert_der = Some(decode_hex_vec(&val)?),
                "server_key_pkcs8_der_hex" => {
                    let mut raw_hex = Zeroizing::new(val);
                    let decoded = Zeroizing::new(decode_hex_vec(&raw_hex)?);
                    raw_hex.clear();
                    mtls.server_key_pkcs8_der = Some(decoded);
                }
                "client_ca_cert_der_hex" => mtls.client_ca_certs_der.push(decode_hex_vec(&val)?),
                "upstream_ca_cert_der_hex" => {
                    mtls.upstream_ca_certs_der.push(decode_hex_vec(&val)?);
                }
                _ => {
                    return Err(DaemonError::InvalidCliUsage {
                        reason: "unrecognized [mtls] policy key",
                    });
                }
            },
            Section::Workload => {
                let wl = cur_workload.as_mut().ok_or(DaemonError::InvalidCliUsage {
                    reason: "missing active [[workload]] stanza",
                })?;
                match key {
                    "workload_id" => wl.workload_id = Some(val),
                    "guest_cid" => {
                        wl.guest_cid =
                            Some(
                                val.parse::<u32>()
                                    .map_err(|_| DaemonError::InvalidCliUsage {
                                        reason: "invalid guest_cid integer",
                                    })?,
                            );
                    }
                    "cert_thumbprint_sha256" => {
                        wl.cert_thumbprint_sha256 = Some(decode_hex_32(&val)?);
                    }
                    _ => {
                        return Err(DaemonError::InvalidCliUsage {
                            reason: "unrecognized [[workload]] policy key",
                        });
                    }
                }
            }
            Section::Rule => {
                let rule = cur_rule.as_mut().ok_or(DaemonError::InvalidCliUsage {
                    reason: "missing active [[rule]] stanza",
                })?;
                match key {
                    "sni_hostname" => rule.sni_hostname = Some(val),
                    "port" => {
                        rule.port =
                            Some(
                                val.parse::<u16>()
                                    .map_err(|_| DaemonError::InvalidCliUsage {
                                        reason: "invalid port integer in [[rule]]",
                                    })?,
                            );
                    }
                    "allowed_methods" => {
                        rule.allowed_methods = val
                            .split(',')
                            .map(|m| m.trim().to_owned())
                            .filter(|m| !m.is_empty())
                            .collect();
                    }
                    "path_prefix" => rule.path_prefix = Some(val),
                    "secret_id" => rule.secret_id = Some(val),
                    "sealed_envelope_hex" => {
                        let raw_env = decode_hex_vec(&val)?;
                        rule.sealed_envelope = Some(SealedSecretEnvelope::from_bytes(&raw_env)?);
                    }
                    "injection_header_name" => rule.injection_header_name = Some(val),
                    "injection_value_prefix" => rule.injection_value_prefix = Some(val),
                    "guest_auth_mode" => {
                        rule.guest_auth_mode = match val.to_ascii_lowercase().as_str() {
                            "reject" => Some(GuestAuthHeaderMode::Reject),
                            "strip" => Some(GuestAuthHeaderMode::Strip),
                            _ => {
                                return Err(DaemonError::InvalidCliUsage {
                                    reason: "guest_auth_mode must be 'reject' or 'strip'",
                                });
                            }
                        };
                    }
                    _ => {
                        return Err(DaemonError::InvalidCliUsage {
                            reason: "unrecognized [[rule]] policy key",
                        });
                    }
                }
            }
        }
    }

    flush_rule(&mut cur_rule, &mut cur_workload)?;
    if let Some(wl) = cur_workload.take() {
        workloads.push(wl.into_workload()?);
    }

    Ok(LoadedPolicyBundle {
        workloads,
        vsock_cids,
        unix_uid_mappings,
        mtls_pki: build_mtls_pki(mtls)?,
    })
}

/// Loads and validates a policy configuration file from `path` using confined
/// `O_NOFOLLOW` regular-file verification (`<= 1 MiB`, non-world-writable).
pub fn load_policy_file(path: &Path) -> Result<LoadedPolicyBundle, DaemonError> {
    let text = read_confined_policy_text(path)?;
    parse_policy_str(&text)
}
