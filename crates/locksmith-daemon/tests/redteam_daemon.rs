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

    // 4. Secret token value smuggled inside an innocuous-looking env variable name (value inspection)
    let canary_ghp = "ghp_SmuggledPersonalAccessTokenValue987654321";
    let out_val = Command::new(bin)
        .env_clear()
        .env("GENERIC_CONFIG_BLOB", canary_ghp)
        .arg("verify-self")
        .output()
        .unwrap();
    assert!(
        !out_val.status.success(),
        "env value containing ghp_ token must be rejected even under an innocuous env var name"
    );
    let combined_val = format!(
        "{}{}",
        String::from_utf8_lossy(&out_val.stdout),
        String::from_utf8_lossy(&out_val.stderr)
    );
    assert!(!combined_val.contains(canary_ghp));
    assert!(combined_val.contains("ambient secret hygiene violation"));

    // 5. GH_TOKEN / STRIPE_SECRET_KEY name patterns + PEM / JWT values in innocuous env vars rejected
    let pem_canary = "-----BEGIN PRIVATE KEY-----\nMIIEvQIBADANBgkqhkiG9w0BAQEFAASCBKcw";
    let jwt_canary = "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.c2lnbmF0dXJlX2NhbmFyeQ";
    for (env_name, env_val) in [
        ("GH_TOKEN", "opaque-ci-token-value"),
        ("MY_CUSTOM_API_KEY", "opaque-custom-key"),
        ("DB_PASSWORD", "opaque-db-pass"),
        ("INNOCUOUS_BLOB_A", pem_canary),
        ("INNOCUOUS_BLOB_B", jwt_canary),
    ] {
        let out = Command::new(bin)
            .env_clear()
            .env(env_name, env_val)
            .arg("verify-self")
            .output()
            .unwrap();
        assert!(
            !out.status.success(),
            "forbidden env var/value ({env_name}) must fail closed"
        );
        let combined = format!(
            "{}{}",
            String::from_utf8_lossy(&out.stdout),
            String::from_utf8_lossy(&out.stderr)
        );
        assert!(
            !combined.contains(env_val),
            "daemon error output must never echo secret env value for {env_name}"
        );
    }
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

    // Exercise BrokerDaemon attested IPC dispatch + concurrency cap shedding + clean shutdown
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
            max_concurrent_connections: 1,
            vsock_listen_port: None,
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

    // Hold sole concurrency slot with client_1 while opening excess client_2 -> must shed client_2
    let mut client_1 = UnixStream::connect(&ipc_sock).await.unwrap();
    tokio::time::sleep(Duration::from_millis(25)).await;
    let mut excess_client = UnixStream::connect(&ipc_sock).await.unwrap();
    {
        use tokio::io::AsyncReadExt;
        let mut probe = [0u8; 4];
        let n = tokio::time::timeout(Duration::from_secs(1), excess_client.read(&mut probe))
            .await
            .unwrap()
            .unwrap();
        assert_eq!(
            n, 0,
            "excess connection past max_concurrent_connections must be shed immediately"
        );
    }

    let now_ms = replay.monotonic_now_ms();
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
    write_bounded_frame(&mut client_1, &req_frame, Duration::from_secs(2))
        .await
        .unwrap();
    let resp_frame = read_bounded_frame(&mut client_1, Duration::from_secs(2))
        .await
        .unwrap();
    assert_eq!(resp_frame.msg_type, MessageType::CommandResponse);
    assert_eq!(resp_frame.payload, b"OK");
    drop(client_1);

    // Trigger clean shutdown and assert ledger integrity
    shutdown_tx.send(true).unwrap();
    server_handle.await.unwrap().unwrap();

    ledger.verify_all().unwrap();
    let entries = ledger.entries_snapshot().unwrap();
    assert!(entries.iter().any(|e| e.kind == "daemon.start"));
    assert!(entries.iter().any(|e| e.kind == "ipc.connection.shed"));
    assert!(entries.iter().any(|e| e.kind == "ipc.command.accepted"));
    assert!(entries.iter().any(|e| e.kind == "daemon.shutdown"));

    let _ = std::fs::remove_dir_all(&dir);
}

// ---------------------------------------------------------------------------
// Minimal RFC 5280 DER X.509v3 Builder for End-to-End Policy + mTLS Daemon Test
// ---------------------------------------------------------------------------

mod x509_helper {
    use aws_lc_rs::rand::SystemRandom;
    use aws_lc_rs::signature::{EcdsaKeyPair, KeyPair, ECDSA_P256_SHA256_ASN1_SIGNING};

    fn der_encode_len(len: usize) -> Vec<u8> {
        if len < 128 {
            vec![len as u8]
        } else if len <= 0xFF {
            vec![0x81, len as u8]
        } else {
            vec![0x82, ((len >> 8) & 0xFF) as u8, (len & 0xFF) as u8]
        }
    }

    fn der_tlv(tag: u8, content: &[u8]) -> Vec<u8> {
        let len_bytes = der_encode_len(content.len());
        let mut out = Vec::with_capacity(1 + len_bytes.len() + content.len());
        out.push(tag);
        out.extend_from_slice(&len_bytes);
        out.extend_from_slice(content);
        out
    }

    fn der_seq(items: &[Vec<u8>]) -> Vec<u8> {
        let total: usize = items.iter().map(Vec::len).sum();
        let mut body = Vec::with_capacity(total);
        for item in items {
            body.extend_from_slice(item);
        }
        der_tlv(0x30, &body)
    }

    fn der_oid(oid: &[u8]) -> Vec<u8> {
        der_tlv(0x06, oid)
    }

    fn der_bit_string(unused_bits: u8, payload: &[u8]) -> Vec<u8> {
        let mut body = Vec::with_capacity(1 + payload.len());
        body.push(unused_bits);
        body.extend_from_slice(payload);
        der_tlv(0x03, &body)
    }

    fn der_cn_name(cn: &str) -> Vec<u8> {
        let attr = der_seq(&[der_oid(&[0x55, 0x04, 0x03]), der_tlv(0x0C, cn.as_bytes())]);
        der_seq(&[der_tlv(0x31, &attr)])
    }

    fn der_extension(oid: &[u8], critical: bool, value_der: &[u8]) -> Vec<u8> {
        let octet = der_tlv(0x04, value_der);
        if critical {
            der_seq(&[der_oid(oid), vec![0x01, 0x01, 0xFF], octet])
        } else {
            der_seq(&[der_oid(oid), octet])
        }
    }

    pub enum Profile<'a> {
        RootCa,
        ServerLeaf { dns_san: &'a str },
        ClientLeaf,
    }

    pub struct Identity {
        pub cert_der: Vec<u8>,
        pub pkcs8_der: Vec<u8>,
        key_pair: EcdsaKeyPair,
        subject_cn: String,
    }

    pub fn gen_cert(subject_cn: &str, issuer: Option<&Identity>, profile: Profile<'_>) -> Identity {
        let rng = SystemRandom::new();
        let pkcs8_doc =
            EcdsaKeyPair::generate_pkcs8(&ECDSA_P256_SHA256_ASN1_SIGNING, &rng).unwrap();
        let pkcs8_der = pkcs8_doc.as_ref().to_vec();
        let key_pair =
            EcdsaKeyPair::from_pkcs8(&ECDSA_P256_SHA256_ASN1_SIGNING, &pkcs8_der).unwrap();

        let mut serial = [0u8; 16];
        aws_lc_rs::rand::fill(&mut serial).unwrap();
        serial[0] = (serial[0] & 0x7F) | 0x01;

        let sig_alg = der_seq(&[der_oid(&[0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x04, 0x03, 0x02])]);
        let issuer_name = match issuer {
            Some(ca) => der_cn_name(&ca.subject_cn),
            None => der_cn_name(subject_cn),
        };
        let validity = der_seq(&[
            der_tlv(0x18, b"20250101000000Z"),
            der_tlv(0x18, b"20360101000000Z"),
        ]);
        let spki_alg = der_seq(&[
            der_oid(&[0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x02, 0x01]),
            der_oid(&[0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x03, 0x01, 0x07]),
        ]);
        let spki = der_seq(&[spki_alg, der_bit_string(0, key_pair.public_key().as_ref())]);

        let exts = match profile {
            Profile::RootCa => vec![
                der_extension(
                    &[0x55, 0x1D, 0x13],
                    true,
                    &der_seq(&[vec![0x01, 0x01, 0xFF]]),
                ),
                der_extension(&[0x55, 0x1D, 0x0F], true, &der_bit_string(1, &[0x06])),
            ],
            Profile::ServerLeaf { dns_san } => {
                let san_seq = der_seq(&[der_tlv(0x82, dns_san.as_bytes())]);
                let eku_seq =
                    der_seq(&[der_oid(&[0x2B, 0x06, 0x01, 0x05, 0x05, 0x07, 0x03, 0x01])]);
                vec![
                    der_extension(&[0x55, 0x1D, 0x13], true, &der_seq(&[])),
                    der_extension(&[0x55, 0x1D, 0x0F], true, &der_bit_string(7, &[0x80])),
                    der_extension(&[0x55, 0x1D, 0x25], false, &eku_seq),
                    der_extension(&[0x55, 0x1D, 0x11], false, &san_seq),
                ]
            }
            Profile::ClientLeaf => {
                let eku_seq =
                    der_seq(&[der_oid(&[0x2B, 0x06, 0x01, 0x05, 0x05, 0x07, 0x03, 0x02])]);
                vec![
                    der_extension(&[0x55, 0x1D, 0x13], true, &der_seq(&[])),
                    der_extension(&[0x55, 0x1D, 0x0F], true, &der_bit_string(7, &[0x80])),
                    der_extension(&[0x55, 0x1D, 0x25], false, &eku_seq),
                ]
            }
        };

        let tbs = der_seq(&[
            der_tlv(0xA0, &[0x02, 0x01, 0x02]),
            der_tlv(0x02, &serial),
            sig_alg.clone(),
            issuer_name,
            validity,
            der_cn_name(subject_cn),
            spki,
            der_tlv(0xA3, &der_seq(&exts)),
        ]);
        let signer = match issuer {
            Some(ca) => &ca.key_pair,
            None => &key_pair,
        };
        let sig = signer.sign(&rng, &tbs).unwrap();
        let cert_der = der_seq(&[tbs, sig_alg, der_bit_string(0, sig.as_ref())]);
        Identity {
            cert_der,
            pkcs8_der,
            key_pair,
            subject_cn: subject_cn.to_owned(),
        }
    }

    pub fn hex_encode(bytes: &[u8]) -> String {
        const HEX: &[u8; 16] = b"0123456789abcdef";
        let mut out = String::with_capacity(bytes.len() * 2);
        for &b in bytes {
            out.push(HEX[(b >> 4) as usize] as char);
            out.push(HEX[(b & 0x0F) as usize] as char);
        }
        out
    }
}

#[tokio::test]
async fn redteam_policy_loader_confinement_and_e2e_broker_egress_proxy_splice() {
    use anvil_core::unwrap::UnwrapAad;
    use locksmith_daemon::load_policy_file;
    use locksmith_proxy::{
        compute_cert_thumbprint_sha256, EgressRule, GuestAuthHeaderMode, MtlsProxyRequest,
        MtlsProxySession, StaticEndpointResolver,
    };
    use rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer, ServerName};
    use rustls::{ClientConfig, RootCertStore, ServerConfig};
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::TcpListener;
    use tokio_rustls::{TlsAcceptor, TlsConnector};
    use x509_helper::{gen_cert, hex_encode, Profile};

    let dir = unique_temp_dir("policy-and-egress");
    let current_uid = rustix::process::getuid().as_raw();

    // Generate mesh & upstream TLS 1.3 PKI
    let mesh_ca = gen_cert("Locksmith Mesh Root CA", None, Profile::RootCa);
    let broker_leaf = gen_cert(
        "locksmith.internal",
        Some(&mesh_ca),
        Profile::ServerLeaf {
            dns_san: "locksmith.internal",
        },
    );
    let guest_leaf = gen_cert("agent-workload-9", Some(&mesh_ca), Profile::ClientLeaf);
    let guest_thumb = compute_cert_thumbprint_sha256(&guest_leaf.cert_der);

    let upstream_ca = gen_cert("Mock Upstream Root CA", None, Profile::RootCa);
    let upstream_leaf = gen_cert(
        "api.anthropic.com",
        Some(&upstream_ca),
        Profile::ServerLeaf {
            dns_san: "api.anthropic.com",
        },
    );

    // Seal a real 2-of-2 AEAD credential bound to EgressRule::policy_hash
    let secret_unwrapper = Arc::new(SecretUnwrapper::new(
        HostShare::from_bytes([0x31; 32]),
        SoftwareTestHsm::new([0x42; 32]),
    ));
    let placeholder_env = anvil_core::unwrap::SealedSecretEnvelope {
        version: 1,
        hkdf_salt: [0u8; 32],
        nonce: [0u8; 12],
        ciphertext_and_tag: vec![0u8; 16],
    };
    let template_rule = EgressRule {
        sni_hostname: "api.anthropic.com".to_owned(),
        port: 443,
        allowed_methods: vec!["POST".to_owned()],
        path_prefix: "/v1/messages".to_owned(),
        secret_id: "anthropic-prod".to_owned(),
        sealed_envelope: placeholder_env,
        injection_header_name: "x-api-key".to_owned(),
        injection_value_prefix: String::new(),
        guest_auth_mode: GuestAuthHeaderMode::Reject,
    };
    let policy_hash = template_rule.policy_hash();
    let live_secret = b"sk-ant-daemon-e2e-secret-99887766";
    let aad = UnwrapAad {
        secret_id: "anthropic-prod",
        policy_hash,
        guest_cid: 9,
    };
    let sealed_env = secret_unwrapper.seal(live_secret, &aad).unwrap();

    let policy_text = format!(
        r#"
allow_vsock_cid = 9
allow_unix_uid = "{current_uid}:9"

[mtls]
server_cert_der_hex = "{}"
server_key_pkcs8_der_hex = "{}"
client_ca_cert_der_hex = "{}"
upstream_ca_cert_der_hex = "{}"

[[workload]]
workload_id = "agent-workload-9"
guest_cid = 9
cert_thumbprint_sha256 = "{}"

[[rule]]
sni_hostname = "api.anthropic.com"
port = 443
allowed_methods = "POST"
path_prefix = "/v1/messages"
secret_id = "anthropic-prod"
sealed_envelope_hex = "{}"
injection_header_name = "x-api-key"
injection_value_prefix = ""
guest_auth_mode = "reject"
"#,
        hex_encode(&broker_leaf.cert_der),
        hex_encode(&broker_leaf.pkcs8_der),
        hex_encode(&mesh_ca.cert_der),
        hex_encode(&upstream_ca.cert_der),
        hex_encode(&guest_thumb),
        hex_encode(&sealed_env.to_bytes()),
    );

    let valid_policy_path = dir.join("policy.conf");
    std::fs::write(&valid_policy_path, &policy_text).unwrap();

    #[cfg(unix)]
    {
        use std::os::unix::fs::{symlink, PermissionsExt};

        // 1. Symlink to policy file MUST be rejected via O_NOFOLLOW
        let symlink_policy = dir.join("policy-link.conf");
        symlink(&valid_policy_path, &symlink_policy).unwrap();
        assert!(
            load_policy_file(&symlink_policy).is_err(),
            "load_policy_file must reject symlink policy paths"
        );

        // 2. World-writable (0666) policy file MUST be rejected on Linux
        std::fs::set_permissions(&valid_policy_path, std::fs::Permissions::from_mode(0o666))
            .unwrap();
        #[cfg(target_os = "linux")]
        assert!(
            load_policy_file(&valid_policy_path).is_err(),
            "load_policy_file must reject world-writable policy files"
        );

        // Restore strict 0600 permissions
        std::fs::set_permissions(&valid_policy_path, std::fs::Permissions::from_mode(0o600))
            .unwrap();
    }

    let bundle = load_policy_file(&valid_policy_path).unwrap();
    assert_eq!(bundle.workloads.len(), 1);
    let pki = bundle
        .mtls_pki
        .expect("[mtls] stanza must build TLS 1.3 PKI");

    // Start real TLS 1.3 upstream server for api.anthropic.com that verifies secret injection
    // and intentionally reflects the secret back in its response body to test scrubbing.
    let provider = Arc::new(rustls::crypto::aws_lc_rs::default_provider());
    let upstream_server_cfg = Arc::new(
        ServerConfig::builder_with_provider(Arc::clone(&provider))
            .with_protocol_versions(&[&rustls::version::TLS13])
            .unwrap()
            .with_no_client_auth()
            .with_single_cert(
                vec![CertificateDer::from(upstream_leaf.cert_der.clone())],
                PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(upstream_leaf.pkcs8_der.clone())),
            )
            .unwrap(),
    );
    let upstream_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let upstream_addr = upstream_listener.local_addr().unwrap();
    let upstream_acceptor = TlsAcceptor::from(upstream_server_cfg);
    let upstream_task = tokio::spawn(async move {
        let (tcp, _) = upstream_listener.accept().await.unwrap();
        let mut tls = upstream_acceptor.accept(tcp).await.unwrap();
        let mut req_buf = vec![0u8; 4096];
        let n = tls.read(&mut req_buf).await.unwrap();
        let req_str = String::from_utf8_lossy(&req_buf[..n]);
        assert!(
            req_str.contains("x-api-key: sk-ant-daemon-e2e-secret-99887766\r\n"),
            "upstream did not receive injected credential: {req_str}"
        );
        assert!(
            req_str.contains("Accept-Encoding: identity\r\n"),
            "upstream must receive Accept-Encoding: identity"
        );
        let body = b"upstream debug reflection: key=sk-ant-daemon-e2e-secret-99887766";
        let resp = format!(
            "HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
            body.len()
        );
        tls.write_all(resp.as_bytes()).await.unwrap();
        tls.write_all(body).await.unwrap();
        tls.shutdown().await.unwrap();
    });

    // Build BrokerDaemon::with_mtls_session from the loaded policy bundle
    let ipc_sock = dir.join("e2e-broker.sock");
    let mut allowlist = PeerAllowlist::new();
    for cid in bundle.vsock_cids {
        allowlist.allow_vsock_cid(cid);
    }
    for (uid, cid) in bundle.unix_uid_mappings {
        allowlist.allow_unix_uid(uid, cid);
    }

    let ledger = Arc::new(AuditLedger::new());
    let replay = Arc::new(ReplayFilter::with_defaults(256).unwrap());
    let attest_key = [0x6B; 32];
    let verifier = Arc::new(CommandVerifier::new(attest_key, Arc::clone(&replay)));
    let policy_engine = Arc::new(PolicyEngine::new(
        bundle.workloads,
        Arc::clone(&replay),
        secret_unwrapper,
    ));

    let resolver = Arc::new(StaticEndpointResolver::single(
        "api.anthropic.com",
        443,
        upstream_addr,
    ));
    let mtls_session = Arc::new(MtlsProxySession {
        tls_server_config: pki.tls_server_config,
        policy_engine: Arc::clone(&policy_engine),
        upstream_resolver: resolver,
        upstream_tls_config: pki.upstream_tls_config,
        io_timeout: Duration::from_secs(5),
    });

    let daemon = Arc::new(BrokerDaemon::with_mtls_session(
        DaemonRuntimeConfig::new(ipc_sock.clone(), allowlist),
        Arc::clone(&ledger),
        verifier,
        policy_engine,
        mtls_session,
    ));

    let (shutdown_tx, shutdown_rx) = watch::channel(false);
    let daemon_runner = Arc::clone(&daemon);
    let server_handle =
        tokio::spawn(async move { daemon_runner.serve_until_shutdown(shutdown_rx).await });

    for _ in 0..40 {
        if ipc_sock.exists() {
            break;
        }
        tokio::time::sleep(Duration::from_millis(10)).await;
    }

    // Check WORKLOAD_COUNT and AUDIT_HEAD control commands
    {
        let mut cmd_stream = UnixStream::connect(&ipc_sock).await.unwrap();
        let env = AttestedCommandEnvelope::sign_new(
            &attest_key,
            9,
            1,
            replay.monotonic_now_ms(),
            [0x10; 32],
            b"WORKLOAD_COUNT".to_vec(),
        )
        .unwrap();
        write_bounded_frame(
            &mut cmd_stream,
            &WireFrame {
                msg_type: MessageType::CommandRequest,
                payload: env.to_bytes().unwrap(),
            },
            Duration::from_secs(2),
        )
        .await
        .unwrap();
        let resp = read_bounded_frame(&mut cmd_stream, Duration::from_secs(2))
            .await
            .unwrap();
        assert_eq!(resp.payload, b"WORKLOADS=1");
    }

    // Drive MessageType::EgressProxyFrame -> READY -> mTLS 1.3 handshake -> spliced HTTP
    let mut proxy_ipc = UnixStream::connect(&ipc_sock).await.unwrap();
    write_bounded_frame(
        &mut proxy_ipc,
        &WireFrame {
            msg_type: MessageType::EgressProxyFrame,
            payload: Vec::new(),
        },
        Duration::from_secs(2),
    )
    .await
    .unwrap();
    let ready_frame = read_bounded_frame(&mut proxy_ipc, Duration::from_secs(2))
        .await
        .unwrap();
    assert_eq!(ready_frame.msg_type, MessageType::EgressProxyFrame);
    assert_eq!(ready_frame.payload, b"READY");

    let mut guest_roots = RootCertStore::empty();
    guest_roots
        .add(CertificateDer::from(mesh_ca.cert_der.clone()))
        .unwrap();
    let guest_tls_cfg = Arc::new(
        ClientConfig::builder_with_provider(provider)
            .with_protocol_versions(&[&rustls::version::TLS13])
            .unwrap()
            .with_root_certificates(guest_roots)
            .with_client_auth_cert(
                vec![CertificateDer::from(guest_leaf.cert_der)],
                PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(guest_leaf.pkcs8_der)),
            )
            .unwrap(),
    );
    let connector = TlsConnector::from(guest_tls_cfg);
    let mut guest_mtls = connector
        .connect(
            ServerName::try_from("locksmith.internal").unwrap(),
            proxy_ipc,
        )
        .await
        .unwrap();

    let proxy_req = MtlsProxyRequest {
        workload_id: "agent-workload-9".to_owned(),
        guest_cid: 9,
        sni_hostname: "api.anthropic.com".to_owned(),
        port: 443,
        nonce: [0xC9; 32],
        timestamp_ms: replay.monotonic_now_ms(),
        raw_http_request: b"POST /v1/messages HTTP/1.1\r\nHost: api.anthropic.com\r\nContent-Type: application/json\r\nContent-Length: 2\r\n\r\n{}".to_vec(),
    };
    let req_bytes = proxy_req.to_bytes().unwrap();
    let req_len = u32::try_from(req_bytes.len()).unwrap();
    guest_mtls.write_all(&req_len.to_be_bytes()).await.unwrap();
    guest_mtls.write_all(&req_bytes).await.unwrap();
    guest_mtls.flush().await.unwrap();

    let mut relayed_resp = Vec::new();
    guest_mtls.read_to_end(&mut relayed_resp).await.unwrap();
    let relayed_str = String::from_utf8_lossy(&relayed_resp);
    assert!(
        relayed_str.contains("HTTP/1.1 200 OK"),
        "unexpected relayed response: {relayed_str}"
    );
    assert!(
        !relayed_str.contains("sk-ant-daemon-e2e-secret-99887766"),
        "BrokerDaemon egress splice MUST scrub reflected secret before returning to Ring 2"
    );
    assert!(relayed_str.contains("[REDACTED_BY_LOCKSMITH]"));

    upstream_task.await.unwrap();

    // Query AUDIT_HEAD and shut down cleanly
    {
        let mut head_stream = UnixStream::connect(&ipc_sock).await.unwrap();
        let env = AttestedCommandEnvelope::sign_new(
            &attest_key,
            9,
            2,
            replay.monotonic_now_ms(),
            [0x11; 32],
            b"AUDIT_HEAD".to_vec(),
        )
        .unwrap();
        write_bounded_frame(
            &mut head_stream,
            &WireFrame {
                msg_type: MessageType::CommandRequest,
                payload: env.to_bytes().unwrap(),
            },
            Duration::from_secs(2),
        )
        .await
        .unwrap();
        let resp = read_bounded_frame(&mut head_stream, Duration::from_secs(2))
            .await
            .unwrap();
        let head_str = String::from_utf8_lossy(&resp.payload);
        assert!(head_str.starts_with("HEAD seq="));
    }

    shutdown_tx.send(true).unwrap();
    server_handle.await.unwrap().unwrap();
    ledger.verify_all().unwrap();
    let entries = ledger.entries_snapshot().unwrap();
    assert!(entries.iter().any(|e| e.kind == "proxy.egress.completed"));

    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn redteam_forge_controller_rejects_injection_floating_tags_and_traversal() {
    #[cfg(unix)]
    use std::os::unix::fs::PermissionsExt;

    let workspace_root = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .unwrap()
        .parent()
        .unwrap();
    let forge_path = workspace_root.join("infra/forge");
    let forge_src = std::fs::read_to_string(&forge_path).unwrap();

    // 1. Static supply-chain & shell hygiene invariants on infra/forge
    assert!(
        forge_src.contains(
            "COSIGN_LINUX_AMD64_SHA256=\"8b24b946dd5809c6bd93de08033bcf6bc0ed7d336b7785787c080f574b89249b\""
        ),
        "infra/forge must pin the verified v2.4.1 cosign SHA-256 digest"
    );
    assert!(
        !forge_src.contains("<<EOF"),
        "infra/forge must quote all heredocs (<<'EOF') to prevent local shell expansion injection"
    );
    assert!(
        !forge_src.contains("shellcheck disable"),
        "infra/forge must pass shellcheck cleanly without disable directives"
    );
    assert!(
        !forge_src.contains("/root/.docker/config.json"),
        "infra/forge must use an ephemeral tmpfs DOCKER_CONFIG instead of /root/.docker/config.json"
    );
    assert!(
        forge_src.contains("--proto '=https'") && forge_src.contains("--tlsv1.2"),
        "infra/forge curl invocations must enforce HTTPS + TLS >= 1.2"
    );
    assert!(
        forge_src.contains("op read --"),
        "infra/forge must pass `--` end-of-options to `op read`"
    );

    // 2. Dynamic adversarial CLI validation harness with canary stubs for ssh/install/op
    let dir = unique_temp_dir("forge-redteam");
    let mock_bin = dir.join("bin");
    std::fs::create_dir_all(&mock_bin).unwrap();
    for cmd_name in ["ssh", "install", "op", "curl"] {
        let stub = mock_bin.join(cmd_name);
        std::fs::write(
            &stub,
            format!("#!/bin/sh\necho \"SENTINEL_EXECUTED:{cmd_name}\" >&2\nexit 42\n"),
        )
        .unwrap();
        #[cfg(unix)]
        std::fs::set_permissions(&stub, std::fs::Permissions::from_mode(0o755)).unwrap();
    }

    let safe_path = format!("{}:/usr/bin:/bin", mock_bin.display());
    let valid_digest = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";
    let valid_image = format!("ghcr.io/susanbeasles/locksmith@sha256:{valid_digest}");

    let hostile_invocations: Vec<Vec<String>> = vec![
        // Command injection smuggled inside ghcr.io wildcard before @sha256:
        vec![
            "verify".into(),
            "--host".into(),
            "203.0.113.10".into(),
            "--image".into(),
            format!("ghcr.io/susanbeasles/$(id)@sha256:{valid_digest}"),
        ],
        // Uppercase hex inside @sha256: digest
        vec![
            "verify".into(),
            "--host".into(),
            "203.0.113.10".into(),
            "--image".into(),
            "ghcr.io/susanbeasles/locksmith@sha256:ABCDEF6789abcdef0123456789abcdef0123456789abcdef0123456789abcdef".into(),
        ],
        // 63-hex (short by 1 nibble) digest
        vec![
            "verify".into(),
            "--host".into(),
            "203.0.113.10".into(),
            "--image".into(),
            "ghcr.io/susanbeasles/locksmith@sha256:123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef".into(),
        ],
        // 65-hex (oversized by 1 nibble) digest
        vec![
            "verify".into(),
            "--host".into(),
            "203.0.113.10".into(),
            "--image".into(),
            format!("ghcr.io/susanbeasles/locksmith@sha256:{valid_digest}0"),
        ],
        // SSH option injection via leading `-` in --host
        vec![
            "verify".into(),
            "--host".into(),
            "-oProxyCommand=id".into(),
            "--image".into(),
            valid_image.clone(),
        ],
        // Out-of-range IPv4 octet in --host
        vec![
            "verify".into(),
            "--host".into(),
            "999.0.113.10".into(),
            "--image".into(),
            valid_image.clone(),
        ],
        // Path traversal in install-self bypassing /usr/local/bin/* prefix
        vec![
            "install-self".into(),
            "/usr/local/bin/../../../tmp/pwned-forge".into(),
        ],
        // Leading hyphen / metacharacter in --region on `forge up`
        vec![
            "up".into(),
            "--region".into(),
            "-ewr".into(),
            "--ssh-key-id".into(),
            "11111111-2222-3333-4444-555555555555".into(),
            "--image".into(),
            valid_image,
        ],
    ];

    for args in hostile_invocations {
        let out = Command::new("/bin/sh")
            .arg(&forge_path)
            .args(&args)
            .env_clear()
            .env("PATH", &safe_path)
            .output()
            .unwrap();
        let stderr = String::from_utf8_lossy(&out.stderr);
        assert!(
            !out.status.success(),
            "infra/forge MUST fail closed for hostile args {args:?}"
        );
        assert_ne!(
            out.status.code(),
            Some(42),
            "infra/forge invoked external command before rejecting hostile args {args:?}: stderr={stderr}"
        );
        assert!(
            !stderr.contains("SENTINEL_EXECUTED:"),
            "infra/forge reached external command for {args:?}: stderr={stderr}"
        );
    }

    let _ = std::fs::remove_dir_all(&dir);
}
