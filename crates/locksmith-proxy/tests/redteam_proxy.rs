//! Mandatory Phase 5 Adversarial Red-Team Suite (`locksmith-proxy`).
//!
//! Includes an in-memory RFC 5280 ASN.1 DER X.509v3 certificate authority and
//! ECDSA P-256 key generator built directly atop `aws-lc-rs`, driving real
//! `tokio-rustls` loopback mTLS + upstream TLS 1.3 handshakes end-to-end.

#![allow(clippy::unwrap_used, clippy::expect_used)]

use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::Duration;

use anvil_core::replay::ReplayFilter;
use anvil_core::unwrap::{HostShare, SecretUnwrapper, SoftwareTestHsm, UnwrapAad};
use aws_lc_rs::rand::SystemRandom;
use aws_lc_rs::signature::{EcdsaKeyPair, KeyPair, ECDSA_P256_SHA256_ASN1_SIGNING};
use rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer, ServerName};
use rustls::server::WebPkiClientVerifier;
use rustls::{ClientConfig, RootCertStore, ServerConfig};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio_rustls::{TlsAcceptor, TlsConnector};

use locksmith_proxy::{
    compute_cert_thumbprint_sha256, handle_mtls_guest_connection, splice_outbound_request,
    EgressAuthorizationInput, EgressRule, GuestAuthHeaderMode, MtlsProxyRequest, MtlsProxySession,
    OutboundHttpRequest, PolicyEngine, PolicyError, ProxyError, StaticEndpointResolver,
    WorkloadIdentity,
};

// ---------------------------------------------------------------------------
// Minimal Pure-Rust RFC 5280 X.509v3 ASN.1 DER Builder (ECDSA P-256 + SHA-256)
// ---------------------------------------------------------------------------

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

fn der_bool_true() -> Vec<u8> {
    vec![0x01, 0x01, 0xFF]
}

fn der_bit_string(unused_bits: u8, payload: &[u8]) -> Vec<u8> {
    let mut body = Vec::with_capacity(1 + payload.len());
    body.push(unused_bits);
    body.extend_from_slice(payload);
    der_tlv(0x03, &body)
}

fn der_cn_name(cn: &str) -> Vec<u8> {
    // OID 2.5.4.3 (commonName) = 55 04 03
    let attr = der_seq(&[der_oid(&[0x55, 0x04, 0x03]), der_tlv(0x0C, cn.as_bytes())]);
    let rdn = der_tlv(0x31, &attr);
    der_seq(&[rdn])
}

fn der_alg_ecdsa_sha256() -> Vec<u8> {
    // OID 1.2.840.10045.4.3.2 (ecdsa-with-SHA256)
    der_seq(&[der_oid(&[0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x04, 0x03, 0x02])])
}

fn der_spki_p256(uncompressed_pub: &[u8]) -> Vec<u8> {
    // id-ecPublicKey (1.2.840.10045.2.1) + prime256v1 (1.2.840.10045.3.1.7)
    let alg = der_seq(&[
        der_oid(&[0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x02, 0x01]),
        der_oid(&[0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x03, 0x01, 0x07]),
    ]);
    der_seq(&[alg, der_bit_string(0, uncompressed_pub)])
}

fn der_extension(oid: &[u8], critical: bool, value_der: &[u8]) -> Vec<u8> {
    let octet = der_tlv(0x04, value_der);
    if critical {
        der_seq(&[der_oid(oid), der_bool_true(), octet])
    } else {
        der_seq(&[der_oid(oid), octet])
    }
}

enum CertProfile<'a> {
    RootCa,
    ServerLeaf { dns_san: &'a str },
    ClientLeaf,
}

struct GeneratedIdentity {
    cert_der: Vec<u8>,
    pkcs8_der: Vec<u8>,
    key_pair: EcdsaKeyPair,
    subject_cn: String,
}

fn generate_x509_cert(
    subject_cn: &str,
    issuer: Option<&GeneratedIdentity>,
    profile: CertProfile<'_>,
) -> GeneratedIdentity {
    let rng = SystemRandom::new();
    let pkcs8_doc = EcdsaKeyPair::generate_pkcs8(&ECDSA_P256_SHA256_ASN1_SIGNING, &rng).unwrap();
    let pkcs8_der = pkcs8_doc.as_ref().to_vec();
    let key_pair = EcdsaKeyPair::from_pkcs8(&ECDSA_P256_SHA256_ASN1_SIGNING, &pkcs8_der).unwrap();

    let mut serial = [0u8; 16];
    aws_lc_rs::rand::fill(&mut serial).unwrap();
    serial[0] = (serial[0] & 0x7F) | 0x01;

    let version_v3 = der_tlv(0xA0, &[0x02, 0x01, 0x02]);
    let serial_int = der_tlv(0x02, &serial);
    let sig_alg = der_alg_ecdsa_sha256();
    let issuer_name = match issuer {
        Some(ca) => der_cn_name(&ca.subject_cn),
        None => der_cn_name(subject_cn),
    };
    // Validity: GeneralizedTime 2025-01-01T00:00:00Z .. 2036-01-01T00:00:00Z
    let validity = der_seq(&[
        der_tlv(0x18, b"20250101000000Z"),
        der_tlv(0x18, b"20360101000000Z"),
    ]);
    let subject_name = der_cn_name(subject_cn);
    let spki = der_spki_p256(key_pair.public_key().as_ref());

    let exts = match profile {
        CertProfile::RootCa => vec![
            // BasicConstraints: critical, cA=TRUE
            der_extension(&[0x55, 0x1D, 0x13], true, &der_seq(&[der_bool_true()])),
            // KeyUsage: critical, keyCertSign | cRLSign
            der_extension(&[0x55, 0x1D, 0x0F], true, &der_bit_string(1, &[0x06])),
        ],
        CertProfile::ServerLeaf { dns_san } => {
            let san_seq = der_seq(&[der_tlv(0x82, dns_san.as_bytes())]);
            let eku_seq = der_seq(&[der_oid(&[0x2B, 0x06, 0x01, 0x05, 0x05, 0x07, 0x03, 0x01])]);
            vec![
                der_extension(&[0x55, 0x1D, 0x13], true, &der_seq(&[])),
                der_extension(&[0x55, 0x1D, 0x0F], true, &der_bit_string(7, &[0x80])),
                der_extension(&[0x55, 0x1D, 0x25], false, &eku_seq),
                der_extension(&[0x55, 0x1D, 0x11], false, &san_seq),
            ]
        }
        CertProfile::ClientLeaf => {
            let eku_seq = der_seq(&[der_oid(&[0x2B, 0x06, 0x01, 0x05, 0x05, 0x07, 0x03, 0x02])]);
            vec![
                der_extension(&[0x55, 0x1D, 0x13], true, &der_seq(&[])),
                der_extension(&[0x55, 0x1D, 0x0F], true, &der_bit_string(7, &[0x80])),
                der_extension(&[0x55, 0x1D, 0x25], false, &eku_seq),
            ]
        }
    };

    let ext_wrapper = der_tlv(0xA3, &der_seq(&exts));
    let tbs = der_seq(&[
        version_v3,
        serial_int,
        sig_alg.clone(),
        issuer_name,
        validity,
        subject_name,
        spki,
        ext_wrapper,
    ]);

    let signing_key = match issuer {
        Some(ca) => &ca.key_pair,
        None => &key_pair,
    };
    let sig = signing_key.sign(&rng, &tbs).unwrap();
    let cert_der = der_seq(&[tbs, sig_alg, der_bit_string(0, sig.as_ref())]);

    GeneratedIdentity {
        cert_der,
        pkcs8_der,
        key_pair,
        subject_cn: subject_cn.to_owned(),
    }
}

struct TestPki {
    proxy_server_cfg: Arc<ServerConfig>,
    guest_a_client_cfg: Arc<ClientConfig>,
    guest_b_client_cfg: Arc<ClientConfig>,
    guest_a_cert_der: Vec<u8>,
    guest_b_cert_der: Vec<u8>,
    upstream_server_cfg: Arc<ServerConfig>,
    proxy_to_upstream_client_cfg: Arc<ClientConfig>,
}

fn build_ephemeral_pki() -> TestPki {
    let provider = Arc::new(rustls::crypto::aws_lc_rs::default_provider());

    let mesh_ca = generate_x509_cert("Locksmith Mesh Root CA", None, CertProfile::RootCa);
    let proxy_leaf = generate_x509_cert(
        "locksmith.internal",
        Some(&mesh_ca),
        CertProfile::ServerLeaf {
            dns_san: "locksmith.internal",
        },
    );
    let workload_a = generate_x509_cert("workload-a", Some(&mesh_ca), CertProfile::ClientLeaf);
    let workload_b = generate_x509_cert("workload-b", Some(&mesh_ca), CertProfile::ClientLeaf);

    let upstream_ca = generate_x509_cert("Mock Upstream Root CA", None, CertProfile::RootCa);
    let upstream_leaf = generate_x509_cert(
        "api.anthropic.com",
        Some(&upstream_ca),
        CertProfile::ServerLeaf {
            dns_san: "api.anthropic.com",
        },
    );

    let mut mesh_roots = RootCertStore::empty();
    mesh_roots
        .add(CertificateDer::from(mesh_ca.cert_der.clone()))
        .unwrap();
    let mesh_roots_arc = Arc::new(mesh_roots);

    let client_verifier = WebPkiClientVerifier::builder_with_provider(
        Arc::clone(&mesh_roots_arc),
        Arc::clone(&provider),
    )
    .build()
    .unwrap();

    let proxy_server_cfg = Arc::new(
        ServerConfig::builder_with_provider(Arc::clone(&provider))
            .with_protocol_versions(&[&rustls::version::TLS13])
            .unwrap()
            .with_client_cert_verifier(client_verifier)
            .with_single_cert(
                vec![CertificateDer::from(proxy_leaf.cert_der)],
                PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(proxy_leaf.pkcs8_der)),
            )
            .unwrap(),
    );

    let guest_a_client_cfg = Arc::new(
        ClientConfig::builder_with_provider(Arc::clone(&provider))
            .with_protocol_versions(&[&rustls::version::TLS13])
            .unwrap()
            .with_root_certificates((*mesh_roots_arc).clone())
            .with_client_auth_cert(
                vec![CertificateDer::from(workload_a.cert_der.clone())],
                PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(workload_a.pkcs8_der)),
            )
            .unwrap(),
    );

    let guest_b_client_cfg = Arc::new(
        ClientConfig::builder_with_provider(Arc::clone(&provider))
            .with_protocol_versions(&[&rustls::version::TLS13])
            .unwrap()
            .with_root_certificates((*mesh_roots_arc).clone())
            .with_client_auth_cert(
                vec![CertificateDer::from(workload_b.cert_der.clone())],
                PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(workload_b.pkcs8_der)),
            )
            .unwrap(),
    );

    let mut upstream_roots = RootCertStore::empty();
    upstream_roots
        .add(CertificateDer::from(upstream_ca.cert_der))
        .unwrap();

    let upstream_server_cfg = Arc::new(
        ServerConfig::builder_with_provider(Arc::clone(&provider))
            .with_protocol_versions(&[&rustls::version::TLS13])
            .unwrap()
            .with_no_client_auth()
            .with_single_cert(
                vec![CertificateDer::from(upstream_leaf.cert_der)],
                PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(upstream_leaf.pkcs8_der)),
            )
            .unwrap(),
    );

    let proxy_to_upstream_client_cfg = Arc::new(
        ClientConfig::builder_with_provider(provider)
            .with_protocol_versions(&[&rustls::version::TLS13])
            .unwrap()
            .with_root_certificates(upstream_roots)
            .with_no_client_auth(),
    );

    TestPki {
        proxy_server_cfg,
        guest_a_client_cfg,
        guest_b_client_cfg,
        guest_a_cert_der: workload_a.cert_der,
        guest_b_cert_der: workload_b.cert_der,
        upstream_server_cfg,
        proxy_to_upstream_client_cfg,
    }
}

fn build_test_engine(
    workload_a_cert_der: &[u8],
    workload_b_cert_der: &[u8],
    raw_secret: &[u8],
) -> PolicyEngine<SoftwareTestHsm> {
    let unwrapper = Arc::new(SecretUnwrapper::new(
        HostShare::from_bytes([0x31; 32]),
        SoftwareTestHsm::new([0x32; 32]),
    ));
    let replay = Arc::new(ReplayFilter::with_defaults(256).unwrap());

    let mut rule_a = EgressRule {
        sni_hostname: "api.anthropic.com".to_owned(),
        port: 443,
        allowed_methods: vec!["POST".to_owned()],
        path_prefix: "/v1/".to_owned(),
        secret_id: "anthropic/live".to_owned(),
        sealed_envelope: anvil_core::unwrap::SealedSecretEnvelope {
            version: 1,
            hkdf_salt: [0; 32],
            nonce: [0; 12],
            ciphertext_and_tag: vec![0; 16],
        },
        injection_header_name: "Authorization".to_owned(),
        injection_value_prefix: "Bearer ".to_owned(),
        guest_auth_mode: GuestAuthHeaderMode::Strip,
    };
    let policy_hash = rule_a.policy_hash();
    rule_a.sealed_envelope = unwrapper
        .seal(
            raw_secret,
            &UnwrapAad {
                secret_id: "anthropic/live",
                policy_hash,
                guest_cid: 10,
            },
        )
        .unwrap();

    PolicyEngine::new(
        vec![
            WorkloadIdentity {
                workload_id: "workload-a".to_owned(),
                guest_cid: 10,
                cert_thumbprint_sha256: compute_cert_thumbprint_sha256(workload_a_cert_der),
                rules: vec![rule_a],
            },
            WorkloadIdentity {
                workload_id: "workload-b".to_owned(),
                guest_cid: 20,
                cert_thumbprint_sha256: compute_cert_thumbprint_sha256(workload_b_cert_der),
                rules: Vec::new(),
            },
        ],
        replay,
        unwrapper,
    )
}

#[tokio::test]
async fn redteam_domain_fronting_host_sni_desync_rejected_before_upstream_dial() {
    let pki = build_ephemeral_pki();
    let engine = Arc::new(build_test_engine(
        &pki.guest_a_cert_der,
        &pki.guest_b_cert_der,
        b"sk-live-secret-999",
    ));

    // Bind upstream listener and assert ZERO connections ever arrive during domain-fronting attempts
    let upstream_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let upstream_addr = upstream_listener.local_addr().unwrap();
    let upstream_dials = Arc::new(AtomicUsize::new(0));
    let dials_counter = Arc::clone(&upstream_dials);
    let watcher = tokio::spawn(async move {
        if upstream_listener.accept().await.is_ok() {
            dials_counter.fetch_add(1, Ordering::SeqCst);
        }
    });

    // Case 1: SNI is api.anthropic.com, HTTP Host is evil.example.com
    let proxy_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let proxy_addr = proxy_listener.local_addr().unwrap();
    let now_ms = 1_762_000_000_000u64;

    let guest_cfg = Arc::clone(&pki.guest_a_client_cfg);
    let client_task = tokio::spawn(async move {
        let tcp = TcpStream::connect(proxy_addr).await.unwrap();
        let connector = TlsConnector::from(guest_cfg);
        let sni = ServerName::try_from("locksmith.internal").unwrap();
        let mut tls = connector.connect(sni, tcp).await.unwrap();

        let fronted_http = OutboundHttpRequest {
            method: "POST".to_owned(),
            path_and_query: "/v1/messages".to_owned(),
            headers: vec![
                ("Host".to_owned(), "evil.example.com".to_owned()),
                ("Content-Length".to_owned(), "2".to_owned()),
            ],
            body: b"{}".to_vec(),
        };
        let req_env = MtlsProxyRequest {
            workload_id: "workload-a".to_owned(),
            guest_cid: 10,
            sni_hostname: "api.anthropic.com".to_owned(),
            port: 443,
            nonce: [0x01; 32],
            timestamp_ms: now_ms,
            raw_http_request: fronted_http.to_wire_bytes(),
        };
        let encoded = req_env.to_bytes().unwrap();
        tls.write_all(&(encoded.len() as u32).to_be_bytes())
            .await
            .unwrap();
        tls.write_all(&encoded).await.unwrap();
        tls.flush().await.unwrap();
    });

    let session = MtlsProxySession {
        tls_server_config: Arc::clone(&pki.proxy_server_cfg),
        policy_engine: Arc::clone(&engine),
        upstream_resolver: Arc::new(StaticEndpointResolver::single(
            "api.anthropic.com",
            443,
            upstream_addr,
        )),
        upstream_tls_config: Arc::clone(&pki.proxy_to_upstream_client_cfg),
        io_timeout: Duration::from_secs(2),
    };
    let (accepted_tcp, _) = proxy_listener.accept().await.unwrap();
    let err = handle_mtls_guest_connection(accepted_tcp, 10, &session, now_ms)
        .await
        .unwrap_err();
    client_task.await.unwrap();

    assert!(matches!(
        err,
        ProxyError::Policy(PolicyError::HostSniMismatch)
    ));

    // Case 2: Duplicate Host headers ([api.anthropic.com, evil.example.com])
    let dup_host_err = engine
        .authorize_egress(EgressAuthorizationInput {
            workload_id: "workload-a",
            guest_cid: 10,
            peer_cert_der: &pki.guest_a_cert_der,
            sni_hostname: "api.anthropic.com",
            port: 443,
            nonce: [0x02; 32],
            timestamp_ms: now_ms,
            now_ms,
            request: OutboundHttpRequest {
                method: "POST".to_owned(),
                path_and_query: "/v1/messages".to_owned(),
                headers: vec![
                    ("Host".to_owned(), "api.anthropic.com".to_owned()),
                    ("Host".to_owned(), "evil.example.com".to_owned()),
                    ("Content-Length".to_owned(), "2".to_owned()),
                ],
                body: b"{}".to_vec(),
            },
        })
        .unwrap_err();
    assert_eq!(dup_host_err, PolicyError::HostSniMismatch);

    tokio::time::sleep(Duration::from_millis(50)).await;
    assert_eq!(
        upstream_dials.load(Ordering::SeqCst),
        0,
        "upstream socket MUST NEVER be dialed when Host != verified SNI"
    );
    watcher.abort();
}

#[test]
fn redteam_crlf_and_nul_header_smuggling_rejected() {
    let pki = build_ephemeral_pki();
    let engine = build_test_engine(
        &pki.guest_a_cert_der,
        &pki.guest_b_cert_der,
        b"sk-live-secret-999",
    );
    let now_ms = 1_762_000_000_000u64;

    // 1. Multi-byte UTF-8 + CRLF header injection ("良\r\nAuthorization: Bearer attacker")
    let crlf_err = engine
        .authorize_egress(EgressAuthorizationInput {
            workload_id: "workload-a",
            guest_cid: 10,
            peer_cert_der: &pki.guest_a_cert_der,
            sni_hostname: "api.anthropic.com",
            port: 443,
            nonce: [0x10; 32],
            timestamp_ms: now_ms,
            now_ms,
            request: OutboundHttpRequest {
                method: "POST".to_owned(),
                path_and_query: "/v1/messages".to_owned(),
                headers: vec![
                    ("Host".to_owned(), "api.anthropic.com".to_owned()),
                    (
                        "X-Custom-Trace".to_owned(),
                        "良\r\nAuthorization: Bearer attacker".to_owned(),
                    ),
                ],
                body: Vec::new(),
            },
        })
        .unwrap_err();
    assert!(matches!(
        crlf_err,
        PolicyError::HeaderSmugglingDetected { .. }
    ));

    // 2. Embedded NUL byte header value ("val\x00smuggled")
    let nul_err = engine
        .authorize_egress(EgressAuthorizationInput {
            workload_id: "workload-a",
            guest_cid: 10,
            peer_cert_der: &pki.guest_a_cert_der,
            sni_hostname: "api.anthropic.com",
            port: 443,
            nonce: [0x11; 32],
            timestamp_ms: now_ms,
            now_ms,
            request: OutboundHttpRequest {
                method: "POST".to_owned(),
                path_and_query: "/v1/messages".to_owned(),
                headers: vec![
                    ("Host".to_owned(), "api.anthropic.com".to_owned()),
                    ("X-Custom-Trace".to_owned(), "val\x00smuggled".to_owned()),
                ],
                body: Vec::new(),
            },
        })
        .unwrap_err();
    assert!(matches!(
        nul_err,
        PolicyError::HeaderSmugglingDetected { .. }
    ));

    // 3. Conflicting Content-Length + Transfer-Encoding smuggling on raw wire
    let cl_te_raw = b"POST /v1/messages HTTP/1.1\r\nHost: api.anthropic.com\r\nContent-Length: 4\r\nTransfer-Encoding: chunked\r\n\r\n0\r\n\r\n";
    assert_eq!(
        OutboundHttpRequest::from_wire_bytes(cl_te_raw).unwrap_err(),
        PolicyError::ConflictingFramingHeaders
    );
}

#[tokio::test]
async fn redteam_stolen_request_wrong_mtls_thumbprint_rejected() {
    let pki = build_ephemeral_pki();
    let engine = Arc::new(build_test_engine(
        &pki.guest_a_cert_der,
        &pki.guest_b_cert_der,
        b"sk-live-secret-999",
    ));
    let now_ms = 1_762_000_000_000u64;

    let upstream_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let upstream_addr = upstream_listener.local_addr().unwrap();

    let proxy_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let proxy_addr = proxy_listener.local_addr().unwrap();

    // Workload B connects with its VALID CA-signed client cert, claiming Workload A's rule
    let guest_b_cfg = Arc::clone(&pki.guest_b_client_cfg);
    let rogue_guest = tokio::spawn(async move {
        let tcp = TcpStream::connect(proxy_addr).await.unwrap();
        let connector = TlsConnector::from(guest_b_cfg);
        let sni = ServerName::try_from("locksmith.internal").unwrap();
        let mut tls = connector.connect(sni, tcp).await.unwrap();

        let http = OutboundHttpRequest {
            method: "POST".to_owned(),
            path_and_query: "/v1/messages".to_owned(),
            headers: vec![
                ("Host".to_owned(), "api.anthropic.com".to_owned()),
                ("Content-Length".to_owned(), "2".to_owned()),
            ],
            body: b"{}".to_vec(),
        };
        let stolen = MtlsProxyRequest {
            workload_id: "workload-a".to_owned(),
            guest_cid: 10,
            sni_hostname: "api.anthropic.com".to_owned(),
            port: 443,
            nonce: [0x55; 32],
            timestamp_ms: now_ms,
            raw_http_request: http.to_wire_bytes(),
        };
        let bytes = stolen.to_bytes().unwrap();
        tls.write_all(&(bytes.len() as u32).to_be_bytes())
            .await
            .unwrap();
        tls.write_all(&bytes).await.unwrap();
        tls.flush().await.unwrap();
    });

    let session = MtlsProxySession {
        tls_server_config: Arc::clone(&pki.proxy_server_cfg),
        policy_engine: Arc::clone(&engine),
        upstream_resolver: Arc::new(StaticEndpointResolver::single(
            "api.anthropic.com",
            443,
            upstream_addr,
        )),
        upstream_tls_config: Arc::clone(&pki.proxy_to_upstream_client_cfg),
        io_timeout: Duration::from_secs(2),
    };
    let (accepted_tcp, _) = proxy_listener.accept().await.unwrap();
    let err = handle_mtls_guest_connection(accepted_tcp, 10, &session, now_ms)
        .await
        .unwrap_err();
    rogue_guest.await.unwrap();

    assert!(matches!(
        err,
        ProxyError::Policy(PolicyError::CertificateThumbprintMismatch)
    ));
}

#[tokio::test]
async fn redteam_live_mtls_splice_and_upstream_secret_reflection_scrubbing() {
    let pki = build_ephemeral_pki();
    let raw_secret = b"sk-live-secret-999";
    let engine = Arc::new(build_test_engine(
        &pki.guest_a_cert_der,
        &pki.guest_b_cert_der,
        raw_secret,
    ));
    let now_ms = 1_762_000_000_000u64;

    // Spawn live TLS 1.3 mock upstream server for api.anthropic.com
    let upstream_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let upstream_addr = upstream_listener.local_addr().unwrap();
    let upstream_cfg = Arc::clone(&pki.upstream_server_cfg);

    let upstream_task = tokio::spawn(async move {
        let (tcp, _) = upstream_listener.accept().await.unwrap();
        let acceptor = TlsAcceptor::from(upstream_cfg);
        let mut tls = acceptor.accept(tcp).await.unwrap();

        let mut req_buf = Vec::new();
        let mut chunk = [0u8; 4096];
        loop {
            let n = tls.read(&mut chunk).await.unwrap();
            req_buf.extend_from_slice(&chunk[..n]);
            if req_buf.windows(4).any(|w| w == b"\r\n\r\n") {
                break;
            }
        }
        let req_text = String::from_utf8_lossy(&req_buf);
        // Confirm real secret WAS injected into upstream TLS 1.3 stream, guest's dummy token stripped,
        // and guest's Accept-Encoding: gzip replaced with Accept-Encoding: identity!
        assert!(req_text.contains("Authorization: Bearer sk-live-secret-999\r\n"));
        assert!(req_text.contains("Accept-Encoding: identity\r\n"));
        assert!(!req_text.contains("Accept-Encoding: gzip"));
        assert!(!req_text.contains("guest-dummy-token"));

        // Hostile/buggy upstream echoes injected Authorization header inside BOTH X-Echo header and 502 body!
        let reflected_body =
            "{\"error\":\"upstream_502\",\"received_auth\":\"Authorization: Bearer sk-live-secret-999\"}";
        let raw_resp = format!(
            "HTTP/1.1 502 Bad Gateway\r\nContent-Type: application/json\r\nX-Echo: Bearer sk-live-secret-999\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
            reflected_body.len(),
            reflected_body
        );
        tls.write_all(raw_resp.as_bytes()).await.unwrap();
        tls.shutdown().await.unwrap();
    });

    // Spawn Ring 2 guest over live mTLS 1.3 to locksmith-proxy
    let proxy_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let proxy_addr = proxy_listener.local_addr().unwrap();
    let guest_a_cfg = Arc::clone(&pki.guest_a_client_cfg);

    let guest_task = tokio::spawn(async move {
        let tcp = TcpStream::connect(proxy_addr).await.unwrap();
        let connector = TlsConnector::from(guest_a_cfg);
        let sni = ServerName::try_from("locksmith.internal").unwrap();
        let mut tls = connector.connect(sni, tcp).await.unwrap();

        let http = OutboundHttpRequest {
            method: "POST".to_owned(),
            path_and_query: "/v1/messages".to_owned(),
            headers: vec![
                ("Host".to_owned(), "api.anthropic.com".to_owned()),
                (
                    "Authorization".to_owned(),
                    "Bearer guest-dummy-token".to_owned(),
                ),
                ("Accept-Encoding".to_owned(), "gzip, br".to_owned()),
                ("Content-Type".to_owned(), "application/json".to_owned()),
                ("Content-Length".to_owned(), "13".to_owned()),
            ],
            body: b"{\"ping\":true}".to_vec(),
        };
        let proxy_req = MtlsProxyRequest {
            workload_id: "workload-a".to_owned(),
            guest_cid: 10,
            sni_hostname: "api.anthropic.com".to_owned(),
            port: 443,
            nonce: [0x77; 32],
            timestamp_ms: now_ms,
            raw_http_request: http.to_wire_bytes(),
        };
        let encoded = proxy_req.to_bytes().unwrap();
        tls.write_all(&(encoded.len() as u32).to_be_bytes())
            .await
            .unwrap();
        tls.write_all(&encoded).await.unwrap();
        tls.flush().await.unwrap();

        let mut relayed_wire = Vec::new();
        tls.read_to_end(&mut relayed_wire).await.unwrap();
        relayed_wire
    });

    let session = MtlsProxySession {
        tls_server_config: Arc::clone(&pki.proxy_server_cfg),
        policy_engine: Arc::clone(&engine),
        upstream_resolver: Arc::new(StaticEndpointResolver::single(
            "api.anthropic.com",
            443,
            upstream_addr,
        )),
        upstream_tls_config: Arc::clone(&pki.proxy_to_upstream_client_cfg),
        io_timeout: Duration::from_secs(5),
    };
    let (accepted_tcp, _) = proxy_listener.accept().await.unwrap();
    let sanitized = handle_mtls_guest_connection(accepted_tcp, 10, &session, now_ms)
        .await
        .unwrap();

    upstream_task.await.unwrap();
    let guest_received_bytes = guest_task.await.unwrap();
    let guest_received_str = std::str::from_utf8(&guest_received_bytes).unwrap();

    // Verify both structured SanitizedHttpResponse AND raw bytes received by Ring 2 guest
    assert_eq!(sanitized.status_code, 502);
    assert!(
        !guest_received_str.contains("sk-live-secret-999"),
        "ZERO raw secret bytes may ever cross back into Ring 2"
    );
    assert!(
        guest_received_str.contains("X-Echo: Bearer [REDACTED_BY_LOCKSMITH]\r\n"),
        "X-Echo response header must be scrubbed"
    );
    let body_str = std::str::from_utf8(&sanitized.body).unwrap();
    assert!(!body_str.contains("sk-live-secret-999"));
    assert!(body_str.contains("[REDACTED_BY_LOCKSMITH]"));
}

#[test]
fn redteam_path_segment_boundary_double_encoding_and_shifted_base64_scrubbing() {
    use locksmith_proxy::{scrub_secret_reflections, SCRUB_REPLACEMENT_TOKEN};

    // 1. Origin-target must reject double-encoded dot traversal (%252e), empty internal segments (//),
    //    matrix path parameters (;), and URI fragments (#)
    for hostile_wire in [
        b"POST /v1/%252e%252e/admin HTTP/1.1\r\nHost: api.anthropic.com\r\n\r\n".as_slice(),
        b"POST /v1//messages HTTP/1.1\r\nHost: api.anthropic.com\r\n\r\n".as_slice(),
        b"POST /v1/messages;admin=true HTTP/1.1\r\nHost: api.anthropic.com\r\n\r\n".as_slice(),
        b"POST /v1/messages#fragment HTTP/1.1\r\nHost: api.anthropic.com\r\n\r\n".as_slice(),
    ] {
        assert!(
            matches!(
                OutboundHttpRequest::from_wire_bytes(hostile_wire),
                Err(PolicyError::MalformedHttpRequest { .. })
            ),
            "hostile origin-target {:?} must fail closed",
            String::from_utf8_lossy(hostile_wire)
        );
    }

    // 2. Path prefix without trailing slash ("/v1/messages") MUST NOT match sibling "/v1/messages_admin"
    let pki = build_ephemeral_pki();
    let unwrapper = Arc::new(SecretUnwrapper::new(
        HostShare::from_bytes([0x41; 32]),
        SoftwareTestHsm::new([0x42; 32]),
    ));
    let replay = Arc::new(ReplayFilter::with_defaults(64).unwrap());
    let mut exact_seg_rule = EgressRule {
        sni_hostname: "api.anthropic.com".to_owned(),
        port: 443,
        allowed_methods: vec!["POST".to_owned()],
        path_prefix: "/v1/messages".to_owned(),
        secret_id: "anthropic/messages-only".to_owned(),
        sealed_envelope: anvil_core::unwrap::SealedSecretEnvelope {
            version: 1,
            hkdf_salt: [0; 32],
            nonce: [0; 12],
            ciphertext_and_tag: vec![0; 16],
        },
        injection_header_name: "Authorization".to_owned(),
        injection_value_prefix: "Bearer ".to_owned(),
        guest_auth_mode: GuestAuthHeaderMode::Strip,
    };
    let p_hash = exact_seg_rule.policy_hash();
    exact_seg_rule.sealed_envelope = unwrapper
        .seal(
            b"sk-live-secret-999",
            &UnwrapAad {
                secret_id: "anthropic/messages-only",
                policy_hash: p_hash,
                guest_cid: 10,
            },
        )
        .unwrap();

    let strict_engine = PolicyEngine::new(
        vec![WorkloadIdentity {
            workload_id: "workload-a".to_owned(),
            guest_cid: 10,
            cert_thumbprint_sha256: compute_cert_thumbprint_sha256(&pki.guest_a_cert_der),
            rules: vec![exact_seg_rule],
        }],
        replay,
        unwrapper,
    );

    let now_ms = 1_762_000_000_000u64;
    let sibling_bypass = strict_engine.authorize_egress(EgressAuthorizationInput {
        workload_id: "workload-a",
        guest_cid: 10,
        peer_cert_der: &pki.guest_a_cert_der,
        sni_hostname: "api.anthropic.com",
        port: 443,
        nonce: [0x81; 32],
        timestamp_ms: now_ms,
        now_ms,
        request: OutboundHttpRequest {
            method: "POST".to_owned(),
            path_and_query: "/v1/messages_admin".to_owned(),
            headers: vec![("Host".to_owned(), "api.anthropic.com".to_owned())],
            body: Vec::new(),
        },
    });
    assert_eq!(
        sibling_bypass.unwrap_err(),
        PolicyError::TargetNotAllowed,
        "/v1/messages_admin must NOT match rule path_prefix /v1/messages"
    );

    // 3. Shifted Base64 reflection scrubbing across ALL 3 alignments:
    //    - "Bearer sk-live-secret-999" -> secret starts at byte 7 (1 mod 3)!
    //    - "Auth:   sk-live-secret-999" -> secret starts at byte 8 (2 mod 3)!
    let secret = b"sk-live-secret-999";
    let b64_offset_1 = b"echo_1mod3=QmVhcmVyIHNrLWxpdmUtc2VjcmV0LTk5OQ==";
    let scrubbed_1 = scrub_secret_reflections(b64_offset_1, secret);
    assert!(
        scrubbed_1 != b64_offset_1,
        "1-mod-3 shifted Base64 ('Bearer <secret>') MUST be scrubbed"
    );
    assert!(scrubbed_1
        .windows(SCRUB_REPLACEMENT_TOKEN.len())
        .any(|w| w == SCRUB_REPLACEMENT_TOKEN));

    let b64_offset_2 = b"echo_2mod3=QXV0aDogICBza2-nope QXV0aDogICBzay1saXZlLXNlY3JldC05OTk=";
    let scrubbed_2 = scrub_secret_reflections(b64_offset_2, secret);
    assert!(
        !scrubbed_2
            .windows(b"ay1saXZlLXNlY3JldC05OTk".len())
            .any(|w| w == b"ay1saXZlLXNlY3JldC05OTk"),
        "2-mod-3 shifted Base64 ('Auth:   <secret>') MUST be scrubbed"
    );

    // 4. Single-pass self-matching immunity when secret contains replacement marker substring
    let tricky_secret = b"LOCKSMITH_SECRET_KEY_1234";
    let tricky_echo = b"leaked: LOCKSMITH_SECRET_KEY_1234!";
    let tricky_scrubbed = scrub_secret_reflections(tricky_echo, tricky_secret);
    assert_eq!(tricky_scrubbed, b"leaked: [REDACTED_BY_LOCKSMITH]!");
}

#[tokio::test]
async fn redteam_transport_cid_spoof_port_pinning_and_policy_hash_mode_binding() {
    let pki = build_ephemeral_pki();
    let engine = Arc::new(build_test_engine(
        &pki.guest_a_cert_der,
        &pki.guest_b_cert_der,
        b"sk-live-secret-999",
    ));
    let now_ms = 1_762_000_000_000u64;

    // 1. Transport peer authenticated as CID 20 spoofing guest_cid=10 in MtlsProxyRequest MUST fail closed
    let upstream_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let upstream_addr = upstream_listener.local_addr().unwrap();
    let (guest_client_io, proxy_server_io) = tokio::io::duplex(32_768);

    let guest_a_cfg = Arc::clone(&pki.guest_a_client_cfg);
    let spoof_client = tokio::spawn(async move {
        let connector = TlsConnector::from(guest_a_cfg);
        let sni = ServerName::try_from("locksmith.internal").unwrap();
        let mut tls = connector.connect(sni, guest_client_io).await.unwrap();
        let http = OutboundHttpRequest {
            method: "POST".to_owned(),
            path_and_query: "/v1/messages".to_owned(),
            headers: vec![
                ("Host".to_owned(), "api.anthropic.com".to_owned()),
                ("Content-Length".to_owned(), "2".to_owned()),
            ],
            body: b"{}".to_vec(),
        };
        let req = MtlsProxyRequest {
            workload_id: "workload-a".to_owned(),
            guest_cid: 10, // Spoofed! Transport peer is CID 20!
            sni_hostname: "api.anthropic.com".to_owned(),
            port: 443,
            nonce: [0xA1; 32],
            timestamp_ms: now_ms,
            raw_http_request: http.to_wire_bytes(),
        };
        let encoded = req.to_bytes().unwrap();
        tls.write_all(&(encoded.len() as u32).to_be_bytes())
            .await
            .unwrap();
        tls.write_all(&encoded).await.unwrap();
        tls.flush().await.unwrap();
        let mut drain = [0u8; 16];
        let _ = tls.read(&mut drain).await;
    });

    let session = MtlsProxySession {
        tls_server_config: Arc::clone(&pki.proxy_server_cfg),
        policy_engine: Arc::clone(&engine),
        upstream_resolver: Arc::new(StaticEndpointResolver::single(
            "api.anthropic.com",
            443,
            upstream_addr,
        )),
        upstream_tls_config: Arc::clone(&pki.proxy_to_upstream_client_cfg),
        io_timeout: Duration::from_secs(2),
    };
    let cid_err = handle_mtls_guest_connection(proxy_server_io, 20, &session, now_ms)
        .await
        .unwrap_err();
    spoof_client.await.unwrap();
    assert!(
        matches!(
            cid_err,
            ProxyError::Policy(PolicyError::GuestCidMismatch {
                expected: 20,
                actual: 10
            })
        ),
        "unexpected cid_err: {cid_err:?}"
    );

    // 2. StaticEndpointResolver MUST reject verified_port mismatch (443 vs 8443)
    let ticket = engine
        .authorize_egress(EgressAuthorizationInput {
            workload_id: "workload-a",
            guest_cid: 10,
            peer_cert_der: &pki.guest_a_cert_der,
            sni_hostname: "api.anthropic.com",
            port: 443,
            nonce: [0xA2; 32],
            timestamp_ms: now_ms,
            now_ms,
            request: OutboundHttpRequest {
                method: "POST".to_owned(),
                path_and_query: "/v1/messages".to_owned(),
                headers: vec![("Host".to_owned(), "api.anthropic.com".to_owned())],
                body: Vec::new(),
            },
        })
        .unwrap();
    let wrong_port_resolver =
        StaticEndpointResolver::single("api.anthropic.com", 8443, upstream_addr);
    let port_err = splice_outbound_request(
        ticket,
        &wrong_port_resolver,
        Arc::clone(&pki.proxy_to_upstream_client_cfg),
        Duration::from_secs(1),
    )
    .await
    .unwrap_err();
    assert!(matches!(
        port_err,
        ProxyError::Policy(PolicyError::TargetNotAllowed)
    ));

    // 3. EgressRule::policy_hash MUST bind guest_auth_mode (Reject != Strip)
    let rule_reject = EgressRule {
        sni_hostname: "api.anthropic.com".to_owned(),
        port: 443,
        allowed_methods: vec!["POST".to_owned()],
        path_prefix: "/v1/".to_owned(),
        secret_id: "anthropic/live".to_owned(),
        sealed_envelope: anvil_core::unwrap::SealedSecretEnvelope {
            version: 1,
            hkdf_salt: [0; 32],
            nonce: [0; 12],
            ciphertext_and_tag: vec![0; 16],
        },
        injection_header_name: "Authorization".to_owned(),
        injection_value_prefix: "Bearer ".to_owned(),
        guest_auth_mode: GuestAuthHeaderMode::Reject,
    };
    let mut rule_strip = rule_reject.clone();
    rule_strip.guest_auth_mode = GuestAuthHeaderMode::Strip;
    assert_ne!(
        rule_reject.policy_hash(),
        rule_strip.policy_hash(),
        "mutating guest_auth_mode MUST alter policy_hash so AEAD AAD unwrap fails"
    );
}
