use std::collections::HashMap;
use std::sync::Arc;

use anvil_core::replay::ReplayFilter;
use anvil_core::unwrap::{HardwareUnwrapper, SealedSecretEnvelope, SecretBytes, SecretUnwrapper};
use aws_lc_rs::digest::{digest, SHA256};
use zeroize::Zeroizing;

use crate::error::PolicyError;
use crate::ticket::ApprovedEgressTicket;

/// Policy disposition when an untrusted guest supplies `Authorization` or
/// `Proxy-Authorization` headers on an outbound request.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum GuestAuthHeaderMode {
    /// Deterministically reject the request with [`PolicyError::ForbiddenGuestAuthHeader`].
    Reject,
    /// Strip guest-supplied `Authorization` and `Proxy-Authorization` headers prior to injection.
    Strip,
}

/// Static allowlist rule binding a workload to a specific upstream endpoint and sealed credential.
#[derive(Clone, Debug)]
pub struct EgressRule {
    pub sni_hostname: String,
    pub port: u16,
    pub allowed_methods: Vec<String>,
    pub path_prefix: String,
    pub secret_id: String,
    pub sealed_envelope: SealedSecretEnvelope,
    pub injection_header_name: String,
    pub injection_value_prefix: String,
    pub guest_auth_mode: GuestAuthHeaderMode,
}

impl EgressRule {
    /// Computes the deterministic 32-byte `BLAKE3` policy hash bound into
    /// [`anvil_core::unwrap::UnwrapAad`].
    #[must_use]
    pub fn policy_hash(&self) -> [u8; 32] {
        let mut sorted_methods = self.allowed_methods.clone();
        sorted_methods.sort();

        let mut hasher = blake3::Hasher::new();
        hasher.update(b"LOCKSMITH-POLICY-RULE-V1");
        hasher.update(&(self.sni_hostname.len() as u32).to_be_bytes());
        hasher.update(self.sni_hostname.as_bytes());
        hasher.update(&self.port.to_be_bytes());
        hasher.update(&(sorted_methods.len() as u32).to_be_bytes());
        for m in &sorted_methods {
            hasher.update(&(m.len() as u32).to_be_bytes());
            hasher.update(m.as_bytes());
        }
        hasher.update(&(self.path_prefix.len() as u32).to_be_bytes());
        hasher.update(self.path_prefix.as_bytes());
        hasher.update(&(self.secret_id.len() as u32).to_be_bytes());
        hasher.update(self.secret_id.as_bytes());
        hasher.update(&(self.injection_header_name.len() as u32).to_be_bytes());
        hasher.update(self.injection_header_name.as_bytes());
        hasher.update(&(self.injection_value_prefix.len() as u32).to_be_bytes());
        hasher.update(self.injection_value_prefix.as_bytes());
        *hasher.finalize().as_bytes()
    }
}

/// Registered Ring 2 workload identity bound to an RFC 8705 mTLS certificate thumbprint.
#[derive(Clone, Debug)]
pub struct WorkloadIdentity {
    pub workload_id: String,
    pub guest_cid: u32,
    pub cert_thumbprint_sha256: [u8; 32],
    pub rules: Vec<EgressRule>,
}

/// Outbound HTTP/1.1 request submitted by a Ring 2 guest.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct OutboundHttpRequest {
    pub method: String,
    pub path_and_query: String,
    pub headers: Vec<(String, String)>,
    pub body: Vec<u8>,
}

/// Maximum raw HTTP/1.1 wire request size accepted from a Ring 2 guest (`256 KiB`).
pub const MAX_HTTP_WIRE_BYTES: usize = 262_144;

const fn is_tchar(b: u8) -> bool {
    matches!(
        b,
        b'!' | b'#' | b'$' | b'%' | b'&' | b'\'' | b'*' | b'+' | b'-' | b'.'
            | b'^' | b'_' | b'`' | b'|' | b'~' | b'0'..=b'9' | b'A'..=b'Z' | b'a'..=b'z'
    )
}

fn validate_header_name(name: &str) -> Result<(), PolicyError> {
    if name.is_empty() {
        return Err(PolicyError::HeaderSmugglingDetected {
            reason: "empty HTTP header name",
        });
    }
    if !name.bytes().all(is_tchar) {
        return Err(PolicyError::HeaderSmugglingDetected {
            reason: "illegal non-tchar byte or whitespace in HTTP header name",
        });
    }
    Ok(())
}

fn validate_header_value(value: &str) -> Result<(), PolicyError> {
    for b in value.bytes() {
        if b == b'\r' || b == b'\n' || b == 0x00 {
            return Err(PolicyError::HeaderSmugglingDetected {
                reason: "CR, LF, or NUL byte in HTTP header value",
            });
        }
        if (b < 0x20 && b != b'\t') || b == 0x7F {
            return Err(PolicyError::HeaderSmugglingDetected {
                reason: "control character in HTTP header value",
            });
        }
    }
    Ok(())
}

fn contains_encoded_traversal(s: &str) -> bool {
    let bytes = s.as_bytes();
    let mut i = 0;
    while i + 2 < bytes.len() {
        if bytes[i] == b'%' {
            let hi = bytes[i + 1].to_ascii_lowercase();
            let lo = bytes[i + 2].to_ascii_lowercase();
            // Reject %2e ('.'), %2f ('/'), %5c ('\\'), and %00 (NUL)
            if (hi == b'2' && (lo == b'e' || lo == b'f'))
                || (hi == b'5' && lo == b'c')
                || (hi == b'0' && lo == b'0')
            {
                return true;
            }
        }
        i += 1;
    }
    false
}

fn validate_method(method: &str) -> Result<String, PolicyError> {
    if method.is_empty() || !method.bytes().all(is_tchar) {
        return Err(PolicyError::MalformedHttpRequest {
            reason: "invalid HTTP method token",
        });
    }
    Ok(method.to_ascii_uppercase())
}

fn validate_origin_target(target: &str) -> Result<&str, PolicyError> {
    if !target.starts_with('/') || target.starts_with("//") {
        return Err(PolicyError::MalformedHttpRequest {
            reason: "HTTP request-target must be origin-form starting with single '/'",
        });
    }
    for b in target.bytes() {
        if b <= 0x20 || b >= 0x7F || b == b'\\' {
            return Err(PolicyError::MalformedHttpRequest {
                reason: "illegal control, whitespace, or backslash byte in request-target",
            });
        }
    }
    let path_only = target.split('?').next().unwrap_or(target);
    if contains_encoded_traversal(path_only) {
        return Err(PolicyError::MalformedHttpRequest {
            reason: "percent-encoded traversal sequence in request path",
        });
    }
    for seg in path_only.split('/') {
        if seg == "." || seg == ".." {
            return Err(PolicyError::MalformedHttpRequest {
                reason: "dot-segment traversal in request path",
            });
        }
    }
    Ok(path_only)
}

fn validate_dns_sni(sni: &str) -> Result<String, PolicyError> {
    if sni.is_empty() || sni.len() > 253 || sni.starts_with('.') || sni.ends_with('.') {
        return Err(PolicyError::TargetNotAllowed);
    }
    for label in sni.split('.') {
        if label.is_empty()
            || label.len() > 63
            || label.starts_with('-')
            || label.ends_with('-')
            || !label
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || b == b'-')
        {
            return Err(PolicyError::TargetNotAllowed);
        }
    }
    Ok(sni.to_ascii_lowercase())
}

fn validate_framing_headers(
    headers: &[(String, String)],
    body_len: usize,
) -> Result<(), PolicyError> {
    let mut parsed_content_length: Option<usize> = None;

    for (name, val) in headers {
        if name.eq_ignore_ascii_case("transfer-encoding") {
            return Err(PolicyError::ConflictingFramingHeaders);
        }
        if name.eq_ignore_ascii_case("content-length") {
            if parsed_content_length.is_some() {
                return Err(PolicyError::ConflictingFramingHeaders);
            }
            let trimmed = val.trim_matches(|c| c == ' ' || c == '\t');
            if trimmed.is_empty() || !trimmed.bytes().all(|b| b.is_ascii_digit()) {
                return Err(PolicyError::ConflictingFramingHeaders);
            }
            let len = trimmed
                .parse::<usize>()
                .map_err(|_| PolicyError::ConflictingFramingHeaders)?;
            parsed_content_length = Some(len);
        }
    }

    match parsed_content_length {
        Some(expected_len) if expected_len != body_len => {
            Err(PolicyError::ConflictingFramingHeaders)
        }
        None if body_len > 0 => Err(PolicyError::ConflictingFramingHeaders),
        _ => Ok(()),
    }
}

fn find_header_end(raw: &[u8]) -> Option<usize> {
    raw.windows(4).position(|w| w == b"\r\n\r\n")
}

fn verify_strict_crlf_headers(header_block_with_crlf: &[u8]) -> Result<(), PolicyError> {
    let mut i = 0;
    while i < header_block_with_crlf.len() {
        let b = header_block_with_crlf[i];
        if b == 0x00 {
            return Err(PolicyError::HeaderSmugglingDetected {
                reason: "NUL byte in raw HTTP header block",
            });
        }
        if b == b'\r' {
            if header_block_with_crlf.get(i + 1) != Some(&b'\n') {
                return Err(PolicyError::HeaderSmugglingDetected {
                    reason: "bare CR without LF in HTTP header block",
                });
            }
            i += 2;
            continue;
        }
        if b == b'\n' {
            return Err(PolicyError::HeaderSmugglingDetected {
                reason: "bare LF without CR in HTTP header block",
            });
        }
        i += 1;
    }
    Ok(())
}

impl OutboundHttpRequest {
    /// Parses a raw HTTP/1.1 wire buffer under strict RFC 9110/9112 framing rules.
    pub fn from_wire_bytes(raw: &[u8]) -> Result<Self, PolicyError> {
        if raw.is_empty() || raw.len() > MAX_HTTP_WIRE_BYTES {
            return Err(PolicyError::MalformedHttpRequest {
                reason: "empty or oversized raw HTTP request",
            });
        }

        let header_end = find_header_end(raw).ok_or(PolicyError::MalformedHttpRequest {
            reason: "missing CRLFCRLF header terminator",
        })?;

        // Include the first trailing CRLF so every header line ends with CRLF
        verify_strict_crlf_headers(&raw[..header_end + 2])?;

        let header_str = std::str::from_utf8(&raw[..header_end]).map_err(|_| {
            PolicyError::MalformedHttpRequest {
                reason: "non-UTF-8 bytes in HTTP request header block",
            }
        })?;

        let mut lines = header_str.split("\r\n");
        let request_line = lines.next().ok_or(PolicyError::MalformedHttpRequest {
            reason: "missing HTTP request line",
        })?;

        let parts: Vec<&str> = request_line.split(' ').collect();
        if parts.len() != 3 {
            return Err(PolicyError::MalformedHttpRequest {
                reason: "HTTP request line must contain exact single-space delimiters",
            });
        }
        if parts[2] != "HTTP/1.1" {
            return Err(PolicyError::MalformedHttpRequest {
                reason: "HTTP version must equal HTTP/1.1",
            });
        }

        let method = validate_method(parts[0])?;
        let _ = validate_origin_target(parts[1])?;
        let path_and_query = parts[1].to_owned();

        let mut headers = Vec::new();
        for line in lines {
            if line.is_empty() {
                return Err(PolicyError::MalformedHttpRequest {
                    reason: "unexpected empty line inside HTTP header block",
                });
            }
            if line.starts_with(' ') || line.starts_with('\t') {
                return Err(PolicyError::HeaderSmugglingDetected {
                    reason: "RFC 9112 obs-fold multiline header rejected",
                });
            }
            let (raw_name, raw_val) =
                line.split_once(':')
                    .ok_or(PolicyError::MalformedHttpRequest {
                        reason: "HTTP header line missing ':' delimiter",
                    })?;
            validate_header_name(raw_name)?;
            let trimmed_val = raw_val.trim_matches(|c| c == ' ' || c == '\t');
            validate_header_value(trimmed_val)?;
            headers.push((raw_name.to_owned(), trimmed_val.to_owned()));
        }

        let body = raw[header_end + 4..].to_vec();
        validate_framing_headers(&headers, body.len())?;

        Ok(Self {
            method,
            path_and_query,
            headers,
            body,
        })
    }

    /// Encodes the request into wire HTTP/1.1 bytes (used by test clients).
    #[must_use]
    pub fn to_wire_bytes(&self) -> Vec<u8> {
        let mut out = Vec::new();
        out.extend_from_slice(self.method.as_bytes());
        out.push(b' ');
        out.extend_from_slice(self.path_and_query.as_bytes());
        out.extend_from_slice(b" HTTP/1.1\r\n");
        for (name, val) in &self.headers {
            out.extend_from_slice(name.as_bytes());
            out.extend_from_slice(b": ");
            out.extend_from_slice(val.as_bytes());
            out.extend_from_slice(b"\r\n");
        }
        out.extend_from_slice(b"\r\n");
        out.extend_from_slice(&self.body);
        out
    }
}

/// Input bundle evaluated by [`PolicyEngine::authorize_egress`].
pub struct EgressAuthorizationInput<'a> {
    pub workload_id: &'a str,
    pub guest_cid: u32,
    pub peer_cert_der: &'a [u8],
    pub sni_hostname: &'a str,
    pub port: u16,
    pub nonce: [u8; 32],
    pub timestamp_ms: u64,
    pub now_ms: u64,
    pub request: OutboundHttpRequest,
}

/// Computes the RFC 8705 SHA-256 certificate thumbprint (`x5t#S256`) over DER bytes.
#[must_use]
pub fn compute_cert_thumbprint_sha256(cert_der: &[u8]) -> [u8; 32] {
    let d = digest(&SHA256, cert_der);
    let mut out = [0u8; 32];
    out.copy_from_slice(d.as_ref());
    out
}

/// Zero-trust policy gate that mints [`ApprovedEgressTicket`]s iff all identity,
/// allowlist, HTTP canonicalization, replay, and 2-of-2 unwrap checks succeed.
pub struct PolicyEngine<H: HardwareUnwrapper> {
    workloads: HashMap<String, WorkloadIdentity>,
    replay_filter: Arc<ReplayFilter>,
    unwrapper: Arc<SecretUnwrapper<H>>,
}

impl<H: HardwareUnwrapper> PolicyEngine<H> {
    /// Creates a new [`PolicyEngine`] with static workload rules.
    #[must_use]
    pub fn new(
        workloads: Vec<WorkloadIdentity>,
        replay_filter: Arc<ReplayFilter>,
        unwrapper: Arc<SecretUnwrapper<H>>,
    ) -> Self {
        let mut map = HashMap::with_capacity(workloads.len());
        for w in workloads {
            map.insert(w.workload_id.clone(), w);
        }
        Self {
            workloads: map,
            replay_filter,
            unwrapper,
        }
    }

    /// Validates all 5 security gates and mints a single-use [`ApprovedEgressTicket`].
    pub fn authorize_egress(
        &self,
        input: EgressAuthorizationInput<'_>,
    ) -> Result<ApprovedEgressTicket, PolicyError> {
        // Gate 1: Peer mTLS leaf certificate presence, RFC 8705 thumbprint, and guest CID
        if input.peer_cert_der.is_empty() {
            return Err(PolicyError::MissingClientCertificate);
        }
        let workload = self
            .workloads
            .get(input.workload_id)
            .ok_or(PolicyError::UnknownWorkload)?;

        let presented_thumbprint = compute_cert_thumbprint_sha256(input.peer_cert_der);
        if aws_lc_rs::constant_time::verify_slices_are_equal(
            &presented_thumbprint,
            &workload.cert_thumbprint_sha256,
        )
        .is_err()
        {
            return Err(PolicyError::CertificateThumbprintMismatch);
        }

        if input.guest_cid != workload.guest_cid {
            return Err(PolicyError::GuestCidMismatch {
                expected: workload.guest_cid,
                actual: input.guest_cid,
            });
        }

        // Gate 2: RFC 9110/9112 syntax, header smuggling, framing, and Host == Verified SNI
        if input.port == 0 || input.request.body.len() > MAX_HTTP_WIRE_BYTES {
            return Err(PolicyError::TargetNotAllowed);
        }
        let normalized_sni = validate_dns_sni(input.sni_hostname)?;
        let normalized_method = validate_method(&input.request.method)?;
        let normalized_path = validate_origin_target(&input.request.path_and_query)?;

        for (name, val) in &input.request.headers {
            validate_header_name(name)?;
            validate_header_value(val)?;
        }
        validate_framing_headers(&input.request.headers, input.request.body.len())?;

        // Enforce strictly ONE Host header matching verified SNI (defeating domain fronting)
        let mut seen_host: Option<&str> = None;
        for (name, val) in &input.request.headers {
            if name.eq_ignore_ascii_case("host") {
                if seen_host.is_some() {
                    return Err(PolicyError::HostSniMismatch);
                }
                seen_host = Some(val.trim_matches(|c| c == ' ' || c == '\t'));
            }
        }
        let raw_host = seen_host.ok_or(PolicyError::HostSniMismatch)?;
        let host_lower = raw_host.to_ascii_lowercase();
        let sni_with_port = format!("{normalized_sni}:{}", input.port);
        if host_lower != normalized_sni && host_lower != sni_with_port {
            return Err(PolicyError::HostSniMismatch);
        }

        // Gate 3: Static workload egress allowlist match
        let rule = workload
            .rules
            .iter()
            .find(|r| {
                r.sni_hostname.eq_ignore_ascii_case(&normalized_sni)
                    && r.port == input.port
                    && r.allowed_methods
                        .iter()
                        .any(|m| m.eq_ignore_ascii_case(&normalized_method))
                    && normalized_path.starts_with(&r.path_prefix)
            })
            .ok_or(PolicyError::TargetNotAllowed)?;

        validate_header_name(&rule.injection_header_name)?;
        validate_header_value(&rule.injection_value_prefix)?;

        let canonical_host = if input.port == 443 {
            normalized_sni.clone()
        } else {
            sni_with_port
        };

        let mut canonical_prefix = Vec::with_capacity(256);
        canonical_prefix.extend_from_slice(normalized_method.as_bytes());
        canonical_prefix.push(b' ');
        canonical_prefix.extend_from_slice(input.request.path_and_query.as_bytes());
        canonical_prefix.extend_from_slice(b" HTTP/1.1\r\nHost: ");
        canonical_prefix.extend_from_slice(canonical_host.as_bytes());
        canonical_prefix.extend_from_slice(b"\r\n");

        for (name, val) in &input.request.headers {
            if name.eq_ignore_ascii_case("host")
                || name.eq_ignore_ascii_case("content-length")
                || name.eq_ignore_ascii_case("connection")
            {
                continue;
            }
            if name.eq_ignore_ascii_case("authorization")
                || name.eq_ignore_ascii_case("proxy-authorization")
                || name.eq_ignore_ascii_case(&rule.injection_header_name)
            {
                match rule.guest_auth_mode {
                    GuestAuthHeaderMode::Reject => {
                        return Err(PolicyError::ForbiddenGuestAuthHeader);
                    }
                    GuestAuthHeaderMode::Strip => continue,
                }
            }
            let trimmed_val = val.trim_matches(|c| c == ' ' || c == '\t');
            canonical_prefix.extend_from_slice(name.as_bytes());
            canonical_prefix.extend_from_slice(b": ");
            canonical_prefix.extend_from_slice(trimmed_val.as_bytes());
            canonical_prefix.extend_from_slice(b"\r\n");
        }

        let cl_line = format!(
            "Content-Length: {}\r\nConnection: close\r\n",
            input.request.body.len()
        );
        canonical_prefix.extend_from_slice(cl_line.as_bytes());

        // Gate 4: Atomic single-use nonce freshness & burn
        self.replay_filter
            .check_and_burn(input.nonce, input.timestamp_ms, input.now_ms)?;

        // Gate 5: 2-of-2 hardware-attested AEAD credential unwrap
        let policy_hash = rule.policy_hash();
        let aad = anvil_core::unwrap::UnwrapAad {
            secret_id: &rule.secret_id,
            policy_hash,
            guest_cid: workload.guest_cid,
        };
        let raw_secret: SecretBytes = self
            .unwrapper
            .unwrap_envelope(&rule.sealed_envelope, &aad)?;

        let secret_str = std::str::from_utf8(raw_secret.expose_secret())
            .map_err(|_| anvil_core::CryptoError::AuthenticationFailed)?;
        validate_header_value(secret_str)?;

        let mut header_val =
            String::with_capacity(rule.injection_value_prefix.len() + secret_str.len());
        header_val.push_str(&rule.injection_value_prefix);
        header_val.push_str(secret_str);
        let injection_header_value = Zeroizing::new(header_val);

        Ok(ApprovedEgressTicket::mint(
            workload.workload_id.clone(),
            workload.guest_cid,
            normalized_sni,
            input.port,
            canonical_prefix,
            input.request.body,
            rule.injection_header_name.clone(),
            injection_header_value,
            raw_secret,
        ))
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;
    use anvil_core::unwrap::{HostShare, SoftwareTestHsm, UnwrapAad};

    #[test]
    fn authorizes_valid_request_and_strips_guest_auth_when_configured() {
        let unwrapper = Arc::new(SecretUnwrapper::new(
            HostShare::from_bytes([0x11; 32]),
            SoftwareTestHsm::new([0x22; 32]),
        ));
        let replay = Arc::new(ReplayFilter::with_defaults(64).unwrap());

        let fake_cert_der = b"mock-der-bytes-for-unit-test";
        let thumbprint = compute_cert_thumbprint_sha256(fake_cert_der);

        let mut placeholder_rule = EgressRule {
            sni_hostname: "api.anthropic.com".to_owned(),
            port: 443,
            allowed_methods: vec!["POST".to_owned()],
            path_prefix: "/v1/".to_owned(),
            secret_id: "anthropic/prod".to_owned(),
            sealed_envelope: SealedSecretEnvelope {
                version: 1,
                hkdf_salt: [0; 32],
                nonce: [0; 12],
                ciphertext_and_tag: vec![0; 16],
            },
            injection_header_name: "Authorization".to_owned(),
            injection_value_prefix: "Bearer ".to_owned(),
            guest_auth_mode: GuestAuthHeaderMode::Strip,
        };
        let p_hash = placeholder_rule.policy_hash();
        placeholder_rule.sealed_envelope = unwrapper
            .seal(
                b"sk-ant-real-key",
                &UnwrapAad {
                    secret_id: "anthropic/prod",
                    policy_hash: p_hash,
                    guest_cid: 5,
                },
            )
            .unwrap();

        let engine = PolicyEngine::new(
            vec![WorkloadIdentity {
                workload_id: "agent-alpha".to_owned(),
                guest_cid: 5,
                cert_thumbprint_sha256: thumbprint,
                rules: vec![placeholder_rule],
            }],
            replay,
            unwrapper,
        );

        let now = 1_762_000_000_000u64;
        let req = OutboundHttpRequest {
            method: "POST".to_owned(),
            path_and_query: "/v1/messages".to_owned(),
            headers: vec![
                ("Host".to_owned(), "api.anthropic.com".to_owned()),
                (
                    "Authorization".to_owned(),
                    "Bearer guest-placeholder".to_owned(),
                ),
                ("Content-Type".to_owned(), "application/json".to_owned()),
                ("Content-Length".to_owned(), "2".to_owned()),
            ],
            body: b"{}".to_vec(),
        };

        let ticket = engine
            .authorize_egress(EgressAuthorizationInput {
                workload_id: "agent-alpha",
                guest_cid: 5,
                peer_cert_der: fake_cert_der,
                sni_hostname: "api.anthropic.com",
                port: 443,
                nonce: [0x99; 32],
                timestamp_ms: now,
                now_ms: now,
                request: req,
            })
            .unwrap();

        assert_eq!(ticket.verified_sni(), "api.anthropic.com");
        assert_eq!(ticket.verified_port(), 443);
        assert!(!format!("{ticket:?}").contains("sk-ant-real-key"));
    }

    #[test]
    fn rejects_bare_lf_obs_fold_and_encoded_dot_traversal() {
        let bare_lf = b"GET /v1/models HTTP/1.1\nHost: api.anthropic.com\r\n\r\n";
        assert!(matches!(
            OutboundHttpRequest::from_wire_bytes(bare_lf).unwrap_err(),
            PolicyError::HeaderSmugglingDetected { .. }
        ));

        let obs_fold =
            b"GET /v1/models HTTP/1.1\r\nHost: api.anthropic.com\r\n continued: evil\r\n\r\n";
        assert!(matches!(
            OutboundHttpRequest::from_wire_bytes(obs_fold).unwrap_err(),
            PolicyError::HeaderSmugglingDetected { .. }
        ));

        let encoded_traversal = b"GET /v1/%2e%2e/admin HTTP/1.1\r\nHost: api.anthropic.com\r\n\r\n";
        assert!(matches!(
            OutboundHttpRequest::from_wire_bytes(encoded_traversal).unwrap_err(),
            PolicyError::MalformedHttpRequest { .. }
        ));
    }
}
