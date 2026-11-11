use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use anvil_core::unwrap::HardwareUnwrapper;
use rustls::pki_types::ServerName;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio_rustls::{TlsAcceptor, TlsConnector};
use zeroize::Zeroizing;

use crate::error::{PolicyError, ProxyError};
use crate::policy::{
    EgressAuthorizationInput, OutboundHttpRequest, PolicyEngine, MAX_HTTP_WIRE_BYTES,
};
use crate::ticket::ApprovedEgressTicket;

/// Replacement marker substituted whenever upstream echoes raw or encoded secret bytes.
pub const SCRUB_REPLACEMENT_TOKEN: &[u8] = b"[REDACTED_BY_LOCKSMITH]";

/// Maximum inner mTLS proxy request envelope size (`512 KiB`).
pub const MAX_MTLS_ENVELOPE_BYTES: usize = 524_288;

/// Maximum upstream HTTP response size buffered in Ring 1 (`4 MiB`).
pub const MAX_UPSTREAM_RESPONSE_BYTES: usize = 4 * 1024 * 1024;

const PROXY_MAGIC: [u8; 4] = *b"LKPX";
const PROXY_VERSION: u8 = 1;

const BASE64_STD: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
const BASE64_URL: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";

/// Sanitized upstream HTTP/1.1 response safe to cross back into Ring 2.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SanitizedHttpResponse {
    pub status_code: u16,
    pub reason_phrase: String,
    pub headers: Vec<(String, String)>,
    pub body: Vec<u8>,
    pub raw_wire_bytes: Vec<u8>,
}

/// Framed egress proxy request sent over the inner Ring 2 -> Ring 1 mTLS stream.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct MtlsProxyRequest {
    pub workload_id: String,
    pub guest_cid: u32,
    pub sni_hostname: String,
    pub port: u16,
    pub nonce: [u8; 32],
    pub timestamp_ms: u64,
    pub raw_http_request: Vec<u8>,
}

impl MtlsProxyRequest {
    /// Encodes the proxy envelope for transport over an mTLS stream.
    pub fn to_bytes(&self) -> Result<Vec<u8>, ProxyError> {
        if self.workload_id.is_empty() || self.workload_id.len() > 256 {
            return Err(ProxyError::TransportError(
                "invalid workload_id length".to_owned(),
            ));
        }
        if self.sni_hostname.is_empty() || self.sni_hostname.len() > 253 {
            return Err(ProxyError::TransportError(
                "invalid sni_hostname length".to_owned(),
            ));
        }
        if self.raw_http_request.is_empty() || self.raw_http_request.len() > MAX_HTTP_WIRE_BYTES {
            return Err(ProxyError::TransportError(
                "invalid raw_http_request length".to_owned(),
            ));
        }

        let wl_len = u16::try_from(self.workload_id.len())
            .map_err(|_| ProxyError::TransportError("workload_id length overflow".to_owned()))?;
        let sni_len = u16::try_from(self.sni_hostname.len())
            .map_err(|_| ProxyError::TransportError("sni_hostname length overflow".to_owned()))?;
        let http_len = u32::try_from(self.raw_http_request.len())
            .map_err(|_| ProxyError::TransportError("http length overflow".to_owned()))?;

        let total = 4
            + 1
            + 2
            + self.workload_id.len()
            + 4
            + 2
            + self.sni_hostname.len()
            + 2
            + 32
            + 8
            + 4
            + self.raw_http_request.len();
        let mut out = Vec::with_capacity(total);
        out.extend_from_slice(&PROXY_MAGIC);
        out.push(PROXY_VERSION);
        out.extend_from_slice(&wl_len.to_be_bytes());
        out.extend_from_slice(self.workload_id.as_bytes());
        out.extend_from_slice(&self.guest_cid.to_be_bytes());
        out.extend_from_slice(&sni_len.to_be_bytes());
        out.extend_from_slice(self.sni_hostname.as_bytes());
        out.extend_from_slice(&self.port.to_be_bytes());
        out.extend_from_slice(&self.nonce);
        out.extend_from_slice(&self.timestamp_ms.to_be_bytes());
        out.extend_from_slice(&http_len.to_be_bytes());
        out.extend_from_slice(&self.raw_http_request);
        Ok(out)
    }

    /// Decodes a proxy envelope from wire bytes.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, ProxyError> {
        if bytes.len() < 4 + 1 + 2 + 4 + 2 + 2 + 32 + 8 + 4 || bytes.len() > MAX_MTLS_ENVELOPE_BYTES
        {
            return Err(ProxyError::TransportError(
                "truncated or oversized mTLS proxy envelope".to_owned(),
            ));
        }
        if bytes.get(..4) != Some(PROXY_MAGIC.as_slice()) {
            return Err(ProxyError::TransportError(
                "invalid mTLS proxy envelope magic".to_owned(),
            ));
        }
        if bytes.get(4) != Some(&PROXY_VERSION) {
            return Err(ProxyError::TransportError(
                "unsupported mTLS proxy envelope version".to_owned(),
            ));
        }

        let mut cursor = 5usize;
        let wl_len = read_u16_be(bytes, &mut cursor)? as usize;
        if wl_len == 0 || wl_len > 256 {
            return Err(ProxyError::TransportError(
                "invalid workload_id length in envelope".to_owned(),
            ));
        }
        let workload_id = read_utf8_field(bytes, &mut cursor, wl_len)?;
        let guest_cid = read_u32_be(bytes, &mut cursor)?;

        let sni_len = read_u16_be(bytes, &mut cursor)? as usize;
        if sni_len == 0 || sni_len > 253 {
            return Err(ProxyError::TransportError(
                "invalid sni_hostname length in envelope".to_owned(),
            ));
        }
        let sni_hostname = read_utf8_field(bytes, &mut cursor, sni_len)?;
        let port = read_u16_be(bytes, &mut cursor)?;

        let nonce_slice = bytes.get(cursor..cursor + 32).ok_or_else(|| {
            ProxyError::TransportError("truncated nonce in mTLS envelope".to_owned())
        })?;
        let mut nonce = [0u8; 32];
        nonce.copy_from_slice(nonce_slice);
        cursor += 32;

        let timestamp_ms = read_u64_be(bytes, &mut cursor)?;
        let http_len = read_u32_be(bytes, &mut cursor)? as usize;
        if http_len == 0 || http_len > MAX_HTTP_WIRE_BYTES {
            return Err(ProxyError::TransportError(
                "invalid raw_http_request length in envelope".to_owned(),
            ));
        }
        let raw_http_slice = bytes.get(cursor..cursor + http_len).ok_or_else(|| {
            ProxyError::TransportError("truncated HTTP payload in mTLS envelope".to_owned())
        })?;
        cursor += http_len;

        if cursor != bytes.len() {
            return Err(ProxyError::TransportError(
                "trailing bytes after mTLS proxy envelope".to_owned(),
            ));
        }

        Ok(Self {
            workload_id,
            guest_cid,
            sni_hostname,
            port,
            nonce,
            timestamp_ms,
            raw_http_request: raw_http_slice.to_vec(),
        })
    }
}

fn read_u16_be(bytes: &[u8], cursor: &mut usize) -> Result<u16, ProxyError> {
    let slice = bytes
        .get(*cursor..*cursor + 2)
        .ok_or_else(|| ProxyError::TransportError("truncated u16 field".to_owned()))?;
    *cursor += 2;
    let mut arr = [0u8; 2];
    arr.copy_from_slice(slice);
    Ok(u16::from_be_bytes(arr))
}

fn read_u32_be(bytes: &[u8], cursor: &mut usize) -> Result<u32, ProxyError> {
    let slice = bytes
        .get(*cursor..*cursor + 4)
        .ok_or_else(|| ProxyError::TransportError("truncated u32 field".to_owned()))?;
    *cursor += 4;
    let mut arr = [0u8; 4];
    arr.copy_from_slice(slice);
    Ok(u32::from_be_bytes(arr))
}

fn read_u64_be(bytes: &[u8], cursor: &mut usize) -> Result<u64, ProxyError> {
    let slice = bytes
        .get(*cursor..*cursor + 8)
        .ok_or_else(|| ProxyError::TransportError("truncated u64 field".to_owned()))?;
    *cursor += 8;
    let mut arr = [0u8; 8];
    arr.copy_from_slice(slice);
    Ok(u64::from_be_bytes(arr))
}

fn read_utf8_field(bytes: &[u8], cursor: &mut usize, len: usize) -> Result<String, ProxyError> {
    let slice = bytes
        .get(*cursor..*cursor + len)
        .ok_or_else(|| ProxyError::TransportError("truncated UTF-8 field".to_owned()))?;
    *cursor += len;
    let s = std::str::from_utf8(slice)
        .map_err(|_| ProxyError::TransportError("invalid UTF-8 field in envelope".to_owned()))?;
    Ok(s.to_owned())
}

fn base64_encode_zeroized(input: &[u8], alphabet: &[u8; 64], pad: bool) -> Zeroizing<Vec<u8>> {
    let mut out = Zeroizing::new(Vec::with_capacity(input.len().div_ceil(3) * 4));
    let mut chunks = input.chunks_exact(3);
    for chunk in &mut chunks {
        let n = (u32::from(chunk[0]) << 16) | (u32::from(chunk[1]) << 8) | u32::from(chunk[2]);
        out.push(alphabet[((n >> 18) & 0x3F) as usize]);
        out.push(alphabet[((n >> 12) & 0x3F) as usize]);
        out.push(alphabet[((n >> 6) & 0x3F) as usize]);
        out.push(alphabet[(n & 0x3F) as usize]);
    }
    let rem = chunks.remainder();
    if rem.len() == 1 {
        let n = u32::from(rem[0]) << 16;
        out.push(alphabet[((n >> 18) & 0x3F) as usize]);
        out.push(alphabet[((n >> 12) & 0x3F) as usize]);
        if pad {
            out.push(b'=');
            out.push(b'=');
        }
    } else if rem.len() == 2 {
        let n = (u32::from(rem[0]) << 16) | (u32::from(rem[1]) << 8);
        out.push(alphabet[((n >> 18) & 0x3F) as usize]);
        out.push(alphabet[((n >> 12) & 0x3F) as usize]);
        out.push(alphabet[((n >> 6) & 0x3F) as usize]);
        if pad {
            out.push(b'=');
        }
    }
    out
}

const fn is_rfc3986_unreserved(b: u8) -> bool {
    b.is_ascii_alphanumeric() || matches!(b, b'-' | b'_' | b'.' | b'~')
}

fn percent_encode_zeroized(input: &[u8], uppercase_hex: bool) -> Zeroizing<Vec<u8>> {
    let hex_digits: &[u8; 16] = if uppercase_hex {
        b"0123456789ABCDEF"
    } else {
        b"0123456789abcdef"
    };
    let mut out = Zeroizing::new(Vec::with_capacity(input.len() * 3));
    for &b in input {
        if is_rfc3986_unreserved(b) {
            out.push(b);
        } else {
            out.push(b'%');
            out.push(hex_digits[(b >> 4) as usize]);
            out.push(hex_digits[(b & 0x0F) as usize]);
        }
    }
    out
}

fn replace_bytes_all(haystack: &[u8], needle: &[u8], replacement: &[u8]) -> Vec<u8> {
    if needle.is_empty() || haystack.len() < needle.len() {
        return haystack.to_vec();
    }
    let mut out = Vec::with_capacity(haystack.len());
    let mut i = 0usize;
    while i + needle.len() <= haystack.len() {
        if &haystack[i..i + needle.len()] == needle {
            out.extend_from_slice(replacement);
            i += needle.len();
        } else {
            out.push(haystack[i]);
            i += 1;
        }
    }
    if i < haystack.len() {
        out.extend_from_slice(&haystack[i..]);
    }
    out
}

/// Scrubs raw, URL-encoded, and Base64-encoded occurrences of `secret` from `input`,
/// replacing every match with [`SCRUB_REPLACEMENT_TOKEN`].
#[must_use]
pub fn scrub_secret_reflections(input: &[u8], secret: &[u8]) -> Vec<u8> {
    if input.is_empty() || secret.is_empty() {
        return input.to_vec();
    }

    let candidates = [
        Zeroizing::new(secret.to_vec()),
        percent_encode_zeroized(secret, true),
        percent_encode_zeroized(secret, false),
        base64_encode_zeroized(secret, BASE64_STD, true),
        base64_encode_zeroized(secret, BASE64_STD, false),
        base64_encode_zeroized(secret, BASE64_URL, true),
        base64_encode_zeroized(secret, BASE64_URL, false),
    ];

    // Sort indices by descending needle length so padded encodings match before unpadded prefixes
    let mut order = [0usize, 1, 2, 3, 4, 5, 6];
    order.sort_by(|&a, &b| candidates[b].len().cmp(&candidates[a].len()));

    let mut current = input.to_vec();
    for idx in order {
        let needle = candidates[idx].as_slice();
        if needle.is_empty() {
            continue;
        }
        // Skip duplicate needles already processed
        let already_seen = order
            .iter()
            .take_while(|&&prev| prev != idx)
            .any(|&prev| candidates[prev].as_slice() == needle);
        if already_seen {
            continue;
        }
        current = replace_bytes_all(&current, needle, SCRUB_REPLACEMENT_TOKEN);
    }
    current
}

fn decode_chunked_body(raw_chunked: &[u8]) -> Result<Vec<u8>, ProxyError> {
    let mut decoded = Vec::new();
    let mut cursor = 0usize;

    loop {
        let rest = raw_chunked
            .get(cursor..)
            .ok_or(ProxyError::MalformedUpstreamResponse {
                reason: "unexpected EOF in chunked body",
            })?;
        let line_end = rest.windows(2).position(|w| w == b"\r\n").ok_or(
            ProxyError::MalformedUpstreamResponse {
                reason: "missing CRLF after chunk size",
            },
        )?;
        let size_line = std::str::from_utf8(&rest[..line_end]).map_err(|_| {
            ProxyError::MalformedUpstreamResponse {
                reason: "non-UTF-8 chunk size line",
            }
        })?;
        let hex_part = size_line.split(';').next().unwrap_or("").trim();
        let chunk_size = usize::from_str_radix(hex_part, 16).map_err(|_| {
            ProxyError::MalformedUpstreamResponse {
                reason: "invalid hexadecimal chunk size",
            }
        })?;
        cursor += line_end + 2;

        if chunk_size == 0 {
            break;
        }
        if decoded.len().saturating_add(chunk_size) > MAX_UPSTREAM_RESPONSE_BYTES {
            return Err(ProxyError::MalformedUpstreamResponse {
                reason: "decoded chunked response exceeded size cap",
            });
        }
        let chunk_data = raw_chunked.get(cursor..cursor + chunk_size).ok_or(
            ProxyError::MalformedUpstreamResponse {
                reason: "truncated chunk payload",
            },
        )?;
        decoded.extend_from_slice(chunk_data);
        cursor += chunk_size;

        if raw_chunked.get(cursor..cursor + 2) != Some(b"\r\n".as_slice()) {
            return Err(ProxyError::MalformedUpstreamResponse {
                reason: "missing CRLF after chunk payload",
            });
        }
        cursor += 2;
    }

    Ok(decoded)
}

fn sanitize_header_line_text(bytes: &[u8]) -> String {
    let text = String::from_utf8_lossy(bytes);
    text.chars()
        .filter(|&c| c != '\r' && c != '\n' && c != '\0')
        .collect()
}

fn parse_and_scrub_upstream_response(
    raw_resp: &[u8],
    secret: &[u8],
) -> Result<SanitizedHttpResponse, ProxyError> {
    let header_end = raw_resp.windows(4).position(|w| w == b"\r\n\r\n").ok_or(
        ProxyError::MalformedUpstreamResponse {
            reason: "upstream response missing CRLFCRLF header terminator",
        },
    )?;

    let header_str = std::str::from_utf8(&raw_resp[..header_end]).map_err(|_| {
        ProxyError::MalformedUpstreamResponse {
            reason: "non-UTF-8 upstream HTTP response headers",
        }
    })?;

    let mut lines = header_str.split("\r\n");
    let status_line = lines.next().ok_or(ProxyError::MalformedUpstreamResponse {
        reason: "missing upstream HTTP status line",
    })?;

    let mut status_parts = status_line.splitn(3, ' ');
    let version = status_parts.next().unwrap_or("");
    if version != "HTTP/1.1" && version != "HTTP/1.0" {
        return Err(ProxyError::MalformedUpstreamResponse {
            reason: "unsupported upstream HTTP response version",
        });
    }
    let code_str = status_parts
        .next()
        .ok_or(ProxyError::MalformedUpstreamResponse {
            reason: "missing upstream HTTP status code",
        })?;
    let status_code =
        code_str
            .parse::<u16>()
            .map_err(|_| ProxyError::MalformedUpstreamResponse {
                reason: "invalid upstream HTTP status code",
            })?;
    if !(100..=599).contains(&status_code) {
        return Err(ProxyError::MalformedUpstreamResponse {
            reason: "out-of-range upstream HTTP status code",
        });
    }
    let raw_reason = status_parts.next().unwrap_or("");
    let scrubbed_reason_bytes = scrub_secret_reflections(raw_reason.as_bytes(), secret);
    let reason_phrase = sanitize_header_line_text(&scrubbed_reason_bytes);

    let mut is_chunked = false;
    let mut upstream_content_length: Option<usize> = None;
    let mut sanitized_headers = Vec::new();

    for line in lines {
        if line.is_empty() {
            continue;
        }
        let (name, val) = line
            .split_once(':')
            .ok_or(ProxyError::MalformedUpstreamResponse {
                reason: "malformed upstream response header line",
            })?;
        let trimmed_name = name.trim();
        let trimmed_val = val.trim_matches(|c| c == ' ' || c == '\t');

        if trimmed_name.eq_ignore_ascii_case("transfer-encoding") {
            if trimmed_val.to_ascii_lowercase().contains("chunked") {
                is_chunked = true;
            }
            continue;
        }
        if trimmed_name.eq_ignore_ascii_case("content-length") {
            let parsed_cl = trimmed_val.parse::<usize>().map_err(|_| {
                ProxyError::MalformedUpstreamResponse {
                    reason: "invalid upstream Content-Length",
                }
            })?;
            upstream_content_length = Some(parsed_cl);
            continue;
        }
        if trimmed_name.eq_ignore_ascii_case("connection") {
            continue;
        }

        let scrubbed_val_bytes = scrub_secret_reflections(trimmed_val.as_bytes(), secret);
        let clean_val = sanitize_header_line_text(&scrubbed_val_bytes);
        sanitized_headers.push((trimmed_name.to_owned(), clean_val));
    }

    let raw_body_section = &raw_resp[header_end + 4..];
    let decoded_body = if is_chunked {
        decode_chunked_body(raw_body_section)?
    } else if let Some(expected_cl) = upstream_content_length {
        if raw_body_section.len() < expected_cl {
            return Err(ProxyError::MalformedUpstreamResponse {
                reason: "truncated upstream response body relative to Content-Length",
            });
        }
        raw_body_section[..expected_cl].to_vec()
    } else {
        raw_body_section.to_vec()
    };

    let scrubbed_body = scrub_secret_reflections(&decoded_body, secret);
    sanitized_headers.push(("Content-Length".to_owned(), scrubbed_body.len().to_string()));
    sanitized_headers.push(("Connection".to_owned(), "close".to_owned()));

    let mut raw_wire_bytes = Vec::with_capacity(header_end + 64 + scrubbed_body.len());
    let status_head = format!("HTTP/1.1 {status_code} {reason_phrase}\r\n");
    raw_wire_bytes.extend_from_slice(status_head.as_bytes());
    for (name, val) in &sanitized_headers {
        raw_wire_bytes.extend_from_slice(name.as_bytes());
        raw_wire_bytes.extend_from_slice(b": ");
        raw_wire_bytes.extend_from_slice(val.as_bytes());
        raw_wire_bytes.extend_from_slice(b"\r\n");
    }
    raw_wire_bytes.extend_from_slice(b"\r\n");
    raw_wire_bytes.extend_from_slice(&scrubbed_body);

    Ok(SanitizedHttpResponse {
        status_code,
        reason_phrase,
        headers: sanitized_headers,
        body: scrubbed_body,
        raw_wire_bytes,
    })
}

/// Consumes `ticket` **by value** (compile-time single-use), dials `upstream_addr`
/// over TLS with `ServerName` pinned to `ticket.verified_sni()`, injects the
/// zeroizing secret header into the encrypted stream, and scrubs any upstream
/// secret reflection before returning [`SanitizedHttpResponse`].
pub async fn splice_outbound_request(
    ticket: ApprovedEgressTicket,
    upstream_addr: SocketAddr,
    tls_client_config: Arc<rustls::ClientConfig>,
    io_timeout: Duration,
) -> Result<SanitizedHttpResponse, ProxyError> {
    let parts = ticket.consume();
    let server_name = ServerName::try_from(parts.verified_sni.clone())
        .map_err(|_| ProxyError::InvalidServerName)?;
    if !matches!(server_name, ServerName::DnsName(_)) {
        return Err(ProxyError::InvalidServerName);
    }

    let ConsumedSpliceOutcome(raw_resp, raw_secret) =
        tokio::time::timeout(io_timeout, async move {
            let tcp = TcpStream::connect(upstream_addr)
                .await
                .map_err(|e| ProxyError::TransportError(e.to_string()))?;
            let connector = TlsConnector::from(tls_client_config);
            let mut tls = connector
                .connect(server_name, tcp)
                .await
                .map_err(|e| ProxyError::TransportError(e.to_string()))?;

            // Build zeroizing header frame so secret material is wiped right after write+flush
            let mut wire_head = Zeroizing::new(Vec::with_capacity(
                parts.canonical_request_prefix.len()
                    + parts.injection_header_name.len()
                    + parts.injection_header_value.len()
                    + 6,
            ));
            wire_head.extend_from_slice(&parts.canonical_request_prefix);
            wire_head.extend_from_slice(parts.injection_header_name.as_bytes());
            wire_head.extend_from_slice(b": ");
            wire_head.extend_from_slice(parts.injection_header_value.as_bytes());
            wire_head.extend_from_slice(b"\r\n\r\n");

            tls.write_all(&wire_head)
                .await
                .map_err(|e| ProxyError::TransportError(e.to_string()))?;
            drop(wire_head);
            drop(parts.injection_header_value);

            if !parts.request_body.is_empty() {
                tls.write_all(&parts.request_body)
                    .await
                    .map_err(|e| ProxyError::TransportError(e.to_string()))?;
            }
            tls.flush()
                .await
                .map_err(|e| ProxyError::TransportError(e.to_string()))?;

            let mut resp_buf = Vec::with_capacity(4096);
            let mut chunk = [0u8; 8192];
            loop {
                let n = tls
                    .read(&mut chunk)
                    .await
                    .map_err(|e| ProxyError::TransportError(e.to_string()))?;
                if n == 0 {
                    break;
                }
                if resp_buf.len().saturating_add(n) > MAX_UPSTREAM_RESPONSE_BYTES {
                    return Err(ProxyError::MalformedUpstreamResponse {
                        reason: "upstream HTTP response exceeded size cap",
                    });
                }
                resp_buf.extend_from_slice(&chunk[..n]);
            }

            Ok::<ConsumedSpliceOutcome, ProxyError>(ConsumedSpliceOutcome(
                resp_buf,
                parts.raw_secret,
            ))
        })
        .await
        .map_err(|_| ProxyError::Timeout)??;

    parse_and_scrub_upstream_response(&raw_resp, raw_secret.expose_secret())
}

struct ConsumedSpliceOutcome(Vec<u8>, anvil_core::unwrap::SecretBytes);

/// Terminates one inbound Ring 2 mTLS connection, extracts the peer leaf X.509
/// certificate DER, runs [`PolicyEngine::authorize_egress`] BEFORE dialing any
/// upstream socket, and splices approved requests to `upstream_addr`.
#[allow(clippy::too_many_arguments)]
pub async fn handle_mtls_guest_connection<H: HardwareUnwrapper>(
    guest_tcp: TcpStream,
    tls_server_config: Arc<rustls::ServerConfig>,
    policy_engine: &PolicyEngine<H>,
    upstream_addr: SocketAddr,
    upstream_tls_config: Arc<rustls::ClientConfig>,
    now_ms: u64,
    io_timeout: Duration,
) -> Result<SanitizedHttpResponse, ProxyError> {
    let acceptor = TlsAcceptor::from(tls_server_config);
    let mut guest_tls = tokio::time::timeout(io_timeout, acceptor.accept(guest_tcp))
        .await
        .map_err(|_| ProxyError::Timeout)?
        .map_err(|e| ProxyError::TransportError(e.to_string()))?;

    let peer_cert_der: Vec<u8> = guest_tls
        .get_ref()
        .1
        .peer_certificates()
        .and_then(|certs| certs.first())
        .map(|cert| cert.as_ref().to_vec())
        .ok_or(ProxyError::Policy(PolicyError::MissingClientCertificate))?;

    let mut len_buf = [0u8; 4];
    tokio::time::timeout(io_timeout, guest_tls.read_exact(&mut len_buf))
        .await
        .map_err(|_| ProxyError::Timeout)?
        .map_err(|e| ProxyError::TransportError(e.to_string()))?;

    let frame_len = u32::from_be_bytes(len_buf) as usize;
    if frame_len == 0 || frame_len > MAX_MTLS_ENVELOPE_BYTES {
        let _ = guest_tls.shutdown().await;
        return Err(ProxyError::TransportError(
            "mTLS request frame length out of bounds".to_owned(),
        ));
    }

    let mut frame_buf = vec![0u8; frame_len];
    tokio::time::timeout(io_timeout, guest_tls.read_exact(&mut frame_buf))
        .await
        .map_err(|_| ProxyError::Timeout)?
        .map_err(|e| ProxyError::TransportError(e.to_string()))?;

    let proxy_req = MtlsProxyRequest::from_bytes(&frame_buf)?;
    let parsed_http = match OutboundHttpRequest::from_wire_bytes(&proxy_req.raw_http_request) {
        Ok(req) => req,
        Err(policy_err) => {
            let _ = guest_tls.shutdown().await;
            return Err(ProxyError::Policy(policy_err));
        }
    };

    let ticket = match policy_engine.authorize_egress(EgressAuthorizationInput {
        workload_id: &proxy_req.workload_id,
        guest_cid: proxy_req.guest_cid,
        peer_cert_der: &peer_cert_der,
        sni_hostname: &proxy_req.sni_hostname,
        port: proxy_req.port,
        nonce: proxy_req.nonce,
        timestamp_ms: proxy_req.timestamp_ms,
        now_ms,
        request: parsed_http,
    }) {
        Ok(t) => t,
        Err(policy_err) => {
            // Close guest stream cleanly without ever dialing upstream_addr
            let _ = guest_tls.shutdown().await;
            return Err(ProxyError::Policy(policy_err));
        }
    };

    let sanitized =
        splice_outbound_request(ticket, upstream_addr, upstream_tls_config, io_timeout).await?;

    tokio::time::timeout(io_timeout, async {
        guest_tls.write_all(&sanitized.raw_wire_bytes).await?;
        guest_tls.shutdown().await
    })
    .await
    .map_err(|_| ProxyError::Timeout)?
    .map_err(|e| ProxyError::TransportError(e.to_string()))?;

    Ok(sanitized)
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;

    #[test]
    fn scrubber_redacts_raw_and_encoded_secret_occurrences() {
        let secret = b"sk-live+secret/999=";
        // Raw, percent-encoded, and Base64-encoded occurrences in one payload
        let b64 = base64_encode_zeroized(secret, BASE64_STD, true);
        let pct = percent_encode_zeroized(secret, true);
        let payload = format!(
            "upstream 502 debug: raw={} pct={} b64={}!",
            std::str::from_utf8(secret).unwrap(),
            std::str::from_utf8(&pct).unwrap(),
            std::str::from_utf8(&b64).unwrap(),
        );
        let scrubbed = scrub_secret_reflections(payload.as_bytes(), secret);
        let scrubbed_str = std::str::from_utf8(&scrubbed).unwrap();
        assert!(!scrubbed_str.contains("sk-live+secret/999="));
        assert!(!scrubbed_str.contains(std::str::from_utf8(&pct).unwrap()));
        assert!(!scrubbed_str.contains(std::str::from_utf8(&b64).unwrap()));
        assert_eq!(scrubbed_str.matches("[REDACTED_BY_LOCKSMITH]").count(), 3);
    }
}
