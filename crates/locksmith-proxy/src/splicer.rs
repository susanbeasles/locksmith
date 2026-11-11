use std::collections::HashMap;
use std::future::Future;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::pin::Pin;
use std::sync::Arc;
use std::time::Duration;

use anvil_core::unwrap::HardwareUnwrapper;
use rustls::pki_types::ServerName;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio_rustls::{TlsAcceptor, TlsConnector};
use zeroize::Zeroizing;

use crate::error::{PolicyError, ProxyError};
use crate::policy::{
    is_tchar, EgressAuthorizationInput, OutboundHttpRequest, PolicyEngine, MAX_HTTP_WIRE_BYTES,
};
use crate::ticket::ApprovedEgressTicket;

/// Replacement marker substituted whenever upstream echoes raw or encoded secret bytes.
pub const SCRUB_REPLACEMENT_TOKEN: &[u8] = b"[REDACTED_BY_LOCKSMITH]";

/// Maximum inner mTLS proxy request envelope size (`512 KiB`).
pub const MAX_MTLS_ENVELOPE_BYTES: usize = 524_288;

/// Maximum upstream HTTP response size buffered in Ring 1 (`16 MiB`).
pub const MAX_UPSTREAM_RESPONSE_BYTES: usize = 16 * 1024 * 1024;

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

const fn b64_index(alphabet: &[u8; 64], byte: u8) -> Option<u8> {
    match byte {
        b'A'..=b'Z' => Some(byte - b'A'),
        b'a'..=b'z' => Some(byte - b'a' + 26),
        b'0'..=b'9' => Some(byte - b'0' + 52),
        _ if byte == alphabet[62] => Some(62),
        _ if byte == alphabet[63] => Some(63),
        _ => None,
    }
}

struct Base64WindowPattern {
    alphabet: &'static [u8; 64],
    prefix_mask_expected: Option<(u8, Zeroizing<u8>)>,
    core: Zeroizing<Vec<u8>>,
    suffix_mask_expected: Option<(u8, Zeroizing<u8>)>,
    max_padding_eq: usize,
}

impl Base64WindowPattern {
    fn build(secret: &[u8], alphabet: &'static [u8; 64], offset: u8) -> Option<Self> {
        if secret.is_empty() {
            return None;
        }
        // Shifted 1-mod-3 and 2-mod-3 patterns share boundary nibbles with neighboring bytes;
        // require >= 6 secret bytes (48+ bits) so invariant cores never false-match short ASCII words.
        if offset != 0 && secret.len() < 6 {
            return None;
        }

        let mut core = Zeroizing::new(Vec::with_capacity(secret.len().div_ceil(3) * 4));
        let (prefix_mask_expected, rest) = match offset {
            0 => (None, secret),
            1 => {
                let s0 = secret[0];
                let s1 = secret[1];
                core.push(alphabet[(((s0 & 0x0F) << 2) | (s1 >> 6)) as usize]);
                core.push(alphabet[(s1 & 0x3F) as usize]);
                (Some((0x0F, Zeroizing::new((s0 >> 4) & 0x0F))), &secret[2..])
            }
            2 => {
                let s0 = secret[0];
                core.push(alphabet[(s0 & 0x3F) as usize]);
                (Some((0x03, Zeroizing::new((s0 >> 6) & 0x03))), &secret[1..])
            }
            _ => return None,
        };

        let mut chunks = rest.chunks_exact(3);
        for chunk in &mut chunks {
            let n = (u32::from(chunk[0]) << 16) | (u32::from(chunk[1]) << 8) | u32::from(chunk[2]);
            core.push(alphabet[((n >> 18) & 0x3F) as usize]);
            core.push(alphabet[((n >> 12) & 0x3F) as usize]);
            core.push(alphabet[((n >> 6) & 0x3F) as usize]);
            core.push(alphabet[(n & 0x3F) as usize]);
        }

        let rem = chunks.remainder();
        let (suffix_mask_expected, max_padding_eq) = match rem.len() {
            0 => (None, 0),
            1 => {
                let r0 = rem[0];
                core.push(alphabet[(r0 >> 2) as usize]);
                (Some((0x30, Zeroizing::new((r0 & 0x03) << 4))), 2)
            }
            2 => {
                let r0 = rem[0];
                let r1 = rem[1];
                core.push(alphabet[(r0 >> 2) as usize]);
                core.push(alphabet[(((r0 & 0x03) << 4) | (r1 >> 4)) as usize]);
                (Some((0x3C, Zeroizing::new((r1 & 0x0F) << 2))), 1)
            }
            _ => return None,
        };

        if core.is_empty() {
            return None;
        }

        Some(Self {
            alphabet,
            prefix_mask_expected,
            core,
            suffix_mask_expected,
            max_padding_eq,
        })
    }

    fn match_len_at(&self, input: &[u8], start: usize) -> Option<usize> {
        let mut pos = start;

        if let Some((mask, ref expected)) = self.prefix_mask_expected {
            let b = *input.get(pos)?;
            let idx = b64_index(self.alphabet, b)?;
            if (idx & mask) != **expected {
                return None;
            }
            pos += 1;
        }

        let core_end = pos.checked_add(self.core.len())?;
        if input.get(pos..core_end)? != self.core.as_slice() {
            return None;
        }
        pos = core_end;

        if let Some((mask, ref expected)) = self.suffix_mask_expected {
            let b = *input.get(pos)?;
            let idx = b64_index(self.alphabet, b)?;
            if (idx & mask) != **expected {
                return None;
            }
            pos += 1;

            if self.max_padding_eq == 2 && input.get(pos..pos + 2) == Some(b"==") {
                pos += 2;
            } else if self.max_padding_eq == 1 && input.get(pos) == Some(&b'=') {
                pos += 1;
            }
        }

        Some(pos - start)
    }
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

/// Scrubs raw, URL-encoded, and Base64-encoded (across `0`, `1`, and `2 mod 3`
/// byte alignments in both standard and URL-safe alphabets) occurrences of `secret`
/// from `input` in a **single left-to-right pass**, replacing every match with
/// [`SCRUB_REPLACEMENT_TOKEN`] without ever re-scanning emitted replacement bytes.
#[must_use]
pub fn scrub_secret_reflections(input: &[u8], secret: &[u8]) -> Vec<u8> {
    if input.is_empty() || secret.is_empty() {
        return input.to_vec();
    }

    let raw_needle = Zeroizing::new(secret.to_vec());
    let pct_upper = percent_encode_zeroized(secret, true);
    let pct_lower = percent_encode_zeroized(secret, false);
    let literals: [&[u8]; 3] = [
        raw_needle.as_slice(),
        pct_upper.as_slice(),
        pct_lower.as_slice(),
    ];

    let b64_patterns: [Option<Base64WindowPattern>; 6] = [
        Base64WindowPattern::build(secret, BASE64_STD, 0),
        Base64WindowPattern::build(secret, BASE64_URL, 0),
        Base64WindowPattern::build(secret, BASE64_STD, 1),
        Base64WindowPattern::build(secret, BASE64_URL, 1),
        Base64WindowPattern::build(secret, BASE64_STD, 2),
        Base64WindowPattern::build(secret, BASE64_URL, 2),
    ];

    let mut out = Vec::with_capacity(input.len());
    let mut i = 0usize;
    while i < input.len() {
        let cur_byte = input[i];
        let mut best_len = 0usize;

        for lit in literals {
            if !lit.is_empty()
                && lit[0] == cur_byte
                && lit.len() > best_len
                && input.get(i..i + lit.len()) == Some(lit)
            {
                best_len = lit.len();
            }
        }

        for pat in b64_patterns.iter().flatten() {
            if let Some(matched_len) = pat.match_len_at(input, i) {
                if matched_len > best_len {
                    best_len = matched_len;
                }
            }
        }

        if best_len > 0 {
            out.extend_from_slice(SCRUB_REPLACEMENT_TOKEN);
            i += best_len;
        } else {
            out.push(cur_byte);
            i += 1;
        }
    }

    out
}

fn decode_chunked_body(raw_chunked: &[u8]) -> Result<Vec<u8>, ProxyError> {
    const MAX_TRAILER_LINES: usize = 64;
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
        if size_line
            .bytes()
            .any(|b| (b < 0x20 && b != b'\t') || b == 0x7F)
        {
            return Err(ProxyError::MalformedUpstreamResponse {
                reason: "control character in chunk size line",
            });
        }
        let hex_part = size_line
            .split(';')
            .next()
            .unwrap_or("")
            .trim_matches(|c| c == ' ' || c == '\t');
        if hex_part.is_empty() || !hex_part.bytes().all(|b| b.is_ascii_hexdigit()) {
            return Err(ProxyError::MalformedUpstreamResponse {
                reason: "invalid hexadecimal chunk size",
            });
        }
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
        decoded
            .try_reserve(chunk_size)
            .map_err(|_| ProxyError::MalformedUpstreamResponse {
                reason: "chunked body allocation failed",
            })?;
        decoded.extend_from_slice(chunk_data);
        cursor += chunk_size;

        if raw_chunked.get(cursor..cursor + 2) != Some(b"\r\n".as_slice()) {
            return Err(ProxyError::MalformedUpstreamResponse {
                reason: "missing CRLF after chunk payload",
            });
        }
        cursor += 2;
    }

    // Require and validate trailer-section + terminating CRLF (`*( field-line CRLF ) CRLF`)
    let mut trailer_count = 0usize;
    loop {
        let trailer_rest =
            raw_chunked
                .get(cursor..)
                .ok_or(ProxyError::MalformedUpstreamResponse {
                    reason: "missing terminating CRLF after last chunk",
                })?;
        let trailer_end = trailer_rest.windows(2).position(|w| w == b"\r\n").ok_or(
            ProxyError::MalformedUpstreamResponse {
                reason: "missing terminating CRLF after last chunk",
            },
        )?;
        if trailer_end == 0 {
            cursor += 2;
            break;
        }
        trailer_count += 1;
        if trailer_count > MAX_TRAILER_LINES {
            return Err(ProxyError::MalformedUpstreamResponse {
                reason: "excessive chunked trailer header lines",
            });
        }
        let trailer_line = std::str::from_utf8(&trailer_rest[..trailer_end]).map_err(|_| {
            ProxyError::MalformedUpstreamResponse {
                reason: "non-UTF-8 chunked trailer line",
            }
        })?;
        let (t_name, t_val) =
            trailer_line
                .split_once(':')
                .ok_or(ProxyError::MalformedUpstreamResponse {
                    reason: "malformed chunked trailer line",
                })?;
        if t_name.is_empty() || !t_name.bytes().all(is_tchar) {
            return Err(ProxyError::MalformedUpstreamResponse {
                reason: "invalid chunked trailer header name",
            });
        }
        if t_val.bytes().any(|b| (b < 0x20 && b != b'\t') || b == 0x7F) {
            return Err(ProxyError::MalformedUpstreamResponse {
                reason: "control byte in chunked trailer header value",
            });
        }
        cursor += trailer_end + 2;
    }

    if cursor != raw_chunked.len() {
        return Err(ProxyError::MalformedUpstreamResponse {
            reason: "unparsed trailing bytes after chunked body terminator",
        });
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

    let mut seen_transfer_encoding = false;
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
        if trimmed_name.is_empty() || !trimmed_name.bytes().all(is_tchar) {
            return Err(ProxyError::MalformedUpstreamResponse {
                reason: "invalid upstream response header name",
            });
        }
        let trimmed_val = val.trim_matches(|c| c == ' ' || c == '\t');

        if trimmed_name.eq_ignore_ascii_case("content-encoding") {
            if !trimmed_val.is_empty() && !trimmed_val.eq_ignore_ascii_case("identity") {
                return Err(ProxyError::MalformedUpstreamResponse {
                    reason: "compressed upstream Content-Encoding rejected",
                });
            }
            continue;
        }
        if trimmed_name.eq_ignore_ascii_case("transfer-encoding") {
            if seen_transfer_encoding {
                return Err(ProxyError::MalformedUpstreamResponse {
                    reason: "duplicate upstream Transfer-Encoding",
                });
            }
            seen_transfer_encoding = true;
            if trimmed_val.eq_ignore_ascii_case("chunked") {
                is_chunked = true;
            } else {
                return Err(ProxyError::MalformedUpstreamResponse {
                    reason: "unsupported upstream Transfer-Encoding",
                });
            }
            continue;
        }
        if trimmed_name.eq_ignore_ascii_case("content-length") {
            if upstream_content_length.is_some() {
                return Err(ProxyError::MalformedUpstreamResponse {
                    reason: "duplicate upstream Content-Length",
                });
            }
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

    if is_chunked && upstream_content_length.is_some() {
        return Err(ProxyError::MalformedUpstreamResponse {
            reason: "conflicting Transfer-Encoding and Content-Length in upstream response",
        });
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

/// Resolves a policy-verified `(verified_sni, verified_port)` pair to concrete
/// upstream socket addresses prior to dialing TLS 1.3.
pub trait UpstreamResolver: Send + Sync {
    /// Resolves `(verified_sni, verified_port)` to one or more target [`SocketAddr`]s.
    fn resolve_upstream<'a>(
        &'a self,
        verified_sni: &'a str,
        verified_port: u16,
    ) -> Pin<Box<dyn Future<Output = Result<Vec<SocketAddr>, ProxyError>> + Send + 'a>>;
}

/// Returns `true` iff `v4` is a globally routable unicast IPv4 address outside all
/// IANA / RFC 6890 special-purpose ranges.
#[must_use]
pub const fn is_globally_routable_ipv4(v4: Ipv4Addr) -> bool {
    let octets = v4.octets();
    // 0.0.0.0/8 — "This host on this network" (RFC 1122 / RFC 791)
    if octets[0] == 0 {
        return false;
    }
    // 10.0.0.0/8 — Private-Use (RFC 1918)
    if octets[0] == 10 {
        return false;
    }
    // 100.64.0.0/10 — Shared Address Space / CGNAT (RFC 6598)
    if octets[0] == 100 && (octets[1] & 0xC0) == 64 {
        return false;
    }
    // 127.0.0.0/8 — Loopback (RFC 1122)
    if octets[0] == 127 {
        return false;
    }
    // 169.254.0.0/16 — Link-Local / Cloud IMDS (RFC 3927)
    if octets[0] == 169 && octets[1] == 254 {
        return false;
    }
    // 172.16.0.0/12 — Private-Use (RFC 1918)
    if octets[0] == 172 && (octets[1] & 0xF0) == 16 {
        return false;
    }
    // 192.0.0.0/24 — IETF Protocol Assignments (RFC 6890)
    if octets[0] == 192 && octets[1] == 0 && octets[2] == 0 {
        return false;
    }
    // 192.0.2.0/24 — Documentation TEST-NET-1 (RFC 5737)
    if octets[0] == 192 && octets[1] == 0 && octets[2] == 2 {
        return false;
    }
    // 192.88.99.0/24 — Deprecated 6to4 Relay Anycast (RFC 3068 / RFC 7526)
    if octets[0] == 192 && octets[1] == 88 && octets[2] == 99 {
        return false;
    }
    // 192.168.0.0/16 — Private-Use (RFC 1918)
    if octets[0] == 192 && octets[1] == 168 {
        return false;
    }
    // 198.18.0.0/15 — Network Interconnect Device Benchmark Testing (RFC 2544)
    if octets[0] == 198 && (octets[1] & 0xFE) == 18 {
        return false;
    }
    // 198.51.100.0/24 — Documentation TEST-NET-2 (RFC 5737)
    if octets[0] == 198 && octets[1] == 51 && octets[2] == 100 {
        return false;
    }
    // 203.0.113.0/24 — Documentation TEST-NET-3 (RFC 5737)
    if octets[0] == 203 && octets[1] == 0 && octets[2] == 113 {
        return false;
    }
    // 224.0.0.0/4 — Multicast (RFC 5771) and 240.0.0.0/4 — Reserved + Broadcast (RFC 1112 / RFC 919)
    if octets[0] >= 224 {
        return false;
    }
    true
}

/// Returns `true` iff `ip` is a globally routable unicast IPv4 or IPv6 address
/// outside all IANA / RFC 6890 special-purpose ranges.
#[must_use]
pub const fn is_globally_routable_ip(ip: IpAddr) -> bool {
    match ip {
        IpAddr::V4(v4) => is_globally_routable_ipv4(v4),
        IpAddr::V6(v6) => {
            let segs = v6.segments();
            // IPv4-mapped ::ffff:0:0/96 — delegate embedded IPv4 to full RFC 6890 filter
            if segs[0] == 0
                && segs[1] == 0
                && segs[2] == 0
                && segs[3] == 0
                && segs[4] == 0
                && segs[5] == 0xffff
            {
                let hi = segs[6].to_be_bytes();
                let lo = segs[7].to_be_bytes();
                return is_globally_routable_ipv4(Ipv4Addr::new(hi[0], hi[1], lo[0], lo[1]));
            }
            // Unspecified ::/128, Loopback ::1/128, and deprecated IPv4-compatible ::/96
            if segs[0] == 0
                && segs[1] == 0
                && segs[2] == 0
                && segs[3] == 0
                && segs[4] == 0
                && segs[5] == 0
            {
                return false;
            }
            // SIIT IPv4-translated ::ffff:0:0:0/96 (RFC 2765)
            if segs[0] == 0
                && segs[1] == 0
                && segs[2] == 0
                && segs[3] == 0
                && segs[4] == 0xffff
                && segs[5] == 0
            {
                return false;
            }
            // RFC 6052 Well-Known NAT64 64:ff9b::/96
            if segs[0] == 0x0064
                && segs[1] == 0xff9b
                && segs[2] == 0
                && segs[3] == 0
                && segs[4] == 0
                && segs[5] == 0
            {
                return false;
            }
            // RFC 8215 Local-Use NAT64 64:ff9b:1::/48
            if segs[0] == 0x0064 && segs[1] == 0xff9b && segs[2] == 0x0001 {
                return false;
            }
            // RFC 6666 Discard-Only 100::/64
            if segs[0] == 0x0100 && segs[1] == 0 && segs[2] == 0 && segs[3] == 0 {
                return false;
            }
            // RFC 6890 IETF Protocol Assignments 2001::/23 (covers Teredo 2001:0000::/32,
            // Benchmarking 2001:2::/48, ORCHID 2001:10::/28, and ORCHIDv2 2001:20::/28)
            if segs[0] == 0x2001 && (segs[1] & 0xfe00) == 0x0000 {
                return false;
            }
            // RFC 3849 Documentation 2001:db8::/32
            if segs[0] == 0x2001 && segs[1] == 0x0db8 {
                return false;
            }
            // RFC 3056 / RFC 7526 6to4 2002::/16
            if segs[0] == 0x2002 {
                return false;
            }
            // RFC 4193 Unique Local fc00::/7
            if (segs[0] & 0xfe00) == 0xfc00 {
                return false;
            }
            // RFC 4291 Link-Local fe80::/10 and deprecated Site-Local fec0::/10
            if (segs[0] & 0xffc0) == 0xfe80 || (segs[0] & 0xffc0) == 0xfec0 {
                return false;
            }
            // RFC 4291 Multicast ff00::/8
            if (segs[0] & 0xff00) == 0xff00 {
                return false;
            }
            true
        }
    }
}

/// Production DNS resolver enforcing exact `verified_port` binding and rejecting
/// loopback, RFC 1918 private, link-local/IMDS (`169.254.0.0/16`), multicast, and
/// unspecified IP addresses (defeating DNS-rebinding SSRF).
#[derive(Clone, Copy, Debug, Default)]
pub struct SystemDnsResolver;

impl UpstreamResolver for SystemDnsResolver {
    fn resolve_upstream<'a>(
        &'a self,
        verified_sni: &'a str,
        verified_port: u16,
    ) -> Pin<Box<dyn Future<Output = Result<Vec<SocketAddr>, ProxyError>> + Send + 'a>> {
        Box::pin(async move {
            if verified_port == 0 {
                return Err(ProxyError::Policy(PolicyError::TargetNotAllowed));
            }
            let resolved = tokio::net::lookup_host((verified_sni, verified_port))
                .await
                .map_err(|e| ProxyError::TransportError(e.to_string()))?;
            let mut valid = Vec::new();
            for addr in resolved {
                if addr.port() != verified_port || !is_globally_routable_ip(addr.ip()) {
                    return Err(ProxyError::Policy(PolicyError::TargetNotAllowed));
                }
                valid.push(addr);
            }
            if valid.is_empty() {
                return Err(ProxyError::TransportError(
                    "DNS lookup returned zero globally routable addresses".to_owned(),
                ));
            }
            Ok(valid)
        })
    }
}

/// Pinned `(sni_hostname, verified_port) -> SocketAddr` resolver failing closed
/// with [`PolicyError::TargetNotAllowed`] whenever `(verified_sni, verified_port)`
/// is not explicitly registered.
#[derive(Clone, Debug, Default)]
pub struct StaticEndpointResolver {
    endpoints: HashMap<(String, u16), SocketAddr>,
}

impl StaticEndpointResolver {
    /// Creates an empty [`StaticEndpointResolver`].
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Creates a [`StaticEndpointResolver`] with a single `(sni, verified_port) -> addr` mapping.
    #[must_use]
    pub fn single(sni_hostname: &str, verified_port: u16, addr: SocketAddr) -> Self {
        let mut r = Self::new();
        r.insert(sni_hostname, verified_port, addr);
        r
    }

    /// Registers an explicit `(sni_hostname, verified_port) -> addr` pin.
    pub fn insert(&mut self, sni_hostname: &str, verified_port: u16, addr: SocketAddr) {
        self.endpoints
            .insert((sni_hostname.to_ascii_lowercase(), verified_port), addr);
    }
}

impl UpstreamResolver for StaticEndpointResolver {
    fn resolve_upstream<'a>(
        &'a self,
        verified_sni: &'a str,
        verified_port: u16,
    ) -> Pin<Box<dyn Future<Output = Result<Vec<SocketAddr>, ProxyError>> + Send + 'a>> {
        Box::pin(async move {
            let key = (verified_sni.to_ascii_lowercase(), verified_port);
            let Some(&addr) = self.endpoints.get(&key) else {
                return Err(ProxyError::Policy(PolicyError::TargetNotAllowed));
            };
            Ok(vec![addr])
        })
    }
}

/// Shared session configuration for terminating Ring 2 mTLS proxy streams without
/// bloated argument lists.
pub struct MtlsProxySession<H: HardwareUnwrapper, R: UpstreamResolver> {
    pub tls_server_config: Arc<rustls::ServerConfig>,
    pub policy_engine: Arc<PolicyEngine<H>>,
    pub upstream_resolver: Arc<R>,
    pub upstream_tls_config: Arc<rustls::ClientConfig>,
    pub io_timeout: Duration,
}

/// Consumes `ticket` **by value** (compile-time single-use), resolves `(verified_sni, verified_port)`
/// via `resolver`, dials TLS 1.3 with `ServerName` pinned to `ticket.verified_sni()`,
/// injects the zeroizing secret header into the encrypted stream, and scrubs any upstream
/// secret reflection before returning [`SanitizedHttpResponse`].
pub async fn splice_outbound_request<R: UpstreamResolver + ?Sized>(
    ticket: ApprovedEgressTicket,
    resolver: &R,
    tls_client_config: Arc<rustls::ClientConfig>,
    io_timeout: Duration,
) -> Result<SanitizedHttpResponse, ProxyError> {
    let parts = ticket.consume();
    if parts.verified_port == 0 {
        return Err(ProxyError::Policy(PolicyError::TargetNotAllowed));
    }
    let server_name = ServerName::try_from(parts.verified_sni.clone())
        .map_err(|_| ProxyError::InvalidServerName)?;
    if !matches!(server_name, ServerName::DnsName(_)) {
        return Err(ProxyError::InvalidServerName);
    }

    let ConsumedSpliceOutcome(raw_resp, raw_secret) =
        tokio::time::timeout(io_timeout, async move {
            let addrs = resolver
                .resolve_upstream(&parts.verified_sni, parts.verified_port)
                .await?;
            let target_addr = *addrs.first().ok_or_else(|| {
                ProxyError::TransportError("no upstream address resolved".to_owned())
            })?;

            let tcp = TcpStream::connect(target_addr)
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

            let resp_buf =
                read_bounded_upstream_response(&mut tls, MAX_UPSTREAM_RESPONSE_BYTES).await?;

            Ok::<ConsumedSpliceOutcome, ProxyError>(ConsumedSpliceOutcome(
                resp_buf,
                parts.raw_secret,
            ))
        })
        .await
        .map_err(|_| ProxyError::Timeout)??;

    parse_and_scrub_upstream_response(&raw_resp, raw_secret.expose_secret())
}

async fn read_bounded_upstream_response<R: AsyncRead + Unpin>(
    reader: &mut R,
    max_bytes: usize,
) -> Result<Vec<u8>, ProxyError> {
    let mut resp_buf = Vec::new();
    resp_buf
        .try_reserve(4096)
        .map_err(|_| ProxyError::MalformedUpstreamResponse {
            reason: "upstream response buffer allocation failed",
        })?;
    let mut chunk = [0u8; 8192];
    loop {
        let n = reader
            .read(&mut chunk)
            .await
            .map_err(|e| ProxyError::TransportError(e.to_string()))?;
        if n == 0 {
            break;
        }
        if resp_buf.len().saturating_add(n) > max_bytes {
            return Err(ProxyError::MalformedUpstreamResponse {
                reason: "upstream HTTP response exceeded size cap",
            });
        }
        resp_buf
            .try_reserve(n)
            .map_err(|_| ProxyError::MalformedUpstreamResponse {
                reason: "upstream response buffer growth failed",
            })?;
        resp_buf.extend_from_slice(&chunk[..n]);
    }
    Ok(resp_buf)
}

struct ConsumedSpliceOutcome(Vec<u8>, anvil_core::unwrap::SecretBytes);

/// Terminates one inbound Ring 2 mTLS connection over any kernel-authenticated
/// stream (`AF_VSOCK`, `AF_UNIX` `SO_PEERCRED`, or loopback test socket),
/// enforces `proxy_req.guest_cid == authenticated_guest_cid`, runs
/// [`PolicyEngine::authorize_egress`] on Tokio's blocking pool **before** dialing
/// any upstream socket, and splices approved requests via `session.upstream_resolver`.
pub async fn handle_mtls_guest_connection<S, H, R>(
    guest_stream: S,
    authenticated_guest_cid: u32,
    session: &MtlsProxySession<H, R>,
    now_ms: u64,
) -> Result<SanitizedHttpResponse, ProxyError>
where
    S: AsyncRead + AsyncWrite + Unpin,
    H: HardwareUnwrapper + 'static,
    R: UpstreamResolver,
{
    let io_timeout = session.io_timeout;
    let acceptor = TlsAcceptor::from(Arc::clone(&session.tls_server_config));
    let mut guest_tls = tokio::time::timeout(io_timeout, acceptor.accept(guest_stream))
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

    let mut frame_buf = Vec::new();
    frame_buf
        .try_reserve_exact(frame_len)
        .map_err(|e| ProxyError::TransportError(format!("mTLS frame allocation failed: {e}")))?;
    frame_buf.resize(frame_len, 0u8);

    tokio::time::timeout(io_timeout, guest_tls.read_exact(&mut frame_buf))
        .await
        .map_err(|_| ProxyError::Timeout)?
        .map_err(|e| ProxyError::TransportError(e.to_string()))?;

    let proxy_req = MtlsProxyRequest::from_bytes(&frame_buf)?;
    if proxy_req.guest_cid != authenticated_guest_cid {
        let _ = guest_tls.shutdown().await;
        return Err(ProxyError::Policy(PolicyError::GuestCidMismatch {
            expected: authenticated_guest_cid,
            actual: proxy_req.guest_cid,
        }));
    }

    let parsed_http = match OutboundHttpRequest::from_wire_bytes(&proxy_req.raw_http_request) {
        Ok(req) => req,
        Err(policy_err) => {
            let _ = guest_tls.shutdown().await;
            return Err(ProxyError::Policy(policy_err));
        }
    };

    let policy_engine = Arc::clone(&session.policy_engine);
    let auth_res = tokio::time::timeout(
        io_timeout,
        tokio::task::spawn_blocking(move || {
            policy_engine.authorize_egress(EgressAuthorizationInput {
                workload_id: &proxy_req.workload_id,
                guest_cid: authenticated_guest_cid,
                peer_cert_der: &peer_cert_der,
                sni_hostname: &proxy_req.sni_hostname,
                port: proxy_req.port,
                nonce: proxy_req.nonce,
                timestamp_ms: proxy_req.timestamp_ms,
                now_ms,
                request: parsed_http,
            })
        }),
    )
    .await
    .map_err(|_| ProxyError::Timeout)?
    .map_err(|e| ProxyError::TransportError(format!("policy task join failed: {e}")))?;

    let ticket = match auth_res {
        Ok(t) => t,
        Err(policy_err) => {
            // Close guest stream cleanly without ever resolving or dialing upstream
            let _ = guest_tls.shutdown().await;
            return Err(ProxyError::Policy(policy_err));
        }
    };

    let sanitized = splice_outbound_request(
        ticket,
        session.upstream_resolver.as_ref(),
        Arc::clone(&session.upstream_tls_config),
        io_timeout,
    )
    .await?;

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

    fn test_base64_encode(input: &[u8], alphabet: &[u8; 64], pad: bool) -> Vec<u8> {
        let mut out = Vec::with_capacity(input.len().div_ceil(3) * 4);
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

    #[test]
    fn scrubber_redacts_raw_and_encoded_secret_occurrences() {
        let secret = b"sk-live+secret/999=";
        // Raw, percent-encoded, and Base64-encoded occurrences in one payload
        let b64 = test_base64_encode(secret, BASE64_STD, true);
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

    #[tokio::test]
    async fn rejects_oversized_upstream_response_before_reflection_scrubbing() {
        let (mut writer, mut reader) = tokio::io::duplex(65_536);
        tokio::spawn(async move {
            let oversized = vec![b'A'; 32_769];
            let _ = writer.write_all(&oversized).await;
        });

        let err = read_bounded_upstream_response(&mut reader, 32_768)
            .await
            .unwrap_err();
        assert!(matches!(err, ProxyError::MalformedUpstreamResponse { .. }));
    }

    #[test]
    fn rejects_compressed_upstream_content_encoding_fail_closed() {
        let compressed_resp =
            b"HTTP/1.1 200 OK\r\nContent-Encoding: gzip\r\nContent-Length: 4\r\n\r\n\x1f\x8b\x08\x00";
        let err =
            parse_and_scrub_upstream_response(compressed_resp, b"sk-live-secret-999").unwrap_err();
        assert!(matches!(
            err,
            ProxyError::MalformedUpstreamResponse {
                reason: "compressed upstream Content-Encoding rejected"
            }
        ));
    }

    #[test]
    fn rejects_duplicate_and_stacked_transfer_encoding_and_truncated_chunks() {
        for raw_resp in [
            &b"HTTP/1.1 200 OK\r\nTransfer-Encoding: gzip, chunked\r\n\r\n2\r\nok\r\n0\r\n\r\n"[..],
            &b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked, gzip\r\n\r\n2\r\nok\r\n0\r\n\r\n"[..],
            &b"HTTP/1.1 200 OK\r\nTransfer-Encoding: xchunked\r\n\r\n2\r\nok\r\n0\r\n\r\n"[..],
            &b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\nTransfer-Encoding: chunked\r\n\r\n2\r\nok\r\n0\r\n\r\n"[..],
            &b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n2\r\nok\r\n0\r\n"[..],
            &b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n2\r\nok\r\n0\r\n\r\nSMUGGLED"[..],
        ] {
            let err =
                parse_and_scrub_upstream_response(raw_resp, b"sk-live-secret-999").unwrap_err();
            assert!(matches!(err, ProxyError::MalformedUpstreamResponse { .. }));
        }

        // Valid chunked response with optional trailer + final CRLF succeeds and scrubs
        let valid_chunked = b"HTTP/1.1 200 OK\r\nTransfer-Encoding: CHUNKED\r\n\r\n12\r\nsk-live-secret-999\r\n0\r\nX-Checksum: ok\r\n\r\n";
        let ok = parse_and_scrub_upstream_response(valid_chunked, b"sk-live-secret-999").unwrap();
        assert_eq!(ok.body, b"[REDACTED_BY_LOCKSMITH]");
    }

    #[test]
    fn rfc6890_ip_filter_blocks_all_special_purpose_v4_and_v6_ranges() {
        for blocked in [
            "0.0.0.1",
            "10.0.0.1",
            "100.64.0.1",
            "127.0.0.1",
            "169.254.169.254",
            "172.16.0.1",
            "192.0.0.1",
            "192.0.2.1",
            "192.88.99.1",
            "192.168.1.1",
            "198.18.0.1",
            "198.19.255.254",
            "198.51.100.1",
            "203.0.113.1",
            "224.0.0.1",
            "240.0.0.1",
            "255.255.255.255",
            "::",
            "::1",
            "::a9fe:a9fe",
            "::ffff:169.254.169.254",
            "::ffff:0:a9fe:a9fe",
            "64:ff9b::a9fe:a9fe",
            "64:ff9b:1::1",
            "100::1",
            "2001::1",
            "2001:1ff::1",
            "2001:db8::1",
            "2002:a9fe:a9fe::1",
            "fc00::1",
            "fd12:3456::1",
            "fe80::1",
            "ff02::1",
        ] {
            let ip: IpAddr = blocked.parse().unwrap();
            assert!(!is_globally_routable_ip(ip), "{blocked} must be rejected");
        }

        for allowed in [
            "1.1.1.1",
            "8.8.8.8",
            "192.0.1.1",
            "198.17.255.254",
            "198.20.0.1",
            "::ffff:1.1.1.1",
            "2606:4700:4700::1111",
            "2001:4860:4860::8888",
        ] {
            let ip: IpAddr = allowed.parse().unwrap();
            assert!(is_globally_routable_ip(ip), "{allowed} must be accepted");
        }
    }
}
