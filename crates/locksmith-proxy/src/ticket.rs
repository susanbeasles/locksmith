use core::fmt;

use anvil_core::unwrap::SecretBytes;
use zeroize::Zeroizing;

/// Unforgeable, single-use capability ticket proving that [`crate::policy::PolicyEngine`]
/// validated RFC 8705 mTLS identity, upstream allowlist rules, RFC 9110/9112 HTTP
/// canonicalization, single-use nonce burn, and 2-of-2 credential unwrapping.
///
/// Intentionally `!Clone`, `!Copy`, and non-deserializable. Consumed by value in
/// [`crate::splicer::splice_outbound_request`].
pub struct ApprovedEgressTicket {
    workload_id: String,
    guest_cid: u32,
    verified_sni: String,
    verified_port: u16,
    canonical_request_prefix: Vec<u8>,
    request_body: Vec<u8>,
    injection_header_name: String,
    injection_header_value: Zeroizing<String>,
    raw_secret: SecretBytes,
}

pub(crate) struct ConsumedTicketParts {
    pub verified_sni: String,
    pub canonical_request_prefix: Vec<u8>,
    pub request_body: Vec<u8>,
    pub injection_header_name: String,
    pub injection_header_value: Zeroizing<String>,
    pub raw_secret: SecretBytes,
}

impl ApprovedEgressTicket {
    #[allow(clippy::too_many_arguments)]
    pub(crate) fn mint(
        workload_id: String,
        guest_cid: u32,
        verified_sni: String,
        verified_port: u16,
        canonical_request_prefix: Vec<u8>,
        request_body: Vec<u8>,
        injection_header_name: String,
        injection_header_value: Zeroizing<String>,
        raw_secret: SecretBytes,
    ) -> Self {
        Self {
            workload_id,
            guest_cid,
            verified_sni,
            verified_port,
            canonical_request_prefix,
            request_body,
            injection_header_name,
            injection_header_value,
            raw_secret,
        }
    }

    /// Returns the verified target DNS SNI hostname locked for TLS 1.3 negotiation.
    #[must_use]
    pub fn verified_sni(&self) -> &str {
        &self.verified_sni
    }

    /// Returns the verified target TCP port.
    #[must_use]
    pub fn verified_port(&self) -> u16 {
        self.verified_port
    }

    /// Returns the authenticated workload identifier.
    #[must_use]
    pub fn workload_id(&self) -> &str {
        &self.workload_id
    }

    /// Returns the authenticated Ring 2 guest CID.
    #[must_use]
    pub fn guest_cid(&self) -> u32 {
        self.guest_cid
    }

    pub(crate) fn consume(self) -> ConsumedTicketParts {
        ConsumedTicketParts {
            verified_sni: self.verified_sni,
            canonical_request_prefix: self.canonical_request_prefix,
            request_body: self.request_body,
            injection_header_name: self.injection_header_name,
            injection_header_value: self.injection_header_value,
            raw_secret: self.raw_secret,
        }
    }
}

impl fmt::Debug for ApprovedEgressTicket {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ApprovedEgressTicket")
            .field("workload_id", &self.workload_id)
            .field("guest_cid", &self.guest_cid)
            .field("verified_sni", &self.verified_sni)
            .field("verified_port", &self.verified_port)
            .field("injection_header_name", &self.injection_header_name)
            .field("secret", &"[REDACTED]")
            .finish()
    }
}
