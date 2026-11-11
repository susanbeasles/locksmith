//! `locksmith-proxy`: Typestate egress splicer, RFC 8705 mTLS thumbprint
//! policy gate, RFC 9110/9112 HTTP/1.1 canonicalizer, and upstream secret
//! reflection scrubber.

pub mod error;
pub mod policy;
pub mod splicer;
pub mod ticket;

pub use error::{PolicyError, ProxyError};
pub use policy::{
    compute_cert_thumbprint_sha256, EgressAuthorizationInput, EgressRule, GuestAuthHeaderMode,
    OutboundHttpRequest, PolicyEngine, WorkloadIdentity, MIN_INJECTED_SECRET_BYTES,
};
pub use splicer::{
    handle_mtls_guest_connection, is_globally_routable_ip, is_globally_routable_ipv4,
    scrub_secret_reflections, splice_outbound_request, MtlsProxyRequest, MtlsProxySession,
    SanitizedHttpResponse, StaticEndpointResolver, SystemDnsResolver, UpstreamResolver,
    SCRUB_REPLACEMENT_TOKEN,
};
pub use ticket::ApprovedEgressTicket;
