//! `anvil-cache`: Content-addressed untrusted cache verification, `openat2`
//! path confinement, TOCTOU-immune `memfd` kernel sealing, and prompt-injection
//! metadata sanitization.

pub mod error;
pub mod sanitize;
pub mod seal;
pub mod store;

pub use error::{CacheError, SanitizeError};
pub use seal::{SealPolicy, VerifiedReadOnlyBlob};
pub use store::{CacheHit, CacheStore, CacheStoreConfig};
