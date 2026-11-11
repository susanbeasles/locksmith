//! `anvil-core`: Clean-room cryptographic primitives, 2-of-2 hardware-attested
//! secret unwrapping, concurrency-safe single-use nonce replay filter, and
//! `BLAKE3` hash-chained audit ledger.

#[cfg(all(feature = "prod-strict", feature = "test-hsm"))]
compile_error!("feature `test-hsm` MUST NEVER be enabled alongside `prod-strict`");

pub mod error;
pub mod kdf;
pub mod ledger;
pub mod replay;
pub mod unwrap;

pub use error::{CryptoError, LedgerError, ReplayError};
