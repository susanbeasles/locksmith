//! `locksmith-daemon`: Ring 1 host credential broker, Linux `PR_SET_DUMPABLE(0)`
//! process hardening, `SO_PEERCRED` Ring 0 hardware token client, and startup KATs.

#[cfg(all(feature = "prod-strict", feature = "test-hsm"))]
compile_error!(
    "`prod-strict` and `test-hsm` features are mutually exclusive: production daemon binaries MUST NOT include mock HSM responders"
);

pub mod cli;
pub mod config;
pub mod error;
pub mod harden;
pub mod hsm;
pub mod runtime;
pub mod selftest;

pub use cli::{parse_cli_args, CliCommand, DEFAULT_MAX_CONCURRENT_CONNECTIONS};
pub use config::{load_policy_file, parse_policy_str, LoadedMtlsPki, LoadedPolicyBundle};
pub use error::DaemonError;
pub use harden::{audit_argv_and_env_hygiene, harden_process, is_process_nondumpable};
pub use hsm::Ring0UnixHardwareUnwrapper;
pub use runtime::{wait_for_os_shutdown_signal, BrokerDaemon, DaemonRuntimeConfig};
pub use selftest::{run_self_test, SelfTestReport};
