//! `locksmith-daemon`: Ring 1 host credential broker, Linux `PR_SET_DUMPABLE(0)`
//! process hardening, `SO_PEERCRED` Ring 0 hardware token client, and startup KATs.

pub mod cli;
pub mod error;
pub mod harden;
pub mod hsm;
pub mod runtime;
pub mod selftest;

pub use cli::{parse_cli_args, CliCommand};
pub use error::DaemonError;
pub use harden::{audit_argv_and_env_hygiene, harden_process, is_process_nondumpable};
pub use hsm::Ring0UnixHardwareUnwrapper;
pub use runtime::{wait_for_os_shutdown_signal, BrokerDaemon, DaemonRuntimeConfig};
pub use selftest::{run_self_test, SelfTestReport};
