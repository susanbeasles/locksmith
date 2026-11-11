use std::ffi::OsString;

use crate::error::DaemonError;

/// Applies OS-level Ring 1 process hardening (`PR_SET_DUMPABLE(0)` on Linux)
/// to forbid non-root `ptrace` attachment and kernel core dumps.
pub fn harden_process() -> Result<(), DaemonError> {
    #[cfg(target_os = "linux")]
    {
        use rustix::process::{dumpable_behavior, set_dumpable_behavior, DumpableBehavior};

        set_dumpable_behavior(DumpableBehavior::NotDumpable)
            .map_err(|e| DaemonError::ProcessHardeningFailed(e.to_string()))?;

        let active =
            dumpable_behavior().map_err(|e| DaemonError::ProcessHardeningFailed(e.to_string()))?;
        if active != DumpableBehavior::NotDumpable {
            return Err(DaemonError::ProcessHardeningFailed(
                "kernel did not retain PR_SET_DUMPABLE(0)".to_owned(),
            ));
        }
    }

    Ok(())
}

/// Returns `true` if the current process is marked non-dumpable by the OS kernel.
pub fn is_process_nondumpable() -> Result<bool, DaemonError> {
    #[cfg(target_os = "linux")]
    {
        let behavior = rustix::process::dumpable_behavior()
            .map_err(|e| DaemonError::ProcessHardeningFailed(e.to_string()))?;
        Ok(behavior == rustix::process::DumpableBehavior::NotDumpable)
    }

    #[cfg(not(target_os = "linux"))]
    {
        Ok(true)
    }
}

fn is_forbidden_arg_flag(arg_lower: &str) -> bool {
    // Allow --host-share-stdin explicitly; block any flag attempting to pass raw secret values
    if arg_lower == "--host-share-stdin" {
        return false;
    }
    const FORBIDDEN_FLAG_PREFIXES: &[&str] = &[
        "--secret",
        "--token",
        "--api-key",
        "--apikey",
        "--password",
        "--private-key",
        "--host-share",
        "--hw-share",
        "--raw-key",
    ];
    FORBIDDEN_FLAG_PREFIXES
        .iter()
        .any(|prefix| arg_lower.starts_with(prefix))
}

fn looks_like_inline_secret_value(arg: &str) -> bool {
    const SECRET_PREFIXES: &[&str] = &["sk-live-", "sk-ant-", "ghp_", "github_pat_", "AKIA"];
    SECRET_PREFIXES.iter().any(|p| arg.contains(p))
}

fn is_forbidden_env_var_name(name_upper: &str) -> bool {
    const EXACT_FORBIDDEN: &[&str] = &[
        "ANTHROPIC_API_KEY",
        "OPENAI_API_KEY",
        "AWS_SECRET_ACCESS_KEY",
        "VULTR_API_KEY",
    ];
    if EXACT_FORBIDDEN.contains(&name_upper) {
        return true;
    }
    if name_upper.starts_with("LOCKSMITH_") {
        const FORBIDDEN_LOCKSMITH_TOKENS: &[&str] =
            &["SECRET", "TOKEN", "KEY", "PASSWORD", "SHARE", "CREDENTIAL"];
        return FORBIDDEN_LOCKSMITH_TOKENS
            .iter()
            .any(|tok| name_upper.contains(tok));
    }
    false
}

/// Audits process `argv` and environment variable names to ensure no raw secrets,
/// API keys, or key shares were passed via ambient process metadata.
pub fn audit_argv_and_env_hygiene<A, E>(args: A, envs: E) -> Result<(), DaemonError>
where
    A: IntoIterator<Item = OsString>,
    E: IntoIterator<Item = (OsString, OsString)>,
{
    for (idx, os_arg) in args.into_iter().enumerate() {
        if idx == 0 {
            continue;
        }
        let arg_lossy = os_arg.to_string_lossy();
        let lower = arg_lossy.to_ascii_lowercase();
        if is_forbidden_arg_flag(&lower) || looks_like_inline_secret_value(&arg_lossy) {
            return Err(DaemonError::AmbientSecretViolation {
                source_kind: "process argv",
            });
        }
    }

    for (os_key, os_val) in envs {
        if os_val.is_empty() {
            continue;
        }
        let key_upper = os_key.to_string_lossy().to_ascii_uppercase();
        if is_forbidden_env_var_name(&key_upper) {
            return Err(DaemonError::AmbientSecretViolation {
                source_kind: "environment variable",
            });
        }
    }

    Ok(())
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;

    #[test]
    fn harden_process_sets_kernel_nondumpable_flag() {
        harden_process().unwrap();
        assert!(is_process_nondumpable().unwrap());
    }
}
