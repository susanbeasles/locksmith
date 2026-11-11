use std::ffi::OsString;
use std::path::PathBuf;

use crate::error::DaemonError;

/// Parsed CLI subcommand for `locksmith-daemon`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum CliCommand {
    /// Run deterministic startup KATs across all subsystems (`verify-self`).
    VerifySelf,
    /// Print daemon version string.
    Version,
    /// Print usage help string.
    Help,
    /// Run production Ring 1 broker daemon (`serve`), reading the 32-byte host share
    /// from standard input (`--host-share-stdin`) so zero secrets appear in `argv` or `env`.
    Serve {
        ipc_socket: PathBuf,
        ring0_socket: PathBuf,
        ring0_uid: u32,
        allowed_peer_uid: u32,
        mapped_guest_cid: u32,
    },
}

/// Parses CLI arguments without ever echoing raw argument values in error messages.
pub fn parse_cli_args<I>(args: I) -> Result<CliCommand, DaemonError>
where
    I: IntoIterator<Item = OsString>,
{
    let mut iter = args.into_iter();
    let _bin_name = iter.next();

    let Some(sub_os) = iter.next() else {
        return Err(DaemonError::InvalidCliUsage {
            reason:
                "missing subcommand (expected 'verify-self', 'serve', '--version', or '--help')",
        });
    };
    let sub = sub_os.to_str().ok_or(DaemonError::InvalidCliUsage {
        reason: "non-UTF-8 subcommand",
    })?;

    match sub {
        "verify-self" => {
            if iter.next().is_some() {
                return Err(DaemonError::InvalidCliUsage {
                    reason: "'verify-self' accepts no extra positional arguments",
                });
            }
            Ok(CliCommand::VerifySelf)
        }
        "--version" | "-V" => Ok(CliCommand::Version),
        "--help" | "-h" => Ok(CliCommand::Help),
        "serve" => parse_serve_flags(iter),
        _ => Err(DaemonError::InvalidCliUsage {
            reason: "unknown subcommand (expected 'verify-self' or 'serve')",
        }),
    }
}

fn parse_serve_flags<I>(mut iter: I) -> Result<CliCommand, DaemonError>
where
    I: Iterator<Item = OsString>,
{
    let mut ipc_socket: Option<PathBuf> = None;
    let mut ring0_socket: Option<PathBuf> = None;
    let mut ring0_uid: u32 = 0;
    let mut allowed_peer_uid: u32 = 0;
    let mut mapped_guest_cid: u32 = 3;
    let mut host_share_stdin = false;

    while let Some(flag_os) = iter.next() {
        let flag = flag_os.to_str().ok_or(DaemonError::InvalidCliUsage {
            reason: "non-UTF-8 CLI flag",
        })?;
        match flag {
            "--ipc-socket" => {
                let path = iter.next().ok_or(DaemonError::InvalidCliUsage {
                    reason: "missing path after --ipc-socket",
                })?;
                ipc_socket = Some(PathBuf::from(path));
            }
            "--ring0-socket" => {
                let path = iter.next().ok_or(DaemonError::InvalidCliUsage {
                    reason: "missing path after --ring0-socket",
                })?;
                ring0_socket = Some(PathBuf::from(path));
            }
            "--ring0-uid" => {
                let val_os = iter.next().ok_or(DaemonError::InvalidCliUsage {
                    reason: "missing integer after --ring0-uid",
                })?;
                let val_s = val_os.to_str().ok_or(DaemonError::InvalidCliUsage {
                    reason: "invalid --ring0-uid encoding",
                })?;
                ring0_uid = val_s
                    .parse::<u32>()
                    .map_err(|_| DaemonError::InvalidCliUsage {
                        reason: "invalid integer for --ring0-uid",
                    })?;
            }
            "--allow-peer-uid" => {
                let val_os = iter.next().ok_or(DaemonError::InvalidCliUsage {
                    reason: "missing integer after --allow-peer-uid",
                })?;
                let val_s = val_os.to_str().ok_or(DaemonError::InvalidCliUsage {
                    reason: "invalid --allow-peer-uid encoding",
                })?;
                allowed_peer_uid =
                    val_s
                        .parse::<u32>()
                        .map_err(|_| DaemonError::InvalidCliUsage {
                            reason: "invalid integer for --allow-peer-uid",
                        })?;
            }
            "--guest-cid" => {
                let val_os = iter.next().ok_or(DaemonError::InvalidCliUsage {
                    reason: "missing integer after --guest-cid",
                })?;
                let val_s = val_os.to_str().ok_or(DaemonError::InvalidCliUsage {
                    reason: "invalid --guest-cid encoding",
                })?;
                mapped_guest_cid =
                    val_s
                        .parse::<u32>()
                        .map_err(|_| DaemonError::InvalidCliUsage {
                            reason: "invalid integer for --guest-cid",
                        })?;
            }
            "--host-share-stdin" => {
                host_share_stdin = true;
            }
            _ => {
                return Err(DaemonError::InvalidCliUsage {
                    reason: "unrecognized CLI flag for 'serve'",
                });
            }
        }
    }

    if !host_share_stdin {
        return Err(DaemonError::InvalidCliUsage {
            reason: "'serve' requires --host-share-stdin",
        });
    }
    let ipc_socket = ipc_socket.ok_or(DaemonError::InvalidCliUsage {
        reason: "'serve' requires --ipc-socket <PATH>",
    })?;
    let ring0_socket = ring0_socket.ok_or(DaemonError::InvalidCliUsage {
        reason: "'serve' requires --ring0-socket <PATH>",
    })?;

    Ok(CliCommand::Serve {
        ipc_socket,
        ring0_socket,
        ring0_uid,
        allowed_peer_uid,
        mapped_guest_cid,
    })
}
