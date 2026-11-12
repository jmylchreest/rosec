//! Legacy syntax policy and normalization. Retired names stay reserved here.
use crate::cli::{
    Cli, Commands, InstanceCli, PasswordOperation, ProviderCommands, ProviderOperation,
    ProviderRequest,
};
use clap::{CommandFactory, FromArgMatches, Parser, error::ErrorKind};
use std::ffi::OsString;

pub struct LegacyCommand {
    pub name: &'static str,
    pub replacement: &'static str,
    /// Filled by release preparation when the new syntax first ships.
    pub deprecated_since: Option<&'static str>,
    pub remove_in: Option<&'static str>,
    pub retired: bool,
}
macro_rules! legacy {
    ($name:literal, $replacement:literal) => {
        LegacyCommand {
            name: $name,
            replacement: $replacement,
            deprecated_since: None,
            remove_in: None,
            retired: false,
        }
    };
}
pub const LEGACY: &[LegacyCommand] = &[
    legacy!(
        "restore-snapshot",
        "rosec vault snapshot restore <snapshot> --path <file> --yes"
    ),
    legacy!("auth", "rosec provider <id> unlock"),
    legacy!("add-password", "rosec provider <id> password add"),
    legacy!("remove-password", "rosec provider <id> password remove"),
    legacy!("list-passwords", "rosec provider <id> password list"),
    legacy!("change-password", "rosec provider <id> password change"),
];
pub struct Prepared {
    pub cli: Cli,
    pub instance: Option<ProviderRequest>,
    pub legacy: Option<&'static LegacyCommand>,
}
fn error(message: impl Into<String>) -> clap::Error {
    clap::Error::raw(ErrorKind::InvalidValue, message.into())
}
pub fn parse_from(args: impl IntoIterator<Item = OsString>) -> Result<Prepared, clap::Error> {
    let mut command = Cli::command();
    command = command.mut_subcommand("provider", |mut p| {
        for spec in LEGACY {
            p = p.mut_subcommand(spec.name, |c| {
                c.about(format!("Deprecated; use: {}", spec.replacement))
            });
        }
        p
    });
    let matches = command.try_get_matches_from(args)?;
    prepare(Cli::from_arg_matches(&matches)?)
}
fn prepare(mut cli: Cli) -> Result<Prepared, clap::Error> {
    let mut instance = None;
    let mut legacy = None;
    if let Commands::Provider { id, action } = &mut cli.command {
        let explicit = id.take();
        match action.take() {
            Some(ProviderCommands::Instance(mut args)) => {
                let id = match explicit {
                    Some(id) => id,
                    None => {
                        let name = args
                            .remove(0)
                            .into_string()
                            .map_err(|_| error("provider ID must be UTF-8"))?;
                        if LEGACY.iter().any(|s| s.name == name) {
                            return Err(error(
                                "retired command name; use --id to select this provider explicitly",
                            ));
                        }
                        name
                    }
                };
                let parsed = InstanceCli::try_parse_from(
                    std::iter::once(OsString::from("rosec provider <id>")).chain(args),
                )?;
                if let Some(config) = parsed.config {
                    cli.config = Some(config);
                }
                cli.deny_deprecated |= parsed.deny_deprecated;
                instance = Some(ProviderRequest {
                    id,
                    operation: parsed.operation,
                });
            }
            value if explicit.is_some() => {
                let _ = value;
                return Err(error(
                    "--id requires an instance operation: status, unlock, sync or password",
                ));
            }
            Some(ProviderCommands::RestoreSnapshot {
                path,
                snapshot,
                yes,
            }) => {
                legacy = LEGACY.iter().find(|spec| spec.name == "restore-snapshot");
                cli.command = Commands::Vault {
                    action: crate::cli::VaultCommands::Snapshot {
                        action: crate::cli::VaultSnapshotCommands::Restore(
                            crate::cli::SnapshotRestoreArgs {
                                path,
                                snapshot,
                                yes,
                            },
                        ),
                    },
                };
            }
            Some(value) => {
                let (name, request) = match value {
                    ProviderCommands::Auth(a) => (
                        "auth",
                        ProviderRequest {
                            id: a.id,
                            operation: ProviderOperation::Unlock { force: a.force },
                        },
                    ),
                    ProviderCommands::AddPassword(a) => (
                        "add-password",
                        ProviderRequest {
                            id: a.id,
                            operation: ProviderOperation::Password {
                                action: PasswordOperation::Add { label: a.label },
                            },
                        },
                    ),
                    ProviderCommands::RemovePassword(a) => (
                        "remove-password",
                        ProviderRequest {
                            id: a.id,
                            operation: ProviderOperation::Password {
                                action: PasswordOperation::Remove {
                                    entry_id: a.entry_id,
                                },
                            },
                        },
                    ),
                    ProviderCommands::ListPasswords(a) => (
                        "list-passwords",
                        ProviderRequest {
                            id: a.id,
                            operation: ProviderOperation::Password {
                                action: PasswordOperation::List,
                            },
                        },
                    ),
                    ProviderCommands::ChangePassword(a) => (
                        "change-password",
                        ProviderRequest {
                            id: a.id,
                            operation: ProviderOperation::Password {
                                action: PasswordOperation::Change,
                            },
                        },
                    ),
                    other => {
                        *action = Some(other);
                        return Ok(Prepared {
                            cli,
                            instance,
                            legacy,
                        });
                    }
                };
                legacy = LEGACY.iter().find(|s| s.name == name);
                instance = Some(request);
            }
            None => (),
        }
    }
    if let Some(spec) = legacy {
        enforce(spec, cli.deny_deprecated)?;
    }
    Ok(Prepared {
        cli,
        instance,
        legacy,
    })
}
fn enforce(spec: &LegacyCommand, deny: bool) -> Result<(), clap::Error> {
    if spec.retired || deny {
        return Err(error(format!(
            "deprecated command syntax: provider {}.\nUse: {}",
            spec.name, spec.replacement
        )));
    }
    Ok(())
}
pub fn warning(spec: &LegacyCommand, terminal: bool) -> Option<String> {
    if !terminal {
        return None;
    }
    let since = spec
        .deprecated_since
        .map(|v| format!(" since {v}"))
        .unwrap_or_default();
    let removal = spec
        .remove_in
        .map(|v| format!(" Scheduled for removal in {v}."))
        .unwrap_or_default();
    Some(format!(
        "warning: 'provider {}' is deprecated{since}; use '{}'.{removal}",
        spec.name, spec.replacement
    ))
}
#[cfg(test)]
mod tests {
    use super::*;
    fn parsed(args: &[&str]) -> Prepared {
        parse_from(args.iter().map(OsString::from)).unwrap_or_else(|e| panic!("{e}"))
    }
    #[test]
    fn both_spellings_normalize_identically() {
        for (old, new) in [
            (
                vec!["provider", "auth", "personal", "--force"],
                vec!["provider", "personal", "unlock", "--force"],
            ),
            (
                vec!["provider", "add-password", "personal", "--label", "laptop"],
                vec![
                    "provider", "personal", "password", "add", "--label", "laptop",
                ],
            ),
            (
                vec!["provider", "remove-password", "personal", "entry"],
                vec!["provider", "personal", "password", "remove", "entry"],
            ),
            (
                vec!["provider", "list-passwords", "personal"],
                vec!["provider", "personal", "password", "list"],
            ),
            (
                vec!["provider", "change-password", "personal"],
                vec!["provider", "personal", "password", "change"],
            ),
        ] {
            let old = parsed(&[vec!["rosec"], old].concat());
            let new = parsed(&[vec!["rosec"], new].concat());
            assert_eq!(old.instance, new.instance);
            assert!(old.legacy.is_some());
            assert!(new.legacy.is_none());
        }
    }
    #[test]
    fn global_flags_after_instance_are_preserved() {
        let cli = parsed(&[
            "rosec",
            "provider",
            "personal",
            "unlock",
            "--config",
            "custom.toml",
            "--deny-deprecated",
        ]);
        assert_eq!(
            cli.cli.config.unwrap(),
            std::path::PathBuf::from("custom.toml")
        );
        assert!(cli.cli.deny_deprecated);
    }
    #[test]
    fn warnings_are_terminal_only_and_removal_is_unscheduled() {
        assert!(warning(&LEGACY[0], false).is_none());
        let text = warning(&LEGACY[0], true).unwrap();
        assert!(text.contains("deprecated"));
        assert!(!text.contains("Scheduled"));
    }
    #[test]
    fn retirement_blocks_without_strict_mode() {
        let mut spec = legacy!("old-name", "rosec provider <id> unlock");
        spec.retired = true;
        assert!(enforce(&spec, false).is_err());
    }
    #[test]
    fn native_recovery_spellings_normalize_identically() {
        fn args(prepared: Prepared) -> crate::cli::SnapshotRestoreArgs {
            let Commands::Vault {
                action:
                    crate::cli::VaultCommands::Snapshot {
                        action: crate::cli::VaultSnapshotCommands::Restore(args),
                    },
            } = prepared.cli.command
            else {
                panic!("not normalized");
            };
            args
        }
        let old = parsed(&[
            "rosec",
            "provider",
            "restore-snapshot",
            "--path",
            "vault",
            "--snapshot",
            "backup",
            "--yes",
        ]);
        let new = parsed(&[
            "rosec", "vault", "snapshot", "restore", "backup", "--path", "vault", "--yes",
        ]);
        assert!(old.legacy.is_some());
        assert!(new.legacy.is_none());
        assert_eq!(args(old), args(new));
    }
}
