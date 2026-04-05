//! CLI argument definitions using clap derive.
//!
//! `-h` shows concise help (about text only).
//! `--help` shows full help including examples (long_about + after_long_help).

use clap::{Parser, Subcommand, ValueEnum};

// ───────────────────────────────────────────────────────────────────────────
// Top-level
// ───────────────────────────────────────────────────────────────────────────

#[derive(Parser)]
#[command(
    name = "rosec",
    about = "read-only secret service CLI",
    long_about = "read-only secret service CLI\n\n\
        rosec provides a unified interface to multiple secret providers\n\
        (local encrypted vaults, Bitwarden, WASM plugins) via the\n\
        freedesktop.org Secret Service D-Bus API.",
    version = env!("ROSEC_VERSION"),
    long_version = concat!(env!("ROSEC_VERSION"), " (", env!("ROSEC_GIT_SHA"), ")"),
    subcommand_required = true,
    arg_required_else_help = true,
    after_long_help = "\
SEARCH FILTERS:
    Pass one or more key=value pairs to filter by public attributes:
      type=login                        Only login items
      username=alice                    Items with username 'alice'
      type=login username=alice         Combine filters (AND)
      uri=github.com                    Items with a matching URI attribute
    Common attribute names: type, username, uri, folder, name

NOTES:
    If a provider is locked when running 'search' or 'get', you will be
    prompted for credentials automatically and the operation retried.

    The 16-char hex ID shown in 'search' output is unique and stable.
    Pass it directly to 'rosec get'.

EXAMPLES:
  Providers:
    rosec provider add local                                create a new local vault
    rosec provider add bitwarden email=you@example.com      add Bitwarden (ID auto-generated)
    rosec provider attach --path /mnt/shared/team.vault     attach an existing vault file
    rosec provider auth personal                            unlock a provider
    rosec provider add-password personal --label laptop     add a second unlock password

  Searching & reading:
    rosec search type=login username=alice                  combine filters (AND)
    rosec search -s name=\"*prod*\"                           sync first, glob on name
    rosec search --format=json type=ssh-key                 JSON output
    rosec get a1b2c3d4e5f60718 | xclip -sel clip            copy secret to clipboard
    rosec get --attr username name=MY_API_KEY               print an attribute value
    rosec inspect -s --all-attrs a1b2c3d4e5f60718           full detail + sensitive attrs

  Creating & editing:
    rosec item add --type=login                             create via $EDITOR
    rosec item add --type=ssh-key --generate-ssh-key        generate + store SSH key
    rosec item edit a1b2c3d4e5f60718                        edit via $EDITOR
    rosec item delete -y a1b2c3d4e5f60718                   delete without confirmation

  Export / import:
    rosec item export a1b2c3d4e5f60718 > backup.toml        backup to file
    rosec item import --provider=my-vault < backup.toml      restore into a provider
    rosec item export ID | rosec item import                 copy between providers

  Configuration:
    rosec config set autolock.idle_timeout_minutes 30       set a config value (hot-reloads)
    rosec enable --mask                                     activate + suppress gnome-keyring",
)]
pub struct Cli {
    #[command(subcommand)]
    pub command: Commands,
}

#[derive(Subcommand)]
pub enum Commands {
    /// Manage providers
    #[command(alias = "providers")]
    Provider {
        #[command(subcommand)]
        action: Option<ProviderCommands>,
    },

    /// Read or modify config.toml
    Config {
        #[command(subcommand)]
        action: Option<ConfigCommands>,
    },

    /// Show daemon status
    Status,

    /// Sync providers with remote servers
    #[command(alias = "refresh")]
    Sync,

    /// Search items by attributes (no args = list all)
    #[command(
        long_about = "Search items by attributes (no args = list all)\n\n\
            Pass one or more key=value pairs to filter by public attributes (AND semantics).\n\
            Glob metacharacters (*, ?, [...]) are accepted.\n\
            The special key 'name' matches the item label.",
        after_long_help = "\
EXAMPLES:
    rosec search                                    list all items
    rosec search -s                                 sync first, then list all
    rosec search --no-unlock                        search without prompting
    rosec search type=login                         only login items
    rosec search username=alice                     items with username 'alice'
    rosec search rosec:provider=personal            items from 'personal' provider
    rosec search type=login username=alice          combine filters
    rosec search name=\"GitHub*\"                     glob on item name
    rosec search --format=json type=login           JSON output
    rosec search --format=kv uri=github.com         key=value output
    rosec search --show-path type=login             table with D-Bus path column"
    )]
    Search(SearchArgs),

    /// Manage items
    #[command(alias = "items")]
    Item {
        #[command(subcommand)]
        action: Option<ItemCommands>,
    },

    /// Print the secret value only (pipeable)
    #[command(
        long_about = "Print the secret value only (pipeable)\n\n\
            By default prints the primary secret. Use --attr to print a named\n\
            public attribute instead.",
        after_long_help = "\
EXAMPLES:
    rosec get a1b2c3d4e5f60718                    by hex ID
    rosec get name=MY_API_KEY                     by exact name
    rosec get 'name=*prod*'                       by name glob
    rosec get uri=github.com                      by URI attribute
    rosec get --sync name=MY_API_KEY              sync first, then fetch
    rosec get --no-unlock a1b2c3d4e5f60718        no prompting
    rosec get a1b2c3d4e5f60718 | xclip -sel clip  pipe to clipboard
    rosec get --attr username name=MY_API_KEY     print username attribute"
    )]
    Get(GetArgs),

    /// Show full item detail: label, attributes, secret
    #[command(after_long_help = "\
EXAMPLES:
    rosec inspect a1b2c3d4e5f60718
    rosec inspect -s a1b2c3d4e5f60718
    rosec inspect -s --all-attrs a1b2c3d4e5f60718
    rosec inspect --all-attrs --format=kv a1b2c3d4e5f60718
    rosec inspect --all-attrs --format=json a1b2c3d4e5f60718")]
    Inspect(InspectArgs),

    /// Lock all providers
    Lock,

    /// Unlock (triggers GUI/TTY prompt)
    Unlock,

    /// Activate rosec as the Secret Service provider
    #[command(
        long_about = "Activate rosec as the Secret Service provider\n\n\
            Generates and installs user-local D-Bus activation files and systemd user\n\
            units so that org.freedesktop.secrets is handled by rosecd.\n\n\
            The rosecd binary path is resolved automatically (sibling of the rosec\n\
            binary, or from $PATH) and embedded into all generated files.",
        after_long_help = "\
FILES INSTALLED:
    ~/.local/share/dbus-1/services/org.freedesktop.secrets.service
        Routes D-Bus activation of org.freedesktop.secrets to rosecd.

    ~/.config/systemd/user/rosecd.service
        systemd user service unit with the resolved rosecd path.

    ~/.config/systemd/user/rosecd.socket
        systemd user socket unit for private-socket activation.

FILES INSTALLED WITH --mask:
    ~/.local/share/dbus-1/services/org.gnome.keyring.service
        Masks gnome-keyring D-Bus auto-activation. User-local files
        take priority over system-wide /usr/share/dbus-1/services/.

    ~/.config/autostart/gnome-keyring-secrets.desktop
        Hides the gnome-keyring XDG autostart entry so your desktop
        session does not launch it automatically.

    systemctl --user mask gnome-keyring-daemon.socket
        Masks the gnome-keyring systemd user socket.

NOTES:
    This command does NOT modify any system files or conflict with
    installed packages. All files are written to user-local directories.
    Run `rosec disable` to reverse all changes."
    )]
    Enable(EnableArgs),

    /// Deactivate rosec (remove D-Bus overrides)
    #[command(long_about = "Deactivate rosec (remove D-Bus overrides)\n\n\
            Removes all files installed by `rosec enable`:\n  \
            - D-Bus activation files from ~/.local/share/dbus-1/services/\n  \
            - systemd user units from ~/.config/systemd/user/\n  \
            - gnome-keyring autostart overrides from ~/.config/autostart/\n  \
            - gnome-keyring systemd socket mask (systemctl --user unmask)\n\n\
            Only removes files that rosec created. If gnome-keyring was masked,\n\
            the mask files are removed and the systemd socket is unmasked,\n\
            allowing gnome-keyring to resume handling Secret Service requests.")]
    Disable(DisableArgs),
}

// ───────────────────────────────────────────────────────────────────────────
// Output format (shared)
// ───────────────────────────────────────────────────────────────────────────

#[derive(Clone, Copy, Debug, PartialEq, Eq, ValueEnum)]
pub enum Format {
    /// Aligned columns (default for search/item list)
    Table,
    /// Key=value pairs, one attribute per line per item
    Kv,
    /// JSON array/object (always includes full path)
    Json,
    /// Labelled sections (default for inspect)
    Human,
}

// ───────────────────────────────────────────────────────────────────────────
// search
// ───────────────────────────────────────────────────────────────────────────

#[derive(Parser)]
pub struct SearchArgs {
    /// Sync providers before searching; also unlocks if needed
    #[arg(short = 's', long = "sync")]
    pub sync: bool,

    /// Never prompt for credentials — only show cached/unlocked items
    #[arg(long)]
    pub no_unlock: bool,

    /// Output format: table (default), kv, json
    #[arg(long, value_enum, default_value_t = Format::Table)]
    pub format: Format,

    /// Also print the full D-Bus object path for each item
    #[arg(long)]
    pub show_path: bool,

    /// Attribute filters: key=value pairs (AND semantics, globs accepted)
    #[arg(trailing_var_arg = true)]
    pub filters: Vec<String>,
}

// ───────────────────────────────────────────────────────────────────────────
// get
// ───────────────────────────────────────────────────────────────────────────

#[derive(Parser)]
pub struct GetArgs {
    /// Sync providers before fetching
    #[arg(short = 's', long = "sync")]
    pub sync: bool,

    /// Never prompt for credentials — only use cached/unlocked items
    #[arg(long)]
    pub no_unlock: bool,

    /// Print a named public attribute instead of the primary secret
    #[arg(long)]
    pub attr: Option<String>,

    /// Item identifier: 16-char hex ID, key=value filter, or D-Bus object path
    pub item: String,
}

// ───────────────────────────────────────────────────────────────────────────
// inspect
// ───────────────────────────────────────────────────────────────────────────

#[derive(Parser)]
pub struct InspectArgs {
    /// Also fetch and display sensitive attributes (password, totp, notes, etc.)
    #[arg(short = 'a', long)]
    pub all_attrs: bool,

    /// Sync providers before inspecting; also unlocks if needed
    #[arg(short = 's', long = "sync")]
    pub sync: bool,

    /// Output format: human (default), kv, json
    #[arg(long, value_enum, default_value_t = Format::Human)]
    pub format: Format,

    /// Item identifier: 16-char hex ID or full D-Bus object path
    pub item: String,
}

// ───────────────────────────────────────────────────────────────────────────
// enable / disable
// ───────────────────────────────────────────────────────────────────────────

#[derive(Parser)]
pub struct EnableArgs {
    /// Do not install/enable systemd user units
    #[arg(long)]
    pub no_systemd: bool,

    /// Suppress gnome-keyring (D-Bus, autostart, systemd socket)
    #[arg(long)]
    pub mask: bool,

    /// Overwrite existing files even if already enabled
    #[arg(short = 'f', long)]
    pub force: bool,
}

#[derive(Parser)]
pub struct DisableArgs {
    /// Do not remove/disable systemd user units
    #[arg(long)]
    pub no_systemd: bool,
}

// ───────────────────────────────────────────────────────────────────────────
// provider subcommands
// ───────────────────────────────────────────────────────────────────────────

#[derive(Subcommand)]
pub enum ProviderCommands {
    /// List all configured providers and their state
    #[command(alias = "ls")]
    List,

    /// List available provider kinds
    Kinds,

    /// Authenticate/unlock a provider
    Auth(ProviderAuthArgs),

    /// Add a provider to config.toml
    #[command(
        long_about = "Add a provider to config.toml\n\n\
            For provider-specific required and optional options, run `rosec provider kinds`.",
        after_long_help = "\
EXAMPLES:
    rosec provider add local                                create a new local vault
    rosec provider add local --id work --path ~/vaults/work.vault
    rosec provider add bitwarden email=you@example.com
    rosec provider add bitwarden --id work email=work@corp.com region=eu
    rosec provider add bitwarden-sm organization_id=uuid"
    )]
    Add(ProviderAddArgs),

    /// Remove a provider (local vaults: offers to delete the file)
    #[command(alias = "rm")]
    Remove(ProviderIdArg),

    /// Enable a disabled provider
    Enable(ProviderIdArg),

    /// Temporarily disable a provider
    Disable(ProviderIdArg),

    /// Attach an existing vault file to the config
    #[command(after_long_help = "\
EXAMPLES:
    rosec provider attach --path /mnt/shared/team.vault
    rosec provider attach --path ~/vaults/work.vault --id work")]
    Attach(ProviderAttachArgs),

    /// Remove provider from config (file stays on disk)
    Detach(ProviderIdArg),

    /// Add a new unlock password to a local vault provider
    #[command(after_long_help = "\
EXAMPLES:
    rosec provider add-password personal
    rosec provider add-password personal --label laptop")]
    AddPassword(ProviderAddPasswordArgs),

    /// Remove a password from a local vault provider
    RemovePassword(ProviderRemovePasswordArgs),

    /// List unlock passwords for a local vault provider
    ListPasswords(ProviderIdArg),

    /// Change the unlock password for a provider
    ChangePassword(ProviderIdArg),
}

#[derive(Parser)]
pub struct ProviderAuthArgs {
    /// Provider ID
    pub id: String,

    /// Re-run registration even when stored credentials already exist
    #[arg(short = 'f', long)]
    pub force: bool,
}

#[derive(Parser)]
pub struct ProviderAddArgs {
    /// Provider kind (local, bitwarden, bitwarden-sm, or a WASM plugin kind)
    pub kind: String,

    /// Override auto-generated ID
    #[arg(long)]
    pub id: Option<String>,

    /// Path to the vault file (local vaults only)
    #[arg(long)]
    pub path: Option<String>,

    /// Collection label for grouping items
    #[arg(long)]
    pub collection: Option<String>,

    /// Provider options as key=value pairs
    #[arg(trailing_var_arg = true)]
    pub options: Vec<String>,
}

#[derive(Parser)]
pub struct ProviderIdArg {
    /// Provider ID
    pub id: String,
}

#[derive(Parser)]
pub struct ProviderAttachArgs {
    /// Path to the existing vault file
    #[arg(long)]
    pub path: String,

    /// Override auto-generated ID
    #[arg(long)]
    pub id: Option<String>,

    /// Collection label for grouping items
    #[arg(long)]
    pub collection: Option<String>,
}

#[derive(Parser)]
pub struct ProviderAddPasswordArgs {
    /// Provider ID
    pub id: String,

    /// Human-readable label for the password entry
    #[arg(long)]
    pub label: Option<String>,
}

#[derive(Parser)]
pub struct ProviderRemovePasswordArgs {
    /// Provider ID
    pub id: String,

    /// Password entry ID to remove
    pub entry_id: String,
}

// ───────────────────────────────────────────────────────────────────────────
// config subcommands
// ───────────────────────────────────────────────────────────────────────────

#[derive(Subcommand)]
pub enum ConfigCommands {
    /// Print the current effective configuration as TOML
    Show {
        /// Include fields set to their default values
        #[arg(long, alias = "show-default")]
        show_defaults: bool,
    },

    /// Print the value of one setting
    #[command(after_long_help = "\
SETTABLE KEYS:
    service.refresh_interval_secs       Vault re-sync interval in seconds (0 = disabled)
    service.dedup_strategy              Deduplication strategy: newest | priority
    service.dedup_time_fallback         Tie-break field when strategy=newest: created | none
    autolock.on_logout                  Lock vault when the session ends (true | false)
    autolock.on_session_lock            Lock vault when the screen locks (true | false)
    autolock.idle_timeout_minutes       Lock after N minutes of inactivity (0 = disabled)
    autolock.max_unlocked_minutes       Hard cap: lock after N minutes unlocked (0 = disabled)")]
    Get {
        /// Dotted config key (e.g. autolock.idle_timeout_minutes)
        key: String,
    },

    /// Update a setting in config.toml (daemon hot-reloads automatically)
    #[command(after_long_help = "\
EXAMPLES:
    rosec config set autolock.idle_timeout_minutes 30
    rosec config set autolock.on_session_lock false
    rosec config set service.refresh_interval_secs 120")]
    Set {
        /// Dotted config key
        key: String,
        /// New value
        value: String,
    },
}

// ───────────────────────────────────────────────────────────────────────────
// item subcommands
// ───────────────────────────────────────────────────────────────────────────

#[derive(Subcommand)]
pub enum ItemCommands {
    /// List items (delegates to search)
    #[command(
        alias = "ls",
        after_long_help = "\
EXAMPLES:
    rosec item list                                         list all items
    rosec item list --provider=local-default                items from one provider
    rosec item list --type=login username=alice              login items for alice
    rosec item list --format=json --type=ssh-key             SSH keys as JSON"
    )]
    List(ItemListArgs),

    /// Create a new item via $EDITOR (TOML template)
    #[command(
        aliases = ["new", "create"],
        after_long_help = "\
EXAMPLES:
    rosec item add                                          create generic item via $EDITOR
    rosec item add --type=login --provider=local-default     create login in specific vault
    rosec item add --type=ssh-key --generate-ssh-key         generate + store SSH key",
    )]
    Add(ItemAddArgs),

    /// Edit an existing item via $EDITOR
    #[command(after_long_help = "\
EXAMPLES:
    rosec item edit a1b2c3d4e5f60718                         edit item by ID
    rosec item edit name=My\\ Login                           edit item by name")]
    Edit(ItemEditArgs),

    /// Delete an item (with confirmation)
    #[command(
        aliases = ["rm", "remove"],
        after_long_help = "\
EXAMPLES:
    rosec item delete a1b2c3d4e5f60718                       delete with confirmation
    rosec item delete -y a1b2c3d4e5f60718                    delete without confirmation",
    )]
    Delete(ItemDeleteArgs),

    /// Export an item as TOML to stdout
    #[command(after_long_help = "\
EXAMPLES:
    rosec item export a1b2c3d4e5f60718                       export item as TOML
    rosec item export a1b2c3d4e5f60718 > backup.toml         export to file
    rosec item export <bitwarden-item> | rosec item import   copy between providers")]
    Export(ItemExportArgs),

    /// Import an item from TOML on stdin
    #[command(after_long_help = "\
EXAMPLES:
    rosec item import < backup.toml                          import from file
    rosec item import --provider=my-vault < backup.toml      import into specific provider")]
    Import(ItemImportArgs),
}

#[derive(Parser)]
pub struct ItemListArgs {
    /// Only items from this provider
    #[arg(long)]
    pub provider: Option<String>,

    /// Only items of this type (login, ssh-key, note, ...)
    #[arg(long = "type")]
    pub item_type: Option<String>,

    /// Output format: table (default), kv, json
    #[arg(long, value_enum, default_value_t = Format::Table)]
    pub format: Format,

    /// Also print the full D-Bus object path
    #[arg(long)]
    pub show_path: bool,

    /// Sync/unlock providers before listing
    #[arg(short = 's', long = "sync")]
    pub sync: bool,

    /// Skip interactive unlock prompts
    #[arg(long)]
    pub no_unlock: bool,

    /// Attribute filters: key=value pairs
    #[arg(trailing_var_arg = true)]
    pub filters: Vec<String>,
}

#[derive(Parser)]
pub struct ItemAddArgs {
    /// Target provider (default: first write-capable)
    #[arg(long)]
    pub provider: Option<String>,

    /// Item type: generic, login, ssh-key, note, card, identity
    #[arg(long = "type", default_value = "generic")]
    pub item_type: String,

    /// Generate an ed25519 SSH key pair
    #[arg(long)]
    pub generate_ssh_key: bool,
}

#[derive(Parser)]
pub struct ItemEditArgs {
    /// Sync/unlock providers before editing
    #[arg(short = 's', long = "sync")]
    pub sync: bool,

    /// Item identifier: 16-char hex ID, key=value filter, or D-Bus object path
    pub item: String,
}

#[derive(Parser)]
pub struct ItemDeleteArgs {
    /// Sync/unlock providers before deleting
    #[arg(short = 's', long = "sync")]
    pub sync: bool,

    /// Skip confirmation prompt
    #[arg(short = 'y', long)]
    pub yes: bool,

    /// Item identifier: 16-char hex ID, key=value filter, or D-Bus object path
    pub item: String,
}

#[derive(Parser)]
pub struct ItemExportArgs {
    /// Sync/unlock providers before exporting
    #[arg(short = 's', long = "sync")]
    pub sync: bool,

    /// Item identifier: 16-char hex ID, key=value filter, or D-Bus object path
    pub item: String,
}

#[derive(Parser)]
pub struct ItemImportArgs {
    /// Target provider (default: first write-capable)
    #[arg(long)]
    pub provider: Option<String>,
}
