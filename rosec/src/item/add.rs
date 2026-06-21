//! `rosec item add` — create a new item via $EDITOR.
//!
//! 1. Parse flags (`--provider`, `--type`, `--generate-ssh-key`)
//! 2. Verify write capability via D-Bus `GetCapabilities`
//! 3. Generate a TOML template for the item type
//! 4. Open `$EDITOR` for the user to fill in
//! 5. Parse the edited TOML
//! 6. Call `CreateItemExtended` on `org.rosec.Items`
//! 7. Print the created item path / ID

use anyhow::{Result, bail};

use crate::cli::ItemAddArgs;
use crate::{conn, is_rosecd};

use super::{open_editor, parse_item_toml, toml_quote};

pub async fn run(args: ItemAddArgs) -> Result<()> {
    let provider_id = args.provider.unwrap_or_default();
    let mut item_type = args.item_type;
    let generate_ssh_key = args.generate_ssh_key;

    item_type
        .parse::<rosec_core::ItemType>()
        .map_err(|e| anyhow::anyhow!("{e}"))?;

    if generate_ssh_key && item_type != "ssh-key" {
        // Auto-set the type when --generate-ssh-key is used without --type.
        if item_type == "generic" {
            item_type = "ssh-key".to_string();
        } else {
            bail!("--generate-ssh-key can only be used with --type=ssh-key");
        }
    }

    let conn = conn().await?;
    if !is_rosecd(&conn).await {
        bail!("rosec item add requires rosecd (the rosec daemon) to be running");
    }

    let items_proxy = zbus::Proxy::new(
        &conn,
        "org.freedesktop.secrets",
        "/org/rosec/Items",
        "org.rosec.Items",
    )
    .await?;

    let caps: Vec<String> = items_proxy
        .call("GetCapabilities", &(&provider_id,))
        .await?;
    if !caps.iter().any(|c| c == "Write") {
        if provider_id.is_empty() {
            bail!("no write-capable provider available — add a local vault first");
        } else {
            bail!("provider '{provider_id}' does not support writes");
        }
    }

    let supported_types: Vec<String> = items_proxy
        .call("GetSupportedItemTypes", &(&provider_id,))
        .await?;
    if !supported_types.is_empty() && !supported_types.contains(&item_type) {
        bail!(
            "provider does not support item type '{item_type}'\nsupported: {}",
            supported_types.join(", ")
        );
    }

    // `is_rosecd` returned true above, so the rosec Search extension is
    // available for conflict detection.
    let rosecd = true;

    // Carry the editor buffer across iterations so "edit again" reopens the
    // user's last text rather than the blank template.
    let mut buffer = if generate_ssh_key {
        generate_ssh_key_template()?
    } else {
        generate_item_template(&item_type)
    };

    loop {
        let edited = open_editor(&buffer)?;
        let content = match edited {
            Some(c) => c,
            None => {
                println!("No changes — item not created.");
                return Ok(());
            }
        };

        let parsed = parse_item_toml(&content)?;

        if parsed.secrets.is_empty() && parsed.attributes.is_empty() {
            bail!("item has no attributes or secrets — nothing to store");
        }

        // Detect items this would duplicate before writing anything, so the
        // user can choose what to do instead of hitting a bare "already
        // exists" error.
        let conflicts = super::find_conflicts(
            &conn,
            rosecd,
            &provider_id,
            &parsed.label,
            &parsed.attributes,
        )
        .await;

        let replace = if conflicts.is_empty() {
            false
        } else {
            print_conflicts(&conflicts, parsed.attributes.is_empty());
            match prompt_conflict_action()? {
                ConflictAction::Replace => true,
                ConflictAction::Edit => {
                    buffer = content;
                    continue;
                }
                ConflictAction::Cancel => {
                    println!("Cancelled — item not created.");
                    return Ok(());
                }
            }
        };

        let item_path: String = items_proxy
            .call(
                "CreateItemExtended",
                &(
                    &parsed.label,
                    &parsed.item_type,
                    &parsed.attributes,
                    &parsed.secrets,
                    replace,
                ),
            )
            .await?;

        let display_id = item_path
            .rsplit('/')
            .next()
            .and_then(|seg| seg.rsplit('_').next())
            .unwrap_or(&item_path);

        let verb = if replace { "Updated" } else { "Created" };
        println!("{verb} item: {} ({})", parsed.label, display_id);
        return Ok(());
    }
}

enum ConflictAction {
    Replace,
    Edit,
    Cancel,
}

/// Print the items a pending create would duplicate.
fn print_conflicts(conflicts: &[crate::ItemSummary], by_label: bool) {
    let matched = if by_label {
        "the same label"
    } else {
        "the same attributes"
    };
    eprintln!("An item with {matched} already exists:");
    for c in conflicts {
        if c.attrs.is_empty() || by_label {
            eprintln!("  • {} ({})", c.label, c.display_id());
        } else {
            let mut keys: Vec<&String> = c
                .attrs
                .keys()
                .filter(|k| !k.starts_with("rosec:") && !k.starts_with("xdg:"))
                .collect();
            keys.sort();
            let attrs = keys
                .iter()
                .map(|k| format!("{k}={}", c.attrs[*k]))
                .collect::<Vec<_>>()
                .join(", ");
            eprintln!("  • {} ({})  [{attrs}]", c.label, c.display_id());
        }
    }
}

/// Prompt for how to resolve a create conflict.  Defaults to cancel.
fn prompt_conflict_action() -> Result<ConflictAction> {
    use std::io::{self, BufRead, Write};

    eprint!("[r]eplace existing, [e]dit again, or [c]ancel? [r/e/C] ");
    io::stderr().flush().ok();

    let mut line = String::new();
    io::stdin().lock().read_line(&mut line)?;
    match line.trim().to_lowercase().as_str() {
        "r" | "replace" => Ok(ConflictAction::Replace),
        "e" | "edit" => Ok(ConflictAction::Edit),
        _ => Ok(ConflictAction::Cancel),
    }
}

/// Generate an ed25519 SSH key pair and return a pre-populated TOML template.
///
/// The private key PEM is placed in `[secrets].private_key` as a multi-line
/// TOML string.  The public key (OpenSSH format) and fingerprint are placed
/// in `[attributes]`.  The user only needs to fill in the label.
fn generate_ssh_key_template() -> Result<String> {
    use ssh_key::{Algorithm, HashAlg, PrivateKey, rand_core::OsRng};

    let private_key = PrivateKey::random(&mut OsRng, Algorithm::Ed25519)
        .map_err(|e| anyhow::anyhow!("failed to generate SSH key: {e}"))?;

    let pem = private_key
        .to_openssh(ssh_key::LineEnding::LF)
        .map_err(|e| anyhow::anyhow!("failed to encode private key as PEM: {e}"))?;

    let public_key = private_key
        .public_key()
        .to_openssh()
        .map_err(|e| anyhow::anyhow!("failed to encode public key: {e}"))?;

    let fingerprint = private_key.fingerprint(HashAlg::Sha256);

    let pem_str: &str = &pem;

    let mut out = String::new();
    out.push_str("# rosec item — type: ssh-key (generated ed25519 key)\n");
    out.push_str("# Lines starting with '#' are comments and will be ignored.\n");
    out.push_str("# The private key below was generated fresh — fill in the label.\n\n");

    out.push_str("[item]\n");
    out.push_str("label = \"\"\n");
    out.push_str("type = \"ssh-key\"\n\n");

    out.push_str("[attributes]\n");
    out.push_str(&format!("public_key = {}\n", toml_quote(&public_key)));
    out.push_str(&format!("fingerprint = \"{fingerprint}\"\n\n"));

    out.push_str("[secrets]\n");
    out.push_str(&format!("private_key = \"\"\"\n{pem_str}\"\"\"\n"));
    out.push_str("notes = \"\"\n");

    Ok(out)
}

/// Generate a TOML template for a given item type, suitable for editing in $EDITOR.
///
/// The template has three sections: `[item]`, `[attributes]`, `[secrets]`.
/// Comments explain each field.  Empty string values are placeholders the user
/// fills in; they are stripped on parse (empty secrets are not stored).
fn generate_item_template(item_type: &str) -> String {
    match item_type {
        "login" => "\
# rosec item — type: login
# Lines starting with '#' are comments and will be ignored.
# Empty secret values will not be stored.

[item]
label = \"\"
type = \"login\"

[attributes]
username = \"\"
uri = \"\"

[secrets]
password = \"\"
totp = \"\"
notes = \"\"
"
        .to_string(),

        "ssh-key" => "\
# rosec item — type: ssh-key
# Lines starting with '#' are comments and will be ignored.
# Empty secret values will not be stored.
#
# Paste the PEM-encoded private key as the value of 'private_key' below.
# Multi-line values use triple quotes: private_key = \"\"\"...\"\"\"

[item]
label = \"\"
type = \"ssh-key\"

[attributes]
public_key = \"\"
fingerprint = \"\"

[secrets]
private_key = \"\"
notes = \"\"
"
        .to_string(),

        "note" => "\
# rosec item — type: note
# Lines starting with '#' are comments and will be ignored.
# The note body is stored as a secret.
#
# Multi-line notes use triple quotes: secret = \"\"\"...\"\"\"

[item]
label = \"\"
type = \"note\"

[attributes]

[secrets]
secret = \"\"
"
        .to_string(),

        "card" => "\
# rosec item — type: card
# Lines starting with '#' are comments and will be ignored.
# Empty secret values will not be stored.

[item]
label = \"\"
type = \"card\"

[attributes]
cardholder_name = \"\"
brand = \"\"
exp_month = \"\"
exp_year = \"\"

[secrets]
number = \"\"
security_code = \"\"
notes = \"\"
"
        .to_string(),

        "identity" => "\
# rosec item — type: identity
# Lines starting with '#' are comments and will be ignored.
# Empty secret values will not be stored.

[item]
label = \"\"
type = \"identity\"

[attributes]
title = \"\"
first_name = \"\"
middle_name = \"\"
last_name = \"\"
email = \"\"
phone = \"\"
company = \"\"
address1 = \"\"
address2 = \"\"
address3 = \"\"
city = \"\"
state = \"\"
postal_code = \"\"
country = \"\"

[secrets]
ssn = \"\"
passport_number = \"\"
license_number = \"\"
notes = \"\"
"
        .to_string(),

        // generic (default)
        _ => "\
# rosec item — type: generic
# Lines starting with '#' are comments and will be ignored.
# Empty secret values will not be stored.
#
# Add any key = \"value\" pairs you need under [attributes] or [secrets].

[item]
label = \"\"
type = \"generic\"

[attributes]

[secrets]
secret = \"\"
notes = \"\"
"
        .to_string(),
    }
}
