//! SSH key extraction from local-vault items.
//!
//! An item is an SSH key when it carries the `private_key` secret and either
//! a `rosec:type` of `ssh-key` or (for items created before type stamping)
//! SSH-shaped attributes. Metadata mapping lives here; the provider trait
//! impl in [`crate::provider`] delegates per item.

use std::time::SystemTime;

use base64::prelude::{BASE64_STANDARD, Engine};
use rosec_core::{ProviderError, SshKeyMeta, SshPrivateKeyMaterial};
use zeroize::Zeroizing;

use crate::types::VaultItemData;

pub(crate) fn is_ssh_key_item(item: &VaultItemData) -> bool {
    if !item.secrets.contains_key("private_key") {
        return false;
    }
    // Prefer explicit type check (handles aliases like "sshkey").
    let typed = rosec_core::ItemType::from_attributes(&item.attributes);
    if typed == rosec_core::ItemType::SshKey {
        return true;
    }
    // Fallback: items without rosec:type that have SSH key attributes
    // (fingerprint or public_key) are treated as SSH keys. This covers
    // items created before type stamping.
    !item.attributes.contains_key(rosec_core::ATTR_TYPE)
        && (item.attributes.contains_key("fingerprint")
            || item.attributes.contains_key("public_key"))
}

pub(crate) fn item_to_ssh_key_meta(item: &VaultItemData, provider_id: &str) -> SshKeyMeta {
    let public_key_openssh = item
        .attributes
        .get("public_key")
        .cloned()
        .filter(|v| !v.is_empty());
    let fingerprint = item
        .attributes
        .get("fingerprint")
        .cloned()
        .filter(|v| !v.is_empty());

    // Attribute keys ship under both `_` and `-` spellings for
    // historical reasons; collect values across both.
    let ssh_attr = |aliases: &[&str]| -> Vec<&str> {
        aliases
            .iter()
            .filter_map(|k| item.attributes.get(*k))
            .map(String::as_str)
            .collect()
    };

    let ssh_hosts: Vec<String> = ssh_attr(&["custom.ssh_host", "custom.ssh-host"])
        .into_iter()
        .flat_map(str::lines)
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .map(String::from)
        .collect();

    let signing_principals: Vec<String> = ssh_attr(&[
        "custom.ssh_signing_principal",
        "custom.ssh-signing-principal",
    ])
    .into_iter()
    .flat_map(str::lines)
    .map(str::trim)
    .filter(|s| !s.is_empty())
    .map(String::from)
    .collect();

    let ssh_user = ssh_attr(&["custom.ssh_user", "custom.ssh-user"])
        .into_iter()
        .map(|v| v.trim().to_string())
        .find(|s| !s.is_empty());

    let require_confirm = ssh_attr(&["custom.ssh_confirm", "custom.ssh-confirm"])
        .into_iter()
        .any(|v| v == "true");

    let revision_date =
        SystemTime::UNIX_EPOCH.checked_add(std::time::Duration::from_secs(item.modified as u64));

    SshKeyMeta {
        item_id: item.id.clone(),
        item_name: item.label.clone(),
        provider_id: provider_id.to_owned(),
        public_key_openssh,
        fingerprint,
        ssh_hosts,
        signing_principals,
        ssh_user,
        require_confirm,
        revision_date,
    }
}

pub(crate) fn item_ssh_private_key(
    item: &VaultItemData,
) -> Result<SshPrivateKeyMaterial, ProviderError> {
    let encoded = item
        .secrets
        .get("private_key")
        .ok_or(ProviderError::NotFound)?;

    let raw = BASE64_STANDARD
        .decode(encoded)
        .map_err(|e| ProviderError::Other(anyhow::anyhow!("base64 decode failed: {e}")))?;

    let pem = String::from_utf8(raw).map_err(|e| {
        ProviderError::Other(anyhow::anyhow!("private key is not valid UTF-8: {e}"))
    })?;

    Ok(SshPrivateKeyMaterial {
        pem: Zeroizing::new(pem),
    })
}
