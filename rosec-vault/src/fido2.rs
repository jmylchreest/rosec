//! FIDO2 credential (passkey) extraction from local-vault items.
//!
//! A local-vault passkey is any item carrying the `fido2_rp_id` attribute
//! plus the `fido2_private_key` secret (PEM PKCS#8, stored base64-encoded
//! like the SSH `private_key` secret). Remaining `fido2_*` attributes are
//! optional metadata:
//!
//! | attribute                  | meaning                                   |
//! |----------------------------|-------------------------------------------|
//! | `fido2_credential_id`      | base64url raw credential ID (required)    |
//! | `fido2_rp_name`            | relying party display name                |
//! | `fido2_user_handle`        | base64url user handle                     |
//! | `fido2_user_name`          | account username at the RP                |
//! | `fido2_user_display_name`  | account display name at the RP            |
//! | `fido2_algorithm`          | COSE alg (default `-7` = ES256)           |
//! | `fido2_counter`            | signature counter (default `0`)           |
//! | `fido2_discoverable`       | `"false"` to mark non-resident            |
//! | `fido2_require_uv`         | `"true"` to force user verification       |

use std::time::SystemTime;

use base64::prelude::{BASE64_STANDARD, Engine};
use rosec_core::{Fido2CredentialMeta, Fido2KeyMaterial, ProviderError};
use zeroize::Zeroizing;

use crate::types::VaultItemData;

pub(crate) fn is_fido2_item(item: &VaultItemData) -> bool {
    item.attributes.contains_key("fido2_rp_id") && item.secrets.contains_key("fido2_private_key")
}

pub(crate) fn item_to_fido2_meta(
    item: &VaultItemData,
    provider_id: &str,
) -> Option<Fido2CredentialMeta> {
    let attr = |k: &str| item.attributes.get(k).cloned().filter(|v| !v.is_empty());
    let rp_id = attr("fido2_rp_id")?;
    let credential_id = attr("fido2_credential_id")?
        .trim_end_matches('=')
        .to_string();
    Some(Fido2CredentialMeta {
        item_id: item.id.clone(),
        credential_id,
        item_name: item.label.clone(),
        provider_id: provider_id.to_owned(),
        rp_id,
        rp_name: attr("fido2_rp_name"),
        user_handle: attr("fido2_user_handle").map(|s| s.trim_end_matches('=').to_string()),
        user_name: attr("fido2_user_name"),
        user_display_name: attr("fido2_user_display_name"),
        algorithm: attr("fido2_algorithm")
            .and_then(|s| s.parse().ok())
            .unwrap_or(-7),
        counter: attr("fido2_counter")
            .and_then(|s| s.parse().ok())
            .unwrap_or(0),
        discoverable: attr("fido2_discoverable").as_deref() != Some("false"),
        require_uv: attr("fido2_require_uv").as_deref() == Some("true"),
        revision_date: SystemTime::UNIX_EPOCH
            .checked_add(std::time::Duration::from_secs(item.modified as u64)),
    })
}

pub(crate) fn item_fido2_key(
    item: &VaultItemData,
    credential_id: &str,
) -> Result<Fido2KeyMaterial, ProviderError> {
    let stored_id = item
        .attributes
        .get("fido2_credential_id")
        .map(|s| s.trim_end_matches('='))
        .ok_or(ProviderError::NotFound)?;
    if stored_id != credential_id.trim_end_matches('=') {
        return Err(ProviderError::NotFound);
    }

    let encoded = item
        .secrets
        .get("fido2_private_key")
        .ok_or(ProviderError::NotFound)?;

    let raw = BASE64_STANDARD
        .decode(encoded)
        .map_err(|e| ProviderError::Other(anyhow::anyhow!("base64 decode failed: {e}")))?;

    let pem = String::from_utf8(raw).map_err(|e| {
        ProviderError::Other(anyhow::anyhow!("private key is not valid UTF-8: {e}"))
    })?;

    Ok(Fido2KeyMaterial {
        pem: Zeroizing::new(pem),
    })
}
