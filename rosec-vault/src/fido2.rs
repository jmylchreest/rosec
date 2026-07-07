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

use std::collections::HashMap;
use std::time::SystemTime;

use base64::prelude::{BASE64_STANDARD, BASE64_URL_SAFE_NO_PAD, Engine};
use rosec_core::{
    Fido2CredentialMeta, Fido2KeyMaterial, ItemType, NewItem, ProviderError, SecretBytes,
};
use zeroize::Zeroizing;

use crate::types::VaultItemData;

/// A newly-created passkey to be written into the local vault by a
/// `makeCredential` ceremony. All the WebAuthn wire fields plus the freshly
/// generated PEM PKCS#8 private key.
#[derive(Clone)]
pub struct NewFido2Credential {
    /// Relying party identifier (e.g. `"github.com"`).
    pub rp_id: String,
    pub rp_name: Option<String>,
    /// Raw credential ID bytes as they appear on the WebAuthn wire.
    pub credential_id: Vec<u8>,
    /// Raw user handle bytes.
    pub user_handle: Vec<u8>,
    pub user_name: Option<String>,
    pub user_display_name: Option<String>,
    /// COSE algorithm id (`-7` ES256, `-8` EdDSA, `-257` RS256).
    pub algorithm: i64,
    /// Whether the credential is discoverable (resident).
    pub discoverable: bool,
    /// Whether user verification is required before assertions.
    pub require_uv: bool,
    /// PEM-encoded PKCS#8 private key.
    pub private_key_pem: Zeroizing<String>,
}

impl std::fmt::Debug for NewFido2Credential {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("NewFido2Credential")
            .field("rp_id", &self.rp_id)
            .field("user_name", &self.user_name)
            .field("algorithm", &self.algorithm)
            .field("discoverable", &self.discoverable)
            .field("private_key_pem", &"[redacted]")
            .finish()
    }
}

/// Human-readable vault label for a stored passkey, e.g.
/// `"Passkey: alice@github.com"` (falls back to the rpId).
fn passkey_label(cred: &NewFido2Credential) -> String {
    match &cred.user_name {
        Some(u) if !u.is_empty() => format!("Passkey: {u}@{}", cred.rp_id),
        _ => format!("Passkey: {}", cred.rp_id),
    }
}

/// Build the [`NewItem`] that stores `cred` as a local-vault passkey. The
/// generic `create_item` path base64-encodes the secret; the read path
/// ([`item_fido2_key`]) base64-decodes it back to the PEM, so we hand the
/// PEM bytes through verbatim. Attribute names match those consumed by
/// [`is_fido2_item`] / [`item_to_fido2_meta`].
pub fn new_item_for_credential(cred: &NewFido2Credential) -> NewItem {
    let mut attributes: HashMap<String, String> = HashMap::new();
    attributes.insert("fido2_rp_id".to_string(), cred.rp_id.clone());
    attributes.insert(
        "fido2_credential_id".to_string(),
        BASE64_URL_SAFE_NO_PAD.encode(&cred.credential_id),
    );
    if !cred.user_handle.is_empty() {
        attributes.insert(
            "fido2_user_handle".to_string(),
            BASE64_URL_SAFE_NO_PAD.encode(&cred.user_handle),
        );
    }
    if let Some(v) = &cred.rp_name {
        attributes.insert("fido2_rp_name".to_string(), v.clone());
    }
    if let Some(v) = &cred.user_name {
        attributes.insert("fido2_user_name".to_string(), v.clone());
    }
    if let Some(v) = &cred.user_display_name {
        attributes.insert("fido2_user_display_name".to_string(), v.clone());
    }
    attributes.insert("fido2_algorithm".to_string(), cred.algorithm.to_string());
    attributes.insert("fido2_counter".to_string(), "0".to_string());
    attributes.insert(
        "fido2_discoverable".to_string(),
        cred.discoverable.to_string(),
    );
    if cred.require_uv {
        attributes.insert("fido2_require_uv".to_string(), "true".to_string());
    }

    let mut secrets: HashMap<String, SecretBytes> = HashMap::new();
    secrets.insert(
        "fido2_private_key".to_string(),
        SecretBytes::new(cred.private_key_pem.as_bytes().to_vec()),
    );

    NewItem {
        label: passkey_label(cred),
        item_type: Some(ItemType::Login),
        attributes,
        secrets,
    }
}

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
