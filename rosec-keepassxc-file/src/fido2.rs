//! FIDO2 credential (passkey) extraction from KeePassXC KDBX entries.
//!
//! KeePassXC stores passkeys as custom entry attributes (since 2.7.7):
//!
//! - `KPEX_PASSKEY_USERNAME` — account username at the relying party
//! - `KPEX_PASSKEY_RELYING_PARTY` — rpId (e.g. `github.com`)
//! - `KPEX_PASSKEY_CREDENTIAL_ID` — base64url credential ID (protected)
//! - `KPEX_PASSKEY_PRIVATE_KEY_PEM` — PEM-encoded PKCS#8 key (protected)
//! - `KPEX_PASSKEY_USER_HANDLE` — base64url user handle (protected)
//!
//! The PEM is already in rosec's boundary format, so key retrieval is a
//! pass-through. The stored key may be ES256, Ed25519, or RSA-2048 —
//! KeePassXC creates ES256 by default; the COSE algorithm is sniffed from
//! the PKCS#8 DER's AlgorithmIdentifier OID.

use chrono::TimeZone;
use keepass::db::EntryRef;
use zeroize::Zeroizing;

use crate::protocol::WasmFido2CredentialMeta;

const ATTR_USERNAME: &str = "KPEX_PASSKEY_USERNAME";
const ATTR_RELYING_PARTY: &str = "KPEX_PASSKEY_RELYING_PARTY";
const ATTR_CREDENTIAL_ID: &str = "KPEX_PASSKEY_CREDENTIAL_ID";
const ATTR_PRIVATE_KEY_PEM: &str = "KPEX_PASSKEY_PRIVATE_KEY_PEM";
const ATTR_USER_HANDLE: &str = "KPEX_PASSKEY_USER_HANDLE";

fn attr(entry: &EntryRef<'_>, name: &str) -> Option<String> {
    entry
        .fields
        .get(name)
        .map(|v| v.get().as_str().trim().to_string())
        .filter(|s| !s.is_empty())
}

/// DER OID byte patterns inside a PKCS#8 `AlgorithmIdentifier`.
const OID_EC_P256: &[u8] = &[0x06, 0x08, 0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x03, 0x01, 0x07];
const OID_ED25519: &[u8] = &[0x06, 0x03, 0x2B, 0x65, 0x70];
const OID_RSA: &[u8] = &[
    0x06, 0x09, 0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x01, 0x01,
];

/// Sniff the COSE algorithm (`-7` ES256, `-8` EdDSA, `-257` RS256) from a
/// PEM-encoded PKCS#8 key by locating the algorithm OID in the DER. The
/// OID sits in the fixed-position AlgorithmIdentifier near the start of
/// the structure, so a byte scan is unambiguous in practice.
fn cose_algorithm_from_pem(pem: &str) -> Option<i64> {
    use base64::Engine;
    let body: String = pem
        .lines()
        .filter(|l| !l.starts_with("-----"))
        .collect::<Vec<_>>()
        .join("");
    let der = Zeroizing::new(
        base64::engine::general_purpose::STANDARD
            .decode(body.trim())
            .ok()?,
    );
    // Only inspect the header region — key material starts later.
    let head = &der[..der.len().min(48)];
    let contains = |needle: &[u8]| head.windows(needle.len()).any(|w| w == needle);
    if contains(OID_EC_P256) {
        Some(-7)
    } else if contains(OID_ED25519) {
        Some(-8)
    } else if contains(OID_RSA) {
        Some(-257)
    } else {
        None
    }
}

/// Build wire metadata for an entry carrying a passkey, or `None` if the
/// entry has no (usable) `KPEX_PASSKEY_*` attributes.
pub(crate) fn entry_to_fido2_meta(entry: &EntryRef<'_>) -> Option<WasmFido2CredentialMeta> {
    let rp_id = attr(entry, ATTR_RELYING_PARTY)?;
    let credential_id = attr(entry, ATTR_CREDENTIAL_ID)?
        .trim_end_matches('=')
        .to_string();
    let pem = attr(entry, ATTR_PRIVATE_KEY_PEM).map(Zeroizing::new)?;

    let Some(algorithm) = cose_algorithm_from_pem(&pem) else {
        extism_pdk::debug!(
            "fido2: entry {} has a passkey with an unrecognised key algorithm, skipping",
            entry.id().uuid()
        );
        return None;
    };

    let revision_date_epoch_secs = entry
        .times
        .last_modification
        .map(|dt| chrono::Utc.from_utc_datetime(&dt).timestamp().max(0) as u64);

    Some(WasmFido2CredentialMeta {
        item_id: entry.id().uuid().to_string(),
        credential_id,
        item_name: entry.get_title().unwrap_or("(unnamed)").to_string(),
        rp_id,
        rp_name: None,
        user_handle: attr(entry, ATTR_USER_HANDLE).map(|s| s.trim_end_matches('=').to_string()),
        user_name: attr(entry, ATTR_USERNAME),
        user_display_name: None,
        algorithm,
        // KeePassXC passkeys are resident by design and report a
        // permanently-zero signature counter.
        counter: 0,
        discoverable: true,
        require_uv: false,
        revision_date_epoch_secs,
    })
}

/// The PEM-encoded PKCS#8 private key for an entry's passkey, verified to
/// match `credential_id`.
pub(crate) fn resolve_fido2_key(
    entry: &EntryRef<'_>,
    credential_id: &str,
) -> Result<Zeroizing<String>, String> {
    let stored = attr(entry, ATTR_CREDENTIAL_ID)
        .map(|s| s.trim_end_matches('=').to_string())
        .ok_or_else(|| format!("entry {} has no passkey", entry.id().uuid()))?;
    if stored != credential_id.trim_end_matches('=') {
        return Err(format!(
            "credential {credential_id} not found on entry {}",
            entry.id().uuid()
        ));
    }
    attr(entry, ATTR_PRIVATE_KEY_PEM)
        .map(Zeroizing::new)
        .ok_or_else(|| {
            format!(
                "entry {} passkey has no private key material",
                entry.id().uuid()
            )
        })
}

