//! In-memory key store.
//!
//! The [`KeyStore`] holds all SSH keys currently available from unlocked
//! backends.  It is populated by `rosecd` after each vault sync and cleared
//! when a backend is locked.
//!
//! The store is accessed from two places:
//! - The SSH agent [`Session`][crate::session::AgentSession] for signing.
//! - The FUSE filesystem (`rosec-fuse`) for public-key file content and
//!   config snippet generation.
//!
//! Thread safety: all mutations go through `Arc<RwLock<KeyStore>>`.

use std::collections::HashMap;
use std::sync::{Arc, RwLock};
use std::time::SystemTime;

use ssh_key::{HashAlg, PrivateKey};
use tracing::debug;
use zeroize::Zeroize;

/// An individual SSH key entry in the store.
#[derive(Clone)]
pub struct KeyEntry {
    /// Human-readable name of the vault item this key came from.
    pub item_name: String,

    /// Backend that owns this key.
    pub backend_id: String,

    /// The private key (zeroized on drop via `ssh_key::PrivateKey`).
    pub private_key: PrivateKey,

    /// SHA-256 fingerprint string (e.g. `"SHA256:abc123…"`).
    pub fingerprint: String,

    /// OpenSSH wire-format public key (the `authorized_keys` line).
    pub public_key_openssh: String,

    /// Host patterns from `custom.ssh_host` / `custom.ssh-host` fields.
    /// Multiple patterns are supported (one per field, or newline-separated).
    pub ssh_hosts: Vec<String>,

    /// SSH username from `custom.ssh_user` / `custom.ssh-user` field.
    /// Emitted as `User <value>` in generated SSH config snippets.
    pub ssh_user: Option<String>,

    /// Whether to require interactive confirmation before signing.
    /// Set when the vault item has `custom.ssh_confirm = "true"`.
    pub require_confirm: bool,

    /// Last revision timestamp — used for conflict resolution in config.d/.
    pub revision_date: Option<SystemTime>,
}

impl std::fmt::Debug for KeyEntry {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("KeyEntry")
            .field("item_name", &self.item_name)
            .field("backend_id", &self.backend_id)
            .field("fingerprint", &self.fingerprint)
            .field("ssh_hosts", &self.ssh_hosts)
            .field("require_confirm", &self.require_confirm)
            .finish_non_exhaustive()
    }
}

impl Drop for KeyEntry {
    fn drop(&mut self) {
        // PrivateKey implements ZeroizeOnDrop internally via zeroize, but we
        // also clear our derived string fields that contain public info only —
        // private key material lives solely in `self.private_key`.
        self.item_name.zeroize();
    }
}

/// Shared, thread-safe key store.
///
/// Create with [`KeyStore::new`] and share via [`Arc::clone`].
///
/// Multiple vault items may share the same key material (and therefore the
/// same fingerprint).  The store keeps **all** entries so that each item's
/// SSH config metadata (`ssh_hosts`, `ssh_user`, etc.) is preserved.  The
/// SSH agent protocol only needs the key material once per fingerprint, so
/// [`unique_keys`](Self::unique_keys) returns one entry per fingerprint for
/// `request_identities`, while [`iter`](Self::iter) returns every entry for
/// FUSE snapshot / config snippet generation.
#[derive(Debug, Default)]
pub struct KeyStore {
    /// Entries grouped by SHA-256 fingerprint.
    ///
    /// Each fingerprint maps to one or more vault items that share that key.
    /// The first entry in each Vec is used for signing (key material is
    /// identical across entries with the same fingerprint).
    entries: HashMap<String, Vec<KeyEntry>>,
}

impl KeyStore {
    /// Create an empty key store.
    pub fn new() -> Arc<RwLock<Self>> {
        Arc::new(RwLock::new(Self::default()))
    }

    /// Insert a key entry, appending to any existing entries with the same
    /// fingerprint.
    pub fn insert(&mut self, entry: KeyEntry) {
        debug!(
            fingerprint = %entry.fingerprint,
            item = %entry.item_name,
            "keystore: adding key"
        );
        self.entries
            .entry(entry.fingerprint.clone())
            .or_default()
            .push(entry);
    }

    /// Remove all keys belonging to a specific backend.
    pub fn remove_backend(&mut self, backend_id: &str) {
        let before: usize = self.entries.values().map(|v| v.len()).sum();
        for group in self.entries.values_mut() {
            group.retain(|e| e.backend_id != backend_id);
        }
        // Remove empty groups.
        self.entries.retain(|_, v| !v.is_empty());
        let after: usize = self.entries.values().map(|v| v.len()).sum();
        let removed = before - after;
        debug!(backend = %backend_id, removed, "keystore: removed keys for backend");
    }

    /// Remove all keys.
    pub fn clear(&mut self) {
        self.entries.clear();
    }

    /// Look up a key by its SHA-256 fingerprint string.
    ///
    /// Returns the first entry for that fingerprint — all entries sharing a
    /// fingerprint have identical key material, so any one suffices for signing.
    pub fn get_by_fingerprint(&self, fingerprint: &str) -> Option<&KeyEntry> {
        self.entries.get(fingerprint).and_then(|v| v.first())
    }

    /// Iterate **all** entries (including multiple vault items that share the
    /// same key material).
    ///
    /// Used by the FUSE snapshot builder and config snippet generator, which
    /// need per-item metadata even when key material is duplicated.
    pub fn iter(&self) -> impl Iterator<Item = &KeyEntry> {
        self.entries.values().flatten()
    }

    /// Iterate one entry per unique fingerprint.
    ///
    /// Used by `request_identities` in the SSH agent protocol — the client
    /// identifies keys by public key, so advertising the same key twice is
    /// redundant.
    pub fn unique_keys(&self) -> impl Iterator<Item = &KeyEntry> {
        self.entries.values().filter_map(|v| v.first())
    }

    /// Total number of entries (including duplicates across vault items).
    pub fn len(&self) -> usize {
        self.entries.values().map(|v| v.len()).sum()
    }

    /// Number of unique fingerprints.
    pub fn unique_count(&self) -> usize {
        self.entries.len()
    }

    /// True if the store has no keys.
    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }
}

/// Build a [`KeyEntry`] from a parsed [`PrivateKey`] and vault item metadata.
///
/// Returns `None` if the public key cannot be serialised to OpenSSH format.
pub fn build_entry(
    private_key: PrivateKey,
    item_name: String,
    backend_id: String,
    ssh_hosts: Vec<String>,
    ssh_user: Option<String>,
    require_confirm: bool,
    revision_date: Option<SystemTime>,
) -> Option<KeyEntry> {
    let public_key = private_key.public_key();
    let fingerprint = public_key.fingerprint(HashAlg::Sha256).to_string();
    let public_key_openssh = public_key.to_openssh().ok()?;

    Some(KeyEntry {
        item_name,
        backend_id,
        private_key,
        fingerprint,
        public_key_openssh,
        ssh_hosts,
        ssh_user,
        require_confirm,
        revision_date,
    })
}
