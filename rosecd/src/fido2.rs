//! Fido2 credential registry — rosecd's index of the passkeys held by
//! unlocked providers.
//!
//! Mirrors the SSH keystore's rebuild-on-event discipline: rebuilt whenever a
//! provider unlocks or reports a changed sync, cleared on lock, and never
//! served from a snapshot captured at some earlier moment. One important
//! difference from SSH — this holds **metadata only**. A passkey's private
//! key is fetched from its provider at ceremony time and never cached here, so
//! the registry never has key material to leak.
//!
//! The security-relevant part (which credentials are offered for which
//! request) lives in the pure [`Fido2Index`]; [`Fido2Registry`] is the live,
//! swap-on-rebuild wrapper the daemon holds.

use std::collections::HashMap;
use std::sync::{Arc, RwLock};

use rosec_core::{Capability, Fido2CredentialMeta, Provider};
use tracing::debug;

/// Immutable index of credential metadata keyed by (lowercased) rp id.
#[derive(Default, Debug)]
pub struct Fido2Index {
    by_rp: HashMap<String, Vec<Fido2CredentialMeta>>,
}

impl Fido2Index {
    /// Build an index from a flat list of credential metadata.
    pub fn build(metas: impl IntoIterator<Item = Fido2CredentialMeta>) -> Self {
        let mut by_rp: HashMap<String, Vec<Fido2CredentialMeta>> = HashMap::new();
        for m in metas {
            by_rp
                .entry(m.rp_id.to_ascii_lowercase())
                .or_default()
                .push(m);
        }
        Self { by_rp }
    }

    /// Credentials to offer for a `getAssertion` on `rp_id`.
    ///
    /// `allow_ids` are the base64url (unpadded) credential IDs from the
    /// relying party's `allowCredentials`:
    /// - **empty** ⇒ a discoverable (username-less) request: only resident
    ///   credentials are offered;
    /// - **non-empty** ⇒ only the credentials the RP named are offered
    ///   (resident or not — the RP asked for them explicitly).
    ///
    /// rp id matching is case-insensitive (WebAuthn rp ids are domains).
    // Consumed by the CTAP2 ceremony event loop (the getAssertion path); the
    // rebuild side is already wired into the daemon callbacks.
    #[allow(dead_code)]
    pub fn find(&self, rp_id: &str, allow_ids: &[String]) -> Vec<Fido2CredentialMeta> {
        let Some(creds) = self.by_rp.get(&rp_id.to_ascii_lowercase()) else {
            return Vec::new();
        };
        creds
            .iter()
            .filter(|c| {
                if allow_ids.is_empty() {
                    c.discoverable
                } else {
                    allow_ids.contains(&c.credential_id)
                }
            })
            .cloned()
            .collect()
    }

    /// Total credentials indexed (across all relying parties).
    pub fn len(&self) -> usize {
        self.by_rp.values().map(Vec::len).sum()
    }
}

/// Live registry: the index is swapped wholesale on each rebuild, so readers
/// always see the current set — never one frozen at unlock/registration time.
#[derive(Default)]
pub struct Fido2Registry {
    gate: crate::consumer_gate::ConsumerGate,
    index: RwLock<Fido2Index>,
}

impl Fido2Registry {
    pub fn register_provider(&self, provider: &Arc<dyn Provider>) {
        self.gate.register(provider);
    }
    pub fn activate_provider(&self, provider: &Arc<dyn Provider>) {
        self.gate.activate(provider);
    }

    pub fn new() -> Self {
        Self::default()
    }

    /// Rebuild the index from the current fido2-capable, unlocked providers.
    ///
    /// Reads the live provider list each time (callers pass
    /// `state.fido2_providers()`); locked providers contribute nothing.
    /// Metadata only — no private keys are fetched or cached.
    pub async fn rebuild(&self, providers: &[Arc<dyn Provider>]) {
        let (epoch, providers) = self.gate.begin(providers);
        let mut metas = Vec::new();
        for provider in &providers {
            // Declared capability is authoritative (matches ssh/totp loops).
            if !provider.capabilities().contains(&Capability::Fido2) {
                continue;
            }
            let id = provider.id().to_string();
            match provider.status().await {
                Ok(s) if s.locked => {
                    debug!(provider = %id, "fido2 rebuild: provider locked, skipping");
                    continue;
                }
                Ok(_) => {}
                Err(e) => {
                    debug!(provider = %id, error = %e, "fido2 rebuild: status check failed, skipping");
                    continue;
                }
            }
            match provider.list_fido2_credentials().await {
                Ok(m) => {
                    debug!(provider = %id, count = m.len(), "fido2 rebuild: discovered credentials");
                    metas.extend(m);
                }
                Err(e) => {
                    debug!(provider = %id, error = %e, "fido2 rebuild: list_fido2_credentials failed")
                }
            }
        }
        let index = Fido2Index::build(metas);
        debug!(total = index.len(), "fido2 rebuild: index updated");
        self.gate.publish(epoch, || {
            *self.index.write().unwrap_or_else(|e| e.into_inner()) = index;
        });
    }

    pub fn remove_provider(&self, id: &str) {
        self.gate.revoke(Some(id), || {
            let mut index = self.index.write().unwrap_or_else(|e| e.into_inner());
            for entries in index.by_rp.values_mut() {
                entries.retain(|m| m.provider_id != id);
            }
        });
    }

    /// Credentials to offer for an assertion (delegates to the live index).
    // Consumed by the CTAP2 ceremony event loop (forthcoming); rebuild is
    // already wired into the daemon's unlock/sync/lock callbacks.
    #[allow(dead_code)]
    pub fn find(&self, rp_id: &str, allow_ids: &[String]) -> Vec<Fido2CredentialMeta> {
        self.index
            .read()
            .unwrap_or_else(|e| e.into_inner())
            .find(rp_id, allow_ids)
    }
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;
    use std::time::SystemTime;

    fn meta(cred_id: &str, rp: &str, discoverable: bool) -> Fido2CredentialMeta {
        Fido2CredentialMeta {
            item_id: format!("item-{cred_id}"),
            credential_id: cred_id.into(),
            item_name: "test".into(),
            provider_id: "local".into(),
            rp_id: rp.into(),
            rp_name: None,
            user_handle: Some("dXNlcg".into()),
            user_name: Some("alice".into()),
            user_display_name: None,
            algorithm: -7,
            counter: 0,
            discoverable,
            require_uv: false,
            revision_date: Some(SystemTime::UNIX_EPOCH),
        }
    }

    fn index() -> Fido2Index {
        Fido2Index::build(vec![
            meta("disc-1", "example.com", true),
            meta("nondisc-1", "example.com", false),
            meta("disc-2", "github.com", true),
        ])
    }

    #[test]
    fn discoverable_request_offers_only_resident() {
        let got = index().find("example.com", &[]);
        assert_eq!(got.len(), 1);
        assert_eq!(got[0].credential_id, "disc-1");
    }

    #[test]
    fn allow_list_offers_named_credentials_resident_or_not() {
        // Naming the non-discoverable credential surfaces it.
        let got = index().find("example.com", &["nondisc-1".into()]);
        assert_eq!(got.len(), 1);
        assert_eq!(got[0].credential_id, "nondisc-1");
    }

    #[test]
    fn allow_list_ignores_credentials_for_other_rps() {
        // A credential id that belongs to github.com is not offered for
        // example.com even if named.
        let got = index().find("example.com", &["disc-2".into()]);
        assert!(got.is_empty());
    }

    #[test]
    fn rp_id_match_is_case_insensitive() {
        let got = index().find("EXAMPLE.COM", &[]);
        assert_eq!(got.len(), 1);
    }

    #[test]
    fn unknown_rp_is_empty() {
        assert!(index().find("unknown.test", &[]).is_empty());
    }

    #[test]
    fn index_counts_all_credentials() {
        assert_eq!(index().len(), 3);
    }
    pub(crate) struct DelayedProvider {
        pub locked: std::sync::atomic::AtomicBool,
        pub entered: tokio::sync::Notify,
        pub release: tokio::sync::Notify,
    }

    #[async_trait::async_trait]
    impl Provider for DelayedProvider {
        fn id(&self) -> &str {
            "local"
        }
        fn name(&self) -> &str {
            "test"
        }
        fn kind(&self) -> &str {
            "test"
        }
        fn capabilities(&self) -> &'static [Capability] {
            &[Capability::Fido2, Capability::Ssh, Capability::Totp]
        }
        async fn status(&self) -> Result<rosec_core::ProviderStatus, rosec_core::ProviderError> {
            Ok(rosec_core::ProviderStatus {
                locked: self.locked.load(std::sync::atomic::Ordering::SeqCst),
                last_sync: None,
                cached: false,
                offline_cache: false,
                last_cache_write: None,
            })
        }
        async fn unlock(
            &self,
            _: rosec_core::UnlockInput,
        ) -> Result<(), rosec_core::ProviderError> {
            Ok(())
        }
        async fn lock(&self) -> Result<(), rosec_core::ProviderError> {
            Ok(())
        }
        async fn list_items(&self) -> Result<Vec<rosec_core::ItemMeta>, rosec_core::ProviderError> {
            Ok(vec![rosec_core::ItemMeta {
                id: "item".into(),
                provider_id: "local".into(),
                label: "Test".into(),
                attributes: [(rosec_core::ATTR_TOTP.into(), "true".into())].into(),
                created: None,
                modified: None,
                locked: false,
                attribute_hashes: None,
            }])
        }
        async fn search(
            &self,
            _: &rosec_core::Attributes,
        ) -> Result<Vec<rosec_core::ItemMeta>, rosec_core::ProviderError> {
            Ok(vec![])
        }
        async fn get_item_attributes(
            &self,
            _: &str,
        ) -> Result<rosec_core::ItemAttributes, rosec_core::ProviderError> {
            Err(rosec_core::ProviderError::NotFound)
        }
        async fn get_secret_attr(
            &self,
            _: &str,
            _: &str,
        ) -> Result<rosec_core::SecretBytes, rosec_core::ProviderError> {
            self.entered.notify_one();
            self.release.notified().await;
            Ok(rosec_core::SecretBytes::new(b"JBSWY3DPEHPK3PXP".to_vec()))
        }
        async fn list_ssh_keys(
            &self,
        ) -> Result<Vec<rosec_core::SshKeyMeta>, rosec_core::ProviderError> {
            Ok(vec![rosec_core::SshKeyMeta {
                item_id: "item".into(),
                item_name: "test".into(),
                provider_id: "local".into(),
                public_key_openssh: None,
                fingerprint: None,
                ssh_hosts: vec![],
                signing_principals: vec![],
                ssh_user: None,
                require_confirm: false,
                revision_date: None,
            }])
        }
        async fn get_ssh_private_key(
            &self,
            _: &str,
        ) -> Result<rosec_core::SshPrivateKeyMaterial, rosec_core::ProviderError> {
            let pair = ssh_key::private::Ed25519Keypair::from_seed(&[7; 32]);
            let key =
                ssh_key::PrivateKey::new(ssh_key::private::KeypairData::Ed25519(pair), "test")
                    .unwrap();
            let pem = key.to_openssh(ssh_key::LineEnding::LF).unwrap();
            self.entered.notify_one();
            self.release.notified().await;
            Ok(rosec_core::SshPrivateKeyMaterial { pem })
        }
        async fn list_fido2_credentials(
            &self,
        ) -> Result<Vec<Fido2CredentialMeta>, rosec_core::ProviderError> {
            self.entered.notify_one();
            self.release.notified().await;
            Ok(vec![meta("stale", "example.com", true)])
        }
    }

    #[tokio::test]
    async fn old_rebuild_cannot_restore_credentials_after_lock() {
        let registry = Arc::new(Fido2Registry::new());
        let provider = Arc::new(DelayedProvider {
            locked: false.into(),
            entered: Default::default(),
            release: Default::default(),
        });
        let providers: Vec<Arc<dyn Provider>> = vec![provider.clone()];
        registry.register_provider(&providers[0]);
        let old = {
            let registry = registry.clone();
            let providers = providers.clone();
            tokio::spawn(async move {
                registry.rebuild(&providers).await;
            })
        };
        provider.entered.notified().await;
        provider
            .locked
            .store(true, std::sync::atomic::Ordering::SeqCst);
        registry.rebuild(&providers).await;
        assert!(registry.find("example.com", &[]).is_empty());
        provider.release.notify_one();
        old.await.unwrap();
        assert!(
            registry.find("example.com", &[]).is_empty(),
            "old rebuild restored a locked provider"
        );
    }

    #[tokio::test]
    async fn revocation_rejects_inflight_and_queued_old_instance() {
        let registry = Arc::new(Fido2Registry::new());
        let provider = Arc::new(DelayedProvider {
            locked: false.into(),
            entered: Default::default(),
            release: Default::default(),
        });
        let old: Arc<dyn Provider> = provider.clone();
        registry.register_provider(&old);
        let task = {
            let registry = registry.clone();
            let old = old.clone();
            tokio::spawn(async move {
                registry.rebuild(&[old]).await;
            })
        };
        provider.entered.notified().await;
        registry.remove_provider("local");
        provider.release.notify_one();
        task.await.unwrap();
        assert!(registry.find("example.com", &[]).is_empty());
        let replacement: Arc<dyn Provider> = Arc::new(DelayedProvider {
            locked: true.into(),
            entered: Default::default(),
            release: Default::default(),
        });
        registry.register_provider(&replacement);
        registry.activate_provider(&old); // A delayed callback cannot reactivate the old source.
        tokio::time::timeout(std::time::Duration::from_secs(1), registry.rebuild(&[old]))
            .await
            .unwrap();
        assert!(registry.find("example.com", &[]).is_empty());
    }
}
