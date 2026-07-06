//! Tests for [`crate::provider`], kept out of the main module for size.

use super::*;
use tempfile::NamedTempFile;

fn create_test_provider() -> (LocalVault, NamedTempFile) {
    let temp = NamedTempFile::new().unwrap();
    let path = temp.path().to_path_buf();
    std::fs::remove_file(&path).unwrap();
    let provider = LocalVault::new("test", path);
    (provider, temp)
}

#[tokio::test]
async fn unlock_creates_vault_if_not_exists() {
    let temp = NamedTempFile::new().unwrap();
    std::fs::remove_file(temp.path()).unwrap();

    let provider = LocalVault::new("test", temp.path());
    let result = provider
        .unlock(UnlockInput::Password(Zeroizing::new(
            "password".to_string(),
        )))
        .await;

    assert!(result.is_ok());
    assert!(temp.path().exists());
}

#[tokio::test]
async fn unlock_fails_with_empty_password() {
    let (provider, _temp) = create_test_provider();
    let result = provider
        .unlock(UnlockInput::Password(Zeroizing::new(String::new())))
        .await;

    assert!(matches!(result, Err(ProviderError::InvalidInput(_))));
}

#[tokio::test]
async fn list_items_returns_empty_when_no_items() {
    let (provider, _temp) = create_test_provider();
    provider
        .unlock(UnlockInput::Password(Zeroizing::new(
            "password".to_string(),
        )))
        .await
        .unwrap();

    let items = provider.list_items().await.unwrap();
    assert!(items.is_empty());
}

#[tokio::test]
async fn fido2_credentials_roundtrip() {
    let (provider, _temp) = create_test_provider();
    provider
        .unlock(UnlockInput::Password(Zeroizing::new(
            "password".to_string(),
        )))
        .await
        .unwrap();

    let pem = "-----BEGIN PRIVATE KEY-----\nZmFrZS1rZXktbWF0ZXJpYWw=\n-----END PRIVATE KEY-----\n";
    let mut secrets = HashMap::new();
    secrets.insert(
        "fido2_private_key".to_string(),
        SecretBytes::new(pem.as_bytes().to_vec()),
    );
    let mut attributes = HashMap::new();
    attributes.insert("fido2_rp_id".to_string(), "example.com".to_string());
    attributes.insert(
        "fido2_credential_id".to_string(),
        "AAECAwQFBgcICQoLDA0ODw".to_string(),
    );
    attributes.insert("fido2_user_name".to_string(), "alice".to_string());
    attributes.insert(
        "fido2_user_handle".to_string(),
        "dXNlci1oYW5kbGU".to_string(),
    );

    let id = provider
        .create_item(
            NewItem {
                label: "Example Passkey".to_string(),
                item_type: None,
                attributes,
                secrets,
            },
            false,
        )
        .await
        .unwrap();

    let creds = provider.list_fido2_credentials().await.unwrap();
    assert_eq!(creds.len(), 1);
    let c = &creds[0];
    assert_eq!(c.rp_id, "example.com");
    assert_eq!(c.credential_id, "AAECAwQFBgcICQoLDA0ODw");
    assert_eq!(c.user_name.as_deref(), Some("alice"));
    assert_eq!(c.algorithm, -7);
    assert!(c.discoverable);
    assert!(!c.require_uv);

    let key = provider.get_fido2_key(&id, &c.credential_id).await.unwrap();
    assert!(key.pem.contains("BEGIN PRIVATE KEY"));

    // Wrong credential id on the right item must not release material.
    assert!(provider.get_fido2_key(&id, "bm9wZQ").await.is_err());
}

#[tokio::test]
async fn fido2_items_without_passkey_attributes_are_not_listed() {
    let (provider, _temp) = create_test_provider();
    provider
        .unlock(UnlockInput::Password(Zeroizing::new(
            "password".to_string(),
        )))
        .await
        .unwrap();

    let mut secrets = HashMap::new();
    secrets.insert("secret".to_string(), SecretBytes::new(b"x".to_vec()));
    provider
        .create_item(
            NewItem {
                label: "Ordinary".to_string(),
                item_type: None,
                attributes: HashMap::new(),
                secrets,
            },
            false,
        )
        .await
        .unwrap();

    assert!(provider.list_fido2_credentials().await.unwrap().is_empty());
}

#[tokio::test]
async fn create_and_get_item() {
    let (provider, _temp) = create_test_provider();
    provider
        .unlock(UnlockInput::Password(Zeroizing::new(
            "password".to_string(),
        )))
        .await
        .unwrap();

    let mut secrets = HashMap::new();
    secrets.insert("secret".to_string(), SecretBytes::new(b"mysecret".to_vec()));

    let item = NewItem {
        label: "Test Item".to_string(),
        item_type: None,
        attributes: HashMap::new(),
        secrets,
    };

    let id = provider.create_item(item, false).await.unwrap();

    let attrs = provider.get_item_attributes(&id).await.unwrap();
    let items = provider.list_items().await.unwrap();
    let meta = items.iter().find(|m| m.id == id).unwrap();
    assert_eq!(meta.label, "Test Item");
    assert!(attrs.secret_names.contains(&"secret".to_string()));
}

#[tokio::test]
async fn create_item_already_exists() {
    let (provider, _temp) = create_test_provider();
    provider
        .unlock(UnlockInput::Password(Zeroizing::new(
            "password".to_string(),
        )))
        .await
        .unwrap();

    let mut attrs = HashMap::new();
    attrs.insert("key".to_string(), "value".to_string());

    let mut secrets = HashMap::new();
    secrets.insert("secret".to_string(), SecretBytes::new(b"mysecret".to_vec()));

    let item = NewItem {
        label: "Test".to_string(),
        item_type: None,
        attributes: attrs.clone(),
        secrets: secrets.clone(),
    };

    provider.create_item(item, false).await.unwrap();

    let item2 = NewItem {
        label: "Test2".to_string(),
        item_type: None,
        attributes: attrs,
        secrets,
    };

    let result = provider.create_item(item2, false).await;
    assert!(matches!(result, Err(ProviderError::AlreadyExists)));
}

#[tokio::test]
async fn create_item_replace() {
    let (provider, _temp) = create_test_provider();
    provider
        .unlock(UnlockInput::Password(Zeroizing::new(
            "password".to_string(),
        )))
        .await
        .unwrap();

    let mut attrs = HashMap::new();
    attrs.insert("key".to_string(), "value".to_string());

    let mut secrets = HashMap::new();
    secrets.insert("secret".to_string(), SecretBytes::new(b"mysecret".to_vec()));

    let item = NewItem {
        label: "Test".to_string(),
        item_type: None,
        attributes: attrs.clone(),
        secrets: secrets.clone(),
    };

    let id1 = provider.create_item(item, false).await.unwrap();

    let item2 = NewItem {
        label: "Replaced".to_string(),
        item_type: None,
        attributes: attrs,
        secrets,
    };

    let id2 = provider.create_item(item2, true).await.unwrap();

    assert_eq!(id1, id2);

    let items = provider.list_items().await.unwrap();
    let meta = items.iter().find(|m| m.id == id1).unwrap();
    assert_eq!(meta.label, "Replaced");
}

/// Attribute-less items are identified by label: distinct labels must
/// coexist (an empty attribute set previously subset-matched every item,
/// so the second create failed with `AlreadyExists`).
#[tokio::test]
async fn create_item_attribute_less_distinct_labels_coexist() {
    let (provider, _temp) = create_test_provider();
    provider
        .unlock(UnlockInput::Password(Zeroizing::new(
            "password".to_string(),
        )))
        .await
        .unwrap();

    let mk = |label: &str| NewItem {
        label: label.to_string(),
        item_type: None,
        attributes: HashMap::new(),
        secrets: HashMap::from([("token".to_string(), SecretBytes::new(b"s".to_vec()))]),
    };

    provider
        .create_item(mk("GitHub token"), false)
        .await
        .unwrap();
    // Different label, also attribute-less — must not collide.
    provider
        .create_item(mk("GitLab token"), false)
        .await
        .unwrap();

    let items = provider.list_items().await.unwrap();
    assert_eq!(items.len(), 2);
}

/// Two attribute-less items with the *same* label are duplicates: the
/// second create conflicts, and replace=true updates in place.
#[tokio::test]
async fn create_item_attribute_less_same_label_conflicts() {
    let (provider, _temp) = create_test_provider();
    provider
        .unlock(UnlockInput::Password(Zeroizing::new(
            "password".to_string(),
        )))
        .await
        .unwrap();

    let mk = |secret: &[u8]| NewItem {
        label: "API token".to_string(),
        item_type: None,
        attributes: HashMap::new(),
        secrets: HashMap::from([("token".to_string(), SecretBytes::new(secret.to_vec()))]),
    };

    let id1 = provider.create_item(mk(b"first"), false).await.unwrap();

    // Same label, replace=false → conflict.
    let conflict = provider.create_item(mk(b"second"), false).await;
    assert!(matches!(conflict, Err(ProviderError::AlreadyExists)));

    // Same label, replace=true → updates the existing item in place.
    let id2 = provider.create_item(mk(b"second"), true).await.unwrap();
    assert_eq!(id1, id2);

    let items = provider.list_items().await.unwrap();
    assert_eq!(items.len(), 1);
}

#[tokio::test]
async fn update_item() {
    let (provider, _temp) = create_test_provider();
    provider
        .unlock(UnlockInput::Password(Zeroizing::new(
            "password".to_string(),
        )))
        .await
        .unwrap();

    let mut secrets = HashMap::new();
    secrets.insert("secret".to_string(), SecretBytes::new(b"mysecret".to_vec()));

    let item = NewItem {
        label: "Original".to_string(),
        item_type: None,
        attributes: HashMap::new(),
        secrets,
    };

    let id = provider.create_item(item, false).await.unwrap();

    let update = ItemUpdate {
        label: Some("Updated".to_string()),
        item_type: None,
        attributes: None,
        secrets: None,
    };

    provider.update_item(&id, update).await.unwrap();

    let items = provider.list_items().await.unwrap();
    let meta = items.iter().find(|m| m.id == id).unwrap();
    assert_eq!(meta.label, "Updated");
}

#[tokio::test]
async fn update_item_reserved_attribute() {
    let (provider, _temp) = create_test_provider();
    provider
        .unlock(UnlockInput::Password(Zeroizing::new(
            "password".to_string(),
        )))
        .await
        .unwrap();

    let mut secrets = HashMap::new();
    secrets.insert("secret".to_string(), SecretBytes::new(b"mysecret".to_vec()));

    let item = NewItem {
        label: "Test".to_string(),
        item_type: None,
        attributes: HashMap::new(),
        secrets,
    };

    let id = provider.create_item(item, false).await.unwrap();

    let mut attrs = HashMap::new();
    attrs.insert("id".to_string(), "newid".to_string());

    let update = ItemUpdate {
        label: None,
        item_type: None,
        attributes: Some(attrs),
        secrets: None,
    };

    let result = provider.update_item(&id, update).await;
    assert!(matches!(result, Err(ProviderError::InvalidInput(_))));
}

#[tokio::test]
async fn delete_item() {
    let (provider, _temp) = create_test_provider();
    provider
        .unlock(UnlockInput::Password(Zeroizing::new(
            "password".to_string(),
        )))
        .await
        .unwrap();

    let mut secrets = HashMap::new();
    secrets.insert("secret".to_string(), SecretBytes::new(b"mysecret".to_vec()));

    let item = NewItem {
        label: "Test".to_string(),
        item_type: None,
        attributes: HashMap::new(),
        secrets,
    };

    let id = provider.create_item(item, false).await.unwrap();

    provider.delete_item(&id).await.unwrap();

    let result = provider.get_item_attributes(&id).await;
    assert!(matches!(result, Err(ProviderError::NotFound)));
}

#[tokio::test]
async fn search_items() {
    let (provider, _temp) = create_test_provider();
    provider
        .unlock(UnlockInput::Password(Zeroizing::new(
            "password".to_string(),
        )))
        .await
        .unwrap();

    let mut attrs1 = HashMap::new();
    attrs1.insert("category".to_string(), "login".to_string());
    attrs1.insert("domain".to_string(), "example.com".to_string());

    let mut attrs2 = HashMap::new();
    attrs2.insert("category".to_string(), "login".to_string());
    attrs2.insert("domain".to_string(), "other.com".to_string());

    let mut secrets = HashMap::new();
    secrets.insert("secret".to_string(), SecretBytes::new(b"mysecret".to_vec()));

    let item1 = NewItem {
        label: "Item1".to_string(),
        item_type: None,
        attributes: attrs1.clone(),
        secrets: secrets.clone(),
    };
    let item2 = NewItem {
        label: "Item2".to_string(),
        item_type: None,
        attributes: attrs2,
        secrets,
    };

    provider.create_item(item1, false).await.unwrap();
    provider.create_item(item2, false).await.unwrap();

    let mut search_attrs = HashMap::new();
    search_attrs.insert("domain".to_string(), "example.com".to_string());

    let results = provider.search(&search_attrs).await.unwrap();
    assert_eq!(results.len(), 1);
    assert_eq!(results[0].label, "Item1");
}

#[tokio::test]
async fn operations_fail_when_locked() {
    let (provider, _temp) = create_test_provider();

    let result = provider.list_items().await;
    assert!(matches!(result, Err(ProviderError::Locked)));

    let result = provider.get_item_attributes("id").await;
    assert!(matches!(result, Err(ProviderError::Locked)));

    let mut secrets = HashMap::new();
    secrets.insert("secret".to_string(), SecretBytes::new(b"test".to_vec()));
    let item = NewItem {
        label: "Test".to_string(),
        item_type: None,
        attributes: HashMap::new(),
        secrets,
    };
    let result = provider.create_item(item, false).await;
    assert!(matches!(result, Err(ProviderError::Locked)));
}

#[tokio::test]
async fn unlock_relock_roundtrip() {
    let (provider, _temp) = create_test_provider();

    provider
        .unlock(UnlockInput::Password(Zeroizing::new(
            "password".to_string(),
        )))
        .await
        .unwrap();

    let mut secrets = HashMap::new();
    secrets.insert("secret".to_string(), SecretBytes::new(b"mysecret".to_vec()));

    let item = NewItem {
        label: "Test".to_string(),
        item_type: None,
        attributes: HashMap::new(),
        secrets,
    };

    let id = provider.create_item(item, false).await.unwrap();

    provider.lock().await.unwrap();

    let result = provider.get_item_attributes(&id).await;
    assert!(matches!(result, Err(ProviderError::Locked)));

    provider
        .unlock(UnlockInput::Password(Zeroizing::new(
            "password".to_string(),
        )))
        .await
        .unwrap();

    let items = provider.list_items().await.unwrap();
    let meta = items.iter().find(|m| m.id == id).unwrap();
    assert_eq!(meta.label, "Test");
}

#[tokio::test]
async fn add_password_enables_second_unlock() {
    let (provider, _temp) = create_test_provider();

    provider
        .unlock(UnlockInput::Password(Zeroizing::new("master".to_string())))
        .await
        .unwrap();

    let entry_id = provider
        .add_password(b"login-password", "login".to_string())
        .await
        .unwrap();
    assert!(!entry_id.is_empty());

    let entries = provider.list_passwords().await.unwrap();
    assert_eq!(entries.len(), 2);
    assert_eq!(entries[0].1.as_deref(), Some("master"));
    assert_eq!(entries[1].1.as_deref(), Some("login"));

    provider.lock().await.unwrap();
    let result = provider
        .unlock(UnlockInput::Password(Zeroizing::new(
            "login-password".to_string(),
        )))
        .await;
    assert!(result.is_ok());

    provider.lock().await.unwrap();
    let result = provider
        .unlock(UnlockInput::Password(Zeroizing::new("master".to_string())))
        .await;
    assert!(result.is_ok());
}

#[tokio::test]
async fn remove_password_prevents_unlock() {
    let (provider, _temp) = create_test_provider();

    provider
        .unlock(UnlockInput::Password(Zeroizing::new("master".to_string())))
        .await
        .unwrap();

    let entry_id = provider
        .add_password(b"second", "second".to_string())
        .await
        .unwrap();

    provider.remove_password(&entry_id).await.unwrap();

    let entries = provider.list_passwords().await.unwrap();
    assert_eq!(entries.len(), 1);

    provider.lock().await.unwrap();
    let result = provider
        .unlock(UnlockInput::Password(Zeroizing::new("second".to_string())))
        .await;
    assert!(result.is_err());

    let result = provider
        .unlock(UnlockInput::Password(Zeroizing::new("master".to_string())))
        .await;
    assert!(result.is_ok());
}

#[tokio::test]
async fn cannot_remove_last_password() {
    let (provider, _temp) = create_test_provider();

    provider
        .unlock(UnlockInput::Password(Zeroizing::new("master".to_string())))
        .await
        .unwrap();

    let entries = provider.list_passwords().await.unwrap();
    assert_eq!(entries.len(), 1);

    let result = provider.remove_password(&entries[0].0).await;
    assert!(matches!(result, Err(ProviderError::InvalidInput(_))));
}

#[tokio::test]
async fn add_password_rejects_empty_label() {
    let (provider, _temp) = create_test_provider();

    provider
        .unlock(UnlockInput::Password(Zeroizing::new("master".to_string())))
        .await
        .unwrap();

    let result = provider.add_password(b"another", String::new()).await;
    assert!(matches!(result, Err(ProviderError::InvalidInput(_))));
}

#[tokio::test]
async fn add_password_rejects_duplicate_label() {
    let (provider, _temp) = create_test_provider();

    provider
        .unlock(UnlockInput::Password(Zeroizing::new("master".to_string())))
        .await
        .unwrap();

    provider
        .add_password(b"login-pw", "login".to_string())
        .await
        .unwrap();

    let result = provider
        .add_password(b"other-pw", "login".to_string())
        .await;
    assert!(matches!(result, Err(ProviderError::InvalidInput(_))));

    // Verify only 2 entries exist (master + login), not 3
    let entries = provider.list_passwords().await.unwrap();
    assert_eq!(entries.len(), 2);
}

#[tokio::test]
async fn wrong_password_fails_to_unlock() {
    let (provider, _temp) = create_test_provider();

    provider
        .unlock(UnlockInput::Password(Zeroizing::new("correct".to_string())))
        .await
        .unwrap();
    provider.lock().await.unwrap();

    let result = provider
        .unlock(UnlockInput::Password(Zeroizing::new("wrong".to_string())))
        .await;
    assert!(result.is_err());
}

#[tokio::test]
async fn change_password_happy_path() {
    let (provider, _temp) = create_test_provider();
    provider
        .unlock(UnlockInput::Password(Zeroizing::new(
            "old-pass".to_string(),
        )))
        .await
        .unwrap();

    provider
        .change_password(
            Zeroizing::new("old-pass".to_string()),
            Zeroizing::new("new-pass".to_string()),
        )
        .await
        .unwrap();

    provider.lock().await.unwrap();
    let result = provider
        .unlock(UnlockInput::Password(Zeroizing::new(
            "new-pass".to_string(),
        )))
        .await;
    assert!(result.is_ok());

    provider.lock().await.unwrap();
    let result = provider
        .unlock(UnlockInput::Password(Zeroizing::new(
            "old-pass".to_string(),
        )))
        .await;
    assert!(result.is_err());
}

#[tokio::test]
async fn change_password_wrong_old_password() {
    let (provider, _temp) = create_test_provider();
    provider
        .unlock(UnlockInput::Password(Zeroizing::new(
            "real-pass".to_string(),
        )))
        .await
        .unwrap();

    let result = provider
        .change_password(
            Zeroizing::new("wrong-pass".to_string()),
            Zeroizing::new("new-pass".to_string()),
        )
        .await;
    assert!(matches!(result, Err(ProviderError::AuthFailed)));
}

#[tokio::test]
async fn change_password_when_locked() {
    let (provider, _temp) = create_test_provider();
    let result = provider
        .change_password(
            Zeroizing::new("old".to_string()),
            Zeroizing::new("new".to_string()),
        )
        .await;
    assert!(matches!(result, Err(ProviderError::Locked)));
}

#[tokio::test]
async fn change_password_preserves_label() {
    let (provider, _temp) = create_test_provider();
    provider
        .unlock(UnlockInput::Password(Zeroizing::new(
            "master-pw".to_string(),
        )))
        .await
        .unwrap();

    // The first wrapping entry has the label "master" by convention.
    let entries_before = provider.list_passwords().await.unwrap();
    assert_eq!(entries_before.len(), 1);
    assert_eq!(entries_before[0].1, Some("master".to_string()));

    provider
        .change_password(
            Zeroizing::new("master-pw".to_string()),
            Zeroizing::new("rotated-pw".to_string()),
        )
        .await
        .unwrap();

    let entries_after = provider.list_passwords().await.unwrap();
    assert_eq!(entries_after.len(), 1);
    assert_eq!(entries_after[0].1, Some("master".to_string()));

    // ID should have changed (new entry, not same entry).
    assert_ne!(entries_before[0].0, entries_after[0].0);
}

#[tokio::test]
async fn change_password_only_affects_matched_entry() {
    let (provider, _temp) = create_test_provider();
    provider
        .unlock(UnlockInput::Password(Zeroizing::new(
            "master-pw".to_string(),
        )))
        .await
        .unwrap();

    provider
        .add_password(b"second-pw", "login".to_string())
        .await
        .unwrap();

    provider
        .change_password(
            Zeroizing::new("master-pw".to_string()),
            Zeroizing::new("rotated-master".to_string()),
        )
        .await
        .unwrap();

    let entries = provider.list_passwords().await.unwrap();
    assert_eq!(entries.len(), 2);

    provider.lock().await.unwrap();
    let result = provider
        .unlock(UnlockInput::Password(Zeroizing::new(
            "rotated-master".to_string(),
        )))
        .await;
    assert!(result.is_ok());

    provider.lock().await.unwrap();
    let result = provider
        .unlock(UnlockInput::Password(Zeroizing::new(
            "second-pw".to_string(),
        )))
        .await;
    assert!(result.is_ok());

    provider.lock().await.unwrap();
    let result = provider
        .unlock(UnlockInput::Password(Zeroizing::new(
            "master-pw".to_string(),
        )))
        .await;
    assert!(result.is_err());
}

async fn unlocked_with_signal_item() -> (LocalVault, NamedTempFile) {
    let (provider, temp) = create_test_provider();
    provider
        .unlock(UnlockInput::Password(Zeroizing::new("pw".into())))
        .await
        .unwrap();
    let mut secrets = HashMap::new();
    secrets.insert(
        "password".to_string(),
        SecretBytes::new(b"hunter2".to_vec()),
    );
    let mut attributes = HashMap::new();
    attributes.insert("application".to_string(), "Signal".to_string());
    attributes.insert(
        "xdg:schema".to_string(),
        "chrome_libsecret_os_crypt_password_v2".to_string(),
    );
    provider
        .create_item(
            NewItem {
                label: "Chromium Safe Storage".to_string(),
                item_type: Some(ItemType::Login),
                attributes,
                secrets,
            },
            false,
        )
        .await
        .unwrap();
    (provider, temp)
}

#[tokio::test]
async fn metadata_cache_capability_declared() {
    let (provider, _temp) = create_test_provider();
    assert!(provider.capabilities().contains(&Capability::MetadataCache));
}

#[tokio::test]
async fn sidecar_written_on_save_no_plaintext_values() {
    let (provider, _temp) = unlocked_with_signal_item().await;
    let meta_path = provider.metadata_path();
    assert!(meta_path.exists());
    let bytes = std::fs::read(&meta_path).unwrap();
    let txt = String::from_utf8_lossy(&bytes);
    assert!(
        !txt.contains("\"Signal\""),
        "plaintext attribute value leaked into sidecar: {txt}"
    );
    assert!(
        !txt.contains("chrome_libsecret_os_crypt_password_v2"),
        "plaintext xdg:schema value leaked into sidecar: {txt}",
    );
    let sidecar: MetaSidecar = serde_json::from_slice(&bytes).unwrap();
    assert_eq!(sidecar.version, META_SIDECAR_VERSION);
    assert_eq!(sidecar.items.len(), 1);
    let item = &sidecar.items[0];
    assert_eq!(item.label, "Chromium Safe Storage");
    assert!(item.attribute_hashes.contains_key("application"));
    assert!(item.attribute_hashes.contains_key("xdg:schema"));
    // values are HMAC hex (64 chars)
    assert_eq!(item.attribute_hashes["application"].len(), 64);
}

#[tokio::test]
async fn locked_search_via_sidecar_matches_signal_query() {
    let (first, _temp) = unlocked_with_signal_item().await;
    let path = first.path().to_path_buf();
    drop(first);

    let provider = LocalVault::new("test", &path);
    let items = provider.list_items().await.unwrap();
    assert_eq!(items.len(), 1, "sidecar should surface the one item");
    let meta = &items[0];
    assert!(meta.locked, "items from sidecar must be locked");
    assert!(
        meta.attribute_hashes.is_some(),
        "items from sidecar must carry hashes"
    );
    // plaintext attributes are blanked
    assert_eq!(meta.attributes.get("application"), Some(&String::new()));
    // hash-based query match works
    let mut query = HashMap::new();
    query.insert("application".to_string(), "Signal".to_string());
    assert!(rosec_core::meta_matches_query(meta, &query));
    // wrong value does NOT match
    query.insert("application".to_string(), "Chrome".to_string());
    assert!(!rosec_core::meta_matches_query(meta, &query));
}

#[tokio::test]
async fn list_items_locked_without_sidecar_returns_locked_err() {
    let (provider, _temp) = create_test_provider();
    let err = provider.list_items().await.unwrap_err();
    assert!(matches!(err, ProviderError::Locked));
}

#[tokio::test]
async fn sidecar_corrupt_file_tolerated() {
    let (first, temp) = unlocked_with_signal_item().await;
    let path = first.path().to_path_buf();
    let meta_path = first.metadata_path();
    drop(first);
    std::fs::write(&meta_path, b"not json").unwrap();

    let provider = LocalVault::new("test", &path);
    let err = provider.list_items().await.unwrap_err();
    assert!(matches!(err, ProviderError::Locked));
    let _ = temp;
}

#[tokio::test]
async fn sidecar_future_version_tolerated() {
    let (first, temp) = unlocked_with_signal_item().await;
    let path = first.path().to_path_buf();
    let meta_path = first.metadata_path();
    drop(first);
    std::fs::write(&meta_path, br#"{"version": 999, "items": []}"#).unwrap();

    let provider = LocalVault::new("test", &path);
    let err = provider.list_items().await.unwrap_err();
    assert!(matches!(err, ProviderError::Locked));
    let _ = temp;
}

#[tokio::test]
async fn unlock_populates_sidecar_when_missing() {
    // Simulate cold-start: vault exists, sidecar deleted.
    let (first, temp) = unlocked_with_signal_item().await;
    let path = first.path().to_path_buf();
    let meta_path = first.metadata_path();
    drop(first);
    std::fs::remove_file(&meta_path).unwrap();
    assert!(!meta_path.exists());

    let provider = LocalVault::new("test", &path);
    provider
        .unlock(UnlockInput::Password(Zeroizing::new("pw".into())))
        .await
        .unwrap();
    assert!(meta_path.exists(), "unlock should populate missing sidecar");
    let _ = temp;
}
