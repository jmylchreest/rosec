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
async fn fido2_write_path_roundtrip() {
    // makeCredential path: build a passkey with the write-path builder, store
    // it via create_item, then read it back through the list/get surface.
    let (provider, _temp) = create_test_provider();
    provider
        .unlock(UnlockInput::Password(Zeroizing::new(
            "password".to_string(),
        )))
        .await
        .unwrap();

    let cred = crate::fido2::NewFido2Credential {
        rp_id: "github.com".to_string(),
        rp_name: Some("GitHub".to_string()),
        credential_id: vec![0, 1, 2, 3, 4, 5, 6, 7],
        user_handle: b"user-handle-bytes".to_vec(),
        user_name: Some("alice".to_string()),
        user_display_name: Some("Alice A".to_string()),
        algorithm: -7,
        discoverable: true,
        require_uv: false,
        private_key_pem: Zeroizing::new(
            "-----BEGIN PRIVATE KEY-----\nZmFrZQ==\n-----END PRIVATE KEY-----\n".to_string(),
        ),
    };
    let item = crate::fido2::new_item_for_credential(&cred);
    let id = provider.create_item(item, false).await.unwrap();

    let creds = provider.list_fido2_credentials().await.unwrap();
    let stored = creds
        .iter()
        .find(|c| c.item_id == id)
        .expect("written passkey listed");
    assert_eq!(stored.rp_id, "github.com");
    assert_eq!(stored.rp_name.as_deref(), Some("GitHub"));
    assert_eq!(stored.user_name.as_deref(), Some("alice"));
    assert_eq!(stored.algorithm, -7);
    assert!(stored.discoverable);
    // credential_id round-trips through base64url on both write and read.
    assert_eq!(stored.credential_id, "AAECAwQFBgc");

    let key = provider
        .get_fido2_key(&id, &stored.credential_id)
        .await
        .unwrap();
    assert!(key.pem.contains("BEGIN PRIVATE KEY"));
    assert!(key.pem.contains("ZmFrZQ"));
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
                content_types: Default::default(),
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
                content_types: Default::default(),
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
        content_types: Default::default(),
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
        content_types: Default::default(),
        label: "Test".to_string(),
        item_type: None,
        attributes: attrs.clone(),
        secrets: secrets.clone(),
    };

    provider.create_item(item, false).await.unwrap();

    let item2 = NewItem {
        content_types: Default::default(),
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
        content_types: Default::default(),
        label: "Test".to_string(),
        item_type: None,
        attributes: attrs.clone(),
        secrets: secrets.clone(),
    };

    let id1 = provider.create_item(item, false).await.unwrap();

    let item2 = NewItem {
        content_types: Default::default(),
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
        content_types: Default::default(),
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
        content_types: Default::default(),
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
        content_types: Default::default(),
        label: "Original".to_string(),
        item_type: None,
        attributes: HashMap::new(),
        secrets,
    };

    let id = provider.create_item(item, false).await.unwrap();

    let update = ItemUpdate {
        content_types: Default::default(),
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
        content_types: Default::default(),
        label: "Test".to_string(),
        item_type: None,
        attributes: HashMap::new(),
        secrets,
    };

    let id = provider.create_item(item, false).await.unwrap();

    let mut attrs = HashMap::new();
    attrs.insert("id".to_string(), "newid".to_string());

    let update = ItemUpdate {
        content_types: Default::default(),
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
        content_types: Default::default(),
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
        content_types: Default::default(),
        label: "Item1".to_string(),
        item_type: None,
        attributes: attrs1.clone(),
        secrets: secrets.clone(),
    };
    let item2 = NewItem {
        content_types: Default::default(),
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
        content_types: Default::default(),
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
        content_types: Default::default(),
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
                content_types: Default::default(),
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

#[tokio::test]
async fn recovery_validates_snapshot_and_excludes_active_writers() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("vault");
    let backup = dir.path().join("snapshot");
    let vault = LocalVault::new("test", &path);
    let password = || UnlockInput::Password(Zeroizing::new("fixture-password".into()));
    vault.unlock(password()).await.unwrap();
    let original = std::fs::read(&path).unwrap();
    std::fs::write(&backup, &original).unwrap();
    let other = LocalVault::new("other", &path);
    assert!(
        other
            .restore_snapshot(&backup, b"fixture-password")
            .await
            .is_err()
    );
    assert!(other.unlock(password()).await.is_err());
    vault.lock().await.unwrap();
    assert!(
        other
            .restore_snapshot(&backup, b"wrong-password")
            .await
            .is_err()
    );
    assert_eq!(std::fs::read(&path).unwrap(), original);
    other
        .restore_snapshot(&backup, b"fixture-password")
        .await
        .unwrap();
    assert_eq!(std::fs::read(&path).unwrap(), original);
    other.unlock(password()).await.unwrap();
    assert!(other.list_items().await.unwrap().is_empty());
    assert_eq!(
        serde_json::from_slice::<VaultFile>(&std::fs::read(&path).unwrap())
            .unwrap()
            .version,
        2
    );
}

#[tokio::test]
async fn mime_changes_format_only_when_needed_and_can_return_to_v2() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("vault");
    let vault = LocalVault::new("test", &path);
    let password = || UnlockInput::Password(Zeroizing::new("fixture-password".into()));
    let file = || serde_json::from_slice::<VaultFile>(&std::fs::read(&path).unwrap()).unwrap();
    vault.unlock(password()).await.unwrap();
    let id = vault
        .create_item(
            NewItem {
                label: "binary fixture".into(),
                item_type: None,
                attributes: HashMap::new(),
                secrets: HashMap::from([
                    ("secret".into(), SecretBytes::new(vec![0, 255, 128, 0])),
                    ("other".into(), SecretBytes::new(vec![])),
                ]),
                content_types: HashMap::new(),
            },
            false,
        )
        .await
        .unwrap();
    assert_eq!(file().version, 2);
    let original = std::fs::read(&path).unwrap();
    vault.lock().await.unwrap();
    vault.unlock(password()).await.unwrap();
    assert_eq!(
        std::fs::read(&path).unwrap(),
        original,
        "unlock must not rewrite"
    );
    let mime = "application/octet-stream; fixture=exact";
    vault
        .update_item(
            &id,
            ItemUpdate {
                content_types: HashMap::from([("secret".into(), mime.into())]),
                ..Default::default()
            },
        )
        .await
        .unwrap();
    assert_eq!(file().version, 3);
    let v3_bytes = std::fs::read(&path).unwrap();
    let backups = || {
        std::fs::read_dir(dir.path())
            .unwrap()
            .map(|e| e.unwrap().path())
            .filter(|p| p.to_string_lossy().contains(".recovery-"))
            .collect::<Vec<_>>()
    };
    assert_eq!(backups().len(), 1);
    assert_eq!(std::fs::read(&backups()[0]).unwrap(), original);
    vault
        .update_item(
            &id,
            ItemUpdate {
                label: Some("renamed".into()),
                secrets: Some(HashMap::from([(
                    "other".into(),
                    SecretBytes::new(b"updated".to_vec()),
                )])),
                ..Default::default()
            },
        )
        .await
        .unwrap();
    assert_eq!(
        backups().len(),
        1,
        "same-format writes need no recovery snapshot"
    );
    vault.lock().await.unwrap();
    vault.unlock(password()).await.unwrap();
    let value = vault.get_secret_value(&id, "secret").await.unwrap();
    assert_eq!(value.content_type, mime);
    assert_eq!(value.bytes.as_slice(), &[0, 255, 128, 0]);
    assert_eq!(
        vault
            .get_secret_value(&id, "other")
            .await
            .unwrap()
            .content_type,
        "text/plain"
    );
    vault.lock().await.unwrap();
    let mut tampered: VaultFile = serde_json::from_slice(&v3_bytes).unwrap();
    tampered.version = 2;
    std::fs::write(&path, serde_json::to_vec(&tampered).unwrap()).unwrap();
    assert!(matches!(
        vault.unlock(password()).await,
        Err(ProviderError::AuthFailed)
    ));
    std::fs::write(&path, &v3_bytes).unwrap();
    vault.unlock(password()).await.unwrap();
    vault
        .update_item(
            &id,
            ItemUpdate {
                content_types: HashMap::from([("secret".into(), "text/plain".into())]),
                ..Default::default()
            },
        )
        .await
        .unwrap();
    assert_eq!(file().version, 2);
    assert_eq!(backups().len(), 2);
    vault.lock().await.unwrap();
    vault.unlock(password()).await.unwrap();
    assert_eq!(
        vault
            .get_secret_value(&id, "secret")
            .await
            .unwrap()
            .bytes
            .as_slice(),
        &[0, 255, 128, 0]
    );
    assert_eq!(
        vault
            .get_secret_value(&id, "secret")
            .await
            .unwrap()
            .content_type,
        "text/plain"
    );
    vault.lock().await.unwrap();
    let v3_snapshot = backups()
        .into_iter()
        .find(|p| {
            serde_json::from_slice::<VaultFile>(&std::fs::read(p).unwrap())
                .unwrap()
                .version
                == 3
        })
        .unwrap();
    vault
        .restore_snapshot(&v3_snapshot, b"fixture-password")
        .await
        .unwrap();
    vault.unlock(password()).await.unwrap();
    assert_eq!(
        vault
            .get_secret_value(&id, "secret")
            .await
            .unwrap()
            .content_type,
        mime
    );
}

#[tokio::test]
async fn replacement_and_invalid_mime_metadata_are_consistent() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("vault");
    let vault = LocalVault::new("test", &path);
    vault
        .unlock(UnlockInput::Password(Zeroizing::new(
            "fixture-password".into(),
        )))
        .await
        .unwrap();
    let item = |mime: &str, bytes: &[u8]| NewItem {
        label: "fixture".into(),
        item_type: None,
        attributes: HashMap::new(),
        secrets: HashMap::from([("secret".into(), SecretBytes::new(bytes.to_vec()))]),
        content_types: HashMap::from([("secret".into(), mime.into())]),
    };
    let id = vault
        .create_item(item("application/x-fixture", &[255, 0]), false)
        .await
        .unwrap();
    assert!(
        vault
            .update_item(
                &id,
                ItemUpdate {
                    label: Some("must-not-change".into()),
                    content_types: HashMap::from([("absent".into(), "x".into())]),
                    ..Default::default()
                }
            )
            .await
            .is_err()
    );
    assert_eq!(vault.list_items().await.unwrap()[0].label, "fixture");
    assert_eq!(
        vault
            .create_item(item("text/plain", b""), true)
            .await
            .unwrap(),
        id
    );
    let value = vault.get_secret_value(&id, "secret").await.unwrap();
    assert_eq!(value.content_type, "text/plain");
    assert!(value.bytes.as_slice().is_empty());
    assert_eq!(
        serde_json::from_slice::<VaultFile>(&std::fs::read(path).unwrap())
            .unwrap()
            .version,
        2
    );
}

#[tokio::test]
async fn failed_save_does_not_publish_mutation_in_memory() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("vault");
    let vault = LocalVault::new("test", &path);
    vault
        .unlock(UnlockInput::Password(Zeroizing::new(
            "fixture-password".into(),
        )))
        .await
        .unwrap();
    let original = std::fs::read(&path).unwrap();
    // Simulate an external writer which does not honour the lease.
    std::fs::write(&path, b"external replacement").unwrap();
    let item = NewItem {
        content_types: Default::default(),

        label: "must-not-appear".into(),
        item_type: None,
        attributes: HashMap::new(),
        secrets: HashMap::from([("secret".into(), SecretBytes::new(b"fixture".to_vec()))]),
    };
    assert!(vault.create_item(item, false).await.is_err());
    assert!(vault.list_items().await.unwrap().is_empty());
    assert_eq!(std::fs::read(&path).unwrap(), b"external replacement");
    std::fs::write(&path, original).unwrap();
}
