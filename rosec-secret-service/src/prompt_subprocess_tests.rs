//! Exercise the real daemon subprocess bridge with deterministic dialog stand-ins.
//! The stand-ins never open a display or receive real credentials.
use rosec_core::{
    config::Config,
    router::{Router, RouterConfig},
};
use std::{collections::HashMap, os::unix::fs::PermissionsExt, sync::Arc, time::Duration};

#[derive(Debug)]
struct ProbeProvider {
    id: &'static str,
    locked: bool,
    deletes: std::sync::atomic::AtomicUsize,
}
#[async_trait::async_trait]
impl rosec_core::Provider for ProbeProvider {
    fn id(&self) -> &str {
        self.id
    }
    fn name(&self) -> &str {
        self.id
    }
    fn kind(&self) -> &str {
        "probe"
    }
    async fn status(&self) -> Result<rosec_core::ProviderStatus, rosec_core::ProviderError> {
        Ok(rosec_core::ProviderStatus {
            locked: self.locked,
            last_sync: None,
            cached: false,
            offline_cache: false,
            last_cache_write: None,
        })
    }
    async fn unlock(&self, _: rosec_core::UnlockInput) -> Result<(), rosec_core::ProviderError> {
        Ok(())
    }
    async fn lock(&self) -> Result<(), rosec_core::ProviderError> {
        Ok(())
    }
    async fn list_items(&self) -> Result<Vec<rosec_core::ItemMeta>, rosec_core::ProviderError> {
        Ok(vec![])
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
        Err(rosec_core::ProviderError::NotFound)
    }
    async fn delete_item(&self, _: &str) -> Result<(), rosec_core::ProviderError> {
        self.deletes
            .fetch_add(1, std::sync::atomic::Ordering::SeqCst);
        Ok(())
    }
}

struct Fixture(std::path::PathBuf);
impl Fixture {
    fn new() -> Self {
        let path = std::env::temp_dir().join(format!("rosec-prompt-test-{}", uuid::Uuid::new_v4()));
        std::fs::create_dir(&path).unwrap();
        Self(path)
    }
    fn script(&self, response: &str, wait: bool) -> String {
        let path = self.0.join("prompt");
        let request = self.0.join("request");
        let body = if wait {
            "exec sleep 30".to_string()
        } else {
            format!("printf '%s\n' '{response}'")
        };
        std::fs::write(
            &path,
            format!("#!/bin/sh\ncat > '{}'\n{body}\n", request.display()),
        )
        .unwrap();
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o700)).unwrap();
        path.to_string_lossy().into_owned()
    }
    fn request(&self) -> serde_json::Value {
        serde_json::from_slice(&std::fs::read(self.0.join("request")).unwrap()).unwrap()
    }
}
impl Drop for Fixture {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

#[tokio::test]
async fn gui_protocol_retry_mfa_and_cancellation() {
    // Set display-selection variables only in a fresh test process. Mutating
    // the environment in a multithreaded test runner would be unsound.
    const CHILD: &str = "ROSEC_PROMPT_PROTOCOL_TEST_CHILD";
    if std::env::var_os(CHILD).is_none() {
        let status = std::process::Command::new(std::env::current_exe().unwrap())
            .args([
                "--exact",
                "prompt_subprocess_tests::gui_protocol_retry_mfa_and_cancellation",
                "--nocapture",
            ])
            .env(CHILD, "1")
            .env("DISPLAY", ":rosec-fixture")
            .env_remove("WAYLAND_DISPLAY")
            .env_remove("SSH_ASKPASS")
            .status()
            .unwrap();
        assert!(status.success());
        return;
    }
    let conn = zbus::Connection::session().await.unwrap();
    let router = Arc::new(Router::new(RouterConfig {
        dedup_strategy: rosec_core::DedupStrategy::Priority,
        dedup_time_fallback: rosec_core::DedupTimeFallback::None,
    }));
    let state = crate::server::register_objects(
        &conn,
        vec![Arc::new(ProbeProvider {
            id: "fixture",
            locked: true,
            deletes: 0.into(),
        })],
        router,
        Arc::new(crate::session::SessionManager::new()),
    )
    .await
    .unwrap();
    let fixture = Fixture::new();
    let mut config = Config::default();
    config.prompt.backend = fixture.script(r#"{"password":"fixture-password"}"#, false);
    state.update_live_config(config.clone());
    let path = state.allocate_prompt("fixture");
    // Password collection can repeat on the same prompt for a wrong-password
    // retry: clearing an exited child must not remove the prompt entry.
    for label in ["Unlock fixture", "Incorrect password — try again"] {
        let state = Arc::clone(&state);
        let path = path.clone();
        let password =
            tokio::task::spawn_blocking(move || state.spawn_prompt(&path, "fixture", label, None))
                .await
                .unwrap()
                .unwrap();
        assert_eq!(password.as_str(), "fixture-password");
        assert_eq!(fixture.request()["fields"][0]["id"], "password");
    }
    config.prompt.backend = fixture.script(r#"{"token":"012345","method":"0"}"#, false);
    state.update_live_config(config.clone());
    let fields = vec![serde_json::json!({"id":"token","label":"Code","kind":"totp"})];
    let values: HashMap<_, _> = {
        let state = Arc::clone(&state);
        let path = path.clone();
        tokio::task::spawn_blocking(move || {
            state.spawn_prompt_fields(
                &path,
                "Two-factor authentication",
                "Enter code",
                &fields,
                None,
            )
        })
        .await
        .unwrap()
        .unwrap()
    };
    assert_eq!(values["token"].as_str(), "012345");
    assert_eq!(values["method"].as_str(), "0");
    assert_eq!(fixture.request()["fields"][0]["kind"], "totp");
    // Dismissing while the child is reading credentials wakes the blocked
    // bridge; the parent reaps the child and reports cancellation.
    std::fs::remove_file(fixture.0.join("request")).unwrap();
    config.prompt.backend = fixture.script("", true);
    state.update_live_config(config);
    let task = {
        let state = Arc::clone(&state);
        let path = path.clone();
        tokio::task::spawn_blocking(move || {
            state.spawn_prompt(&path, "fixture", "Cancel fixture", None)
        })
    };
    tokio::time::timeout(Duration::from_secs(2), async {
        while !fixture.0.join("request").exists() {
            tokio::time::sleep(Duration::from_millis(5)).await;
        }
    })
    .await
    .unwrap();
    assert!(state.cancel_prompt(&path));
    assert!(
        tokio::time::timeout(Duration::from_secs(2), task)
            .await
            .unwrap()
            .unwrap()
            .is_err()
    );
    assert!(!state.prompts.contains_path(&path));
}
