use futures_util::StreamExt as _;
use rosec_core::router::{Router, RouterConfig};
use rosec_secret_service::{server::register_objects, session::SessionManager};
use std::sync::Arc;
#[derive(Debug)]
struct ProbeProvider {
    id: &'static str,
    locked: std::sync::atomic::AtomicBool,
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
            locked: self.locked.load(std::sync::atomic::Ordering::SeqCst),
            last_sync: None,
            cached: false,
            offline_cache: false,
            last_cache_write: None,
        })
    }
    async fn unlock(
        &self,
        input: rosec_core::UnlockInput,
    ) -> Result<(), rosec_core::ProviderError> {
        if let rosec_core::UnlockInput::Password(password) = input
            && password.as_str() == format!("{}-password", self.id)
        {
            self.locked
                .store(false, std::sync::atomic::Ordering::SeqCst);
            return Ok(());
        }
        Err(rosec_core::ProviderError::Other(anyhow::anyhow!(
            "fixture password mismatch"
        )))
    }
    async fn lock(&self) -> Result<(), rosec_core::ProviderError> {
        Ok(())
    }
    async fn list_items(&self) -> Result<Vec<rosec_core::ItemMeta>, rosec_core::ProviderError> {
        Ok(vec![rosec_core::ItemMeta {
            id: "item".into(),
            provider_id: self.id.into(),
            label: self.id.into(),
            attributes: [("provider".into(), self.id.into())].into(),
            locked: self.locked.load(std::sync::atomic::Ordering::SeqCst),
            created: None,
            modified: None,
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
        Err(rosec_core::ProviderError::NotFound)
    }
    async fn delete_item(&self, _: &str) -> Result<(), rosec_core::ProviderError> {
        self.deletes
            .fetch_add(1, std::sync::atomic::Ordering::SeqCst);
        Ok(())
    }
}

#[tokio::test]
async fn real_item_paths_select_their_own_provider_and_preserve_immediate_results() {
    let server = zbus::Connection::session().await.unwrap();
    let a = Arc::new(ProbeProvider {
        id: "a",
        locked: false.into(),
        deletes: 0.into(),
    });
    let b = Arc::new(ProbeProvider {
        id: "b",
        locked: false.into(),
        deletes: 0.into(),
    });
    let router = Arc::new(Router::new(RouterConfig {
        dedup_strategy: rosec_core::DedupStrategy::Priority,
        dedup_time_fallback: rosec_core::DedupTimeFallback::None,
    }));
    let state = register_objects(
        &server,
        vec![a.clone(), b.clone()],
        router,
        Arc::new(SessionManager::new()),
    )
    .await
    .unwrap();
    let items = state.rebuild_cache().await.unwrap();
    let a_path = zbus::OwnedObjectPath::try_from(
        items
            .iter()
            .find(|(_, m)| m.provider_id == "a")
            .unwrap()
            .0
            .clone(),
    )
    .unwrap();
    let b_path = zbus::OwnedObjectPath::try_from(
        items
            .iter()
            .find(|(_, m)| m.provider_id == "b")
            .unwrap()
            .0
            .clone(),
    )
    .unwrap();
    b.locked.store(true, std::sync::atomic::Ordering::SeqCst);
    let client = zbus::Connection::session().await.unwrap();
    let service = zbus::Proxy::new(
        &client,
        server.unique_name().unwrap().as_str(),
        "/org/freedesktop/secrets",
        "org.freedesktop.Secret.Service",
    )
    .await
    .unwrap();
    let collection =
        zbus::OwnedObjectPath::try_from("/org/freedesktop/secrets/collection/default").unwrap();
    for request in [
        vec![b_path.clone()],
        vec![collection.clone(), a_path.clone(), b_path.clone()],
    ] {
        let (immediate, prompt): (Vec<zbus::OwnedObjectPath>, zbus::OwnedObjectPath) =
            service.call("Unlock", &(request.clone(),)).await.unwrap();
        assert!(
            !immediate.contains(&b_path),
            "locked B item was reported unlocked because A is open"
        );
        assert_ne!(prompt.as_str(), "/");
        assert_eq!(
            immediate,
            request
                .into_iter()
                .filter(|p| p != &b_path)
                .collect::<Vec<_>>()
        );
        let object = server
            .object_server()
            .interface::<_, rosec_secret_service::prompt::SecretPrompt>(prompt.as_str())
            .await
            .unwrap();
        assert_eq!(object.get().await.provider_id, "b");
        state.cancel_prompt(prompt.as_str());
    }
    for request in [
        vec![],
        vec![zbus::OwnedObjectPath::try_from("/missing").unwrap()],
    ] {
        let (immediate, prompt): (Vec<zbus::OwnedObjectPath>, zbus::OwnedObjectPath) =
            service.call("Unlock", &(request,)).await.unwrap();
        assert!(immediate.is_empty());
        assert_eq!(prompt.as_str(), "/");
    }
    let (immediate, prompt): (Vec<zbus::OwnedObjectPath>, zbus::OwnedObjectPath) = service
        .call("Unlock", &(vec![collection.clone()],))
        .await
        .unwrap();
    assert_eq!(immediate, vec![collection]);
    assert_eq!(prompt.as_str(), "/");
    a.locked.store(true, std::sync::atomic::Ordering::SeqCst);
    let (_, prompt): (Vec<zbus::OwnedObjectPath>, zbus::OwnedObjectPath) =
        service.call("Unlock", &(vec![b_path],)).await.unwrap();
    assert_eq!(
        server
            .object_server()
            .interface::<_, rosec_secret_service::prompt::SecretPrompt>(prompt.as_str())
            .await
            .unwrap()
            .get()
            .await
            .provider_id,
        "b"
    );
    state.cancel_prompt(prompt.as_str());
}

#[tokio::test]
async fn multiple_provider_prompts_return_requested_items_and_cancel_between_steps() {
    use std::{os::unix::fs::PermissionsExt, time::Duration};
    const CHILD: &str = "ROSEC_UNLOCK_TEST_CHILD";
    if std::env::var_os(CHILD).is_none() {
        let status = std::process::Command::new(std::env::current_exe().unwrap())
            .args([
                "--exact",
                "multiple_provider_prompts_return_requested_items_and_cancel_between_steps",
                "--nocapture",
            ])
            .env(CHILD, "1")
            .env("DISPLAY", ":fixture")
            .env_remove("WAYLAND_DISPLAY")
            .env_remove("SSH_ASKPASS")
            .status()
            .unwrap();
        assert!(status.success());
        return;
    }
    let dir = std::env::temp_dir().join(format!("rosec-unlock-{}", uuid::Uuid::new_v4()));
    std::fs::create_dir(&dir).unwrap();
    struct Cleanup(std::path::PathBuf);
    impl Drop for Cleanup {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.0);
        }
    }
    let _cleanup = Cleanup(dir.clone());
    let script = dir.join("prompt");
    for cancel_second in [false, true] {
        let second = if cancel_second {
            "exit 1"
        } else {
            "printf '%s\n' '{\"password\":\"b-password\"}'"
        };
        // The stand-in consumes exactly the GUI JSON protocol. Each provider
        // requires a different password, so the opportunistic sweep cannot
        // make the second explicit prompt redundant.
        std::fs::write(&script,format!("#!/bin/sh\nrequest=$(cat)\ncase \"$request\" in\n*'\"provider\":\"a\"'*) printf '%s\\n' '{{\"password\":\"a-password\"}}' ;;\n*) {second} ;;\nesac\n")).unwrap();
        std::fs::set_permissions(&script, std::fs::Permissions::from_mode(0o700)).unwrap();
        let server = zbus::Connection::session().await.unwrap();
        let a = Arc::new(ProbeProvider {
            id: "a",
            locked: false.into(),
            deletes: 0.into(),
        });
        let b = Arc::new(ProbeProvider {
            id: "b",
            locked: false.into(),
            deletes: 0.into(),
        });
        let router = Arc::new(Router::new(RouterConfig {
            dedup_strategy: rosec_core::DedupStrategy::Priority,
            dedup_time_fallback: rosec_core::DedupTimeFallback::None,
        }));
        let state = register_objects(
            &server,
            vec![a.clone(), b.clone()],
            router,
            Arc::new(SessionManager::new()),
        )
        .await
        .unwrap();
        let items = state.rebuild_cache().await.unwrap();
        let mut paths: Vec<_> = items
            .into_iter()
            .map(|(p, _)| zbus::OwnedObjectPath::try_from(p).unwrap())
            .collect();
        paths.sort_by(|a, b| a.as_str().cmp(b.as_str()));
        a.locked.store(true, std::sync::atomic::Ordering::SeqCst);
        b.locked.store(true, std::sync::atomic::Ordering::SeqCst);
        let mut config = rosec_core::config::Config::default();
        config.prompt.backend = script.to_string_lossy().into_owned();
        state.update_live_config(config);
        let client = zbus::Connection::session().await.unwrap();
        let service = zbus::Proxy::new(
            &client,
            server.unique_name().unwrap().as_str(),
            "/org/freedesktop/secrets",
            "org.freedesktop.Secret.Service",
        )
        .await
        .unwrap();
        let (immediate, path): (Vec<zbus::OwnedObjectPath>, zbus::OwnedObjectPath) =
            service.call("Unlock", &(paths.clone(),)).await.unwrap();
        assert!(immediate.is_empty());
        let prompt = zbus::Proxy::new(
            &client,
            server.unique_name().unwrap().as_str(),
            path.as_str(),
            "org.freedesktop.Secret.Prompt",
        )
        .await
        .unwrap();
        let mut completed = prompt.receive_signal("Completed").await.unwrap();
        prompt.call_method("Prompt", &("",)).await.unwrap();
        let signal = tokio::time::timeout(Duration::from_secs(5), completed.next())
            .await
            .unwrap()
            .unwrap();
        let (dismissed, result): (bool, zbus::OwnedVariant) = signal.body().deserialize().unwrap();
        assert_eq!(dismissed, cancel_second);
        assert!(!a.locked.load(std::sync::atomic::Ordering::SeqCst));
        assert_eq!(
            b.locked.load(std::sync::atomic::Ordering::SeqCst),
            cancel_second
        );
        if !cancel_second {
            let mut actual: Vec<zbus::OwnedObjectPath> = result.try_into().unwrap();
            actual.sort_by(|a, b| a.as_str().cmp(b.as_str()));
            assert_eq!(actual, paths);
        }
        assert!(
            tokio::time::timeout(Duration::from_millis(100), completed.next())
                .await
                .is_err()
        );
    }
}
