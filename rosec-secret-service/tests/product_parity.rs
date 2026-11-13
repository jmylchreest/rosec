//! The same harness can run against main and the eventing branch. Fixtures
//! contain no user credentials; transcripts include exact CLI output/status.
#[path = "../../tests/support/private_bus.rs"]
mod private_bus;
mod support;
use private_bus::PrivateBus;
use serde_json::json;
use support::{MutableProvider, setup_on};
use zbus::{OwnedObjectPath, OwnedVariant, Variant};

#[tokio::test]
async fn ordinary_product_workflows() {
    let bus = PrivateBus::new();
    let provider = MutableProvider::new("parity");
    provider.put("one", "Example login");
    provider.items.lock().unwrap()[0]
        .attributes
        .insert("username".into(), "alice".into());
    let connection = zbus::connection::Builder::address(bus.address.as_str())
        .build()
        .await
        .unwrap();
    let (server, state) = setup_on(connection, vec![provider.clone()]).await;
    server
        .request_name("org.freedesktop.secrets")
        .await
        .unwrap();
    let entries = state.rebuild_cache().await.unwrap();
    let path = entries[0].0.clone();
    let client = zbus::connection::Builder::address(bus.address.as_str())
        .build()
        .await
        .unwrap();
    let service = zbus::Proxy::new(
        &client,
        "org.freedesktop.secrets",
        "/org/freedesktop/secrets",
        "org.freedesktop.Secret.Service",
    )
    .await
    .unwrap();
    let (_, session): (OwnedVariant, OwnedObjectPath) = service
        .call("OpenSession", &("plain", Variant::from("")))
        .await
        .unwrap();
    let item = zbus::Proxy::new(
        &client,
        "org.freedesktop.secrets",
        path.as_str(),
        "org.freedesktop.Secret.Item",
    )
    .await
    .unwrap();
    let (secret,): ((OwnedObjectPath, Vec<u8>, Vec<u8>, String),) =
        item.call("GetSecret", &(session.clone(),)).await.unwrap();
    assert_eq!(secret.2, b"fixture-secret");
    let alias: OwnedObjectPath = service.call("ReadAlias", &("login",)).await.unwrap();
    let mut transcript = vec![
        json!({"dbus": {"path": path, "label": item.get_property::<String>("Label").await.unwrap(), "secret": secret.2, "content_type": secret.3, "alias": alias.as_str()}}),
    ];
    let cli = std::env::var("ROSEC_PARITY_CLI").ok();
    if let Some(cli) = &cli {
        for args in [
            vec!["search", "--no-unlock", "--format=json"],
            vec!["get", "--no-unlock", path.as_str()],
            vec!["get", "--no-unlock", "--attr", "username", path.as_str()],
        ] {
            let exe = cli.clone();
            let address = bus.address.clone();
            let owned: Vec<String> = args.iter().map(|s| s.to_string()).collect();
            let output = tokio::task::spawn_blocking(move || {
                std::process::Command::new(exe)
                    .args(owned)
                    .env("DBUS_SESSION_BUS_ADDRESS", address)
                    .env_remove("ROSEC_SOCKET")
                    .env("XDG_CONFIG_HOME", "/tmp/rosec-parity-empty-config")
                    .output()
                    .unwrap()
            })
            .await
            .unwrap();
            assert!(
                output.status.success(),
                "{args:?}: {}",
                String::from_utf8_lossy(&output.stderr)
            );
            transcript.push(json!({"args":args,"status":output.status.code(),"stdout":String::from_utf8(output.stdout).unwrap(),"stderr":String::from_utf8(output.stderr).unwrap()}));
        }
    }
    provider
        .locked
        .store(true, std::sync::atomic::Ordering::SeqCst);
    state.mark_provider_locked_in_cache("parity");
    let error = item
        .call_method("GetSecret", &(session.clone(),))
        .await
        .unwrap_err();
    assert!(error.to_string().contains("IsLocked"));
    transcript.push(json!({"locked_error":error.to_string()}));
    provider
        .locked
        .store(false, std::sync::atomic::Ordering::SeqCst);
    state.mark_provider_unlocked_in_cache("parity");
    let (secret,): ((OwnedObjectPath, Vec<u8>, Vec<u8>, String),) =
        item.call("GetSecret", &(session,)).await.unwrap();
    transcript.push(json!({"after_unlock":secret.2}));
    if let Ok(output) = std::env::var("ROSEC_PARITY_OUTPUT") {
        std::fs::write(output, serde_json::to_string_pretty(&transcript).unwrap()).unwrap();
    }
}
