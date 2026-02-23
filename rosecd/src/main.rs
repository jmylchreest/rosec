use std::path::PathBuf;
use std::sync::Arc;

use anyhow::Result;
use rosec_core::config::Config;
use rosec_core::router::{Router, RouterConfig};
use rosec_core::VaultBackend;
use rosec_secret_service::PromptLauncher;
use rosec_secret_service::server::register_objects;
use rosec_secret_service::session::SessionManager;

#[tokio::main]
async fn main() -> Result<()> {
    tracing_subscriber::fmt().with_env_filter("info").init();

    let config_path = parse_config_path();
    let config = load_config(&config_path)?;
    tracing::info!("loaded config from {}", config_path.display());
    tracing::info!("backends configured: {}", config.backend.len());

    let router_config = RouterConfig {
        dedup_strategy: config.service.dedup_strategy,
        dedup_time_fallback: config.service.dedup_time_fallback,
    };
    let router = Arc::new(Router::new(router_config));
    let sessions = Arc::new(SessionManager::new());

    let backend: Arc<dyn VaultBackend> = build_backend(&config)?;
    let prompt_launcher = build_prompt_launcher(&config);

    let conn = zbus::Connection::session().await?;
    let state = register_objects(&conn, backend, router, sessions).await?;

    // Attach prompt launcher for unlock flow
    state.set_prompt_launcher(prompt_launcher);

    // Claim the well-known bus name so clients can discover us
    conn.request_name("org.freedesktop.secrets").await?;

    // TODO: Integrate with logind for on_logout / on_session_lock policies.
    // Currently deferred — auto-lock policies (idle timeout, max-unlocked) are
    // handled below. SystemD logind integration (lock-on-sleep, lock-on-switch)
    // will require monitoring org.freedesktop.login1 D-Bus signals.
    tracing::info!("rosecd ready on session bus");

    let refresh_interval = config
        .service
        .refresh_interval_secs
        .unwrap_or(60);

    let refresh_state = Arc::clone(&state);
    tokio::spawn(async move {
        let interval = tokio::time::Duration::from_secs(refresh_interval);
        let mut consecutive_failures = 0u32;
        loop {
            tokio::time::sleep(interval).await;

            // Skip refresh if backend is locked — avoid triggering unlock prompt
            match refresh_state.backend.status().await {
                Ok(status) if status.locked => {
                    tracing::debug!("background refresh skipped: backend is locked");
                    continue;
                }
                Err(e) => {
                    tracing::debug!("background refresh skipped: status check failed: {e}");
                    continue;
                }
                Ok(_) => {}
            }

            match refresh_state.refresh_items().await {
                Ok(entries) => {
                    if consecutive_failures > 0 {
                        tracing::info!(
                            "background refresh recovered after {} failures: {} items",
                            consecutive_failures,
                            entries.len()
                        );
                    } else {
                        tracing::debug!("background refresh: {} items", entries.len());
                    }
                    consecutive_failures = 0;
                }
                Err(err) => {
                    consecutive_failures += 1;
                    if consecutive_failures <= 3 {
                        tracing::warn!(
                            attempt = consecutive_failures,
                            "background refresh failed: {err}"
                        );
                    } else if consecutive_failures == 4 {
                        tracing::warn!(
                            "background refresh has failed {} times, suppressing further warnings",
                            consecutive_failures
                        );
                    }
                    // else: silently continue to avoid log spam
                }
            }
        }
    });

    // Auto-lock policy background task
    let autolock = config.autolock.clone();
    let autolock_state = Arc::clone(&state);
    tokio::spawn(async move {
        let check_interval = tokio::time::Duration::from_secs(30);
        loop {
            tokio::time::sleep(check_interval).await;

            // Check idle timeout
            if let Some(idle_min) = autolock.idle_timeout_minutes
                && autolock_state.is_idle_expired(idle_min)
            {
                tracing::info!(idle_minutes = idle_min, "idle timeout expired, locking");
                if let Err(e) = autolock_state.auto_lock().await {
                    tracing::warn!("auto-lock failed: {e}");
                }
                continue;
            }

            // Check max-unlocked timeout
            if let Some(max_min) = autolock.max_unlocked_minutes
                && autolock_state.is_max_unlocked_expired(max_min)
            {
                tracing::info!(max_minutes = max_min, "max-unlocked timeout expired, locking");
                if let Err(e) = autolock_state.auto_lock().await {
                    tracing::warn!("auto-lock failed: {e}");
                }
            }
        }
    });

    // Wait for SIGTERM or SIGINT for graceful shutdown
    shutdown_signal().await;
    tracing::info!("received shutdown signal, exiting");
    Ok(())
}

/// Wait for ctrl-c (SIGINT) or SIGTERM.
async fn shutdown_signal() {
    let ctrl_c = tokio::signal::ctrl_c();

    #[cfg(unix)]
    {
        match tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate()) {
            Ok(mut sigterm) => {
                tokio::select! {
                    _ = ctrl_c => {}
                    _ = sigterm.recv() => {}
                }
            }
            Err(e) => {
                tracing::warn!("failed to register SIGTERM handler: {e}, falling back to SIGINT only");
                ctrl_c.await.ok();
            }
        }
    }

    #[cfg(not(unix))]
    {
        ctrl_c.await.ok();
    }
}

/// Build a `PromptLauncher` from the prompt section of the config.
fn build_prompt_launcher(config: &Config) -> PromptLauncher {
    let program = match config.prompt.backend.as_str() {
        "builtin" | "" => "rosec-prompt".to_string(),
        custom => custom.to_string(),
    };
    let args = config.prompt.args.clone();
    let theme = config.prompt.theme.clone();
    PromptLauncher::new(program, args, theme)
}

/// Build the appropriate backend based on config.
fn build_backend(config: &Config) -> Result<Arc<dyn VaultBackend>> {
    let entry = match config.backend.first() {
        Some(e) => e,
        None => {
            tracing::warn!("no backends configured; using mock backend");
            return Ok(Arc::new(MockBackend));
        }
    };

    match entry.kind.as_str() {
        "bitwarden" => {
            let email = entry
                .options
                .get("email")
                .and_then(|v| v.as_str())
                .ok_or_else(|| anyhow::anyhow!("bitwarden backend requires 'email' option"))?
                .to_string();

            let server_url = entry
                .options
                .get("base_url")
                .and_then(|v| v.as_str())
                .map(String::from);

            let bw_config = rosec_bitwarden::BitwardenConfig {
                server_url,
                email,
            };

            let backend = rosec_bitwarden::BitwardenBackend::new(bw_config)
                .map_err(|e| anyhow::anyhow!("failed to create bitwarden backend: {e}"))?;

            tracing::info!(
                backend_id = entry.id,
                "bitwarden backend initialized (locked, awaiting unlock)"
            );

            Ok(Arc::new(backend))
        }
        other => {
            tracing::warn!(
                backend_type = other,
                "unknown backend type; using mock backend"
            );
            Ok(Arc::new(MockBackend))
        }
    }
}

/// Parse `--config <path>` from CLI args, falling back to XDG default.
fn parse_config_path() -> PathBuf {
    let args: Vec<String> = std::env::args().collect();
    let mut i = 1;
    while i < args.len() {
        if args[i] == "--config" || args[i] == "-c" {
            if let Some(path) = args.get(i + 1) {
                return PathBuf::from(path);
            }
            eprintln!("error: --config requires a path argument");
            std::process::exit(1);
        }
        if let Some(path) = args[i].strip_prefix("--config=") {
            return PathBuf::from(path);
        }
        if args[i] == "--help" || args[i] == "-h" {
            eprintln!("Usage: rosecd [--config <path>]");
            eprintln!();
            eprintln!("Options:");
            eprintln!("  -c, --config <path>  Path to config file (default: $XDG_CONFIG_HOME/rosec/config.toml)");
            eprintln!("  -h, --help           Show this help message");
            std::process::exit(0);
        }
        i += 1;
    }
    default_config_path()
}

fn default_config_path() -> PathBuf {
    let mut base = std::env::var_os("XDG_CONFIG_HOME")
        .map(PathBuf::from)
        .unwrap_or_else(|| {
            let home = std::env::var_os("HOME").unwrap_or_default();
            PathBuf::from(home).join(".config")
        });
    base.push("rosec");
    base.push("config.toml");
    base
}

fn load_config(path: &PathBuf) -> Result<Config> {
    if !path.exists() {
        tracing::warn!(
            "config file not found at {}, using defaults",
            path.display()
        );
        return Ok(Config::default());
    }
    let content = std::fs::read_to_string(path)?;
    let config: Config = toml::from_str(&content)?;
    Ok(config)
}

#[derive(Debug)]
struct MockBackend;

#[async_trait::async_trait]
impl rosec_core::VaultBackend for MockBackend {
    fn id(&self) -> &str {
        "mock"
    }

    fn name(&self) -> &str {
        "Mock Backend"
    }

    async fn status(&self) -> Result<rosec_core::BackendStatus, rosec_core::BackendError> {
        Ok(rosec_core::BackendStatus {
            locked: true,
            last_sync: None,
        })
    }

    async fn unlock(
        &self,
        _input: rosec_core::UnlockInput,
    ) -> Result<(), rosec_core::BackendError> {
        Ok(())
    }

    async fn lock(&self) -> Result<(), rosec_core::BackendError> {
        Ok(())
    }

    async fn recover(&self) -> Result<rosec_core::RecoveryOutcome, rosec_core::BackendError> {
        Ok(rosec_core::RecoveryOutcome::Recovered)
    }

    async fn list_items(&self) -> Result<Vec<rosec_core::VaultItemMeta>, rosec_core::BackendError> {
        Ok(Vec::new())
    }

    async fn get_item(&self, _id: &str) -> Result<rosec_core::VaultItem, rosec_core::BackendError> {
        Err(rosec_core::BackendError::NotFound)
    }

    async fn get_secret(
        &self,
        _id: &str,
    ) -> Result<rosec_core::SecretBytes, rosec_core::BackendError> {
        Err(rosec_core::BackendError::NotFound)
    }

    async fn search(
        &self,
        _attrs: &rosec_core::Attributes,
    ) -> Result<Vec<rosec_core::VaultItemMeta>, rosec_core::BackendError> {
        Ok(Vec::new())
    }
}
