pub mod collection;
pub mod crypto;
pub mod daemon;
pub mod item;
pub mod prompt;
pub mod server;
pub mod service;
pub mod session;
pub mod session_iface;
pub mod state;

pub use service::SecretService;
pub use state::ServiceState;

#[cfg(test)]
mod tests {
    #[test]
    fn opens_plain_session() {
        let sessions = std::sync::Arc::new(crate::session::SessionManager::new());
        let (output, path) = match sessions.open_session("plain", &zvariant::Value::from("")) {
            Ok(result) => result,
            Err(err) => panic!("open session failed: {err}"),
        };
        let _ = output;
        assert!(path.contains("/org/freedesktop/secrets/session/"));
        assert!(sessions.is_valid(&path).unwrap_or(false));
    }
}
