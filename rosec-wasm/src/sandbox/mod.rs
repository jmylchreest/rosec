//! Per-WASM-provider sandbox primitives.
//!
//! Provides:
//!   - [`worker::Worker`] — generic actor pattern for embedding a sync,
//!     stateful resource (extism::Plugin) inside an async daemon.
//!     Eliminates the async-blocking anti-pattern of calling the sync
//!     `Plugin::call` under a `tokio::sync::Mutex` from async code.
//!   - [`policy_to_ruleset`] — pure function translating `PluginPolicy` +
//!     resolved options into the `PathRule`/`ConnectPort` lists that
//!     `rosec_core::sandbox::landlock` consumes. Per-provider Landlock
//!     applied at worker thread startup.

pub(crate) mod policy_to_ruleset;
pub(crate) mod worker;
