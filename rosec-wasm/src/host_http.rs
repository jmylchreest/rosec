//! Custom HTTP host functions that override extism's built-in HTTP support.
//!
//! Extism's built-in `http_request` uses `ureq::agent()` which defaults to
//! `RootCerts::WebPki` (Mozilla's bundled root certificates).  This means
//! self-signed certificates or certificates signed by a private CA are rejected
//! even if the OS trusts them.
//!
//! This module provides replacement host functions registered in the
//! `extism:host/env` namespace that shadow the built-ins.  Because extism's
//! linker has `allow_shadowing(true)` and user-provided functions are registered
//! *after* built-ins, these overrides take precedence transparently.

use std::collections::BTreeMap;
use std::io::Read;

use extism::{CurrentPlugin, EXTISM_ENV_MODULE, Function, UserData, Val, ValType};
use rosec_core::config::TlsMode;

/// Shared state between the three HTTP host function overrides.
///
/// The WASM guest calls `http_request` first, then separately calls
/// `http_status_code` and `http_headers` to retrieve response metadata.
/// This struct carries that state across the three calls.
///
/// Wrapped by `UserData` which provides its own `Arc<Mutex<T>>`.
struct HttpState {
    agent: ureq::Agent,
    status: u16,
    headers: BTreeMap<String, String>,
}

fn build_tls_config(tls_mode: &TlsMode) -> ureq::tls::TlsConfig {
    match tls_mode {
        TlsMode::Bundled => ureq::tls::TlsConfig::builder().build(),
        TlsMode::System => ureq::tls::TlsConfig::builder()
            .root_certs(ureq::tls::RootCerts::PlatformVerifier)
            .build(),
        TlsMode::Disabled => ureq::tls::TlsConfig::builder()
            .disable_verification(true)
            .build(),
    }
}

/// Build a `ureq::Agent` configured for the given TLS mode.
pub(crate) fn build_agent(tls_mode: &TlsMode) -> ureq::Agent {
    ureq::Agent::config_builder()
        .tls_config(build_tls_config(tls_mode))
        .build()
        .new_agent()
}

/// Build a `ureq::Agent` for readiness probes.
///
/// Like [`build_agent`] but also disables redirects to prevent SSRF via an
/// allowed host that 302-redirects to internal endpoints.
pub(crate) fn build_probe_agent(tls_mode: &TlsMode) -> ureq::Agent {
    ureq::Agent::config_builder()
        .max_redirects(0)
        .tls_config(build_tls_config(tls_mode))
        .build()
        .new_agent()
}

/// Build the three HTTP host functions that shadow extism's built-ins.
///
/// Returns a `Vec<Function>` ready to pass to `Plugin::new`.
pub(crate) fn build_http_host_functions(tls_mode: &TlsMode) -> Vec<Function> {
    // UserData::new wraps in Arc<Mutex<T>>; cloning shares the same Arc.
    let user_data: UserData<HttpState> = UserData::new(HttpState {
        agent: build_agent(tls_mode),
        status: 0,
        headers: BTreeMap::new(),
    });

    vec![
        Function::new(
            "http_request",
            [ValType::I64, ValType::I64],
            [ValType::I64],
            user_data.clone(),
            http_request_impl,
        )
        .with_namespace(EXTISM_ENV_MODULE),
        Function::new(
            "http_status_code",
            [],
            [ValType::I32],
            user_data.clone(),
            http_status_code_impl,
        )
        .with_namespace(EXTISM_ENV_MODULE),
        Function::new(
            "http_headers",
            [],
            [ValType::I64],
            user_data,
            http_headers_impl,
        )
        .with_namespace(EXTISM_ENV_MODULE),
    ]
}

/// Default maximum HTTP response size (50 MiB), matching extism's default.
const DEFAULT_MAX_HTTP_RESPONSE_BYTES: u64 = 1024 * 1024 * 50;

fn get_state(
    user_data: &UserData<HttpState>,
) -> Result<std::sync::Arc<std::sync::Mutex<HttpState>>, extism::Error> {
    user_data
        .get()
        .map_err(|e| extism::Error::msg(format!("http state error: {e}")))
}

fn lock_state(
    arc: &std::sync::Arc<std::sync::Mutex<HttpState>>,
) -> Result<std::sync::MutexGuard<'_, HttpState>, extism::Error> {
    arc.lock()
        .map_err(|e| extism::Error::msg(format!("http state lock poisoned: {e}")))
}

/// Override for `extism:host/env::http_request`.
///
/// Replicates the logic from extism's `pdk.rs` but uses a custom ureq agent
/// with configurable TLS root certificates.
fn http_request_impl(
    data: &mut CurrentPlugin,
    input: &[Val],
    output: &mut [Val],
    user_data: UserData<HttpState>,
) -> Result<(), extism::Error> {
    // Clone the agent before doing anything else so we don't hold the lock
    // across WASM memory operations.
    let state_arc = get_state(&user_data)?;
    let agent = lock_state(&state_arc)?.agent.clone();

    // Reset state from previous request.
    {
        let mut state = lock_state(&state_arc)?;
        state.status = 0;
        state.headers.clear();
    }

    // ── Read the request from WASM memory ──────────────────────────

    let http_req_offset = input[0].unwrap_i64() as u64;
    let handle = match data.memory_handle(http_req_offset) {
        Some(h) => h,
        None => anyhow::bail!("invalid handle offset for http request: {http_req_offset}"),
    };
    let req: extism_manifest::HttpRequest = serde_json::from_slice(data.memory_bytes(handle)?)?;
    data.memory_free(handle)?;

    let body_offset = input[1].unwrap_i64() as u64;

    // ── Check allowed_hosts ────────────────────────────────────────

    let url = match url::Url::parse(&req.url) {
        Ok(u) => u,
        Err(e) => return Err(extism::Error::msg(format!("Invalid URL: {e:?}"))),
    };
    let allowed_hosts = &data.manifest().allowed_hosts;
    let host_str = url.host_str().unwrap_or_default();
    let host_matches = if let Some(allowed_hosts) = allowed_hosts {
        allowed_hosts.iter().any(|pattern| {
            let pat = match glob::Pattern::new(pattern) {
                Ok(x) => x,
                Err(_) => return pattern == host_str,
            };
            pat.matches(host_str)
        })
    } else {
        false
    };

    if !host_matches {
        return Err(extism::Error::msg(format!(
            "HTTP request to {} is not allowed",
            req.url
        )));
    }

    // ── Build the ureq request ─────────────────────────────────────

    let mut r = ureq::http::request::Builder::new()
        .method(
            req.method
                .as_deref()
                .unwrap_or("GET")
                .to_uppercase()
                .as_str(),
        )
        .uri(&req.url);

    for (k, v) in req.headers.iter() {
        r = r.header(k, v);
    }

    let timeout = data.time_remaining();
    let res = if body_offset > 0 {
        let handle = match data.memory_handle(body_offset) {
            Some(h) => h,
            None => {
                anyhow::bail!("invalid handle offset for http request body: {http_req_offset}")
            }
        };
        let buf: &[u8] = data.memory_bytes(handle)?;
        let config = agent
            .configure_request(r.body(buf)?)
            .http_status_as_error(false);
        let req = config.timeout_global(timeout).build();
        ureq::run(req)
    } else {
        let config = agent
            .configure_request(r.body(())?)
            .http_status_as_error(false);
        let req = config.timeout_global(timeout).build();
        ureq::run(req)
    };

    if let Some(handle) = data.memory_handle(body_offset) {
        data.memory_free(handle)?;
    }

    // ── Process the response ───────────────────────────────────────

    let reader = match res {
        Ok(res) => {
            let mut state = lock_state(&state_arc)?;
            for (name, h) in res.headers() {
                if let Ok(h) = h.to_str() {
                    state
                        .headers
                        .insert(name.as_str().to_string(), h.to_string());
                }
            }
            state.status = res.status().as_u16();
            Some(res.into_body().into_reader())
        }
        Err(e) => {
            if let Some(d) = data.time_remaining()
                && matches!(e, ureq::Error::Timeout(_))
                && d.as_nanos() == 0
            {
                anyhow::bail!("timeout");
            }
            let msg = e.to_string();
            if let ureq::Error::StatusCode(status) = e {
                lock_state(&state_arc)?.status = status;
                None
            } else {
                return Err(extism::Error::msg(msg));
            }
        }
    };

    if let Some(reader) = reader {
        let mut buf = Vec::new();
        let max = data
            .manifest()
            .memory
            .max_http_response_bytes
            .unwrap_or(DEFAULT_MAX_HTTP_RESPONSE_BYTES);
        reader.take(max + 1).read_to_end(&mut buf)?;

        if buf.len() > max as usize {
            anyhow::bail!("HTTP response exceeds the configured maximum number of bytes: {max}");
        }

        let mem = data.memory_new(&buf)?;
        output[0] = Val::I64(mem.offset() as i64);
    } else {
        output[0] = Val::I64(0);
    }

    Ok(())
}

/// Override for `extism:host/env::http_status_code`.
fn http_status_code_impl(
    _data: &mut CurrentPlugin,
    _input: &[Val],
    output: &mut [Val],
    user_data: UserData<HttpState>,
) -> Result<(), extism::Error> {
    let state_arc = get_state(&user_data)?;
    output[0] = Val::I32(lock_state(&state_arc)?.status as i32);
    Ok(())
}

/// Override for `extism:host/env::http_headers`.
fn http_headers_impl(
    data: &mut CurrentPlugin,
    _input: &[Val],
    output: &mut [Val],
    user_data: UserData<HttpState>,
) -> Result<(), extism::Error> {
    let state_arc = get_state(&user_data)?;
    let state = lock_state(&state_arc)?;
    if state.headers.is_empty() {
        output[0] = Val::I64(0);
    } else {
        let headers = serde_json::to_string(&state.headers)?;
        drop(state);
        data.memory_set_val(&mut output[0], headers)?;
    }
    Ok(())
}
