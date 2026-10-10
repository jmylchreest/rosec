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
use zeroize::{Zeroize, Zeroizing};

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

impl Drop for HttpState {
    fn drop(&mut self) {
        for value in self.headers.values_mut() {
            value.zeroize();
        }
    }
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

/// Build a `ureq::Agent` for guest HTTP requests.
///
/// Redirects are disabled so a 302 response from an allow-listed host cannot
/// silently redirect the guest to an internal endpoint. The allow-host check
/// in `http_request_impl` only sees the original URL — without this cap, a
/// `Location:` header would bypass it.
pub(crate) fn build_agent(tls_mode: &TlsMode) -> ureq::Agent {
    ureq::Agent::config_builder()
        .max_redirects(0)
        .tls_config(build_tls_config(tls_mode))
        .build()
        .new_agent()
}

/// Build a `ureq::Agent` for readiness probes.
///
/// Same redirect cap as [`build_agent`] for the same SSRF reason.
pub(crate) fn build_probe_agent(tls_mode: &TlsMode) -> ureq::Agent {
    ureq::Agent::config_builder()
        .max_redirects(0)
        .tls_config(build_tls_config(tls_mode))
        .build()
        .new_agent()
}

/// Build the three HTTP host functions that shadow extism's built-ins.
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
// Extism owns these input allocations. Wipe them on success and errors before
// freeing; the guest must not free the HTTP request/body a second time.
fn http_request_impl(
    data: &mut CurrentPlugin,
    input: &[Val],
    output: &mut [Val],
    user_data: UserData<HttpState>,
) -> Result<(), extism::Error> {
    let handles: Vec<_> = input
        .iter()
        .filter_map(|v| {
            let offset = v.unwrap_i64() as u64;
            if offset == 0 {
                None
            } else {
                data.memory_handle(offset)
            }
        })
        .collect();
    let result = http_request_inner(data, input, output, user_data);
    for handle in handles {
        data.memory_bytes_mut(handle)?.zeroize();
        data.memory_free(handle)?;
    }
    result
}

struct SensitiveRequest(extism_manifest::HttpRequest);
impl std::ops::Deref for SensitiveRequest {
    type Target = extism_manifest::HttpRequest;
    fn deref(&self) -> &Self::Target {
        &self.0
    }
}
impl Drop for SensitiveRequest {
    fn drop(&mut self) {
        self.0.url.zeroize();
        for value in self.0.headers.values_mut() {
            value.zeroize();
        }
    }
}

fn http_request_inner(
    data: &mut CurrentPlugin,
    input: &[Val],
    output: &mut [Val],
    user_data: UserData<HttpState>,
) -> Result<(), extism::Error> {
    // Clone the agent before doing anything else so we don't hold the lock
    // across WASM memory operations.
    let state_arc = get_state(&user_data)?;
    let agent = lock_state(&state_arc)?.agent.clone();

    {
        let mut state = lock_state(&state_arc)?;
        state.status = 0;
        for value in state.headers.values_mut() {
            value.zeroize();
        }
        state.headers.clear();
    }

    let http_req_offset = input[0].unwrap_i64() as u64;
    let handle = match data.memory_handle(http_req_offset) {
        Some(h) => h,
        None => anyhow::bail!("invalid handle offset for http request: {http_req_offset}"),
    };
    let req = SensitiveRequest(
        serde_json::from_slice(data.memory_bytes(handle)?)
            .map_err(|_| extism::Error::msg("Invalid HTTP request"))?,
    );

    let body_offset = input[1].unwrap_i64() as u64;

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
        return Err(extism::Error::msg("HTTP destination is not allowed"));
    }

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

    // Bound a blocking host transport call even when guest cancellation cannot
    // interrupt the underlying socket. The whole guest call has its own deadline.
    let timeout = Some(
        data.time_remaining()
            .unwrap_or(std::time::Duration::from_secs(10))
            .min(std::time::Duration::from_secs(10)),
    );
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

            if let ureq::Error::StatusCode(status) = e {
                lock_state(&state_arc)?.status = status;
                None
            } else {
                return Err(extism::Error::msg("HTTP transport failed"));
            }
        }
    };

    if let Some(reader) = reader {
        let mut buf = Zeroizing::new(Vec::new());
        let max = data
            .manifest()
            .memory
            .max_http_response_bytes
            .unwrap_or(DEFAULT_MAX_HTTP_RESPONSE_BYTES);
        reader.take(max + 1).read_to_end(&mut buf)?;

        if buf.len() > max as usize {
            anyhow::bail!("HTTP response exceeds the configured maximum number of bytes: {max}");
        }

        let mem = data.memory_new(buf.as_slice())?;
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
        let headers = Zeroizing::new(serde_json::to_string(&state.headers)?);
        drop(state);
        data.memory_set_val(&mut output[0], headers.as_str())?;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    const HTTP_GUEST: &str = r#"(module
        (import "extism:host/env" "input_offset" (func $input (result i64)))
        (import "extism:host/env" "http_request" (func $http (param i64 i64) (result i64)))
        (import "extism:host/env" "length" (func $length (param i64) (result i64)))
        (import "extism:host/env" "output_set" (func $output (param i64 i64)))
        (func (export "request") (result i32) (local $response i64)
            call $input i64.const 0 call $http local.set $response
            local.get $response local.get $response call $length call $output
            i32.const 0))"#;

    fn plugin(max: u64, timeout: std::time::Duration) -> extism::Plugin {
        let mut manifest =
            extism::Manifest::new([extism::Wasm::data(HTTP_GUEST.as_bytes().to_vec())])
                .with_allowed_host("127.0.0.1")
                .with_timeout(timeout);
        manifest.memory.max_http_response_bytes = Some(max);
        extism::Plugin::new(manifest, build_http_host_functions(&TlsMode::Bundled), true).unwrap()
    }
    fn server(
        body: &'static str,
        delay: std::time::Duration,
    ) -> (String, std::thread::JoinHandle<()>) {
        use std::io::Write;
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let url = format!("http://{}", listener.local_addr().unwrap());
        let task = std::thread::spawn(move || {
            let (mut socket, _) = listener.accept().unwrap();
            socket
                .set_read_timeout(Some(std::time::Duration::from_secs(2)))
                .unwrap();
            let mut request = [0; 4096];
            let _ = socket.read(&mut request).unwrap();
            std::thread::sleep(delay);
            let response = format!(
                "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
                body.len(),
                body
            );
            let _ = socket.write_all(response.as_bytes());
        });
        (url, task)
    }
    fn request(plugin: &mut extism::Plugin, url: &str) -> Result<Vec<u8>, extism::Error> {
        let json = serde_json::to_vec(&extism_manifest::HttpRequest::new(url)).unwrap();
        plugin.call("request", json)
    }
    #[test]
    fn override_enforces_response_limit_and_execution_deadline() {
        let (url, task) = server("synthetic-response", std::time::Duration::ZERO);
        let mut p = plugin(64, std::time::Duration::from_secs(2));
        assert_eq!(request(&mut p, &url).unwrap(), b"synthetic-response");
        task.join().unwrap();
        let (url, task) = server("synthetic-response", std::time::Duration::ZERO);
        let mut p = plugin(4, std::time::Duration::from_secs(2));
        assert!(request(&mut p, &url).is_err());
        task.join().unwrap();
        let (url, task) = server("synthetic-response", std::time::Duration::from_millis(300));
        let mut p = plugin(64, std::time::Duration::from_millis(50));
        assert!(request(&mut p, &url).is_err());
        task.join().unwrap();
    }
    #[test]
    fn denied_url_does_not_leak_query_credentials() {
        let mut p = plugin(64, std::time::Duration::from_secs(2));
        let error = request(&mut p, "https://denied.invalid/?token=synthetic-secret").unwrap_err();
        assert!(!error.to_string().contains("synthetic-secret"));
    }
}
