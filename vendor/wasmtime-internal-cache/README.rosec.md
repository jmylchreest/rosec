# Temporary Wasmtime cache security backport

This is the published crates.io wasmtime-internal-cache 49.0.5 source, including
its license and upstream tests. Upstream revision:
805a0f15320e8836cf2b9f001b53d884bf866c89, crates/cache. Cargo.toml.orig is retained as provenance.
Only the normalized Cargo.toml dependency requirement is changed: zstd 0.13.0
becomes 0.14.3, with default features still disabled. Rust sources are unchanged.

This backports https://github.com/bytecodealliance/wasmtime/pull/15003,
merged upstream on 2026-10-27. That patch uses a 0.14.0 requirement with 0.14.3
locked; we require the fixed minimum 0.14.3 directly. The 49.0.5 release still
requires 0.13, so a lockfile update alone cannot resolve the zstd/zstd-safe
advisories. No audit exemptions are added.

The root and standalone rosec-protonpass workspace patches select this copy for Extism 1.41.0 / Wasmtime 49.0.5.
Keep the crate version and its exact wasmtime-environ dependency in sync with
the runtime. Remove both workspace patches and this directory once the compatible
Wasmtime release uses zstd >=0.14.3 and zstd-safe >=8.2.0; regenerate Cargo.lock
and rerun the workspace, cache, compiled WASM tests and security audit.

Run upstream cache tests with:
    cargo test -p wasmtime-internal-cache --locked
