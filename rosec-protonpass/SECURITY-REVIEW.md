# Proton Pass security and performance review

Reviewed 2026-10-10, starting at `2f3648c`. Scope: the standalone
`rosec-protonpass` guest, its tests/probe, selected host integration boundaries and
provider documentation. This is a source review with targeted tests, not a formal
audit or a claim of production readiness. The live account was not accessed.

## Result

The spike is suitable for further isolated development. **Do not release it yet.**
The concrete plugin issues below were fixed. Shared host advisories, complete
credential lifecycle, remaining secret copies and the agreed first-release
retrieval features still need work. No write/password-change forwarding was added.

## Fixed in this pass

| Finding | Change and evidence |
|---|---|
| A failed reauthentication with an empty/missing password left the old unlocked snapshot usable. | `guest::unlock` now clears state before examining credentials. The probe reproduced the failure before the fix, then verified rejected authentication leaves the guest locked. |
| Malformed scalar/array session or credential JSON could panic through mutable indexing. | `take_secret` and session extraction use checked access. The probe covers null/array inputs, non-string passwords, malformed registration fields and malformed session replies. |
| Invalid reinitialization could leave old state active; loopback URL validation used a loose prefix. | `init` clears prior state first. `valid_api_endpoint` permits only Proton's exact HTTPS URL by default. The explicit `test-http` feature accepts numeric nonzero loopback ports only; userinfo, suffix hosts, paths and out-of-range ports are rejected. |
| PAT/base64/protobuf and aggregate sync inputs had insufficient bounds. | PAT length is checked before decoding; encrypted fields, plaintext items, shares, keys, pages, total active items and total plaintext now have limits documented in README. Oversized input/page/share tests cover representative boundaries. |
| Duplicate API IDs could create ambiguous entries. | Items are indexed by ID; duplicate IDs and key rotations reject the sync. The probe tests duplicate item IDs. |
| Session JSON and some known protobuf fields could remain in ordinary allocations on success or early mapping failure. | `SensitiveJson` and `SensitiveItem` scrub owned parsed fields on drop. Mapping borrows from the guarded message so an early error does not bypass cleanup of remaining fields. HTTP response memory is wiped before release. The token request serializes a borrowed field instead of making an extra JSON token copy. |
| Repeated item lookups scanned the full item vector. | A `BTreeMap` replaces linear lookup with logarithmic lookup. It also gives deterministic enumeration order. Measurements below include the hardening overhead. |
| Deployment and limitations were difficult to find. | Added the provider guide/sidebar link, canonical Markdown README and a least-privilege policy sidecar; retained the earlier live transcript. |

## Remaining findings and release gates

1. **High: the shared host dependency audit is not clean.** The lockfile includes
   Extism 1.30.0 / Wasmtime 43.0.2 for the native test host, matching the rosec host.
   An unfiltered RustSec audit reports four Wasmtime advisories:
   [RUSTSEC-2026-0222](https://rustsec.org/advisories/RUSTSEC-2026-0222.html),
   [RUSTSEC-2026-0269](https://rustsec.org/advisories/RUSTSEC-2026-0269.html),
   [RUSTSEC-2026-0316](https://rustsec.org/advisories/RUSTSEC-2026-0316.html), and
   [RUSTSEC-2026-0327](https://rustsec.org/advisories/RUSTSEC-2026-0327.html).
   The normal repo audit suppresses 0222 through an existing exception; no new
   exceptions were added. Informational findings cover unmaintained `bitmaps`,
   `im-rc`, `sized-chunks`, plus `sized-chunks` panic-safety unsoundness (0255).
   These are absent from the guest's normal WASI dependency tree.

   Reachability is narrower than a general-purpose component host: Extism 1.30.0
   uses `wasmtime::Module`, this guest uses preview1, and its policy has no filesystem
   preopens. Those observations reduce applicability of component/async and
   filesystem advisories; they do not prove the whole host safe. The cross-engine
   advisory is already tracked by the repository's exception referring to issue 45.
   Upgrade and regression-test the shared host instead of independently changing
   only this probe's host version. Upstream Extism's main branch now targets
   Wasmtime 48; the critical async-component advisory lists 48.0.4/49.0.2 as patched.
   A release/version migration is outside this plugin-only change.

2. **Critical production conformance gap (`security-imperative`): secret cleanup
   is not complete.** Successfully parsed owned JSON and known protobuf fields now
   have cleanup guards. Parser failures can still free partially parsed values
   before those guards exist. Generated protobuf unknown fields, crypto key
   schedules, Extism request/input/output buffers, serialized secret responses,
   HTTP header copies and host transport buffers are not all proven to be wiped.
   Do not describe lock as erasing every historical memory copy. Vendored generated
   code remains unchanged, so its unchecked generated paths were not silently
   rewritten during this pass.

3. **High: local password/credential lifecycle is not production authentication.**
   The guest accepts any nonempty local password when a valid PAT is supplied.
   The daemon currently forwards additional prompt fields as registration fields;
   both registration/auth envelopes are supported. Host credential wrapping exists,
   but restart, wrong-password, recovery and rotation behavior for this provider
   remains unverified. Session refresh and remote session logout/revocation are
   not implemented by the guest. Manual revocation of test PATs remains necessary.

4. **Medium: full sync holds guest state while fetching and can replace a large
   snapshot.** There is no incremental event cursor or concurrency. An outage,
   unsupported folder/share/format or resource limit currently discards the old
   snapshot and locks. Distinguish transport outages from confirmed revocation
   before adding an offline cache. Old and new snapshots can coexist during a
   successful sync. The 32 MiB plaintext limit is not a heap limit because JSON,
   protobuf, maps and serialized output add overhead.

5. **Medium: resource limits span guest and host.** The guest's 8 MiB response check
   now precedes its Rust copy, but the host has already buffered the response.
   `rosec-wasm::host_http` caps that at 50 MiB and disables redirects; the worker
   caps guest memory at 4,096 WASM pages (256 MiB). Its host-call timeout is 60 s,
   while its guest timeout is 180 s. A timeout/trap and in-flight lock cancellation
   still need lifecycle testing with the real daemon. The synthetic probe uses
   Extism's default transport and a 30 s call timeout, not the rosec HTTP override.

6. **First-release scope remains incomplete (`protonpass-scope`).** SSH-agent
   enumeration/signing, existing passkey use, offline cache, protected metadata,
   folders and full cross-provider attribute normalization remain required work.
   Extra TOTP fields are stored but are not additional frontend entries. None of
   these capabilities are falsely advertised. The eight-type CLI demonstration
   proves mapped reading, not completion of the first-release scope.

7. **Distribution review remains open.** GPL source/provenance is present and the
   vendored schema/generated-source hashes match UPSTREAM.txt. This review did not
   provide legal clearance for combined host/plugin distribution or complete a
   corresponding-source/third-party-notice audit.

## Performance evidence

The `probe --bench` fixture uses 1,000 synthetic login items, ten pages, 50 warmup
attribute lookups and 1,000 measured lookups of the final item. It measures actual
compiled release WASM through Extism; the native harness uses its debug profile.
One additional full sync is timed. Results include serialization/host-call overhead.
The fixture server polls every 5 ms, so sync timing is not a Proton network benchmark.

| Measurement | Before indexing/hardening | After, three runs |
|---|---:|---:|
| Attribute lookup p50 | 52.729 µs | 37.260 / 37.050 / 37.099 µs |
| Attribute lookup p95 | 54.789 µs | 38.649 / 37.920 / 56.599 µs |
| Full sync | 72 ms | 70 / 70 / 73 ms |
| HTTP requests per full sync | 12 | 12 |
| Whole-process peak RSS | Not measured | 43,764 / 42,776 / 43,176 KiB |

The observed median lookup improved about 29–30%. The noisy third p95 prevents a
claim of uniformly improved tail latency. Full sync is essentially unchanged and
still needs one share-list request, one key-page request and ten item-page requests.
No per-item HTTP requests occur. Peak RSS is Linux `wait4` usage for the entire
host/fixture process, not isolated guest memory. There is no baseline memory
measurement, so no memory improvement is claimed. Reproduce with README commands.

## Validation and audit method

- Native tests run with default features and with `test-http` enabled; guest
  release builds run with and without that feature.
- The Extism fixture tests cover TOTP, authenticated decryption/tampering, secret
  metadata separation, changes/deletions, mutation stubs, malformed input,
  rejected reauthentication/reinitialization, duplicate IDs, oversized pages/share
  counts, revocation and locking. These are synthetic regression tests.
- Guest and native Clippy use `-D warnings`; formatting and repository commit hooks
  run separately. The Docusaurus docs build checks rendered content and links.
- `cargo audit` used RustSec database commit
  `7eebec69c352c7191b1f13eb95dd510eeca5d1de` (updated 2026-10-09).
  A second run from `/tmp` used the absolute lockfile path to exclude the repo's
  `.cargo/audit.toml` suppressions. The current database was fetched before both.
  The audited lockfile has 342 packages including native dev dependencies.
- `cargo tree --target wasm32-wasip1 --edges normal` distinguishes actual guest
  dependencies from native harness dependencies. No current RustSec finding from
  this audit matched that guest tree; this is not a general safety guarantee.

## Decision conformance

Decisions loaded: **25**, using the live `.aide/bin/aide decision list/get` CLI
because the decision MCP tools were unavailable. Each line names the checked
scope/evidence. “Pending” means this spike must not be treated as a release.

- `attribute-model`: Conforms for mapped reads. `mapping.rs`, mapping tests and the fixture metadata check keep notes/custom fields/identity/card values out of public attributes.
- `attribute-naming`: Mostly conforms. `mapping.rs` uses unprefixed fields and `custom.*`; card/identity canonical normalization remains pending. The recorded `type` name is stale relative to current `rosec:type` in existing providers and the CLI alias.
- `avoid-clone`: Checked production mapping/guest code. Secrets move into guarded storage; the public first-URL clone and index ID copy maintain independent ownership. Fixture clones contain only synthetic data.
- `bitwarden-sm-crate`: Not applicable. Changed paths do not include Bitwarden SM or its dependencies.
- `capability-enum`: Conforms. `guest::capabilities` and probe assertions expose Sync/Totp only; all mutation exports remain `not_supported`.
- `clippy-zero-warnings`: Checked by native and WASI Clippy with `-D warnings`.
- `identity-fields`: The Bitwarden-specific scope is unchanged. Applied its PII rule to Proton: `mapping.rs` maps identity string values to sensitive storage, verified by tests.
- `jmylchreest-writing-change-notes`: Reviewed the hardening change description and commit body for concrete behavior, validation and limitations.
- `jmylchreest-writing-comments`: New comments explain invalidation order, secret lifetime, test endpoint restrictions and copying boundaries.
- `jmylchreest-writing-concision`: README/provider guide give commands and limits; detailed findings are kept in this report.
- `jmylchreest-writing-sentences`: Authored prose was checked for complete sentences and no em dashes.
- `jmylchreest-writing-tone`: Documentation leads with experimental status and measured results without claiming production assurance.
- `key-wrapping`: Not applicable. Local-vault key wrapping is unchanged; this guest implements no key-wrapping capability.
- `no-ai-coauthor`: Commit metadata must contain no co-author or assistant attribution; checked at commit creation.
- `no-naked-unwrap`: Handwritten guest/library production paths were searched. Test code uses assertions; generated upstream protobuf still contains generated unwrap paths and requires separate treatment under this rule.
- `offline-cache`: Pending first-release capability, not falsely advertised. No plaintext cache export or persistence was added; README requires `offline_cache=false` for tests.
- `private-socket`: Conforms to existing interfaces. The development guide uses `--socket`, `--no-migrate` and `ROSEC_SOCKET`; no bus implementation changed.
- `protonpass-scope`: Read-only boundary conforms, verified by zero-request mutation tests. Required retrieval features remain pending as listed above; the first release is not complete.
- `provider-rename`: Configuration and docs use `[[provider]]` and `rosec provider`; no legacy backend interface added.
- `rust-edition`: Cargo.toml uses edition 2024. Validation uses the installed compiler; this pass does not establish an MSRV test on Rust 1.93.
- `security-imperative`: Partial, with a critical production gap. Cleanup guards and fail-closed tests improve the boundary, but the residual copies listed above prevent full conformance.
- `sm-passphrase-unlock`: Bitwarden SM is outside the changed paths. Its passphrase-bound lifecycle is relevant guidance; Proton's nonempty-only guest check remains an explicit production blocker.
- `trait-simplification`: Guest exports separate metadata/secret-attribute methods; no removed host trait methods were reintroduced.
- `vault-architecture`: Local-vault storage is untouched. Its old backend/CLI naming conflicts with the newer `provider-rename` decision, so new docs follow the latter.
- `wasm-providers`: Conforms to the Extism/JSON/allowlisted-HTTP architecture. The standalone guest uses WASI; host callbacks and runtime APIs were not replaced.
