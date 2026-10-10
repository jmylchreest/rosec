# Proton Pass security and performance review

Reviewed 2026-10-10, starting at `2f3648c`. Scope: the standalone
`rosec-protonpass` guest, its tests/probe, selected host integration boundaries and
provider documentation. This is a source review with targeted tests, not a formal
audit or a claim of production readiness. The live account was not accessed.

## Result

The security follow-up fixes the identified host lifecycle, credential persistence,
owned-memory cleanup and resource-boundary defects. **The spike is still not a
release candidate:** the agreed retrieval features and distribution review remain
incomplete. Erasure of every upstream-library/compiler copy is not proven. No
account credentials were accessed during these changes.

## Security follow-up (2026-10-10)

| Finding | Resolution and evidence |
|---|---|
| Four Wasmtime advisories and old WASI dependencies | Both lockfiles use Extism 1.41.0 / Wasmtime 49.0.2. Removed the obsolete 0222 exception. The standalone plugin audit has no suppressions or findings. Workspace audit passes its existing policy; unrelated `rsa`, `quick-xml` and `ttf-parser` exceptions remain. Upgraded `rqrr` to 0.11 / `lru` 0.18.5 to remove 0253. Workspace MSRV is now 1.96. |
| Timed-out/cancelled unlock could finish later | Worker call guards cancel execution and invalidate a generation. Closed/stale queued calls are skipped. The same generation fences the whole authentication flow, including credential KDF/replay and offline restore. Later calls require a fresh instance. Actual WASM tests cover dropped futures, caller timeout, traps, malformed output, panic, explicit invalidation and queue saturation. |
| Panic or failed reinitialization retained a damaged instance | Panics force recreation; failed rebuild/init stops the worker. Closed watch channels no longer spin. Guest-call errors do not include raw guest error text. |
| Lock waited behind active work and retained host cache keys on error | Lock fences queued calls and cancels active execution; idle guests may perform session cleanup before unconditional disposal. Host cache keys clear before waiting. Tests verify idle cleanup, cancellation and locked state after restart. |
| Password/registration lifecycle incomplete | PAT moved to registration metadata. Password-only unlock returns `registration_required`, activating host credential replay. Host tests cover register/lock/restart/correct and wrong password; credential tests cover token/passphrase replacement, machine/provider binding and v1 migration. Persistence failure invalidates the unlocked instance. |
| Weak password-only credential wrapping and unsafe persistence edges | New writes use Argon2id, 64 MiB/3 passes/1 lane, 16-byte random salt, installation secret and provider-bound HKDF. KDF scratch memory is guarded and work runs off Tokio threads. Atomic mode-0600 writes avoid predictable temporary paths. Machine-key creation cannot overwrite a concurrent winner. Corrupt/oversized credential files fail with redacted errors. |
| Partial parser allocations, secret replies and request copies | Guest allocator wipes on deallocation/reallocation, covering partially parsed/unknown fields and serialization temporaries. AES/GHASH/CTR/POLYVAL cleanup enabled. Unlock requests own drop guards; secret result fields deserialize into guarded strings. Host scrubs output memory, HTTP request/body buffers and owned response buffers. Allocation regression checks memory before release. |
| Session expiry and cleanup absent | One refresh attempt after 401 rotates UID/access/refresh atomically; 403 never retries. Normal lock/re-authentication best-effort revokes only this session. Fixture covers successful refresh, revoked refresh, permission denial, outage and cleanup. Abrupt disposal/network failure cannot guarantee server logout. |
| Snapshot duplication and split resource limits | Sync clears the previous snapshot before replacement; transport outages report unavailable while remaining locked. Host enforces Proton's 8 MiB response limit, 256 MiB memory, 60-second execution/65-second caller deadline and 10-second HTTP cap. Other guests retain their 180-second execution budget for slow KeePass KDFs, with a 185-second caller limit. Real HTTP override tests check size, execution deadline and redacted denial errors. |

The refresh/revocation protocol was checked against Proton's published
[Go API refresh implementation](https://github.com/ProtonMail/go-proton-api/blob/master/manager_auth.go)
and [WebClients authentication routes](https://github.com/ProtonMail/WebClients/blob/main/packages/shared/lib/api/auth.ts).
Those upstream sources establish request shapes, not proof of live PAT-session compatibility.
The new lifecycle tests use synthetic data only.

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

1. **Residual memory-assurance gap (`security-imperative`).** Owned buffers now have
   cleanup, including guest parser failures, crypto state and host reply transport.
   Upstream HTTP/TLS/header/parser internals and compiler-generated stack/register
   copies are not all under rosec's control. Process memory, swap and crash-dump
   inspection were not performed. Do not claim lock erases every historical copy.
   A strict interpretation requiring that proof remains unfulfilled.
2. **Live lifecycle validation.** Synthetic tests cover password replay/recovery,
   refresh and logout, but those changes have not been tested against the live
   Proton account. Network failure or a trap may prevent remote session revocation;
   locally discarded tokens are not persisted. A retained PAT is an intentional
   credential for future unlock, and must be revoked separately in Proton when
   decommissioning the provider. Remote revocation is observed on the next API call.
3. **Availability limits.** Full sync remains serial and fails closed on any error.
   Large/slow vaults can hit the documented memory/time/item limits. HTTP cancellation
   can wait for its bounded blocking operation. No incremental cursor or offline
   cache was introduced by this security work. Limits are not a throughput guarantee.
4. **First-release scope (`protonpass-scope`).** SSH-agent enumeration/signing,
   existing passkey use, offline cache, protected metadata, folders and canonical
   attribute normalization remain required. Extra TOTP fields are not separately
   indexed frontend entries. These unsupported capabilities are not advertised.
5. **Distribution.** GPL provenance/source is present; combined distribution,
   corresponding-source and third-party notices still need review. There is no AUR
   package and this plugin remains outside the release pipeline.
6. **Existing workspace advisory exceptions.** The unfiltered workspace audit still
   reports `rsa` 2023-0071, `quick-xml` 2026-0194/0195 and unmaintained `ttf-parser`
   2026-0192. They are outside the Proton/Extism dependency tree and retain their
   existing documented exceptions. No new exception was added by this follow-up.

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

The security follow-up (Extism 1.41, wiping allocator, same synthetic fixture)
measured **30.369 µs p50 / 34.549 µs p95**, with **68 ms** full sync and **12 requests**.
This single follow-up run detects no regression; it is not a controlled attribution
of the improvement to any one change and is not a live-network benchmark.

## Validation and audit method

Follow-up checks: 108 core tests, 101 WASM-host tests and nine standalone guest tests,
actual compiled fixture with refresh/logout/outages, production endpoint restrictions,
HTTP override tests, native/WASI Clippy, full workspace/all-targets check on Rust
1.96, formatting and Docusaurus production build. No live Proton account was used.


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
  The follow-up plugin lockfile has 326 packages including native dev dependencies.
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
- `rust-edition`: Cargo.toml uses edition 2024. Validation uses the installed compiler; the patched host requires Rust 1.96. The old recorded 1.93 minimum is stale relative to this security dependency upgrade.
- `security-imperative`: Owned-buffer and lifecycle fixes checked by allocator, credential, HTTP and actual-WASM tests. Strict full-memory-erasure conformance remains unproven for the upstream/compiler copies listed above.
- `sm-passphrase-unlock`: Shared registration wrapping now includes the installation secret and passphrase, with Argon2id strengthening; no auto-unlock path added. Host tests prove wrong-password rejection and replay after restart. Explicit PAT registration chooses the local passphrase.
- `trait-simplification`: Guest exports separate metadata/secret-attribute methods; no removed host trait methods were reintroduced.
- `vault-architecture`: Local-vault storage is untouched. Its old backend/CLI naming conflicts with the newer `provider-rename` decision, so new docs follow the latter.
- `wasm-providers`: Conforms to the Extism/JSON/allowlisted-HTTP architecture. The standalone guest uses WASI; HTTP overrides, cancellation and output cleanup were regression-tested against Extism 1.41.
