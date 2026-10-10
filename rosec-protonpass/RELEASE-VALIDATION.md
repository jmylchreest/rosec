# Proton Pass release validation

Validation date: 2026-10-10. This records local checks, not publication or an
independent audit. See SECURITY-REVIEW.md for findings and residual boundaries.

## Completed

- Actual compiled guest fixture: authenticated sync, malformed inputs, AEAD,
  metadata separation, TOTP, changes/deletions, limits, refresh, revocation,
  lock and unsupported writes. Folder, SSH, passkey and cache exports exercised.
- Actual sandboxed host: registration, recreation, wrong-password rejection,
  offline snapshot recovery after stopping the server, and locked-read denial.
- Isolated live Proton: temporary viewer PAT scoped to an existing synthetic
  vault, eight native types plus an additional TOTP entry, secret-field reads,
  independently verified TOTP, SSH agent signing verified by OpenSSH, session
  refresh followed by sync, lock, daemon restart, wrong-passphrase rejection and
  saved-PAT replay. Temporary PAT revoked and CLI logout confirmed.
- Standalone native regression suite: 15 tests passed with all features.
- Production and fixture release WASM builds passed, using separate target dirs.
- Proton lockfile audit passed without suppressions; workspace audit passed its
  existing documented policy. Database commit is recorded in SECURITY-REVIEW.md.

## Final checks

| Check | Result |
|---|---|
| `cargo test --workspace --locked --offline` | PASS, including 108 core and 104 WASM-host tests |
| Standalone guest tests, default and all features | PASS, 15 tests in each configuration |
| Workspace/all-target Clippy, native guest/all-target Clippy and WASI guest Clippy | PASS with `-D warnings` |
| Rust 1.96 workspace/all-target and production WASI checks | PASS |
| Rust formatting and commit hooks | PASS |
| Production and fixture WASM release builds | PASS |
| Production endpoint/fixture-export rejection probe | PASS on original and source-rebuilt WASM |
| Real guest and host synthetic integration | PASS, including offline/restart/wrong password |
| Dependency audit | PASS under the scope/policy described above |
| Documentation typecheck and production build | PASS, 237 indexed documents |
| Workflow YAML and embedded Bash syntax | PASS |
| Corresponding-source generation | PASS, 95 dependency notice entries and vendored locked sources |
| Offline source rebuild with an empty Cargo home and fresh target directory | PASS |
| Bundle signing/verification with a disposable key | PASS; test private key removed |
| AUR `.SRCINFO` generation and `makepkg --nodeps --noconfirm --cleanbuild` | PASS; no installation performed |
| AUR installed payload inspection | PASS: exact WASM, policy, signature, GPL text, dependency notices and source reference |

Source packaging was tested from commit `0ff7757`. Later changes to the report,
licence documentation, clean-tree check and workflow gates do not change the
provider binary. Source rebuilds are functional rebuilds, not a claim of
bit-for-bit reproducibility across source/vendor paths. Both artifacts passed
production restriction checks.

Final synthetic benchmark: 1,000 items, 1,000 lookups, p50 **30.509 microseconds**,
p95 **51.889 microseconds**, full sync **69 ms**, **12 HTTP requests**. This is a
local fixture measurement, not a live-network throughput promise.

The local release gates are complete. The plugin remains marked experimental.
No release/tag/AUR upload has been published. Release-key signing and GitHub/AUR
execution remain deployment steps, and were not simulated with real release keys.

## Reproduction

The README gives build, probe, test, Clippy and benchmark commands. Use a separate
production target directory and pass its guest path via `PROTONPASS_WASM` with
`probe --check-production`. Use the `test-http` build only for synthetic fixtures.

For live checks, follow the README isolated-daemon instructions. Never store a
PAT in a shell argument, configuration file, committed fixture or transcript.
Live passkey/browser and live folder tests were not performed; their protocol
coverage is synthetic. Remote logout after interrupted calls is best-effort.

For distribution, follow DISTRIBUTION.md. Source generation must use a clean
committed checkout, and the resulting archive must rebuild offline. The AUR
package must install the WASM, policy, combined signature and notices. Local
packaging validation uses a disposable signing key, never a release key.
