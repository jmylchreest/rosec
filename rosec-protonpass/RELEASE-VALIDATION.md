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

## Final checks in progress

Final workspace tests/Clippy/MSRV, guest checks, production restrictions,
benchmark, docs build, source archive offline rebuild and AUR package validation
will be recorded here before release readiness is declared.

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
