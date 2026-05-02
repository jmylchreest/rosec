# Tech Debt

Tracked issues that are known but deferred.

## `rosec unlock` does not re-prompt on wrong password

**Location:** `rosec-secret-service/src/unlock.rs` — `unlock_with_tty()`, line ~176

When the opportunistic sweep tries a single password against all locked
providers and one fails with `auth_failed`, that provider is skipped
entirely. The comment says "re-prompting individually won't help since
we'd use the same password" — but that's only true within the same sweep.
The user may have a different master password for that provider.

**Current behaviour:** Provider is added to `results` as a failure and
the user sees "wrong password (skipped)". No second chance is offered.

**Expected behaviour:** After the sweep completes, providers that failed
with `auth_failed` should be moved into `need_individual` (or a new
`need_retry` list) so the user is prompted with a provider-specific
password prompt. This matches how `need_registration` and `need_2fa`
providers already get a second pass.

**Workaround:** Run `rosec provider auth <id>` to unlock individually.
