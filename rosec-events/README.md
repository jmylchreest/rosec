# Event coordination

`rosec-events` owns response reconciliation, the committed metadata projection,
bounded change history, and revision subscriptions. It depends on `rosec-core`
and Tokio, with no D-Bus, FUSE, WASM host, or Secret Service dependency.

A caller supplies the projection key function. Secret Service uses object paths;
other callers can use provider/item identities. Existing transport readers share
the coordinator's projection rather than maintaining another authoritative map.
All mutations must use the coordinator; the shared projection is for adapter reads.

## Publication

- `note_hint` records a hint for later response reconciliation.
- `commit_refresh` rejects results invalidated by concurrent operations and
  preserves the existing inventory and deduplication policy.
- `confirm_content_changed` records a successful operation's content change,
  including secret-only changes and providers hidden by deduplication. It does
  not assert that a new metadata listing succeeded.
- `set_locked`, `edit`, and `remove_provider` update state and history together.
- `snapshot` and `changes_since` support bounded replay and snapshot recovery.

Events contain identities and change information, never keys or TOTP seeds.
This is an in-process reconciliation mechanism, not a durable audit log.

## Consumers

The daemon's SSH, TOTP and passkey workers use `run_consumer`. Each performs a
full reconciliation from live providers at startup and after a revision wakeup.
Consequently coalesced notifications and journal gaps do not lose required state.
Each worker supervises one attempt at a time, retries failed attempts with bounded
backoff, and cancels its attempt if the worker is dropped.

`ConsumerGate` serializes publication with direct revocation. It rejects old
rebuilds and unregistered provider instances, including replacements using the
same logical ID. Unlock reactivates only the registered instance. Revocation
never waits for provider I/O or event delivery.

SSH caches private keys, TOTP caches seeds, and passkeys cache metadata only.
Passkey registration still waits for its explicit registry refresh; private keys
remain fetched from the provider during ceremonies. Keys or responses already
copied into an operation before revocation cannot be recalled by this mechanism.

Provider traits, callbacks, WASM exports and JSON formats are unchanged. Host
callbacks adapt confirmed operation results into events and retain synchronous
revocation. D-Bus object registration, aliases, sessions and prompts remain in
`rosec-secret-service`.
