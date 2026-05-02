# KeePassXC (file) provider

**Status: experimental.** The `keepassxc-file` provider opens a `.kdbx` database directly and exposes its entries to rosec. Read-only — rosec never writes back to the file. KeePassXC remains the editor.

The plugin is shipped as a WASM guest, runs sandboxed under wasmtime, and uses the host's `host_file` allow-list to access only the configured kdbx and key file.

## Adding a database

```bash
rosec provider add keepassxc-file path=~/Passwords.kdbx
```

To require a key file as a second factor:

```bash
rosec provider add keepassxc-file path=~/Passwords.kdbx key_file=~/Passwords.keyx
```

`rosec provider auth <id>` prompts for the master password (or skips it if a key file is the sole factor).

## Hot reload on save

When KeePassXC writes the kdbx, the host's inotify watcher (`register_watch`) fires `on_path_changed` in the guest, which invalidates the cached mtime so the next `sync()` re-decrypts with the cached master password. You should not need to run `rosec sync` after a save — but it's harmless if you do.

## TOTP entries

Set up TOTP on a KeePassXC entry the normal way:

1. Open the entry → `Entry` menu → `TOTP` → `Set up TOTP`.
2. Paste a base32 secret or an `otpauth://` URL.
3. Save the kdbx (Ctrl-S).

The plugin reads the TOTP from KeePassXC's standard `otp` field via `entry.get_raw_otp_value()`. No custom field is needed.

After save:

```bash
rosec search rosec:totp=true                    # entry should appear
rosec totp get <entry-name>                     # 6-digit code
ls "$XDG_RUNTIME_DIR/rosec/totp/by-name/"       # FUSE view (if totp_fuse=true)
```

The plugin auto-stamps `rosec:totp=true` on every entry that has a TOTP seed; this is what `rosec totp` and the TOTP FUSE filesystem use to discover the entry.

## SSH keys

KeePassXC's built-in SSH agent stores keys as a binary attachment plus a `KeeAgent.settings` attachment carrying XML config. The plugin parses both and exposes the key to rosec's SSH agent and SSH FUSE.

> **Only Attachment mode is supported.** KeePassXC's *External file* mode (where the private key lives at a host filesystem path outside the kdbx) is **not** supported by rosec — the kdbx wouldn't be self-contained, and the rosec sandbox would need every external path explicitly allow-listed. Use Attachment mode; the steps below show how.

### Setup in KeePassXC

1. `Tools` → `Settings` → `SSH Agent` → tick *Enable SSH Agent integration*. (The SSH Agent tab on the entry editor only appears once this is on. *KeePassXC's own* agent doesn't need to be enabled — rosec is the agent — but this checkbox also unlocks the per-entry SSH Agent tab, which we need.)
2. Generate or pick an existing OpenSSH private key file:
   ```bash
   ssh-keygen -t ed25519 -f ~/.ssh/rosec_test -C "rosec-test" -N ""
   # passphrase variant:
   # ssh-keygen -t ed25519 -f ~/.ssh/rosec_test -C "rosec-test" -N "secret"
   ```
3. Create a new entry. Username can be anything you like. If the key has a passphrase, put the passphrase in the entry's *Password* field — the plugin uses it to decrypt the key on demand.
4. **Switch to the *Advanced* tab and add the key as an attachment first.** This is the non-obvious step: KeePassXC's SSH Agent tab can only *select* attachments, not add them.
   - In the *Advanced* tab, find the *Attachments* section.
   - Click *Add* and pick `~/.ssh/rosec_test`. KeePassXC embeds the file as a binary inside the kdbx.
   - The on-disk file is now redundant — you can delete it after saving if you want.
5. **Switch back to the *SSH Agent* tab.**
   - Under *Private key*, click the *Attachment* radio button.
   - Pick the attachment you just added from the dropdown.
   - The other checkboxes on this tab (*Add key to agent…*, *Remove key from agent…*, *Require user confirmation*) control KeePassXC's own SSH agent behaviour and are ignored by rosec — leave them as you like.
6. Ctrl-S to save.

After save (~5 s for the inotify watcher to fire and re-decrypt):

```bash
rosec inspect <id>                                # rosec:type=ssh-key, Secret has the PEM
ssh-add -l                                        # key listed via the rosec agent
ls "$XDG_RUNTIME_DIR/rosec/ssh/keys/by-name/"     # public keys via FUSE
```

### Restricting where a key is offered

By default the SSH FUSE doesn't generate `~/.ssh/config` snippets unless the key has at least one host pattern. Add custom string fields on the entry to control this:

| Field name (either accepted) | Type        | Meaning |
|------------------------------|-------------|---------|
| `ssh_host` *or* `ssh-host`   | string      | Glob/host pattern (e.g. `github.com`, `*.internal.example`). Multi-line: one pattern per line — each becomes a `Host` block in the generated config. |
| `ssh_user` *or* `ssh-user`   | string      | SSH login user. Falls back to the entry's *Username* field if absent. |
| `ssh_confirm` *or* `ssh-confirm` | "true"/"false" | Force `IdentitiesOnly`-style confirm-before-sign behaviour even if KeePassXC's own *Require user confirmation* flag isn't set. |

Add them via the *Advanced* tab on the entry editor → *Additional attributes*. Plain string (not protected) is fine for these — only the key material itself is sensitive.

Worked example:

| Field    | Value             |
|----------|-------------------|
| Title    | github            |
| Username | git               |
| Password | *(empty unless your key has a passphrase)* |
| `ssh_host` | `github.com`<br>`gist.github.com` |
| `ssh_user` | `git` *(optional — Username already covers this)* |

After save, rosec will write a config snippet at `$XDG_RUNTIME_DIR/rosec/ssh/config.d/<provider>-<item>.conf` with `Host github.com gist.github.com` blocks pointing at the rosec agent socket.

### Encrypted (passphrase-protected) keys

If the OpenSSH file in the attachment is passphrase-protected, the plugin tries to decrypt it with the entry's *Password* field. If that succeeds the unencrypted PEM is handed to the host SSH agent — your `ssh` clients never see the passphrase. If the password doesn't match, the entry is silently skipped (look for `kdbx open failed` or `ssh rebuild` lines in `journalctl --user -fu rosecd` for diagnostics).

## Troubleshooting

| Symptom | Likely cause |
|---------|--------------|
| `rosec search rosec:totp=true` returns nothing for a kdbx entry | TOTP wasn't saved to the standard `otp` field — re-run *Set up TOTP* from the *Entry → TOTP* menu rather than adding a custom field by hand. |
| Entry visible to `rosec search` but no SSH key in `$XDG_RUNTIME_DIR/rosec/ssh/` | Either the SSH key isn't an *Attachment* (rosec doesn't support External file mode), or the attachment is missing/named differently. Re-check the SSH Agent tab on the entry: the *Attachment* radio must be selected and the dropdown must point at the embedded key. |
| `ssh-add -l` shows fewer keys than expected | Encrypted key with a passphrase that doesn't match the entry's *Password* field — the plugin can't decrypt. Either set the matching passphrase in the entry, or replace the attachment with an unencrypted key file. |
| `kdbx open failed: PreviousParentGroup` | You're on an old build — rebuild against `keepass-rs` ≥ the version with [PR #319](https://github.com/sseemayer/keepass-rs/pull/319) merged (the local fork already carries this fix). |
| Changes in KeePassXC not visible until `rosec sync` is run | The `host_watch` (inotify) hook didn't register at unlock. Check `journalctl --user -fu rosecd \| grep host_watch` for an error — usually a path that didn't canonicalise the same way (e.g. tilde not expanded). |
