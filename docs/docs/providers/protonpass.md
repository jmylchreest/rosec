# Proton Pass

**Experimental provider.**

The `protonpass` WASM provider reads a Proton Pass vault directly through Proton's
API using a personal access token (PAT). It does not invoke the Proton CLI at
runtime. The plugin is read-only and separately distributed under GPL-3.0-or-later.
Use a matching rosec host version and keep plugin signature verification enabled.

## Supported behavior

| Feature | Current behavior |
|---|---|
| Sync | Full sync of direct vault shares, including nested folders. Any failure locks the provider. |
| Login | Username, email and first URL are public; password, notes and primary TOTP are sensitive. |
| TOTP | Primary and additional custom TOTP fields work with `rosec totp get`; additional fields appear as separate entries. |
| Note | Note contents are sensitive. |
| Card | Number, cardholder, CVV, expiry and PIN are sensitive. Canonical fields include `cardholder`, `number`, `code`, `exp_month`, `exp_year` and `pin`. |
| Identity | All mapped identity values are sensitive, including contact and address details. |
| SSH key | Public/private attributes and SSH-agent enumeration/signing. Signing requires confirmation. |
| Wi-Fi | SSID/security type are public; password is sensitive. |
| Alias | The alias email address is public. Alias management and mailbox destinations are not exposed. |
| Custom | Text, hidden, TOTP and timestamp values are sensitive, named `custom.SECTION.FIELD` or `custom.FIELD`. Duplicate names reject the sync. |
| Passkeys | Existing ES256 and Ed25519 synced credentials can sign through rosec FIDO2. Creation and counter updates are unsupported. |
| Offline cache | Encrypted local snapshot, password and installation bound; maximum age ten days. |
| Notifications | No push subscription; use periodic/manual full sync. |
| Write / password change | Intentionally unsupported. Use Proton's applications to edit vault contents. |

Capabilities are `Sync`, `Totp`, `Ssh`, `Fido2` and `OfflineCache`. Item types are `login`, `note`,
`card`, `identity`, `ssh-key` or `generic`. Wi-Fi, alias and custom items also have
`proton_type`. The public attributes are visible to Secret Service clients, so
SSIDs, usernames, login URLs and alias addresses are not treated as secrets.

## Authentication and use

A PAT must grant access to the desired vault; viewer permission is sufficient.
The token's encryption-key component stays local to the guest. The provider exchanges
the token portion for an API session and decrypts share keys, item keys and contents.
Account passwords and account TOTP are not needed by the plugin itself.

Install the signed `rosec-provider-protonpass` release bundle (WASM, policy and
signature together), or the `rosec-provider-protonpass-bin` AUR package.
The `rosec-git` source package also bundles this provider and its licence notices.
Like the other source-built plugins, it is unsigned and uses the existing
`wasm_verify = "disabled"` development configuration.
Add a provider through `rosec provider add` or configure:

```toml
[[provider]]
id = "proton"
kind = "protonpass"
offline_cache = true
```

### Obtain a personal access token

You can create the token in **Proton Pass web → Settings → Access tokens → New token**.
Choose a name and expiry, select the vaults rosec should read, and leave **Use for
AI agent** off. Copy the complete token when shown: Proton does not show it again.
See [Proton's access-token guide](https://proton.me/support/pass-access-tokens)
for current plan eligibility and the web interface. This provider uses a normal
PAT, not an AI-agent token.

Alternatively, install the official `pass-cli` from
[Proton's installation instructions](https://protonpass.github.io/pass-cli/get-started/installation/).
The following commands were checked against CLI 2.4.2:

```sh
pass-cli login
# Complete the browser login, or use: pass-cli login --interactive
pass-cli vault list
pass-cli personal-access-token create --name rosec --expiration 3m
pass-cli personal-access-token access grant \
  --personal-access-token-name rosec --vault-name "Personal" --role viewer
pass-cli personal-access-token access list-access --personal-access-token-name rosec
```

Replace `Personal` with your vault name; repeat the grant for each vault. If names
are ambiguous, use `--personal-access-token-id PAT_ID --share-id VAULT_SHARE_ID`
instead. These IDs are identifiers, **not the secret token**. New CLI-created
PATs initially have no vault access. Use vault grants; item-only/group shares are
not supported by this provider.

The create command displays `PROTON_PASS_PERSONAL_ACCESS_TOKEN=pst_…::…`.
Copy just the full **`pst_…::…` value**, including both parts, into rosec's secure
prompt. Do not copy the environment-variable name, put the token in TOML, pass it
on a command line, or save it in shell history. Avoid recording the terminal while
creating it. You can log out of `pass-cli` once registration is complete; rosec
operates directly against the API and does not depend on that CLI session.

### Register and unlock

There are three different credentials:

| Credential | Where it is used |
|---|---|
| Proton account password and 2FA | Proton's web/CLI login to create/manage a PAT. Never requested by this plugin. |
| Complete PAT (`pst_…::…`) | Enter once in `rosec provider auth`; stored encrypted locally. Grants access to selected vaults until expiry/revocation. |
| Local unlock passphrase | Choose in rosec's registration prompt; enter for subsequent unlocks. Not stored and not sent to Proton. |

```sh
rosec provider auth proton
rosec sync
rosec search
rosec get ITEM_ID
rosec totp get --stdout ITEM_ID
rosec inspect --all-attrs ITEM_ID
rosec lock
```

`get --attr` reads public attributes. `inspect --all-attrs` also reveals sensitive
fields, so use it only when you intend to display their contents. Configuration,
fixture builds, the HTTP policy and isolated-daemon instructions are in
`rosec-protonpass/README.md` in the source tree. No credentials belong in TOML.

### Replace, renew or revoke a token

For a replacement PAT, repeat the creation/grant steps with a distinct name, run
`rosec provider auth proton`, enter the replacement and your chosen local
passphrase, then verify a sync before deleting the old PAT. Re-registration also
lets you choose a different local passphrase; it does not change your Proton password.

```sh
pass-cli personal-access-token list
pass-cli personal-access-token renew --personal-access-token-name rosec --expiration 3m
# To revoke permanently, use the non-secret ID shown by the list command:
pass-cli personal-access-token delete --personal-access-token-id PAT_ID
pass-cli logout
```

You can also manage or delete tokens in Proton Pass web. Revocation stops future
online access; it cannot erase data already cached on an offline machine. Disable
offline caching and remove the provider/local cache if that is your desired policy.
An empty item list usually means no vault grant; a rejected token may be expired,
revoked, or the wrong token type. A wrong local passphrase leaves the encrypted
registration intact. If the local passphrase or installation key is lost,
re-register with a valid PAT.

## Current limits and failure behavior

Group shares, non-vault shares and content formats other than version 7
are rejected. The guest accepts at most 32 shares, 10,000 active items and 32 MiB
of decrypted content per sync. Individual item content is capped at 1 MiB; API
responses are capped at 8 MiB in the guest. Duplicate IDs, malformed responses,
authentication failures and exceeded limits clear the snapshot and lock it.
If the connectivity probe fails during unlock, rosec can restore the encrypted
snapshot. It contains no PAT or session tokens. Cached data is marked unconfirmed;
remote revocation cannot be checked offline. Unlock again with connectivity to
resume online sync. Setting `offline_cache = false` disables this feature.
Each vault supports at most 1,024 folders; cycles and missing parents are rejected.
Cache snapshots over 24 MiB of serialized data are not saved. Host cache format v2
uses Argon2id; older host caches need an online unlock to regenerate.

Register the PAT once with a separate local passphrase. The host encrypts it using
Argon2id, a random salt and the installation key; later unlocks use the passphrase.
Wrong passwords preserve the saved registration. Re-run `rosec provider auth` to
replace the PAT/passphrase. Restore the installation key alongside encrypted
credentials, or re-register if that key or passphrase is lost.

Access-token expiry permits one refresh attempt. Permission denials do not retry.
Normal lock attempts to revoke this API session and clears local state even if the
network request fails. Cancellation/traps may prevent remote logout; lock does not
revoke the registered PAT. Worker cancellation, timeout and malformed responses
invalidate the guest before later requests can access its state.

The host now uses Extism 1.41.0 / Wasmtime 49.0.2 and requires Rust 1.96 or newer.
Both host and guest cap Proton responses at 8 MiB. Guest execution is capped at
60 seconds, caller waits at 65 seconds, and individual HTTP operations at 10 seconds.
Secret cleanup covers owned guest allocations and rosec transport buffers, but
complete erasure of upstream library and compiler copies is not proven.

Passkeys with unknown encodings, unsupported curves or nonzero stored counters
are rejected rather than silently misused. Canonical identity fields include
`ssn`, `phone`, `address1`, `postal_code`, `state` and `country`; other Proton
fields retain their original names. Public attributes can also be retrieved via
the protected secret lookup interface. Custom field values and notes are never
published as public attributes.

The source tree's `rosec-protonpass/SECURITY-REVIEW.md` records verification and
performance evidence, supported boundaries and remaining deployment checks.

## Licence

The plugin is GPL-3.0-or-later. The source tree includes Proton provenance,
unchanged schema/generated code, the licence and a pinned dependency lockfile.
Release archives include third-party notices and a matching vendored corresponding-source
archive. See `rosec-protonpass/DISTRIBUTION.md` for the distribution record.
