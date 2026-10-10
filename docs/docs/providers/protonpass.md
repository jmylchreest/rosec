# Proton Pass (experimental spike)

The `protonpass` WASM provider reads a Proton Pass vault directly through Proton's
API using a personal access token (PAT). It does not invoke the Proton CLI at
runtime. It is currently a development spike, not included in release packages
and not ready to install as a normal provider.

## Supported behavior

| Feature | Current behavior |
|---|---|
| Sync | Full sync of direct vault shares and root items. Any failure locks the provider. |
| Login | Username, email and first URL are public; password, notes and primary TOTP are sensitive. |
| TOTP | Primary login TOTP works with `rosec totp get`; extra custom TOTP seeds are readable but not separately indexed. |
| Note | Note contents are sensitive. |
| Card | Number, cardholder, CVV, expiry and PIN are sensitive. Field names currently follow Proton's schema. |
| Identity | All mapped identity values are sensitive, including contact and address details. |
| SSH key | Public and private key attributes can be read. SSH-agent enumeration/signing is not implemented. |
| Wi-Fi | SSID/security type are public; password is sensitive. |
| Alias | The alias email address is public. Alias management and mailbox destinations are not exposed. |
| Custom | Text, hidden, TOTP and timestamp values are sensitive, named `custom.SECTION.FIELD` or `custom.FIELD`. Duplicate names reject the sync. |
| Passkeys | Not exposed. No passkey creation or signing support in this spike. |
| Offline cache / notifications | Not implemented. |
| Write / password change | Intentionally unsupported. Use Proton's applications to edit vault contents. |

Only `Sync` and `Totp` are advertised capabilities. Item types are `login`, `note`,
`card`, `identity`, `ssh-key` or `generic`. Wi-Fi, alias and custom items also have
`proton_type`. The public attributes are visible to Secret Service clients, so
SSIDs, usernames, login URLs and alias addresses are not treated as secrets.

## Authentication and use

A PAT must grant access to the desired vault; viewer permission is sufficient.
The token's encryption-key component stays local to the guest. The provider exchanges
the token portion for an API session and decrypts share keys, item keys and contents.
Account passwords and account TOTP are not needed by the plugin itself.

The official CLI was used to create the eight synthetic items in the development
test. The real rosec CLI then read those items through a separate daemon and WASM
provider. Provisioning through Proton's CLI does not imply rosec supports writing.

For an already configured isolated development instance:

```sh
rosec provider auth proton-demo
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

## Current limits and failure behavior

Folders, group shares, non-vault shares and content formats other than version 7
are rejected. The guest accepts at most 32 shares, 10,000 active items and 32 MiB
of decrypted content per sync. Individual item content is capped at 1 MiB; API
responses are capped at 8 MiB in the guest. Duplicate IDs, malformed responses,
authentication failures and exceeded limits clear the snapshot and lock it.
A network outage therefore requires authentication again; there is no offline fallback.

The local passphrase is only checked for nonemptiness by the guest. Host-wrapped
credential restart/rotation/recovery flows are not yet validated. Additional
production work includes full secret-buffer cleanup, shared runtime advisory
remediation, protected metadata/offline cache, passkeys and SSH-agent support.
The source tree's `rosec-protonpass/SECURITY-REVIEW.md` contains the findings and
synthetic performance measurements. These limitations are not production guarantees.

## Licence

The plugin is GPL-3.0-or-later. The source tree includes Proton provenance,
unchanged schema/generated code, the licence and a pinned dependency lockfile.
Distribution and corresponding-source/notice review is still outstanding.
