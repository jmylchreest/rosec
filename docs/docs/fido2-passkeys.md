---
sidebar_position: 4
title: FIDO2 passkeys
---

# FIDO2 passkeys

rosec can act as a **virtual security key**, so an unmodified browser can sign
in with passkeys held in your vault (WebAuthn / FIDO2). Register a passkey on a
website and it is saved to a rosec provider; sign in later and rosec runs the
ceremony, asking you to confirm each time.

Passkeys stored elsewhere are served too: the local vault, Bitwarden logins
that carry a passkey, and KeePassXC databases all appear as the same
authenticator.

## What you need

The feature is **off by default** and aimed at desktop use. Three pieces
enable it:

1. **The `rosec-uhid` broker** — a small system service (root,
   socket-activated) that creates the virtual device. Install the separate
   `rosec-uhid-bin` package (or build from `contrib/uhid/`); see
   [Installation](installation#fido2).
2. **The `uhid` kernel module** — loaded at boot by the `modules-load.d` file
   the broker package ships (or `sudo modprobe uhid` to load it now).
3. **`fido2 = true`** under `[service]` in your [configuration](configuration),
   after which you restart rosecd.

With those in place and a provider unlocked, a rosec authenticator is present
whenever your session is running. If you have `libfido2` installed you can
confirm it:

```bash
fido2-token -L        # lists a rosec virtual authenticator among your devices
```

## Using it in a browser

- **Register** (`navigator.credentials.create`) — on a site's passkey or
  security-key prompt, choose the **security key** option (Chrome may hide it
  under *"Use a different device"* / *"More choices"*). rosec-prompt asks you
  to confirm, and the new passkey is written to your vault.
- **Sign in** (`navigator.credentials.get`) — pick the passkey the way you
  would any security key; rosec-prompt confirms it before signing.

When more than one of your passkeys matches a site, rosec shows a chooser —
picking an account *is* the confirmation. If you have no passkey for a site,
rosec stays silent, so ordinary logins are unaffected.

## Managing passkeys

Passkeys are ordinary vault items with FIDO2 attributes:

```bash
rosec search rosec:passkey=true    # every passkey, across all providers
rosec search type=passkey          # passkeys stored by rosec itself
rosec item delete <id>             # remove one
```

## Where new passkeys are stored

A browser registration is written to the first provider that can both **write**
and **store passkeys** — today that is the **local vault**. Bitwarden and
KeePassXC passkeys are read-only: rosec serves them for sign-in but never
writes passkeys back to those managers. If no writable passkey store is
available, registration fails cleanly rather than hanging the browser.

## Security

- Passkey private keys never leave their provider except at signing time, and
  are wiped from memory immediately afterwards — nothing is cached in the
  authenticator.
- Every registration and sign-in requires your confirmation through
  rosec-prompt.
- The virtual device node is owned by your user at mode `0600`; other local
  users cannot enumerate or drive it.
- rosec is a **software** authenticator and signs with attestation `"none"` —
  the norm for synced passkeys, and the same posture as every password manager.
  Relying parties that demand hardware-backed attestation (for example
  Microsoft Entra ID) will not accept it, regardless of which manager holds the
  key.
- While your vault is locked the authenticator offers no passkeys, so sign-in
  and registration quietly fail until you unlock.

## How it works

`/dev/uhid` — the kernel facility for creating a virtual HID device — is
root-only, because it could otherwise be used to forge a keyboard. rosec keeps
the privileged part tiny: the `rosec-uhid` broker opens `/dev/uhid`, creates a
device whose descriptor is **hard-coded** to the FIDO usage page (it cannot be
asked to create anything else), hands the device to your rosec daemon, and
exits. From then on every CTAP2 exchange runs unprivileged inside rosecd,
signing with keys your providers hold. Closing the daemon — even a crash —
destroys the device, so a stopped daemon cannot leave a virtual key behind.

## Limitations

- Flatpak- or Snap-confined browsers need device access granted to reach the
  authenticator.
- Attestation-enforcing relying parties reject software authenticators (see
  Security, above).
- It is a per-user, opt-in desktop feature. Each user's device is isolated —
  owned by that user at mode `0600`, keyed to their uid — so concurrent local
  users are safe from one another; there is simply no reason to install the
  broker on a headless server.
