---
sidebar_position: 5
title: Flatpak app secrets
---

# Flatpak app secrets (Secret Portal)

Sandboxed applications can't reach the Secret Service bus directly — they go
through the [XDG Desktop Portal](https://flatpak.github.io/xdg-desktop-portal/).
rosec implements the portal's **Secret** backend
(`org.freedesktop.impl.portal.Secret`), so Flatpak and other confined apps get
their secrets from your rosec providers with no extra setup. `rosec enable`
installs the portal backend automatically.

## How it works

Each confined app has a stable **app ID** (for example
`com.belmoussaoui.Authenticator`). When the app asks the portal for its secret,
rosec:

1. Searches your providers for an item whose `app_id` attribute matches, ranked
   by provider priority (then by whether it carries an `xdg:schema` hint).
2. If one exists, returns its secret. If not, it **generates a random secret,
   stores it** in your first writable provider, and returns that — so the app
   gets the same secret on every launch.

The secret is written straight to the app's file descriptor and never appears on
the bus. If your vault is **locked**, the request fails cleanly (the app sees no
secret) until you unlock.

## Migrating from gnome-keyring or oo7

rosec reads portal secrets that `gnome-keyring-daemon` or `oo7-portal` already
stored: it matches on `app_id` and accepts the secret under either the `secret`
or `password` attribute, so existing Flatpak apps keep working after you switch.

## Inspecting a portal secret

Portal items are ordinary vault items — find one by its `app_id` attribute:

```bash
rosec search app_id=com.belmoussaoui.Authenticator
```
