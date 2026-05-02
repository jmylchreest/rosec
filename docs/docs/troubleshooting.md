# Troubleshooting

## Chrome / Vivaldi / Chromium — "Encrypted keystore changed or is now unavailable"

This happens when Chromium-based browsers find their "Chrome Safe Storage"
encryption key has a different value than expected. The most common cause when
running rosec is **cross-provider duplication**: the same item exists in two
providers (e.g. `gnome-keyring` and your `local` vault) with different secret
values, and deduplication picks the wrong copy.

Chromium identifies its key by searching for
`application=chrome xdg:schema=chrome_libsecret_os_crypt_password_v2` (or the
`_v1` variant). Vivaldi, Brave, and other Chromium forks also use
`application=chrome`.

### Diagnose — find the duplicates

Temporarily set `dedup_strategy = "none"` in your config so both copies are
visible:

```toml
# ~/.config/rosec/config.toml
[service]
dedup_strategy = "none"
```

Then search for the duplicate items:

```bash
rosec search application=chrome
```

If two items appear from different providers with the same label but different
`rosec:provider` values, you have cross-provider duplication.

### Fix — keep the correct copy

1. Identify which provider holds the **original** secret (typically the one your
   browser was using before rosec — often `gnome-keyring`).

2. Set `dedup_strategy = "priority"` and list that provider **first** in your
   config so its copy wins:

   ```toml
   [service]
   dedup_strategy = "priority"

   # provider listed first wins dedup
   [[provider]]
   id = "gnome-keyring"
   kind = "gnome-keyring"

   [[provider]]
   id = "local"
   kind = "local"
   # ...remaining providers...
   ```

3. Restart your browser to verify it no longer shows the error.

4. *(Optional)* Migrate the correct secret into your preferred vault and remove
   the stale copy:

   ```bash
   # Export the correct item from gnome-keyring
   rosec item export <item-id> > chrome-key.toml

   # Import into your local vault
   rosec item import --provider=local < chrome-key.toml

   # Delete the stale copy from the local vault (the old wrong one)
   rosec item delete <stale-item-id>
   ```

   After migrating, you can switch back to `dedup_strategy = "newest"` or
   remove the explicit strategy to use the default.

> **Why does this happen?** When rosec replaced `gnome-keyring-daemon` as the
> Secret Service provider, Chromium's `CreateItem` call stored a new encryption
> key in rosec's write target (your local vault). The original key in
> gnome-keyring was still present but had a different value. Depending on which
> copy won deduplication, Chromium could see the wrong key on its next startup.

## Self-signed certificates / Vaultwarden with private CA

By default, rosec uses Mozilla's bundled root certificates for TLS verification.
Self-signed certs or certs signed by a private CA are not in this bundle, so
connections will fail even if your OS trusts the CA.

Set `tls_mode = "system"` on your provider to use the OS trust store instead:

```toml
[[provider]]
id   = "bitwarden"
kind = "bitwarden"
tls_mode = "system"

[provider.options]
email    = "user@example.com"
base_url = "https://vaultwarden.example.com"
```

Make sure your CA certificate is installed in the system trust store (e.g. via
`update-ca-certificates` on Debian/Ubuntu or `trust anchor` on Arch/Fedora).

> **Important:** The certificate presented by the server must be a leaf
> (end-entity) certificate signed by the CA in the trust store. A bare
> self-signed certificate added directly as a trust anchor will be rejected with
> a `CaUsedAsEndEntity` error because TLS libraries treat trust-store entries as
> CA certificates, which are not valid end-entity certificates.
>
> To set this up correctly, create a private CA and use it to sign a server
> certificate:
>
> ```bash
> # 1. Create a CA
> openssl req -x509 -newkey rsa:2048 -keyout ca-key.pem -out ca-cert.pem \
>   -days 365 -nodes -subj "/CN=My Private CA" \
>   -addext "basicConstraints=critical,CA:true" \
>   -addext "keyUsage=critical,keyCertSign,cRLSign"
>
> # 2. Create a server key + CSR
> openssl req -newkey rsa:2048 -keyout server-key.pem -out server.csr \
>   -nodes -subj "/CN=vaultwarden.example.com"
>
> # 3. Sign the server cert with the CA
> openssl x509 -req -in server.csr -CA ca-cert.pem -CAkey ca-key.pem \
>   -CAcreateserial -out server-cert.pem -days 365 \
>   -extfile <(printf 'subjectAltName=DNS:vaultwarden.example.com,IP:127.0.0.1\nbasicConstraints=CA:false\nkeyUsage=digitalSignature,keyEncipherment\nextendedKeyUsage=serverAuth')
> ```
>
> Install `ca-cert.pem` in the system trust store and configure your server with
> `server-cert.pem` and `server-key.pem`.

By default, readiness probes inherit the same TLS mode. You can override this
separately with `tls_mode_probe` (accepts `"bundled"`, `"system"`, or
`"disabled"` to skip TLS verification entirely).
