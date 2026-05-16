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

`rosec search` only returns the dedup winner per group, so a stale copy and
the real one look identical from the cache's perspective. Use `--no-dedup` to
query a provider directly, bypassing the cache:

```bash
# Whatever provider you think holds the original key — try each:
rosec search --no-dedup --provider gnome-keyring application=chrome
rosec search --no-dedup --provider local         application=chrome
```

Each invocation prints the matching item (including its secret bytes) from
that one provider, without any deduplication. If you see different `Secret:`
values across providers for the same `application=chrome`, you have
cross-provider duplication and the cache is hiding one of them.

### Fix — replant the correct value into your writable provider

From the `--no-dedup` output above, copy the `Secret:` field of the provider
whose value your browser was sealed against (typically `gnome-keyring` — the
one that predates rosec on your machine). Then overwrite the stale copy in
your writable provider with `item import --force`:

```bash
cat <<EOF | rosec item import --provider local --force
[item]
label = "Chrome Safe Storage"
type = "generic"

[attributes]
application = "chrome"
"xdg:schema" = "chrome_libsecret_os_crypt_password_v2"

[secrets]
secret = "<paste the Secret value from --no-dedup output>"
EOF
```

`--force` passes `replace=true` to `CreateItemExtended` so the new TOML
overwrites the existing item with matching attributes instead of failing with
"already exists".

Restart your browser. It should accept the keystore on next launch.

> **Alternative:** if you'd rather keep the original copy as the live source,
> set `dedup_strategy = "priority"` and list its provider **first** in
> `[[provider]]` ordering. The dedup layer will then surface it as the winner
> automatically — no copying needed. This affects every cross-provider
> duplicate, not just `application=chrome`, so prefer the targeted import
> above unless you know all the duplicates should flip together.

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
