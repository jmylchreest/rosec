# Design: WebAuthn Passkey Support

## Overview

Add passkey (WebAuthn/FIDO2) support to rosec, allowing users to create,
store, and authenticate with passkeys directly from their rosec vault.
Rosec acts as a **software platform authenticator** — the same role that
iCloud Keychain, Windows Hello, or 1Password play on their respective
platforms.

Linux currently has **no native platform authenticator** and no standard
D-Bus or XDG portal for credential management. Browsers on Linux handle
WebAuthn as follows:

| Browser   | Platform authenticator?                | Passkey storage            |
|-----------|----------------------------------------|----------------------------|
| Chrome    | GPM cloud enclave only (PIN-verified)  | Google Password Manager    |
| Firefox   | None — rejects `attachment:"platform"` | USB security keys only     |
| Brave     | None (strips Google integrations)      | USB keys + extensions only |
| Chromium  | Same as Chrome                         | Same as Chrome             |

Every password manager that provides passkeys on Linux today (1Password,
Bitwarden, KeePassXC) uses the same architecture: a **browser extension**
that monkey-patches `navigator.credentials` plus a **native messaging host**
that communicates with the credential store. There is no shortcut — this is
the only proven approach.

The `credentialsd` project (`xyz.iinuwa.credentialsd`) proposes a D-Bus
portal specification, but as of April 2026 it has zero integration in any
shipping browser (confirmed by source-code audit of Chromium and Firefox).
Our design does not depend on it, but remains compatible if it matures.

## Goals

- Store passkey private keys in the rosec vault (encrypted, multi-password
  key-wrapped, syncable)
- Register new passkeys on websites via browser extension
- Authenticate with stored passkeys via browser extension
- Support Chrome, Firefox, Brave, and all Chromium-based browsers
- Expose passkey management via CLI (`rosec passkey list/delete`)
- Use 1Password's open-source `passkey-rs` crate for CTAP2/WebAuthn
  protocol logic rather than reimplementing the spec

## Non-goals (initial scope)

- TPM-backed key storage (future enhancement — see appendix)
- Hardware authenticator passthrough (USB/NFC security keys already work
  natively in browsers)
- Conditional mediation / autofill-assisted passkey UI (fragile to fake,
  KeePassXC explicitly disables this)
- Attestation formats beyond `"none"` (inappropriate for software
  authenticators; sites requiring hardware attestation won't accept these)
- Ed25519 or RSA key types (passkey-rs only supports ES256/P-256, which
  covers ~99% of real-world passkeys)

## Architecture

```
+------------------------------------------------------------------+
| Browser (Chrome / Firefox / Brave)                               |
|                                                                  |
|  +-------------------+  window.postMessage  +------------------+ |
|  | Page JS world     |<------------------->| Content script   | |
|  |                   |                      | (isolated world) | |
|  | webauthn-shim.js  |                      +--------+---------+ |
|  | - overrides        |                              |           |
|  |   navigator.       |                 runtime.sendMessage      |
|  |   credentials      |                              |           |
|  | - constructs       |                      +-------v---------+ |
|  |   response objects |                      | Background      | |
|  +-------------------+                      | script          | |
|                                              +-------+---------+ |
+----------------------------------------------+-------+----------+
                                               |
                              runtime.connectNative("com.rosec.host")
                            stdin/stdout (4-byte LE length + JSON)
                                               |
                                    +----------v-----------+
                                    | rosec-native-host    |
                                    | (spawned by browser) |
                                    +----------+-----------+
                                               |
                                          D-Bus (org.rosec.Passkey)
                                               |
                                    +----------v-----------+
                                    | rosecd                |
                                    |  +- rosec-webauthn   |
                                    |  |  (passkey-rs)     |
                                    |  +- vault storage    |
                                    +-----------------------+
```

### Component breakdown

| Component            | Language | Purpose                                         |
|----------------------|----------|-------------------------------------------------|
| `rosec-webauthn`     | Rust     | Core passkey logic: credential store, authenticator, D-Bus interface |
| `rosec-native-host`  | Rust     | Native messaging bridge: browser stdin/stdout to rosecd D-Bus |
| `rosec-extension`    | JS       | WebExtension: intercepts WebAuthn API, manages native messaging port |

## Component 1: Browser Extension (`rosec-extension`)

### Script execution contexts

The extension requires three scripts running in different browser contexts:

**`webauthn-shim.js`** — Injected into the page's **MAIN world** (the only
context where `navigator.credentials` can be overridden):

- Saves references to original `navigator.credentials.create()` and `.get()`
- Replaces them with functions that serialize the `PublicKeyCredentialCreationOptions`
  / `PublicKeyCredentialRequestOptions` (converting `ArrayBuffer` fields to
  base64url strings) and post a message to the content script
- On receiving a response, constructs proper `PublicKeyCredential` objects
  with correct prototypes (`AuthenticatorAttestationResponse.prototype` /
  `AuthenticatorAssertionResponse.prototype`) and real `ArrayBuffer` fields
  that pass `instanceof` checks
- Overrides `PublicKeyCredential.isUserVerifyingPlatformAuthenticatorAvailable()`
  to return `true`
- On failure or user dismissal, falls through to the browser's native
  WebAuthn handler (hardware security keys still work)

**`content-script.js`** — Runs in the **isolated content script world**.
Bridges between the page shim (via `window.postMessage` / `CustomEvent`)
and the background script (via `chrome.runtime.sendMessage`). Handles
Firefox's `cloneInto()` requirement for cross-world object passing.

**`background.js`** — Service worker / background script. Maintains a
persistent native messaging port via `runtime.connectNative("com.rosec.host")`.
Routes `passkeys_register` and `passkeys_get` messages from content scripts
to the native host and returns responses.

### Manifest

```json
{
  "manifest_version": 3,
  "name": "Rosec Passkeys",
  "permissions": ["nativeMessaging"],
  "host_permissions": ["<all_urls>"],
  "content_scripts": [
    {
      "matches": ["<all_urls>"],
      "js": ["webauthn-shim.js"],
      "run_at": "document_start",
      "world": "MAIN"
    },
    {
      "matches": ["<all_urls>"],
      "js": ["content-script.js"],
      "run_at": "document_start"
    }
  ],
  "background": {
    "service_worker": "background.js"
  },
  "web_accessible_resources": [
    {
      "resources": ["webauthn-shim.js"],
      "matches": ["<all_urls>"]
    }
  ]
}
```

Key requirements:
- `run_at: "document_start"` — override must happen before any page JS runs
- `"world": "MAIN"` — Manifest V3 way to run in page context (Chrome 111+).
  Firefox fallback: content script injects a `<script>` tag from extension URL
- `nativeMessaging` permission for native host communication

### Wire format (extension to native host)

Registration request:
```json
{
  "type": "passkeys_register",
  "origin": "https://example.com",
  "publicKey": {
    "rp": { "id": "example.com", "name": "Example" },
    "user": { "id": "<base64url>", "name": "user@example.com", "displayName": "User" },
    "challenge": "<base64url>",
    "pubKeyCredParams": [{ "type": "public-key", "alg": -7 }],
    "authenticatorSelection": {
      "authenticatorAttachment": "platform",
      "residentKey": "required",
      "userVerification": "required"
    },
    "attestation": "none",
    "excludeCredentials": [],
    "timeout": 60000
  }
}
```

Authentication request:
```json
{
  "type": "passkeys_get",
  "origin": "https://example.com",
  "publicKey": {
    "rpId": "example.com",
    "challenge": "<base64url>",
    "allowCredentials": [
      { "type": "public-key", "id": "<base64url>" }
    ],
    "userVerification": "required",
    "timeout": 60000
  }
}
```

Success response (registration):
```json
{
  "type": "passkeys_register_response",
  "credential": {
    "id": "<base64url credential_id>",
    "rawId": "<base64url>",
    "type": "public-key",
    "authenticatorAttachment": "platform",
    "response": {
      "clientDataJSON": "<base64url>",
      "attestationObject": "<base64url>",
      "transports": ["internal"],
      "publicKey": "<base64url>",
      "publicKeyAlgorithm": -7,
      "authenticatorData": "<base64url>"
    }
  }
}
```

Success response (authentication):
```json
{
  "type": "passkeys_get_response",
  "credential": {
    "id": "<base64url credential_id>",
    "rawId": "<base64url>",
    "type": "public-key",
    "authenticatorAttachment": "platform",
    "response": {
      "clientDataJSON": "<base64url>",
      "authenticatorData": "<base64url>",
      "signature": "<base64url>",
      "userHandle": "<base64url>"
    }
  }
}
```

Error response:
```json
{
  "type": "error",
  "code": "NotAllowedError",
  "message": "User cancelled the operation"
}
```

All binary fields use **base64url encoding without padding**, matching the
W3C WebAuthn spec's JSON serialization.

## Component 2: Native Messaging Host (`rosec-native-host`)

### Protocol

Chrome and Firefox use an identical native messaging protocol:
**4-byte little-endian uint32 length prefix + JSON payload**, over
stdin/stdout. One binary serves both browsers — only the manifest files
differ.

```rust
fn read_message(stdin: &mut impl Read) -> io::Result<serde_json::Value> {
    let mut len_buf = [0u8; 4];
    stdin.read_exact(&mut len_buf)?;
    let len = u32::from_le_bytes(len_buf) as usize;
    let mut msg_buf = vec![0u8; len];
    stdin.read_exact(&mut msg_buf)?;
    Ok(serde_json::from_slice(&msg_buf)?)
}

fn write_message(stdout: &mut impl Write, msg: &serde_json::Value) -> io::Result<()> {
    let json = serde_json::to_vec(msg)?;
    stdout.write_all(&(json.len() as u32).to_le_bytes())?;
    stdout.write_all(&json)?;
    stdout.flush()
}
```

Message size limit: 1 MB in both directions (Chrome enforced; Firefox
unlimited from host but 1 MB to host). Passkey messages are well under this.

### Manifest files

Chrome (`~/.config/google-chrome/NativeMessagingHosts/com.rosec.host.json`):
```json
{
  "name": "com.rosec.host",
  "description": "Rosec Password Manager - WebAuthn Bridge",
  "path": "/usr/bin/rosec-native-host",
  "type": "stdio",
  "allowed_origins": ["chrome-extension://<extension-id>/"]
}
```

Firefox (`~/.mozilla/native-messaging-hosts/com.rosec.host.json`):
```json
{
  "name": "com.rosec.host",
  "description": "Rosec Password Manager - WebAuthn Bridge",
  "path": "/usr/bin/rosec-native-host",
  "type": "stdio",
  "allowed_extensions": ["rosec@rosec.dev"]
}
```

Additional manifest locations for Chromium, Brave, etc. are installed during
`rosec setup` or via distro packaging.

### Architecture decision: proxy to daemon

The browser spawns and kills native host processes with the connection
lifecycle. We do **not** want rosecd's lifecycle tied to browser tabs.
The native host is a thin proxy that connects to the running rosecd over
D-Bus (which rosec already uses for Secret Service). This mirrors
KeePassXC's architecture (`keepassxc-proxy` -> Unix socket -> `keepassxc`).

### Crate layout

```
rosec-native-host/
  Cargo.toml       # deps: zbus, serde_json, tokio
  src/
    main.rs        # stdin/stdout message loop, D-Bus client
    protocol.rs    # read_message / write_message helpers
```

## Component 3: Core Passkey Logic (`rosec-webauthn`)

### passkey-rs integration

Rather than reimplementing ~3,000 lines of CTAP2/WebAuthn spec handling
(AuthenticatorData binary format, COSE key encoding, CBOR attestation
objects, clientDataJSON construction, origin validation, signature
computation), we use 1Password's open-source
[passkey-rs](https://github.com/1Password/passkey-rs) crate (MIT/Apache-2.0).

passkey-rs provides:
- `passkey-types` — WebAuthn Level 3 + CTAP 2.0 type definitions
- `passkey-authenticator` — Software CTAP2 authenticator with
  `CredentialStore` and `UserValidationMethod` extension traits
- `passkey-client` — WebAuthn client (origin validation, clientDataJSON,
  marshaling between RP and authenticator formats)

Rosec implements two traits to plug in:

### CredentialStore — vault-backed passkey storage

```rust
struct VaultCredentialStore {
    state: Arc<ServiceState>,
}

#[async_trait]
impl CredentialStore for VaultCredentialStore {
    type PasskeyItem = VaultPasskey;

    async fn find_credentials(
        &self,
        ids: Option<&[PublicKeyCredentialDescriptor]>,
        rp_id: &str,
        user_handle: Option<&[u8]>,
    ) -> Result<Vec<VaultPasskey>, StatusCode> {
        // Search vault: rosec:type = "passkey", rosec:passkey:rp_id = rp_id
        // Filter by credential_id if ids provided
        // Filter by user_handle if provided
    }

    async fn save_credential(
        &mut self,
        cred: Passkey,
        user: PublicKeyCredentialUserEntity,
        rp: PublicKeyCredentialRpEntity,
        options: Options,
    ) -> Result<(), StatusCode> {
        // Create vault item with ItemType::Passkey
        // Public attrs: rp_id, user_handle, credential_id, user_name, discoverable
        // Secret attrs: {"private_key_cbor": COSE key CBOR bytes}
    }

    async fn update_credential(&mut self, cred: &VaultPasskey) -> Result<(), StatusCode> {
        // Increment sign_count in vault item
    }

    async fn get_info(&self) -> StoreInfo {
        StoreInfo { discoverability: DiscoverabilitySupport::Full }
    }
}
```

### UserValidationMethod — rosec-prompt integration

```rust
struct RosecUserValidation {
    prompt_config: PromptConfig,
}

#[async_trait]
impl UserValidationMethod for RosecUserValidation {
    type PasskeyItem = VaultPasskey;

    async fn check_user<'a>(
        &self,
        hint: UiHint<'a, VaultPasskey>,
        presence: bool,
        verification: bool,
    ) -> Result<UserCheck, Ctap2Error> {
        // Launch rosec-prompt showing:
        //   Registration: "{rp_name} wants to create a passkey for {user_name}"
        //   Authentication: "Sign in to {rp_name} as {user_name}"
        //   Multiple matches: credential picker
        // If vault locked, prompt unlock first
        // Return UserCheck { presence: true, verification: true } on confirm
        // Return Ctap2Error::OperationDenied on cancel
    }
}
```

### Authenticator assembly

```rust
const ROSEC_AAGUID: Aaguid = Aaguid::new_128bit(/* unique UUID for rosec */);

let store = VaultCredentialStore::new(state.clone());
let uv = RosecUserValidation::new(prompt_config);
let authenticator = Authenticator::new(ROSEC_AAGUID, store, uv);
let client = Client::new(authenticator);

// Registration
let credential = client.register(origin, creation_options, None).await?;

// Authentication
let assertion = client.authenticate(origin, request_options, None).await?;
```

### Crate layout

```
rosec-webauthn/
  Cargo.toml       # deps: passkey, coset, ciborium, p256, sha2, zbus
  src/
    lib.rs         # Public API: RosecAuthenticator
    store.rs       # VaultCredentialStore (impl CredentialStore)
    validation.rs  # RosecUserValidation (impl UserValidationMethod)
    types.rs       # VaultPasskey, ROSEC_AAGUID, attribute constants
    dbus.rs        # org.rosec.Passkey D-Bus interface
```

### Key dependencies

| Crate        | Purpose                                               |
|--------------|-------------------------------------------------------|
| `passkey`    | Umbrella: authenticator + client + types              |
| `p256`       | ES256 key generation and signing (via passkey-rs)     |
| `coset`      | COSE key representation                               |
| `ciborium`   | CBOR serialization                                    |
| `sha2`       | SHA-256 for RP ID hash                                |
| `zbus`       | D-Bus interface for native host communication         |
| `base64url`  | Binary field encoding for wire format                 |

## Vault Storage

Passkeys are stored as regular vault items, benefiting from existing
encryption, multi-password key wrapping, offline cache, and sync:

```
ItemType: Passkey
Label: "example.com - user@example.com"

Public Attributes:
  rosec:type                    = "passkey"
  rosec:passkey:rp_id           = "example.com"
  rosec:passkey:credential_id   = "<base64url>"
  rosec:passkey:user_handle     = "<base64url>"
  rosec:passkey:user_name       = "user@example.com"
  rosec:passkey:user_display    = "User"
  rosec:passkey:discoverable    = "true"
  rosec:passkey:sign_count      = "0"
  rosec:passkey:created_at      = "<ISO 8601>"

Secret Attributes:
  private_key_cbor = <COSE_Key CBOR bytes (ES256/P-256 private key)>
```

### New rosec-core additions

```rust
// Capability
pub enum Capability {
    // ... existing ...
    Passkey,       // Can store WebAuthn credentials
    PasskeySign,   // Can sign assertions (key never leaves daemon)
}

// ItemType
pub enum ItemType {
    // ... existing ...
    Passkey,       // Default secret attr: "private_key_cbor"
}

// Reserved attributes
pub const ATTR_PASSKEY_RP_ID: &str = "rosec:passkey:rp_id";
pub const ATTR_PASSKEY_CREDENTIAL_ID: &str = "rosec:passkey:credential_id";
pub const ATTR_PASSKEY_USER_HANDLE: &str = "rosec:passkey:user_handle";
pub const ATTR_PASSKEY_USER_NAME: &str = "rosec:passkey:user_name";
pub const ATTR_PASSKEY_USER_DISPLAY: &str = "rosec:passkey:user_display";
pub const ATTR_PASSKEY_DISCOVERABLE: &str = "rosec:passkey:discoverable";
pub const ATTR_PASSKEY_SIGN_COUNT: &str = "rosec:passkey:sign_count";
```

## D-Bus Interface

New interface on rosecd, consumed by the native messaging host:

```xml
<interface name="org.rosec.Passkey">
  <!-- Registration: create a new passkey -->
  <method name="MakeCredential">
    <arg name="request_json" type="s" direction="in"/>
    <arg name="origin" type="s" direction="in"/>
    <arg name="response_json" type="s" direction="out"/>
  </method>

  <!-- Authentication: sign an assertion -->
  <method name="GetAssertion">
    <arg name="request_json" type="s" direction="in"/>
    <arg name="origin" type="s" direction="in"/>
    <arg name="response_json" type="s" direction="out"/>
  </method>

  <!-- Management -->
  <method name="ListPasskeys">
    <arg name="rp_id" type="s" direction="in"/>
    <arg name="passkeys_json" type="s" direction="out"/>
  </method>

  <method name="DeletePasskey">
    <arg name="credential_id" type="s" direction="in"/>
    <arg name="success" type="b" direction="out"/>
  </method>
</interface>
```

Path: `/org/rosec/Passkey`

The JSON wire format uses base64url-encoded binary fields, matching the W3C
WebAuthn JSON serialization. This format is also compatible with the
credentialsd wire format, making future D-Bus portal adaptation
straightforward.

## CLI

```
rosec passkey list [--rp <rp_id>]       # List stored passkeys
rosec passkey delete <credential_id>    # Remove a passkey
rosec passkey info <credential_id>      # Show passkey details
```

## User Flows

### Registration

```
1. User clicks "Register with passkey" on example.com
2. Website calls navigator.credentials.create(options)
3. webauthn-shim.js intercepts, serializes options to base64url JSON
4. Message posted to content script -> background script -> native host
5. Native host calls rosecd D-Bus: MakeCredential(request, origin)
6. rosecd checks vault is unlocked (prompts unlock if needed)
7. rosec-prompt shows: "example.com wants to create a passkey for user@example.com"
   [Create] [Cancel]
8. User confirms -> passkey-rs generates ES256 keypair
9. Private key stored in vault, attestation response returned
10. Response flows back: D-Bus -> native host -> background -> content -> shim
11. Shim constructs PublicKeyCredential object, returns to website
12. Website sends attestation to server -> registration complete
```

### Authentication

```
1. User clicks "Sign in with passkey" on example.com
2. Website calls navigator.credentials.get(options)
3. webauthn-shim.js intercepts, serializes to base64url JSON
4. Message flows to native host -> rosecd D-Bus: GetAssertion(request, origin)
5. rosecd searches vault: rosec:passkey:rp_id = "example.com"
6. If multiple matches -> rosec-prompt shows credential picker
7. If single match -> rosec-prompt shows: "Sign in to example.com as user@example.com"
   [Sign in] [Cancel]
8. User confirms -> passkey-rs signs challenge with stored private key
9. sign_count incremented and saved to vault
10. Assertion response returned through the full chain
11. Website sends assertion to server -> authenticated
```

## Implementation Plan

### Phase 1: Core crate + vault storage
- Add `Passkey` capability and `ItemType` to rosec-core
- Create `rosec-webauthn` crate
- Implement `VaultCredentialStore` (passkey-rs `CredentialStore` trait)
- Implement `RosecUserValidation` (passkey-rs `UserValidationMethod` trait)
- Unit tests with passkey-rs test utilities

### Phase 2: D-Bus interface + native host
- Add `org.rosec.Passkey` D-Bus interface to rosecd
- Create `rosec-native-host` crate (native messaging binary)
- Integration tests: native host -> D-Bus -> vault round-trip

### Phase 3: Browser extension
- Implement `webauthn-shim.js` (MAIN world override)
- Implement `content-script.js` (bridge)
- Implement `background.js` (native messaging port management)
- Test with Chrome, Firefox, Brave
- Handle edge cases: iframe origins, cross-origin, fallback to native

### Phase 4: CLI + polish
- `rosec passkey` subcommands
- Native messaging host manifest installation (`rosec setup`)
- Documentation

### Phase 5 (future): Enhancements
- TPM-backed key storage (see appendix)
- credentialsd `Credentials1` D-Bus interface adapter
- Conditional mediation support
- FUSE exposure of passkey metadata

## Appendix: TPM-Backed Passkeys (Future)

For TPM-backed passkeys, the private key never leaves the TPM:

```rust
pub enum PasskeyKeyStorage {
    /// Private key stored in vault (software, portable)
    Vault,
    /// Private key generated and held in TPM 2.0 (hardware-bound)
    Tpm { persistent_handle: u32 },
}
```

This would use the `tss-esapi` crate (Rust bindings to TPM2 TSS). The TPM
generates the ES256 key, rosec stores the TPM handle + metadata in the
vault, and signing operations are dispatched through the TPM. This provides
hardware-bound credentials at the cost of portability (key is bound to the
machine's TPM and cannot be synced).

Implementation requires:
- Detecting TPM 2.0 availability
- Managing TPM persistent object handles
- Handling TPM authorization (owner hierarchy)
- User choice at registration time: vault (portable) vs TPM (hardware-bound)

## Appendix: credentialsd Compatibility (Future)

If the `xyz.iinuwa.credentialsd.Credentials1` D-Bus interface gains browser
adoption, rosec can expose it as an additional transport with minimal effort:

```rust
// Thin adapter: Credentials1 D-Bus -> rosec-webauthn -> vault
#[interface(name = "xyz.iinuwa.credentialsd.Credentials1")]
impl CredentialsdAdapter {
    async fn create_credential(&self, parent_window: &str, options: HashMap<String, Value>)
        -> Result<HashMap<String, Value>> {
        // Deserialize WebAuthn JSON from options
        // Delegate to RosecAuthenticator::make_credential()
        // Serialize response back to D-Bus format
    }

    async fn get_credential(&self, parent_window: &str, options: HashMap<String, Value>)
        -> Result<HashMap<String, Value>> {
        // Same pattern for authentication
    }
}
```

This can run alongside the native messaging approach, giving users both
paths. The core `rosec-webauthn` logic is transport-agnostic.
