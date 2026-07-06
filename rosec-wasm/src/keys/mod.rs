//! Embedded public keys for verifying WASM provider plugin signatures.
//!
//! The corresponding private key is stored as the `WASM_SIGNING_KEY` GitHub
//! Actions secret and is used by the release workflow to sign every released
//! `.wasm` bundle with `rosec-package-wasm` (minisign/ed25519).
//!
//! # Key rotation
//!
//! [`WASM_SIGNING_PUBKEYS`] is a *set* so rotation can run a deprecation
//! window instead of a flag-day: releases during the window trust both the
//! outgoing and incoming key, so previously-downloaded plugins keep loading
//! while newly-signed ones verify too.
//!
//! 1. Generate a new keypair: `rosec-package-wasm keygen --no-password`
//!    (equivalent to `rsign generate -W`).
//! 2. Append the new public key to [`WASM_SIGNING_PUBKEYS`] and update
//!    [`WASM_SIGNING_PUBKEY`] (the primary) plus the sibling `.pub` file.
//! 3. Update the `WASM_SIGNING_KEY` GitHub Actions secret; the release
//!    workflow's post-sign `rosec-package-wasm verify` gate fails the build
//!    if the secret and this file ever disagree.
//! 4. Re-sign published provider artifacts:
//!    `rosec-package-wasm sign --key new.key dist/providers/`.
//! 5. After the deprecation window (a few releases), remove the old key
//!    from [`WASM_SIGNING_PUBKEYS`].

/// The primary minisign public key: the one the current release workflow
/// signs with. This is the base64-encoded key string (the second line of
/// the `.pub` file).
pub const WASM_SIGNING_PUBKEY: &str = "RWTn6nvrCuaMdWkYb2aZOTsyKh1XW36iFZZGNw3kiGvJza33mB7mqXPD";

/// Every release key this build trusts, newest first. Exactly one entry
/// outside a rotation window; old + new during one. Signature verification
/// tries each in order (minisign key IDs make a wrong key a cheap, explicit
/// mismatch).
///
/// There is deliberately no runtime expiry: removing an entry here in a
/// release *is* the expiry mechanism — instant per-release and independent
/// of the user's clock. Instead, annotate every entry with its history so
/// the deprecation window is enforced by the release checklist:
///
/// ```text
/// KEY,                // added v0.0.x (primary) — remove by v0.0.y
/// ```
pub const WASM_SIGNING_PUBKEYS: &[&str] = &[
    WASM_SIGNING_PUBKEY, // added pre-v0.0.32 (primary)
];
