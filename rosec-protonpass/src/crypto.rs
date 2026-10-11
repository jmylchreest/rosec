// Copyright (c) 2026 Proton AG
// SPDX-License-Identifier: GPL-3.0-or-later
// Adapted from pass-cli 2.4.2 pass/src/domain/crypto.rs (see UPSTREAM.txt).
// Uses aes-gcm 0.11, fixed AAD slices, checked lengths and zeroizing output.
use aes_gcm::{
    Aes256Gcm, KeyInit, Nonce,
    aead::{Aead, Payload},
};
use zeroize::Zeroizing;

pub const SHARE_KEY: &[u8] = b"sharekey";
pub const ITEM_KEY: &[u8] = b"itemkey";
pub const ITEM_CONTENT: &[u8] = b"itemcontent";

pub fn decrypt(
    ciphertext: &[u8],
    key: &[u8],
    aad: &[u8],
) -> Result<Zeroizing<Vec<u8>>, &'static str> {
    if ciphertext.len() < 28 {
        return Err("Invalid encrypted payload");
    }
    let cipher = Aes256Gcm::new_from_slice(key).map_err(|_| "Invalid key length")?;
    let (nonce, data) = ciphertext.split_at(12);
    let nonce = Nonce::try_from(nonce).map_err(|_| "Invalid nonce length")?;
    cipher
        .decrypt(&nonce, Payload { msg: data, aad })
        .map(Zeroizing::new)
        .map_err(|_| "Payload authentication failed")
}
