// Copyright (c) 2026 Proton AG (adapted PAT parser)
// SPDX-License-Identifier: GPL-3.0-or-later
//! Feasibility spike: Proton's GPL wire schema, PAT key hierarchy and Extism HTTP.
//! Not installed or included in release packaging.
pub mod crypto;
#[cfg(target_family = "wasm")]
mod guest;
#[rustfmt::skip]
pub mod upstream;

use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use zeroize::Zeroizing;

/// Adapted from pass-cli 2.4.2, pass/src/auth/personal_access_token.rs.
/// Errors deliberately never include the supplied credential.
pub fn parse_pat(input: &str) -> Result<(Zeroizing<String>, Zeroizing<Vec<u8>>), &'static str> {
    let (token, encoded) = input.split_once("::").ok_or("Invalid PAT format")?;
    if !token.starts_with("pst_") || token.len() != 68 {
        return Err("Invalid PAT format");
    }
    let key = Zeroizing::new(
        URL_SAFE_NO_PAD
            .decode(encoded)
            .map_err(|_| "Invalid PAT key")?,
    );
    if key.len() != 32 {
        return Err("Invalid PAT key length");
    }
    Ok((Zeroizing::new(token.to_owned()), key))
}
