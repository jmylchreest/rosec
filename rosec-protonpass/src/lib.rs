// Copyright (c) 2026 Proton AG (adapted PAT parser)
// SPDX-License-Identifier: GPL-3.0-or-later
//! Read-only Proton Pass provider: GPL wire schema, PAT key hierarchy and Extism HTTP.
pub mod crypto;
pub mod folders;
#[cfg(target_family = "wasm")]
mod guest;
pub mod mapping;
pub mod passkey;
pub mod sensitive;
#[rustfmt::skip]
pub mod upstream;

use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use zeroize::Zeroizing;

/// pass-cli 2.4.2 pass/src/constants.rs. Pin to the format exercised live.
pub const ITEM_CONTENT_FORMAT_VERSION: u64 = 7;

/// Adapted from pass-cli 2.4.2, pass/src/auth/personal_access_token.rs.
/// Errors deliberately never include the supplied credential.
pub fn parse_pat(input: &str) -> Result<(Zeroizing<String>, Zeroizing<Vec<u8>>), &'static str> {
    if input.len() != 113 {
        return Err("Invalid PAT format");
    }
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

/// Production credentials can only go to Proton. The optional fixture feature
/// admits an exact loopback authority, never userinfo, paths, or redirects.
pub fn valid_api_endpoint(api: &str) -> bool {
    if api == "https://pass-api.proton.me" {
        return true;
    }
    #[cfg(feature = "test-http")]
    if let Some(port) = api.strip_prefix("http://127.0.0.1:") {
        return !port.is_empty()
            && port.bytes().all(|b| b.is_ascii_digit())
            && port.parse::<u16>().is_ok_and(|p| p > 0);
    }
    false
}

// Cover allocations made inside parsers, including partial/unknown fields and
// temporary serialization buffers which never reach our typed cleanup guards.
#[cfg(any(target_arch = "wasm32", test))]
mod wiping_allocator;
#[cfg(target_arch = "wasm32")]
#[global_allocator]
static ALLOCATOR: wiping_allocator::WipingAllocator<std::alloc::System> =
    wiping_allocator::WipingAllocator(std::alloc::System);
