// Copyright (c) 2026 Proton AG (adapted serialization format)
// SPDX-License-Identifier: GPL-3.0-or-later
//! Read Proton's versioned MessagePack passkey envelope. See UPSTREAM.txt.
use crate::{sensitive::SensitiveJson, upstream::item_v1::Passkey};
use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use p256::pkcs8::{EncodePrivateKey, LineEnding};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use zeroize::Zeroizing;

#[derive(Serialize, Deserialize)]
pub struct Credential {
    pub credential_id: String,
    pub rp_id: String,
    pub rp_name: String,
    pub user_handle: Option<String>,
    pub user_name: String,
    pub user_display_name: String,
    pub algorithm: i64,
    pub pem: Zeroizing<String>,
}

#[derive(Deserialize)]
struct Envelope {
    c: Zeroizing<Vec<u8>>,
    v: u8,
}

fn bytes(v: &Value) -> Result<Zeroizing<Vec<u8>>, &'static str> {
    v.as_array()
        .ok_or("Invalid passkey bytes")?
        .iter()
        .map(|n| {
            n.as_u64()
                .and_then(|n| u8::try_from(n).ok())
                .ok_or("Invalid passkey bytes")
        })
        .collect::<Result<Vec<_>, _>>()
        .map(Zeroizing::new)
}

pub fn decode(p: &Passkey) -> Result<Credential, &'static str> {
    if p.content.len() > 64 * 1024 {
        return Err("Passkey too large");
    }
    let envelope: Envelope =
        rmp_serde::from_slice(&p.content).map_err(|_| "Invalid passkey envelope")?;
    if envelope.v != 1 {
        return Err("Unsupported passkey format");
    }
    let key = SensitiveJson(
        rmp_serde::from_slice::<Value>(&envelope.c).map_err(|_| "Invalid passkey content")?,
    );
    let cid = bytes(&key["cid"])?;
    let rp = key["rid"]
        .as_str()
        .filter(|s| !s.is_empty())
        .ok_or("Missing passkey RP")?;
    if cid.is_empty()
        || cid.len() > 1024
        || (!p.credential_id.is_empty() && *cid != p.credential_id)
        || (!p.rp_id.is_empty() && rp != p.rp_id)
    {
        return Err("Passkey metadata mismatch");
    }
    // Synced credentials use a zero counter: read-only providers cannot persist increments.
    if !key["cnt"].is_null() && key["cnt"].as_u64() != Some(0) {
        return Err("Unsupported passkey counter");
    }
    let params = key["key"]["par"]
        .as_array()
        .ok_or("Missing passkey parameters")?;
    let param = |label: i64| -> Result<&Value, &'static str> {
        let mut values = params
            .iter()
            .filter(|p| p[0] == json!({"t":"int","c":label}));
        let value = values.next().ok_or("Missing passkey parameter")?;
        if values.next().is_some() {
            return Err("Duplicate passkey parameter");
        }
        Ok(&value[1])
    };
    let scalar = param(-4)?;
    if scalar["t"] != "bytes" {
        return Err("Invalid passkey private key");
    }
    let scalar = bytes(&scalar["c"])?;
    let curve = param(-1)?;
    if curve["t"] != "int" {
        return Err("Invalid passkey curve");
    }
    let curve = bytes(&curve["c"]["inner"])?;
    let curve = i128::from_le_bytes(
        curve
            .as_slice()
            .try_into()
            .map_err(|_| "Invalid passkey curve")?,
    );
    let kty = &key["key"]["kty"];
    let alg = &key["key"]["alg"];
    let (algorithm, pem) = if kty == &json!({"t":"assign","c":"EC2"})
        && curve == 1
        && (alg.is_null() || alg == &json!({"t":"assign","c":"ES256"}))
    {
        let secret =
            p256::SecretKey::from_slice(&scalar).map_err(|_| "Invalid passkey private key")?;
        let public = secret.public_key().to_sec1_bytes();
        for (label, expected) in [(-2, &public[1..33]), (-3, &public[33..])] {
            let actual = param(label)?;
            if actual["t"] != "bytes" || bytes(&actual["c"])?.as_slice() != expected {
                return Err("Passkey public key mismatch");
            }
        }
        (
            -7,
            secret
                .to_pkcs8_pem(LineEnding::LF)
                .map_err(|_| "Invalid passkey private key")?,
        )
    } else if kty == &json!({"t":"assign","c":"OKP"})
        && curve == 6
        && (alg.is_null() || alg == &json!({"t":"assign","c":"EdDSA"}))
    {
        let secret = ed25519_dalek::SigningKey::from_bytes(
            scalar
                .as_slice()
                .try_into()
                .map_err(|_| "Invalid passkey private key")?,
        );
        let actual = param(-2)?;
        if actual["t"] != "bytes"
            || bytes(&actual["c"])?.as_slice() != secret.verifying_key().as_bytes()
        {
            return Err("Passkey public key mismatch");
        }
        (
            -8,
            secret
                .to_pkcs8_pem(LineEnding::LF)
                .map_err(|_| "Invalid passkey private key")?,
        )
    } else {
        return Err("Unsupported passkey algorithm");
    };
    let handle = if key["uhd"].is_null() {
        None
    } else {
        Some(URL_SAFE_NO_PAD.encode(bytes(&key["uhd"])?))
    };
    Ok(Credential {
        credential_id: URL_SAFE_NO_PAD.encode(&*cid),
        rp_id: rp.into(),
        rp_name: p.rp_name.to_owned(),
        user_handle: handle,
        user_name: p.user_name.to_owned(),
        user_display_name: p.user_display_name.to_owned(),
        algorithm,
        pem,
    })
}
