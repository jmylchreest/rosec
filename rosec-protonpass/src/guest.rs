// Copyright (c) 2026 Proton AG (adapted protocol handling)
// SPDX-License-Identifier: GPL-3.0-or-later
// REST envelope and PAT flow adapted from Proton pass-cli 2.4.2; see UPSTREAM.md.
use crate::{crypto, parse_pat, upstream::item_v1};
use base64::{Engine, engine::general_purpose::STANDARD};
use extism_pdk::*;
use protobuf::Message;
use serde_json::{Value, json};
use std::{collections::BTreeMap, sync::Mutex};
use zeroize::{Zeroize, Zeroizing};

static STATE: Mutex<Option<State>> = Mutex::new(None);
struct State {
    api: String,
    session: Option<Session>,
    items: Vec<Entry>,
}
struct Session {
    uid: Zeroizing<String>,
    access: Zeroizing<String>,
    key: Zeroizing<Vec<u8>>,
}
struct Entry {
    id: String,
    label: String,
    public: BTreeMap<String, String>,
    secrets: BTreeMap<String, Zeroizing<String>>,
}

fn fail(kind: &str, message: &str) -> Json<Value> {
    Json(json!({"ok":false,"error_kind":kind,"error":message}))
}
fn request(
    s: &State,
    method: &str,
    path: &str,
    body: Option<&[u8]>,
) -> Result<Value, &'static str> {
    let mut req = HttpRequest::new(format!("{}{path}", s.api))
        .with_method(method)
        .with_header("Content-Type", "application/json")
        .with_header("Accept", "application/vnd.protonmail.v1+json")
        .with_header("x-pm-appversion", "cli-pass@2.4.2");
    if let Some(session) = &s.session {
        req = req
            .with_header("x-pm-uid", session.uid.as_str())
            .with_header(
                "Authorization",
                format!("Bearer {}", session.access.as_str()),
            );
    }
    let response = http::request::<&[u8]>(&req, body).map_err(|_| "HTTP transport failed")?;
    let code = response.status_code();
    if code == 401 || code == 403 {
        return Err("Proton authorization rejected");
    }
    if !(200..300).contains(&code) {
        return Err("Proton HTTP request failed");
    }
    let bytes = Zeroizing::new(response.body());
    if bytes.len() > 16 * 1024 * 1024 {
        return Err("Response too large");
    }
    serde_json::from_slice(&bytes).map_err(|_| "Invalid API response")
}
fn field<'a>(v: &'a Value, name: &str) -> Result<&'a str, &'static str> {
    v.get(name)
        .and_then(Value::as_str)
        .ok_or("Missing API field")
}
fn array<'a>(v: &'a Value, name: &str) -> Result<&'a Vec<Value>, &'static str> {
    v.get(name)
        .and_then(Value::as_array)
        .ok_or("Missing API array")
}
fn decode(v: &str) -> Result<Vec<u8>, &'static str> {
    STANDARD
        .decode(v)
        .map_err(|_| "Invalid ciphertext encoding")
}
fn take_secret(v: &mut Value, name: &str) -> Result<Zeroizing<String>, &'static str> {
    match v[name].take() {
        Value::String(s) => Ok(Zeroizing::new(s)),
        _ => Err("Missing session field"),
    }
}

fn map_item(id: String, bytes: &[u8]) -> Result<Entry, &'static str> {
    let mut item = item_v1::Item::parse_from_bytes(bytes).map_err(|_| "Invalid item protobuf")?;
    let mut e = Entry {
        id,
        label: String::new(),
        public: BTreeMap::new(),
        secrets: BTreeMap::new(),
    };
    if let Some(mut metadata) = item.metadata.take() {
        e.label = std::mem::take(&mut metadata.name);
        e.secrets.insert(
            "notes".into(),
            Zeroizing::new(std::mem::take(&mut metadata.note)),
        );
    }
    let content = item
        .content
        .as_mut()
        .and_then(|c| c.content.take())
        .ok_or("Missing item content")?;
    match content {
        item_v1::content::Content::Login(mut login) => {
            e.public.insert("type".into(), "login".into());
            e.public
                .insert("username".into(), std::mem::take(&mut login.item_username));
            e.public.insert(
                "uri".into(),
                login.urls.first().cloned().unwrap_or_default(),
            );
            e.secrets.insert(
                "password".into(),
                Zeroizing::new(std::mem::take(&mut login.password)),
            );
            if !login.totp_uri.is_empty() {
                e.public.insert("rosec:totp".into(), "true".into());
                e.secrets.insert(
                    "totp".into(),
                    Zeroizing::new(std::mem::take(&mut login.totp_uri)),
                );
            }
            // The spike does not expose passkeys yet; scrub their private payloads.
            for p in &mut login.passkeys {
                p.content.zeroize();
            }
        }
        item_v1::content::Content::Note(_) => {
            e.public.insert("type".into(), "note".into());
        }
        item_v1::content::Content::SshKey(mut ssh) => {
            e.public.insert("type".into(), "ssh-key".into());
            e.public
                .insert("public_key".into(), std::mem::take(&mut ssh.public_key));
            e.secrets.insert(
                "private_key".into(),
                Zeroizing::new(std::mem::take(&mut ssh.private_key)),
            );
        }
        _ => return Err("Item type not implemented in spike"),
    }
    // Limit the spike to uncomplicated fixtures rather than silently dropping fields.
    if !item.extra_fields.is_empty() {
        return Err("Custom fields not implemented in spike");
    }
    Ok(e)
}

fn fetch_items(s: &State) -> Result<Vec<Entry>, &'static str> {
    let session = s.session.as_ref().ok_or("Locked")?;
    let shares = request(s, "GET", "/pass/v1/share", None)?;
    let mut result = Vec::new();
    for share in array(&shares, "Shares")? {
        if share["TargetType"].as_u64() != Some(1) || !share["GroupID"].is_null() {
            return Err("Only direct vault shares supported in spike");
        }
        let sid = field(share, "ShareID")?;
        let encoded_sid = urlencoding::encode(sid);
        let mut keys = BTreeMap::new();
        for page in 0..100 {
            let response = request(
                s,
                "GET",
                &format!("/pass/v1/share/{encoded_sid}/key?Page={page}&PageSize=100"),
                None,
            )?;
            let rows = array(&response["ShareKeys"], "Keys")?;
            for row in rows {
                let rotation = row["KeyRotation"].as_u64().ok_or("Missing key rotation")?;
                let key = crypto::decrypt(
                    &decode(field(row, "Key")?)?,
                    &session.key,
                    crypto::SHARE_KEY,
                )?;
                keys.insert(rotation, key);
            }
            if rows.len() < 100 {
                break;
            }
            if page == 99 {
                return Err("Too many key pages");
            }
        }
        let mut since = String::new();
        for page in 0..100 {
            let suffix = if since.is_empty() {
                String::new()
            } else {
                format!("&Since={}", urlencoding::encode(&since))
            };
            let response = request(
                s,
                "GET",
                &format!("/pass/v1/share/{encoded_sid}/item?PageSize=100{suffix}"),
                None,
            )?;
            let rows = array(&response["Items"], "RevisionsData")?;
            for row in rows {
                if row["State"].as_u64() != Some(1) {
                    continue;
                }
                if !row["FolderID"].is_null() {
                    return Err("Folders not implemented in spike");
                }
                if row["ContentFormatVersion"].as_u64() != Some(1) {
                    return Err("Unsupported item format");
                }
                let rotation = row["KeyRotation"].as_u64().ok_or("Missing key rotation")?;
                let key = keys.get(&rotation).ok_or("Missing share key")?;
                let item_key =
                    crypto::decrypt(&decode(field(row, "ItemKey")?)?, key, crypto::ITEM_KEY)?;
                let content = crypto::decrypt(
                    &decode(field(row, "Content")?)?,
                    &item_key,
                    crypto::ITEM_CONTENT,
                )?;
                result.push(map_item(
                    format!("{sid}/{}", field(row, "ItemID")?),
                    &content,
                )?);
            }
            let next = response["Items"]["LastToken"].as_str().unwrap_or_default();
            if next.is_empty() {
                break;
            }
            if next == since || page == 99 {
                return Err("Invalid item pagination");
            }
            since = next.to_owned();
        }
    }
    Ok(result)
}

#[plugin_fn]
pub fn init(Json(v): Json<Value>) -> FnResult<Json<Value>> {
    // Configurable only for the loopback harness. The host must separately allowlist HTTP.
    let api = v["options"]["api_url"]
        .as_str()
        .unwrap_or("https://pass-api.proton.me")
        .trim_end_matches('/')
        .to_owned();
    if api != "https://pass-api.proton.me" && !api.starts_with("http://127.0.0.1:") {
        return Ok(fail("InvalidInput", "Unsupported API endpoint"));
    }
    *STATE.lock().map_err(|_| Error::msg("State unavailable"))? = Some(State {
        api,
        session: None,
        items: Vec::new(),
    });
    Ok(Json(json!({"ok":true})))
}
#[plugin_fn]
pub fn capabilities(_: ()) -> FnResult<Json<Value>> {
    Ok(Json(json!({"capabilities":["Sync","Totp"]})))
}
#[plugin_fn]
pub fn status(_: ()) -> FnResult<Json<Value>> {
    let guard = STATE.lock().map_err(|_| Error::msg("State unavailable"))?;
    Ok(Json(
        json!({"locked":guard.as_ref().is_none_or(|s|s.session.is_none()),"last_sync_epoch_secs":null}),
    ))
}
#[plugin_fn]
pub fn unlock(Json(mut input): Json<Value>) -> FnResult<Json<Value>> {
    let token = take_secret(&mut input["auth_fields"], "personal_access_token");
    let password = take_secret(&mut input, "password");
    if !password.as_ref().is_ok_and(|p| !p.is_empty()) {
        return Ok(fail("AuthFailed", "Local passphrase required"));
    }
    let mut guard = STATE.lock().map_err(|_| Error::msg("State unavailable"))?;
    let Some(s) = guard.as_mut() else {
        return Ok(fail("InvalidInput", "Not initialized"));
    };
    s.session = None;
    s.items.clear();
    let result = (|| {
        let raw = token?;
        let (token, key) = parse_pat(&raw)?;
        let body = Zeroizing::new(
            serde_json::to_vec(&json!({"Token":token.as_str()}))
                .map_err(|_| "Invalid login request")?,
        );
        let mut response = request(
            s,
            "POST",
            "/account/v4/personal-access-token/session",
            Some(&body),
        )?;
        let uid = take_secret(&mut response["Session"], "SessionUID")?;
        let access = take_secret(&mut response["Session"], "AccessToken")?;
        let _refresh = take_secret(&mut response["Session"], "RefreshToken")?;
        s.session = Some(Session { uid, access, key });
        s.items = fetch_items(s)?;
        Ok::<(), &'static str>(())
    })();
    match result {
        Ok(()) => Ok(Json(json!({"ok":true}))),
        Err(e) => {
            s.session = None;
            s.items.clear();
            Ok(fail("AuthFailed", e))
        }
    }
}
#[plugin_fn]
pub fn lock(_: ()) -> FnResult<Json<Value>> {
    let mut guard = STATE.lock().map_err(|_| Error::msg("State unavailable"))?;
    if let Some(s) = guard.as_mut() {
        s.session = None;
        s.items.clear();
    }
    Ok(Json(json!({"ok":true})))
}
#[plugin_fn]
pub fn sync(_: ()) -> FnResult<Json<Value>> {
    let mut guard = STATE.lock().map_err(|_| Error::msg("State unavailable"))?;
    let Some(s) = guard.as_mut().filter(|s| s.session.is_some()) else {
        return Ok(fail("Locked", "Locked"));
    };
    match fetch_items(s) {
        Ok(items) => {
            s.items = items;
            Ok(Json(json!({"ok":true})))
        }
        Err(e) => {
            s.session = None;
            s.items.clear();
            Ok(fail("AuthFailed", e))
        }
    }
}
fn metadata(e: &Entry) -> Value {
    json!({"id":e.id,"label":e.label,"attributes":e.public,"created_epoch_secs":null,"modified_epoch_secs":null})
}
#[plugin_fn]
pub fn list_items(_: ()) -> FnResult<Json<Value>> {
    search_impl(json!({"attributes":{}}))
}
#[plugin_fn]
pub fn search(Json(v): Json<Value>) -> FnResult<Json<Value>> {
    search_impl(v)
}
fn search_impl(v: Value) -> FnResult<Json<Value>> {
    let guard = STATE.lock().map_err(|_| Error::msg("State unavailable"))?;
    let Some(s) = guard.as_ref().filter(|s| s.session.is_some()) else {
        return Ok(fail("Locked", "Locked"));
    };
    let items: Vec<_> = s
        .items
        .iter()
        .filter(|e| {
            v["attributes"].as_object().is_none_or(|a| {
                a.iter()
                    .all(|(k, v)| e.public.get(k).map(String::as_str) == v.as_str())
            })
        })
        .map(metadata)
        .collect();
    Ok(Json(json!({"ok":true,"items":items})))
}
#[plugin_fn]
pub fn get_item_attributes(Json(v): Json<Value>) -> FnResult<Json<Value>> {
    let guard = STATE.lock().map_err(|_| Error::msg("State unavailable"))?;
    let Some(s) = guard.as_ref().filter(|s| s.session.is_some()) else {
        return Ok(fail("Locked", "Locked"));
    };
    match s
        .items
        .iter()
        .find(|e| Some(e.id.as_str()) == v["id"].as_str())
    {
        Some(e) => Ok(Json(
            json!({"ok":true,"public":e.public,"secret_names":e.secrets.keys().collect::<Vec<_>>()}),
        )),
        None => Ok(fail("NotFound", "Item not found")),
    }
}
#[plugin_fn]
pub fn get_secret_attr(Json(v): Json<Value>) -> FnResult<Json<Value>> {
    let guard = STATE.lock().map_err(|_| Error::msg("State unavailable"))?;
    let Some(s) = guard.as_ref().filter(|s| s.session.is_some()) else {
        return Ok(fail("Locked", "Locked"));
    };
    let secret = s
        .items
        .iter()
        .find(|e| Some(e.id.as_str()) == v["id"].as_str())
        .and_then(|e| e.secrets.get(v["attr"].as_str().unwrap_or_default()));
    match secret {
        Some(secret) => Ok(Json(
            json!({"ok":true,"value_b64":STANDARD.encode(secret.as_bytes())}),
        )),
        None => Ok(fail("NotFound", "Secret not found")),
    }
}
// Mutations intentionally remain unsupported, matching all rosec WASM providers.
#[plugin_fn]
pub fn create_item(_: Json<Value>) -> FnResult<Json<Value>> {
    Ok(fail("NotSupported", "Read-only provider"))
}
#[plugin_fn]
pub fn update_item(_: Json<Value>) -> FnResult<Json<Value>> {
    Ok(fail("NotSupported", "Read-only provider"))
}
#[plugin_fn]
pub fn delete_item(_: Json<Value>) -> FnResult<Json<Value>> {
    Ok(fail("NotSupported", "Read-only provider"))
}
#[plugin_fn]
pub fn change_password(_: Json<Value>) -> FnResult<Json<Value>> {
    Ok(fail("NotSupported", "Read-only provider"))
}
