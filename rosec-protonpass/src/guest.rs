// Copyright (c) 2026 Proton AG (adapted protocol handling)
// SPDX-License-Identifier: GPL-3.0-or-later
// REST envelope and PAT flow adapted from Proton pass-cli 2.4.2; see UPSTREAM.txt.
use crate::{
    crypto,
    mapping::{Entry, map_item},
    parse_pat,
    sensitive::SensitiveJson,
};
use base64::{Engine, engine::general_purpose::STANDARD};
use extism_pdk::*;
use serde_json::{Value, json};
use std::{collections::BTreeMap, sync::Mutex};
use zeroize::Zeroizing;

static STATE: Mutex<Option<State>> = Mutex::new(None);
struct State {
    api: String,
    session: Option<Session>,
    items: BTreeMap<String, Entry>,
    offline: bool,
}
struct Session {
    uid: Zeroizing<String>,
    access: Zeroizing<String>,
    refresh: Zeroizing<String>,
    key: Zeroizing<Vec<u8>>,
}

// HTTP session replies contain bearer tokens even when later validation fails.
struct WipedResponse(ManagedMemory);
impl Drop for WipedResponse {
    fn drop(&mut self) {
        let zeros = [0u8; 4096];
        for start in (0..self.0.len()).step_by(zeros.len()) {
            let len = (self.0.len() - start).min(zeros.len());
            extism_pdk::memory::internal::store(
                MemoryHandle {
                    offset: self.0.offset() + start as u64,
                    length: len as u64,
                },
                &zeros[..len],
            );
        }
    }
}
#[link(wasm_import_module = "extism:host/env")]
unsafe extern "C" {
    fn input_offset() -> u64;
}
fn wipe_input() {
    // The plugin macro has already deserialized input into Rust-owned memory.
    // Clear the host's source allocation without freeing its runtime-owned handle.
    let offset = unsafe { input_offset() };
    let length = unsafe { extism_pdk::extism::input_length() };
    let zeros = [0u8; 4096];
    for start in (0..length).step_by(zeros.len()) {
        let len = (length - start).min(zeros.len() as u64);
        extism_pdk::memory::internal::store(
            MemoryHandle {
                offset: offset + start,
                length: len,
            },
            &zeros[..len as usize],
        );
    }
}

fn fail(kind: &str, message: &str) -> Json<Value> {
    Json(json!({"ok":false,"error_kind":kind,"error":message}))
}
fn error_kind(message: &str) -> &'static str {
    match message {
        "HTTP transport failed" | "Proton HTTP request failed" => "unavailable",
        "Proton authorization rejected" | "Proton access token expired" => "auth_failed",
        _ => "invalid_input",
    }
}
// Refresh at most once after an expired access token. Permission failures (403)
// are never refreshed or retried. Rotated credentials replace the old pair only
// after the entire response validates.
fn request(
    s: &mut State,
    method: &str,
    path: &str,
    body: Option<&[u8]>,
) -> Result<SensitiveJson, &'static str> {
    let result = request_once(s, method, path, body);
    if result.as_ref().err() != Some(&"Proton access token expired")
        || (s.session.is_none() && !s.offline)
    {
        return result;
    }
    refresh_session(s)?;
    request_once(s, method, path, body)
}

fn refresh_session(s: &mut State) -> Result<(), &'static str> {
    let session = s.session.as_ref().ok_or("locked")?;
    let mut state = Zeroizing::new([0u8; 32]);
    getrandom::getrandom(state.as_mut()).map_err(|_| "Refresh randomness unavailable")?;
    let refresh_body = SensitiveJson(json!({"UID":session.uid.as_str(),
        "State":STANDARD.encode(&*state), "AccessToken":session.access.as_str(),
        "RefreshToken":session.refresh.as_str(), "ResponseType":"token",
        "GrantType":"refresh_token", "RedirectURI":"https://protonmail.ch"}));
    let bytes =
        Zeroizing::new(serde_json::to_vec(&*refresh_body).map_err(|_| "Invalid refresh request")?);
    let mut response = request_once(s, "POST", "/auth/v4/refresh", Some(&bytes))?;
    let uid = take_secret(&mut response, "UID")?;
    let access = take_secret(&mut response, "AccessToken")?;
    let refresh = take_secret(&mut response, "RefreshToken")?;
    if uid.is_empty() || access.is_empty() || refresh.is_empty() {
        return Err("Invalid refreshed session");
    }
    let session = s.session.as_mut().ok_or("locked")?;
    session.uid = uid;
    session.access = access;
    session.refresh = refresh;
    Ok(())
}

// Exercise the real refresh endpoint without waiting for access-token expiry.
// This export is absent from production builds.
#[cfg(feature = "test-http")]
#[plugin_fn]
pub fn test_refresh(_: ()) -> FnResult<Json<Value>> {
    let mut guard = STATE.lock().map_err(|_| Error::msg("State unavailable"))?;
    let Some(s) = guard.as_mut() else {
        return Ok(fail("locked", "locked"));
    };
    match refresh_session(s) {
        Ok(()) => Ok(Json(json!({"ok":true}))),
        Err(e) => {
            clear_session(s);
            Ok(fail(error_kind(e), e))
        }
    }
}

fn request_once(
    s: &State,
    method: &str,
    path: &str,
    body: Option<&[u8]>,
) -> Result<SensitiveJson, &'static str> {
    let mut req = HttpRequest::new(format!("{}{path}", s.api))
        .with_method(method)
        .with_header("Content-Type", "application/json")
        .with_header("Accept", "application/vnd.protonmail.v1+json")
        .with_header("x-pm-appversion", "cli-pass@2.4.2");
    if let Some(session) = &s.session {
        // Refresh authenticates using its body credentials. A bearer with PAT
        // scopes must not be used as authorization for the account refresh API.
        if path != "/auth/v4/refresh" {
            req = req
                .with_header("x-pm-uid", session.uid.as_str())
                .with_header(
                    "Authorization",
                    format!("Bearer {}", session.access.as_str()),
                );
        }
    }
    let response = http::request::<&[u8]>(&req, body).map_err(|_| "HTTP transport failed")?;
    let code = response.status_code();
    let memory = WipedResponse(ManagedMemory::new(response.into_memory()));
    if code == 401 {
        return Err("Proton access token expired");
    }
    if code == 403 {
        return Err("Proton authorization rejected");
    }
    if !(200..300).contains(&code) {
        return Err("Proton HTTP request failed");
    }
    // Check the host response allocation before making a second guest copy.
    if memory.0.len() > 8 * 1024 * 1024 {
        return Err("Response too large");
    }
    let bytes = Zeroizing::new(memory.0.0.to_vec());
    serde_json::from_slice(&bytes)
        .map(SensitiveJson)
        .map_err(|_| "Invalid API response")
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
    if v.len() > 2 * 1024 * 1024 {
        return Err("Encrypted field too large");
    }
    STANDARD
        .decode(v)
        .map_err(|_| "Invalid ciphertext encoding")
}
fn take_secret(v: &mut Value, name: &str) -> Result<Zeroizing<String>, &'static str> {
    if !v.get(name).is_some_and(Value::is_string) {
        return Err("Missing session field");
    }
    match v.get_mut(name).map(Value::take) {
        Some(Value::String(s)) => Ok(Zeroizing::new(s)),
        _ => Err("Missing session field"),
    }
}

fn fetch_items(s: &mut State) -> Result<BTreeMap<String, Entry>, &'static str> {
    // Refresh may rotate the session during pagination; keep the guarded vault
    // key independently owned while requests mutably update bearer credentials.
    let key = s.session.as_ref().ok_or("locked")?.key.clone();
    let shares = request(s, "GET", "/pass/v1/share", None)?;
    let mut result = BTreeMap::new();
    let shares = array(&shares, "Shares")?;
    if shares.len() > 32 {
        return Err("Too many shares");
    }
    let mut total_bytes = 0usize;
    for share in shares {
        if share["TargetType"].as_u64() != Some(1) || !share["GroupID"].is_null() {
            return Err("Only direct vault shares are supported");
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
            if rows.len() > 100 || keys.len() + rows.len() > 128 {
                return Err("Too many share keys");
            }
            for row in rows {
                let rotation = row["KeyRotation"].as_u64().ok_or("Missing key rotation")?;
                let key = crypto::decrypt(&decode(field(row, "Key")?)?, &key, crypto::SHARE_KEY)?;
                if key.len() != 32 {
                    return Err("Invalid share key length");
                }
                if keys.insert(rotation, key).is_some() {
                    return Err("Duplicate key rotation");
                }
            }
            if rows.len() < 100 {
                break;
            }
            if page == 99 {
                return Err("Too many key pages");
            }
        }
        let mut folders = None;
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
            if rows.len() > 100 {
                return Err("Item page too large");
            }
            for row in rows {
                if row["State"].as_u64() != Some(1) {
                    continue;
                }
                if row["ContentFormatVersion"].as_u64() != Some(crate::ITEM_CONTENT_FORMAT_VERSION)
                {
                    return Err("Unsupported item format");
                }
                let rotation = row["KeyRotation"].as_u64().ok_or("Missing key rotation")?;
                if !row["FolderID"].is_null() && folders.is_none() {
                    folders = Some(fetch_folders(s, &encoded_sid, &keys)?);
                }
                let folder = if row["FolderID"].is_null() {
                    None
                } else {
                    Some(
                        folders
                            .as_ref()
                            .and_then(|f| f.get(row["FolderID"].as_str()?))
                            .ok_or("Missing item folder")?,
                    )
                };
                let key = match folder {
                    Some(f) if f.rotation == rotation => &f.key,
                    Some(_) => return Err("Folder key rotation mismatch"),
                    None => keys.get(&rotation).ok_or("Missing share key")?,
                };
                let item_key =
                    crypto::decrypt(&decode(field(row, "ItemKey")?)?, key, crypto::ITEM_KEY)?;
                if result.len() >= 10_000 {
                    return Err("Too many items");
                }
                let content = crypto::decrypt(
                    &decode(field(row, "Content")?)?,
                    &item_key,
                    crypto::ITEM_CONTENT,
                )?;
                total_bytes = total_bytes
                    .checked_add(content.len())
                    .ok_or("Vault too large")?;
                if total_bytes > 32 * 1024 * 1024 {
                    return Err("Vault too large");
                }
                let mut entry = map_item(format!("{sid}/{}", field(row, "ItemID")?), &content)?;
                if let Some(folder) = folder {
                    entry.public.insert("folder".into(), folder.path.to_owned());
                }
                if entry
                    .public
                    .get("proton_type")
                    .is_some_and(|v| v == "alias")
                    && let Some(email) = row["AliasEmail"].as_str()
                {
                    entry.public.insert("email".into(), email.into());
                }
                for totp in crate::mapping::additional_totp_entries(&entry) {
                    if result.len() >= 9_999 || result.insert(totp.id.to_owned(), totp).is_some() {
                        return Err("Too many items or duplicate TOTP ID");
                    }
                }
                if result.insert(entry.id.to_owned(), entry).is_some() {
                    return Err("Duplicate item ID");
                }
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

fn fetch_folders(
    s: &mut State,
    sid: &str,
    keys: &BTreeMap<u64, Zeroizing<Vec<u8>>>,
) -> Result<BTreeMap<String, crate::folders::Folder>, &'static str> {
    let mut revisions = Vec::new();
    let mut since = String::new();
    let mut tokens = std::collections::BTreeSet::new();
    for _ in 0..100 {
        let suffix = if since.is_empty() {
            String::new()
        } else {
            format!("&Since={}", urlencoding::encode(&since))
        };
        let mut response = request(
            s,
            "GET",
            &format!("/pass/v1/share/{sid}/folder?PageSize=100{suffix}"),
            None,
        )?;
        let rows = array(&response["Folders"], "Folders")?;
        if rows.len() > 100 || revisions.len() + rows.len() > 1024 {
            return Err("Too many folders");
        }
        since = response["Folders"]["LastToken"]
            .as_str()
            .unwrap_or_default()
            .to_owned();
        let rows: Vec<crate::folders::Revision> =
            serde_json::from_value(response["Folders"]["Folders"].take())
                .map_err(|_| "Invalid folder response")?;
        revisions.extend(rows);
        if since.is_empty() {
            return crate::folders::open(revisions, keys);
        }
        if !tokens.insert(since.to_owned()) {
            return Err("Invalid folder pagination");
        }
    }
    Err("Too many folder pages")
}

#[plugin_fn]
pub fn init(Json(v): Json<Value>) -> FnResult<Json<Value>> {
    *STATE.lock().map_err(|_| Error::msg("State unavailable"))? = None;
    // Configurable only for the loopback harness. The host must separately allowlist HTTP.
    let api = v["options"]["api_url"]
        .as_str()
        .unwrap_or("https://pass-api.proton.me")
        .trim_end_matches('/')
        .to_owned();
    if !crate::valid_api_endpoint(&api) {
        return Ok(fail("invalid_input", "Unsupported API endpoint"));
    }
    *STATE.lock().map_err(|_| Error::msg("State unavailable"))? = Some(State {
        api,
        session: None,
        items: BTreeMap::new(),
        offline: false,
    });
    Ok(Json(json!({"ok":true})))
}
#[plugin_fn]
pub fn capabilities(_: ()) -> FnResult<Json<Value>> {
    Ok(Json(
        json!({"capabilities":["Sync","Totp","Ssh","Fido2","OfflineCache"]}),
    ))
}
#[plugin_fn]
pub fn status(_: ()) -> FnResult<Json<Value>> {
    let guard = STATE.lock().map_err(|_| Error::msg("State unavailable"))?;
    Ok(Json(
        json!({"locked":guard.as_ref().is_none_or(|s|s.session.is_none() && !s.offline),"last_sync_epoch_secs":null}),
    ))
}
#[plugin_fn]
pub fn unlock(Json(input): Json<Value>) -> FnResult<Json<Value>> {
    wipe_input();
    let mut input = SensitiveJson(input);
    let mut guard = STATE.lock().map_err(|_| Error::msg("State unavailable"))?;
    let Some(s) = guard.as_mut() else {
        return Ok(fail("invalid_input", "Not initialized"));
    };
    // Every re-authentication attempt invalidates the previous snapshot first.
    clear_session(s);
    // The daemon currently routes additional interactive auth fields through
    // WithRegistration; the direct harness uses WithAuth. Accept both envelopes.
    let token = if input["auth_fields"]["personal_access_token"].is_string() {
        take_secret(
            input
                .get_mut("auth_fields")
                .ok_or_else(|| Error::msg("Invalid auth envelope"))?,
            "personal_access_token",
        )
    } else {
        input
            .get_mut("registration_fields")
            .ok_or("Missing auth fields")
            .and_then(|v| take_secret(v, "personal_access_token"))
    };
    let password = take_secret(&mut input, "password");
    if !password.as_ref().is_ok_and(|p| !p.is_empty()) {
        return Ok(fail("auth_failed", "Local passphrase required"));
    }
    if token.is_err() {
        return Ok(fail(
            "registration_required",
            "Register a viewer personal access token",
        ));
    }
    let result = (|| {
        let raw = token?;
        let (token, key) = parse_pat(&raw)?;
        #[derive(serde::Serialize)]
        struct TokenBody<'a> {
            #[serde(rename = "Token")]
            token: &'a str,
        }
        let body = Zeroizing::new(
            serde_json::to_vec(&TokenBody {
                token: token.as_str(),
            })
            .map_err(|_| "Invalid login request")?,
        );
        let mut response = request(
            s,
            "POST",
            "/account/v4/personal-access-token/session",
            Some(&body),
        )?;
        let uid = take_secret(
            response.get_mut("Session").ok_or("Missing session")?,
            "SessionUID",
        )?;
        let access = take_secret(
            response.get_mut("Session").ok_or("Missing session")?,
            "AccessToken",
        )?;
        let refresh = take_secret(
            response.get_mut("Session").ok_or("Missing session")?,
            "RefreshToken",
        )?;
        if uid.is_empty() || access.is_empty() || refresh.is_empty() {
            return Err("Invalid session");
        }
        s.session = Some(Session {
            uid,
            access,
            refresh,
            key,
        });
        s.items = fetch_items(s)?;
        Ok::<(), &'static str>(())
    })();
    match result {
        Ok(()) => Ok(Json(json!({"ok":true}))),
        Err(e) => {
            clear_session(s);
            Ok(fail(error_kind(e), e))
        }
    }
}
fn clear_session(s: &mut State) {
    s.items.clear();
    s.offline = false;
    if let Some(session) = s.session.take() {
        let retired = State {
            api: s.api.clone(),
            session: Some(session),
            items: BTreeMap::new(),
            offline: false,
        };
        // Best effort: local lock cannot depend on network availability. Only
        // revoke this API session; never revoke the user's PAT or other sessions.
        let _ = request_once(&retired, "DELETE", "/core/v4/auth", None);
    }
}
#[plugin_fn]
pub fn lock(_: ()) -> FnResult<Json<Value>> {
    let mut guard = STATE.lock().map_err(|_| Error::msg("State unavailable"))?;
    if let Some(s) = guard.as_mut() {
        clear_session(s);
    }
    Ok(Json(json!({"ok":true})))
}
#[plugin_fn]
pub fn sync(_: ()) -> FnResult<Json<Value>> {
    let mut guard = STATE.lock().map_err(|_| Error::msg("State unavailable"))?;
    let Some(s) = guard.as_mut().filter(|s| s.session.is_some() || s.offline) else {
        return Ok(fail("locked", "locked"));
    };
    if s.offline {
        return Ok(fail(
            "unavailable",
            "Unlock again online to refresh the cached vault",
        ));
    }
    // Drop the old plaintext snapshot before constructing its replacement. The
    // provider serializes operations, so retaining both buys no concurrent reads.
    s.items.clear();
    match fetch_items(s) {
        Ok(items) => {
            s.items = items;
            Ok(Json(json!({"ok":true})))
        }
        Err(e) => {
            clear_session(s);
            Ok(fail(error_kind(e), e))
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
    let Some(s) = guard.as_ref().filter(|s| s.session.is_some() || s.offline) else {
        return Ok(fail("locked", "locked"));
    };
    let items: Vec<_> = s
        .items
        .values()
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
    let Some(s) = guard.as_ref().filter(|s| s.session.is_some() || s.offline) else {
        return Ok(fail("locked", "locked"));
    };
    match v["id"].as_str().and_then(|id| s.items.get(id)) {
        Some(e) => Ok(Json(
            json!({"ok":true,"public":e.public,"secret_names":e.secrets.keys().collect::<Vec<_>>()}),
        )),
        None => Ok(fail("not_found", "Item not found")),
    }
}
#[plugin_fn]
pub fn get_secret_attr(Json(v): Json<Value>) -> FnResult<Json<Value>> {
    let guard = STATE.lock().map_err(|_| Error::msg("State unavailable"))?;
    let Some(s) = guard.as_ref().filter(|s| s.session.is_some() || s.offline) else {
        return Ok(fail("locked", "locked"));
    };
    let secret = v["id"]
        .as_str()
        .and_then(|id| s.items.get(id))
        .and_then(|e| {
            let attr = v["attr"].as_str().unwrap_or_default();
            e.secrets
                .get(attr)
                .map(|s| s.as_str())
                .or_else(|| e.public.get(attr).map(String::as_str))
        });
    match secret {
        Some(secret) => Ok(Json(
            json!({"ok":true,"value_b64":STANDARD.encode(secret.as_bytes())}),
        )),
        None => Ok(fail("not_found", "Secret not found")),
    }
}

#[plugin_fn]
pub fn list_ssh_keys(_: ()) -> FnResult<Json<Value>> {
    let guard = STATE.lock().map_err(|_| Error::msg("State unavailable"))?;
    let Some(s) = guard.as_ref().filter(|s| s.session.is_some() || s.offline) else {
        return Ok(fail("locked", "locked"));
    };
    let keys: Vec<_> = s.items.values().filter(|e| e.public.get("rosec:type").is_some_and(|t| t == "ssh-key"))
        .filter(|e| e.secrets.get("private_key").is_some_and(|p| !p.is_empty()))
        .map(|e| {
            let lines = |names: &[&str]| -> Vec<&str> { names.iter().filter_map(|n| e.secrets.get(*n)).flat_map(|v| v.lines()).map(str::trim).filter(|v| !v.is_empty()).collect() };
            json!({"item_id":e.id,"item_name":e.label,"public_key_openssh":e.public.get("public_key"),
                "fingerprint":null,"ssh_hosts":lines(&["custom.ssh_hosts","custom.ssh-hosts"]),
                "signing_principals":lines(&["custom.ssh_signing_principal","custom.ssh-signing-principal"]),
                "ssh_user":e.secrets.get("custom.ssh_user").map(|s|s.as_str()),"require_confirm":true,"revision_date_epoch_secs":null})
        }).collect();
    Ok(Json(json!({"ok":true,"keys":keys})))
}
#[plugin_fn]
pub fn get_ssh_private_key(Json(v): Json<Value>) -> FnResult<Json<Value>> {
    let guard = STATE.lock().map_err(|_| Error::msg("State unavailable"))?;
    let Some(s) = guard.as_ref().filter(|s| s.session.is_some() || s.offline) else {
        return Ok(fail("locked", "locked"));
    };
    match v["item_id"]
        .as_str()
        .and_then(|id| s.items.get(id))
        .and_then(|e| e.secrets.get("private_key"))
    {
        Some(pem) if !pem.is_empty() => Ok(Json(json!({"ok":true,"pem":pem.as_str()}))),
        _ => Ok(fail("not_found", "SSH key not found")),
    }
}
#[plugin_fn]
pub fn list_fido2_credentials(_: ()) -> FnResult<Json<Value>> {
    let guard = STATE.lock().map_err(|_| Error::msg("State unavailable"))?;
    let Some(s) = guard.as_ref().filter(|s| s.session.is_some() || s.offline) else {
        return Ok(fail("locked", "locked"));
    };
    let credentials: Vec<_> = s.items.values().flat_map(|e| e.passkeys.iter().map(move |p| {
        json!({"item_id":e.id,"item_name":e.label,"credential_id":p.credential_id,"rp_id":p.rp_id,"rp_name":p.rp_name,
            "user_handle":p.user_handle,"user_name":p.user_name,"user_display_name":p.user_display_name,"algorithm":p.algorithm,
            "counter":0,"discoverable":p.user_handle.is_some(),"require_uv":true,"revision_date_epoch_secs":null})
    })).collect();
    Ok(Json(json!({"ok":true,"credentials":credentials})))
}
#[plugin_fn]
pub fn get_fido2_key(Json(v): Json<Value>) -> FnResult<Json<Value>> {
    let guard = STATE.lock().map_err(|_| Error::msg("State unavailable"))?;
    let Some(s) = guard.as_ref().filter(|s| s.session.is_some() || s.offline) else {
        return Ok(fail("locked", "locked"));
    };
    let credential = v["item_id"]
        .as_str()
        .and_then(|id| s.items.get(id))
        .and_then(|e| {
            e.passkeys
                .iter()
                .find(|p| Some(p.credential_id.as_str()) == v["credential_id"].as_str())
        });
    match credential {
        Some(p) => Ok(Json(json!({"ok":true,"pem":p.pem.as_str()}))),
        None => Ok(fail("not_found", "Passkey not found")),
    }
}

// No bearer credentials or PAT in the offline snapshot. The host authenticates
// the password + machine + provider bound encrypted envelope before restoring.
#[derive(serde::Serialize, serde::Deserialize)]
struct Cache {
    version: u32,
    items: BTreeMap<String, Entry>,
}
#[plugin_fn]
pub fn export_cache(_: ()) -> FnResult<Json<Value>> {
    let guard = STATE.lock().map_err(|_| Error::msg("State unavailable"))?;
    let Some(s) = guard.as_ref().filter(|s| s.session.is_some()) else {
        return Ok(fail("locked", "Online snapshot required"));
    };
    #[derive(serde::Serialize)]
    struct Snapshot<'a> {
        version: u32,
        items: &'a BTreeMap<String, Entry>,
    }
    let bytes = Zeroizing::new(
        serde_json::to_vec(&Snapshot {
            version: 1,
            items: &s.items,
        })
        .map_err(|_| Error::msg("Cache serialization failed"))?,
    );
    if bytes.len() > 24 * 1024 * 1024 {
        return Ok(fail("invalid_input", "Cache too large"));
    }
    Ok(Json(json!({"ok":true,"blob_b64":STANDARD.encode(&*bytes)})))
}
#[plugin_fn]
pub fn restore_cache(Json(input): Json<Value>) -> FnResult<Json<Value>> {
    wipe_input();
    let input = SensitiveJson(input);
    let mut guard = STATE.lock().map_err(|_| Error::msg("State unavailable"))?;
    let Some(s) = guard.as_mut() else {
        return Ok(fail("invalid_input", "Not initialized"));
    };
    clear_session(s);
    let result = (|| {
        let encoded = input["blob_b64"].as_str().ok_or("Missing cache")?;
        if encoded.len() > 32 * 1024 * 1024 {
            return Err("Cache too large");
        }
        let bytes = Zeroizing::new(
            STANDARD
                .decode(encoded)
                .map_err(|_| "Invalid cache encoding")?,
        );
        let cache: Cache = serde_json::from_slice(&bytes).map_err(|_| "Invalid cache data")?;
        if cache.version != 1
            || cache.items.len() > 10_000
            || cache.items.iter().any(|(id, e)| id != &e.id)
        {
            return Err("Invalid cache version or items");
        }
        s.items = cache.items;
        s.offline = true;
        Ok(())
    })();
    match result {
        Ok(()) => Ok(Json(json!({"ok":true}))),
        Err(e) => Ok(fail("invalid_input", e)),
    }
}
// Mutations intentionally remain unsupported, matching all rosec WASM providers.
#[plugin_fn]
pub fn create_item(_: Json<Value>) -> FnResult<Json<Value>> {
    Ok(fail("not_supported", "Read-only provider"))
}
#[plugin_fn]
pub fn update_item(_: Json<Value>) -> FnResult<Json<Value>> {
    Ok(fail("not_supported", "Read-only provider"))
}
#[plugin_fn]
pub fn delete_item(_: Json<Value>) -> FnResult<Json<Value>> {
    Ok(fail("not_supported", "Read-only provider"))
}
#[plugin_fn]
pub fn change_password(_: Json<Value>) -> FnResult<Json<Value>> {
    Ok(fail("not_supported", "Read-only provider"))
}

#[plugin_fn]
pub fn plugin_manifest(_: String) -> FnResult<Json<Value>> {
    Ok(Json(
        json!({"kind":"protonpass","name":"Proton Pass","description":"Experimental read-only Proton Pass provider","version":env!("CARGO_PKG_VERSION"),"default_allowed_hosts":["pass-api.proton.me"],"required_options":[],"optional_options":[],"experimental":true}),
    ))
}
#[plugin_fn]
pub fn auth_fields(_: String) -> FnResult<Json<Value>> {
    Ok(Json(json!({"fields":[]})))
}
#[plugin_fn]
pub fn registration_info(_: String) -> FnResult<Json<Value>> {
    Ok(Json(json!({
        "has_registration": true,
        "instructions": "Create a normal personal access token in Proton Pass web settings or CLI, with viewer access to the desired vaults. Choose a local passphrase to encrypt it on this installation. Re-register to replace the token or local passphrase.",
        "fields": [{"id":"personal_access_token","label":"Personal access token","placeholder":"","required":true,"kind":"secret"}]
    })))
}

#[plugin_fn]
pub fn readiness_probes(_: ()) -> FnResult<Json<Value>> {
    #[cfg(feature = "test-http")]
    {
        let guard = STATE.lock().map_err(|_| Error::msg("State unavailable"))?;
        if let Some(port) = guard
            .as_ref()
            .and_then(|s| s.api.strip_prefix("http://127.0.0.1:"))
            .and_then(|p| p.parse::<u16>().ok())
        {
            return Ok(Json(
                json!({"probes":[{"kind":"tcp","host":"127.0.0.1","port":port,"timeout_secs":1}]}),
            ));
        }
    }
    Ok(Json(
        json!({"probes":[{"kind":"tcp","host":"pass-api.proton.me","port":443,"timeout_secs":5}]}),
    ))
}
