// Copyright (c) 2026 Proton AG (adapted key hierarchy)
// SPDX-License-Identifier: GPL-3.0-or-later
use crate::{crypto, upstream::folder_v1};
use base64::{Engine, engine::general_purpose::STANDARD};
use protobuf::Message;
use serde::Deserialize;
use std::collections::{BTreeMap, BTreeSet};
use zeroize::Zeroizing;

pub const FOLDER_KEY: &[u8] = b"key.folder.pass.proton";
pub const FOLDER_CONTENT: &[u8] = b"content.folder.pass.proton";
#[derive(Deserialize)]
#[serde(rename_all = "PascalCase")]
pub struct Revision {
    #[serde(rename = "FolderID")]
    pub id: String,
    #[serde(rename = "ParentFolderID")]
    pub parent: Option<String>,
    pub key_rotation: u64,
    pub folder_key: String,
    pub content_format_version: u64,
    pub content: String,
}
pub struct Folder {
    pub key: Zeroizing<Vec<u8>>,
    pub rotation: u64,
    pub path: String,
}
pub fn open(
    revisions: Vec<Revision>,
    keys: &BTreeMap<u64, Zeroizing<Vec<u8>>>,
) -> Result<BTreeMap<String, Folder>, &'static str> {
    if revisions.len() > 1024 {
        return Err("Too many folders");
    }
    let mut remaining = BTreeMap::new();
    for r in revisions {
        if r.id.is_empty() || remaining.insert(r.id.to_owned(), r).is_some() {
            return Err("Duplicate folder ID");
        }
    }
    let mut opened: BTreeMap<String, Folder> = BTreeMap::new();
    // Resolve parents before children. A bounded pass with no progress detects
    // both cycles and missing parents; no attacker-controlled recursion.
    while !remaining.is_empty() {
        let ready: BTreeSet<_> = remaining
            .iter()
            .filter(|(_, r)| r.parent.as_ref().is_none_or(|p| opened.contains_key(p)))
            .map(|(id, _)| id.to_owned())
            .collect();
        if ready.is_empty() {
            return Err("Invalid folder hierarchy");
        }
        for id in ready {
            let r = remaining.remove(&id).ok_or("Missing folder")?;
            if r.content_format_version != 1
                || r.content.len() > 64 * 1024
                || r.folder_key.len() > 256
            {
                return Err("Invalid folder content");
            }
            let parent = r.parent.as_ref().and_then(|p| opened.get(p));
            let wrapping_key = match parent {
                Some(p) => &p.key,
                None => keys
                    .get(&r.key_rotation)
                    .ok_or("Missing folder wrapping key")?,
            };
            let encrypted = STANDARD
                .decode(&r.folder_key)
                .map_err(|_| "Invalid folder key")?;
            let key = crypto::decrypt(&encrypted, wrapping_key, FOLDER_KEY)?;
            if key.len() != 32 {
                return Err("Invalid folder key length");
            }
            let encrypted = STANDARD
                .decode(&r.content)
                .map_err(|_| "Invalid folder content")?;
            let plain = crypto::decrypt(&encrypted, &key, FOLDER_CONTENT)?;
            let folder = folder_v1::Folder::parse_from_bytes(&plain)
                .map_err(|_| "Invalid folder protobuf")?;
            let path = match parent {
                Some(p) => format!("{}/{}", p.path, folder.name),
                None => folder.name,
            };
            if path.len() > 4096 {
                return Err("Folder path too long");
            }
            opened.insert(
                id,
                Folder {
                    key,
                    rotation: r.key_rotation,
                    path,
                },
            );
        }
    }
    Ok(opened)
}
