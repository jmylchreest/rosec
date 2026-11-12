//! Versioned payload codecs. The in-memory model does not define the disk format.
use crate::types::{VaultData, VaultItemData};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use zeroize::Zeroizing;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum VaultVersion {
    V2,
    V3,
}
impl TryFrom<u32> for VaultVersion {
    type Error = anyhow::Error;
    fn try_from(value: u32) -> anyhow::Result<Self> {
        match value {
            2 => Ok(Self::V2),
            3 => Ok(Self::V3),
            _ => anyhow::bail!("unsupported vault version: {value}"),
        }
    }
}
impl VaultVersion {
    pub fn number(self) -> u32 {
        match self {
            Self::V2 => 2,
            Self::V3 => 3,
        }
    }
}

#[derive(Serialize)]
struct V2Ref<'a> {
    items: Vec<V2ItemRef<'a>>,
}
#[derive(Serialize)]
struct V2ItemRef<'a> {
    id: &'a str,
    label: &'a str,
    attributes: &'a HashMap<String, String>,
    secrets: &'a HashMap<String, String>,
    created: i64,
    modified: i64,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct V2 {
    items: Vec<V2Item>,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct V2Item {
    id: String,
    label: String,
    attributes: HashMap<String, String>,
    secrets: HashMap<String, String>,
    created: i64,
    modified: i64,
}

#[derive(Serialize)]
struct V3Ref<'a> {
    items: Vec<V3ItemRef<'a>>,
}
#[derive(Serialize)]
struct V3ItemRef<'a> {
    #[serde(flatten)]
    item: V2ItemRef<'a>,
    content_types: &'a HashMap<String, String>,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct V3 {
    items: Vec<V3Item>,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct V3Item {
    id: String,
    label: String,
    attributes: HashMap<String, String>,
    secrets: HashMap<String, String>,
    created: i64,
    modified: i64,
    content_types: HashMap<String, String>,
}
fn v2_ref(i: &VaultItemData) -> V2ItemRef<'_> {
    V2ItemRef {
        id: &i.id,
        label: &i.label,
        attributes: &i.attributes,
        secrets: &i.secrets,
        created: i.created,
        modified: i.modified,
    }
}
pub fn required_version(data: &VaultData) -> VaultVersion {
    if data
        .items
        .iter()
        .any(|i| i.content_types.values().any(|v| v != "text/plain"))
    {
        VaultVersion::V3
    } else {
        VaultVersion::V2
    }
}
fn validate(data: &VaultData) -> anyhow::Result<()> {
    anyhow::ensure!(
        data.items
            .iter()
            .all(|i| i.content_types.keys().all(|k| i.secrets.contains_key(k))),
        "content type has no corresponding secret"
    );
    Ok(())
}
pub fn encode(data: &VaultData, version: VaultVersion) -> anyhow::Result<Zeroizing<Vec<u8>>> {
    validate(data)?;
    anyhow::ensure!(
        version.number() >= required_version(data).number(),
        "vault contents cannot be represented by requested format"
    );
    let bytes = match version {
        VaultVersion::V2 => serde_json::to_vec(&V2Ref {
            items: data.items.iter().map(v2_ref).collect(),
        })?,
        VaultVersion::V3 => serde_json::to_vec(&V3Ref {
            items: data
                .items
                .iter()
                .map(|i| V3ItemRef {
                    item: v2_ref(i),
                    content_types: &i.content_types,
                })
                .collect(),
        })?,
    };
    Ok(Zeroizing::new(bytes))
}
pub fn decode(bytes: &[u8], version: VaultVersion) -> anyhow::Result<VaultData> {
    let data = match version {
        VaultVersion::V2 => {
            let wire: V2 = serde_json::from_slice(bytes)?;
            VaultData {
                items: wire
                    .items
                    .into_iter()
                    .map(|i| VaultItemData {
                        id: i.id,
                        label: i.label,
                        attributes: i.attributes,
                        secrets: i.secrets,
                        created: i.created,
                        modified: i.modified,
                        content_types: HashMap::new(),
                    })
                    .collect(),
            }
        }
        VaultVersion::V3 => {
            let wire: V3 = serde_json::from_slice(bytes)?;
            VaultData {
                items: wire
                    .items
                    .into_iter()
                    .map(|i| VaultItemData {
                        id: i.id,
                        label: i.label,
                        attributes: i.attributes,
                        secrets: i.secrets,
                        created: i.created,
                        modified: i.modified,
                        content_types: i.content_types,
                    })
                    .collect(),
            }
        }
    };
    validate(&data)?;
    Ok(data)
}
/// Bind v3 integrity to its format so changing the header to v2 cannot trick an
/// older reader into dropping metadata. V2 MAC bytes remain exactly compatible.
pub(crate) fn mac_input(version: VaultVersion, ciphertext: &[u8]) -> std::borrow::Cow<'_, [u8]> {
    match version {
        VaultVersion::V2 => std::borrow::Cow::Borrowed(ciphertext),
        VaultVersion::V3 => {
            let mut input = b"rosec-vault-v3\0".to_vec();
            input.extend_from_slice(ciphertext);
            std::borrow::Cow::Owned(input)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn v2_codec_is_explicit_and_refuses_lossy_writes() {
        let old = br#"{"items":[{"id":"i","label":"l","attributes":{},"secrets":{"secret":"AA=="},"created":1,"modified":2}]}"#;
        let mut data = decode(old, VaultVersion::V2).unwrap();
        assert_eq!(encode(&data, VaultVersion::V2).unwrap().as_slice(), old);
        data.items[0]
            .content_types
            .insert("secret".into(), "text/plain".into());
        assert_eq!(required_version(&data), VaultVersion::V2);
        data.items[0]
            .content_types
            .insert("secret".into(), "application/octet-stream".into());
        assert!(encode(&data, VaultVersion::V2).is_err());
        let v3 = encode(&data, VaultVersion::V3).unwrap();
        assert!(decode(&v3, VaultVersion::V2).is_err());
        assert_eq!(
            decode(&v3, VaultVersion::V3).unwrap().items[0].content_types["secret"],
            "application/octet-stream"
        );
        assert!(VaultVersion::try_from(4).is_err());
    }
}
