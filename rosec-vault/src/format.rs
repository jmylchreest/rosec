//! Versioned payload codecs. The in-memory model does not define the disk format.
use crate::types::{VaultData, VaultItemData};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use zeroize::Zeroizing;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum VaultVersion {
    V2,
}
impl TryFrom<u32> for VaultVersion {
    type Error = anyhow::Error;
    fn try_from(value: u32) -> anyhow::Result<Self> {
        match value {
            2 => Ok(Self::V2),
            _ => anyhow::bail!("unsupported vault version: {value}"),
        }
    }
}
impl VaultVersion {
    pub fn number(self) -> u32 {
        match self {
            Self::V2 => 2,
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
pub fn required_version(_data: &VaultData) -> VaultVersion {
    VaultVersion::V2
}
pub fn encode(data: &VaultData, version: VaultVersion) -> anyhow::Result<Zeroizing<Vec<u8>>> {
    anyhow::ensure!(
        version == required_version(data),
        "vault contents cannot be represented by requested format"
    );
    let wire = V2Ref {
        items: data
            .items
            .iter()
            .map(|i| V2ItemRef {
                id: &i.id,
                label: &i.label,
                attributes: &i.attributes,
                secrets: &i.secrets,
                created: i.created,
                modified: i.modified,
            })
            .collect(),
    };
    Ok(Zeroizing::new(serde_json::to_vec(&wire)?))
}
pub fn decode(bytes: &[u8], version: VaultVersion) -> anyhow::Result<VaultData> {
    match version {
        VaultVersion::V2 => {
            let wire: V2 = serde_json::from_slice(bytes)?;
            Ok(VaultData {
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
                    })
                    .collect(),
            })
        }
    }
}
