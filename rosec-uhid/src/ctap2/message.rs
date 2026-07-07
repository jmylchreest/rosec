//! CTAP2 `getAssertion` / `makeCredential` request decoding and response
//! encoding (CTAP spec §6.1–6.2).
//!
//! Requests and responses are CBOR maps keyed by small integers. This module
//! parses the incoming request bytes into typed structs and encodes the
//! typed responses back to CBOR — the pure translation layer between the wire
//! and the ceremony engine. Malformed input maps to
//! [`Ctap2Status::InvalidParameter`].

use coset::CborSerializable;
use coset::cbor::value::Value;

use super::command::Ctap2Status;

/// A WebAuthn credential descriptor: `{ "type": ..., "id": <bytes> }`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CredentialDescriptor {
    pub cred_type: String,
    pub id: Vec<u8>,
}

impl CredentialDescriptor {
    fn from_value(v: &Value) -> Option<Self> {
        let m = as_map(v)?;
        Some(Self {
            cred_type: map_text(m, "type")?,
            id: map_bytes(m, "id")?,
        })
    }

    fn to_value(&self) -> Value {
        // CTAP2 canonical CBOR: map keys are ordered by encoded bytes, so the
        // shorter "id" (0x62…) must precede "type" (0x64…). libfido2's
        // ctap_check_cbor rejects the whole response otherwise.
        Value::Map(vec![
            (Value::Text("id".into()), Value::Bytes(self.id.clone())),
            (
                Value::Text("type".into()),
                Value::Text(self.cred_type.clone()),
            ),
        ])
    }
}

/// Decoded `authenticatorGetAssertion` request (CTAP §6.2).
#[derive(Debug, Clone)]
pub struct GetAssertionRequest {
    pub rp_id: String,
    pub client_data_hash: Vec<u8>,
    /// Empty = discoverable-credential request (match any for the RP).
    pub allow_list: Vec<CredentialDescriptor>,
    pub up: bool,
    pub uv: bool,
}

impl GetAssertionRequest {
    pub fn decode(bytes: &[u8]) -> Result<Self, Ctap2Status> {
        let map = top_map(bytes)?;
        let rp_id = int_text(&map, 1).ok_or(Ctap2Status::InvalidParameter)?;
        let client_data_hash = int_bytes(&map, 2).ok_or(Ctap2Status::InvalidParameter)?;
        let allow_list = match int_get(&map, 3) {
            Some(Value::Array(items)) => items
                .iter()
                .map(CredentialDescriptor::from_value)
                .collect::<Option<Vec<_>>>()
                .ok_or(Ctap2Status::InvalidParameter)?,
            Some(_) => return Err(Ctap2Status::InvalidParameter),
            None => Vec::new(),
        };
        // options map (key 5): up defaults true, uv defaults false.
        let (up, uv) = match int_get(&map, 5) {
            Some(v) => {
                let o = as_map(v).ok_or(Ctap2Status::InvalidParameter)?;
                (
                    map_bool(o, "up").unwrap_or(true),
                    map_bool(o, "uv").unwrap_or(false),
                )
            }
            None => (true, false),
        };
        Ok(Self {
            rp_id,
            client_data_hash,
            allow_list,
            up,
            uv,
        })
    }
}

/// `authenticatorGetAssertion` response (CTAP §6.2).
#[derive(Debug, Clone)]
pub struct GetAssertionResponse {
    pub credential: CredentialDescriptor,
    pub auth_data: Vec<u8>,
    pub signature: Vec<u8>,
    /// User handle bytes, for discoverable credentials.
    pub user_handle: Option<Vec<u8>>,
    /// Only set (to 1) when the authenticator itself selected among several.
    pub number_of_credentials: Option<u32>,
}

impl GetAssertionResponse {
    pub fn encode(&self) -> Vec<u8> {
        let mut entries = vec![
            (Value::Integer(1.into()), self.credential.to_value()),
            (
                Value::Integer(2.into()),
                Value::Bytes(self.auth_data.clone()),
            ),
            (
                Value::Integer(3.into()),
                Value::Bytes(self.signature.clone()),
            ),
        ];
        if let Some(uh) = &self.user_handle {
            entries.push((
                Value::Integer(4.into()),
                Value::Map(vec![(Value::Text("id".into()), Value::Bytes(uh.clone()))]),
            ));
        }
        if let Some(n) = self.number_of_credentials {
            entries.push((Value::Integer(5.into()), Value::Integer((n as i64).into())));
        }
        Value::Map(entries)
            .to_vec()
            .expect("getAssertion CBOR encodes")
    }
}

/// A `{ alg, type }` entry from `pubKeyCredParams`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CredParam {
    pub alg: i64,
    pub cred_type: String,
}

/// Decoded `authenticatorMakeCredential` request (CTAP §6.1).
#[derive(Debug, Clone)]
pub struct MakeCredentialRequest {
    pub client_data_hash: Vec<u8>,
    pub rp_id: String,
    pub rp_name: Option<String>,
    pub user_id: Vec<u8>,
    pub user_name: Option<String>,
    pub user_display_name: Option<String>,
    /// Relying party's accepted algorithms, in preference order.
    pub pub_key_cred_params: Vec<CredParam>,
    pub exclude_list: Vec<CredentialDescriptor>,
    pub rk: bool,
    pub up: bool,
    pub uv: bool,
}

impl MakeCredentialRequest {
    pub fn decode(bytes: &[u8]) -> Result<Self, Ctap2Status> {
        let map = top_map(bytes)?;
        let client_data_hash = int_bytes(&map, 1).ok_or(Ctap2Status::InvalidParameter)?;

        let rp = int_get(&map, 2)
            .and_then(as_map)
            .ok_or(Ctap2Status::InvalidParameter)?;
        let rp_id = map_text(rp, "id").ok_or(Ctap2Status::InvalidParameter)?;
        let rp_name = map_text(rp, "name");

        let user = int_get(&map, 3)
            .and_then(as_map)
            .ok_or(Ctap2Status::InvalidParameter)?;
        let user_id = map_bytes(user, "id").ok_or(Ctap2Status::InvalidParameter)?;
        let user_name = map_text(user, "name");
        let user_display_name = map_text(user, "displayName");

        let pub_key_cred_params = match int_get(&map, 4) {
            Some(Value::Array(items)) => items
                .iter()
                .filter_map(|v| {
                    let m = as_map(v)?;
                    Some(CredParam {
                        alg: map_int(m, "alg")?,
                        cred_type: map_text(m, "type")?,
                    })
                })
                .collect(),
            _ => return Err(Ctap2Status::InvalidParameter),
        };

        let exclude_list = match int_get(&map, 5) {
            Some(Value::Array(items)) => items
                .iter()
                .filter_map(CredentialDescriptor::from_value)
                .collect(),
            _ => Vec::new(),
        };

        let (rk, up, uv) = match int_get(&map, 7) {
            Some(v) => {
                let o = as_map(v).ok_or(Ctap2Status::InvalidParameter)?;
                (
                    map_bool(o, "rk").unwrap_or(false),
                    map_bool(o, "up").unwrap_or(true),
                    map_bool(o, "uv").unwrap_or(false),
                )
            }
            None => (false, true, false),
        };

        Ok(Self {
            client_data_hash,
            rp_id,
            rp_name,
            user_id,
            user_name,
            user_display_name,
            pub_key_cred_params,
            exclude_list,
            rk,
            up,
            uv,
        })
    }

    /// The first accepted algorithm rosec can generate (ES256 or EdDSA), in
    /// the relying party's preference order. `None` if it accepts none.
    pub fn preferred_algorithm(&self) -> Option<i64> {
        self.pub_key_cred_params
            .iter()
            .filter(|p| p.cred_type == "public-key")
            .map(|p| p.alg)
            .find(|alg| *alg == super::sign::ALG_ES256 || *alg == super::sign::ALG_EDDSA)
    }
}

/// `authenticatorMakeCredential` response (CTAP §6.1): "none" attestation.
#[derive(Debug, Clone)]
pub struct MakeCredentialResponse {
    pub auth_data: Vec<u8>,
}

impl MakeCredentialResponse {
    pub fn encode(&self) -> Vec<u8> {
        let map = Value::Map(vec![
            (Value::Integer(1.into()), Value::Text("none".into())),
            (
                Value::Integer(2.into()),
                Value::Bytes(self.auth_data.clone()),
            ),
            (Value::Integer(3.into()), Value::Map(vec![])), // empty attStmt
        ]);
        map.to_vec().expect("makeCredential CBOR encodes")
    }
}

// ── CBOR extraction helpers ─────────────────────────────────────────────

fn top_map(bytes: &[u8]) -> Result<Vec<(Value, Value)>, Ctap2Status> {
    let v: Value = coset::cbor::from_reader(bytes).map_err(|_| Ctap2Status::InvalidParameter)?;
    match v {
        Value::Map(m) => Ok(m),
        _ => Err(Ctap2Status::InvalidParameter),
    }
}

fn int_get(map: &[(Value, Value)], key: i64) -> Option<&Value> {
    map.iter()
        .find(|(k, _)| matches!(k, Value::Integer(i) if *i == key.into()))
        .map(|(_, v)| v)
}

fn int_text(map: &[(Value, Value)], key: i64) -> Option<String> {
    match int_get(map, key)? {
        Value::Text(s) => Some(s.clone()),
        _ => None,
    }
}

fn int_bytes(map: &[(Value, Value)], key: i64) -> Option<Vec<u8>> {
    match int_get(map, key)? {
        Value::Bytes(b) => Some(b.clone()),
        _ => None,
    }
}

fn as_map(v: &Value) -> Option<&Vec<(Value, Value)>> {
    match v {
        Value::Map(m) => Some(m),
        _ => None,
    }
}

fn map_get<'a>(map: &'a [(Value, Value)], key: &str) -> Option<&'a Value> {
    map.iter()
        .find(|(k, _)| matches!(k, Value::Text(t) if t == key))
        .map(|(_, v)| v)
}

fn map_text(map: &[(Value, Value)], key: &str) -> Option<String> {
    match map_get(map, key)? {
        Value::Text(s) => Some(s.clone()),
        _ => None,
    }
}

fn map_bytes(map: &[(Value, Value)], key: &str) -> Option<Vec<u8>> {
    match map_get(map, key)? {
        Value::Bytes(b) => Some(b.clone()),
        _ => None,
    }
}

fn map_bool(map: &[(Value, Value)], key: &str) -> Option<bool> {
    match map_get(map, key)? {
        Value::Bool(b) => Some(*b),
        _ => None,
    }
}

fn map_int(map: &[(Value, Value)], key: &str) -> Option<i64> {
    match map_get(map, key)? {
        Value::Integer(i) => (*i).try_into().ok(),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn encode(v: Value) -> Vec<u8> {
        v.to_vec().unwrap()
    }

    #[test]
    fn get_assertion_request_decodes() {
        // { 1: "example.com", 2: h'...', 3: [{type,id}], 5: {up,uv} }
        let req = encode(Value::Map(vec![
            (Value::Integer(1.into()), Value::Text("example.com".into())),
            (Value::Integer(2.into()), Value::Bytes(vec![0xAA; 32])),
            (
                Value::Integer(3.into()),
                Value::Array(vec![Value::Map(vec![
                    (Value::Text("type".into()), Value::Text("public-key".into())),
                    (Value::Text("id".into()), Value::Bytes(vec![1, 2, 3])),
                ])]),
            ),
            (
                Value::Integer(5.into()),
                Value::Map(vec![
                    (Value::Text("up".into()), Value::Bool(true)),
                    (Value::Text("uv".into()), Value::Bool(true)),
                ]),
            ),
        ]));
        let got = GetAssertionRequest::decode(&req).unwrap();
        assert_eq!(got.rp_id, "example.com");
        assert_eq!(got.client_data_hash.len(), 32);
        assert_eq!(got.allow_list.len(), 1);
        assert_eq!(got.allow_list[0].id, vec![1, 2, 3]);
        assert!(got.up && got.uv);
    }

    #[test]
    fn get_assertion_discoverable_has_empty_allow_list() {
        let req = encode(Value::Map(vec![
            (Value::Integer(1.into()), Value::Text("github.com".into())),
            (Value::Integer(2.into()), Value::Bytes(vec![0; 32])),
        ]));
        let got = GetAssertionRequest::decode(&req).unwrap();
        assert!(got.allow_list.is_empty());
        assert!(got.up); // default
        assert!(!got.uv); // default
    }

    #[test]
    fn get_assertion_response_roundtrips() {
        let resp = GetAssertionResponse {
            credential: CredentialDescriptor {
                cred_type: "public-key".into(),
                id: vec![9, 8, 7],
            },
            auth_data: vec![0x11; 37],
            signature: vec![0x22; 64],
            user_handle: Some(vec![0x33; 8]),
            number_of_credentials: Some(1),
        };
        let cbor = resp.encode();
        let v: Value = coset::cbor::from_reader(&cbor[..]).unwrap();
        let Value::Map(m) = v else { panic!() };
        assert!(int_get(&m, 1).is_some()); // credential
        assert!(matches!(int_get(&m, 2), Some(Value::Bytes(b)) if b.len() == 37));
        assert!(matches!(int_get(&m, 3), Some(Value::Bytes(b)) if b.len() == 64));
        assert!(int_get(&m, 4).is_some()); // user handle
        assert_eq!(int_get(&m, 5), Some(&Value::Integer(1.into())));
    }

    #[test]
    fn make_credential_request_decodes_and_picks_algorithm() {
        let req = encode(Value::Map(vec![
            (Value::Integer(1.into()), Value::Bytes(vec![0xAB; 32])),
            (
                Value::Integer(2.into()),
                Value::Map(vec![
                    (Value::Text("id".into()), Value::Text("example.com".into())),
                    (Value::Text("name".into()), Value::Text("Example".into())),
                ]),
            ),
            (
                Value::Integer(3.into()),
                Value::Map(vec![
                    (Value::Text("id".into()), Value::Bytes(vec![1, 2, 3, 4])),
                    (Value::Text("name".into()), Value::Text("alice".into())),
                    (
                        Value::Text("displayName".into()),
                        Value::Text("Alice A".into()),
                    ),
                ]),
            ),
            (
                Value::Integer(4.into()),
                Value::Array(vec![
                    // RS256 first (rosec can't generate) then ES256.
                    Value::Map(vec![
                        (Value::Text("alg".into()), Value::Integer((-257).into())),
                        (Value::Text("type".into()), Value::Text("public-key".into())),
                    ]),
                    Value::Map(vec![
                        (Value::Text("alg".into()), Value::Integer((-7).into())),
                        (Value::Text("type".into()), Value::Text("public-key".into())),
                    ]),
                ]),
            ),
            (
                Value::Integer(7.into()),
                Value::Map(vec![(Value::Text("rk".into()), Value::Bool(true))]),
            ),
        ]));
        let got = MakeCredentialRequest::decode(&req).unwrap();
        assert_eq!(got.rp_id, "example.com");
        assert_eq!(got.rp_name.as_deref(), Some("Example"));
        assert_eq!(got.user_id, vec![1, 2, 3, 4]);
        assert_eq!(got.user_name.as_deref(), Some("alice"));
        assert_eq!(got.pub_key_cred_params.len(), 2);
        assert!(got.rk);
        // Skips RS256 (can't generate), picks ES256.
        assert_eq!(
            got.preferred_algorithm(),
            Some(super::super::sign::ALG_ES256)
        );
    }

    #[test]
    fn make_credential_response_is_none_attestation() {
        let resp = MakeCredentialResponse {
            auth_data: vec![0x44; 100],
        };
        let cbor = resp.encode();
        let v: Value = coset::cbor::from_reader(&cbor[..]).unwrap();
        let Value::Map(m) = v else { panic!() };
        assert_eq!(int_get(&m, 1), Some(&Value::Text("none".into())));
        assert!(matches!(int_get(&m, 2), Some(Value::Bytes(b)) if b.len() == 100));
        assert_eq!(int_get(&m, 3), Some(&Value::Map(vec![])));
    }

    #[test]
    fn malformed_request_is_invalid_parameter() {
        // Not a map.
        assert_eq!(
            GetAssertionRequest::decode(&encode(Value::Integer(1.into()))).unwrap_err(),
            Ctap2Status::InvalidParameter
        );
        // Missing rpId.
        let no_rp = encode(Value::Map(vec![(
            Value::Integer(2.into()),
            Value::Bytes(vec![0; 32]),
        )]));
        assert_eq!(
            GetAssertionRequest::decode(&no_rp).unwrap_err(),
            Ctap2Status::InvalidParameter
        );
    }
}
