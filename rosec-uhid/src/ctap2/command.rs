//! CTAP2 command dispatch and status codes (CTAP spec §6).
//!
//! A CTAP2 message is a single command byte followed by an optional CBOR
//! request map. The response is a status byte (`0x00` on success) followed by
//! an optional CBOR response map. This module covers the command framing and
//! the `authenticatorGetInfo` response; the request/response bodies for
//! make/get live alongside in the ceremony engine.

use coset::CborSerializable;

/// CTAP2 command bytes (the first byte of a CBOR message).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Command {
    MakeCredential,
    GetAssertion,
    GetInfo,
    GetNextAssertion,
    Reset,
    /// A command byte we don't implement.
    Unknown(u8),
}

impl Command {
    pub fn from_byte(b: u8) -> Self {
        match b {
            0x01 => Self::MakeCredential,
            0x02 => Self::GetAssertion,
            0x04 => Self::GetInfo,
            0x08 => Self::GetNextAssertion,
            0x07 => Self::Reset,
            other => Self::Unknown(other),
        }
    }
}

/// CTAP2 status codes (CTAP spec §11.2.4). The response's leading byte.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum Ctap2Status {
    Ok = 0x00,
    InvalidCommand = 0x01,
    InvalidParameter = 0x02,
    InvalidLength = 0x03,
    OperationDenied = 0x27,
    UnsupportedAlgorithm = 0x26,
    NoCredentials = 0x2b,
    CredentialExcluded = 0x19,
    UserActionTimeout = 0x2f,
    NotAllowed = 0x30,
    Other = 0x7f,
}

/// rosec's authenticator AAGUID — a fixed identifier for this virtual
/// authenticator (not a certified vendor AAGUID). Embedded in
/// attestedCredentialData and reported by `getInfo`.
pub const ROSEC_AAGUID: [u8; 16] = [
    0x72, 0x30, 0x73, 0x65, 0x63, 0x2d, 0x75, 0x68, 0x69, 0x64, 0x2d, 0x61, 0x75, 0x74, 0x68, 0x00,
];

/// Build the CBOR body of an `authenticatorGetInfo` response (the bytes after
/// the `0x00` status byte). Advertises FIDO2, resident keys, and that user
/// presence/verification are available (our UV is the rosec-prompt
/// confirmation).
pub fn get_info_response() -> Vec<u8> {
    use coset::cbor::value::Value;

    // options map: rk (discoverable creds), up (user presence), uv (user
    // verification — satisfied by rosec-prompt).
    let options = Value::Map(vec![
        (Value::Text("rk".into()), Value::Bool(true)),
        (Value::Text("up".into()), Value::Bool(true)),
        (Value::Text("uv".into()), Value::Bool(true)),
    ]);

    let map = Value::Map(vec![
        // 0x01 versions
        (
            Value::Integer(1.into()),
            Value::Array(vec![
                Value::Text("FIDO_2_0".into()),
                Value::Text("FIDO_2_1".into()),
            ]),
        ),
        // 0x03 aaguid
        (
            Value::Integer(3.into()),
            Value::Bytes(ROSEC_AAGUID.to_vec()),
        ),
        // 0x04 options
        (Value::Integer(4.into()), options),
    ]);

    map.to_vec().expect("getInfo CBOR encodes")
}

#[cfg(test)]
mod tests {
    use super::*;
    use coset::cbor::value::Value;

    #[test]
    fn command_bytes_map() {
        assert_eq!(Command::from_byte(0x01), Command::MakeCredential);
        assert_eq!(Command::from_byte(0x02), Command::GetAssertion);
        assert_eq!(Command::from_byte(0x04), Command::GetInfo);
        assert_eq!(Command::from_byte(0x08), Command::GetNextAssertion);
        assert_eq!(Command::from_byte(0xFE), Command::Unknown(0xFE));
    }

    #[test]
    fn get_info_advertises_fido2_and_options() {
        let cbor = get_info_response();
        let val: Value = coset::cbor::from_reader(&cbor[..]).unwrap();
        let Value::Map(entries) = val else {
            panic!("getInfo is a map")
        };

        // versions (key 1) includes FIDO_2_0.
        let versions = entries
            .iter()
            .find(|(k, _)| matches!(k, Value::Integer(i) if *i == 1.into()))
            .map(|(_, v)| v)
            .expect("versions present");
        let Value::Array(vs) = versions else {
            panic!("versions is array")
        };
        assert!(vs.contains(&Value::Text("FIDO_2_0".into())));

        // aaguid (key 3) is 16 bytes.
        let aaguid = entries
            .iter()
            .find(|(k, _)| matches!(k, Value::Integer(i) if *i == 3.into()))
            .map(|(_, v)| v)
            .expect("aaguid present");
        assert!(matches!(aaguid, Value::Bytes(b) if b.len() == 16));

        // options (key 4) has rk/up/uv = true.
        let options = entries
            .iter()
            .find(|(k, _)| matches!(k, Value::Integer(i) if *i == 4.into()))
            .map(|(_, v)| v)
            .expect("options present");
        let Value::Map(opts) = options else {
            panic!("options is map")
        };
        for name in ["rk", "up", "uv"] {
            let found = opts
                .iter()
                .any(|(k, v)| matches!(k, Value::Text(t) if t == name) && *v == Value::Bool(true));
            assert!(found, "option {name} = true");
        }
    }

    #[test]
    fn status_codes_are_spec_values() {
        assert_eq!(Ctap2Status::Ok as u8, 0x00);
        assert_eq!(Ctap2Status::NoCredentials as u8, 0x2b);
        assert_eq!(Ctap2Status::OperationDenied as u8, 0x27);
        assert_eq!(Ctap2Status::CredentialExcluded as u8, 0x19);
    }
}
