//! WebAuthn `authenticatorData` assembly (spec §6.1).
//!
//! Layout:
//! ```text
//! rpIdHash (32)  ‖  flags (1)  ‖  signCount (4, big-endian)
//!   ‖ [ attestedCredentialData ]   (present iff the AT flag is set)
//!   ‖ [ extensions CBOR ]          (present iff the ED flag is set)
//! ```
//!
//! attestedCredentialData:
//! ```text
//! aaguid (16)  ‖  credentialIdLength (2, big-endian)  ‖  credentialId
//!   ‖  credentialPublicKey (COSE_Key CBOR)
//! ```
//!
//! `getAssertion` produces just the first line (no AT, usually no ED);
//! `makeCredential` includes attestedCredentialData with the new key.

use sha2::{Digest, Sha256};

/// authenticatorData flag bits (spec §6.1).
pub mod flag {
    pub const UP: u8 = 1 << 0; // user present
    pub const UV: u8 = 1 << 2; // user verified
    pub const BE: u8 = 1 << 3; // backup eligible
    pub const BS: u8 = 1 << 4; // backup state
    pub const AT: u8 = 1 << 6; // attested credential data included
    pub const ED: u8 = 1 << 7; // extension data included
}

/// SHA-256 of the relying party id — the first 32 bytes of authenticatorData.
pub fn rp_id_hash(rp_id: &str) -> [u8; 32] {
    let mut h = Sha256::new();
    h.update(rp_id.as_bytes());
    h.finalize().into()
}

/// attestedCredentialData block, present in `makeCredential` authData.
pub struct AttestedCredentialData {
    /// Authenticator AAGUID (16 bytes). rosec uses a fixed identifier.
    pub aaguid: [u8; 16],
    /// Raw credential ID bytes.
    pub credential_id: Vec<u8>,
    /// COSE_Key CBOR of the credential public key (see [`super::cose`]).
    pub cose_public_key: Vec<u8>,
}

impl AttestedCredentialData {
    fn encode_into(&self, out: &mut Vec<u8>) {
        out.extend_from_slice(&self.aaguid);
        out.extend_from_slice(&(self.credential_id.len() as u16).to_be_bytes());
        out.extend_from_slice(&self.credential_id);
        out.extend_from_slice(&self.cose_public_key);
    }
}

/// Assemble authenticatorData. `flags` is the caller-composed flag byte; the
/// AT/ED bits are set automatically to match the presence of
/// `attested`/`extensions`, so callers pass only UP/UV/BE/BS.
pub fn assemble(
    rp_id_hash: &[u8; 32],
    mut flags: u8,
    sign_count: u32,
    attested: Option<&AttestedCredentialData>,
    extensions: Option<&[u8]>,
) -> Vec<u8> {
    if attested.is_some() {
        flags |= flag::AT;
    }
    if extensions.is_some() {
        flags |= flag::ED;
    }

    let mut out = Vec::with_capacity(37);
    out.extend_from_slice(rp_id_hash);
    out.push(flags);
    out.extend_from_slice(&sign_count.to_be_bytes());
    if let Some(acd) = attested {
        acd.encode_into(&mut out);
    }
    if let Some(ext) = extensions {
        out.extend_from_slice(ext);
    }
    out
}

/// The message signed for an assertion/attestation:
/// `authenticatorData || clientDataHash`.
pub fn signed_message(auth_data: &[u8], client_data_hash: &[u8]) -> Vec<u8> {
    let mut m = Vec::with_capacity(auth_data.len() + client_data_hash.len());
    m.extend_from_slice(auth_data);
    m.extend_from_slice(client_data_hash);
    m
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rp_id_hash_is_sha256() {
        // Known SHA-256("example.com").
        let h = rp_id_hash("example.com");
        assert_eq!(
            hex(&h),
            "a379a6f6eeafb9a55e378c118034e2751e682fab9f2d30ab13d2125586ce1947"
        );
    }

    #[test]
    fn assertion_authdata_is_37_bytes_with_up() {
        let h = rp_id_hash("example.com");
        let ad = assemble(&h, flag::UP, 0, None, None);
        assert_eq!(ad.len(), 37);
        assert_eq!(&ad[0..32], &h);
        assert_eq!(ad[32], flag::UP);
        assert_eq!(&ad[33..37], &[0, 0, 0, 0]); // counter 0 (synced passkey)
    }

    #[test]
    fn uv_and_counter_encode() {
        let h = rp_id_hash("github.com");
        let ad = assemble(&h, flag::UP | flag::UV, 0x01020304, None, None);
        assert_eq!(ad[32], flag::UP | flag::UV);
        assert_eq!(&ad[33..37], &[0x01, 0x02, 0x03, 0x04]);
    }

    #[test]
    fn attested_data_sets_at_flag_and_layout() {
        let h = rp_id_hash("example.com");
        let acd = AttestedCredentialData {
            aaguid: [0xAB; 16],
            credential_id: vec![1, 2, 3, 4, 5],
            cose_public_key: vec![0xA5, 0x01, 0x02], // stand-in COSE bytes
        };
        let ad = assemble(&h, flag::UP | flag::UV, 0, Some(&acd), None);
        // AT flag set automatically.
        assert_eq!(ad[32] & flag::AT, flag::AT);
        // aaguid begins at offset 37.
        assert_eq!(&ad[37..53], &[0xAB; 16]);
        // credentialIdLength (big-endian) = 5.
        assert_eq!(&ad[53..55], &[0x00, 0x05]);
        assert_eq!(&ad[55..60], &[1, 2, 3, 4, 5]);
        assert_eq!(&ad[60..63], &[0xA5, 0x01, 0x02]);
    }

    #[test]
    fn extensions_set_ed_flag() {
        let h = rp_id_hash("example.com");
        let ext = [0xA0]; // empty CBOR map
        let ad = assemble(&h, flag::UP, 0, None, Some(&ext));
        assert_eq!(ad[32] & flag::ED, flag::ED);
        assert_eq!(ad[37], 0xA0);
    }

    #[test]
    fn signed_message_concatenates() {
        let m = signed_message(&[1, 2, 3], &[4, 5]);
        assert_eq!(m, vec![1, 2, 3, 4, 5]);
    }

    fn hex(b: &[u8]) -> String {
        b.iter().map(|x| format!("{x:02x}")).collect()
    }
}
