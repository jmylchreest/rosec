//! CTAP2 ceremony orchestration.
//!
//! Ties the pure CTAP2 layers (message decode/encode, authenticatorData,
//! signing) to the passkey store and the user-gesture prompt. The store and
//! gesture are traits so the engine is testable in isolation; the real rosecd
//! wiring implements them over the Fido2 registry and rosec-prompt.

use async_trait::async_trait;
use zeroize::Zeroizing;

use super::authdata;
use super::command::{Ctap2Status, ROSEC_AAGUID};
use super::message::{
    CredentialDescriptor, GetAssertionRequest, GetAssertionResponse, MakeCredentialRequest,
    MakeCredentialResponse,
};
use super::sign::SigningKey;

/// Where the store fetches a credential's private key from.
#[derive(Debug, Clone)]
pub struct KeyRef {
    pub provider_id: String,
    pub item_id: String,
}

/// A stored passkey the engine can assert with (supplied by the registry).
#[derive(Debug, Clone)]
pub struct StoredCredential {
    pub credential_id: Vec<u8>,
    pub rp_id: String,
    pub user_handle: Option<Vec<u8>>,
    pub user_name: Option<String>,
    /// COSE algorithm id (`-7`/`-8`/`-257`).
    pub algorithm: i64,
    /// Signature counter to report; `0` for synced passkeys.
    pub counter: u32,
    pub key_ref: KeyRef,
}

impl StoredCredential {
    /// Human label for the confirmation/selection prompt.
    pub fn account_label(&self) -> String {
        let user = self.user_name.as_deref().unwrap_or("(unknown user)");
        format!("{user} — {}", self.rp_id)
    }
}

/// The engine's view of stored passkeys and their key material.
#[async_trait]
pub trait PasskeyStore: Send + Sync {
    /// Passkeys for `rp_id`. If `allow_ids` is non-empty, restrict to those
    /// credential IDs; empty means a discoverable request (all for the RP).
    async fn find(&self, rp_id: &str, allow_ids: &[Vec<u8>]) -> Vec<StoredCredential>;

    /// The credential's private key as PEM PKCS#8, fetched at ceremony time
    /// and zeroized after signing.
    async fn private_key(&self, cred: &StoredCredential) -> Result<Zeroizing<String>, Ctap2Status>;

    /// Create a new credential for `req` using `algorithm`: the store
    /// generates the keypair (provider key custody), persists the private key
    /// and metadata, and returns the new credential id plus its COSE public
    /// key for attestedCredentialData. `NotAllowed` if there is no writable
    /// passkey store.
    async fn create(
        &self,
        req: &MakeCredentialRequest,
        algorithm: i64,
    ) -> Result<CreatedCredential, Ctap2Status>;
}

/// What the store returns after minting a new credential.
#[derive(Debug, Clone)]
pub struct CreatedCredential {
    pub credential_id: Vec<u8>,
    /// COSE_Key CBOR of the new public key (see [`super::cose`]).
    pub cose_public_key: Vec<u8>,
}

/// User presence/verification, via rosec-prompt.
#[async_trait]
pub trait UserGesture: Send + Sync {
    /// Confirm use of a single account. `true` = approved (counts as UP+UV).
    async fn confirm(&self, rp_id: &str, account: &str) -> bool;

    /// Choose among several accounts; `Some(index)` or `None` if cancelled.
    async fn select(&self, rp_id: &str, accounts: &[String]) -> Option<usize>;
}

/// Run an `authenticatorGetAssertion` ceremony.
///
/// No-match is silent (`NoCredentials`, no prompt) so we never reveal to a
/// relying party — or flash a prompt — for a credential we don't hold. One
/// match confirms; several present rosec's own account chooser and return a
/// single assertion (platform-authenticator style, not CTAP paging).
pub async fn get_assertion(
    req: &GetAssertionRequest,
    store: &dyn PasskeyStore,
    gesture: &dyn UserGesture,
) -> Result<GetAssertionResponse, Ctap2Status> {
    let allow_ids: Vec<Vec<u8>> = req.allow_list.iter().map(|d| d.id.clone()).collect();
    let matches = store.find(&req.rp_id, &allow_ids).await;

    if matches.is_empty() {
        return Err(Ctap2Status::NoCredentials);
    }

    let chosen = if matches.len() == 1 {
        if !gesture
            .confirm(&req.rp_id, &matches[0].account_label())
            .await
        {
            return Err(Ctap2Status::OperationDenied);
        }
        &matches[0]
    } else {
        let labels: Vec<String> = matches.iter().map(|c| c.account_label()).collect();
        match gesture.select(&req.rp_id, &labels).await {
            Some(i) if i < matches.len() => &matches[i],
            _ => return Err(Ctap2Status::OperationDenied),
        }
    };

    let pem = store.private_key(chosen).await?;
    let key = SigningKey::from_pem(chosen.algorithm, &pem).map_err(|_| Ctap2Status::Other)?;

    let rp_hash = authdata::rp_id_hash(&req.rp_id);
    // The account confirmation/choice is the user presence + verification.
    let flags = authdata::flag::UP | authdata::flag::UV;
    let auth_data = authdata::assemble(&rp_hash, flags, chosen.counter, None, None);
    let message = authdata::signed_message(&auth_data, &req.client_data_hash);
    let signature = key.sign(&message);

    Ok(GetAssertionResponse {
        credential: CredentialDescriptor {
            cred_type: "public-key".into(),
            id: chosen.credential_id.clone(),
        },
        auth_data,
        signature,
        user_handle: chosen.user_handle.clone(),
        number_of_credentials: Some(1),
    })
}

/// Run an `authenticatorMakeCredential` (registration) ceremony.
///
/// Refuses if the relying party's `excludeList` names a credential rosec
/// already holds (`CredentialExcluded`), or if it accepts no algorithm rosec
/// can generate (`UnsupportedAlgorithm`). Registration always prompts. The
/// store mints and persists the key; the engine assembles authData with
/// attestedCredentialData under `"none"` attestation.
pub async fn make_credential(
    req: &MakeCredentialRequest,
    store: &dyn PasskeyStore,
    gesture: &dyn UserGesture,
) -> Result<MakeCredentialResponse, Ctap2Status> {
    // excludeList: refuse if we already hold one of the listed credentials.
    let exclude_ids: Vec<Vec<u8>> = req.exclude_list.iter().map(|d| d.id.clone()).collect();
    if !exclude_ids.is_empty() && !store.find(&req.rp_id, &exclude_ids).await.is_empty() {
        return Err(Ctap2Status::CredentialExcluded);
    }

    // Pick the RP's most-preferred algorithm we can generate.
    let algorithm = req
        .preferred_algorithm()
        .ok_or(Ctap2Status::UnsupportedAlgorithm)?;

    let label = format!(
        "{} — {}",
        req.user_name.as_deref().unwrap_or("new passkey"),
        req.rp_id
    );
    if !gesture.confirm(&req.rp_id, &label).await {
        return Err(Ctap2Status::OperationDenied);
    }

    let created = store.create(req, algorithm).await?;

    let acd = authdata::AttestedCredentialData {
        aaguid: ROSEC_AAGUID,
        credential_id: created.credential_id,
        cose_public_key: created.cose_public_key,
    };
    let rp_hash = authdata::rp_id_hash(&req.rp_id);
    let auth_data = authdata::assemble(
        &rp_hash,
        authdata::flag::UP | authdata::flag::UV,
        0, // new synced passkey starts at counter 0
        Some(&acd),
        None,
    );

    Ok(MakeCredentialResponse { auth_data })
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Mutex;

    const ES256_PEM: &str = "-----BEGIN PRIVATE KEY-----
MIGHAgEAMBMGByqGSM49AgEGCCqGSM49AwEHBG0wawIBAQQgzTa8ki9W2Fr5RXSQ
Uibx++X3ObXxU7hHFQcc2EpjBfShRANCAATnIl1Wh70gWgvnhUdJaxdv59jY2ZSv
Ujz/li9W7GD/hsON2LbfjwOb84yfhDiVAHEDDNbPytYRXp33/HqOjWsu
-----END PRIVATE KEY-----";

    fn cred(id: &[u8], user: &str) -> StoredCredential {
        StoredCredential {
            credential_id: id.to_vec(),
            rp_id: "example.com".into(),
            user_handle: Some(b"user-handle".to_vec()),
            user_name: Some(user.into()),
            algorithm: super::super::sign::ALG_ES256,
            counter: 0,
            key_ref: KeyRef {
                provider_id: "local".into(),
                item_id: "item-1".into(),
            },
        }
    }

    struct MockStore {
        creds: Vec<StoredCredential>,
    }

    #[async_trait]
    impl PasskeyStore for MockStore {
        async fn find(&self, rp_id: &str, allow_ids: &[Vec<u8>]) -> Vec<StoredCredential> {
            self.creds
                .iter()
                .filter(|c| c.rp_id == rp_id)
                .filter(|c| allow_ids.is_empty() || allow_ids.contains(&c.credential_id))
                .cloned()
                .collect()
        }
        async fn private_key(
            &self,
            _cred: &StoredCredential,
        ) -> Result<Zeroizing<String>, Ctap2Status> {
            Ok(Zeroizing::new(ES256_PEM.into()))
        }
        async fn create(
            &self,
            _req: &MakeCredentialRequest,
            algorithm: i64,
        ) -> Result<CreatedCredential, Ctap2Status> {
            // Derive the COSE public key from the static test key, as a real
            // store would from the key it generated.
            let key = SigningKey::from_pem(algorithm, &Zeroizing::new(ES256_PEM.into()))
                .map_err(|_| Ctap2Status::Other)?;
            let cose_public_key =
                super::super::cose::public_key_cbor(&key).map_err(|_| Ctap2Status::Other)?;
            Ok(CreatedCredential {
                credential_id: b"new-cred-id".to_vec(),
                cose_public_key,
            })
        }
    }

    /// Records the last prompt and returns scripted answers.
    struct MockGesture {
        confirm: bool,
        select: Option<usize>,
        seen: Mutex<Vec<String>>,
    }

    #[async_trait]
    impl UserGesture for MockGesture {
        async fn confirm(&self, _rp_id: &str, account: &str) -> bool {
            self.seen.lock().unwrap().push(account.to_string());
            self.confirm
        }
        async fn select(&self, _rp_id: &str, accounts: &[String]) -> Option<usize> {
            *self.seen.lock().unwrap() = accounts.to_vec();
            self.select
        }
    }

    fn req(allow: &[&[u8]]) -> GetAssertionRequest {
        GetAssertionRequest {
            rp_id: "example.com".into(),
            client_data_hash: vec![0xCD; 32],
            allow_list: allow
                .iter()
                .map(|id| CredentialDescriptor {
                    cred_type: "public-key".into(),
                    id: id.to_vec(),
                })
                .collect(),
            up: true,
            uv: false,
        }
    }

    #[tokio::test]
    async fn no_match_is_silent_no_credentials() {
        let store = MockStore { creds: vec![] };
        let gesture = MockGesture {
            confirm: true,
            select: None,
            seen: Mutex::new(vec![]),
        };
        let err = get_assertion(&req(&[]), &store, &gesture)
            .await
            .unwrap_err();
        assert_eq!(err, Ctap2Status::NoCredentials);
        // No prompt was shown.
        assert!(gesture.seen.lock().unwrap().is_empty());
    }

    #[tokio::test]
    async fn single_match_confirmed_produces_valid_assertion() {
        let store = MockStore {
            creds: vec![cred(b"cred-1", "alice")],
        };
        let gesture = MockGesture {
            confirm: true,
            select: None,
            seen: Mutex::new(vec![]),
        };
        let resp = get_assertion(&req(&[]), &store, &gesture).await.unwrap();
        assert_eq!(resp.credential.id, b"cred-1");
        assert_eq!(resp.number_of_credentials, Some(1));
        assert_eq!(resp.auth_data.len(), 37); // rpIdHash+flags+counter, no ACD

        // UP and UV flags set.
        let flags = resp.auth_data[32];
        assert_eq!(flags & authdata::flag::UP, authdata::flag::UP);
        assert_eq!(flags & authdata::flag::UV, authdata::flag::UV);

        // Signature verifies over authData || clientDataHash with the pubkey.
        use p256::ecdsa::signature::Verifier;
        use p256::pkcs8::DecodePrivateKey;
        let sk = p256::SecretKey::from_pkcs8_pem(ES256_PEM).unwrap();
        let vk = p256::ecdsa::VerifyingKey::from(sk.public_key());
        let msg = authdata::signed_message(&resp.auth_data, &req(&[]).client_data_hash);
        let sig = p256::ecdsa::Signature::from_der(&resp.signature).unwrap();
        assert!(vk.verify(&msg, &sig).is_ok());
    }

    #[tokio::test]
    async fn single_match_declined_is_denied() {
        let store = MockStore {
            creds: vec![cred(b"cred-1", "alice")],
        };
        let gesture = MockGesture {
            confirm: false,
            select: None,
            seen: Mutex::new(vec![]),
        };
        let err = get_assertion(&req(&[]), &store, &gesture)
            .await
            .unwrap_err();
        assert_eq!(err, Ctap2Status::OperationDenied);
    }

    #[tokio::test]
    async fn multiple_matches_use_selection() {
        let store = MockStore {
            creds: vec![cred(b"cred-1", "alice"), cred(b"cred-2", "bob")],
        };
        let gesture = MockGesture {
            confirm: false,
            select: Some(1), // choose bob
            seen: Mutex::new(vec![]),
        };
        let resp = get_assertion(&req(&[]), &store, &gesture).await.unwrap();
        assert_eq!(resp.credential.id, b"cred-2");
        // The chooser saw both accounts.
        assert_eq!(gesture.seen.lock().unwrap().len(), 2);
    }

    #[tokio::test]
    async fn selection_cancelled_is_denied() {
        let store = MockStore {
            creds: vec![cred(b"cred-1", "alice"), cred(b"cred-2", "bob")],
        };
        let gesture = MockGesture {
            confirm: false,
            select: None, // cancel
            seen: Mutex::new(vec![]),
        };
        let err = get_assertion(&req(&[]), &store, &gesture)
            .await
            .unwrap_err();
        assert_eq!(err, Ctap2Status::OperationDenied);
    }

    #[tokio::test]
    async fn allow_list_restricts_matches() {
        let store = MockStore {
            creds: vec![cred(b"cred-1", "alice"), cred(b"cred-2", "bob")],
        };
        let gesture = MockGesture {
            confirm: true,
            select: None,
            seen: Mutex::new(vec![]),
        };
        // allow only cred-2 → single match → confirm path, no selection.
        let resp = get_assertion(&req(&[b"cred-2"]), &store, &gesture)
            .await
            .unwrap();
        assert_eq!(resp.credential.id, b"cred-2");
    }

    fn mkreq(algs: &[i64], exclude: &[&[u8]]) -> MakeCredentialRequest {
        use super::super::message::CredParam;
        MakeCredentialRequest {
            client_data_hash: vec![0xCD; 32],
            rp_id: "example.com".into(),
            rp_name: Some("Example".into()),
            user_id: b"user-1".to_vec(),
            user_name: Some("alice".into()),
            user_display_name: Some("Alice".into()),
            pub_key_cred_params: algs
                .iter()
                .map(|a| CredParam {
                    alg: *a,
                    cred_type: "public-key".into(),
                })
                .collect(),
            exclude_list: exclude
                .iter()
                .map(|id| CredentialDescriptor {
                    cred_type: "public-key".into(),
                    id: id.to_vec(),
                })
                .collect(),
            rk: true,
            up: true,
            uv: false,
        }
    }

    #[tokio::test]
    async fn make_credential_confirmed_builds_attested_authdata() {
        let store = MockStore { creds: vec![] };
        let gesture = MockGesture {
            confirm: true,
            select: None,
            seen: Mutex::new(vec![]),
        };
        let resp = make_credential(
            &mkreq(&[super::super::sign::ALG_ES256], &[]),
            &store,
            &gesture,
        )
        .await
        .unwrap();
        // AT flag set, attestedCredentialData present.
        assert_eq!(resp.auth_data[32] & authdata::flag::AT, authdata::flag::AT);
        // aaguid (offset 37..53) is the rosec AAGUID.
        assert_eq!(&resp.auth_data[37..53], &ROSEC_AAGUID);
        // credentialIdLength then id.
        let id_len = u16::from_be_bytes([resp.auth_data[53], resp.auth_data[54]]) as usize;
        assert_eq!(&resp.auth_data[55..55 + id_len], b"new-cred-id");
        // The trailing COSE key parses.
        use coset::CborSerializable;
        let cose = resp.auth_data[55 + id_len..].to_vec();
        assert!(coset::CoseKey::from_slice(&cose).is_ok());
    }

    #[tokio::test]
    async fn make_credential_excluded_is_refused() {
        let store = MockStore {
            creds: vec![cred(b"known", "alice")],
        };
        let gesture = MockGesture {
            confirm: true,
            select: None,
            seen: Mutex::new(vec![]),
        };
        let err = make_credential(
            &mkreq(&[super::super::sign::ALG_ES256], &[b"known"]),
            &store,
            &gesture,
        )
        .await
        .unwrap_err();
        assert_eq!(err, Ctap2Status::CredentialExcluded);
    }

    #[tokio::test]
    async fn make_credential_no_acceptable_algorithm() {
        let store = MockStore { creds: vec![] };
        let gesture = MockGesture {
            confirm: true,
            select: None,
            seen: Mutex::new(vec![]),
        };
        // RS256 only — rosec won't generate it.
        let err = make_credential(
            &mkreq(&[super::super::sign::ALG_RS256], &[]),
            &store,
            &gesture,
        )
        .await
        .unwrap_err();
        assert_eq!(err, Ctap2Status::UnsupportedAlgorithm);
    }

    #[tokio::test]
    async fn make_credential_declined_is_denied() {
        let store = MockStore { creds: vec![] };
        let gesture = MockGesture {
            confirm: false,
            select: None,
            seen: Mutex::new(vec![]),
        };
        let err = make_credential(
            &mkreq(&[super::super::sign::ALG_ES256], &[]),
            &store,
            &gesture,
        )
        .await
        .unwrap_err();
        assert_eq!(err, Ctap2Status::OperationDenied);
    }
}
