//! CTAP2 ceremony engine — the authenticator semantics layer.
//!
//! Sits above [`crate::ctaphid`] (transport) and below the CTAP2 CBOR command
//! dispatch. Built in-house rather than on `passkey-authenticator` because
//! rosec needs multi-algorithm signing (ES256/EdDSA/RS256) over keys the
//! *provider* owns and hands over at ceremony time — neither of which that
//! crate supports (ES256-only; generates its own keys at registration).

pub mod authdata;
pub mod cose;
pub mod sign;
