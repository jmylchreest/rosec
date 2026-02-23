use rosec_core::BackendError;

/// Session encryption algorithms defined by the Secret Service specification.
///
/// `Plain` sends secrets unencrypted over the unix domain socket (adequate
/// when client and daemon share the same user session).
///
/// `DhIetf1024Sha256Aes128CbcPkcs7` negotiates a shared AES-128-CBC key via
/// Diffie-Hellman.  This is **not yet implemented** — sessions requesting it
/// will receive `NotSupported`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SessionAlgorithm {
    Plain,
}

impl SessionAlgorithm {
    pub fn parse(name: &str) -> Result<Self, BackendError> {
        match name {
            "plain" => Ok(Self::Plain),
            "dh-ietf1024-sha256-aes128-cbc-pkcs7" => Err(BackendError::NotSupported),
            _ => Err(BackendError::NotSupported),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn plain_algorithm_accepted() {
        let algo = SessionAlgorithm::parse("plain");
        assert_eq!(algo.unwrap(), SessionAlgorithm::Plain);
    }

    #[test]
    fn dh_algorithm_rejected() {
        let algo = SessionAlgorithm::parse("dh-ietf1024-sha256-aes128-cbc-pkcs7");
        assert!(algo.is_err());
    }

    #[test]
    fn unknown_algorithm_rejected() {
        let algo = SessionAlgorithm::parse("bogus");
        assert!(algo.is_err());
    }
}
