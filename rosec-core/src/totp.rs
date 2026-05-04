//! RFC 6238 TOTP (Time-based One-Time Password) implementation.
//!
//! Parses `otpauth://` URIs and bare base32 secrets, then generates
//! time-based codes using HMAC-SHA1, HMAC-SHA256, or HMAC-SHA512.

use std::time::{SystemTime, UNIX_EPOCH};

use hmac::{Hmac, Mac};
use sha1::Sha1;
use sha2::{Sha256, Sha512};
use zeroize::Zeroizing;

/// Hash algorithm used for the HMAC step.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TotpAlgorithm {
    Sha1,
    Sha256,
    Sha512,
}

/// Parsed TOTP parameters — everything needed to generate a code.
#[derive(Clone)]
pub struct TotpParams {
    /// Decoded secret key (raw bytes, not base32).
    pub secret: Zeroizing<Vec<u8>>,
    /// HMAC algorithm (default: SHA1).
    pub algorithm: TotpAlgorithm,
    /// Number of output digits (default: 6).
    pub digits: u32,
    /// Time step in seconds (default: 30).
    pub period: u64,
    /// Issuer string from the URI, if present.
    pub issuer: Option<String>,
    /// Account/label from the URI, if present.
    pub account: Option<String>,
}

impl std::fmt::Debug for TotpParams {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("TotpParams")
            .field("algorithm", &self.algorithm)
            .field("digits", &self.digits)
            .field("period", &self.period)
            .field("issuer", &self.issuer)
            .field("account", &self.account)
            .field("secret", &"[redacted]")
            .finish()
    }
}

/// Errors from TOTP parsing and code generation.
#[derive(Debug, thiserror::Error)]
pub enum TotpError {
    #[error("missing TOTP secret")]
    MissingSecret,
    #[error("invalid base32 encoding")]
    InvalidBase32,
    #[error("unsupported TOTP algorithm: {0}")]
    UnsupportedAlgorithm(String),
    #[error("invalid otpauth URI: {0}")]
    InvalidUri(String),
    #[error("TOTP code generation failed: {0}")]
    GenerationFailed(String),
}

/// Parse a raw TOTP input (as stored by providers).
///
/// Accepts:
/// - `otpauth://totp/...` URIs (RFC 6238 / Google Authenticator format)
/// - `steam://...` URIs (Steam Guard — 5-digit alphanumeric, SHA1, 30s)
/// - Bare base32-encoded secrets (defaults: SHA1, 6 digits, 30s period)
pub fn parse_totp_input(raw: &[u8]) -> Result<TotpParams, TotpError> {
    let text = std::str::from_utf8(raw)
        .map_err(|_| TotpError::InvalidUri("input is not valid UTF-8".into()))?
        .trim();

    if text.starts_with("otpauth://") {
        parse_otpauth_uri(text)
    } else if text.starts_with("steam://") {
        parse_steam_uri(text)
    } else {
        // Bare base32 secret — use defaults.
        let secret = decode_base32(text)?;
        Ok(TotpParams {
            secret,
            algorithm: TotpAlgorithm::Sha1,
            digits: 6,
            period: 30,
            issuer: None,
            account: None,
        })
    }
}

fn parse_otpauth_uri(uri: &str) -> Result<TotpParams, TotpError> {
    let parsed =
        url::Url::parse(uri).map_err(|e| TotpError::InvalidUri(format!("URL parse: {e}")))?;

    // Extract account from the path: /totp/Issuer:account or /totp/account
    let path = parsed.path();
    let label = path.strip_prefix('/').unwrap_or(path);
    let account = if label.contains(':') {
        label.split_once(':').map(|(_, acct)| acct.to_string())
    } else if !label.is_empty() {
        Some(label.to_string())
    } else {
        None
    };

    let mut secret_str: Option<Zeroizing<String>> = None;
    let mut algorithm = TotpAlgorithm::Sha1;
    let mut digits: u32 = 6;
    let mut period: u64 = 30;
    let mut issuer: Option<String> = None;

    for (key, value) in parsed.query_pairs() {
        match key.as_ref() {
            "secret" => secret_str = Some(Zeroizing::new(value.into_owned())),
            "algorithm" | "algo" => {
                algorithm = match value.to_ascii_uppercase().as_str() {
                    "SHA1" => TotpAlgorithm::Sha1,
                    "SHA256" => TotpAlgorithm::Sha256,
                    "SHA512" => TotpAlgorithm::Sha512,
                    other => return Err(TotpError::UnsupportedAlgorithm(other.to_string())),
                };
            }
            "digits" => {
                digits = value
                    .parse()
                    .map_err(|_| TotpError::InvalidUri("invalid digits".into()))?;
                if !(1..=9).contains(&digits) {
                    return Err(TotpError::InvalidUri(format!(
                        "digits must be 1-9, got {digits}"
                    )));
                }
            }
            "period" => {
                period = value
                    .parse()
                    .map_err(|_| TotpError::InvalidUri("invalid period".into()))?;
                if period == 0 {
                    return Err(TotpError::InvalidUri("period must be > 0".into()));
                }
            }
            "issuer" => issuer = Some(value.into_owned()),
            _ => {}
        }
    }

    let secret = decode_base32(&secret_str.ok_or(TotpError::MissingSecret)?)?;

    Ok(TotpParams {
        secret,
        algorithm,
        digits,
        period,
        issuer,
        account,
    })
}

fn parse_steam_uri(uri: &str) -> Result<TotpParams, TotpError> {
    // steam://JBSWY3DPEHPK3PXP — secret follows the scheme
    let secret_str = uri
        .strip_prefix("steam://")
        .ok_or_else(|| TotpError::InvalidUri("missing steam:// prefix".into()))?;
    let secret = decode_base32(secret_str)?;
    Ok(TotpParams {
        secret,
        algorithm: TotpAlgorithm::Sha1,
        digits: 5,
        period: 30,
        issuer: Some("Steam".to_string()),
        account: None,
    })
}

/// Decode a base32-encoded string (case-insensitive, ignoring padding/spaces).
fn decode_base32(input: &str) -> Result<Zeroizing<Vec<u8>>, TotpError> {
    // Normalise: uppercase, strip spaces and padding.
    let cleaned: Zeroizing<String> = Zeroizing::new(
        input
            .chars()
            .filter(|c| !c.is_whitespace() && *c != '=')
            .flat_map(|c| c.to_uppercase())
            .collect(),
    );

    if cleaned.is_empty() {
        return Err(TotpError::MissingSecret);
    }

    // Re-pad to a multiple of 8 for the decoder.
    let pad_len = (8 - cleaned.len() % 8) % 8;
    let padded = Zeroizing::new(format!("{}{}", &*cleaned, "=".repeat(pad_len)));

    data_encoding::BASE32
        .decode(padded.as_bytes())
        .map(Zeroizing::new)
        .map_err(|_| TotpError::InvalidBase32)
}

/// Generate a TOTP code for a specific point in time.
pub fn generate_code(
    params: &TotpParams,
    time: SystemTime,
) -> Result<Zeroizing<String>, TotpError> {
    if params.secret.is_empty() {
        return Err(TotpError::GenerationFailed("empty secret".into()));
    }
    if params.period == 0 {
        return Err(TotpError::GenerationFailed("period is zero".into()));
    }
    if params.digits == 0 || params.digits > 9 {
        return Err(TotpError::GenerationFailed(format!(
            "digits must be 1-9, got {}",
            params.digits
        )));
    }

    let unix_secs = time
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);

    let counter = unix_secs / params.period;
    let counter_bytes = counter.to_be_bytes();

    let hash = match params.algorithm {
        TotpAlgorithm::Sha1 => {
            let mut mac = Hmac::<Sha1>::new_from_slice(&params.secret)
                .map_err(|e| TotpError::GenerationFailed(format!("HMAC init: {e}")))?;
            mac.update(&counter_bytes);
            mac.finalize().into_bytes().to_vec()
        }
        TotpAlgorithm::Sha256 => {
            let mut mac = Hmac::<Sha256>::new_from_slice(&params.secret)
                .map_err(|e| TotpError::GenerationFailed(format!("HMAC init: {e}")))?;
            mac.update(&counter_bytes);
            mac.finalize().into_bytes().to_vec()
        }
        TotpAlgorithm::Sha512 => {
            let mut mac = Hmac::<Sha512>::new_from_slice(&params.secret)
                .map_err(|e| TotpError::GenerationFailed(format!("HMAC init: {e}")))?;
            mac.update(&counter_bytes);
            mac.finalize().into_bytes().to_vec()
        }
    };

    // Dynamic truncation (RFC 4226 §5.4).
    let offset = (*hash
        .last()
        .ok_or_else(|| TotpError::GenerationFailed("empty HMAC output".into()))?
        & 0x0f) as usize;
    let binary = ((hash[offset] as u32 & 0x7f) << 24)
        | ((hash[offset + 1] as u32) << 16)
        | ((hash[offset + 2] as u32) << 8)
        | (hash[offset + 3] as u32);

    let modulus = 10u32.pow(params.digits);
    Ok(Zeroizing::new(format!(
        "{:0>width$}",
        binary % modulus,
        width = params.digits as usize
    )))
}

/// Generate a TOTP code for the current time.
pub fn generate_code_now(params: &TotpParams) -> Result<Zeroizing<String>, TotpError> {
    generate_code(params, SystemTime::now())
}

/// Seconds remaining until the current code expires.
pub fn time_remaining(params: &TotpParams) -> u64 {
    time_remaining_at(params, SystemTime::now())
}

/// Seconds remaining until the code expires, relative to the given time.
pub fn time_remaining_at(params: &TotpParams, time: SystemTime) -> u64 {
    if params.period == 0 {
        return 0;
    }
    let unix_secs = time
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);
    let elapsed = unix_secs % params.period;
    params.period - elapsed
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Duration;

    /// RFC 6238 Appendix B test vector (SHA1, 8 digits, 30s period).
    /// Secret = "12345678901234567890" (ASCII) = base32 "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ"
    const RFC_SECRET_SHA1: &str = "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ";

    fn rfc_params(alg: TotpAlgorithm, secret: &str) -> TotpParams {
        TotpParams {
            secret: decode_base32(secret).unwrap(),
            algorithm: alg,
            digits: 8,
            period: 30,
            issuer: None,
            account: None,
        }
    }

    /// RFC 6238 Appendix B test vectors for SHA1.
    #[test]
    fn rfc6238_sha1_test_vectors() {
        let params = rfc_params(TotpAlgorithm::Sha1, RFC_SECRET_SHA1);

        // T = 59 → counter = 1
        let t = UNIX_EPOCH + Duration::from_secs(59);
        assert_eq!(generate_code(&params, t).unwrap().as_str(), "94287082");

        // T = 1111111109 → counter = 37037036
        let t = UNIX_EPOCH + Duration::from_secs(1111111109);
        assert_eq!(generate_code(&params, t).unwrap().as_str(), "07081804");

        // T = 1111111111 → counter = 37037037
        let t = UNIX_EPOCH + Duration::from_secs(1111111111);
        assert_eq!(generate_code(&params, t).unwrap().as_str(), "14050471");

        // T = 1234567890 → counter = 41152263
        let t = UNIX_EPOCH + Duration::from_secs(1234567890);
        assert_eq!(generate_code(&params, t).unwrap().as_str(), "89005924");

        // T = 2000000000 → counter = 66666666
        let t = UNIX_EPOCH + Duration::from_secs(2000000000);
        assert_eq!(generate_code(&params, t).unwrap().as_str(), "69279037");

        // T = 20000000000 → counter = 666666666
        let t = UNIX_EPOCH + Duration::from_secs(20000000000);
        assert_eq!(generate_code(&params, t).unwrap().as_str(), "65353130");
    }

    /// RFC 6238 Appendix B test vectors for SHA256.
    /// Secret = "12345678901234567890123456789012" (32 bytes).
    #[test]
    fn rfc6238_sha256_test_vectors() {
        let secret_b32 = data_encoding::BASE32.encode(b"12345678901234567890123456789012");
        let params = rfc_params(TotpAlgorithm::Sha256, &secret_b32);

        let t = UNIX_EPOCH + Duration::from_secs(59);
        assert_eq!(generate_code(&params, t).unwrap().as_str(), "46119246");

        let t = UNIX_EPOCH + Duration::from_secs(1111111109);
        assert_eq!(generate_code(&params, t).unwrap().as_str(), "68084774");

        let t = UNIX_EPOCH + Duration::from_secs(1234567890);
        assert_eq!(generate_code(&params, t).unwrap().as_str(), "91819424");

        let t = UNIX_EPOCH + Duration::from_secs(2000000000);
        assert_eq!(generate_code(&params, t).unwrap().as_str(), "90698825");
    }

    /// RFC 6238 Appendix B test vectors for SHA512.
    /// Secret = "1234567890123456789012345678901234567890123456789012345678901234" (64 bytes).
    #[test]
    fn rfc6238_sha512_test_vectors() {
        let secret_b32 = data_encoding::BASE32
            .encode(b"1234567890123456789012345678901234567890123456789012345678901234");
        let params = rfc_params(TotpAlgorithm::Sha512, &secret_b32);

        let t = UNIX_EPOCH + Duration::from_secs(59);
        assert_eq!(generate_code(&params, t).unwrap().as_str(), "90693936");

        let t = UNIX_EPOCH + Duration::from_secs(1111111109);
        assert_eq!(generate_code(&params, t).unwrap().as_str(), "25091201");

        let t = UNIX_EPOCH + Duration::from_secs(1234567890);
        assert_eq!(generate_code(&params, t).unwrap().as_str(), "93441116");

        let t = UNIX_EPOCH + Duration::from_secs(2000000000);
        assert_eq!(generate_code(&params, t).unwrap().as_str(), "38618901");
    }

    #[test]
    fn parse_otpauth_uri_full() {
        let uri = b"otpauth://totp/ACME:john@example.com?secret=JBSWY3DPEHPK3PXP&algorithm=SHA256&digits=8&period=60&issuer=ACME";
        let params = parse_totp_input(uri).unwrap();
        assert_eq!(params.algorithm, TotpAlgorithm::Sha256);
        assert_eq!(params.digits, 8);
        assert_eq!(params.period, 60);
        assert_eq!(params.issuer.as_deref(), Some("ACME"));
        assert_eq!(params.account.as_deref(), Some("john@example.com"));
    }

    #[test]
    fn parse_otpauth_uri_minimal() {
        let uri = b"otpauth://totp/MyService?secret=JBSWY3DPEHPK3PXP";
        let params = parse_totp_input(uri).unwrap();
        assert_eq!(params.algorithm, TotpAlgorithm::Sha1);
        assert_eq!(params.digits, 6);
        assert_eq!(params.period, 30);
        assert_eq!(params.account.as_deref(), Some("MyService"));
    }

    #[test]
    fn parse_bare_base32() {
        let params = parse_totp_input(b"JBSWY3DPEHPK3PXP").unwrap();
        assert_eq!(params.algorithm, TotpAlgorithm::Sha1);
        assert_eq!(params.digits, 6);
        assert_eq!(params.period, 30);
        assert!(params.issuer.is_none());
    }

    #[test]
    fn parse_bare_base32_lowercase_with_spaces() {
        let params = parse_totp_input(b"jbsw y3dp ehpk 3pxp").unwrap();
        assert_eq!(
            params.secret,
            parse_totp_input(b"JBSWY3DPEHPK3PXP").unwrap().secret
        );
    }

    #[test]
    fn parse_steam_uri() {
        let params = parse_totp_input(b"steam://JBSWY3DPEHPK3PXP").unwrap();
        assert_eq!(params.digits, 5);
        assert_eq!(params.issuer.as_deref(), Some("Steam"));
    }

    #[test]
    fn parse_missing_secret_errors() {
        assert!(parse_totp_input(b"otpauth://totp/Test?issuer=Foo").is_err());
    }

    #[test]
    fn parse_empty_input_errors() {
        assert!(parse_totp_input(b"").is_err());
        assert!(parse_totp_input(b"   ").is_err());
    }

    #[test]
    fn time_remaining_is_within_period() {
        let params = TotpParams {
            secret: Zeroizing::new(vec![0x41; 20]),
            algorithm: TotpAlgorithm::Sha1,
            digits: 6,
            period: 30,
            issuer: None,
            account: None,
        };
        let remaining = time_remaining(&params);
        assert!((1..=30).contains(&remaining));
    }

    #[test]
    fn six_digit_code_is_zero_padded() {
        // Use a known time where the code starts with zeros.
        let params = TotpParams {
            secret: Zeroizing::new(b"12345678901234567890".to_vec()),
            algorithm: TotpAlgorithm::Sha1,
            digits: 6,
            period: 30,
            issuer: None,
            account: None,
        };
        let t = UNIX_EPOCH + Duration::from_secs(1111111109);
        let code = generate_code(&params, t).unwrap();
        assert_eq!(code.len(), 6);
    }
}
