//! PEM key auto-detection.
//!
//! Scans arbitrary text for SSH private key PEM blocks and returns parsed
//! [`ssh_key::PrivateKey`] values.  Works on notes, passwords, and hidden
//! custom fields — no special item type required.

use ssh_key::PrivateKey;

/// PEM headers that indicate an SSH private key.
const PEM_HEADERS: &[&str] = &[
    "-----BEGIN OPENSSH PRIVATE KEY-----",
    "-----BEGIN PRIVATE KEY-----",
    "-----BEGIN RSA PRIVATE KEY-----",
    "-----BEGIN EC PRIVATE KEY-----",
    "-----BEGIN DSA PRIVATE KEY-----",
    "-----BEGIN ENCRYPTED PRIVATE KEY-----",
];

/// Extract all SSH private keys found in `text`.
///
/// Returns a `Vec` of successfully parsed keys.  Unrecognised PEM blocks and
/// parse errors are silently skipped.
pub fn extract_keys(text: &str) -> Vec<PrivateKey> {
    let mut keys = Vec::new();

    for header in PEM_HEADERS {
        let mut remaining = text;
        while let Some(start) = remaining.find(header) {
            let pem_start = start;
            // Find the matching -----END ... ----- line
            let after_header = &remaining[pem_start..];
            if let Some(end_rel) = find_pem_end(after_header) {
                let pem_block = &after_header[..end_rel];
                if let Ok(key) = PrivateKey::from_openssh(pem_block.as_bytes()) {
                    keys.push(key);
                } else {
                    // Try pkcs8 / legacy PEM via from_str (covers RSA/EC/PKCS8)
                    if let Ok(key) = pem_block.parse::<PrivateKey>() {
                        keys.push(key);
                    }
                }
                remaining = &after_header[end_rel..];
            } else {
                break;
            }
        }
    }

    keys
}

/// Find the byte offset just past the `-----END …-----` footer in `pem`.
fn find_pem_end(pem: &str) -> Option<usize> {
    let end_marker = "-----END ";
    let pos = pem.find(end_marker)?;
    // Advance past the full footer line
    let after = &pem[pos..];
    let line_end = after.find('\n').unwrap_or(after.len());
    Some(pos + line_end + 1)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn extract_no_keys_from_plain_text() {
        let result = extract_keys("hello world\nno keys here");
        assert!(result.is_empty());
    }

    #[test]
    fn extract_keys_with_garbage_around() {
        // Not a real key — just ensure the function doesn't panic on garbage PEM.
        let text = "some prefix\n-----BEGIN OPENSSH PRIVATE KEY-----\ngarbage\n-----END OPENSSH PRIVATE KEY-----\nsome suffix";
        // parse will fail on the garbage — we expect zero keys, no panic
        let keys = extract_keys(text);
        assert!(keys.is_empty());
    }
}
