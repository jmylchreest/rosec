//! GNOME Keyring on-disk file format parser.
//!
//! Handles two formats:
//!
//! 1. **Binary encrypted** (magic `GnomeKeyring\n\r\0\n`): most `.keyring`
//!    files.  KDF is `egg_symkey_generate_simple(GCRY_CIPHER_AES128,
//!    GCRY_MD_SHA256, ...)` — a SHA-256-based password stretching scheme
//!    (despite the file header claiming "hash = MD5").  Cipher is AES-128-CBC.
//!    An in-band MD5 hash of the decrypted payload verifies the password.
//!
//! 2. **Plaintext GKeyFile** format: used when the user has set no password.
//!    Begins with `[keyring]` and is an INI-style text file.
//!
//! Reference: `egg/egg-symkey.c` `egg_symkey_generate_simple()`,
//! `pkcs11/secret-store/gkm-secret-binary.c` in gnome-keyring source.

use std::collections::HashMap;
use std::io::{self, Cursor, Read};

use aes::Aes128;
use cbc::cipher::{BlockModeDecrypt, KeyIvInit};
use md5::Digest as _;
use zeroize::{Zeroize, Zeroizing};

// ── Wire-level constants ──────────────────────────────────────────────────────

const MAGIC: &[u8] = b"GnomeKeyring\n\r\0\n";
const MAGIC_LEN: usize = 16;

const CRYPTO_AES128_CBC: u8 = 0;
/// The file header byte for hash — confusingly labelled "MD5" (0) but
/// the actual KDF uses SHA-256.  MD5 is only used for the post-decryption
/// integrity check (`verify_decrypted_buffer` in gnome-keyring source).
const HASH_MD5: u8 = 0;
const SUPPORTED_VERSION: u16 = 0;

// ── Public types ──────────────────────────────────────────────────────────────

/// Attribute value — either a UTF-8 string or a 32-bit unsigned integer.
#[derive(Debug, Clone)]
pub enum AttributeValue {
    String(String),
    UInt32(u32),
}

/// A single item read from a GNOME Keyring file.
#[derive(Debug)]
pub struct KeyringItem {
    /// Numeric item ID from the file.
    pub id: u32,
    /// Item type from the binary format (1 = generic, 2 = network, etc.).
    pub item_type: u32,
    /// Human-readable display name.
    pub display_name: Zeroizing<String>,
    /// The raw secret bytes (decrypted).
    pub secret: Zeroizing<Vec<u8>>,
    /// Creation time as Unix epoch seconds (0 if unknown).
    pub ctime: u64,
    /// Modification time as Unix epoch seconds (0 if unknown).
    pub mtime: u64,
    /// Public (hashed) attributes — searchable without unlock.
    pub attributes: HashMap<String, AttributeValue>,
}

impl Drop for KeyringItem {
    fn drop(&mut self) {
        // display_name and secret are Zeroizing<_> and handle themselves.
        // Explicitly zeroize attribute string values in case they're sensitive.
        for val in self.attributes.values_mut() {
            if let AttributeValue::String(s) = val {
                s.zeroize();
            }
        }
    }
}

/// A parsed GNOME Keyring file — either plaintext or decrypted binary.
#[derive(Debug)]
pub struct ParsedKeyring {
    pub name: String,
    #[allow(dead_code)]
    pub ctime: u64,
    #[allow(dead_code)]
    pub mtime: u64,
    pub items: Vec<KeyringItem>,
}

// ── Top-level entry point ─────────────────────────────────────────────────────

/// Parse a `.keyring` file from `bytes`.
///
/// * For plaintext (no-password) keyrings, `password` is ignored.
/// * For encrypted keyrings, `password` is used to derive the decryption key.
///   Returns `Err` if the password is wrong (MAC/hash mismatch).
pub fn parse_keyring_file(
    bytes: &[u8],
    password: &Zeroizing<String>,
) -> Result<ParsedKeyring, KeyringError> {
    if bytes.starts_with(MAGIC) {
        parse_binary(bytes, password)
    } else if bytes.starts_with(b"[keyring]") || bytes.starts_with(b"[keyring]\n") {
        parse_plaintext(bytes)
    } else {
        Err(KeyringError::UnknownFormat)
    }
}

// ── Error type ────────────────────────────────────────────────────────────────

#[derive(Debug)]
pub enum KeyringError {
    UnknownFormat,
    TruncatedFile(&'static str),
    UnsupportedVersion(u16),
    UnsupportedCrypto(u8),
    UnsupportedHash(u8),
    WrongPassword,
    Utf8Error(std::string::FromUtf8Error),
    Io(io::Error),
}

impl std::fmt::Display for KeyringError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::UnknownFormat => write!(f, "not a GNOME Keyring file"),
            Self::TruncatedFile(section) => write!(f, "truncated file at {section}"),
            Self::UnsupportedVersion(v) => write!(f, "unsupported keyring version {v}"),
            Self::UnsupportedCrypto(c) => write!(f, "unsupported crypto algorithm {c}"),
            Self::UnsupportedHash(h) => write!(f, "unsupported hash algorithm {h}"),
            Self::WrongPassword => write!(f, "wrong password (decryption MAC mismatch)"),
            Self::Utf8Error(e) => write!(f, "UTF-8 error: {e}"),
            Self::Io(e) => write!(f, "I/O error: {e}"),
        }
    }
}

impl std::error::Error for KeyringError {}

impl From<io::Error> for KeyringError {
    fn from(e: io::Error) -> Self {
        Self::Io(e)
    }
}

impl From<std::string::FromUtf8Error> for KeyringError {
    fn from(e: std::string::FromUtf8Error) -> Self {
        Self::Utf8Error(e)
    }
}

// ── Binary format parser ──────────────────────────────────────────────────────

fn parse_binary(bytes: &[u8], password: &Zeroizing<String>) -> Result<ParsedKeyring, KeyringError> {
    let mut cur = Cursor::new(bytes);

    // Skip magic (already verified)
    cur.set_position(MAGIC_LEN as u64);

    // 2-byte version, 1-byte crypto, 1-byte hash
    let version = read_u16(&mut cur, "version")?;
    if version != SUPPORTED_VERSION {
        return Err(KeyringError::UnsupportedVersion(version));
    }
    let crypto = read_u8(&mut cur, "crypto")?;
    if crypto != CRYPTO_AES128_CBC {
        return Err(KeyringError::UnsupportedCrypto(crypto));
    }
    let hash_alg = read_u8(&mut cur, "hash")?;
    if hash_alg != HASH_MD5 {
        return Err(KeyringError::UnsupportedHash(hash_alg));
    }

    // Keyring metadata
    let name = read_string(&mut cur, "keyring name")?;
    let ctime = read_time_t(&mut cur, "ctime")?;
    let mtime = read_time_t(&mut cur, "mtime")?;
    let _flags = read_u32(&mut cur, "flags")?;
    let _lock_timeout = read_u32(&mut cur, "lock_timeout")?;
    let hash_iterations = read_u32(&mut cur, "hash_iterations")?;
    let mut salt = [0u8; 8];
    cur.read_exact(&mut salt)
        .map_err(|_| KeyringError::TruncatedFile("salt"))?;
    // 4 reserved u32s
    for _ in 0..4 {
        read_u32(&mut cur, "reserved")?;
    }

    // Hashed (unencrypted) items — public attributes only; we skip content.
    // We read them to advance the cursor to the encrypted section.
    let num_items = read_u32(&mut cur, "num_items")?;
    let mut hashed_item_ids: Vec<u32> = Vec::with_capacity(num_items as usize);
    let mut hashed_item_types: Vec<u32> = Vec::with_capacity(num_items as usize);
    for _ in 0..num_items {
        let id = read_u32(&mut cur, "item id")?;
        let item_type = read_u32(&mut cur, "item type")?;
        hashed_item_ids.push(id);
        hashed_item_types.push(item_type);
        let num_attrs = read_u32(&mut cur, "num_attributes")?;
        for _ in 0..num_attrs {
            skip_string(&mut cur, "attr name")?;
            let attr_type = read_u32(&mut cur, "attr type")?;
            match attr_type {
                0 => skip_string(&mut cur, "attr string hash")?, // string hash: 16-byte MD5
                _ => {
                    // integer: u32 hash
                    read_u32(&mut cur, "attr int hash")?;
                }
            }
        }
    }

    // Encrypted section
    let enc_len = read_u32(&mut cur, "encrypted length")? as usize;
    let mut enc_data = vec![0u8; enc_len];
    cur.read_exact(&mut enc_data)
        .map_err(|_| KeyringError::TruncatedFile("encrypted data"))?;

    // Derive decryption key from password
    let (key, iv) = derive_key_iv(password.as_bytes(), &salt, hash_iterations);

    // Decrypt in place using AES-128-CBC
    let mut plaintext = decrypt_aes128_cbc(&key, &iv, &enc_data)?;

    // First 16 bytes of plaintext are an MD5 hash of the rest (integrity check)
    if plaintext.len() < 16 {
        plaintext.zeroize();
        return Err(KeyringError::WrongPassword);
    }
    let expected_hash = &plaintext[..16].to_vec();
    let computed = md5::Md5::digest(&plaintext[16..]);
    if computed.as_slice() != expected_hash.as_slice() {
        plaintext.zeroize();
        return Err(KeyringError::WrongPassword);
    }

    // Parse the plaintext item data
    let mut pcur = Cursor::new(&plaintext[16..]);
    let items = parse_encrypted_items(&mut pcur, num_items, &hashed_item_ids, &hashed_item_types)?;

    plaintext.zeroize();

    Ok(ParsedKeyring {
        name: name.unwrap_or_default(),
        ctime,
        mtime,
        items,
    })
}

/// Derive AES-128 key (16 bytes) + IV (16 bytes) from password + salt.
///
/// This is a faithful port of `egg_symkey_generate_simple()` from
/// `egg/egg-symkey.c` in the gnome-keyring source, called with
/// `GCRY_CIPHER_AES128` (key=16, iv=16) and `GCRY_MD_SHA256` (digest=32).
///
/// Algorithm (multi-pass, though AES128+SHA256 only needs one pass):
///   - Pass 0: SHA256(password || salt), then iterate hash `iterations-1`
///     more times.
///   - Pass N (N>0): SHA256(prev_digest || password || salt), then iterate.
///   - Fill key bytes first, then IV bytes, from each pass's final digest.
fn derive_key_iv(password: &[u8], salt: &[u8; 8], iterations: u32) -> ([u8; 16], [u8; 16]) {
    // SHA-256 produces 32 bytes — exactly what we need for key(16) + IV(16).
    // So only one pass is required, but the loop handles the general case.
    const N_DIGEST: usize = 32;
    const NEEDED: usize = 32; // 16 key + 16 iv

    let mut result = Zeroizing::new([0u8; NEEDED]);
    let mut filled = 0usize;
    let mut prev_digest: Option<Zeroizing<[u8; N_DIGEST]>> = None;

    while filled < NEEDED {
        // First iteration of this pass: hash (prev_digest? || password || salt)
        let mut hasher = sha2::Sha256::new();
        if let Some(ref prev) = prev_digest {
            sha2::Digest::update(&mut hasher, prev.as_slice());
        }
        sha2::Digest::update(&mut hasher, password);
        sha2::Digest::update(&mut hasher, salt);
        let mut digest = Zeroizing::new([0u8; N_DIGEST]);
        digest.copy_from_slice(&sha2::Digest::finalize(hasher));

        // Remaining iterations: hash the digest itself
        for _ in 1..iterations {
            let mut h = sha2::Sha256::new();
            sha2::Digest::update(&mut h, digest.as_slice());
            digest.copy_from_slice(&sha2::Digest::finalize(h));
        }

        // Copy as many bytes as we still need
        let take = (NEEDED - filled).min(N_DIGEST);
        result[filled..filled + take].copy_from_slice(&digest[..take]);
        filled += take;

        prev_digest = Some(digest);
    }

    let mut key = [0u8; 16];
    let mut iv = [0u8; 16];
    key.copy_from_slice(&result[..16]);
    iv.copy_from_slice(&result[16..]);
    result.zeroize();
    (key, iv)
}

/// Decrypt AES-128-CBC. Returns plaintext or `WrongPassword` on unpad failure.
fn decrypt_aes128_cbc(
    key: &[u8; 16],
    iv: &[u8; 16],
    ciphertext: &[u8],
) -> Result<Vec<u8>, KeyringError> {
    // AES-128-CBC with zero padding (gnome-keyring pads with zeroes to block boundary)
    // The in-band MD5 hash is the real integrity check; we just need raw block decryption.
    use cbc::cipher::block_padding::NoPadding;
    type Aes128CbcDec = cbc::Decryptor<Aes128>;

    if !ciphertext.len().is_multiple_of(16) {
        return Err(KeyringError::WrongPassword);
    }

    let mut buf = ciphertext.to_vec();
    Aes128CbcDec::new(key.into(), iv.into())
        .decrypt_padded::<NoPadding>(&mut buf)
        .map_err(|_| KeyringError::WrongPassword)?;

    Ok(buf)
}

/// Parse the decrypted item payload.
fn parse_encrypted_items(
    cur: &mut Cursor<&[u8]>,
    num_items: u32,
    ids: &[u32],
    types: &[u32],
) -> Result<Vec<KeyringItem>, KeyringError> {
    let mut items = Vec::with_capacity(num_items as usize);

    for i in 0..num_items as usize {
        let id = ids.get(i).copied().unwrap_or(0);
        let item_type = types.get(i).copied().unwrap_or(0);

        let display_name =
            Zeroizing::new(read_string(cur, "item display_name")?.unwrap_or_default());
        let secret = Zeroizing::new(read_byte_array(cur, "item secret")?);

        let ctime = read_time_t(cur, "item ctime")?;
        let mtime = read_time_t(cur, "item mtime")?;

        // reserved string + 4 reserved u32s
        skip_string(cur, "reserved_str")?;
        for _ in 0..4 {
            read_u32(cur, "reserved_uint")?;
        }

        let num_attrs = read_u32(cur, "num_attributes")?;
        let mut attributes = HashMap::new();
        for _ in 0..num_attrs {
            let attr_name = read_string(cur, "attr name")?.unwrap_or_default();
            let attr_type = read_u32(cur, "attr type")?;
            let val = match attr_type {
                0 => {
                    let s = read_string(cur, "attr string val")?.unwrap_or_default();
                    AttributeValue::String(s)
                }
                _ => {
                    let n = read_u32(cur, "attr uint val")?;
                    AttributeValue::UInt32(n)
                }
            };
            attributes.insert(attr_name, val);
        }

        // ACL list — skip entirely
        let acl_len = read_u32(cur, "acl_len")?;
        for _ in 0..acl_len {
            read_u32(cur, "acl types_allowed")?;
            skip_string(cur, "acl display_name")?;
            skip_string(cur, "acl pathname")?;
            skip_string(cur, "acl reserved_str")?;
            read_u32(cur, "acl reserved_uint")?;
        }

        items.push(KeyringItem {
            id,
            item_type,
            display_name,
            secret,
            ctime,
            mtime,
            attributes,
        });
    }

    Ok(items)
}

// ── Plaintext GKeyFile format parser ─────────────────────────────────────────
//
// Format (GKeyFile / Desktop File format):
//
//   [keyring]
//   display-name=Login
//   ctime=1234567890
//   mtime=1234567890
//   lock-on-idle=false
//   lock-timeout=0
//
//   [item1]
//   display-name=GitHub
//   secret=mysecret
//   mtime=1234567890
//   ctime=1234567890
//   id=1
//   type=1
//
//   [item1:attribute0]
//   name=xdg:schema
//   type=string
//   value=org.freedesktop.Secret.Generic
//
// The item sections are `[item<N>]` and attribute sections `[item<N>:attribute<M>]`.

fn parse_plaintext(bytes: &[u8]) -> Result<ParsedKeyring, KeyringError> {
    let text = std::str::from_utf8(bytes)
        .map_err(|_| KeyringError::Utf8Error(String::from_utf8(bytes.to_vec()).unwrap_err()))?;

    // Parse into sections: section_name → key=value pairs
    let mut sections: HashMap<String, HashMap<String, String>> = HashMap::new();
    let mut current_section = String::new();

    for line in text.lines() {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        if let Some(name) = line.strip_prefix('[').and_then(|l| l.strip_suffix(']')) {
            current_section = name.to_owned();
            sections.entry(current_section.clone()).or_default();
        } else if let Some((key, val)) = line.split_once('=')
            && !current_section.is_empty()
            && !key.trim().is_empty()
        {
            sections
                .entry(current_section.clone())
                .or_default()
                .insert(key.trim().to_owned(), val.trim().to_owned());
        }
    }

    // Keyring header
    let hdr = sections.get("keyring").cloned().unwrap_or_default();
    let name = hdr.get("display-name").cloned().unwrap_or_default();
    let ctime = hdr
        .get("ctime")
        .and_then(|s| s.parse::<u64>().ok())
        .unwrap_or(0);
    let mtime = hdr
        .get("mtime")
        .and_then(|s| s.parse::<u64>().ok())
        .unwrap_or(0);

    // Collect items: sections named `item<N>` (not containing ':')
    let mut item_indices: Vec<u32> = sections
        .keys()
        .filter_map(|k| {
            k.strip_prefix("item")
                .filter(|suffix| !suffix.contains(':'))
                .and_then(|s| s.parse::<u32>().ok())
        })
        .collect();
    item_indices.sort_unstable();

    let mut items = Vec::new();
    for idx in item_indices {
        let sec_name = format!("item{idx}");
        let sec = match sections.get(&sec_name) {
            Some(s) => s.clone(),
            None => continue,
        };

        let id = sec
            .get("id")
            .and_then(|s| s.parse::<u32>().ok())
            .unwrap_or(idx);
        let item_type = sec
            .get("type")
            .and_then(|s| s.parse::<u32>().ok())
            .unwrap_or(1);
        let display_name = Zeroizing::new(sec.get("display-name").cloned().unwrap_or_default());
        let secret_str = sec.get("secret").cloned().unwrap_or_default();
        let secret = Zeroizing::new(secret_str.into_bytes());
        let item_ctime = sec
            .get("ctime")
            .and_then(|s| s.parse::<u64>().ok())
            .unwrap_or(0);
        let item_mtime = sec
            .get("mtime")
            .and_then(|s| s.parse::<u64>().ok())
            .unwrap_or(0);

        // Collect attributes: sections named `item<N>:attribute<M>`
        let mut attr_indices: Vec<u32> = sections
            .keys()
            .filter_map(|k| {
                k.strip_prefix(&format!("{sec_name}:attribute"))
                    .and_then(|s| s.parse::<u32>().ok())
            })
            .collect();
        attr_indices.sort_unstable();

        let mut attributes = HashMap::new();
        for aidx in attr_indices {
            let attr_sec = format!("{sec_name}:attribute{aidx}");
            if let Some(asec) = sections.get(&attr_sec) {
                let aname = asec.get("name").cloned().unwrap_or_default();
                let atype = asec.get("type").map(|s| s.as_str()).unwrap_or("string");
                let aval = asec.get("value").cloned().unwrap_or_default();
                let val = if atype == "uint32" {
                    aval.parse::<u32>()
                        .map(AttributeValue::UInt32)
                        .unwrap_or(AttributeValue::String(aval))
                } else {
                    AttributeValue::String(aval)
                };
                if !aname.is_empty() {
                    attributes.insert(aname, val);
                }
            }
        }

        items.push(KeyringItem {
            id,
            item_type,
            display_name,
            secret,
            ctime: item_ctime,
            mtime: item_mtime,
            attributes,
        });
    }

    Ok(ParsedKeyring {
        name,
        ctime,
        mtime,
        items,
    })
}

// ── Binary read helpers ───────────────────────────────────────────────────────

fn read_u8(cur: &mut Cursor<&[u8]>, ctx: &'static str) -> Result<u8, KeyringError> {
    let mut buf = [0u8; 1];
    cur.read_exact(&mut buf)
        .map_err(|_| KeyringError::TruncatedFile(ctx))?;
    Ok(buf[0])
}

fn read_u16(cur: &mut Cursor<&[u8]>, ctx: &'static str) -> Result<u16, KeyringError> {
    let mut buf = [0u8; 2];
    cur.read_exact(&mut buf)
        .map_err(|_| KeyringError::TruncatedFile(ctx))?;
    Ok(u16::from_be_bytes(buf))
}

fn read_u32(cur: &mut Cursor<&[u8]>, ctx: &'static str) -> Result<u32, KeyringError> {
    let mut buf = [0u8; 4];
    cur.read_exact(&mut buf)
        .map_err(|_| KeyringError::TruncatedFile(ctx))?;
    Ok(u32::from_be_bytes(buf))
}

/// GNOME Keyring time_t: two consecutive u32 values.
/// The first is seconds since epoch (Unix); the second is sub-second precision
/// that we discard.
fn read_time_t(cur: &mut Cursor<&[u8]>, ctx: &'static str) -> Result<u64, KeyringError> {
    let secs = read_u32(cur, ctx)?;
    let _subsec = read_u32(cur, ctx)?;
    Ok(secs as u64)
}

/// Read a length-prefixed UTF-8 string.
/// Length `0xffffffff` means NULL → returns `None`.
fn read_string(cur: &mut Cursor<&[u8]>, ctx: &'static str) -> Result<Option<String>, KeyringError> {
    let len = read_u32(cur, ctx)?;
    if len == 0xffff_ffff {
        return Ok(None);
    }
    let mut buf = vec![0u8; len as usize];
    cur.read_exact(&mut buf)
        .map_err(|_| KeyringError::TruncatedFile(ctx))?;
    let s = String::from_utf8(buf)?;
    Ok(Some(s))
}

/// Read a length-prefixed byte array (raw bytes, no UTF-8 validation).
/// The gnome-keyring binary format uses this for secrets:
/// `egg_buffer_get_byte_array()` in C source.
/// Length `0xffffffff` means NULL → returns empty vec.
fn read_byte_array(cur: &mut Cursor<&[u8]>, ctx: &'static str) -> Result<Vec<u8>, KeyringError> {
    let len = read_u32(cur, ctx)?;
    if len == 0xffff_ffff {
        return Ok(Vec::new());
    }
    let mut buf = vec![0u8; len as usize];
    cur.read_exact(&mut buf)
        .map_err(|_| KeyringError::TruncatedFile(ctx))?;
    Ok(buf)
}

/// Skip a length-prefixed string without allocating.
fn skip_string(cur: &mut Cursor<&[u8]>, ctx: &'static str) -> Result<(), KeyringError> {
    let len = read_u32(cur, ctx)?;
    if len == 0xffff_ffff {
        return Ok(());
    }
    let pos = cur.position();
    cur.set_position(pos + len as u64);
    // Verify we didn't go past end
    if cur.position() > cur.get_ref().len() as u64 {
        return Err(KeyringError::TruncatedFile(ctx));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn plaintext_preserves_unicode_secrets_and_typed_attributes() {
        let data = "[keyring]\ndisplay-name=Test keyring\nctime=100\nmtime=200\n\
                    [item7]\nid=42\ntype=2\ndisplay-name=Café\nsecret=synthetic=秘密\n\
                    [item7:attribute0]\nname=username\nvalue=alice\n\
                    [item7:attribute1]\nname=port\ntype=uint32\nvalue=443\n";
        let keyring = parse_keyring_file(data.as_bytes(), &Zeroizing::new(String::new())).unwrap();
        assert_eq!(keyring.name, "Test keyring");
        assert_eq!((keyring.ctime, keyring.mtime), (100, 200));
        assert_eq!(keyring.items.len(), 1);
        let item = &keyring.items[0];
        assert_eq!(item.id, 42);
        assert_eq!(item.item_type, 2);
        assert_eq!(item.display_name.as_str(), "Café");
        assert_eq!(item.secret.as_slice(), "synthetic=秘密".as_bytes());
        assert!(matches!(&item.attributes["username"], AttributeValue::String(s) if s == "alice"));
        assert!(matches!(
            item.attributes["port"],
            AttributeValue::UInt32(443)
        ));
    }

    #[test]
    fn empty_plaintext_keyring_has_no_items() {
        let keyring = parse_keyring_file(
            b"[keyring]\ndisplay-name=Empty\n",
            &Zeroizing::new(String::new()),
        )
        .unwrap();
        assert_eq!(keyring.name, "Empty");
        assert!(keyring.items.is_empty());
    }

    #[test]
    fn rejects_unknown_truncated_and_unsupported_headers() {
        let password = Zeroizing::new(String::new());
        for bytes in [b"".as_slice(), b"not a keyring"] {
            assert!(matches!(
                parse_keyring_file(bytes, &password),
                Err(KeyringError::UnknownFormat)
            ));
        }
        assert!(matches!(
            parse_keyring_file(MAGIC, &password),
            Err(KeyringError::TruncatedFile(_))
        ));
        let mut header = MAGIC.to_vec();
        header.extend_from_slice(&[0, 1]);
        assert!(matches!(
            parse_keyring_file(&header, &password),
            Err(KeyringError::UnsupportedVersion(1))
        ));
        header.truncate(MAGIC_LEN);
        header.extend_from_slice(&[0, 0, 1]);
        assert!(matches!(
            parse_keyring_file(&header, &password),
            Err(KeyringError::UnsupportedCrypto(1))
        ));
        header[MAGIC_LEN + 2] = 0;
        header.push(1);
        assert!(matches!(
            parse_keyring_file(&header, &password),
            Err(KeyringError::UnsupportedHash(1))
        ));
    }

    #[test]
    fn binary_secrets_preserve_non_utf8_and_null_bytes() {
        let data = [0, 0, 0, 3, 0xff, 0, 0x80];
        assert_eq!(
            read_byte_array(&mut Cursor::new(data.as_slice()), "secret").unwrap(),
            [0xff, 0, 0x80]
        );
        assert!(matches!(
            read_string(&mut Cursor::new(data.as_slice()), "label"),
            Err(KeyringError::Utf8Error(_))
        ));
        assert!(matches!(
            read_byte_array(&mut Cursor::new(&data[..6]), "secret"),
            Err(KeyringError::TruncatedFile("secret"))
        ));
        let null = [0xff; 4];
        assert!(
            read_byte_array(&mut Cursor::new(null.as_slice()), "secret")
                .unwrap()
                .is_empty()
        );
        assert!(
            read_string(&mut Cursor::new(null.as_slice()), "label")
                .unwrap()
                .is_none()
        );
    }
}
