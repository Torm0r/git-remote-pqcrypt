//! Key management worker for X-Wing KEM-based repository key unlocking.
//!
//! The `keys.json` file contains a list of entries, each encapsulating the
//! repository master key for a different user's X-Wing public key.
//! The `KeyWorker` takes a user's private (decapsulation) key, scans the
//! list, and returns the unlocked master key for the matching entry.
//!
//! ## On-disk format (`keys.json`)
//! ```json
//! {
//!   "keys": [
//!     {
//!       "ciphertext": "<base64 X-Wing ciphertext, 1120 bytes raw>",
//!       "encrypted_master_key": "<base64 nonce(24) + AEAD ciphertext(32+16)>"
//!     }
//!   ]
//! }
//! ```
//!
//! ## Unlocking flow
//! 1. For each entry, decapsulate the X-Wing ciphertext with the user's private key
//!    to derive a 32-byte shared secret.
//! 2. Use that shared secret as an XChaCha20-Poly1305 key to AEAD-decrypt the
//!    `encrypted_master_key` blob.
//! 3. If AEAD authentication passes → the shared secret was correct → we found
//!    our entry. Return the decrypted repo master key.
//! 4. If authentication fails → wrong key for this entry, try the next one.

use base64::{engine::general_purpose::STANDARD as BASE64, Engine as _};
use chacha20poly1305::{
    aead::{Aead, AeadCore},
    Key, KeyInit, XChaCha20Poly1305,
};
use rand::rngs::OsRng;
use serde::{Deserialize, Serialize};
use std::io::Read;
use x_wing::{
    kem::{Decapsulate, Encapsulate},
    DecapsulationKey, EncapsulationKey,
};

// ─── On-disk types ───────────────────────────────────────────────────────────

/// A single entry in the key list: an X-Wing ciphertext paired with the
/// repo master key encrypted under the derived shared secret.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct KeyEntry {
    /// Base64-encoded X-Wing ciphertext (1120 bytes raw).
    pub ciphertext: String,
    /// Base64-encoded nonce (24 bytes) + AEAD ciphertext (32 + 16 bytes).
    pub encrypted_master_key: String,
}

/// The on-disk format of `keys.json`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct KeyFile {
    pub keys: Vec<KeyEntry>,
}

// ─── Error type ──────────────────────────────────────────────────────────────

#[derive(Debug)]
pub enum KeyWorkerError {
    /// No entry in the key file could be opened with the provided private key.
    NoMatchingKey,
    /// The key file JSON was malformed.
    InvalidKeyFile(String),
    /// An I/O error occurred reading the key source.
    Io(std::io::Error),
    /// A base64 decoding error.
    Decode(String),
    /// The ciphertext had an unexpected length.
    InvalidCiphertext,
}

impl std::fmt::Display for KeyWorkerError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::NoMatchingKey => write!(f, "No matching key found in key file"),
            Self::InvalidKeyFile(e) => write!(f, "Invalid key file: {e}"),
            Self::Io(e) => write!(f, "I/O error: {e}"),
            Self::Decode(e) => write!(f, "Decode error: {e}"),
            Self::InvalidCiphertext => write!(f, "Ciphertext has invalid length"),
        }
    }
}

impl std::error::Error for KeyWorkerError {}

impl From<std::io::Error> for KeyWorkerError {
    fn from(e: std::io::Error) -> Self {
        Self::Io(e)
    }
}

// ─── KeyWorker ───────────────────────────────────────────────────────────────

/// Holds the unlocked repository master key for the lifetime of the operation.
///
/// Created by scanning a key file against the user's X-Wing private key.
/// Once constructed, the master key is available via [`KeyWorker::master_key`]
/// for use with the `CryptoWorker`.
pub struct KeyWorker {
    master_key: Key,
}

impl KeyWorker {
    /// Unlock from a file path.
    ///
    /// Opens `keys.json` (or similar), parses it, and tries every entry
    /// against the provided decapsulation key.
    pub fn from_file(
        path: &std::path::Path,
        sk: &DecapsulationKey,
    ) -> Result<Self, KeyWorkerError> {
        let file = std::fs::File::open(path)?;
        Self::from_reader(file, sk)
    }

    /// Unlock from any `Read` source (file, stream, stdin, network, etc.).
    pub fn from_reader<R: Read>(reader: R, sk: &DecapsulationKey) -> Result<Self, KeyWorkerError> {
        let key_file: KeyFile =
            serde_json::from_reader(reader).map_err(|e| KeyWorkerError::InvalidKeyFile(e.to_string()))?;

        Self::try_unlock(&key_file, sk)
    }

    /// Returns a reference to the unlocked repo master key.
    pub fn master_key(&self) -> &Key {
        &self.master_key
    }

    // ── Internal ─────────────────────────────────────────────────────────

    /// Iterate every entry, returning the first one that decapsulates successfully.
    fn try_unlock(key_file: &KeyFile, sk: &DecapsulationKey) -> Result<Self, KeyWorkerError> {
        for entry in &key_file.keys {
            match Self::try_entry(entry, sk) {
                Ok(master_key) => return Ok(Self { master_key }),
                Err(KeyWorkerError::NoMatchingKey) => continue, // wrong entry, try next
                Err(e) => return Err(e),                        // hard error, bail
            }
        }
        Err(KeyWorkerError::NoMatchingKey)
    }

    /// Attempt to decapsulate and AEAD-verify a single key entry.
    fn try_entry(entry: &KeyEntry, sk: &DecapsulationKey) -> Result<Key, KeyWorkerError> {
        // 1. Decode the X-Wing ciphertext
        let ct_bytes = BASE64
            .decode(&entry.ciphertext)
            .map_err(|e| KeyWorkerError::Decode(e.to_string()))?;

        if ct_bytes.len() != x_wing::CIPHERTEXT_SIZE {
            return Err(KeyWorkerError::InvalidCiphertext);
        }

        let mut ct = x_wing::Ciphertext::default();
        ct.copy_from_slice(&ct_bytes);

        // 2. Decapsulate → 32-byte shared secret (always succeeds; wrong key = wrong secret)
        let shared_secret = sk.decapsulate(&ct);

        // 3. Decode the encrypted master key blob: nonce (24 bytes) + AEAD ciphertext
        let blob = BASE64
            .decode(&entry.encrypted_master_key)
            .map_err(|e| KeyWorkerError::Decode(e.to_string()))?;

        if blob.len() < 24 {
            return Err(KeyWorkerError::Decode(
                "encrypted_master_key too short for nonce".into(),
            ));
        }

        let (nonce_bytes, aead_ct) = blob.split_at(24);

        // 4. AEAD decrypt — authentication failure means wrong shared secret
        let aead_key = Key::from_slice(shared_secret.as_ref());
        let cipher = XChaCha20Poly1305::new(aead_key);
        let nonce = chacha20poly1305::XNonce::from_slice(nonce_bytes);

        let plaintext = cipher
            .decrypt(nonce, aead_ct)
            .map_err(|_| KeyWorkerError::NoMatchingKey)?;

        if plaintext.len() != 32 {
            return Err(KeyWorkerError::Decode(
                "Decrypted master key has wrong length".into(),
            ));
        }

        Ok(*Key::from_slice(&plaintext))
    }
}

// ─── Key sealing helper ──────────────────────────────────────────────────────

/// Create a new `KeyEntry` that encapsulates `master_key` for the holder
/// of the given X-Wing public (encapsulation) key.
///
/// Use this when granting a new user access to the repository:
/// ```ignore
/// let entry = seal_master_key_for(&user_pk, &repo_master_key);
/// key_file.keys.push(entry);
/// ```
pub fn seal_master_key_for(pk: &EncapsulationKey, master_key: &Key) -> KeyEntry {
    // 1. Encapsulate → (ciphertext, shared_secret)
    let (ct, shared_secret) = pk.encapsulate();

    // 2. AEAD-encrypt the master key under the shared secret
    let aead_key = Key::from_slice(shared_secret.as_ref());
    let cipher = XChaCha20Poly1305::new(aead_key);
    let nonce = XChaCha20Poly1305::generate_nonce(&mut OsRng);
    let encrypted = cipher.encrypt(&nonce, master_key.as_slice()).expect("encryption failed");

    // 3. Concatenate nonce + AEAD ciphertext and base64-encode
    let mut blob = Vec::with_capacity(24 + encrypted.len());
    blob.extend_from_slice(&nonce);
    blob.extend_from_slice(&encrypted);

    KeyEntry {
        ciphertext: BASE64.encode(&ct),
        encrypted_master_key: BASE64.encode(&blob),
    }
}
