use crate::storage::Storage;
use anyhow::{anyhow, Result};
use base64::prelude::*;
use hpke::{aead::ChaCha20Poly1305, kdf::HkdfSha384, kem::XWing, Deserializable, Serializable};
//use hpke::kem::Kem;
use rand::RngCore;
use serde::{Deserialize, Serialize};
use std::env;
use std::path::Path;
use std::process::Command;
use zeroize::Zeroizing;

const ENV_KEY_PATH: &str = "PQCRYPT_KEY_PATH";

type Kem = XWing;

type Aead = ChaCha20Poly1305;
type Kdf = HkdfSha384;

#[derive(Debug, Serialize, Deserialize)]
pub struct KeysJson {
    #[serde(rename = "masterKey")]
    pub master_key_encapsulations: Vec<KeyEncapsulation>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct KeyEncapsulation {
    #[serde(rename = "publicKey")]
    pub public_key: String,
    #[serde(rename = "encapsulatedKey")]
    pub encapsulated_key: String,
    #[serde(rename = "authTag")]
    pub auth_tag: String,
    #[serde(rename = "wrappedMasterKey")]
    pub wrapped_master_key: String,
}

pub struct KeyWorker<S: Storage> {
    storage: S,
    repo_url: String,
}

async fn load_key_from_file(path: &str) -> Result<<Kem as hpke::kem::Kem>::PrivateKey> {
    let key_b64 = Zeroizing::new(tokio::fs::read_to_string(path).await?);
    let key_bytes = Zeroizing::new(BASE64_STANDARD.decode(key_b64.trim())?);
    <Kem as hpke::kem::Kem>::PrivateKey::from_bytes(&key_bytes)
        .map_err(|_| anyhow!("Invalid private key format at {}", path))
}

impl<S: Storage + Clone + Send + Sync> KeyWorker<S> {
    pub fn new(storage: S, repo_url: String) -> Self {
        KeyWorker { storage, repo_url }
    }

    pub fn get_aad(&self) -> &[u8] {
        &[]
    }

    pub async fn get_local_key(&self) -> Result<<Kem as hpke::kem::Kem>::PrivateKey> {
        // 1. Environment variable
        if let Ok(path) = env::var(ENV_KEY_PATH) {
            if !path.is_empty() {
                return load_key_from_file(&path).await;
            }
        }

        // 2. Git local config
        if let Ok(output) = Command::new("git")
            .args(["config", "--get", "pqcrypt.keypath"])
            .output()
        {
            if output.status.success() {
                let path = String::from_utf8(output.stdout)?.trim().to_string();
                if !path.is_empty() {
                    return load_key_from_file(&path).await;
                }
            }
        }

        // 3. Workspace directory: .pqcrypt/key
        if Path::new(".pqcrypt/key").exists() {
            return load_key_from_file(".pqcrypt/key").await;
        }

        // 4. Global directory scan against keys.json
        let global_dir = dirs::home_dir()
            .ok_or_else(|| anyhow!("No home directory"))?
            .join(".config/pqcrypt");
        if global_dir.exists() {
            return self.find_matching_key(&global_dir).await;
        }

        Err(anyhow!("No suitable private key found"))
    }

    async fn find_matching_key(
        &self,
        key_dir: &Path,
    ) -> Result<<Kem as hpke::kem::Kem>::PrivateKey> {
        let raw_json = self.storage.get("keys.json").await?;
        let public_keys: KeysJson = serde_json::from_slice(&raw_json)?;

        let mut entries = tokio::fs::read_dir(key_dir).await?;
        while let Some(entry) = entries.next_entry().await? {
            let path = entry.path();
            if !path.is_file() {
                continue;
            }
            let sk = match load_key_from_file(&path.to_string_lossy()).await {
                Ok(sk) => sk,
                Err(_) => continue,
            };
            let pk = <Kem as hpke::kem::Kem>::sk_to_pk(&sk);
            let pk_bytes = pk.to_bytes();
            for enc in &public_keys.master_key_encapsulations {
                if let Ok(enc_pk) = BASE64_STANDARD.decode(&enc.public_key) {
                    if enc_pk == pk_bytes.as_slice() {
                        return Ok(sk);
                    }
                }
            }
        }
        Err(anyhow!("No matching key found in {}", key_dir.display()))
    }

    pub async fn add_new_master_key(&self) -> Result<()> {
        let local_sk = self.get_local_key().await?;
        let local_pk = <Kem as hpke::kem::Kem>::sk_to_pk(&local_sk);

        let mut master_key = Zeroizing::new(vec![0u8; 32]);
        rand::rngs::OsRng.fill_bytes(&mut master_key);

        let (encapsulated_key, mut sender_ctx) = hpke::setup_sender::<Aead, Kdf, Kem>(
            &hpke::OpModeS::Base,
            &local_pk,
            self.repo_url.as_bytes(),
        )
        .map_err(|e| anyhow!("HPKE setup failed: {}", e))?;

        let mut ciphertext = master_key.clone();
        let auth_tag = sender_ctx
            .seal_inout_detached(
                hpke::inout::InOutBuf::from(&mut ciphertext[..]),
                self.get_aad(),
            )
            .map_err(|e| anyhow!("HPKE seal failed: {}", e))?;

        let keys_json = KeysJson {
            master_key_encapsulations: vec![KeyEncapsulation {
                public_key: BASE64_STANDARD.encode(local_pk.to_bytes()),
                encapsulated_key: BASE64_STANDARD.encode(encapsulated_key.to_bytes()),
                auth_tag: BASE64_STANDARD.encode(auth_tag.to_bytes()),
                wrapped_master_key: BASE64_STANDARD.encode(ciphertext),
            }],
        };

        self.storage
            .put("keys.json", serde_json::to_string(&keys_json)?.into_bytes())
            .await?;
        Ok(())
    }

    pub async fn unlock_master_key(&self) -> Result<Zeroizing<Vec<u8>>> {
        let local_sk = self.get_local_key().await?;
        let local_pk = <Kem as hpke::kem::Kem>::sk_to_pk(&local_sk);
        let local_pk_bytes = local_pk.to_bytes();

        let raw_json = self.storage.get("keys.json").await?;
        let keys: KeysJson = serde_json::from_slice(&raw_json)?;

        for enc in keys.master_key_encapsulations {
            let pk_bytes = BASE64_STANDARD.decode(&enc.public_key)?;
            if pk_bytes == local_pk_bytes.as_slice() {
                let enc_key = <Kem as hpke::kem::Kem>::EncappedKey::from_bytes(
                    &BASE64_STANDARD.decode(&enc.encapsulated_key)?,
                )
                .map_err(|_| anyhow!("Invalid enc key"))?;

                let mut ciphertext =
                    Zeroizing::new(BASE64_STANDARD.decode(&enc.wrapped_master_key)?);
                let auth_tag_bytes = BASE64_STANDARD.decode(&enc.auth_tag)?;

                // Fix: Use concrete AeadTag type instead of trait associated type
                let auth_tag = hpke::aead::AeadTag::<Aead>::from_bytes(&auth_tag_bytes)
                    .map_err(|_| anyhow!("Invalid authentication tag"))?;

                let mut receiver_ctx = hpke::setup_receiver::<Aead, Kdf, Kem>(
                    &hpke::OpModeR::Base,
                    &local_sk,
                    &enc_key,
                    self.repo_url.as_bytes(),
                )
                .map_err(|e| anyhow!("HPKE receiver setup failed: {}", e))?;

                receiver_ctx
                    .open_inout_detached(
                        hpke::inout::InOutBuf::from(&mut ciphertext[..]),
                        self.get_aad(),
                        &auth_tag,
                    )
                    .map_err(|e| anyhow!("HPKE open failed: {}", e))?;

                if ciphertext.len() != 32 {
                    return Err(anyhow!("Invalid key length"));
                }
                return Ok(ciphertext);
            }
        }
        Err(anyhow!("User not authorized"))
    }

    pub async fn add_user(&self, new_pubkey_b64: &str) -> Result<()> {
        let mut master_key = self.unlock_master_key().await?;

        let pk_bytes = BASE64_STANDARD.decode(new_pubkey_b64)?;
        let new_pubkey = <Kem as hpke::kem::Kem>::PublicKey::from_bytes(&pk_bytes)
            .map_err(|_| anyhow!("Invalid pubkey format"))?;

        let (encapsulated_key, mut sender_ctx) = hpke::setup_sender::<Aead, Kdf, Kem>(
            &hpke::OpModeS::Base,
            &new_pubkey,
            self.repo_url.as_bytes(),
        )
        .map_err(|e| anyhow!("HPKE setup failed: {}", e))?;

        let auth_tag = sender_ctx
            .seal_inout_detached(
                hpke::inout::InOutBuf::from(&mut master_key[..]),
                self.get_aad(),
            )
            .map_err(|e| anyhow!("HPKE seal failed: {}", e))?;

        let new_enc = KeyEncapsulation {
            public_key: BASE64_STANDARD.encode(new_pubkey.to_bytes()),
            encapsulated_key: BASE64_STANDARD.encode(encapsulated_key.to_bytes()),
            auth_tag: BASE64_STANDARD.encode(auth_tag.to_bytes()),
            wrapped_master_key: BASE64_STANDARD.encode(&master_key[..]),
        };

        let current_keys = self.storage.get("keys.json").await?;
        let mut keys_json: KeysJson = serde_json::from_slice(&current_keys)?;

        if keys_json
            .master_key_encapsulations
            .iter()
            .any(|v| v.public_key == new_enc.public_key)
        {
            return Err(anyhow!("Public key already exists"));
        }

        keys_json.master_key_encapsulations.push(new_enc);

        self.storage
            .put("keys.json", serde_json::to_string(&keys_json)?.into_bytes())
            .await?;
        Ok(())
    }
}
