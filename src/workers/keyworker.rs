use crate::storage::Storage;
use anyhow::{anyhow, Result};
use base64::prelude::*;
use hpke::{
    aead::ChaCha20Poly1305, kdf::HkdfSha384, kem::XWing, Deserializable, Kem as HpkeKem,
    Serializable,
};
use rand::RngCore;
use serde::{Deserialize, Serialize};
use std::env;
use std::path::{Path, PathBuf};
use std::process::Command;
use zeroize::Zeroizing;

const ENV_KEY_PATH: &str = "PQCRYPT_KEY_PATH";
const DEFAULT_KEY_SUBPATH: &str = ".config/pqcrypt/key";

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
    #[serde(rename = "comment", default, skip_serializing_if = "String::is_empty")]
    pub comment: String,
}

pub enum InitKeyResult {
    Existing,
    Generated { pubkey_b64: String, path: PathBuf },
}

pub struct KeyWorker<S: Storage> {
    storage: S,
    repo_url: String,
}

fn get_default_key_path() -> Result<PathBuf> {
    dirs::home_dir()
        .ok_or_else(|| anyhow!("No home directory found"))
        .map(|home| home.join(DEFAULT_KEY_SUBPATH))
}

async fn load_key_from_file(path: &Path) -> Result<<Kem as HpkeKem>::PrivateKey> {
    let key_b64 = Zeroizing::new(tokio::fs::read_to_string(path).await?);
    let key_bytes = Zeroizing::new(BASE64_STANDARD.decode(key_b64.trim())?);
    <Kem as HpkeKem>::PrivateKey::from_bytes(&key_bytes)
        .map_err(|_| anyhow!("Invalid private key format at {}", path.display()))
}

pub async fn resolve_or_generate_init_key(
    key_path: Option<PathBuf>,
) -> Result<(<Kem as HpkeKem>::PrivateKey, InitKeyResult)> {
    if let Some(path) = key_path {
        let sk = load_key_from_file(&path).await?;
        return Ok((sk, InitKeyResult::Existing));
    }

    let default_path = get_default_key_path()?;
    if default_path.exists() {
        let sk = load_key_from_file(&default_path).await?;
        return Ok((sk, InitKeyResult::Existing));
    }

    if let Some(parent) = default_path.parent() {
        tokio::fs::create_dir_all(parent).await?;
    }

    let (sk, pk) = Kem::gen_keypair();
    tokio::fs::write(&default_path, BASE64_STANDARD.encode(sk.to_bytes())).await?;

    let pubkey_b64 = BASE64_STANDARD.encode(pk.to_bytes());
    Ok((
        sk,
        InitKeyResult::Generated {
            pubkey_b64,
            path: default_path,
        },
    ))
}

pub fn generate_and_save_keypair(output_path: &Path) -> Result<String> {
    if let Some(parent) = output_path.parent() {
        std::fs::create_dir_all(parent)?;
    }
    let (sk, pk) = Kem::gen_keypair();
    std::fs::write(output_path, BASE64_STANDARD.encode(sk.to_bytes()))?;
    Ok(BASE64_STANDARD.encode(pk.to_bytes()))
}

pub async fn get_pubkey_from_file(path: &Path) -> Result<String> {
    let b64 = Zeroizing::new(tokio::fs::read_to_string(path).await?);
    let key_bytes = Zeroizing::new(BASE64_STANDARD.decode(b64.trim())?);
    let sk = <Kem as HpkeKem>::PrivateKey::from_bytes(&key_bytes)
        .map_err(|_| anyhow!("Invalid private key format at {}", path.display()))?;
    let pk = Kem::sk_to_pk(&sk);
    Ok(BASE64_STANDARD.encode(pk.to_bytes()))
}

impl<S: Storage + Clone + Send + Sync> KeyWorker<S> {
    pub fn new(storage: S, repo_url: String) -> Self {
        KeyWorker { storage, repo_url }
    }

    pub async fn get_local_key(&self) -> Result<<Kem as HpkeKem>::PrivateKey> {
        if let Ok(path_str) = env::var(ENV_KEY_PATH) {
            if !path_str.is_empty() {
                return load_key_from_file(Path::new(&path_str)).await;
            }
        }

        if let Ok(output) = Command::new("git")
            .args(["config", "--get", "pqcrypt.keypath"])
            .output()
        {
            if output.status.success() {
                let path_str = String::from_utf8(output.stdout)?.trim().to_string();
                if !path_str.is_empty() {
                    return load_key_from_file(Path::new(&path_str)).await;
                }
            }
        }

        if Path::new(".pqcrypt/key").exists() {
            return load_key_from_file(Path::new(".pqcrypt/key")).await;
        }

        let global_dir = dirs::home_dir()
            .ok_or_else(|| anyhow!("No home directory"))?
            .join(".config/pqcrypt");
        if global_dir.exists() {
            return self.find_matching_key(&global_dir).await;
        }

        Err(anyhow!("No suitable private key found"))
    }

    async fn find_matching_key(&self, key_dir: &Path) -> Result<<Kem as HpkeKem>::PrivateKey> {
        let raw_json = self.storage.get("keys.json").await?;
        let public_keys: KeysJson = serde_json::from_slice(&raw_json)?;

        let mut entries = tokio::fs::read_dir(key_dir).await?;
        while let Some(entry) = entries.next_entry().await? {
            let path = entry.path();
            if !path.is_file() {
                continue;
            }
            let sk = match load_key_from_file(&path).await {
                Ok(sk) => sk,
                Err(_) => continue,
            };
            let pk = <Kem as HpkeKem>::sk_to_pk(&sk);
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

    pub async fn add_new_master_key(
        &self,
        local_sk: &<Kem as HpkeKem>::PrivateKey,
        comment: &str,
    ) -> Result<()> {
        let local_pk = <Kem as HpkeKem>::sk_to_pk(local_sk);
        let aad = comment.as_bytes();

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
            .seal_inout_detached(hpke::inout::InOutBuf::from(&mut ciphertext[..]), aad)
            .map_err(|e| anyhow!("HPKE seal failed: {}", e))?;

        let keys_json = KeysJson {
            master_key_encapsulations: vec![KeyEncapsulation {
                public_key: BASE64_STANDARD.encode(local_pk.to_bytes()),
                encapsulated_key: BASE64_STANDARD.encode(encapsulated_key.to_bytes()),
                auth_tag: BASE64_STANDARD.encode(auth_tag.to_bytes()),
                wrapped_master_key: BASE64_STANDARD.encode(ciphertext),
                comment: comment.to_string(),
            }],
        };

        self.storage
            .put("keys.json", serde_json::to_string(&keys_json)?.into_bytes())
            .await?;
        Ok(())
    }

    pub async fn unlock_master_key(&self) -> Result<Zeroizing<Vec<u8>>> {
        let local_sk = self.get_local_key().await?;
        let local_pk = <Kem as HpkeKem>::sk_to_pk(&local_sk);
        let local_pk_bytes = local_pk.to_bytes();

        let raw_json = self.storage.get("keys.json").await?;
        let keys: KeysJson = serde_json::from_slice(&raw_json)?;

        for enc in keys.master_key_encapsulations {
            let pk_bytes = BASE64_STANDARD.decode(&enc.public_key)?;
            if pk_bytes == local_pk_bytes.as_slice() {
                let enc_key = <Kem as HpkeKem>::EncappedKey::from_bytes(
                    &BASE64_STANDARD.decode(&enc.encapsulated_key)?,
                )
                .map_err(|_| anyhow!("Invalid enc key"))?;

                let mut ciphertext =
                    Zeroizing::new(BASE64_STANDARD.decode(&enc.wrapped_master_key)?);
                let auth_tag_bytes = BASE64_STANDARD.decode(&enc.auth_tag)?;

                let auth_tag = hpke::aead::AeadTag::<Aead>::from_bytes(&auth_tag_bytes)
                    .map_err(|_| anyhow!("Invalid authentication tag"))?;

                let aad = enc.comment.as_bytes();

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
                        aad,
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

    pub async fn add_user(&self, new_pubkey_b64: &str, comment: &str) -> Result<()> {
        let mut master_key = self.unlock_master_key().await?;

        let pk_bytes = BASE64_STANDARD.decode(new_pubkey_b64)?;
        let new_pubkey = <Kem as HpkeKem>::PublicKey::from_bytes(&pk_bytes)
            .map_err(|_| anyhow!("Invalid pubkey format"))?;

        let aad = comment.as_bytes();

        let (encapsulated_key, mut sender_ctx) = hpke::setup_sender::<Aead, Kdf, Kem>(
            &hpke::OpModeS::Base,
            &new_pubkey,
            self.repo_url.as_bytes(),
        )
        .map_err(|e| anyhow!("HPKE setup failed: {}", e))?;

        let auth_tag = sender_ctx
            .seal_inout_detached(hpke::inout::InOutBuf::from(&mut master_key[..]), aad)
            .map_err(|e| anyhow!("HPKE seal failed: {}", e))?;

        let new_enc = KeyEncapsulation {
            public_key: BASE64_STANDARD.encode(new_pubkey.to_bytes()),
            encapsulated_key: BASE64_STANDARD.encode(encapsulated_key.to_bytes()),
            auth_tag: BASE64_STANDARD.encode(auth_tag.to_bytes()),
            wrapped_master_key: BASE64_STANDARD.encode(&master_key[..]),
            comment: comment.to_string(),
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
