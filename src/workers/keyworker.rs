use crate::storage::Storage;
use anyhow::{anyhow, Result};
use base64::prelude::*;
use hpke::{aead::ChaCha20Poly1305, kdf::HkdfSha384, kem::XWing, Deserializable, Serializable};
use rand::RngCore;
use serde::{Deserialize, Serialize};
use std::env;

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

impl<S: Storage + Clone + Send + Sync + 'static> KeyWorker<S> {
    pub fn new(storage: S, repo_url: String) -> Self {
        KeyWorker { storage, repo_url }
    }

    pub fn get_aad(&self) -> &[u8] {
        &[]
    }

    pub async fn get_local_key(&self) -> Result<<Kem as hpke::kem::Kem>::PrivateKey> {
        let key_path_str =
            env::var(ENV_KEY_PATH).map_err(|_| anyhow!("No key path found in {}", ENV_KEY_PATH))?;
        let key_b64 = tokio::fs::read_to_string(key_path_str).await?;
        let key_bytes = BASE64_STANDARD.decode(key_b64.trim())?;
        <Kem as hpke::kem::Kem>::PrivateKey::from_bytes(&key_bytes)
            .map_err(|_| anyhow!("Invalid private key format"))
    }

    pub async fn generate_new_master_key(&self) -> Result<(Vec<u8>, String)> {
        let local_sk = self.get_local_key().await?;
        let local_pk = <Kem as hpke::kem::Kem>::sk_to_pk(&local_sk);

        let mut master_key = vec![0u8; 32];
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

        Ok((master_key, serde_json::to_string(&keys_json)?))
    }

    pub async fn unlock_master_key(&self) -> Result<Vec<u8>> {
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

                let mut ciphertext = BASE64_STANDARD.decode(&enc.wrapped_master_key)?;
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

    pub async fn add_user_to_keys_json(
        &self,
        mut current_keys: serde_json::Value,
        new_pubkey: &<Kem as hpke::kem::Kem>::PublicKey,
        master_key: &[u8],
    ) -> Result<serde_json::Value> {
        let (encapsulated_key, mut sender_ctx) = hpke::setup_sender::<Aead, Kdf, Kem>(
            &hpke::OpModeS::Base,
            new_pubkey,
            self.repo_url.as_bytes(),
        )
        .map_err(|e| anyhow!("HPKE setup failed: {}", e))?;

        let mut ciphertext = master_key.to_vec();
        let auth_tag = sender_ctx
            .seal_inout_detached(
                hpke::inout::InOutBuf::from(&mut ciphertext[..]),
                self.get_aad(),
            )
            .map_err(|e| anyhow!("HPKE seal failed: {}", e))?;

        let new_enc = KeyEncapsulation {
            public_key: BASE64_STANDARD.encode(new_pubkey.to_bytes()),
            encapsulated_key: BASE64_STANDARD.encode(encapsulated_key.to_bytes()),
            auth_tag: BASE64_STANDARD.encode(auth_tag.to_bytes()),
            wrapped_master_key: BASE64_STANDARD.encode(ciphertext),
        };

        let master_key_array = current_keys["masterKey"]
            .as_array_mut()
            .ok_or_else(|| anyhow!("Invalid JSON"))?;

        if master_key_array
            .iter()
            .any(|v| v["publicKey"] == new_enc.public_key)
        {
            return Err(anyhow!("Public key already exists"));
        }

        master_key_array.push(serde_json::to_value(new_enc)?);
        Ok(current_keys)
    }
}
