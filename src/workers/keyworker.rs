use anyhow::{anyhow, Result};
use base64::prelude::*;
use kem::{Decapsulate, Decapsulator, Encapsulate, KeyExport};
use rand::{rngs::OsRng, RngCore};
use serde::{Deserialize, Serialize};
use std::env;
use std::path::PathBuf;

use crate::storage::Storage;
use crate::workers::cryptworker;

const ENV_KEY_PATH: &str = "PQCRYPT_KEY_PATH";

#[derive(Debug, Serialize, Deserialize)]
pub struct KeysJson {
    #[serde(rename = "masterKey")]
    pub master_key_encapsulations: Vec<KeyEncapsulation>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct KeyEncapsulation {
    #[serde(rename = "publicKey")]
    pub public_key: String, // Base64 encoded X-Wing public key
    #[serde(rename = "encapsulatedKey")]
    pub encapsulated_key: String, // Base64 encoded encapsulated key
    #[serde(rename = "wrappedMasterKey")]
    pub wrapped_master_key: String, // Base64 encoded master key encrypted with the KEM shared key
}

pub struct KeyWorker<S: Storage> {
    storage: S,
}

impl<S: Storage + Clone + Send + Sync + 'static> KeyWorker<S> {
    pub fn new(storage: S) -> Self {
        KeyWorker { storage }
    }

    pub async fn get_local_key(&self) -> Result<x_wing::DecapsulationKey> {
        // Try environment variable for key file path
        if let Some(key_path_str) = env::var_os(ENV_KEY_PATH) {
            let key_path = PathBuf::from(key_path_str);
            let key_b64 = tokio::fs::read_to_string(&key_path).await?;
            let key_bytes = BASE64_STANDARD
                .decode(key_b64.trim())
                .map_err(|e| anyhow!("Failed to decode base64 key: {}", e))?;
            let key_array: [u8; x_wing::DECAPSULATION_KEY_SIZE] =
                key_bytes.as_slice().try_into().map_err(|_| {
                    anyhow!(
                        "Invalid X-Wing private key size from {}",
                        key_path.display()
                    )
                })?;
            return Ok(x_wing::DecapsulationKey::from(key_array));
        }

        Err(anyhow!("No X-Wing private key found via {}", ENV_KEY_PATH))
    }

    // This function generates a new symmetric master key and wraps it for the initial user.
    pub async fn generate_new_master_key(&self) -> Result<(Vec<u8>, String)> {
        let local_decaps_key = self.get_local_key().await?;
        let local_pub_key = local_decaps_key.encapsulation_key().clone();

        // 1. Generate a random 32-byte master key
        let mut master_key = vec![0u8; 32];
        OsRng.fill_bytes(&mut master_key);

        // 2. Encapsulate a shared key for the initial user
        let (ciphertext, shared_key) = local_pub_key.encapsulate();

        // 3. Wrap the master key using the KEM shared key
        let wrapped_master_key = cryptworker::encrypt_bytes(&master_key, shared_key.as_slice())?;

        let initial_keys_json = KeysJson {
            master_key_encapsulations: vec![KeyEncapsulation {
                public_key: BASE64_STANDARD.encode(local_pub_key.to_bytes().as_slice()),
                encapsulated_key: BASE64_STANDARD.encode(ciphertext.as_slice()),
                wrapped_master_key: BASE64_STANDARD.encode(&wrapped_master_key),
            }],
        };

        let keys_json_string = serde_json::to_string(&initial_keys_json)?;
        Ok((master_key, keys_json_string))
    }

    pub async fn unlock_master_key(&self) -> Result<Vec<u8>> {
        let local_decaps_key = self.get_local_key().await?;

        let raw_keys_json_content = self.storage.get("keys.json").await?;
        let keys_json: KeysJson = serde_json::from_slice(&raw_keys_json_content)?;

        let local_pub_key_bytes = local_decaps_key.encapsulation_key().to_bytes();

        for encapsulation in keys_json.master_key_encapsulations {
            let pub_key_bytes = BASE64_STANDARD
                .decode(&encapsulation.public_key)
                .map_err(|e| anyhow!("Failed to decode public key base64: {}", e))?;

            // Check if this encapsulation is for our local key
            if local_pub_key_bytes.as_slice() == pub_key_bytes.as_slice() {
                let encapsulated_key_bytes = BASE64_STANDARD
                    .decode(&encapsulation.encapsulated_key)
                    .map_err(|e| anyhow!("Failed to decode encapsulated key base64: {}", e))?;

                let ciphertext: x_wing::Ciphertext =
                    encapsulated_key_bytes
                        .as_slice()
                        .try_into()
                        .map_err(|_| anyhow!("Invalid encapsulated key size in keys.json"))?;

                let shared_key = local_decaps_key.decapsulate(&ciphertext);

                let wrapped_master_key = BASE64_STANDARD
                    .decode(&encapsulation.wrapped_master_key)
                    .map_err(|e| anyhow!("Failed to decode wrapped master key base64: {}", e))?;

                // Unwrap the master key
                let master_key =
                    cryptworker::decrypt_bytes(&wrapped_master_key, shared_key.as_slice())
                        .map_err(|e| anyhow!("Failed to unwrap master key: {}", e))?;

                if master_key.len() != 32 {
                    return Err(anyhow!("Unwrapped master key is not 32 bytes"));
                }

                return Ok(master_key);
            }
        }

        Err(anyhow!(
            "No master key encapsulation found for local X-Wing key in keys.json"
        ))
    }

    pub async fn add_user_to_keys_json(
        &self,
        mut current_keys_json_value: serde_json::Value,
        new_pubkey: &x_wing::EncapsulationKey,
        master_key: &[u8],
    ) -> Result<serde_json::Value> {
        // Re-encapsulate a new shared key for the new user's public key
        let (new_ciphertext, shared_key) = new_pubkey.encapsulate();

        // Wrap the master key using the new shared key
        let wrapped_master_key = cryptworker::encrypt_bytes(master_key, shared_key.as_slice())?;

        let new_encapsulation = KeyEncapsulation {
            public_key: BASE64_STANDARD.encode(new_pubkey.to_bytes().as_slice()),
            encapsulated_key: BASE64_STANDARD.encode(new_ciphertext.as_slice()),
            wrapped_master_key: BASE64_STANDARD.encode(&wrapped_master_key),
        };

        // Add the new encapsulation to the `masterKey` array in the JSON
        if let Some(master_key_array) = current_keys_json_value
            .get_mut("masterKey")
            .and_then(|v| v.as_array_mut())
        {
            // Check for duplicates
            let new_pubkey_b64 = BASE64_STANDARD.encode(new_pubkey.to_bytes().as_slice());
            for item in master_key_array.iter() {
                if let Some(pk) = item.get("publicKey").and_then(|s| s.as_str()) {
                    if pk == new_pubkey_b64 {
                        return Err(anyhow!("User already exists in repository"));
                    }
                }
            }

            master_key_array.push(serde_json::to_value(new_encapsulation)?);
        } else {
            return Err(anyhow!(
                "Invalid keys.json format: missing 'masterKey' array"
            ));
        }

        Ok(current_keys_json_value)
    }
}
