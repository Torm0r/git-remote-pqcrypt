use anyhow::{anyhow, Result};
use base64::prelude::*;
use clap::{Parser, Subcommand};
use kem::{Kem, KeyExport};
use std::fs;
use std::path::PathBuf;

use crate::storage::{sftp::SftpStorage, Storage};
use crate::types::manifest::Manifest;
use crate::workers::cryptworker;
use crate::workers::keyworker::KeyWorker;

#[derive(Parser, Debug)]
#[command(author, version, about, long_about = None)]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand, Debug)]
enum Commands {
    /// Initializes a new PQ-Crypt repository
    Init {
        /// URL of the remote repository (e.g., pqcrypt://git@example.com/path/to/repo)
        url: String,
    },
    /// Adds a new user to an existing PQ-Crypt repository
    AddUser {
        /// URL of the remote repository (e.g., pqcrypt://git@example.com/path/to/repo)
        url: String,
        /// Base64 encoded X-Wing public key of the new user
        pubkey: String,
    },
    /// Generates a local X-Wing keypair and stores the private key to a file
    Keygen {
        /// Output path for the private key file
        #[arg(long, default_value = "pqcrypt_private.key")]
        output: PathBuf,
    },
}

pub async fn parse_and_run() -> Result<()> {
    let cli = Cli::parse();

    match &cli.command {
        Commands::Init { url } => init_repo(url).await,
        Commands::AddUser { url, pubkey } => add_user(url, pubkey).await,
        Commands::Keygen { output } => generate_keypair(output),
    }
}

async fn init_repo(url: &str) -> Result<()> {
    let repo_path = url.trim_start_matches("pqcrypt://");
    let storage = SftpStorage::new(repo_path).await?;
    let key_worker = KeyWorker::new(storage.clone());

    println!("Initializing new PQ-Crypt repository at {}", url);

    let (master_key, initial_keys_json) = key_worker.generate_new_master_key().await?;

    let lock_guard = storage.lock().await?;

    if let Ok(_) = storage.get("manifest.enc").await {
        lock_guard.release().await?;
        return Err(anyhow!("Repository already initialized at this location."));
    }

    // Upload keys.json as plaintext — it contains KEM ciphertexts which are
    // already cryptographically opaque. Only the matching private key holder
    // can decapsulate them to recover the master key.
    storage
        .put("keys.json", initial_keys_json.as_bytes())
        .await?;

    // Upload encrypted empty manifest
    let manifest_json = serde_json::to_string(&Manifest::new())?;
    let encrypted_manifest = cryptworker::encrypt_bytes(manifest_json.as_bytes(), &master_key)?;
    storage.put("manifest.enc", &encrypted_manifest).await?;

    println!("Repository initialized successfully.");
    lock_guard.release().await?;
    Ok(())
}

async fn add_user(url: &str, pubkey_b64: &str) -> Result<()> {
    let repo_path = url.trim_start_matches("pqcrypt://");
    let storage = SftpStorage::new(repo_path).await?;
    let key_worker = KeyWorker::new(storage.clone());

    println!("Adding user to PQ-Crypt repository at {}", url);

    let lock_guard = storage.lock().await?;

    // Unlock master key to verify the caller is authorized (holds a valid private key)
    let _master_key = key_worker.unlock_master_key().await?;
    let raw_keys = storage.get("keys.json").await?;
    let keys_json: serde_json::Value = serde_json::from_slice(&raw_keys)?;

    // Add new user's encapsulated key
    let new_pubkey_bytes = BASE64_STANDARD
        .decode(pubkey_b64)
        .map_err(|e| anyhow!("Failed to decode public key base64: {}", e))?;
    let new_pubkey = x_wing::EncapsulationKey::try_from(new_pubkey_bytes.as_slice())
        .map_err(|_| anyhow!("Invalid X-Wing public key format"))?;

    let updated_keys_json = key_worker
        .add_user_to_keys_json(keys_json, &new_pubkey, &_master_key)
        .await?;

    // Upload updated keys.json (plaintext)
    let updated_json = serde_json::to_string(&updated_keys_json)?;
    storage.put("keys.json", updated_json.as_bytes()).await?;

    println!("User added successfully.");
    lock_guard.release().await?;
    Ok(())
}

fn generate_keypair(output: &PathBuf) -> Result<()> {
    println!("Generating new X-Wing keypair...");
    let (decaps_key, encaps_key) = x_wing::XWingKem::generate_keypair();
    let public_key_b64 = BASE64_STANDARD.encode(encaps_key.to_bytes().as_slice());
    let private_key_b64 = BASE64_STANDARD.encode(decaps_key.as_bytes());

    fs::write(output, &private_key_b64)?;

    println!("X-Wing keypair generated.");
    println!("Private key saved to: {}", output.display());
    println!("Your public key (base64): {}", public_key_b64);
    println!("Share this public key with repository administrators to be added to a repository.");
    Ok(())
}
