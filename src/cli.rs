use crate::storage::sftp::SftpStorage;
use crate::storage::Storage;
use crate::workers::keyworker::KeyWorker;
use anyhow::{anyhow, Result};
use base64::prelude::*;
use clap::{Parser, Subcommand};
use hpke::aead::ChaCha20Poly1305;
use hpke::kdf::HkdfSha384;
use hpke::kem::{Kem, XWing};
use hpke::{Deserializable, Serializable};
use std::fs;
use std::path::PathBuf;

type MyKem = XWing;
type MyAead = ChaCha20Poly1305;
type MyKdf = HkdfSha384;

#[derive(Parser, Debug)]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand, Debug)]
enum Commands {
    Init {
        url: String,
    },
    AddUser {
        url: String,
        pubkey: String,
    },
    Keygen {
        #[arg(long, default_value = "pqcrypt.key")]
        output: PathBuf,
    },
}

pub async fn parse_and_run() -> Result<()> {
    let cli = Cli::parse();
    match cli.command {
        Commands::Init { url } => {
            let storage = SftpStorage::new(&url).await?;
            let kw = KeyWorker::new(storage.clone(), url);
            let (_, json) = kw.generate_new_master_key().await?;
            storage.put("keys.json", json.as_bytes()).await?;
            Ok(())
        }
        Commands::AddUser { url, pubkey } => {
            let storage = SftpStorage::new(&url).await?;
            let kw = KeyWorker::new(storage.clone(), url);
            let master_key = kw.unlock_master_key().await?;
            let pk_bytes = BASE64_STANDARD.decode(pubkey)?;
            let pk = <MyKem as Kem>::PublicKey::from_bytes(&pk_bytes)
                .map_err(|_| anyhow!("Invalid pubkey format"))?;
            let raw = storage.get("keys.json").await?;
            let mut json: serde_json::Value = serde_json::from_slice(&raw)?;
            json = kw.add_user_to_keys_json(json, &pk, &master_key).await?;
            storage
                .put("keys.json", serde_json::to_string(&json)?.as_bytes())
                .await?;
            Ok(())
        }
        Commands::Keygen { output } => {
            // Explicitly use the type alias to resolve the tuple type
            let (sk, pk): (<MyKem as Kem>::PrivateKey, <MyKem as Kem>::PublicKey) =
                MyKem::gen_keypair();
            fs::write(output, BASE64_STANDARD.encode(sk.to_bytes()))?;
            println!("Public Key: {}", BASE64_STANDARD.encode(pk.to_bytes()));
            Ok(())
        }
    }
}
