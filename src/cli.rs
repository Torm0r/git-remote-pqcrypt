// I would consider this checked
use crate::storage::dispatch::{determine_type, StorageType};
use crate::storage::git_ssh::GitStorage;
use crate::storage::local::LocalStorage;
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
use std::io::Write;
use std::path::PathBuf;
use std::{fs, io};
use zeroize::Zeroizing;

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
        /// The public key to add
        pubkey: String,
        // This should get the local repo you are in right now by default
        /// Optional: The repository URL (defaults to local git remote starting with pqcrypt://)
        #[arg(short, long)]
        url: Option<String>,
    },
    Keygen {
        /// Optional: Path to save the private key (defaults to ~/.config/pqcrypt/key)
        #[arg(short, long)]
        output: Option<PathBuf>,
    },
    Pubgen {
        private_key_path: PathBuf,
    },
}

// Generic: works for any storage backend that implements Storage + Clone
async fn init_storage<S: Storage + Clone>(storage: S, url: String) -> Result<()> {
    let kw = KeyWorker::new(storage.clone(), url);
    kw.add_new_master_key().await?;
    Ok(())
}

async fn add_user_to_storage<S: Storage + Clone>(
    storage: S,
    url: String,
    pubkey: String,
) -> Result<()> {
    let kw = KeyWorker::new(storage.clone(), url);
    kw.add_user(&pubkey).await?;
    Ok(())
}

async fn init_repo(url: String) -> Result<()> {
    let repo_path = url.trim_start_matches("pqcrypt://");
    match determine_type(&url) {
        StorageType::Local => init_storage(LocalStorage::new(repo_path).await?, url).await,
        StorageType::Sftp => init_storage(SftpStorage::new(repo_path).await?, url).await,
        StorageType::Git => init_storage(GitStorage::new(repo_path).await?, url).await,
    }
}

async fn add_user_repo(url: String, pubkey: String) -> Result<()> {
    let repo_path = url.trim_start_matches("pqcrypt://");
    match determine_type(&url) {
        StorageType::Local => {
            add_user_to_storage(LocalStorage::new(repo_path).await?, url, pubkey).await
        }
        StorageType::Sftp => {
            add_user_to_storage(SftpStorage::new(repo_path).await?, url, pubkey).await
        }
        StorageType::Git => {
            add_user_to_storage(GitStorage::new(repo_path).await?, url, pubkey).await
        }
    }
}

pub async fn parse_and_run() -> Result<()> {
    let cli = Cli::parse();
    match cli.command {
        Commands::Init { url } => init_repo(url).await,
        Commands::AddUser { url, pubkey } => {
            // Resolve the URL: either the user gave us one, or we auto-detect it
            let final_url = match url {
                Some(u) => u,
                None => get_default_repo_url()?,
            };

            add_user_repo(final_url, pubkey).await
        }
        Commands::Keygen { output } => {
            // Only generate and save if the user didn't abort
            if let Some(resolved_path) = resolve_key_path(output)? {
                generate_and_save_keypair(resolved_path)?;
            }
            Ok(())
        }
        Commands::Pubgen {
            private_key_path: input,
        } => {
            // Read base64-encoded private key (matches Keygen output format)
            let key_bytes = Zeroizing::new(
                BASE64_STANDARD.decode(tokio::fs::read_to_string(&input).await?.trim())?,
            );

            // Parse into the KEM's PrivateKey type
            let sk = <MyKem as Kem>::PrivateKey::from_bytes(&key_bytes)
                .map_err(|_| anyhow!("Invalid private key format at {}", input.display()))?;

            // Derive public key from secret key
            let pk = MyKem::sk_to_pk(&sk);

            println!("Public Key: \n{}", BASE64_STANDARD.encode(pk.to_bytes()));
            Ok(())
        }
    }
}
fn get_default_repo_url() -> Result<String> {
    // `git config --get-regexp remote\..*\.url` prints all remotes like:
    // remote.origin.url pqcrypt://local/path
    // remote.upstream.url git@github.com:...
    let output = std::process::Command::new("git")
        .args(["config", "--get-regexp", r"remote\..*\.url"])
        .output()
        .map_err(|_| anyhow!("Failed to execute git command. Are you in a git repository?"))?;

    if output.status.success() {
        let stdout = String::from_utf8_lossy(&output.stdout);
        for line in stdout.lines() {
            let parts: Vec<&str> = line.split_whitespace().collect();
            // parts[0] is the config key, parts[1] is the URL
            if parts.len() == 2 && parts[1].starts_with("pqcrypt://") {
                return Ok(parts[1].to_string());
            }
        }
    }

    Err(anyhow!("Could not find a default pqcrypt:// remote in this git repository. Please specify one explicitly using --url"))
}

/// Interactively resolves the output path, prompting the user if the file already exists.
/// Returns `Ok(Some(PathBuf))` if safe to proceed, or `Ok(None)` if the user aborted.
fn resolve_key_path(output: Option<PathBuf>) -> Result<Option<PathBuf>> {
    let mut final_output = match output {
        Some(path) => path,
        None => dirs::home_dir()
            .ok_or_else(|| anyhow!("Could not find home directory"))?
            .join(".config/pqcrypt/key"),
    };

    loop {
        if final_output.exists() {
            print!(
                "Warning: File '{}' already exists.\n[O]verwrite, [C]hange path, or [A]bort? ",
                final_output.display()
            );
            io::stdout().flush()?;

            let mut choice = String::new();
            io::stdin().read_line(&mut choice)?;

            match choice.trim().to_lowercase().as_str() {
                "o" | "overwrite" => {
                    println!("Overwriting existing key...");
                    break;
                }
                "c" | "change" => {
                    print!("Enter new path: ");
                    io::stdout().flush()?;

                    let mut new_path = String::new();
                    io::stdin().read_line(&mut new_path)?;
                    let new_path_trimmed = new_path.trim();

                    if new_path_trimmed.is_empty() {
                        println!("Path cannot be empty. Please try again.");
                        continue;
                    }

                    // Expand "~/" to the user's home directory
                    if new_path_trimmed.starts_with("~/") {
                        if let Some(home) = dirs::home_dir() {
                            final_output = home.join(&new_path_trimmed[2..]);
                            continue;
                        }
                    }

                    final_output = PathBuf::from(new_path_trimmed);
                }
                _ => {
                    println!("Key generation aborted.");
                    return Ok(None);
                }
            }
        } else {
            // Path does not exist, safe to proceed
            break;
        }
    }

    Ok(Some(final_output))
}
/// Generates the keypair and saves it safely to disk.
fn generate_and_save_keypair(output_path: PathBuf) -> Result<()> {
    // Safely create the parent directories if they don't exist
    if let Some(parent) = output_path.parent() {
        fs::create_dir_all(parent)?;
    }

    // Generate the keys
    let (sk, pk): (<MyKem as Kem>::PrivateKey, <MyKem as Kem>::PublicKey) = MyKem::gen_keypair();

    // Save the private key
    fs::write(&output_path, BASE64_STANDARD.encode(sk.to_bytes()))?;

    // Provide clear feedback to the user
    println!("\nSaved private key to: {}", output_path.display());
    println!("Public Key:\n{}", BASE64_STANDARD.encode(pk.to_bytes()));

    Ok(())
}
