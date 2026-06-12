use crate::storage::Storage;
use crate::url::parse_pqcrypt_url;
use crate::with_storage;
use crate::workers::gitworker;
use crate::workers::keyworker::{self, InitKeyResult, KeyWorker};
use anyhow::{anyhow, Context, Result};
use clap::{Parser, Subcommand};
use std::io;
use std::io::Write;
use std::path::PathBuf;

#[derive(Parser, Debug)]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand, Debug)]
enum Commands {
    /// Initialize a new pqcrypt repository at the specified URL
    Init {
        /// The storage URL (e.g., pqcrypt://local/path, sftp://..., git://...)
        url: String,

        /// Optional: Path to the private key to initialize the repo with
        #[arg(short, long)]
        key: Option<PathBuf>,

        /// Optional: Identity comment for this key (e.g. 'work', 'personal')
        #[arg(short, long)]
        comment: Option<String>,
    },

    /// Grant a user access by adding their public key to the repository
    AddUser {
        /// The Base64-encoded public key of the user to add
        pubkey: String,

        /// Optional: The repository URL (defaults to the local git remote starting with pqcrypt://)
        #[arg(short, long)]
        url: Option<String>,

        /// Optional: Identity comment for the new user
        #[arg(short, long)]
        comment: Option<String>,
    },

    /// Generate a new post-quantum keypair
    Keygen {
        /// Optional: Path to save the private key (defaults to ~/.config/pqcrypt/key)
        #[arg(short, long)]
        output: Option<PathBuf>,
    },

    /// Derive and display the public key from an existing private key file
    Pubgen {
        /// Path to the existing private key file
        private_key_path: PathBuf,
    },
}

async fn init_storage<S: Storage + Clone>(
    storage: S,
    url: String,
    sk: <hpke::kem::XWing as hpke::kem::Kem>::PrivateKey,
    comment: String,
) -> Result<()> {
    storage
        .fetch_sync()
        .await
        .context("init: fetch_sync failed")?;

    if storage.get("keys.json").await.is_ok() {
        return Err(anyhow!(
            "Repository already initialized (keys.json already exists). Aborting to prevent overwriting the master key."
        ));
    }

    let kw = KeyWorker::new(storage.clone(), url);
    kw.add_new_master_key(&sk, &comment)
        .await
        .context("init: failed to create keys.json")?;

    storage
        .push_sync()
        .await
        .context("init: failed to push initial pqcrypt state")?;

    Ok(())
}

async fn add_user_to_storage<S: Storage + Clone>(
    storage: S,
    url: String,
    pubkey: String,
    comment: String,
) -> Result<()> {
    storage.fetch_sync().await?;

    let kw = KeyWorker::new(storage.clone(), url);
    kw.add_user(&pubkey, &comment).await?;

    storage.push_sync().await?;

    Ok(())
}

async fn init_repo(url: String, key_path: Option<PathBuf>, comment: Option<String>) -> Result<()> {
    let parsed = parse_pqcrypt_url(&url);
    let url = parsed.canonical;
    let repo_path = parsed.storage_path;

    let (sk, key_result) = keyworker::resolve_or_generate_init_key(key_path).await?;
    if let InitKeyResult::Generated { pubkey_b64, path } = &key_result {
        println!(
            "No key found. Auto-generating default key at {}...",
            path.display()
        );
        println!("Public Key:\n{}", pubkey_b64);
    }

    let comment = match comment {
        Some(c) => c,
        None => prompt_for_comment()?,
    };

    with_storage!(&repo_path, storage => {
        init_storage(storage, url.clone(), sk, comment).await?;
        Ok::<(), anyhow::Error>(())
    })?;

    gitworker::add_pqcrypt_remote(&url)?;
    Ok(())
}

async fn add_user_repo(url: String, pubkey: String, comment: String) -> Result<()> {
    let parsed = parse_pqcrypt_url(&url);
    let url = parsed.canonical;
    let repo_path = parsed.storage_path;

    with_storage!(&repo_path, storage => {
        add_user_to_storage(storage, url, pubkey, comment).await
    })
}

pub async fn parse_and_run() -> Result<()> {
    let cli = Cli::parse();
    match cli.command {
        Commands::Init { url, key, comment } => init_repo(url, key, comment).await,
        Commands::AddUser {
            url,
            pubkey,
            comment,
        } => {
            let final_url = match url {
                Some(u) => parse_pqcrypt_url(&u).canonical,
                None => gitworker::get_default_repo_url()?,
            };
            let comment = comment.unwrap_or_default();
            add_user_repo(final_url, pubkey, comment).await
        }

        Commands::Keygen { output } => {
            if let Some(resolved_path) = resolve_key_path(output)? {
                let pubkey = keyworker::generate_and_save_keypair(&resolved_path)?;
                println!("\nSaved private key to: {}", resolved_path.display());
                println!("Public Key:\n{}", pubkey);
            }
            Ok(())
        }

        Commands::Pubgen {
            private_key_path: input,
        } => {
            let pubkey = keyworker::get_pubkey_from_file(&input).await?;
            println!("Public Key: \n{}", pubkey);
            Ok(())
        }
    }
}

fn prompt_for_comment() -> Result<String> {
    print!("Add a comment/identity to this key (e.g. 'personal', 'work') [optional]: ");
    io::stdout().flush()?;
    let mut comment = String::new();
    io::stdin().read_line(&mut comment)?;
    Ok(comment.trim().to_string())
}

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
            break;
        }
    }
    Ok(Some(final_output))
}
