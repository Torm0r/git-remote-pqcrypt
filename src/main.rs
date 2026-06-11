use crate::storage::dispatch::determine_type;
use crate::storage::dispatch::StorageType;
use crate::storage::Storage;
use anyhow::Result;
use std::env;
use std::path::Path;
use std::process;

mod cli;
mod storage;
mod types;
mod workers;

#[derive(Debug, Clone)]
struct ParsedPqcryptUrl {
    canonical: String,
    storage_path: String,
}

fn parse_pqcrypt_url(input: &str) -> ParsedPqcryptUrl {
    if let Some(rest) = input.strip_prefix("pqcrypt::") {
        ParsedPqcryptUrl {
            canonical: format!("pqcrypt::{}", rest),
            storage_path: rest.to_string(),
        }
    } else if let Some(rest) = input.strip_prefix("pqcrypt://") {
        ParsedPqcryptUrl {
            canonical: format!("pqcrypt::{}", rest),
            storage_path: rest.to_string(),
        }
    } else if let Some(rest) = input.strip_prefix("pqcrypt:") {
        ParsedPqcryptUrl {
            canonical: format!("pqcrypt::{}", rest),
            storage_path: rest.to_string(),
        }
    } else {
        ParsedPqcryptUrl {
            canonical: format!("pqcrypt::{}", input),
            storage_path: input.to_string(),
        }
    }
}

fn invoked_as_git_remote_helper(args: &[String]) -> bool {
    if args.len() != 3 {
        return false;
    }

    let exe_name = args
        .first()
        .and_then(|p| Path::new(p).file_name())
        .and_then(|s| s.to_str())
        .unwrap_or("");

    if exe_name != "git-remote-pqcrypt" {
        return false;
    }

    // When git invokes a remote helper, argv[1] is the remote name (e.g. "origin").
    // If argv[1] is a known CLI subcommand, this is a direct user invocation,
    // not a git remote helper call — fall through to the CLI parser.
    let cli_subcommands = ["init", "add-user", "keygen", "pubgen", "help"];
    if let Some(first_arg) = args.get(1) {
        if cli_subcommands.contains(&first_arg.as_str()) {
            return false;
        }
    }

    true
}

#[tokio::main]
async fn main() {
    let args: Vec<String> = env::args().collect();

    if invoked_as_git_remote_helper(&args) {
        let parsed = parse_pqcrypt_url(&args[2]);

        if let Err(e) = handle_remote(&parsed.storage_path, &parsed.canonical).await {
            eprintln!("error: {}", e);
            process::exit(1);
        }
    } else if let Err(e) = cli::parse_and_run().await {
        eprintln!("error: {}", e);
        process::exit(1);
    }
}

async fn run_remote<S: Storage + Clone>(storage: S, remote_url: String) -> Result<()> {
    storage.fetch_sync().await?;

    let key_worker = workers::keyworker::KeyWorker::new(storage.clone(), remote_url);
    let master_key = key_worker.unlock_master_key().await?;
    let mut git_worker = workers::gitworker::GitWorker::new(storage, master_key);
    git_worker.run().await
}

async fn handle_remote(repo_path: &str, remote_url: &str) -> Result<()> {
    match determine_type(repo_path) {
        StorageType::Local => {
            let storage = storage::local::LocalStorage::new(repo_path).await?;
            run_remote(storage, remote_url.to_string()).await?;
        }
        StorageType::Sftp => {
            let storage = storage::sftp::SftpStorage::new(repo_path).await?;
            run_remote(storage, remote_url.to_string()).await?;
        }
        StorageType::Git => {
            let storage = storage::git_ssh::GitStorage::new(repo_path).await?;
            run_remote(storage, remote_url.to_string()).await?;
        }
    }

    Ok(())
}
