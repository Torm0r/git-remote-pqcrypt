use crate::storage::dispatch::determine_type;
use crate::storage::dispatch::StorageType;
use crate::storage::Storage;
use anyhow::Result;
use std::env;
use std::process;

mod cli;
mod storage;

mod types;
mod workers;

#[tokio::main]
async fn main() {
    let args: Vec<String> = env::args().collect();

    let is_git_remote_helper = args.len() == 3
        && args[2].starts_with("pqcrypt://")
        && !matches!(args[1].as_str(), "init" | "add-user" | "keygen" | "help");

    if is_git_remote_helper {
        let remote_url = args[2].clone();
        let repo_path = remote_url.trim_start_matches("pqcrypt://");

        if let Err(e) = handle_remote(repo_path, &remote_url).await {
            eprintln!("error: {}", e);
            process::exit(1);
        }
    } else {
        if let Err(e) = cli::parse_and_run().await {
            eprintln!("error: {}", e);
            process::exit(1);
        }
    }
}

async fn run_remote<S: Storage + Clone>(storage: S, remote_url: String) -> Result<()> {
    let key_worker = workers::keyworker::KeyWorker::new(storage.clone(), remote_url);
    let master_key = key_worker.unlock_master_key().await?;
    let mut git_worker = workers::gitworker::GitWorker::new(storage, master_key);
    git_worker.run().await
}

async fn handle_remote(repo_path: &str, remote_url: &str) -> Result<()> {
    match determine_type(remote_url) {
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
