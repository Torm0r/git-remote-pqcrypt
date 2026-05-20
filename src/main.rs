use std::env;
use std::process;

mod cli;
mod storage;
mod types;
mod workers;

#[tokio::main]
async fn main() {
    let args: Vec<String> = env::args().collect();

    // Git remote helper mode detection
    let is_git_remote_helper = args.len() == 3
        && args[2].starts_with("pqcrypt://")
        && !matches!(args[1].as_str(), "init" | "add-user" | "keygen" | "help");

    if is_git_remote_helper {
        let remote_url = args[2].clone();
        let repo_path = remote_url.trim_start_matches("pqcrypt://");

        let storage = match storage::sftp::SftpStorage::new(repo_path).await {
            Ok(s) => s,
            Err(e) => {
                eprintln!("error: Failed to initialize storage: {}", e);
                process::exit(1);
            }
        };

        // Pass the full URL to KeyWorker for the HPKE info_str
        let key_worker = workers::keyworker::KeyWorker::new(storage.clone(), remote_url);

        let master_key = match key_worker.unlock_master_key().await {
            Ok(key) => key,
            Err(e) => {
                eprintln!("error: Failed to unlock master key: {}", e);
                process::exit(1);
            }
        };

        let mut git_worker = workers::gitworker::GitWorker::new(storage, master_key);
        if let Err(e) = git_worker.run().await {
            eprintln!("error: Git worker failed: {}", e);
            process::exit(1);
        }
    } else {
        // Admin CLI mode
        if let Err(e) = cli::parse_and_run().await {
            eprintln!("error: {}", e);
            process::exit(1);
        }
    }
}
