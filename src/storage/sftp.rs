use anyhow::{anyhow, Result};
use async_trait::async_trait;
use std::path::PathBuf;
use std::time::{SystemTime, UNIX_EPOCH};
use tokio::fs;
use tokio::time::{sleep, Duration};

use crate::storage::{LockGuard, Storage};

const LOCK_DIR_NAME: &str = "pqcrypt.lock";
const LOCK_INFO_FILE: &str = "info";
const LOCK_TIMEOUT_MINUTES: u64 = 10;

/// A simple file-system-based storage backend.
/// TODO: Replace with actual SFTP implementation using an SSH/SFTP crate.
#[derive(Clone)]
pub struct SftpStorage {
    repo_root: PathBuf,
}

impl SftpStorage {
    pub async fn new(repo_url: &str) -> Result<Self> {
        // For now, treat the repo_url as a local path for development/testing.
        // TODO: Implement actual SFTP connection (e.g., using ssh2 or russh crates).
        let repo_root = PathBuf::from(repo_url);

        // Ensure the repo root directory exists
        fs::create_dir_all(&repo_root).await.ok();

        Ok(SftpStorage { repo_root })
    }

    fn full_path(&self, relative_path: &str) -> PathBuf {
        self.repo_root.join(relative_path)
    }
}

#[async_trait]
impl Storage for SftpStorage {
    async fn get(&self, path: &str) -> Result<Vec<u8>> {
        let full_path = self.full_path(path);
        let contents = fs::read(&full_path)
            .await
            .map_err(|e| anyhow!("Failed to read {}: {}", full_path.display(), e))?;
        Ok(contents)
    }

    async fn put(&self, path: &str, content: &[u8]) -> Result<()> {
        let full_path = self.full_path(path);
        // Ensure parent directory exists
        if let Some(parent) = full_path.parent() {
            fs::create_dir_all(parent).await?;
        }
        fs::write(&full_path, content)
            .await
            .map_err(|e| anyhow!("Failed to write {}: {}", full_path.display(), e))?;
        Ok(())
    }

    async fn list(&self, path: &str) -> Result<Vec<String>> {
        let full_path = self.full_path(path);
        let mut entries = Vec::new();
        let mut read_dir = fs::read_dir(&full_path)
            .await
            .map_err(|e| anyhow!("Failed to list {}: {}", full_path.display(), e))?;
        while let Some(entry) = read_dir.next_entry().await? {
            if let Some(name) = entry.file_name().to_str() {
                entries.push(name.to_string());
            }
        }
        Ok(entries)
    }

    async fn lock(&self) -> Result<LockGuard<Self>> {
        let lock_dir_path = self.full_path(LOCK_DIR_NAME);
        let lock_info_path = lock_dir_path.join(LOCK_INFO_FILE);

        let current_username = std::env::var("USER").unwrap_or_else(|_| "unknown".to_string());
        let current_timestamp = SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs();

        loop {
            match fs::create_dir(&lock_dir_path).await {
                Ok(_) => {
                    // Successfully created lock directory, write info file
                    let lock_info_content = format!("{}\n{}", current_username, current_timestamp);
                    fs::write(&lock_info_path, lock_info_content.as_bytes()).await?;
                    return Ok(LockGuard {
                        storage: self.clone(),
                        locked: true,
                    });
                }
                Err(e) => {
                    if e.kind() == std::io::ErrorKind::AlreadyExists {
                        // Lock directory exists, check for stale lock
                        match fs::read_to_string(&lock_info_path).await {
                            Ok(info_content) => {
                                let mut lines = info_content.lines();
                                let locked_by_user = lines.next().unwrap_or("unknown");
                                let locked_timestamp_str = lines.next().unwrap_or("0");
                                let locked_timestamp =
                                    locked_timestamp_str.parse::<u64>().unwrap_or(0);

                                if current_timestamp > locked_timestamp + LOCK_TIMEOUT_MINUTES * 60
                                {
                                    eprintln!("warning: Detected stale lock from {} at {}. Attempting to force remove.", locked_by_user, locked_timestamp_str);
                                    // Stale lock, remove and retry
                                    fs::remove_file(&lock_info_path).await.ok();
                                    fs::remove_dir(&lock_dir_path).await.ok();
                                    sleep(Duration::from_secs(1)).await;
                                    continue; // Retry locking
                                } else {
                                    // Lock is active
                                    return Err(anyhow!("Remote repository is locked by another process ({}). Try again later.", locked_by_user));
                                }
                            }
                            Err(_) => {
                                // Lock directory exists but info file is missing or unreadable.
                                return Err(anyhow!("Remote repository is locked by an unknown process. Lock directory exists but info file is unreadable."));
                            }
                        }
                    } else {
                        return Err(anyhow!("Failed to acquire lock: {}", e));
                    }
                }
            }
        }
    }

    async fn unlock(&self) -> Result<()> {
        let lock_dir_path = self.full_path(LOCK_DIR_NAME);
        let lock_info_path = lock_dir_path.join(LOCK_INFO_FILE);

        fs::remove_file(&lock_info_path).await.ok(); // Ignore error if file already gone
        fs::remove_dir(&lock_dir_path).await.ok(); // Ignore error if dir already gone
        Ok(())
    }
}
