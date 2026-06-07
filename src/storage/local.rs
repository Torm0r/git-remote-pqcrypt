use anyhow::anyhow;
use async_trait::async_trait;
use std::path::PathBuf;
use std::time::{SystemTime, UNIX_EPOCH};
use tokio::fs;
use tokio::time::{sleep, Duration};

use crate::storage::{LockGuard, Result, Storage, StorageError};

const LOCK_DIR_NAME: &str = "pqcrypt.lock";
const LOCK_INFO_FILE: &str = "info";
const LOCK_TIMEOUT_MINUTES: u64 = 10;

/// Filesystem-based storage backend for local repos.
#[derive(Clone)]
pub struct LocalStorage {
    repo_root: PathBuf,
}

impl LocalStorage {
    pub async fn new(repo_path: &str) -> Result<Self> {
        let repo_root = PathBuf::from(repo_path);
        fs::create_dir_all(&repo_root).await.ok();
        Ok(LocalStorage { repo_root })
    }

    fn full_path(&self, relative_path: &str) -> PathBuf {
        self.repo_root.join(relative_path)
    }
}

#[async_trait]
impl Storage for LocalStorage {
    async fn get(&self, path: &str) -> Result<Vec<u8>> {
        let full_path = self.full_path(path);
        match fs::read(&full_path).await {
            Ok(contents) => Ok(contents),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
                Err(StorageError::NotFound(path.to_string()))
            }
            Err(e) => Err(StorageError::Io(e)),
        }
    }

    async fn put(&self, path: &str, content: &[u8]) -> Result<()> {
        let full_path = self.full_path(path);
        if let Some(parent) = full_path.parent() {
            fs::create_dir_all(parent).await?;
        }
        fs::write(&full_path, content).await?;
        Ok(())
    }

    async fn list(&self, path: &str) -> Result<Vec<String>> {
        let full_path = self.full_path(path);
        let mut entries = Vec::new();
        let mut read_dir = fs::read_dir(&full_path).await?;
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
        let current_timestamp = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_err(|e| StorageError::Other(anyhow!(e)))?
            .as_secs();

        loop {
            match fs::create_dir(&lock_dir_path).await {
                Ok(_) => {
                    let lock_info_content = format!("{}\n{}", current_username, current_timestamp);
                    fs::write(&lock_info_path, lock_info_content.as_bytes()).await?;
                    return Ok(LockGuard {
                        storage: self.clone(),
                        locked: true,
                    });
                }
                Err(e) => {
                    if e.kind() == std::io::ErrorKind::AlreadyExists {
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
                                    fs::remove_file(&lock_info_path).await.ok();
                                    fs::remove_dir(&lock_dir_path).await.ok();
                                    sleep(Duration::from_secs(1)).await;
                                    continue;
                                } else {
                                    return Err(StorageError::Other(anyhow!("Remote repository is locked by another process ({}). Try again later.", locked_by_user)));
                                }
                            }
                            Err(_) => {
                                return Err(StorageError::Other(anyhow!("Remote repository is locked by an unknown process. Lock directory exists but info file is unreadable.")));
                            }
                        }
                    } else {
                        return Err(StorageError::Other(anyhow!("Failed to acquire lock: {}", e)));
                    }
                }
            }
        }
    }

    async fn unlock(&self) -> Result<()> {
        let lock_dir_path = self.full_path(LOCK_DIR_NAME);
        let lock_info_path = lock_dir_path.join(LOCK_INFO_FILE);
        fs::remove_file(&lock_info_path).await.ok();
        fs::remove_dir(&lock_dir_path).await.ok();
        Ok(())
    }
}
