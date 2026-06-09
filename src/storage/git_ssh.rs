use anyhow::anyhow;
use std::path::PathBuf;
use tokio::fs;
use tokio::process::Command;

use crate::storage::{LockGuard, Result, Storage, StorageError};
use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;

/// Stores encrypted blobs in a local git proxy cache directory.
/// Uses git reset --hard and shell execution of the local `git` CLI for synchronization.
#[derive(Clone)]
pub struct GitStorage {
    repo_root: PathBuf,
}

impl GitStorage {
    pub async fn new(repo_path: &str) -> Result<Self> {
        let cache_base = dirs::cache_dir()
            .ok_or_else(|| StorageError::Other(anyhow!("Could not determine system cache directory")))?;

        // Safe directory name from base64 encoding of the full repo url/path
        let encoded_name = URL_SAFE_NO_PAD.encode(repo_path);
        let repo_root = cache_base
            .join("pqcrypt")
            .join(encoded_name);

        if !repo_root.exists() {
            fs::create_dir_all(&repo_root).await?;
            let status = Command::new("git")
                .arg("init")
                .current_dir(&repo_root)
                .status()
                .await?;
            if !status.success() {
                return Err(StorageError::Other(anyhow!("Failed to run git init")));
            }
        }

        // Add origin remote pointing to repo_path itself (ignores error if already exists)
        let _ = Command::new("git")
            .args(["remote", "add", "origin", repo_path])
            .current_dir(&repo_root)
            .output()
            .await;

        Ok(GitStorage { repo_root })
    }

    fn full_path(&self, relative: &str) -> PathBuf {
        self.repo_root.join(relative)
    }

    pub async fn push_sync(&self) -> Result<()> {
        // Stage specific paths
        let add_status = Command::new("git")
            .args(["add", "--all", "objects/", "manifest.enc", "keys.json"])
            .current_dir(&self.repo_root)
            .status()
            .await?;
        if !add_status.success() {
            // Ignore staging failures if paths don't exist yet, but let's log or continue
        }

        // Commit changes (ignores if working tree is clean)
        let _commit_output = Command::new("git")
            .args(["commit", "-m", "pqcrypt: state update"])
            .current_dir(&self.repo_root)
            .output()
            .await?;

        // Try pushing HEAD to origin. If push is rejected (non-fast-forward), return an error.
        let push_output = Command::new("git")
            .args(["push", "origin", "HEAD"])
            .current_dir(&self.repo_root)
            .output()
            .await?;

        if !push_output.status.success() {
            let stderr = String::from_utf8_lossy(&push_output.stderr).to_string();
            if stderr.contains("rejected") || stderr.contains("non-fast-forward") {
                return Err(StorageError::Other(anyhow!(
                    "Push rejected (non-fast-forward). Please run a sync/pull operation to fetch upstream changes first.\nDetails:\n{}",
                    stderr
                )));
            } else {
                return Err(StorageError::Other(anyhow!(
                    "Failed to push state to remote Git repository.\nDetails:\n{}",
                    stderr
                )));
            }
        }

        Ok(())
    }

    pub async fn fetch_sync(&self) -> Result<()> {
        let fetch_output = Command::new("git")
            .args(["fetch", "origin"])
            .current_dir(&self.repo_root)
            .output()
            .await?;

        if !fetch_output.status.success() {
            let stderr = String::from_utf8_lossy(&fetch_output.stderr).to_string();
            return Err(StorageError::Other(anyhow!(
                "Failed to fetch from origin remote.\nDetails:\n{}",
                stderr
            )));
        }

        // Hard reset fallbacks: try origin/HEAD, then origin/main, then origin/master
        let mut reset_success = false;
        let mut last_error = String::new();

        for ref_target in &["origin/HEAD", "origin/main", "origin/master"] {
            let reset_output = Command::new("git")
                .args(["reset", "--hard", ref_target])
                .current_dir(&self.repo_root)
                .output()
                .await?;
            if reset_output.status.success() {
                reset_success = true;
                break;
            } else {
                last_error = String::from_utf8_lossy(&reset_output.stderr).to_string();
            }
        }

        if !reset_success {
            // It might be a brand new empty remote repository (origin has no branches yet)
            // Let's only return an error if it's not a completely empty/unborn HEAD state.
            // In a brand new empty repo, origin/HEAD doesn't exist, which is normal.
            let status_output = Command::new("git")
                .args(["status"])
                .current_dir(&self.repo_root)
                .output()
                .await?;
            let status_str = String::from_utf8_lossy(&status_output.stdout);
            if !status_str.contains("No commits yet") && !status_str.contains("Initial commit") {
                return Err(StorageError::Other(anyhow!(
                    "Failed to reset proxy to upstream HEAD, main, or master.\nLast git error:\n{}",
                    last_error
                )));
            }
        }

        Ok(())
    }
}

impl Storage for GitStorage {
    async fn get(&self, path: &str) -> Result<Vec<u8>> {
        let full = self.full_path(path);
        match fs::read(&full).await {
            Ok(data) => Ok(data),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
                Err(StorageError::NotFound(path.to_string()))
            }
            Err(e) => Err(StorageError::Io(e)),
        }
    }

    async fn put(&self, path: &str, content: Vec<u8>) -> Result<()> {
        let full = self.full_path(path);
        if let Some(parent) = full.parent() {
            fs::create_dir_all(parent).await?;
        }
        fs::write(&full, content).await?;
        Ok(())
    }

    async fn list(&self, path: &str) -> Result<Vec<String>> {
        let full = self.full_path(path);
        if !full.exists() {
            return Ok(Vec::new());
        }
        let mut entries = Vec::new();
        let mut read_dir = fs::read_dir(&full).await?;
        while let Some(entry) = read_dir.next_entry().await? {
            if let Some(name) = entry.file_name().to_str() {
                entries.push(name.to_string());
            }
        }
        Ok(entries)
    }

    async fn lock(&self) -> Result<LockGuard<Self>> {
        // No-op local locking for Git proxy storage to prevent local concurrency complexity,
        // since the remote is the source of truth.
        Ok(LockGuard {
            storage: self.clone(),
            locked: false,
        })
    }

    async fn unlock(&self) -> Result<()> {
        // No-op
        Ok(())
    }

    async fn delete(&self, path: &str) -> Result<()> {
        let full = self.full_path(path);
        match fs::remove_file(&full).await {
            Ok(_) => Ok(()),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(()),
            Err(e) => Err(StorageError::Io(e)),
        }
    }

    async fn put_atomic(&self, path: &str, content: Vec<u8>) -> Result<()> {
        let full = self.full_path(path);
        if let Some(parent) = full.parent() {
            fs::create_dir_all(parent).await?;
        }
        let tmp_path = full.with_extension("tmp");
        fs::write(&tmp_path, content).await?;
        fs::rename(&tmp_path, &full).await?;
        Ok(())
    }

    async fn fetch_sync(&self) -> Result<()> {
        self.fetch_sync().await
    }

    async fn push_sync(&self) -> Result<()> {
        self.push_sync().await
    }
}
