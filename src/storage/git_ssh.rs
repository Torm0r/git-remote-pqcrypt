use anyhow::anyhow;
use std::path::PathBuf;
use tokio::fs;
use tokio::process::Command;

use crate::storage::{LockGuard, Result, Storage, StorageError};
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine;

/// Create a git Command with all GIT_* environment variables stripped.
///
/// When invoked as a git remote helper (e.g. during `git clone` or `git push`),
/// git sets GIT_DIR, GIT_WORK_TREE, etc. pointing to the user's repository.
/// These override `.current_dir()`, causing cache repo operations to silently
/// target the wrong repository. Stripping them ensures the cache repo commands
/// always operate on the actual cache directory.
fn git_cmd() -> Command {
    let mut cmd = Command::new("git");
    for (key, _) in std::env::vars() {
        if key.starts_with("GIT_") {
            cmd.env_remove(&key);
        }
    }
    cmd
}

#[derive(Clone)]
pub struct GitStorage {
    repo_root: PathBuf,
    remote_url: String,
}

impl GitStorage {
    pub async fn new(repo_path: &str) -> Result<Self> {
        let cache_base = dirs::cache_dir().ok_or_else(|| {
            StorageError::Other(anyhow!("Could not determine system cache directory"))
        })?;

        let encoded_name = URL_SAFE_NO_PAD.encode(repo_path);
        let repo_root = cache_base.join("pqcrypt").join(encoded_name);

        let storage = GitStorage {
            repo_root,
            remote_url: repo_path.to_string(),
        };

        storage.ensure_cache_repo().await?;
        Ok(storage)
    }

    /// Ensures the local cache git repo exists and has the correct origin.
    /// Recreates it from scratch if it's missing or corrupted.
    async fn ensure_cache_repo(&self) -> Result<()> {
        let git_dir = self.repo_root.join(".git");

        // Check if it's a valid git repo
        if git_dir.exists() {
            let check = git_cmd()
                .args(["rev-parse", "--git-dir"])
                .current_dir(&self.repo_root)
                .output()
                .await;

            match check {
                Ok(output) if output.status.success() => {
                    // Valid repo — ensure origin is correct
                    let _ = git_cmd()
                        .args(["remote", "set-url", "origin", &self.remote_url])
                        .current_dir(&self.repo_root)
                        .output()
                        .await;
                    return Ok(());
                }
                _ => {
                    // Corrupted — remove and recreate
                    eprintln!(
                        "warning: Cache repo corrupted at {}, recreating...",
                        self.repo_root.display()
                    );
                    fs::remove_dir_all(&self.repo_root).await.ok();
                }
            }
        }

        // Create fresh cache repo
        fs::create_dir_all(&self.repo_root).await?;

        let status = git_cmd()
            .arg("init")
            .current_dir(&self.repo_root)
            .output()
            .await?;

        if !status.status.success() {
            return Err(StorageError::Other(anyhow!("Failed to run git init")));
        }

        let _ = git_cmd()
            .args(["remote", "add", "origin", &self.remote_url])
            .current_dir(&self.repo_root)
            .output()
            .await;

        Ok(())
    }

    fn full_path(&self, relative: &str) -> PathBuf {
        self.repo_root.join(relative)
    }

    pub async fn push_sync(&self) -> Result<()> {
        // Stage each path individually — some may not exist yet (e.g., during init)
        for path in &["keys.json", "manifest.enc", "objects/"] {
            let full = self.repo_root.join(path);
            if !full.exists() {
                continue;
            }
            let _ = git_cmd()
                .args(["add", "--force", path])
                .current_dir(&self.repo_root)
                .output()
                .await?;
        }

        // Check if there's anything staged
        let diff_output = git_cmd()
            .args(["diff", "--cached", "--quiet"])
            .current_dir(&self.repo_root)
            .output()
            .await?;

        if diff_output.status.success() {
            return Ok(());
        }

        let commit_output = git_cmd()
            .args(["commit", "-m", "pqcrypt: state update"])
            .current_dir(&self.repo_root)
            .output()
            .await?;

        if !commit_output.status.success() {
            let stderr = String::from_utf8_lossy(&commit_output.stderr);
            if stderr.contains("nothing to commit") {
                return Ok(());
            }
            if stderr.contains("user.name") || stderr.contains("user.email") {
                return Err(StorageError::Other(anyhow!(
                    "Git identity not configured. Please run:\n  git config --global user.name \"Your Name\"\n  git config --global user.email \"you@example.com\""
                )));
            }
            return Err(StorageError::Other(anyhow!(
                "Failed to commit state.\nDetails:\n{}",
                stderr
            )));
        }

        let push_output = git_cmd()
            .args(["push", "origin", "HEAD"])
            .current_dir(&self.repo_root)
            .output()
            .await?;

        if !push_output.status.success() {
            let stderr = String::from_utf8_lossy(&push_output.stderr).to_string();
            if stderr.contains("rejected") || stderr.contains("non-fast-forward") {
                return Err(StorageError::Other(anyhow!(
                    "Push rejected (non-fast-forward). Please sync first.\nDetails:\n{}",
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

    /// Remove all tracked and untracked files from the working tree.
    /// Used when the remote is empty so stale cached files don't persist.
    async fn clean_cache(&self) -> Result<()> {
        // Remove all tracked files from the index
        let _ = git_cmd()
            .args(["rm", "-rf", "--ignore-unmatch", "."])
            .current_dir(&self.repo_root)
            .output()
            .await;

        // Remove any untracked files and directories
        let _ = git_cmd()
            .args(["clean", "-fdx", "-e", ".git"])
            .current_dir(&self.repo_root)
            .output()
            .await;

        Ok(())
    }

    pub async fn fetch_sync(&self) -> Result<()> {
        self.ensure_cache_repo().await?;

        let fetch_output = git_cmd()
            .args(["fetch", "origin"])
            .current_dir(&self.repo_root)
            .output()
            .await?;

        if !fetch_output.status.success() {
            let stderr = String::from_utf8_lossy(&fetch_output.stderr).to_string();
            if stderr.contains("no matching remote head")
                || stderr.contains("couldn't find remote ref")
            {
                // Remote is empty — clean the working tree to match
                self.clean_cache().await?;
                return Ok(());
            }
            return Err(StorageError::Other(anyhow!(
                "Failed to fetch from origin remote.\nDetails:\n{}",
                stderr
            )));
        }

        let branch_output = git_cmd()
            .args(["branch", "-r"])
            .current_dir(&self.repo_root)
            .output()
            .await?;

        if branch_output.status.success() {
            let branches = String::from_utf8_lossy(&branch_output.stdout);
            let remote_ref = branches
                .lines()
                .map(|l| l.trim())
                .find(|l| *l == "origin/main")
                .or_else(|| {
                    branches
                        .lines()
                        .map(|l| l.trim())
                        .find(|l| *l == "origin/master")
                })
                .or_else(|| {
                    branches
                        .lines()
                        .map(|l| l.trim())
                        .find(|l| !l.contains("->"))
                });

            if let Some(ref_target) = remote_ref {
                let reset_output = git_cmd()
                    .args(["reset", "--hard", ref_target])
                    .current_dir(&self.repo_root)
                    .output()
                    .await?;

                if !reset_output.status.success() {
                    let stderr = String::from_utf8_lossy(&reset_output.stderr);
                    return Err(StorageError::Other(anyhow!(
                        "Failed to reset to {}.\nDetails:\n{}",
                        ref_target,
                        stderr
                    )));
                }
            } else {
                // Fetch succeeded but no remote branches — empty repo
                self.clean_cache().await?;
            }
        } else {
            self.clean_cache().await?;
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
        Ok(LockGuard {
            storage: self.clone(),
            locked: false,
        })
    }

    async fn unlock(&self) -> Result<()> {
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
        GitStorage::fetch_sync(self).await
    }

    async fn push_sync(&self) -> Result<()> {
        GitStorage::push_sync(self).await
    }
}
