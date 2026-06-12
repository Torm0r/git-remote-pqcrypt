use anyhow::anyhow;
use tokio::fs;
use tokio::process::Command;

use crate::storage::local::LocalStorage;
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

/// Git-repo-backed storage that uses a local filesystem cache.
///
/// File operations (get/put/list/delete/put_atomic) are delegated to an
/// embedded `LocalStorage` pointing at the cache directory. `GitStorage`
/// adds git fetch/push sync on top of that local cache.
#[derive(Clone)]
pub struct GitStorage {
    local: LocalStorage,
    remote_url: String,
}

impl GitStorage {
    pub async fn new(repo_path: &str) -> Result<Self> {
        let cache_base = dirs::cache_dir().ok_or_else(|| {
            StorageError::Other(anyhow!("Could not determine system cache directory"))
        })?;

        let encoded_name = URL_SAFE_NO_PAD.encode(repo_path);
        let cache_path = cache_base.join("pqcrypt").join(encoded_name);
        let cache_path_str = cache_path.to_string_lossy().to_string();

        let local = LocalStorage::new(&cache_path_str).await?;

        let storage = GitStorage {
            local,
            remote_url: repo_path.to_string(),
        };

        storage.ensure_cache_repo().await?;
        Ok(storage)
    }

    /// Ensures the local cache git repo exists and has the correct origin.
    /// Recreates it from scratch if it's missing or corrupted.
    async fn ensure_cache_repo(&self) -> Result<()> {
        let repo_root = self.local.root();
        let git_dir = repo_root.join(".git");

        // Check if it's a valid git repo
        if git_dir.exists() {
            let check = git_cmd()
                .args(["rev-parse", "--git-dir"])
                .current_dir(repo_root)
                .output()
                .await;

            match check {
                Ok(output) if output.status.success() => {
                    // Valid repo — ensure origin is correct
                    let _ = git_cmd()
                        .args(["remote", "set-url", "origin", &self.remote_url])
                        .current_dir(repo_root)
                        .output()
                        .await;
                    return Ok(());
                }
                _ => {
                    // Corrupted — remove and recreate
                    eprintln!(
                        "warning: Cache repo corrupted at {}, recreating...",
                        repo_root.display()
                    );
                    fs::remove_dir_all(repo_root).await.ok();
                }
            }
        }

        // Create fresh cache repo
        fs::create_dir_all(repo_root).await?;

        let status = git_cmd()
            .arg("init")
            .current_dir(repo_root)
            .output()
            .await?;

        if !status.status.success() {
            return Err(StorageError::Other(anyhow!("Failed to run git init")));
        }

        let _ = git_cmd()
            .args(["remote", "add", "origin", &self.remote_url])
            .current_dir(repo_root)
            .output()
            .await;

        Ok(())
    }

    async fn do_push_sync(&self) -> Result<()> {
        let repo_root = self.local.root();

        // Stage each path individually — some may not exist yet (e.g., during init)
        for path in &["keys.json", "manifest.enc", "objects/"] {
            let full = repo_root.join(path);
            if !full.exists() {
                continue;
            }
            let _ = git_cmd()
                .args(["add", "--force", path])
                .current_dir(repo_root)
                .output()
                .await?;
        }

        // Check if there's anything staged
        let diff_output = git_cmd()
            .args(["diff", "--cached", "--quiet"])
            .current_dir(repo_root)
            .output()
            .await?;

        if diff_output.status.success() {
            return Ok(());
        }

        let commit_output = git_cmd()
            .args(["commit", "-m", "pqcrypt: state update"])
            .current_dir(repo_root)
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
            .current_dir(repo_root)
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
        let repo_root = self.local.root();

        // Remove all tracked files from the index
        let _ = git_cmd()
            .args(["rm", "-rf", "--ignore-unmatch", "."])
            .current_dir(repo_root)
            .output()
            .await;

        // Remove any untracked files and directories
        let _ = git_cmd()
            .args(["clean", "-fdx", "-e", ".git"])
            .current_dir(repo_root)
            .output()
            .await;

        Ok(())
    }

    async fn do_fetch_sync(&self) -> Result<()> {
        let repo_root = self.local.root();
        self.ensure_cache_repo().await?;

        let fetch_output = git_cmd()
            .args(["fetch", "origin"])
            .current_dir(repo_root)
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
            .current_dir(repo_root)
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
                    .current_dir(repo_root)
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
    // Delegate file operations to the embedded LocalStorage
    async fn get(&self, path: &str) -> Result<Vec<u8>> {
        self.local.get(path).await
    }

    async fn put(&self, path: &str, content: Vec<u8>) -> Result<()> {
        self.local.put(path, content).await
    }

    async fn list(&self, path: &str) -> Result<Vec<String>> {
        self.local.list(path).await
    }

    async fn delete(&self, path: &str) -> Result<()> {
        self.local.delete(path).await
    }

    async fn put_atomic(&self, path: &str, content: Vec<u8>) -> Result<()> {
        self.local.put_atomic(path, content).await
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

    async fn fetch_sync(&self) -> Result<()> {
        self.do_fetch_sync().await
    }

    async fn push_sync(&self) -> Result<()> {
        self.do_push_sync().await
    }
}
