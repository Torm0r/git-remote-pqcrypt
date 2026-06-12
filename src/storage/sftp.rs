use anyhow::anyhow;
use futures::{StreamExt, pin_mut};
use openssh::{KnownHosts, Session};
use openssh_sftp_client::{Sftp, SftpOptions};
use std::sync::Arc;

use crate::storage::{LockGuard, Result, Storage, StorageError};

fn parse_sftp_url(url: &str) -> std::result::Result<(String, String), StorageError> {
    let url = url.strip_prefix("sftp://").unwrap_or(url);
    let (authority, path) = url.split_once('/').unwrap_or((url, ""));
    let path = format!("/{}", path.trim_start_matches('/'));
    Ok((format!("ssh://{}", authority), path))
}

fn rpath(root: &str, relative: &str) -> String {
    format!("{}/{}", root.trim_end_matches('/'), relative)
}

/// Ensure all parent directories of `path` exist on the remote.
/// Walks from the root downward, ignoring "already exists" errors.
async fn ensure_parent_dirs(sftp: &Sftp, path: &str) {
    let parent = match path.rsplit_once('/') {
        Some((parent, _)) if !parent.is_empty() => parent,
        _ => return,
    };

    let mut cumulative = String::new();
    for component in parent.split('/') {
        if component.is_empty() {
            cumulative.push('/');
            continue;
        }
        if cumulative.is_empty() || cumulative == "/" {
            cumulative = format!("{}{}", cumulative, component);
        } else {
            cumulative = format!("{}/{}", cumulative, component);
        }
        // Ignore errors — the directory likely already exists.
        let mut fs = sftp.fs();
        fs.create_dir(&cumulative).await.ok();
    }
}

#[derive(Clone)]
pub struct SftpStorage {
    sftp: Arc<Sftp>,
    remote_root: String,
}

impl SftpStorage {
    pub async fn new(url: &str) -> Result<Self> {
        let (connection_string, path) = parse_sftp_url(url)?;
        let session = Session::connect_mux(connection_string, KnownHosts::Strict)
            .await
            .map_err(|e| StorageError::Other(anyhow!(e)))?;
        let sftp = Sftp::from_session(session, SftpOptions::default())
            .await
            .map_err(|e| StorageError::Other(anyhow!(e)))?;
        Ok(SftpStorage {
            sftp: Arc::new(sftp),
            remote_root: path,
        })
    }
}

fn is_not_found(e: &openssh_sftp_client::Error) -> bool {
    let msg = e.to_string().to_lowercase();
    msg.contains("no such file") || msg.contains("not found")
}

impl Storage for SftpStorage {
    async fn get(&self, path: &str) -> Result<Vec<u8>> {
        let mut fs = self.sftp.fs();
        let remote_path = rpath(&self.remote_root, path);
        fs.read(&remote_path)
            .await
            .map(|data| data.to_vec())
            .map_err(|e| {
                if is_not_found(&e) {
                    StorageError::NotFound(path.to_string())
                } else {
                    StorageError::Other(anyhow!(e))
                }
            })
    }

    async fn put(&self, path: &str, content: Vec<u8>) -> Result<()> {
        let remote_path = rpath(&self.remote_root, path);
        ensure_parent_dirs(&self.sftp, &remote_path).await;
        let mut fs = self.sftp.fs();
        fs.write(&remote_path, content)
            .await
            .map_err(|e| StorageError::Other(anyhow!(e)))
    }

    async fn list(&self, path: &str) -> Result<Vec<String>> {
        let mut fs = self.sftp.fs();
        let remote_path = rpath(&self.remote_root, path);
        let dir = fs
            .open_dir(&remote_path)
            .await
            .map_err(|e| StorageError::Other(anyhow!(e)))?;
        let read_dir = dir.read_dir();
        pin_mut!(read_dir);
        let mut entries = Vec::new();
        while let Some(entry) = read_dir.next().await {
            let entry = entry.map_err(|e| StorageError::Other(anyhow!(e)))?;
            entries.push(entry.filename().to_string_lossy().to_string());
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
        let mut fs = self.sftp.fs();
        let remote_path = rpath(&self.remote_root, path);
        match fs.remove_file(&remote_path).await {
            Ok(_) => Ok(()),
            Err(e) if is_not_found(&e) => Ok(()),
            Err(e) => Err(StorageError::Other(anyhow!(e))),
        }
    }

    async fn put_atomic(&self, path: &str, content: Vec<u8>) -> Result<()> {
        let remote_path = rpath(&self.remote_root, path);
        let remote_tmp_path = format!("{}.tmp", &remote_path);

        ensure_parent_dirs(&self.sftp, &remote_path).await;

        let mut fs = self.sftp.fs();
        fs.write(&remote_tmp_path, content)
            .await
            .map_err(|e| StorageError::Other(anyhow!(e)))?;

        fs.rename(&remote_tmp_path, &remote_path)
            .await
            .map_err(|e| StorageError::Other(anyhow!(e)))?;
        Ok(())
    }
}
