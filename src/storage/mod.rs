use thiserror::Error;

pub type Result<T> = std::result::Result<T, StorageError>;

#[derive(Debug, Error)]
pub enum StorageError {
    #[error("File not found: {0}")]
    NotFound(String),
    #[error("Network/IO error: {0}")]
    Io(#[from] std::io::Error),
    #[error("{0}")]
    Other(#[from] anyhow::Error),
}

pub(crate) mod dispatch;
pub(crate) mod git_ssh;
pub(crate) mod local;
#[cfg(feature = "sftp")]
pub(crate) mod sftp;
#[allow(dead_code)]
pub trait Storage: Send + Sync + Clone {
    async fn get(&self, path: &str) -> Result<Vec<u8>>;

    async fn put(&self, path: &str, content: Vec<u8>) -> Result<()>;

    async fn list(&self, path: &str) -> Result<Vec<String>>;

    async fn lock(&self) -> Result<LockGuard<Self>>;

    async fn unlock(&self) -> Result<()>;

    async fn delete(&self, path: &str) -> Result<()>;

    async fn put_atomic(&self, path: &str, content: Vec<u8>) -> Result<()>;

    async fn fetch_sync(&self) -> Result<()> {
        Ok(())
    }

    async fn push_sync(&self) -> Result<()> {
        Ok(())
    }
}

pub struct LockGuard<S: Storage> {
    pub(crate) storage: S,
    pub(crate) locked: bool,
}

impl<S: Storage> LockGuard<S> {
    pub async fn release(mut self) -> Result<()> {
        if self.locked {
            self.locked = false;
            self.storage.unlock().await?;
        }
        Ok(())
    }
}
