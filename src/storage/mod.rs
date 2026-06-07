use async_trait::async_trait;
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

pub mod dispatch;
pub mod git_ssh;
pub mod local;
pub mod sftp;

#[async_trait]
pub trait Storage: Send + Sync + Clone + 'static {
    async fn get(&self, path: &str) -> Result<Vec<u8>>;

    async fn put(&self, path: &str, content: &[u8]) -> Result<()>;

    async fn list(&self, path: &str) -> Result<Vec<String>>;

    async fn lock(&self) -> Result<LockGuard<Self>>;

    async fn unlock(&self) -> Result<()>;
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
