use anyhow::Result;
use async_trait::async_trait;

pub mod sftp;

#[async_trait]
pub trait Storage: Send + Sync + Clone + 'static {
    /// Retrieves the content of a file.
    async fn get(&self, path: &str) -> Result<Vec<u8>>;

    /// Puts content into a file, overwriting if it exists.
    async fn put(&self, path: &str, content: &[u8]) -> Result<()>;

    /// Lists files or directories at a given path.
    async fn list(&self, path: &str) -> Result<Vec<String>>;

    /// Acquires a distributed lock for the repository.
    async fn lock(&self) -> Result<LockGuard<Self>>;

    /// Releases a distributed lock for the repository.
    async fn unlock(&self) -> Result<()>;
}

/// RAII guard that automatically releases the storage lock on drop.
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
