pub enum StorageType {
    Local,
    Sftp,
    Git,
}

pub fn determine_type(url: &str) -> StorageType {
    let url = url.strip_prefix("pqcrypt://").unwrap_or(url);
    if url.starts_with("sftp://") || url.starts_with("ssh://") {
        StorageType::Sftp
    } else if url.starts_with("git@") || url.ends_with(".git") || url.starts_with("https://git") {
        StorageType::Git
    } else {
        StorageType::Local
    }
}

/// Dispatch to the correct storage backend based on URL, then call the provided
/// async expression with the constructed storage. Eliminates the repeated
/// `match determine_type { Local => ..., Sftp => ..., Git => ... }` boilerplate.
///
/// Usage:
/// ```ignore
/// with_storage!(repo_path, storage => {
///     do_something(storage).await
/// })
/// ```
#[macro_export]
macro_rules! with_storage {
    ($repo_path:expr, $storage:ident => $body:expr) => {{
        use $crate::storage::dispatch::{StorageType, determine_type};
        match determine_type($repo_path) {
            StorageType::Local => {
                let $storage = $crate::storage::local::LocalStorage::new($repo_path).await?;
                $body
            }
            StorageType::Sftp => {
                let $storage = $crate::storage::sftp::SftpStorage::new($repo_path).await?;
                $body
            }
            StorageType::Git => {
                let $storage = $crate::storage::git_ssh::GitStorage::new($repo_path).await?;
                $body
            }
        }
    }};
}
