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
