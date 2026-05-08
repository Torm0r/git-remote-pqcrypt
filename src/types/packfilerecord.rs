use crate::types::githash::GitHash;
use serde::{Deserialize, Serialize};

#[derive(Debug, Serialize, Deserialize)]
pub struct PackfileRecord {
    pub id: String,
    pub path: String, // Relative path to the packfile (e.g., "objects/pack-abc.pack.enc")
    pub contains_commits: Vec<GitHash>, // List of commit hashes contained in this packfile
}
