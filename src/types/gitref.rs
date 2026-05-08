use anyhow::{anyhow, Result};
use serde::{Deserialize, Serialize};
use std::fmt;
use std::str::FromStr;

#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct GitRef(String);

impl GitRef {
    // Enforces Git's reference naming conventions
    pub fn new(ref_name: String) -> Result<Self> {
        // 1. Git refs cannot contain whitespace
        if ref_name.contains(char::is_whitespace) {
            return Err(anyhow!(
                "Invalid reference! Git references cannot contain whitespace."
            ));
        }

        // 2. Must be exactly "HEAD", or start with standard namespaces
        if ref_name == "HEAD"
            || ref_name.starts_with("refs/heads/")
            || ref_name.starts_with("refs/tags/")
        {
            Ok(Self(ref_name.to_string()))
        } else {
            Err(anyhow!(
                "Invalid reference! Must be 'HEAD', or start with 'refs/heads/' or 'refs/tags/'."
            ))
        }
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Display for GitRef {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.0)
    }
}

impl FromStr for GitRef {
    type Err = anyhow::Error;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        GitRef::new(s.to_string())
    }
}
