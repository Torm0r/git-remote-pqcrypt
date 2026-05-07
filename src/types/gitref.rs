use serde::{Deserialize, Serialize};

#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq, Hash)]
#[serde(transparent)]
pub struct GitRef(String);

impl GitRef {
    // Enforces Git's reference naming conventions
    pub fn new(ref_name: &str) -> Result<Self, &'static str> {
        // 1. Git refs cannot contain whitespace
        if ref_name.contains(char::is_whitespace) {
            return Err("Invalid reference! Git references cannot contain whitespace.");
        }

        // 2. Must be exactly "HEAD", or start with standard namespaces
        if ref_name == "HEAD"
            || ref_name.starts_with("refs/heads/")
            || ref_name.starts_with("refs/tags/")
        {
            Ok(Self(ref_name.to_string()))
        } else {
            Err("Invalid reference! Must be 'HEAD', or start with 'refs/heads/' or 'refs/tags/'.")
        }
    }

    // Helper to easily get the string back
    pub fn as_str(&self) -> &str {
        &self.0
    }
}
