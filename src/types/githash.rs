use serde::{Deserialize, Serialize};
use std::collections::HashMap;

// The `transparent` macro tells Serde: "When saving to JSON,
// pretend this struct doesn't exist and just output the inner String."
#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq, Hash)]
#[serde(transparent)]
pub struct GitHash(String);
impl GitHash {
    // The ONLY way to create a GitHash. It enforces the rules.
    pub fn new(hash: &str) -> Result<Self, &'static str> {
        if hash.len() == 40 && hash.chars().all(|c| c.is_ascii_hexdigit()) {
            Ok(Self(hash.to_string()))
        } else {
            Err("Invalid SHA-1 hash format! Must be 40 hex characters.")
        }
    }

    // A helper to easily print it back to Git
    pub fn as_str(&self) -> &str {
        &self.0
    }
}
