#[derive(Debug, Clone)]
pub struct ParsedPqcryptUrl {
    pub canonical: String,
    pub storage_path: String,
}

pub fn parse_pqcrypt_url(input: &str) -> ParsedPqcryptUrl {
    if let Some(rest) = input.strip_prefix("pqcrypt::") {
        ParsedPqcryptUrl {
            canonical: format!("pqcrypt::{}", rest),
            storage_path: rest.to_string(),
        }
    } else if let Some(rest) = input.strip_prefix("pqcrypt://") {
        ParsedPqcryptUrl {
            canonical: format!("pqcrypt::{}", rest),
            storage_path: rest.to_string(),
        }
    } else if let Some(rest) = input.strip_prefix("pqcrypt:") {
        ParsedPqcryptUrl {
            canonical: format!("pqcrypt::{}", rest),
            storage_path: rest.to_string(),
        }
    } else {
        ParsedPqcryptUrl {
            canonical: format!("pqcrypt::{}", input),
            storage_path: input.to_string(),
        }
    }
}
