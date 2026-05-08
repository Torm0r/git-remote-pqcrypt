use serde::{Deserialize, Serialize};
use std::collections::HashMap;

use crate::types::githash::GitHash;
use crate::types::gitref::GitRef;
use crate::types::packfilerecord::PackfileRecord;

#[derive(Debug, Serialize, Deserialize, Default)]
pub struct Manifest {
    pub heads: HashMap<GitRef, GitHash>,
    pub packfiles: Vec<PackfileRecord>,
}

impl Manifest {
    pub fn new() -> Self {
        Default::default()
    }
}
