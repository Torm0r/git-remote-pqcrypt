use std::collections::HashMap;

use serde::{Deserialize, Serialize};
//use hex_literal::hex;
use sha1_checked::Sha1;

use crate::types::{githash::GitHash, gitref::GitRef};

//let result = Sha1::try_digest(b"hello world");
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Manifest {
    head: GitRef,                   // (/refs/heads/main)
    refs: HashMap<GitRef, GitHash>, // refs/heads/main , HASH
}

impl Manifest {
    pub fn new() -> Self {
        Self {
            head: GitRef::new("refs/heads/main").unwrap(),
            refs: HashMap::new(),
        }
    }

    pub fn change_head(&mut self, head: GitRef) {
        self.head = head;
    }
    // Note: It's better to use `&self` here so you don't destroy/consume
    // the Manifest struct when you print it!
    pub fn output_git_list(&self) {
        // 1. Tell Git what the default branch is using the symref
        println!("@{} HEAD", self.head.as_str());

        // 2. Fix the closure: destructure the tuple into `ref_name` and `hash`
        self.refs.iter().for_each(|(ref_name, hash)| {
            // Print the hash first, then a space, then the branch name
            println!("{} {}", hash.as_str(), ref_name.as_str());
        });

        // 3. IMPORTANT: Print a blank line to tell Git you are done sending the list!
        println!();
    }

    pub fn input_ref(&mut self, git_ref: GitRef, git_hash: GitHash) {
        // The "Null Hash" is Git's universal symbol for "Delete this!"
        let null_hash = "0000000000000000000000000000000000000000";

        if git_hash.as_str() == null_hash {
            // It's a deletion! Remove the branch from the HashMap entirely.
            self.refs.remove(&git_ref);
        } else {
            self.refs.insert(git_ref, git_hash);
        }
    }
}
