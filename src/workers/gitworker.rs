use std::io::{self, BufRead};

use crate::types::manifest::Manifest;

pub struct GitWorker {
    manifest: Manifest,

    // Buffers to hold commands until Git sends a blank line
    pending_fetches: Vec<(String, String)>, // (Hash, Ref)
    pending_pushes: Vec<String>,            // Raw push command strings
}

impl GitWorker {
    pub fn new(manifest: Manifest) -> Self {
        Self {
            manifest,
            pending_fetches: Vec::new(),
            pending_pushes: Vec::new(),
        }
    }

    // The main loop that blocks and listens to Git forever
    pub fn run(&mut self) {
        let stdin = io::stdin();
        let mut lines = stdin.lock().lines();

        while let Some(Ok(line)) = lines.next() {
            let line = line.trim();

            if line == "capabilities" {
                self.handle_capabilities();
            } else if line.starts_with("list") {
                self.handle_list();
            } else if line.starts_with("fetch ") {
                self.buffer_fetch(line);
            } else if line.starts_with("push ") {
                self.buffer_push(line);
            } else if line.is_empty() {
                // THE BLANK LINE: Time to execute the buffers!
                self.execute_batches();
            } else {
                eprintln!("Unsupported command from Git: {}", line);
            }
        }
    }

    fn handle_capabilities(&self) {
        println!("fetch");
        println!("push");
        println!(); // Blank line means done sending capabilities
    }

    fn handle_list(&self) {
        // Here we just call the method you already wrote!
        self.manifest.output_git_list();
    }

    fn buffer_fetch(&mut self, line: &str) {
        // e.g. "fetch [HASH] refs/heads/main"
        let parts: Vec<&str> = line.split_whitespace().collect();
        if parts.len() == 3 {
            self.pending_fetches
                .push((parts[1].to_string(), parts[2].to_string()));
        }
    }

    fn buffer_push(&mut self, line: &str) {
        // e.g. "push refs/heads/main:refs/heads/main"
        self.pending_pushes.push(line.to_string());
    }

    fn execute_batches(&mut self) {
        // 1. Execute Fetches (if any)
        if !self.pending_fetches.is_empty() {
            // TODO: Download actual Git objects from S3 here

            // Clear the buffer and tell Git we finished fetching
            self.pending_fetches.clear();
            println!();
        }

        // 2. Execute Pushes (if any)
        if !self.pending_pushes.is_empty() {
            for push_line in &self.pending_pushes {
                // Use the string-splitting logic we talked about earlier
                // to update self.manifest.input_ref()
                // and print "ok refs/heads/main"
            }

            // TODO: Upload the actual Git objects to S3
            // TODO: Upload the updated Manifest JSON to S3

            // Clear the buffer and tell Git we are done pushing
            self.pending_pushes.clear();
            println!();
        }
    }
}
