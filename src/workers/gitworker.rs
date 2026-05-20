use anyhow::{anyhow, Result};
use std::collections::HashMap;
use std::io::{self, BufRead, BufReader, Write};
use std::process::{Command, Stdio};
use std::str::FromStr;
use zeroize::Zeroizing;

use crate::storage::Storage;
use crate::types::githash::GitHash;
use crate::types::gitref::GitRef;
use crate::types::manifest::Manifest;
use crate::types::packfilerecord::PackfileRecord;
use crate::workers::cryptworker;

pub struct GitWorker<S: Storage> {
    storage: S,
    master_key: Zeroizing<Vec<u8>>,
    manifest: Manifest,
}

impl<S: Storage + Clone + Send + Sync + 'static> GitWorker<S> {
    pub fn new(storage: S, master_key: Zeroizing<Vec<u8>>) -> Self {
        GitWorker {
            storage,
            master_key,
            manifest: Manifest::new(),
        }
    }

    pub async fn run(&mut self) -> Result<()> {
        self.load_manifest().await?;

        let stdin = io::stdin();
        let mut reader = BufReader::new(stdin.lock());
        let mut batch: Vec<String> = Vec::new();

        loop {
            let mut line = String::new();
            match reader.read_line(&mut line) {
                Ok(0) => break, // EOF
                Ok(_) => {
                    let trimmed = line.trim().to_string();

                    if trimmed.is_empty() {
                        // Blank line = end of batch. Process any queued commands.
                        if !batch.is_empty() {
                            self.process_batch(&batch).await?;
                            batch.clear();
                        }
                        io::stdout().flush()?;
                        continue;
                    }

                    let cmd = trimmed.split_whitespace().next().unwrap_or("");
                    match cmd {
                        "capabilities" => {
                            // Respond immediately (not batched)
                            println!("push");
                            println!("fetch");
                            println!();
                            io::stdout().flush()?;
                        }
                        "list" => {
                            // Respond immediately (not batched)
                            self.list_refs();
                            io::stdout().flush()?;
                        }
                        "push" | "fetch" => {
                            // Queue for batch processing
                            batch.push(trimmed);
                        }
                        _ => {
                            eprintln!("error: Unknown command: {}", trimmed);
                        }
                    }
                }
                Err(e) => return Err(anyhow!("Failed to read from stdin: {}", e)),
            }
        }
        Ok(())
    }

    /// Process a batch of push or fetch commands, then print a terminating blank line.
    async fn process_batch(&mut self, batch: &[String]) -> Result<()> {
        for line in batch {
            let parts: Vec<&str> = line.split_whitespace().collect();
            let cmd = parts[0];
            let arg = parts.get(1).map(|s| *s).unwrap_or("");

            match cmd {
                "push" => {
                    // Parse refspec: "+src:dst" or "src:dst" -> extract dst
                    let refspec = arg.trim_start_matches('+');
                    let dst_ref = refspec.split(':').nth(1).unwrap_or(refspec);
                    match self.do_push(refspec).await {
                        Ok(_) => {
                            println!("ok {}", dst_ref);
                        }
                        Err(e) => {
                            println!("error {} {}", dst_ref, e);
                        }
                    }
                }
                "fetch" => {
                    if let Err(e) = self.do_fetch(arg).await {
                        eprintln!("error: fetch {} failed: {}", arg, e);
                    }
                }
                _ => {}
            }
        }
        // Blank line terminates the batch response
        println!();
        io::stdout().flush()?;
        Ok(())
    }

    async fn load_manifest(&mut self) -> Result<()> {
        match self.storage.get("manifest.enc").await {
            Ok(encrypted_manifest) => {
                let decrypted = cryptworker::decrypt_bytes(&encrypted_manifest, &self.master_key)?;
                self.manifest = serde_json::from_slice(&decrypted)?;
            }
            Err(e) => {
                eprintln!(
                    "warning: Could not load manifest.enc: {}. Assuming empty repository.",
                    e
                );
                self.manifest = Manifest::new();
            }
        }
        Ok(())
    }

    async fn save_manifest(&self) -> Result<()> {
        let manifest_json = serde_json::to_string(&self.manifest)?;
        let encrypted = cryptworker::encrypt_bytes(manifest_json.as_bytes(), &self.master_key)?;
        self.storage.put("manifest.enc", &encrypted).await?;
        Ok(())
    }

    fn list_refs(&self) {
        for (git_ref, git_hash) in self.manifest.heads.iter() {
            println!("{} {}", git_hash, git_ref);
        }
        // Tell git which ref HEAD points to.
        // If we have refs/heads/main, use that; otherwise use the first branch.
        let default_ref = self
            .manifest
            .heads
            .keys()
            .find(|r| r.as_str() == "refs/heads/main")
            .or_else(|| self.manifest.heads.keys().next());

        if let Some(head_ref) = default_ref {
            println!("@{} HEAD", head_ref);
        }
        println!(); // blank line terminates list
    }

    /// Push a refspec like "refs/heads/main:refs/heads/main".
    /// Returns the destination ref on success.
    async fn do_push(&mut self, ref_spec: &str) -> Result<String> {
        let parts: Vec<&str> = ref_spec.split(':').collect();
        if parts.len() != 2 {
            return Err(anyhow!("Invalid refspec: {}", ref_spec));
        }
        let local_ref = parts[0];
        let remote_ref = parts[1];

        // Acquire lock
        let lock_guard = self.storage.lock().await?;

        // Handle deletion: if local_ref is empty, git wants to delete remote_ref
        if local_ref.is_empty() {
            self.manifest
                .heads
                .remove(&GitRef::from_str(remote_ref).unwrap());
            self.save_manifest().await?;
            lock_guard.release().await?;
            return Ok(remote_ref.to_string());
        }

        // Resolve local refs
        let local_heads = self.resolve_local_heads()?;
        let current_remote_hash = self
            .manifest
            .heads
            .get(&GitRef::from_str(remote_ref).unwrap());
        let local_hash = local_heads
            .get(&GitRef::from_str(remote_ref).unwrap())
            .ok_or_else(|| anyhow!("No local ref found for {}", local_ref))?;

        let commit_range = match current_remote_hash {
            Some(r_hash) => format!("^{}\n{}\n", r_hash, local_hash),
            None => format!("{}\n", local_hash),
        };

        // Generate packfile via git pack-objects
        let pack_data = self.run_pack_objects(&commit_range)?;

        // Encrypt and upload
        let encrypted_pack = cryptworker::encrypt_bytes(&pack_data, &self.master_key)?;
        let pack_id = uuid::Uuid::new_v4().to_string();
        let remote_pack_path = format!("objects/pack-{}.pack.enc", pack_id);
        self.storage.put(&remote_pack_path, &encrypted_pack).await?;

        // Update manifest
        let new_head_hash = local_hash.clone();
        self.manifest
            .heads
            .insert(GitRef::from_str(remote_ref).unwrap(), new_head_hash.clone());
        self.manifest.packfiles.push(PackfileRecord {
            id: pack_id,
            path: remote_pack_path,
            contains_commits: vec![new_head_hash],
        });
        self.save_manifest().await?;
        lock_guard.release().await?;

        Ok(remote_ref.to_string())
    }

    /// Fetch objects for a given sha + ref, e.g. "abc123 refs/heads/main"
    async fn do_fetch(&mut self, _arg: &str) -> Result<()> {
        // We must process packfiles in chronological order to resolve thin-pack deltas.
        for pack_record in &self.manifest.packfiles {
            // Check if we already have the objects this pack provides
            let mut all_present = true;
            for commit in &pack_record.contains_commits {
                let status = Command::new("git")
                    .args(["cat-file", "-e", commit.as_str()])
                    .status()?;
                if !status.success() {
                    all_present = false;
                    break;
                }
            }

            if all_present {
                continue; // We already have this pack's commits
            }

            let encrypted_pack = self.storage.get(&pack_record.path).await?;
            let decrypted_pack = cryptworker::decrypt_bytes(&encrypted_pack, &self.master_key)?;
            self.run_index_pack(&decrypted_pack)?;
        }

        Ok(())
    }

    // --- Git subprocess helpers ---

    fn resolve_local_heads(&self) -> Result<HashMap<GitRef, GitHash>> {
        let output = Command::new("git")
            .args(["ls-remote", "--heads", "."])
            .stdout(Stdio::piped())
            .output()?;

        let stdout = String::from_utf8(output.stdout)?;
        let mut heads = HashMap::new();
        for line in stdout.lines() {
            let parts: Vec<&str> = line.split_whitespace().collect();
            if parts.len() == 2 {
                heads.insert(
                    GitRef::from_str(parts[1]).unwrap(),
                    GitHash::new(parts[0].to_string())?,
                );
            }
        }
        Ok(heads)
    }

    fn run_pack_objects(&self, commit_range: &str) -> Result<Vec<u8>> {
        let mut child = Command::new("git")
            .args([
                "pack-objects",
                "--stdout",
                "--revs",
                "--thin",
                "--delta-base-offset",
            ])
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::inherit())
            .spawn()?;

        if let Some(mut stdin) = child.stdin.take() {
            stdin.write_all(commit_range.as_bytes())?;
            stdin.write_all(b"\n")?;
        }

        let output = child.wait_with_output()?;
        if !output.status.success() {
            return Err(anyhow!("git pack-objects failed"));
        }
        Ok(output.stdout)
    }

    fn run_index_pack(&self, pack_data: &[u8]) -> Result<()> {
        let mut child = Command::new("git")
            .args(["index-pack", "--stdin", "--fix-thin"])
            .stdin(Stdio::piped())
            .stdout(Stdio::null())
            .stderr(Stdio::inherit())
            .spawn()?;

        if let Some(mut stdin) = child.stdin.take() {
            stdin.write_all(pack_data)?;
        }

        let status = child.wait()?;
        if !status.success() {
            return Err(anyhow!("git index-pack failed"));
        }
        Ok(())
    }
}
