# git-remote-pqcrypt
----
```md
THIS IS AN EXPERIMENTAL PROJECT, there hasnt been a formal security audit. DO NOT rely on this for any critical repositories.
```

`git-remote-pqcrypt` is an encrypted Git remote helper similar to [gcrypt](https://github.com/spwhitton/git-remote-gcrypt). It stores Git packfiles and repository metadata encrypted at rest. Access is with post-quantum XWing wrapping.

## How it works
1. `git-remote-pqcrypt init` creates a repository master key.
2. The master key is wrapped for each user with their public key
3. Git packfiles and manifest are encrypted using the master key
4. Git uses pqcrypt through `git-remote-pqcrypt` remote helper
5. The Master key is decrypted locally by the helper and then packfiles are decrypted to local repository


Example files of remote storage:
```
keys.json
manifest.enc
objects/
    pack-.....pack.enc
```
`keys.json` contains metadata and encrypted master key wrappings.


## Installation 
Build with default backend support:

```bash
cargo build --release
```

This includes local filesystem and Git-backed storage support.

To enable SFTP support on Unix-like systems:

```bash
cargo build --release --features sftp
```

The `sftp` feature is currently not supported on Windows.
Install the binary to your PATH:
```bash
sudo cp target/release/git-remote-pqcrypt /usr/local/bin/
```
Name must remain the same since Git finds remote helpers by name `git-remote-[name]`.

Then check if it is working:
```bash
git-remote-pqcrypt --help
```

## Requirements

- Rust toolchain for building from source
- `git` must be installed
- For Git-backed storage, working Git credentials and a configured Git identity are required
- For SSH/SFTP access, existing SSH authentication must be configured
- SFTP support requires building with `--features sftp` and is currently Unix-like only

## Quick start

1. Go to an existing Git repository or make one
2. Initialize pqcrypt storage

Local path:
```bash
git-remote-pqcrypt init pqcrypt:///path/to/encrypted-store
```

SFTP requires building with the `sftp` feature and is currently supported only on Unix-like systems:

```bash
git-remote-pqcrypt init pqcrypt::sftp://user@example.com/path/to/store
```

Git-backed:
```bash
git-remote-pqcrypt init pqcrypt::git@example.com:org/store.git
```

If no private key exists, one is generated at `~/.config/pqcrypt/key` and the public key is printed.

You will be prompted for an optional key comment (e.g. `personal`, `work-laptop`).

After init git remote named `pqcrypt` is added. 
```bash
pqcrypt  pqcrypt::/path/to/encrypted-store (fetch)
pqcrypt  pqcrypt::/path/to/encrypted-store (push)
```

3. Push
```bash
git push pqcrypt main
```

4. Clone or fetch
```bash
git clone pqcrypt::git@github.com:Torm0r/pqcrypt-test.git my-clone
```

5. Add another user

- They must generate a keypair with:
    ```bash
    git-remote-pqcrypt keygen
    ```
- They get their public key with: 
    ```bash
    git-remote-pqcrypt pubgen ~/.config/pqcrypt/key
    ```
    or just paste it to you since `keygen` prints it.
- Now you must add them to the repository:
    ```bash
    git-remote-pqcrypt add-user <base64-public-key>
    ```
    run `git-remote-pqcrypt add-user -h` for more options.
- By default `add-user` looks for a local Git remote whose URL starts with `pqcrypt` and adds the public key there.


## Git-backed storage cache
For Git-backed storage URLs, pqcrypt maintains a local cache under the system cache directory, for example:
```md
~/.cache/pqcrypt/
```
pqcrypt fetches encrypted state from the backing Git repository before operations and pushes encrypted state after updates.

If cache corruption is detected, pqcrypt attempts to recreate the cache automatically.

## URL formats

`pqcrypt::`, `pqcrypt://`, and `pqcrypt:` are all accepted and normalized internally to `pqcrypt::`. These are equivalent:
```bash
git-remote-pqcrypt init pqcrypt:///path/to/store
git-remote-pqcrypt init pqcrypt::/path/to/store
git-remote-pqcrypt init pqcrypt:/path/to/store
```

Backend is determined by the storage path:

| Pattern | Backend | Notes |
|---|---|---|
| `/local/path` | Local filesystem | Default |
| `git@host:`, `*.git`, `https://git*` | Git-backed | Default |
| `sftp://` or `ssh://` | SFTP | Requires `--features sftp`; Unix-like systems only |

## Private key discovery logic

During decryption pqcrypt looks for private key in this order:
1. `PQCRYPT_KEY_PATH` environment variable
2. `git config pqcrypt.keypath`
3. `.pqcrypt/key` in the current directory 
4. Any matching key file in `~/.config/pqcrypt` (all are tested)

For multi-key setups (e.g. work and personal):

```bash
git config pqcrypt.keypath ~/.config/pqcrypt/work-key
```
The key must be one that was used during `init` or added via `add-user`.

## CI builds

GitHub Actions builds the project on Linux, macOS, and Windows. Workflow artifacts may contain binaries from CI runs, but these are not official releases.

## Security info

- Repository contents are encrypted using `XChaCha20Poly1305`.
- The repository master key is wrapped for users using HPKE with `XWing`.
- Each authorized public key receives its own encrypted copy of the master key.
- Comments attached to keys are authenticated as HPKE associated data. (meaning that in case of corruption you will be unable to decrypt master key)
- Git refs and packfile metadata are stored inside the encrypted manifest.
- Private key files are created with `0600` permissions on Unix-like systems.

## Limitations

- Currently only local filesystem, Git-backed, and optional SFTP storage backends are supported.
- SFTP support is behind the optional `sftp` feature and is currently not supported on Windows.
- Git remote-helper behavior is minimal and may not support every Git workflow or CI/CD operation.
- SFTP/Git backends lack locking, so concurrent pushes might lead to data loss.
- HPKE crate depends on a git source because XWing is not supported yet on published crate releases. This will be changed once HPKE is updated.
- Test coverage is currently minimal; end-to-end backend tests are still limited.
- No way to revoke or remove user access. Since users can recover the master key from Git history, the best course of action is to re-init the repository with a new master key and wipe the remote.
- The storage format might change in future versions.
- Git-backed storage requires working Git credentials and a configured Git identity for commits.
- For Git, SSH, or SFTP authentication, pqcrypt relies on existing SSH/Git credentials.
- `ssh` and `git` must be installed.
