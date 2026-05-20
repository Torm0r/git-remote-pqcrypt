use anyhow::{anyhow, Result};
use chacha20poly1305::aead::stream::{DecryptorBE32, EncryptorBE32};
use chacha20poly1305::{Key, KeyInit, XChaCha20Poly1305};
use rand::{rngs::OsRng, RngCore};
use std::io::{self, Read, Write};
use zeroize::Zeroizing;

pub enum CryptoMode {
    Encrypt,
    Decrypt,
}

const CHUNK_SIZE: usize = 64 * 1024;
// XChaCha20 streaming uses a 19-byte nonce (24 bytes total - 5 bytes for the stream counter)
const STREAM_NONCE_SIZE: usize = 19;
// Poly1305 auth tag added to every chunk
const TAG_SIZE: usize = 16;

pub fn pipe_crypto<R: Read, W: Write>(
    mut source: R,
    mut dest: W,
    key: &[u8],
    mode: CryptoMode,
) -> Result<()> {
    if key.len() != 32 {
        return Err(anyhow!("Key must be exactly 32 bytes"));
    }

    let cipher_key = Key::from_slice(key);
    let aead = XChaCha20Poly1305::new(cipher_key);
    let mut nonce_bytes = [0u8; STREAM_NONCE_SIZE];

    match mode {
        CryptoMode::Encrypt => {
            // 1. Generate ONE nonce for the entire stream
            OsRng.fill_bytes(&mut nonce_bytes);
            dest.write_all(&nonce_bytes)?;

            let mut encryptor = EncryptorBE32::from_aead(aead, nonce_bytes.as_ref().into());
            let mut buffer = Zeroizing::new(vec![0u8; CHUNK_SIZE]);

            loop {
                // Safely fill the buffer to the brim, handling short reads
                let read_count = read_up_to(&mut source, &mut buffer)?;

                if read_count == CHUNK_SIZE {
                    let ciphertext = encryptor
                        .encrypt_next(&buffer[..])
                        .map_err(|e| anyhow!("Stream encryption error: {}", e))?;
                    dest.write_all(&ciphertext)?;
                } else {
                    // We truly hit EOF. Encrypt the final partial block and exit.
                    let ciphertext = encryptor
                        .encrypt_last(&buffer[..read_count])
                        .map_err(|e| anyhow!("Final block encryption error: {}", e))?;
                    dest.write_all(&ciphertext)?;
                    break;
                }
            }
        }

        CryptoMode::Decrypt => {
            // 1. Read the ONE nonce from the top of the file
            source
                .read_exact(&mut nonce_bytes)
                .map_err(|e| anyhow!("Failed to read stream nonce: {}", e))?;

            let mut decryptor = DecryptorBE32::from_aead(aead, nonce_bytes.as_ref().into());

            // Ciphertext chunks are larger due to the MAC tag
            let mut buffer = Zeroizing::new(vec![0u8; CHUNK_SIZE + TAG_SIZE]);

            loop {
                // Safely fill the buffer handling short reads
                let read_count = read_up_to(&mut source, &mut buffer)?;

                if read_count == CHUNK_SIZE + TAG_SIZE {
                    let plaintext = Zeroizing::new(
                        decryptor
                            .decrypt_next(&buffer[..])
                            .map_err(|e| anyhow!("Corrupted stream or bad key: {}", e))?,
                    );
                    dest.write_all(&plaintext)?;
                } else {
                    // We truly hit EOF. Decrypt the final partial block and exit.
                    let plaintext = Zeroizing::new(
                        decryptor
                            .decrypt_last(&buffer[..read_count])
                            .map_err(|e| anyhow!("Corrupted EOF block or bad key: {}", e))?,
                    );
                    dest.write_all(&plaintext)?;
                    break;
                }
            }
        }
    }

    Ok(())
}

/// Helper: Forces Rust to keep reading until the buffer is full OR we hit true EOF.
fn read_up_to<R: Read>(source: &mut R, buf: &mut [u8]) -> Result<usize> {
    let mut total = 0;
    while total < buf.len() {
        match source.read(&mut buf[total..]) {
            Ok(0) => break, // True EOF
            Ok(n) => total += n,
            Err(e) if e.kind() == io::ErrorKind::Interrupted => continue,
            Err(e) => return Err(anyhow!("I/O Read error: {}", e)),
        }
    }
    Ok(total)
}

/// Encrypt bytes in-memory.
pub fn encrypt_bytes(plaintext: &[u8], key: &[u8]) -> Result<Vec<u8>> {
    let mut output = Vec::new();
    pipe_crypto(
        io::Cursor::new(plaintext),
        &mut output,
        key,
        CryptoMode::Encrypt,
    )?;
    Ok(output)
}

/// Decrypt bytes in-memory.
pub fn decrypt_bytes(ciphertext: &[u8], key: &[u8]) -> Result<Zeroizing<Vec<u8>>> {
    let mut output = Zeroizing::new(Vec::new());
    pipe_crypto(
        io::Cursor::new(ciphertext),
        &mut *output,
        key,
        CryptoMode::Decrypt,
    )?;
    Ok(output)
}
