use chacha20poly1305::aead::stream::{DecryptorBE32, EncryptorBE32};
use chacha20poly1305::{Key, KeyInit, XChaCha20Poly1305};
use rand::{rngs::OsRng, RngCore};
use std::io::{Read, Write};

/// Flag to dictate the operation
#[derive(Debug, Clone, Copy, PartialEq)]
pub enum CryptoMode {
    Encrypt,
    Decrypt,
}

/// Pipes data from ANY reader to ANY writer, using ChaCha20-Poly1305.
/// Memory usage is fixed at ~4KB, allowing it to encrypt/decrypt massive files.
pub fn pipe_crypto<R: Read, W: Write>(
    mut source: R,
    mut dest: W,
    key: &Key,
    mode: CryptoMode,
) -> Result<(), Box<dyn std::error::Error>> {
    // The STREAM construction requires a 19-byte nonce.
    let mut nonce_bytes = [0u8; 19];

    // We initialize the underlying cipher with our Master Key
    let aead = XChaCha20Poly1305::new(key);

    // We process the file in 4KB chunks
    let mut buffer = [0u8; 65536];

    match mode {
        CryptoMode::Encrypt => {
            // 1. Generate a random nonce specifically for this file
            OsRng.fill_bytes(&mut nonce_bytes);

            // 2. Write the 7-byte nonce to the very beginning of the destination file
            // so we know what it is when we need to decrypt it later.
            dest.write_all(&nonce_bytes)?;

            // 3. Setup the streaming encryptor
            let mut encryptor = EncryptorBE32::from_aead(aead, nonce_bytes.as_ref().into());

            // 4. Stream the data!
            loop {
                let read_count = source.read(&mut buffer)?;

                if read_count == buffer.len() {
                    // Buffer is full, encrypt a standard block
                    let ciphertext = encryptor
                        .encrypt_next(buffer.as_slice())
                        .map_err(|e| format!("Encryption error: {}", e))?;
                    dest.write_all(&ciphertext)?;
                } else {
                    // We hit the end of the file, encrypt the final partial block
                    let ciphertext = encryptor
                        .encrypt_last(&buffer[..read_count])
                        .map_err(|e| format!("Encryption error: {}", e))?;
                    dest.write_all(&ciphertext)?;
                    break; // Exit the loop
                }
            }
        }

        CryptoMode::Decrypt => {
            // 1. Read the first 19 bytes from the source file to recover the nonce
            source.read_exact(&mut nonce_bytes)?;

            // 2. Setup the streaming decryptor using that nonce
            let mut decryptor = DecryptorBE32::from_aead(aead, nonce_bytes.as_ref().into());

            // 3. Stream the data!
            // Note: Ciphertext blocks are 16 bytes larger than plaintext blocks because of MAC tags.
            // So we read in chunks of 4096 + 16 = 4112 bytes.
            let mut enc_buffer = [0u8; 65536 + 16];

            loop {
                let read_count = source.read(&mut enc_buffer)?;

                if read_count == enc_buffer.len() {
                    // Buffer is full, decrypt a standard block
                    let plaintext = decryptor
                        .decrypt_next(enc_buffer.as_slice())
                        .map_err(|e| format!("Decryption error (Corrupted file?): {}", e))?;
                    dest.write_all(&plaintext)?;
                } else {
                    // We hit the end of the file, decrypt the final partial block
                    let plaintext = decryptor
                        .decrypt_last(&enc_buffer[..read_count])
                        .map_err(|e| format!("Decryption error (Corrupted file?): {}", e))?;
                    dest.write_all(&plaintext)?;
                    break; // Exit the loop
                }
            }
        }
    }

    Ok(())
}
