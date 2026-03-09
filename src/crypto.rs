// src/crypto.rs

use std::fs::File;
use std::io::{BufReader, Read};
use blake3::Hasher;
use argon2::{Argon2, Algorithm, Version, Params};
use secrecy::{Secret, ExposeSecret};
use thiserror::Error;
use aes_gcm::{Aes256Gcm, Key, Nonce, aead::{Aead, KeyInit}};
use crate::format::Tpf2Header;

#[derive(Debug, Error)]
pub enum CryptoError {
    #[error("I/O Error processing the pulsar dataset: {0}")]
    IoError(#[from] std::io::Error),
    #[error("Argon2id Key Derivation failed")]
    KdfError,
    #[error("Encryption/Decryption failed: Payload tampered or wrong key")]
    AeadError,
}

/// Streams a massive Pulsar dataset through BLAKE3 using a tiny 64KB memory footprint.
pub fn hash_pulsar_dataset(file_path: &str) -> Result<blake3::Hash, CryptoError> {
    let file = File::open(file_path)?;
    let mut reader = BufReader::with_capacity(65_536, file);
    let mut hasher = Hasher::new();
    let mut buffer = [0u8; 65_536];

    loop {
        let bytes_read = reader.read(&mut buffer)?;
        if bytes_read == 0 {
            break;
        }
        hasher.update(&buffer[..bytes_read]);
    }

    Ok(hasher.finalize())
}

/// Derives the ultimate master key using the user's passphrase, the OS salt, 
/// and optionally the massive BLAKE3 dataset hash.
pub fn derive_master_key(
    passphrase: &Secret<String>,
    dataset_hash: Option<blake3::Hash>,
    os_salt: &[u8; 32],
    m_cost: u32,
    t_cost: u32,
    p_cost: u32,
) -> Result<Secret<Vec<u8>>, CryptoError> {
    let params = Params::new(m_cost, t_cost, p_cost, Some(32))
        .map_err(|_| CryptoError::KdfError)?;
    let argon2 = Argon2::new(Algorithm::Argon2id, Version::V0x13, params);

    let mut ikm = Vec::new();
    ikm.extend_from_slice(passphrase.expose_secret().as_bytes());
    
    if let Some(hash) = dataset_hash {
        ikm.extend_from_slice(hash.as_bytes());
    }

    let mut master_key = vec![0u8; 32];
    
    argon2.hash_password_into(ikm.as_slice(), os_salt, &mut master_key)
        .map_err(|_| CryptoError::KdfError)?;

    Ok(Secret::new(master_key))
}

/// Encrypts the payload using AES-256-GCM, cryptographically binding the TPF2 header.
pub fn encrypt_payload(
    master_key: &Secret<Vec<u8>>, 
    header: &Tpf2Header, 
    plaintext: &[u8]
) -> Result<Vec<u8>, CryptoError> {
    let key = Key::<Aes256Gcm>::from_slice(master_key.expose_secret().as_slice());
    let cipher = Aes256Gcm::new(key);
    let nonce = Nonce::from_slice(&header.nonce);

    let payload = aes_gcm::aead::Payload {
        msg: plaintext,
        aad: &header.as_bytes(),
    };

    cipher.encrypt(nonce, payload)
        .map_err(|_| CryptoError::AeadError)
}

/// Decrypts the payload, instantly failing if the header or ciphertext was tampered with.
pub fn decrypt_payload(
    master_key: &Secret<Vec<u8>>, 
    header: &Tpf2Header, 
    ciphertext: &[u8]
) -> Result<Vec<u8>, CryptoError> {
    let key = Key::<Aes256Gcm>::from_slice(master_key.expose_secret().as_slice());
    let cipher = Aes256Gcm::new(key);
    let nonce = Nonce::from_slice(&header.nonce);

    let payload = aes_gcm::aead::Payload {
        msg: ciphertext,
        aad: &header.as_bytes(),
    };

    cipher.decrypt(nonce, payload)
        .map_err(|_| CryptoError::AeadError)
}