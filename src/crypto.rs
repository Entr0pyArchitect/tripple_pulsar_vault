// src/crypto.rs

use std::fs::File;
use std::io::{BufReader, Read};

use aes_gcm::{
    aead::{Aead, KeyInit, Payload},
    Aes256Gcm, Key, Nonce,
};
use argon2::{Algorithm, Argon2, Params, Version};
use blake3::Hasher;
#[cfg(feature = "cipher-xchacha20poly1305")]
use chacha20poly1305::{Key as XChaChaKey, XChaCha20Poly1305, XNonce};
use hkdf::Hkdf;
use rand::{thread_rng, RngCore};
use secrecy::{ExposeSecret, Secret};
use sha2::Sha256;
use thiserror::Error;
use zeroize::Zeroize;

use crate::format::{CipherSuite, FormatError, Tpf2Header, Tpf3Header};

const ROOT_KEY_LEN: usize = 32;
const V2_ENC_INFO: &[u8] = b"TPV2:ENC:AES-256-GCM";
const TPF3_AES_ENC_INFO: &[u8] = b"TPF3:ENC:AES-256-GCM";
const TPF3_XCHACHA_ENC_INFO: &[u8] = b"TPF3:ENC:XCHACHA20-POLY1305";

#[derive(Debug, Error)]
pub enum CryptoError {
    #[error("I/O error processing the dataset: {0}")]
    IoError(#[from] std::io::Error),

    #[error("Invalid vault header: {0}")]
    FormatError(#[from] FormatError),

    #[error("Argon2id key derivation failed")]
    KdfError,

    #[error("HKDF expansion failed")]
    HkdfError,

    #[cfg(not(feature = "cipher-xchacha20poly1305"))]
    #[error("Requested cipher suite is not enabled in this build: {0}")]
    CipherSuiteUnavailable(&'static str),

    #[error("Encryption/decryption failed: wrong key or tampered payload")]
    AeadError,
}

/// Streams a large dataset through BLAKE3 using a small memory footprint.
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

/// Legacy-compatible helper:
/// derives the direct Argon2id output key from passphrase + optional dataset hash.
///
/// This exists so older code paths remain easy to reason about while we transition
/// the application flow to the TPV 2.0 vault key schedule.
#[allow(dead_code)]
pub fn derive_master_key(
    passphrase: &Secret<String>,
    dataset_hash: Option<blake3::Hash>,
    os_salt: &[u8; 32],
    m_cost: u32,
    t_cost: u32,
    p_cost: u32,
) -> Result<Secret<Vec<u8>>, CryptoError> {
    let root_key = derive_argon2_root_key(passphrase, dataset_hash, os_salt, m_cost, t_cost, p_cost)?;
    Ok(Secret::new(root_key))
}

/// Version-aware vault key derivation.
///
/// Behavior:
/// - v1 vaults: direct Argon2id output is used as the encryption key
/// - v2 vaults: Argon2id derives a root key, then HKDF-SHA256 expands a
///   domain-separated encryption key for AES-256-GCM
pub fn derive_vault_key(
    passphrase: &Secret<String>,
    dataset_hash: Option<blake3::Hash>,
    header: &Tpf2Header,
) -> Result<Secret<Vec<u8>>, CryptoError> {
    let mut root_key = derive_argon2_root_key(
        passphrase,
        dataset_hash,
        &header.os_salt,
        header.kdf_m,
        header.kdf_t as u32,
        header.kdf_p as u32,
    )?;

    if header.uses_v2_key_schedule() {
        let enc_key = expand_v2_encryption_key(&root_key, &header.os_salt)?;
        root_key.zeroize();
        Ok(Secret::new(enc_key))
    } else {
        Ok(Secret::new(root_key))
    }
}

/// Generates a random TPF3 nonce with the correct size for the selected cipher suite.
pub fn generate_tpf3_nonce(cipher_suite: CipherSuite) -> Vec<u8> {
    let mut nonce = vec![0u8; cipher_suite.nonce_len()];
    thread_rng().fill_bytes(&mut nonce);
    nonce
}

/// Derives the content-encryption key for a direct-derivation TPF3 vault.
///
/// Current build behavior:
/// - Argon2id derives a 32-byte root key from passphrase + optional dataset hash
/// - HKDF-SHA256 expands a domain-separated AEAD key based on the selected cipher suite
pub fn derive_tpf3_content_key(
    passphrase: &Secret<String>,
    dataset_hash: Option<blake3::Hash>,
    header: &Tpf3Header,
) -> Result<Secret<Vec<u8>>, CryptoError> {
    let mut root_key = derive_argon2_root_key(
        passphrase,
        dataset_hash,
        &header.os_salt,
        header.kdf_m,
        header.kdf_t as u32,
        header.kdf_p as u32,
    )?;

    let enc_key = expand_tpf3_content_key(&root_key, &header.os_salt, header.cipher_suite)?;
    root_key.zeroize();
    Ok(Secret::new(enc_key))
}

/// Encrypts the payload using AES-256-GCM, binding the TPF2 header as AAD.
pub fn encrypt_payload(
    vault_key: &Secret<Vec<u8>>,
    header: &Tpf2Header,
    plaintext: &[u8],
) -> Result<Vec<u8>, CryptoError> {
    let key = Key::<Aes256Gcm>::from_slice(vault_key.expose_secret().as_slice());
    let cipher = Aes256Gcm::new(key);
    let nonce = Nonce::from_slice(&header.nonce);

    let payload = Payload {
        msg: plaintext,
        aad: &header.as_bytes(),
    };

    cipher.encrypt(nonce, payload).map_err(|_| CryptoError::AeadError)
}

/// Decrypts the payload, failing closed if authentication fails.
pub fn decrypt_payload(
    vault_key: &Secret<Vec<u8>>,
    header: &Tpf2Header,
    ciphertext: &[u8],
) -> Result<Vec<u8>, CryptoError> {
    let key = Key::<Aes256Gcm>::from_slice(vault_key.expose_secret().as_slice());
    let cipher = Aes256Gcm::new(key);
    let nonce = Nonce::from_slice(&header.nonce);

    let payload = Payload {
        msg: ciphertext,
        aad: &header.as_bytes(),
    };

    cipher.decrypt(nonce, payload).map_err(|_| CryptoError::AeadError)
}

/// Encrypts a TPF3 payload using the cipher specified by the header.
/// The serialized TPF3 header is bound as AEAD associated data.
pub fn encrypt_tpf3_payload(
    content_key: &Secret<Vec<u8>>,
    header: &Tpf3Header,
    plaintext: &[u8],
) -> Result<Vec<u8>, CryptoError> {
    let header_bytes = header.as_bytes()?;

    match header.cipher_suite {
        CipherSuite::Aes256Gcm => {
            let key = Key::<Aes256Gcm>::from_slice(content_key.expose_secret().as_slice());
            let cipher = Aes256Gcm::new(key);
            let nonce = Nonce::from_slice(&header.nonce);
            let payload = Payload {
                msg: plaintext,
                aad: &header_bytes,
            };
            cipher.encrypt(nonce, payload).map_err(|_| CryptoError::AeadError)
        }
        CipherSuite::XChaCha20Poly1305 => {
            encrypt_tpf3_xchacha20poly1305(content_key, header, plaintext, &header_bytes)
        }
    }
}

/// Decrypts a TPF3 payload, failing closed if authentication fails.
pub fn decrypt_tpf3_payload(
    content_key: &Secret<Vec<u8>>,
    header: &Tpf3Header,
    ciphertext: &[u8],
) -> Result<Vec<u8>, CryptoError> {
    let header_bytes = header.as_bytes()?;

    match header.cipher_suite {
        CipherSuite::Aes256Gcm => {
            let key = Key::<Aes256Gcm>::from_slice(content_key.expose_secret().as_slice());
            let cipher = Aes256Gcm::new(key);
            let nonce = Nonce::from_slice(&header.nonce);
            let payload = Payload {
                msg: ciphertext,
                aad: &header_bytes,
            };
            cipher.decrypt(nonce, payload).map_err(|_| CryptoError::AeadError)
        }
        CipherSuite::XChaCha20Poly1305 => {
            decrypt_tpf3_xchacha20poly1305(content_key, header, ciphertext, &header_bytes)
        }
    }
}

fn derive_argon2_root_key(
    passphrase: &Secret<String>,
    dataset_hash: Option<blake3::Hash>,
    os_salt: &[u8; 32],
    m_cost: u32,
    t_cost: u32,
    p_cost: u32,
) -> Result<Vec<u8>, CryptoError> {
    let params =
        Params::new(m_cost, t_cost, p_cost, Some(ROOT_KEY_LEN)).map_err(|_| CryptoError::KdfError)?;
    let argon2 = Argon2::new(Algorithm::Argon2id, Version::V0x13, params);

    let mut ikm = Vec::new();
    ikm.extend_from_slice(passphrase.expose_secret().as_bytes());

    if let Some(hash) = dataset_hash {
        ikm.extend_from_slice(hash.as_bytes());
    }

    let mut root_key = vec![0u8; ROOT_KEY_LEN];
    let result = argon2.hash_password_into(ikm.as_slice(), os_salt, &mut root_key);

    ikm.zeroize();
    result.map_err(|_| CryptoError::KdfError)?;

    Ok(root_key)
}

fn expand_v2_encryption_key(root_key: &[u8], os_salt: &[u8; 32]) -> Result<Vec<u8>, CryptoError> {
    let hkdf = Hkdf::<Sha256>::new(Some(os_salt), root_key);

    let mut enc_key = vec![0u8; ROOT_KEY_LEN];
    hkdf.expand(V2_ENC_INFO, &mut enc_key)
        .map_err(|_| CryptoError::HkdfError)?;

    Ok(enc_key)
}

fn expand_tpf3_content_key(
    root_key: &[u8],
    os_salt: &[u8; 32],
    cipher_suite: CipherSuite,
) -> Result<Vec<u8>, CryptoError> {
    let hkdf = Hkdf::<Sha256>::new(Some(os_salt), root_key);
    let info = match cipher_suite {
        CipherSuite::Aes256Gcm => TPF3_AES_ENC_INFO,
        CipherSuite::XChaCha20Poly1305 => TPF3_XCHACHA_ENC_INFO,
    };

    let mut enc_key = vec![0u8; ROOT_KEY_LEN];
    hkdf.expand(info, &mut enc_key)
        .map_err(|_| CryptoError::HkdfError)?;

    Ok(enc_key)
}

#[cfg(feature = "cipher-xchacha20poly1305")]
fn encrypt_tpf3_xchacha20poly1305(
    content_key: &Secret<Vec<u8>>,
    header: &Tpf3Header,
    plaintext: &[u8],
    header_bytes: &[u8],
) -> Result<Vec<u8>, CryptoError> {
    let key = XChaChaKey::from_slice(content_key.expose_secret().as_slice());
    let cipher = XChaCha20Poly1305::new(key);
    let nonce = XNonce::from_slice(&header.nonce);
    let payload = Payload {
        msg: plaintext,
        aad: header_bytes,
    };
    cipher.encrypt(nonce, payload).map_err(|_| CryptoError::AeadError)
}

#[cfg(not(feature = "cipher-xchacha20poly1305"))]
fn encrypt_tpf3_xchacha20poly1305(
    _content_key: &Secret<Vec<u8>>,
    _header: &Tpf3Header,
    _plaintext: &[u8],
    _header_bytes: &[u8],
) -> Result<Vec<u8>, CryptoError> {
    Err(CryptoError::CipherSuiteUnavailable("XChaCha20-Poly1305"))
}

#[cfg(feature = "cipher-xchacha20poly1305")]
fn decrypt_tpf3_xchacha20poly1305(
    content_key: &Secret<Vec<u8>>,
    header: &Tpf3Header,
    ciphertext: &[u8],
    header_bytes: &[u8],
) -> Result<Vec<u8>, CryptoError> {
    let key = XChaChaKey::from_slice(content_key.expose_secret().as_slice());
    let cipher = XChaCha20Poly1305::new(key);
    let nonce = XNonce::from_slice(&header.nonce);
    let payload = Payload {
        msg: ciphertext,
        aad: header_bytes,
    };
    cipher.decrypt(nonce, payload).map_err(|_| CryptoError::AeadError)
}

#[cfg(not(feature = "cipher-xchacha20poly1305"))]
fn decrypt_tpf3_xchacha20poly1305(
    _content_key: &Secret<Vec<u8>>,
    _header: &Tpf3Header,
    _ciphertext: &[u8],
    _header_bytes: &[u8],
) -> Result<Vec<u8>, CryptoError> {
    Err(CryptoError::CipherSuiteUnavailable("XChaCha20-Poly1305"))
}
