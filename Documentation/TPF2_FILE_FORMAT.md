# TPF2 Vault File Format Specification

TripplePulsar Vault stores encrypted data using the **TPF2 (TripplePulsar File Format v2)** container format.

This document describes the binary layout of the vault file and how encryption metadata is structured.

The format is intentionally simple and deterministic to support:

• secure parsing  
• version upgrades  
• forward compatibility  
• forensic inspection tools  

# File Layout Overview

A `.tpf2` vault is composed of three sections:

    +-------------------+
    | Header (62 bytes) |
    +-------------------+
    | Ciphertext |
    +-------------------+
    | GCM Tag (16B) |
    +-------------------+
    
    
The header contains all information required to reconstruct the key derivation parameters needed to decrypt the vault.

# Header Layout

Total Size: **62 bytes**

| Offset | Size | Field | Description |
|------|------|------|-------------|
| 0 | 4 | magic | ASCII `"TPF2"` file signature |
| 4 | 1 | version | Vault format version |
| 5 | 1 | flags | Feature flags |
| 6 | 1 | alg_id | Encryption algorithm identifier |
| 7 | 1 | kdf_id | Key derivation function identifier |
| 8 | 4 | kdf_m | Argon2 memory cost (KiB) |
| 12 | 4 | kdf_t | Argon2 iteration count |
| 16 | 1 | kdf_p | Argon2 parallelism |
| 17 | 1 | tpm_flag | Reserved for TPM hardware binding |
| 18 | 8 | reserved | Reserved for future use |
| 26 | 16 | os_salt | Random salt used for key derivation |
| 42 | 12 | nonce | AES-GCM nonce |
| 54 | 8 | reserved2 | Reserved expansion space |


# Algorithm Identifiers

## Encryption Algorithms

| ID | Algorithm |
|---|---|
| 1 | AES-256-GCM |

Future versions may support additional AEAD ciphers.


## Key Derivation Functions

| ID | KDF |
|---|---|
| 1 | Argon2id |


# Key Derivation Procedure

To reconstruct the encryption key, the following procedure is used:


    dataset_hash = BLAKE3(dataset_file)

    IKM = passphrase || dataset_hash

    derived_key = Argon2id(
    input = IKM,
    salt = os_salt,
    memory = kdf_m,
    iterations = kdf_t,
    parallelism = kdf_p
    )
    
    
If no dataset was used during encryption, the dataset hash component is omitted.


# Authenticated Encryption

Vault payloads are encrypted using **AES-256-GCM**.

The encryption process includes the vault header as **Associated Authenticated Data (AAD)**:


    ciphertext, tag = AES256_GCM_Encrypt(
    key = derived_key,
    nonce = nonce,
    plaintext = file_data,
    AAD = header_bytes
    )
    
    
This ensures that any modification to header fields invalidates the authentication tag.


# Ciphertext Section

The ciphertext section contains the encrypted form of the original file contents.

The ciphertext length is:

    ciphertext_length = file_size
    
AES-GCM does not expand ciphertext beyond the authentication tag.

# Authentication Tag

The vault concludes with the **16-byte AES-GCM authentication tag**.

This tag verifies both:

• ciphertext integrity  
• header integrity  

If verification fails, the vault **must not be decrypted**.

# Forward Compatibility

The header includes reserved fields to allow future expansion without breaking existing parsers.

Planned extensions include:

• TPM hardware binding metadata  
• dataset fingerprint storage  
• algorithm agility fields  

Future versions will increment the **version field** while maintaining backward compatibility where possible.

# Security Considerations

Developers implementing TPF2 parsers should:

• validate the magic value before parsing  
• reject unsupported version numbers  
• enforce strict header size checks  
• avoid unsafe memory parsing techniques  
• verify authentication tags before returning plaintext  

Failure to enforce these rules may lead to parsing vulnerabilities.

# Summary

The TPF2 format provides a compact, deterministic container for encrypted files using modern authenticated encryption and memory-hard key derivation.

Its design emphasizes:

• simplicity  
• strong integrity guarantees  
• forward compatibility  
• safe parsing behavior
