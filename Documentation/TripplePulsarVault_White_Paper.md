# TripplePulsar Vault: A Rust-Based Cryptographic File Vault System

## Abstract

TripplePulsar Vault (TPV) is a Rust-based cryptographic file vault system designed to explore practical defensive systems engineering with modern cryptographic primitives. The current TPV 3.0 codebase supports both legacy-compatible TPF2 vaults and modern TPF3 vaults, combining Argon2id-based key derivation, streaming BLAKE3 dataset hashing, authenticated encryption, and Windows-oriented memory-hygiene measures.

In the current implementation, TPF2 vaults use AES-256-GCM with a version-aware key schedule, while TPF3 vaults support direct passphrase-and-dataset derivation with either AES-256-GCM or XChaCha20-Poly1305. The system also includes TPF3 header parsing, TPM provider inspection, and TPM RSA key provisioning on Windows, while TPM-wrapped and ML-KEM-wrapped TPF3 vault operation remains defined in the format but not yet wired into the end-to-end encryption and decryption flows.

This project is intended as a security engineering research implementation rather than a production-certified cryptographic product.

## 1. Introduction

TripplePulsar Vault was built to demonstrate how well-established cryptographic components can be integrated into a memory-safe systems language without inventing new primitives. Instead of proposing novel cryptography, TPV focuses on implementation architecture, authenticated file-container design, memory-hardened key derivation, and defensive operational hygiene.

The current codebase provides two vault families:

- **TPF2** for legacy compatibility and continued support of earlier vault structure.
- **TPF3** for modernized cipher agility, variable-length authenticated headers, and future wrapped-key expansion.

The system is Windows-oriented at runtime, with explicit support for clipboard clearing, memory locking attempts through Win32 APIs, and TPM provider interaction.

## 2. Design Objectives

The project is structured around the following goals:

1. Use established primitives rather than custom cryptographic algorithms.
2. Increase offline cracking cost through memory-hard Argon2id derivation.
3. Allow optional incorporation of a deterministic external dataset through streaming BLAKE3 hashing.
4. Bind vault metadata as authenticated data so header tampering is detected before plaintext is released.
5. Reduce accidental exposure of sensitive material in memory through `secrecy`, `zeroize`, and best-effort platform hygiene.
6. Maintain backward compatibility while introducing a more extensible file format.

## 3. Cryptographic Architecture

### 3.1 Key Derivation

TripplePulsar Vault derives its initial keying material from:

- a user passphrase
- an optional external dataset hash
- a random per-vault operating-system salt

The dataset component is hashed with BLAKE3 using a buffered streaming pipeline, allowing large files to be processed without loading them entirely into RAM. The passphrase bytes and optional dataset hash are concatenated as input keying material for Argon2id.

In the legacy-compatible path, TPF2 v1 vaults use the direct Argon2id output as the encryption key, while TPF2 v2 vaults derive an Argon2id root key and then expand a domain-separated encryption key with HKDF-SHA256. TPF3 uses the same general root-key pattern and expands a domain-separated content-encryption key according to the selected cipher suite.

Conceptually:

```text
dataset_hash = BLAKE3(dataset)
IKM = passphrase || dataset_hash
root_key = Argon2id(IKM, os_salt)
enc_key = HKDF-SHA256(root_key, os_salt, domain_info)
```

If no dataset is used, the dataset hash component is omitted.

### 3.2 Authenticated Encryption

TPV uses authenticated encryption with associated data (AEAD):

- **TPF2:** AES-256-GCM
- **TPF3:** AES-256-GCM or XChaCha20-Poly1305

In both vault families, the serialized header is bound as associated authenticated data (AAD). This means header tampering causes authentication failure during decryption. TPF3 extends this design with a variable-length header that can carry nonce data and future wrapped-key metadata.

### 3.3 File-Format Families

#### TPF2

TPF2 is the legacy-compatible container and uses a fixed 62-byte header with canonical fields for versioning, KDF settings, flags, random salt, and nonce. The current implementation supports both version 1 and version 2 parsing, with version 2 enabling the newer HKDF-based key schedule.

#### TPF3

TPF3 is the modern format in the current codebase. It introduces:

- explicit cipher-suite identifiers
- a TPF3 KDF identifier
- wrap-mode identifiers
- variable-length nonce storage
- variable-length wrapped-key, KEM ciphertext, and TPM policy regions

The current implementation supports **direct/local derivation** end-to-end. TPM-wrapped and ML-KEM-wrapped modes are represented in the format and surfaced in the CLI, but actual wrapped-key encryption/decryption is not yet wired into the operational flow.

## 4. Implementation Overview

### 4.1 Rust and Memory Safety

The implementation uses Rust to reduce common memory-management risks and complements this with:

- `secrecy` for secret-wrapping of sensitive values
- `zeroize` for explicit scrubbing of selected in-memory buffers
- structured error types for cryptographic and parsing failures

These measures reduce accidental retention and unsafe handling of key material, though they do not eliminate the risk posed by a compromised host.

### 4.2 Windows Integration

TripplePulsar Vault currently targets Windows-oriented operation. The code includes:

- best-effort memory locking via Win32 `VirtualLock`
- corresponding unlock behavior via `VirtualUnlock`
- clipboard clearing support
- TPM platform crypto provider checks
- TPM RSA key provisioning through the Windows NCrypt provider

These platform integrations should be understood as operational hardening features, not as guarantees against privileged malware or hostile kernel-level inspection.

### 4.3 Secure Deletion Behavior

The tool includes an optional best-effort overwrite-and-delete routine for source plaintext files. The implementation performs two overwrite passes:

1. random data
2. zeros

It then closes the handle and removes the file. This may reduce recoverability on some storage media, but it is not a guarantee of secure deletion on SSDs, copy-on-write filesystems, or storage layers with wear-leveling, journaling, snapshots, or remapping behavior.

## 5. Command-Line Interface and Operational Flows

The current TPV 3.0 CLI exposes the following primary functions:

1. Encrypt legacy-compatible TPF2 vaults
2. Encrypt modern TPF3 vaults
3. Decrypt vaults
4. Inspect vault headers
5. Check TPM provider availability
6. Provision a TPM RSA key
7. Secure exit
0. Emergency exit

The decryption flow automatically parses the vault header and routes the operation to either the TPF2 or TPF3 path. For TPF3 vaults, the current build rejects wrapped-key decryption paths and clearly reports that those modes are not yet wired.

## 6. Threat Model Summary

TPV is designed to improve resistance against:

- offline brute-force attacks on encrypted vaults
- ciphertext and header tampering
- accidental plaintext persistence after encryption in some environments
- accidental secret exposure through ordinary memory mishandling

TPV does **not** claim protection against:

- a compromised kernel or hostile hypervisor
- DMA attacks or hardware implants
- keyloggers on the trusted input path
- loss of the dataset required for vault reconstruction
- unsupported assumptions about secure deletion on modern storage devices

## 7. Limitations

TripplePulsar Vault has several current limitations:

- it has not undergone independent cryptographic audit
- CLI input/output paths still prioritize practicality over fully hardened terminal error handling
- TPF3 wrapped-key modes are specified but not fully implemented end-to-end
- TPM support currently covers provider checks and RSA key provisioning, not completed TPM-wrapped vault operations
- secure deletion is best-effort only

These limitations should be stated plainly in any public-facing write-up.

## 8. Research Value

Despite those limitations, TPV remains useful as a compact research implementation because it demonstrates:

- migration from a fixed legacy header to a more extensible authenticated format
- version-aware key-schedule evolution
- domain-separated HKDF expansion over Argon2id-derived root material
- algorithm agility in the modern vault format
- Windows-specific hygiene and TPM-preparation hooks integrated into a Rust CLI

That makes it a practical example of defensive cryptographic systems engineering rather than simply a single-algorithm file encryptor.

## 9. Conclusion

TripplePulsar Vault 3.0 demonstrates how a Rust-based application can combine modern cryptographic libraries, authenticated file-container design, and defensive operational controls into a coherent experimental vault system. The codebase now spans legacy-compatible TPF2 support, modern TPF3 support, configurable TPF3 cipher selection, and Windows TPM preparation paths.

At the same time, the project remains explicit about what is not yet complete: wrapped-key TPF3 operation is still pending, secure deletion remains best-effort, and the system should not be represented as independently audited or production-certified.

Framed accurately, TPV provides a strong case study in practical cryptographic implementation, migration strategy, and secure-systems documentation.
