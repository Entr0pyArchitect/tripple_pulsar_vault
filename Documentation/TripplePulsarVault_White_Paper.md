# TripplePulsar Vault: A Rust-Based Cryptographic File Vault System

## Abstract

TripplePulsar Vault (TPV) is a Rust-based cryptographic file vault system built as a practical security-engineering project rather than a novel cryptographic scheme. The final TPV 3.0 codebase supports both legacy-compatible TPF2 vaults and modern TPF3 vaults, combining Argon2id-based key derivation, streaming BLAKE3 dataset hashing, authenticated encryption, and Windows-oriented memory-hygiene features.

In the finalized implementation, TPF2 vaults use AES-256-GCM with a version-aware key schedule, while TPF3 vaults support three operational modes: direct derivation, TPM-wrapped content keys, and ML-KEM-768 wrapped content keys. The system also includes TPF3 header parsing, TPM provider inspection, TPM RSA key provisioning, and ML-KEM-768 keypair generation through the interactive CLI.

This project should be understood as a research and engineering-grade local vault tool, not a production-certified cryptographic product.

## 1. Introduction

TripplePulsar Vault was built to demonstrate how established cryptographic components can be integrated into a memory-safe systems language without inventing new primitives. Rather than proposing custom cryptography, TPV focuses on implementation architecture, authenticated file-container design, memory-hard derivation, wrap-mode extensibility, and defensive operational hygiene.

The final codebase provides two vault families:

- **TPF2** for legacy compatibility and continued support of earlier vault structure.
- **TPF3** for modern cipher agility, variable-length authenticated headers, and multiple key-handling modes.

The system is Windows-oriented at runtime, with explicit support for clipboard clearing, memory-locking attempts through Win32 APIs, TPM provider interaction, TPM RSA key provisioning, and ML-KEM-768 keypair generation.

## 2. Design Objectives

The project is structured around the following goals:

1. Use established primitives rather than custom cryptographic algorithms.
2. Increase offline cracking cost through memory-hard Argon2id derivation.
3. Allow optional incorporation of a deterministic external dataset through streaming BLAKE3 hashing.
4. Bind vault metadata as authenticated data so header tampering is detected before plaintext is released.
5. Support multiple TPF3 key-handling modes without changing the core on-disk container family.
6. Reduce accidental exposure of sensitive material in memory through `secrecy`, `zeroize`, and best-effort platform hygiene.
7. Maintain backward compatibility while introducing a more extensible file format.

## 3. Cryptographic Architecture

### 3.1 Key Derivation

TripplePulsar Vault derives its initial keying material from:

- a user passphrase
- an optional external dataset hash
- a random per-vault operating-system salt

The dataset component is hashed with BLAKE3 using a buffered streaming pipeline, allowing large files to be processed without loading them entirely into RAM. The passphrase bytes and optional dataset hash are concatenated as input keying material for Argon2id.

In the legacy-compatible path, TPF2 v1 vaults use the direct Argon2id output as the encryption key, while TPF2 v2 vaults derive an Argon2id root key and then expand a domain-separated encryption key with HKDF-SHA256. TPF3 direct mode uses the same general root-key pattern and expands a domain-separated content-encryption key according to the selected cipher suite.

Conceptually:

```text
dataset_hash = optional BLAKE3(dataset)
IKM = passphrase || dataset_hash
root_key = Argon2id(IKM, os_salt)
enc_key = HKDF-SHA256(root_key, os_salt, domain_info)
```

If no dataset is used, the dataset hash component is omitted.

### 3.2 Authenticated Encryption

TPV uses authenticated encryption with associated data (AEAD):

- **TPF2:** AES-256-GCM
- **TPF3:** AES-256-GCM or XChaCha20-Poly1305

In both vault families, the serialized header is bound as associated authenticated data (AAD). This means header tampering causes authentication failure during decryption.

### 3.3 Wrapped-Key Design in TPF3

TPF3 supports multiple wrap modes:

- **Direct / local derivation (`wrap_mode = None`)**
- **TPM-wrapped content key (`wrap_mode = TpmWrapped`)**
- **ML-KEM-768 wrapped content key (`wrap_mode = MlKem768`)**

In wrapped-key modes, TPV generates a random TPF3 content key and then protects that key externally:

- In **TPM-wrapped mode**, the content key is protected using a persisted TPM-backed RSA key through the Windows Platform Crypto Provider.
- In **ML-KEM-768 wrapped mode**, the content key is wrapped using an ML-KEM-derived shared secret expanded through HKDF-SHA256 and then used to protect the random content key.

This allows TPF3 to separate payload encryption from how the payload key itself is recovered.

## 4. File-Format Families

### 4.1 TPF2

TPF2 is the legacy-compatible container and uses a fixed 62-byte header with canonical fields for versioning, KDF settings, flags, random salt, and nonce. The implementation supports both version 1 and version 2 parsing, with version 2 enabling the newer HKDF-based key schedule.

### 4.2 TPF3

TPF3 is the modern extensible format. It introduces:

- explicit cipher-suite identifiers
- a TPF3 KDF identifier
- wrap-mode identifiers
- variable-length nonce storage
- variable-length wrapped-key, KEM ciphertext, and TPM policy regions

The finalized implementation supports direct mode, TPM-wrapped mode, and ML-KEM-768 wrapped mode end-to-end.

## 5. Implementation Overview

### 5.1 Rust and Memory Safety

The implementation uses Rust to reduce common memory-management risks and complements this with:

- `secrecy` for secret-wrapping of sensitive values
- `zeroize` for explicit scrubbing of selected in-memory buffers
- structured error types for cryptographic and parsing failures

These measures reduce accidental retention and unsafe handling of key material, though they do not eliminate the risk posed by a compromised host.

### 5.2 Windows Integration

TripplePulsar Vault currently targets Windows-oriented operation. The code includes:

- best-effort memory locking via Win32 `VirtualLock`
- corresponding unlock behavior via `VirtualUnlock`
- clipboard clearing support
- TPM platform crypto provider checks
- TPM RSA key provisioning through the Windows NCrypt provider
- TPM-backed unwrap support for TPF3 content keys

These platform integrations should be understood as operational hardening features, not as guarantees against privileged malware or hostile kernel-level inspection.

### 5.3 Post-Quantum Integration

The final TPV 3.0 build also includes ML-KEM-768 support through the `ml-kem` crate. The CLI can generate an ML-KEM-768 keypair and use that material for TPF3 wrapped-key encryption and decryption.

## 6. Command-Line Interface and Operational Flows

The final TPV 3.0 CLI exposes the following primary functions:

1. Encrypt legacy-compatible TPF2 vaults
2. Encrypt modern TPF3 vaults
3. Decrypt vaults
4. Inspect vault headers
5. Check TPM provider availability
6. Provision a TPM RSA key
7. Generate ML-KEM-768 keypair
8. Secure exit
0. Emergency exit

The decryption flow automatically parses the vault header and routes the operation to either the TPF2 or TPF3 path. For TPF3 vaults, the current build supports direct derivation, TPM-wrapped recovery, and ML-KEM-768 wrapped recovery.

## 7. Threat Model Summary

TPV is designed to improve resistance against:

- offline brute-force attacks on encrypted vaults
- ciphertext and header tampering
- accidental plaintext persistence after encryption in some environments
- accidental secret exposure through ordinary memory mishandling

TPV does **not** claim protection against:

- a compromised kernel or hostile hypervisor
- DMA attacks or hardware implants
- keyloggers on the trusted input path
- weak passphrase selection
- unsupported assumptions about secure deletion on modern storage devices

In direct-mode workflows that use an external dataset, TPV also depends on the continued availability of that dataset for successful decryption.

## 8. Limitations

TripplePulsar Vault still has practical limits:

- it has not undergone independent cryptographic audit
- secure deletion is best-effort only
- memory locking is best-effort only
- the system remains local interactive software rather than a hardened network service
- host compromise defeats user-space hygiene measures

These limits should be stated plainly in any public-facing write-up.

## 9. Research Value

TPV remains useful as a compact research implementation because it demonstrates:

- migration from a fixed legacy header to a more extensible authenticated format
- version-aware key-schedule evolution
- domain-separated HKDF expansion over Argon2id-derived root material
- algorithm agility in the modern vault format
- wrapped-key integration through both TPM-backed and post-quantum KEM-backed flows
- Windows-specific hygiene and provider integration within a Rust CLI

That makes it a practical example of defensive cryptographic systems engineering rather than simply a single-algorithm file encryptor.

## 10. Conclusion

TripplePulsar Vault 3.0 demonstrates how a Rust-based application can combine modern cryptographic libraries, authenticated file-container design, format evolution, and defensive operational controls into a coherent experimental vault system. The finalized codebase spans legacy-compatible TPF2 support, modern TPF3 support, configurable TPF3 cipher selection, TPM-wrapped key handling, and ML-KEM-768 wrapped-key operation.

Framed accurately, TPV provides a strong case study in practical cryptographic implementation, migration strategy, and secure-systems documentation. It should be described as a research and engineering project with clear boundaries, not as an independently audited or production-certified security product.
