# TripplePulsar Vault: Architecture and Security Overview

## Overview

TripplePulsar Vault (TPV) is a Rust-based cryptographic file protection system focused on practical defensive engineering rather than novel cryptographic design. The current TPV 3.0 codebase supports both legacy-compatible **TPF2** vaults and modern **TPF3** vaults through a single interactive Windows-oriented CLI. The menu currently exposes flows for TPF2 encryption, TPF3 encryption, vault decryption, header inspection, TPM provider checks, and TPM RSA key provisioning. fileciteturn13file15 fileciteturn6file6

The system is built around established primitives and supporting libraries rather than custom cryptography. In the current implementation, the core cryptographic stack includes **Argon2id** for memory-hard derivation, **BLAKE3** for streaming dataset hashing, **HKDF-SHA256** for domain-separated key expansion, **AES-256-GCM** for TPF2 and TPF3 authenticated encryption, and optional **XChaCha20-Poly1305** support for TPF3. The build also includes optional dependencies and format support for TPM-related workflows and future ML-KEM-based wrapped-key modes. fileciteturn13file2turn13file8turn6file6

## Architectural Layers

### 1. CLI and orchestration layer

The top-level orchestration lives in `main.rs`. It is responsible for user interaction, file I/O, passphrase prompting, optional dataset selection, vault creation, vault parsing, decryption dispatch, and TPM utility operations. The CLI routes operations based on detected vault type so the same decryption path can handle either TPF2 or TPF3 inputs. fileciteturn13file15turn13file19

### 2. Format and parsing layer

The file format layer in `format.rs` defines both the legacy `Tpf2Header` and the newer `Tpf3Header`, together with enum types for cipher suites, KDF identifiers, and wrap modes. TPF2 remains a fixed 62-byte header format, while TPF3 uses a fixed prelude plus variable-length blobs for nonce, wrapped key material, KEM ciphertext, and TPM policy data. This gives TPV a cleaner path for forward compatibility and algorithm agility without breaking the older container type. fileciteturn13file16turn13file11

### 3. Cryptographic layer

The cryptographic engine in `crypto.rs` handles dataset hashing, key derivation, nonce generation for TPF3, authenticated encryption, and authenticated decryption. TPF2 uses AES-256-GCM with the serialized TPF2 header bound as associated authenticated data. TPF3 also binds the serialized header as AEAD associated data and currently supports direct/local derivation for both AES-256-GCM and XChaCha20-Poly1305. fileciteturn13file2

### 4. Windows integration layer

The Windows-specific support in `win32.rs` provides best-effort memory locking and unlocking through `VirtualLock` and `VirtualUnlock`, clipboard clearing, TPM provider availability checks, and persisted TPM RSA key provisioning using the Microsoft Platform Crypto Provider via NCrypt APIs. These capabilities are exposed through the CLI but are intentionally narrower than full TPM-wrapped vault operations. fileciteturn6file2

### 5. Data hygiene layer

The `shred.rs` module implements a best-effort overwrite-and-delete routine for source plaintext files. The current implementation performs two passes, one with random data and one with zeros, flushes and syncs the file, scrubs the temporary memory buffer, then removes the file. This is useful as defense in depth, but it should not be described as guaranteed secure deletion on SSDs or any storage with wear-leveling, snapshots, journaling, or copy-on-write behavior. fileciteturn6file4

## Key Derivation Design

### TPF2 / legacy-compatible path

For legacy-compatible vaults, TPV derives a root key from the passphrase, optional dataset hash, and OS salt using Argon2id. For version 2 TPF2 vaults, that root key is then expanded with HKDF-SHA256 into a domain-separated encryption key for AES-256-GCM. The code retains a legacy helper for the older direct Argon2id output model, but the current v2 flow is the HKDF-based schedule. fileciteturn13file14turn13file16

### TPF3 path

For TPF3 vaults in the currently implemented direct/local mode, TPV derives a 32-byte Argon2id root key and then expands it through HKDF-SHA256 using cipher-suite-specific context strings. This produces distinct content-encryption keys for AES-256-GCM and XChaCha20-Poly1305 under the TPF3 design. TPF3 therefore introduces both domain separation and cipher agility without forcing the legacy TPF2 format to change. fileciteturn13file2turn13file8

### Optional dataset binding

In both TPF2 and TPF3 direct-derivation flows, the CLI can optionally hash an external dataset with BLAKE3 and append the resulting digest to the passphrase input material before Argon2id runs. This preserves a low-memory hashing pipeline while allowing a deterministic external factor to participate in derivation. The operational cost is that decryption requires access to the exact same dataset when that feature was used during encryption. fileciteturn13file2turn13file19

## Authenticated Encryption Model

TPV uses authenticated encryption rather than separate encryption and integrity layers.

- **TPF2** currently uses **AES-256-GCM**.
- **TPF3** currently supports **AES-256-GCM** and **XChaCha20-Poly1305** in the direct/local derivation path.
- In both formats, the serialized vault header is bound as **associated authenticated data (AAD)** so header tampering causes authentication failure during decryption. fileciteturn13file2turn13file16turn13file11

This design means that a modified header, altered ciphertext, wrong passphrase, or wrong dataset selection all fail closed at the AEAD verification boundary rather than producing partially decrypted output. The decryption flow in `main.rs` reflects this by surfacing a generic failure message rather than attempting recovery after authentication errors. fileciteturn13file19

## Container Format Evolution

### TPF2

TPF2 remains the legacy-compatible fixed-size container. In the current code, its 62-byte header includes the magic value, version, flags, algorithm identifier, KDF identifier, Argon2 parameters, TPM flag, reserved bytes, a 32-byte salt, and a 12-byte nonce. That exact layout is what the parser and serializer use. fileciteturn13file16turn13file10

### TPF3

TPF3 is the extensible container introduced for TPV 3.0. Its fixed header records the magic value, version, flags, cipher suite, KDF identifier, wrap mode, nonce length, lengths for wrapped-key and policy blobs, Argon2 parameters, and a 32-byte OS salt. After that prelude, variable-length binary sections hold the nonce and optional wrap-related material. This lets the format support algorithm agility and future wrapped-key designs without duplicating the TPF2 structure. fileciteturn13file8

## Windows and TPM Integration

The Windows integration should be understood as useful platform support, not as a claim of hardware-backed vault protection across the whole codebase. The current build can:

- test whether the TPM platform crypto provider can be opened,
- check whether a persisted TPM-backed RSA key already exists,
- create and finalize a persisted TPM-backed RSA key if needed. fileciteturn6file2turn13file15

However, the actual **TPF3 TPM-wrapped content-key encryption and decryption path is not wired yet** in the current CLI. The interface explicitly reports that TPM-wrapped and ML-KEM-768 wrapped vault modes are pending for encryption, and TPF3 decryption exits early if it encounters a wrapped-key mode other than direct/local derivation. Any architecture description should make that implementation boundary explicit. fileciteturn13file19turn13file15

## Security Posture

TripplePulsar Vault is best understood as a defensive cryptographic engineering project with a practical local threat model.

It is designed to raise the cost of:

- offline passphrase guessing against captured vaults,
- undetected ciphertext or header tampering,
- accidental retention of sensitive material in memory,
- casual plaintext recovery after local encryption workflows. fileciteturn13file6turn6file4turn6file2

It is **not** designed to fully defend against:

- compromised kernels or hostile hypervisors,
- hardware implants or DMA-style attacks,
- local malware already controlling the host,
- user loss of a required dataset used in derivation. fileciteturn13file6turn13file19

## Engineering Boundaries and Limitations

Several constraints are important to state accurately:

1. **Secure deletion is best-effort only.** The implementation improves hygiene but cannot guarantee physical media sanitization on modern SSDs or storage stacks with remapping or snapshots. fileciteturn6file4
2. **Memory locking is best-effort only.** `VirtualLock` reduces paging risk but does not create a hard security boundary against a hostile host. fileciteturn6file2
3. **Wrapped-key TPF3 modes are format-defined but not fully implemented.** TPM-related provisioning exists, but wrapped-key vault creation and decryption are still pending. fileciteturn13file8turn13file15turn13file19
4. **The system is local interactive software, not a hardened service.** The CLI still uses direct terminal I/O patterns and should be documented as a research-grade desktop utility rather than a formally hardened product. fileciteturn6file3

## Conclusion

TripplePulsar Vault 3.0 demonstrates a more mature architecture than the earlier TPV snapshot: it preserves compatibility with the legacy TPF2 format while introducing a more extensible TPF3 format, domain-separated HKDF-based derivation, cipher-suite agility for TPF3, and TPM utility integration on Windows. At the same time, the codebase is appropriately honest about what remains incomplete, especially wrapped-key vault operations. That combination makes TPV a solid security engineering project and a credible example of evolving a simple encrypted container design into a more extensible cryptographic toolchain without overstating its guarantees. fileciteturn13file2turn13file8turn13file15turn6file2
