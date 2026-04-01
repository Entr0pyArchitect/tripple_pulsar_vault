# TripplePulsar Vault: Architecture and Security Overview

## Overview

TripplePulsar Vault (TPV) is a Rust-based cryptographic file protection system focused on practical defensive engineering rather than novel cryptographic design. The current TPV 3.0 codebase supports both legacy-compatible **TPF2** vaults and modern **TPF3** vaults through a single interactive Windows-oriented CLI.

The validated codebase now supports:

- TPF2 encryption, decryption, and header inspection
- TPF3 direct/local derivation mode
- TPF3 **TPM-wrapped** content-key mode
- TPF3 **ML-KEM-768 wrapped-key** mode
- AES-256-GCM for TPF2 and TPF3
- XChaCha20-Poly1305 for TPF3
- TPM provider inspection and TPM RSA key provisioning on Windows
- ML-KEM-768 keypair generation from the CLI
- best-effort clipboard clearing, memory locking, and secure exit handling

The project remains a research and engineering-grade local vault tool, not a formally audited or production-certified cryptographic product.

## Architectural Layers

### 1. CLI and orchestration layer

The top-level orchestration lives in `main.rs`. It is responsible for:

- user interaction and menu routing
- plaintext and vault file I/O
- passphrase prompting for direct-derivation flows
- optional dataset selection and hashing
- TPF2 and TPF3 encryption workflows
- automatic decryption dispatch based on detected file format
- TPM and ML-KEM utility flows
- secure exit and emergency exit behavior

The current interactive menu exposes:

1. Encrypt legacy-compatible TPF2 vault
2. Encrypt modern TPF3 vault
3. Decrypt vault
4. Inspect vault header
5. Check TPM provider
6. Provision TPM RSA key
7. Generate ML-KEM-768 keypair
8. Secure exit
0. Emergency exit

### 2. Format and parsing layer

The format layer in `format.rs` defines both the legacy `Tpf2Header` and the newer `Tpf3Header`, together with enums for cipher suites, KDF identifiers, and wrap modes.

#### TPF2

TPF2 remains a compact fixed-size format with a **62-byte** header containing:

- magic
- version
- flags
- algorithm id
- KDF id
- Argon2 parameters
- TPM flag
- reserved bytes
- 32-byte OS salt
- 12-byte AES-GCM nonce

#### TPF3

TPF3 is the extensible container introduced for TPV 3.0. Its fixed header records:

- magic and version
- flags
- cipher suite id
- TPF3 KDF id
- wrap mode id
- nonce length
- wrapped-key length
- KEM ciphertext length
- TPM policy length
- Argon2 parameters
- 32-byte OS salt

After the fixed prelude, TPF3 serializes variable-length sections in this order:

1. `nonce`
2. `wrapped_key`
3. `kem_ciphertext`
4. `tpm_policy`

This gives TPV a forward-compatible structure for algorithm agility and multiple wrapped-key workflows without breaking the older TPF2 layout.

### 3. Cryptographic layer

The cryptographic engine in `crypto.rs` handles:

- streaming dataset hashing with BLAKE3
- Argon2id root-key derivation
- HKDF-SHA256 key expansion
- TPF3 nonce generation
- AEAD encryption and decryption
- TPM-based wrapping and unwrapping support
- ML-KEM-768 wrapping and unwrapping support
- ML-KEM-768 keypair generation

TPV uses established primitives rather than custom cryptography:

- **Argon2id** for memory-hard derivation
- **BLAKE3** for optional dataset hashing
- **HKDF-SHA256** for domain-separated key expansion
- **AES-256-GCM** for TPF2 and TPF3
- **XChaCha20-Poly1305** for TPF3
- **ML-KEM-768** for post-quantum wrapped-key transport in TPF3
- **Windows TPM-backed RSA wrapping** for hardware-bound wrapped-key workflows in TPF3

### 4. Windows integration layer

The Windows-specific support in `win32.rs` provides:

- best-effort memory locking and unlocking through `VirtualLock` and `VirtualUnlock`
- clipboard clearing
- TPM provider availability checks
- persisted TPM RSA key provisioning using the Microsoft Platform Crypto Provider
- TPM wrap/unwrap helpers and TPM policy encoding for TPF3 metadata

These features improve operational hardening on Windows, but they do not create a guarantee against hostile local malware, kernel compromise, or privileged live-memory inspection.

### 5. Data hygiene layer

The `shred.rs` module implements a best-effort overwrite-and-delete routine for source plaintext files. The current implementation performs:

1. one overwrite pass with random bytes
2. one overwrite pass with zeros
3. file flush and sync
4. in-memory buffer scrubbing
5. file deletion

This is useful as defense in depth, but it must not be described as guaranteed secure deletion on SSDs, copy-on-write filesystems, journaling filesystems, snapshot-backed environments, or storage media with wear-leveling and remapping behavior.

## Key Derivation and Key-Wrap Design

### TPF2 path

For legacy-compatible vaults, TPV derives key material from:

- the user passphrase
- an optional dataset hash
- a random per-vault OS salt

For TPF2 v1 vaults, the direct Argon2id output is used as the AES-256-GCM key. For TPF2 v2 vaults, TPV derives an Argon2id root key and then expands the actual encryption key with HKDF-SHA256 using a version-specific domain string.

### TPF3 direct/local derivation path

For TPF3 `wrap_mode = None`, TPV derives a 32-byte Argon2id root key and then expands a domain-separated content-encryption key with HKDF-SHA256 according to the selected cipher suite.

Current TPF3 HKDF info labels include:

- `TPF3:ENC:AES-256-GCM`
- `TPF3:ENC:XCHACHA20-POLY1305`

If the user opts in to dataset binding, the dataset is hashed with BLAKE3 and appended to the passphrase input material before Argon2id runs.

### TPF3 TPM-wrapped path

For `wrap_mode = TpmWrapped`, TPV generates a fresh random TPF3 content key, encrypts the file using that content key, and stores the wrapped form of that content key in the TPF3 header. TPM policy metadata is also stored so the unwrap path can reconstruct the Windows TPM context needed during decryption.

This mode reduces reliance on direct passphrase-based derivation for the content-encryption key itself, while still depending on Windows TPM availability and the persisted TPM-backed RSA key selected by the user.

### TPF3 ML-KEM-768 wrapped path

For `wrap_mode = MlKem768`, TPV generates a fresh random TPF3 content key, encapsulates a shared secret against the recipient ML-KEM-768 public key, derives a key-wrapping key with HKDF-SHA256, and wraps the TPF3 content key under AES-256-GCM.

The TPF3 header stores:

- the wrapped content key blob
- the ML-KEM ciphertext
- the normal TPF3 nonce and parameter metadata

Decryption requires the matching ML-KEM-768 private key. This mode provides a post-quantum wrapped-key transport path for TPF3 without changing the basic authenticated vault structure.

## Authenticated Encryption Model

TPV uses authenticated encryption rather than separate encryption and integrity layers.

- **TPF2** uses **AES-256-GCM**
- **TPF3** uses **AES-256-GCM** or **XChaCha20-Poly1305** depending on the selected cipher suite

In both formats, the serialized header is bound as **associated authenticated data (AAD)**. This means modifications to header fields, wrapped-key metadata, policy blobs, or ciphertext should fail closed at the authentication boundary instead of yielding silently corrupted plaintext.

## Security Posture

TripplePulsar Vault is designed to raise the cost of:

- offline passphrase guessing against captured vaults
- undetected header or ciphertext tampering
- accidental retention of selected sensitive data in memory
- casual plaintext recovery after local encryption workflows

It is **not** designed to fully defend against:

- compromised kernels or hostile hypervisors
- local malware already controlling the host
- privileged live-memory acquisition
- DMA attacks or hardware implants
- user loss of required decryption materials such as datasets, TPM-bound keys, or ML-KEM private keys

## Engineering Boundaries and Limitations

Several constraints remain important to state accurately:

1. **Secure deletion is best-effort only.** It improves hygiene but does not guarantee physical media sanitization.
2. **Memory locking is best-effort only.** `VirtualLock` reduces paging risk but does not create a hard software boundary on a hostile host.
3. **TPM workflows are Windows-dependent.** TPM-wrapped TPF3 requires compatible Windows TPM provider support and the persisted TPM-backed RSA key material used for wrapping.
4. **ML-KEM workflows depend on external key management.** Users must correctly protect and preserve the matching ML-KEM private key for decryption.
5. **The project remains unaudited.** TPV should still be described as a research and engineering project rather than as a formally validated commercial cryptographic product.
6. **The system is an interactive local CLI.** It is not a hardened multi-user service or remote secret-management platform.

## Conclusion

TripplePulsar Vault 3.0 now presents a more complete architecture than the earlier snapshot. It preserves backward compatibility with the legacy TPF2 format while introducing a more extensible TPF3 container, domain-separated HKDF-based key schedules, cipher-suite agility, TPM-backed wrapped-key workflows, and ML-KEM-768 wrapped-key support.

That combination makes TPV a strong example of practical cryptographic systems engineering: evolutionary format design, explicit threat boundaries, careful use of established primitives, and clear distinction between implemented security properties and remaining limitations.
