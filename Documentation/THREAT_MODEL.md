# 🛡️ TripplePulsar Vault: Threat Model & Attack Analysis

TripplePulsar Vault (TPV) is a local cryptographic file protection tool focused on resisting offline password cracking, detecting ciphertext tampering, and reducing accidental exposure of sensitive material in memory.

This document describes the threat model for the current codebase and its practical security boundaries.

---

## 1. Security Goals

### Confidentiality
Prevent unauthorized recovery of plaintext from encrypted vault files without the correct passphrase and, when used, the correct auxiliary dataset.

### Integrity
Ensure that modifications to the vault header or encrypted payload are detected before plaintext is returned.

### Controlled Exposure of Sensitive Material
Reduce the chance that passphrases, derived keys, or plaintext remain exposed in process memory longer than necessary.

### Defensive File Handling
Offer a best-effort overwrite-and-delete path for plaintext source files after successful encryption.

---

## 2. Assets Protected

The current implementation is designed to protect:

- plaintext file contents stored inside TPF2 or TPF3 vaults
- user passphrases entered during encryption and decryption
- derived key material produced by Argon2id and HKDF-SHA256
- vault metadata needed for authenticated decryption
- optional dataset-derived entropy used in the KDF input pipeline

---

## 3. Relevant Security Mechanisms

### Memory-Hard Key Derivation
TPV derives root key material with Argon2id using stored cost parameters from the vault header. This increases the cost of offline guessing attacks against weak or reused passphrases.

### Optional Dataset Binding
When the user opts in, TPV hashes an external dataset with BLAKE3 and includes the digest in the key-derivation input. Decryption requires the same dataset choice and the same dataset content.

### Authenticated Encryption
TPF2 and TPF3 payloads are protected with AEAD constructions. The serialized header is bound as associated authenticated data, so header tampering causes decryption failure instead of silent acceptance.

### Secret Handling in Memory
The code uses the `secrecy` and `zeroize` crates to reduce accidental copying and to scrub selected sensitive buffers when they leave scope.

### Best-Effort Memory Locking
On Windows, TPV attempts to call `VirtualLock` on a startup buffer and warns if that request fails. This is a defense-in-depth measure, not a guarantee that all sensitive process memory is pinned or unreadable.

### Best-Effort Secure Deletion
The overwrite routine performs two passes over a file before deletion:

1. random bytes
2. zeros

This may reduce recoverability on some storage media, but it does **not** guarantee secure deletion on SSDs, copy-on-write filesystems, journaling filesystems, snapshots, cloud-backed storage, or any medium with wear-leveling behavior.

---

## 4. Threat Actors & What TPV Tries to Defend Against

### 4.1 Offline Vault Cracker
**Scenario:** An attacker obtains a `.tpf2` or `.tpf3` vault file and attempts to recover plaintext by guessing passphrases offline.

**Relevant defenses:**
- Argon2id key derivation with explicit memory/time parameters
- optional dataset-derived input binding
- random per-vault salt
- authenticated encryption preventing partial decryption or silent corruption

**Important limitation:**
TPV does not make weak passphrases safe. A weak passphrase remains guessable, only more expensive to attack.

### 4.2 Tampering Adversary
**Scenario:** An attacker modifies header bytes or ciphertext in an attempt to induce malformed parsing, silent corruption, or successful decryption under altered metadata.

**Relevant defenses:**
- strict format parsing for TPF2 and TPF3 headers
- AEAD verification before plaintext is returned
- header bytes used as authenticated associated data

**Expected outcome:**
Modified vaults should fail authentication or parsing instead of decrypting successfully.

### 4.3 Opportunistic Local Memory Exposure
**Scenario:** Secrets are accidentally exposed through normal process lifetime, paging behavior, leftover buffers, or casual local inspection on a trusted host.

**Relevant defenses:**
- `secrecy` wrappers
- `zeroize` on selected buffers
- best-effort `VirtualLock`
- clipboard wipe on selected flows

**Important limitation:**
These measures reduce exposure; they do not stop malware, admin-level inspection, kernel capture, or a compromised runtime environment.

### 4.4 Plaintext Recovery After Encryption
**Scenario:** A user encrypts a file and chooses to erase the source plaintext.

**Relevant defenses:**
- optional two-pass overwrite followed by deletion

**Important limitation:**
This is a best-effort hygiene feature, not a forensic guarantee.

---

## 5. Threats Explicitly Out of Scope

TripplePulsar Vault is **not** designed to defend against the following conditions:

### Compromised Host or Kernel
If the operating system, kernel, hypervisor, or endpoint security context is already compromised, TPV cannot create a trustworthy software boundary.

### Active Malware or Keylogging
Malware that intercepts keyboard input, reads process memory, injects into the process, or captures the screen can defeat user-space protections.

### Privileged Local Adversaries
Administrators, debuggers with sufficient rights, kernel drivers, DMA-capable devices, and forensic acquisition tools may bypass or nullify application-level safeguards.

### Hardware Implants and Physical Interception
Hardware keyloggers, firmware implants, bus sniffing, and similar physical attacks are outside the protection claims of this tool.

### User Mistakes
TPV cannot protect against:
- weak or reused passphrases
- loss of the required auxiliary dataset
- accidental disclosure of plaintext after decryption
- writing decrypted output to an untrusted location

### Unsupported Wrapped-Key Expectations
The codebase includes TPF3 metadata and Windows TPM key provisioning support, but TPM-wrapped and ML-KEM-wrapped TPF3 encrypt/decrypt flows are not yet wired in the current CLI path.

---

## 6. Trust Assumptions

The current security model assumes:

- the host operating system is trusted while TPV is running
- the user chooses and protects a sufficiently strong passphrase
- any dataset used during encryption remains available and unchanged for decryption
- the local filesystem returns the bytes written to disk without silent corruption outside the AEAD threat model
- the user understands that secure deletion is best-effort only

---

## 7. Format-Specific Notes

### TPF2
TPF2 is the legacy-compatible format. It uses an Argon2id-derived root key and, for version 2 headers, HKDF-SHA256 expansion into the AES-256-GCM encryption key.

### TPF3
TPF3 is the modern format. In the currently implemented direct-derivation path, TPV derives a root key with Argon2id and expands a content-encryption key with HKDF-SHA256. The CLI supports:

- AES-256-GCM
- XChaCha20-Poly1305
- direct/local derivation mode

TPM-wrapped and ML-KEM-wrapped TPF3 modes are defined in the format and feature flags, but the vault creation/decryption flows for those wrap modes are still pending.

---

## 8. Practical Security Claims

The current codebase reasonably supports the following claims:

- encrypted vaults are resistant to casual offline inspection without the correct decryption inputs
- header tampering and ciphertext tampering are authenticated and should fail closed
- the implementation uses memory-safety-oriented Rust crates and explicit buffer scrubbing in key areas
- the program includes Windows-specific hygiene measures such as clipboard clearing and best-effort memory locking

The current codebase should **not** claim:

- guaranteed secure deletion
- protection against a compromised machine
- formal resistance to privileged live-memory attacks
- production-grade TPM-sealed vault workflows
- completed post-quantum wrapped-key deployment

---

## 9. Residual Risk

Even when used correctly, residual risks remain:

- weak passphrases can still be guessed offline
- plaintext exists in memory during encryption and decryption
- decrypted files written to disk are outside vault protection
- user-space wiping and locking are incomplete against strong local attackers
- the project has not undergone formal third-party cryptographic review or audit

---

## 10. Summary

TripplePulsar Vault is best understood as a defensive cryptographic engineering project that provides:

- memory-hard key derivation
- authenticated encryption
- deterministic optional dataset binding
- structured binary vault formats
- Windows-oriented operational hygiene features

It is appropriate to describe TPV as a **research and engineering-grade local vault tool** with clear security boundaries, rather than as a system that guarantees protection against full host compromise or advanced forensic acquisition.
