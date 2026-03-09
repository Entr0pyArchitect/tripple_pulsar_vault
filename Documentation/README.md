# 🌌 TripplePulsar Vault (TPV)

┌──────────────────────────────────────────────────────────────────────────┐
│  ████████╗██████╗ ██╗██████╗ ██████╗ ██╗      ███████╗                   │
│  ╚══██╔══╝██╔══██╗██║██╔══██╗██╔══██╗██║      ██╔════╝                   │
│     ██║   ██████╔╝██║██████╔╝██████╔╝██║      █████╗                     │
│     ██║   ██╔══██╗██║██╔═══╝ ██╔═══╝ ██║      ██╔══╝                     │
│     ██║   ██║  ██║██║██║      ██║      ███████╗███████╗                  │
│     ╚═╝   ╚═╝  ╚═╝╚═╝╚═╝      ╚═╝      ╚══════╝╚══════╝                  │
│                                                                          │
│           T R I P P L E   P U L S A R   V A U L T                        │
│          "Tripple checking that security since 2026"                     │
└──────────────────────────────────────────────────────────────────────────┘

TripplePulsar Vault (TPV) is a high-assurance cryptographic file sequestration environment written in Rust.
It focuses on secure key derivation, authenticated encryption, and memory-safety practices designed to resist offline vault cracking and common memory-exposure risks.

The project demonstrates defensive systems engineering practices including streaming cryptographic hashing, memory-hardened key derivation, and secure handling of sensitive data in RAM.

Architecture Overview

Encryption Pipeline

User Passphrase
      +
Optional Dataset Hash (BLAKE3)
      ↓
Argon2id Memory-Hardened KDF
      ↓
Derived Encryption Key
      ↓
AES-256-GCM Authenticated Encryption
      ↓
TPF2 Vault File

TPV optionally allows the user to incorporate a large external dataset into the key-derivation pipeline.

The dataset is stream-hashed using BLAKE3, and the resulting digest is concatenated with the user passphrase before being processed by Argon2id.

This mechanism increases the effective entropy input to the KDF without requiring large amounts of system memory.


Core Security Features:
      Memory-Hardened Key Derivation

      Keys are derived using Argon2id, configured with high memory cost parameters to resist GPU and ASIC brute-force attacks.

      Authenticated Encryption

      All vaults are encrypted using AES-256-GCM, providing both confidentiality and tamper detection.

Streaming Dataset Hashing:

      Large datasets are hashed using BLAKE3 with a buffered streaming pipeline to support multi-gigabyte files without excessive RAM usage.

      Secure Memory Handling
      

Sensitive cryptographic material is protected using:

      secrecy crate for secret memory wrapping

      zeroize for deterministic memory clearing

      Rust ownership guarantees to reduce accidental memory exposure

Windows Memory Locking:

      The application interfaces with the Win32 API (VirtualLock) to verify that memory locking is permitted on the host system.

      Secure File Deletion

      An optional multi-pass overwrite routine is available to reduce the chance of plaintext file recovery after encryption.

      
Operational Rules

To maintain the integrity of the vault:

      Dataset Persistence

      If encryption used a dataset, the same dataset must be available during decryption.

      Host Integrity

      TripplePulsar assumes the host OS is trusted and uncompromised.

      
Proper Termination:

      Use the built-in exit or self-destruct functions to ensure sensitive memory is cleared before termination.


Build Instructions

Requirements:

            Rust 1.93+

            Windows 10 / 11

Clone repository:

      git clone https://github.com/Entr0pyArchitect/tripple_pulsar_vault.git
      cd tripple_pulsar_vault

Verify dependencies:

      cargo deny check

      Build release binary:

      cargo build --release
      
Usage

Run the interactive terminal interface:

      cargo run --release

Menu options:

1 — Encrypt File

      Encrypts a target file into the .tpf2 vault format.
      Optionally performs secure overwrite of the original file.

2 — Decrypt Vault

      Derives the encryption key using stored parameters and decrypts the vault payload.

3 — Inspect Vault Header

      Displays vault metadata including algorithm identifiers and KDF parameters.

0 — Self-Destruct

      Emergency exit that clears sensitive memory and clipboard data before terminating.

      
Security Model

TripplePulsar Vault is designed to defend against:

      Offline brute-force attacks on encrypted vaults

      Ciphertext tampering

      Memory scraping attacks

      Accidental plaintext recovery after deletion


Assumptions:

      The host system is trusted

      The passphrase remains secret

      Required datasets remain available

Future Roadmap:

      TPM Hardware Binding

      Optional TPM 2.0 integration to bind vaults to specific hardware.

      Multiple Cipher Support

      Support for additional AEAD algorithms such as XChaCha20-Poly1305.

      Fuzz Testing Pipeline

      Continuous fuzzing of vault header parsing.

      Post-Quantum Readiness

      Exploration of integration with CNSA 2.0-aligned cryptographic primitives.

      
      
Security Disclaimer: 

TripplePulsar Vault is an experimental cryptographic system.

This software has not undergone independent security auditing and should not be relied upon for protecting critical secrets without further review.

Use at your own risk.
