# 🌌 TripplePulsar Vault (TPV)

```text
  ██████╗██████╗ ██╗██████╗ ██████╗ ██╗      ███████╗
  ╚══██╔══╝██╔══██╗██║██╔══██╗██╔══██╗██║      ██╔════╝
    ██║   ██████╔╝██║██████╔╝██████╔╝██║      █████╗  
    ██║   ██╔══██╗██║██╔═══╝ ██╔═══╝ ██║      ██╔══╝  
    ██║   ██║  ██║██║██║      ██║      ███████╗███████╗
    ╚═╝   ╚═╝  ╚═╝╚═╝╚═╝      ╚═╝      ╚══════╝╚══════╝
      P  U  L  S  A  R      V  A  U  L  T
      "Tripple checking that security since 2026"
TripplePulsar is a high-assurance, Windows-optimized cryptographic environment that goes beyond standard "password managers." By combining memory-hard key derivation (Argon2id), astronomical entropy diversification (BLAKE3 dataset streaming), and kernel-level anti-forensics, TPV defends against both network-based interception and offline physical forensic extraction.

⚠️ The Mandates of Operation
To maintain the integrity of the TripplePulsar security boundary, operators must adhere to the following rules:

The Persistence Rule: Pulsar datasets must be kept consistent. If you encrypt a vault using HTRU_2.csv, you must have that exact file available for future key derivations in the same salt domain.

The Environment Rule: Never run TripplePulsar in an untrusted Virtual Machine or on a host where the base OS/Kernel is compromised by malware.

The Cleanup Rule: Always terminate sessions via the designated Secure Exit (Option 4) or Self-Destruct (Option 0) to guarantee the cryptographic teardown sequence is properly executed.

🛠️ Build Instructions
This project requires Rust 1.93.1 or higher and is strictly compiled for Windows 10/11 to leverage bare-metal memory locking APIs.

Bash
# Clone the repository
git clone [https://github.com/Entr0pyArchitect/tripple_pulsar_vault.git](https://github.com/Entr0pyArchitect/tripple_pulsar_vault.git)
cd tripple_pulsar_vault

# Verify supply chain security (requires cargo-deny)
cargo deny check

# Build the release binary
cargo build --release
🚀 Usage Guide
Run the compiled executable to launch the interactive, self-destructing terminal menu:

Bash
cargo run --release
Option 1 (Encrypt File): Encrypts a target file into the .tpf2 vault format. Optionally triggers the DoD-level 2-pass secure wipe to obliterate the original plaintext file from physical disk sectors.

Option 2 (Decrypt Vault): Reconstructs the Argon2id parameters from the vault header, verifies the AEAD MAC tag, and safely decrypts the payload. Automatically scrubs the Windows clipboard upon completion.

Option 3 (Inspect Vault Header): Probes the 62-byte TPF2 header to verify KDF memory costs, algorithm IDs, and hardware binding status without attempting decryption.

Option 0 (Self-Destruct): Emergency interrupt. Instantly scrubs the Windows clipboard, unlocks all pinned RAM, zeroizes in-scope memory, and terminates the process.


***

### 2. `TripplePulsarVault White Paper.md`

```markdown
# TripplePulsar: A High-Assurance Entropy Model for Data Sequestration

## Abstract
Modern data security often fails not at the encryption algorithm level, but at the implementation level—specifically memory forensics and entropy exhaustion. TripplePulsar addresses these vulnerabilities by introducing a "Triple Pillar" approach: Memory-Hardened Key Derivation Functions (KDFs), Astronomical Entropy Diversification, and Hardware-Level OS Integration. It is a software-defined security boundary engineered for high-threat environments.

## 1. Astronomical Entropy Diversification
Traditional encryption relies on a single secret (the passphrase). If the passphrase is weak or the memory is dumped, the data is lost. TripplePulsar addresses the "Entropy Exhaustion" problem by injecting deterministic "Natural Entropy" from massive external Pulsar datasets to fortify the root key. 



By streaming gigabytes of astrophysical data through a BLAKE3 hashing engine and combining it with OS-generated randomness and the user's passphrase, the system expands the Initial Keying Material (IKM). This renders pre-computation, dictionary, or rainbow-table attacks mathematically unfeasible.

## 2. Cryptographic Integrity and the TPF2 Format
TripplePulsar employs an Authenticated Encryption with Associated Data (AEAD) construction. 



The proprietary `TPF2` binary format rigorously defines a 62-byte header containing the salt, nonces, and KDF parameters. This entire header is bound to the AES-256-GCM cipher as Associated Authenticated Data. The system mathematically verifies the integrity of the data before the decryption engine ever attempts to process the plaintext, neutralizing bit-flipping and tampering attacks.

## 3. Memory Hardening & Anti-Forensics
Most applications passively allow the OS to page memory to the hard drive, leaving master keys recoverable long after the machine powers down (the "Swap-File Leak"). TripplePulsar mitigates this via deep Windows API integration:

* **RAM Pinning:** Pins sensitive key material to physical RAM using the Windows `VirtualLock` API, preventing keys from bleeding into the hard drive's swap-file (`pagefile.sys`). 

* **DoD-Level Wiping:** Standard file deletion removes only the file pointer, leaving the plaintext data on the disk sectors. TripplePulsar's standalone shredder physically overwrites the data blocks (random overwrite followed by a zero-fill) prior to OS-level unlinking.


## Conclusion
TripplePulsar Vault represents the pinnacle of personal data protection. By combining astronomical entropy, strict AEAD integrity checks, and kernel-level memory protection, it creates a "Sequestration Zone" where secrets can be stored with the highest degree of confidence.