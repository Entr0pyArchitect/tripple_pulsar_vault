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
git clone [https://github.com/Entr0pyArchitect/tripple_pulsar_vault.git]
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



## 🔮 Future Roadmap (Version 2.0)
While V1.0 establishes a pristine, mathematically sound sequestration zone, future iterations will expand the defense-in-depth architecture to neutralize emerging threats:

* **TPM 2.0 Hardware Binding:** Integration with the Windows TBS (TPM Base Services) API to physically bind the cryptographic vault to the host machine's motherboard. This will render exfiltrated vaults entirely useless, even if the adversary possesses the master passphrase and the exact astronomical dataset.
* **Polymorphic Cipher Engine:** Implementing dynamic trait dispatch to allow runtime selection between `AES-256-GCM` and `XChaCha20-Poly1305`, preventing single-algorithm points of failure.
* **Automated Fuzz Testing Pipeline:** Aggressive, continuous memory-fuzzing of the `TPF2` binary parsing engine to mathematically guarantee absolute resilience against maliciously crafted or corrupted vault headers.
* **Post-Quantum Cryptography (PQC) Readiness:** Mapping out integration for CNSA 2.0 compliant algorithms (such as ML-KEM) to defend against future quantum-enabled decryption threats ("Harvest Now, Decrypt Later").