# 🛡️ TripplePulsar Vault: Threat Model & Attack Analysis

## 1. Security Goals
* **Confidentiality:** Prevent unauthorized access to the plaintext content of encrypted vaults.
* **Integrity:** Ensure that any tampering with the ciphertext or the vault header results in an immediate authentication failure.
* **Forensic Resistance:** Minimize the footprint of cryptographic keys in system memory and securely overwrite plaintext source files.

## 2. Threat Actors & Scenarios
* **The Forensic Investigator:** An attacker with physical access to a powered-down machine.
  * *Defense:* TPV uses Argon2id to maximize cracking costs and DoD-level shredding to prevent data recovery from disk sectors.
* **The Memory Scraper:** Malware attempting to read secrets from RAM while the program is running.
  * *Defense:* TPV utilizes Win32 `VirtualLock` to pin keys to RAM and the `Zeroize` trait to scrub sensitive buffers immediately after use.
* **The Tamperer:** An attacker who modifies bits in the vault to cause a "padding oracle" or bit-flipping attack.
  * *Defense:* AES-256-GCM (AEAD) binds the entire header as Associated Authenticated Data. Verification fails before decryption begins.

## 3. Adversarial Assumptions (Out of Scope)
TripplePulsar Vault is not designed to protect against:
* **Compromised Kernel:** If the host Operating System is infected with a rootkit or kernel-level keylogger, no software-defined security boundary is effective.
* **Hardware Interception:** Hardware-based implants (e.g., physical keyloggers or DMA-attack devices) are outside the scope of this software.
* **User Negligence:** The system cannot protect against a compromised passphrase or the loss of the required astronomical dataset.


