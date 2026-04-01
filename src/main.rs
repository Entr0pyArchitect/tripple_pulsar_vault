// src/main.rs

mod crypto;
mod format;
mod shred;
mod win32;

use rand::{thread_rng, RngCore};
use secrecy::Secret;
use std::fs;
use std::io::{self, Write};

use crate::format::{
    parse_vault_header, CipherSuite, KeyWrapMode, ParsedVaultHeader, Tpf2Header, Tpf3Header,
};
use crate::win32::TpmKeyScope;

const DEFAULT_KDF_M_COST: u32 = 262_144; // 256 MiB
const DEFAULT_KDF_T_COST: u16 = 3;
const DEFAULT_KDF_P_COST: u8 = 1;
const DEFAULT_TPM_KEY_ALIAS: &str = "TPV-TPM-ContentKey";

fn print_banner() {
    let banner = r#"
  ██████╗██████╗ ██╗██████╗ ██████╗ ██╗      ███████╗
  ╚══██╔══╝██╔══██╗██║██╔══██╗██╔══██╗██║      ██╔════╝
    ██║   ██████╔╝██║██████╔╝██████╔╝██║      █████╗
    ██║   ██╔══██╗██║██╔═══╝ ██╔═══╝ ██║      ██╔══╝
    ██║   ██║  ██║██║██║      ██║      ███████╗███████╗
    ╚═╝   ╚═╝  ╚═╝╚═╝╚═╝      ╚═╝      ╚══════╝╚══════╝
      P U L S A R   V A U L T   3.0
"#;
    println!("{banner}");
    println!("Windows-oriented cryptographic file vault with TPF2 compatibility and TPF3 support.\n");
}

fn prompt_input(prompt: &str) -> String {
    print!("{prompt}");
    io::stdout().flush().unwrap();
    let mut input = String::new();
    io::stdin().read_line(&mut input).unwrap();
    input.trim().to_string()
}

fn prompt_yes_no(prompt: &str) -> bool {
    matches!(prompt_input(prompt).to_lowercase().as_str(), "y" | "yes")
}

fn prompt_passphrase() -> Secret<String> {
    let password =
        rpassword::prompt_password("Enter vault passphrase: ").expect("Failed to read passphrase");
    Secret::new(password.trim().to_string())
}

fn load_optional_dataset_hash(encrypting: bool) -> Result<Option<blake3::Hash>, ()> {
    let prompt = if encrypting {
        "  -> Use an auxiliary dataset in key derivation? (y/n): "
    } else {
        "  -> Was an auxiliary dataset used when this vault was created? (y/n): "
    };

    if !prompt_yes_no(prompt) {
        return Ok(None);
    }

    let path_prompt = if encrypting {
        "  -> Enter path to dataset (for example, HTRU_2.csv): "
    } else {
        "  -> Enter path to the exact same dataset used during encryption: "
    };

    let dataset_path = prompt_input(path_prompt);
    println!("[*] Hashing dataset with BLAKE3...");

    match crypto::hash_pulsar_dataset(&dataset_path) {
        Ok(hash) => {
            println!("[+] Dataset hash completed.");
            Ok(Some(hash))
        }
        Err(e) => {
            eprintln!("[!] Failed to process dataset: {e}");
            Err(())
        }
    }
}

fn select_cipher_suite() -> Option<CipherSuite> {
    println!("\nSelect cipher suite:");
    println!("1. AES-256-GCM");
    println!("2. XChaCha20-Poly1305");

    match prompt_input("Choice: ").as_str() {
        "1" => Some(CipherSuite::Aes256Gcm),
        "2" => Some(CipherSuite::XChaCha20Poly1305),
        _ => {
            eprintln!("[!] Invalid cipher suite selection.");
            None
        }
    }
}

fn select_tpm_scope() -> Option<TpmKeyScope> {
    println!("\nSelect TPM key scope:");
    println!("1. Current user");
    println!("2. Local machine");

    match prompt_input("Choice: ").as_str() {
        "1" => Some(TpmKeyScope::CurrentUser),
        "2" => Some(TpmKeyScope::LocalMachine),
        _ => {
            eprintln!("[!] Invalid TPM scope selection.");
            None
        }
    }
}

fn prompt_tpm_alias(default_alias: &str) -> String {
    let alias = prompt_input(&format!(
        "  -> Enter TPM RSA key alias [{}]: ",
        default_alias
    ));
    if alias.trim().is_empty() {
        default_alias.to_string()
    } else {
        alias
    }
}

fn prompt_mlkem_key_path(prompt: &str) -> String {
    prompt_input(prompt)
}

fn inspect_tpf2_header(header: &Tpf2Header) {
    println!("\n[+] Parsed TPF2 header:");
    println!("    Version: {}", header.version);
    println!("    Algorithm: {}", header.algorithm_name());
    println!("    KDF: {}", header.kdf_name());
    println!("    Argon2id Memory Cost: {} KiB", header.kdf_m);
    println!("    Argon2id Time Cost: {} iterations", header.kdf_t);
    println!("    Argon2id Parallelism: {} lane(s)", header.kdf_p);
    println!(
        "    Key Schedule: {}",
        if header.uses_v2_key_schedule() {
            "TPV 2.0 (Argon2id root key + HKDF expansion)"
        } else {
            "Legacy TPV 1.x (direct Argon2id output)"
        }
    );
    println!(
        "    TPM Flag: {}",
        if header.tpm_flag == 1 { "YES" } else { "NO" }
    );
}

fn inspect_tpf3_header(header: &Tpf3Header) {
    println!("\n[+] Parsed TPF3 header:");
    println!("    Version: {}", header.version);
    println!("    Cipher Suite: {}", header.cipher_name());
    println!("    KDF: {}", header.kdf_name());
    println!("    Wrap Mode: {}", header.wrap_mode_name());
    println!("    Argon2id Memory Cost: {} KiB", header.kdf_m);
    println!("    Argon2id Time Cost: {} iterations", header.kdf_t);
    println!("    Argon2id Parallelism: {} lane(s)", header.kdf_p);
    println!("    Nonce Length: {} bytes", header.nonce.len());
    println!("    Wrapped Key Length: {} bytes", header.wrapped_key.len());
    println!("    KEM Ciphertext Length: {} bytes", header.kem_ciphertext.len());
    println!("    TPM Policy Length: {} bytes", header.tpm_policy.len());
    println!("    Payload Offset: {} bytes", header.body_offset());
}

fn secure_teardown(startup_buffer: &mut [u8]) {
    let _ = win32::wipe_clipboard();
    let _ = win32::unlock_memory(startup_buffer);
}

fn encrypt_tpf2_flow() {
    println!("\n[*] Encrypting legacy-compatible TPF2 vault");
    let input_path = prompt_input("  -> Enter path to plaintext file: ");
    let output_path = prompt_input("  -> Enter destination vault path (.tpf2): ");

    let dataset_hash = match load_optional_dataset_hash(true) {
        Ok(hash) => hash,
        Err(_) => return,
    };

    let wipe_source = prompt_yes_no(
        "  -> Securely overwrite the plaintext source after encryption? (y/n): ",
    );
    let passphrase = prompt_passphrase();

    println!("[*] Reading plaintext file...");
    let plaintext = match fs::read(&input_path) {
        Ok(data) => data,
        Err(e) => {
            eprintln!("[!] Failed to read input file: {e}");
            return;
        }
    };

    let mut os_salt = [0u8; 32];
    let mut nonce = [0u8; 12];
    thread_rng().fill_bytes(&mut os_salt);
    thread_rng().fill_bytes(&mut nonce);

    let header = Tpf2Header::new_v2(
        0,
        DEFAULT_KDF_M_COST,
        DEFAULT_KDF_T_COST,
        DEFAULT_KDF_P_COST,
        0,
        os_salt,
        nonce,
    );

    println!("[*] Deriving vault key...");
    let vault_key = match crypto::derive_vault_key(&passphrase, dataset_hash, &header) {
        Ok(k) => k,
        Err(e) => {
            eprintln!("[!] Key derivation failed: {e}");
            return;
        }
    };

    println!("[*] Encrypting payload...");
    match crypto::encrypt_payload(&vault_key, &header, &plaintext) {
        Ok(ciphertext) => {
            let mut vault_data = header.as_bytes();
            vault_data.extend(ciphertext);

            if let Err(e) = fs::write(&output_path, vault_data) {
                eprintln!("[!] Failed to write vault to disk: {e}");
                return;
            }

            println!("[+] TPF2 vault created successfully.");
        }
        Err(e) => {
            eprintln!("[!] Encryption failed: {e}");
            return;
        }
    }

    if wipe_source {
        println!("[*] Securely overwriting source file...");
        if let Err(e) = shred::secure_erase(std::path::Path::new(&input_path)) {
            eprintln!("[!] Secure erase failed: {e}");
        } else {
            println!("[+] Source file removed.");
        }
    }
}

fn encrypt_tpf3_flow() {
    println!("
[*] Encrypting TPF3 vault");
    let input_path = prompt_input("  -> Enter path to plaintext file: ");
    let output_path = prompt_input("  -> Enter destination vault path (.tpf3): ");

    let cipher_suite = match select_cipher_suite() {
        Some(suite) => suite,
        None => return,
    };

    println!("
Select wrap mode:");
    println!("1. Direct/local derivation (implemented)");
    println!("2. TPM-wrapped content key (implemented)");
    println!("3. ML-KEM-768 wrapped content key (implemented)");

    let wrap_mode = match prompt_input("Choice: ").as_str() {
        "1" => KeyWrapMode::None,
        "2" => KeyWrapMode::TpmWrapped,
        "3" => KeyWrapMode::MlKem768,
        _ => {
            eprintln!("[!] Invalid wrap mode selection.");
            return;
        }
    };

    let dataset_hash = if wrap_mode == KeyWrapMode::None {
        match load_optional_dataset_hash(true) {
            Ok(hash) => hash,
            Err(_) => return,
        }
    } else {
        None
    };

    let wipe_source = prompt_yes_no(
        "  -> Securely overwrite the plaintext source after encryption? (y/n): ",
    );

    let passphrase = if wrap_mode == KeyWrapMode::None {
        Some(prompt_passphrase())
    } else {
        None
    };

    println!("[*] Reading plaintext file...");
    let plaintext = match fs::read(&input_path) {
        Ok(data) => data,
        Err(e) => {
            eprintln!("[!] Failed to read input file: {e}");
            return;
        }
    };

    let mut os_salt = [0u8; 32];
    thread_rng().fill_bytes(&mut os_salt);
    let nonce = crypto::generate_tpf3_nonce(cipher_suite);

    let (wrapped_key, kem_ciphertext, tpm_policy, content_key) = match wrap_mode {
        KeyWrapMode::None => {
            println!("[*] Deriving TPF3 content key...");
            let temp_header = match Tpf3Header::new_v3(
                0,
                cipher_suite,
                KeyWrapMode::None,
                DEFAULT_KDF_M_COST,
                DEFAULT_KDF_T_COST,
                DEFAULT_KDF_P_COST,
                os_salt,
                nonce.clone(),
                vec![],
                vec![],
                vec![],
            ) {
                Ok(h) => h,
                Err(e) => {
                    eprintln!("[!] Failed to build temporary TPF3 header: {e}");
                    return;
                }
            };

            let content_key = match crypto::derive_tpf3_content_key(
                passphrase.as_ref().expect("passphrase required for direct mode"),
                dataset_hash,
                &temp_header,
            ) {
                Ok(k) => k,
                Err(e) => {
                    eprintln!("[!] Key derivation failed: {e}");
                    return;
                }
            };

            (vec![], vec![], vec![], content_key)
        }
        KeyWrapMode::TpmWrapped => {
            if !win32::tpm_provider_available() {
                eprintln!("[!] TPM provider is unavailable on this system.");
                return;
            }

            let scope = match select_tpm_scope() {
                Some(scope) => scope,
                None => return,
            };

            let alias = prompt_tpm_alias(DEFAULT_TPM_KEY_ALIAS);

            println!("[*] Ensuring TPM RSA key exists...");
            if let Err(e) = win32::ensure_tpm_rsa_key(&alias, scope) {
                eprintln!("[!] Failed to provision/open TPM RSA key: {e}");
                return;
            }

            println!("[*] Generating random TPF3 content key...");
            let content_key = crypto::generate_tpf3_random_content_key(cipher_suite);

            println!("[*] Wrapping content key with TPM-backed RSA key...");
            let (wrapped_key, tpm_policy) =
                match crypto::tpm_wrap_tpf3_content_key(&content_key, &alias, scope) {
                    Ok(parts) => parts,
                    Err(e) => {
                        eprintln!("[!] Failed to TPM-wrap content key: {e}");
                        return;
                    }
                };

            (wrapped_key, vec![], tpm_policy, content_key)
        }
        KeyWrapMode::MlKem768 => {
            let pubkey_path =
                prompt_mlkem_key_path("  -> Enter recipient ML-KEM-768 public key path: ");

            let recipient_public_key_bytes = match fs::read(&pubkey_path) {
                Ok(bytes) => bytes,
                Err(e) => {
                    eprintln!("[!] Failed to read ML-KEM public key file: {e}");
                    return;
                }
            };

            println!("[*] Generating random TPF3 content key...");
            let content_key = crypto::generate_tpf3_random_content_key(cipher_suite);

            println!("[*] Wrapping content key with ML-KEM-768...");
            let (wrapped_key, kem_ciphertext) =
                match crypto::mlkem768_wrap_tpf3_content_key(
                    &content_key,
                    &recipient_public_key_bytes,
                ) {
                    Ok(parts) => parts,
                    Err(e) => {
                        eprintln!("[!] Failed to ML-KEM-wrap content key: {e}");
                        return;
                    }
                };

            (wrapped_key, kem_ciphertext, vec![], content_key)
        }
    };

    let header = match Tpf3Header::new_v3(
        0,
        cipher_suite,
        wrap_mode,
        DEFAULT_KDF_M_COST,
        DEFAULT_KDF_T_COST,
        DEFAULT_KDF_P_COST,
        os_salt,
        nonce,
        wrapped_key,
        kem_ciphertext,
        tpm_policy,
    ) {
        Ok(h) => h,
        Err(e) => {
            eprintln!("[!] Failed to build TPF3 header: {e}");
            return;
        }
    };

    println!("[*] Encrypting payload...");
    let header_bytes = match header.as_bytes() {
        Ok(bytes) => bytes,
        Err(e) => {
            eprintln!("[!] Failed to serialize TPF3 header: {e}");
            return;
        }
    };

    match crypto::encrypt_tpf3_payload(&content_key, &header, &plaintext) {
        Ok(ciphertext) => {
            let mut vault_data = header_bytes;
            vault_data.extend(ciphertext);

            if let Err(e) = fs::write(&output_path, vault_data) {
                eprintln!("[!] Failed to write vault to disk: {e}");
                return;
            }

            println!("[+] TPF3 vault created successfully.");
        }
        Err(e) => {
            eprintln!("[!] Encryption failed: {e}");
            return;
        }
    }

    if wipe_source {
        println!("[*] Securely overwriting source file...");
        if let Err(e) = shred::secure_erase(std::path::Path::new(&input_path)) {
            eprintln!("[!] Secure erase failed: {e}");
        } else {
            println!("[+] Source file removed.");
        }
    }
}

fn decrypt_vault_flow() {
    println!("\n[*] Decryption");
    let input_path = prompt_input("  -> Enter path to vault file: ");
    let output_path = prompt_input("  -> Enter destination plaintext path: ");

    let vault_data = match fs::read(&input_path) {
        Ok(data) => data,
        Err(e) => {
            eprintln!("[!] Failed to read vault file: {e}");
            return;
        }
    };

    let parsed = match parse_vault_header(&vault_data) {
        Ok(header) => header,
        Err(e) => {
            eprintln!("[!] Failed to parse vault header: {e}");
            return;
        }
    };

    match parsed {
        ParsedVaultHeader::Tpf2(header) => {
            inspect_tpf2_header(&header);

            let dataset_hash = match load_optional_dataset_hash(false) {
                Ok(hash) => hash,
                Err(_) => return,
            };

            let passphrase = prompt_passphrase();
            let ciphertext = &vault_data[format::HEADER_SIZE..];

            println!("[*] Deriving legacy vault key...");
            let vault_key = match crypto::derive_vault_key(&passphrase, dataset_hash, &header) {
                Ok(k) => k,
                Err(e) => {
                    eprintln!("[!] Key derivation failed: {e}");
                    return;
                }
            };

            println!("[*] Decrypting and verifying authentication tag...");
            match crypto::decrypt_payload(&vault_key, &header, ciphertext) {
                Ok(plaintext) => {
                    if let Err(e) = fs::write(&output_path, plaintext) {
                        eprintln!("[!] Failed to write plaintext to disk: {e}");
                        return;
                    }
                    println!("[+] TPF2 vault decrypted successfully.");
                }
                Err(_) => {
                    eprintln!(
                        "[!] Decryption failed. Check the passphrase, dataset selection, or file integrity."
                    );
                    return;
                }
            }
        }

        ParsedVaultHeader::Tpf3(header) => {
            inspect_tpf3_header(&header);

            let body_offset = header.body_offset();
            if vault_data.len() < body_offset {
                eprintln!("[!] Vault payload offset is invalid.");
                return;
            }

            let ciphertext = &vault_data[body_offset..];

            let content_key = match header.wrap_mode {
                KeyWrapMode::None => {
                    let dataset_hash = match load_optional_dataset_hash(false) {
                        Ok(hash) => hash,
                        Err(_) => return,
                    };

                    let passphrase = prompt_passphrase();

                    println!("[*] Deriving TPF3 content key...");
                    match crypto::derive_tpf3_content_key(&passphrase, dataset_hash, &header) {
                        Ok(k) => k,
                        Err(e) => {
                            eprintln!("[!] Key derivation failed: {e}");
                            return;
                        }
                    }
                }
                KeyWrapMode::TpmWrapped => {
                    println!("[*] Recovering TPM-wrapped TPF3 content key...");
                    match crypto::tpm_unwrap_tpf3_content_key(&header) {
                        Ok(k) => k,
                        Err(e) => {
                            eprintln!("[!] Failed to unwrap TPM content key: {e}");
                            return;
                        }
                    }
                }
                KeyWrapMode::MlKem768 => {
                    let privkey_path =
                        prompt_mlkem_key_path("  -> Enter ML-KEM-768 private key path: ");

                    let recipient_private_key_bytes = match fs::read(&privkey_path) {
                        Ok(bytes) => bytes,
                        Err(e) => {
                            eprintln!("[!] Failed to read ML-KEM private key file: {e}");
                            return;
                        }
                    };

                    println!("[*] Unwrapping TPF3 content key with ML-KEM-768...");
                    match crypto::mlkem768_unwrap_tpf3_content_key(
                        &header.wrapped_key,
                        &header.kem_ciphertext,
                        &recipient_private_key_bytes,
                    ) {
                        Ok(k) => k,
                        Err(e) => {
                            eprintln!("[!] Failed to unwrap ML-KEM content key: {e}");
                            return;
                        }
                    }
                }
            };

            println!("[*] Decrypting and verifying authentication tag...");
            match crypto::decrypt_tpf3_payload(&content_key, &header, ciphertext) {
                Ok(plaintext) => {
                    if let Err(e) = fs::write(&output_path, plaintext) {
                        eprintln!("[!] Failed to write plaintext to disk: {e}");
                        return;
                    }
                    println!("[+] TPF3 vault decrypted successfully.");
                }
                Err(_) => {
                    eprintln!(
                        "[!] Decryption failed. Check the credentials, dataset selection, cipher choice, TPM context, or file integrity."
                    );
                    return;
                }
            }
        }
    }

    if let Err(_) = win32::wipe_clipboard() {
        eprintln!("[WARNING] Failed to clear the Windows clipboard.");
    } else {
        println!("[+] Clipboard cleared.");
    }
}

fn inspect_vault_flow() {
    println!("\n[*] Header inspection");
    let input_path = prompt_input("  -> Enter path to vault file: ");

    let vault_data = match fs::read(&input_path) {
        Ok(data) => data,
        Err(e) => {
            eprintln!("[!] Failed to read vault file: {e}");
            return;
        }
    };

    match parse_vault_header(&vault_data) {
        Ok(ParsedVaultHeader::Tpf2(header)) => inspect_tpf2_header(&header),
        Ok(ParsedVaultHeader::Tpf3(header)) => inspect_tpf3_header(&header),
        Err(e) => eprintln!("[!] Failed to parse header: {e}"),
    }
}

fn check_tpm_provider_flow() {
    println!("\n[*] Checking TPM provider...");
    if win32::tpm_provider_available() {
        println!("[+] Microsoft Platform Crypto Provider is available.");
    } else {
        println!("[!] Microsoft Platform Crypto Provider is unavailable on this system.");
    }
}

fn generate_mlkem_keypair_flow() {
    println!("\n[*] ML-KEM-768 keypair generation");
    let public_key_path =
        prompt_mlkem_key_path("  -> Enter destination public key path (.mlkem.pub): ");
    let private_key_path =
        prompt_mlkem_key_path("  -> Enter destination private key path (.mlkem.sec): ");

    match crypto::generate_mlkem768_keypair_files(&public_key_path, &private_key_path) {
        Ok(()) => println!("[+] ML-KEM-768 keypair generated successfully."),
        Err(e) => eprintln!("[!] Failed to generate ML-KEM-768 keypair: {e}"),
    }
}

fn provision_tpm_key_flow() {
    println!("\n[*] TPM RSA key provisioning");
    if !win32::tpm_provider_available() {
        eprintln!("[!] TPM provider is unavailable on this system.");
        return;
    }

    let scope = match select_tpm_scope() {
        Some(scope) => scope,
        None => return,
    };

    let alias = prompt_tpm_alias(DEFAULT_TPM_KEY_ALIAS);

    println!(
        "[*] Ensuring TPM RSA key '{}' exists in scope {}...",
        alias,
        scope.label()
    );

    match win32::ensure_tpm_rsa_key(&alias, scope) {
        Ok(()) => println!("[+] TPM RSA key is ready."),
        Err(e) => eprintln!("[!] Failed to provision TPM RSA key: {e}"),
    }
}

fn secure_exit_flow(startup_buffer: &mut [u8]) {
    println!("\n[*] Performing secure exit...");
    secure_teardown(startup_buffer);
    println!("[+] Session closed.");
}

fn emergency_exit_flow(startup_buffer: &mut [u8]) {
    eprintln!("\n[!] Emergency exit initiated...");
    secure_teardown(startup_buffer);
    eprintln!("[!] Emergency teardown complete.");
}

fn main() {
    let mut startup_buffer = vec![0u8; 4096];
    if let Err(e) = win32::lock_memory(&mut startup_buffer) {
        eprintln!("[WARNING] Failed to lock startup buffer in RAM: {e}");
    }

    print_banner();

    loop {
        println!("=== TripplePulsar Vault 3.0 ===");
        println!("1. Encrypt legacy-compatible TPF2 vault");
        println!("2. Encrypt modern TPF3 vault");
        println!("3. Decrypt vault");
        println!("4. Inspect vault header");
        println!("5. Check TPM provider");
        println!("6. Provision TPM RSA key");
        println!("7. Generate ML-KEM-768 keypair");
        println!("8. Secure exit");
        println!("0. Emergency exit");

        match prompt_input("Select an option: ").as_str() {
            "1" => encrypt_tpf2_flow(),
            "2" => encrypt_tpf3_flow(),
            "3" => decrypt_vault_flow(),
            "4" => inspect_vault_flow(),
            "5" => check_tpm_provider_flow(),
            "6" => provision_tpm_key_flow(),
            "7" => generate_mlkem_keypair_flow(),
            "8" => {
                secure_exit_flow(&mut startup_buffer);
                break;
            }
            "0" => {
                emergency_exit_flow(&mut startup_buffer);
                break;
            }
            _ => eprintln!("[!] Invalid option.\n"),
        }

        println!();
    }
}
