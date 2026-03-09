// src/main.rs

mod crypto;
mod format;
mod win32;
mod shred;

use secrecy::Secret;
use std::io::{self, Write};
use std::fs;
use rand::{thread_rng, RngCore};

fn print_banner() {
    let banner = r#"
  ██████╗██████╗ ██╗██████╗ ██████╗ ██╗      ███████╗
  ╚══██╔══╝██╔══██╗██║██╔══██╗██╔══██╗██║      ██╔════╝
    ██║   ██████╔╝██║██████╔╝██████╔╝██║      █████╗  
    ██║   ██╔══██╗██║██╔═══╝ ██╔═══╝ ██║      ██╔══╝  
    ██║   ██║  ██║██║██║      ██║      ███████╗███████╗
    ╚═╝   ╚═╝  ╚═╝╚═╝╚═╝      ╚═╝      ╚══════╝╚══════╝
      P  U  L  S  A  R      V  A  U  L  T
      "Tripple checking that security since 2026"
"#;
    println!("{}", banner);
}

fn prompt_input(prompt: &str) -> String {
    print!("{}", prompt);
    io::stdout().flush().unwrap();
    let mut input = String::new();
    io::stdin().read_line(&mut input).unwrap();
    input.trim().to_string()
}

fn prompt_passphrase() -> Secret<String> {
    let password = rpassword::prompt_password("Enter Vault Passphrase: ")
        .expect("Failed to read passphrase");
    Secret::new(password.trim().to_string())
}

fn main() {
    print_banner();

    let mut startup_buffer = [0u8; 32];
    if let Err(e) = win32::lock_memory(&mut startup_buffer) {
        eprintln!("[WARNING] OS Memory Lock failed: {}. Ensure you have the right permissions.", e);
    }

    loop {
        println!("\n=== TRIPLE PULSAR VAULT (Windows Edition) ===");
        println!("1. Encrypt File");
        println!("2. Decrypt Vault");
        println!("3. Inspect Vault Header");
        println!("4. Secure Exit");
        println!("0. Self-Destruct (Emergency Wipe & Exit)");
        print!("Select an option: ");
        io::stdout().flush().unwrap();

        let mut choice = String::new();
        io::stdin().read_line(&mut choice).unwrap();

        match choice.trim() {
            "1" => {
                println!("\n[*] ENCRYPTION SEQUENCE");
                let input_str = prompt_input("  -> Enter path to plaintext file: ");
                let output_str = prompt_input("  -> Enter destination vault path (.tpf2): ");
                
                let use_pulsar = prompt_input("  -> Use Pulsar dataset for extreme entropy? (y/n): ");
                let mut dataset_hash = None;
                if use_pulsar.to_lowercase() == "y" {
                    let ds_str = prompt_input("  -> Enter path to Pulsar dataset (e.g., mock_pulsar.csv): ");
                    println!("[*] Streaming dataset through BLAKE3...");
                    match crypto::hash_pulsar_dataset(&ds_str) {
                        Ok(h) => {
                            dataset_hash = Some(h);
                            println!("[+] Dataset hashed successfully.");
                        },
                        Err(e) => {
                            eprintln!("[!] Failed to read dataset: {}", e);
                            continue;
                        }
                    }
                }
                
                let wipe_choice = prompt_input("  -> Perform DoD 2-pass wipe on plaintext source after encryption? (y/n): ");
                let passphrase = prompt_passphrase();

                println!("[*] Reading plaintext file...");
                let plaintext = match fs::read(&input_str) {
                    Ok(data) => data,
                    Err(e) => {
                        eprintln!("[!] Failed to read input file: {}", e);
                        continue;
                    }
                };

                // Generate 32-byte OS Salt and 12-byte Nonce
                let mut os_salt = [0u8; 32];
                let mut nonce = [0u8; 12];
                thread_rng().fill_bytes(&mut os_salt);
                thread_rng().fill_bytes(&mut nonce);

                println!("[*] Deriving Argon2id Master Key (This may take a moment)...");
                // 262144 KB = 256 MB RAM, 3 iterations, 1 parallelism lane
                let master_key = match crypto::derive_master_key(&passphrase, dataset_hash, &os_salt, 262144, 3, 1) {
                    Ok(k) => k,
                    Err(e) => {
                        eprintln!("[!] Key derivation failed: {}", e);
                        continue;
                    }
                };

                let header = format::Tpf2Header {
                    magic: *format::MAGIC_BYTES,
                    version: format::CURRENT_VERSION,
                    flags: 0,
                    alg_id: 0, // AES-256-GCM
                    kdf_id: 0, // Argon2id
                    kdf_m: 262144,
                    kdf_t: 3,
                    kdf_p: 1,
                    tpm_flag: 0,
                    reserved: [0; 2],
                    os_salt,
                    nonce,
                };

                println!("[*] Encrypting payload with AES-256-GCM...");
                match crypto::encrypt_payload(&master_key, &header, &plaintext) {
                    Ok(ciphertext) => {
                        let mut vault_data = header.as_bytes();
                        vault_data.extend(ciphertext);
                        if let Err(e) = fs::write(&output_str, vault_data) {
                            eprintln!("[!] Failed to write vault to disk: {}", e);
                            continue;
                        }
                        println!("\n[+] Cryptographic core engaged. Vault secured successfully!");
                    },
                    Err(e) => {
                        eprintln!("[!] Encryption failed: {}", e);
                        continue;
                    }
                }

                if wipe_choice.to_lowercase() == "y" {
                    println!("[*] Initiating DoD secure wipe on source file...");
                    if let Err(e) = shred::secure_erase(std::path::Path::new(&input_str)) {
                        eprintln!("[!] Shredding failed: {}", e);
                    } else {
                        println!("[+] Source file securely obliterated from physical disk.");
                    }
                }
            }
            "2" => {
                println!("\n[*] DECRYPTION SEQUENCE");
                let input_str = prompt_input("  -> Enter path to vault file: ");
                let output_str = prompt_input("  -> Enter destination plaintext path: ");
                
                let use_pulsar = prompt_input("  -> Was a Pulsar dataset used to encrypt this? (y/n): ");
                let mut dataset_hash = None;
                if use_pulsar.to_lowercase() == "y" {
                    let ds_str = prompt_input("  -> Enter path to exact Pulsar dataset: ");
                    println!("[*] Streaming dataset through BLAKE3...");
                    match crypto::hash_pulsar_dataset(&ds_str) {
                        Ok(h) => dataset_hash = Some(h),
                        Err(e) => {
                            eprintln!("[!] Failed to read dataset: {}", e);
                            continue;
                        }
                    }
                }
                
                let passphrase = prompt_passphrase();
                
                let vault_data = match fs::read(&input_str) {
                    Ok(data) => data,
                    Err(e) => {
                        eprintln!("[!] Failed to read vault file: {}", e);
                        continue;
                    }
                };

                if vault_data.len() < format::HEADER_SIZE {
                    eprintln!("[!] File is too small to be a valid TPF2 vault.");
                    continue;
                }

                println!("[*] Parsing TPF2 Header...");
                let header = match format::Tpf2Header::from_bytes(&vault_data[..format::HEADER_SIZE]) {
                    Ok(h) => h,
                    Err(e) => {
                        eprintln!("[!] Header validation failed: {}", e);
                        continue;
                    }
                };

                let ciphertext = &vault_data[format::HEADER_SIZE..];

                println!("[*] Deriving Argon2id Master Key (Reconstructing from header parameters)...");
                let master_key = match crypto::derive_master_key(
                    &passphrase, 
                    dataset_hash, 
                    &header.os_salt, 
                    header.kdf_m, 
                    header.kdf_t as u32, 
                    header.kdf_p as u32
                ) {
                    Ok(k) => k,
                    Err(e) => {
                        eprintln!("[!] Key derivation failed: {}", e);
                        continue;
                    }
                };

                println!("[*] Decrypting and verifying MAC tag...");
                match crypto::decrypt_payload(&master_key, &header, ciphertext) {
                    Ok(plaintext) => {
                        if let Err(e) = fs::write(&output_str, plaintext) {
                            eprintln!("[!] Failed to write plaintext to disk: {}", e);
                            continue;
                        }
                        println!("\n[+] Integrity verified. Payload decrypted successfully!");
                    },
                    Err(_) => {
                        eprintln!("\n[!] FATAL: Decryption failed. Incorrect passphrase, wrong dataset, or file was tampered with.");
                        continue;
                    }
                }
                
                if let Err(_) = win32::wipe_clipboard() {
                    eprintln!("[WARNING] Failed to securely wipe the Windows clipboard.");
                } else {
                    println!("[+] Windows clipboard securely wiped.");
                }
            }
            "3" => {
                println!("\n[*] VAULT INSPECTION");
                let input_str = prompt_input("  -> Enter path to vault file: ");
                
                let vault_data = match fs::read(&input_str) {
                    Ok(data) => data,
                    Err(e) => {
                        eprintln!("[!] Failed to read vault file: {}", e);
                        continue;
                    }
                };

                match format::Tpf2Header::from_bytes(&vault_data) {
                    Ok(h) => {
                        println!("\n[+] TPF2 Header parsed successfully:");
                        println!("    Version: {}", h.version);
                        println!("    Algorithm ID: {} (AES-GCM)", h.alg_id);
                        println!("    Argon2id Memory Cost: {} KB", h.kdf_m);
                        println!("    Argon2id Time Cost: {} iterations", h.kdf_t);
                        println!("    Argon2id Parallelism: {} lanes", h.kdf_p);
                        println!("    Hardware TPM Bound: {}", if h.tpm_flag == 1 { "YES" } else { "NO" });
                    },
                    Err(e) => eprintln!("[!] Failed to parse header: {}", e),
                }
            }
            "4" => {
                println!("\n[*] Initiating Secure Exit...");
                break;
            }
            "0" => {
                println!("\n[!] EMERGENCY SELF-DESTRUCT INITIATED [!]");
                let _ = win32::wipe_clipboard();
                let _ = win32::unlock_memory(&mut startup_buffer);
                println!("[+] RAM unpinned. Clipboard scrubbed. Terminating instantly.");
                std::process::exit(0);
            }
            _ => println!("[!] Invalid option. Please select an option from 0 to 4."),
        }
    }
    
    let _ = win32::unlock_memory(&mut startup_buffer);
    println!("[+] Cryptographic teardown sequence complete. Stay safe.");
}