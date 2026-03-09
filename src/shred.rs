// src/shred.rs

use std::fs::OpenOptions;
use std::io::{Write, Seek, SeekFrom};
use std::path::Path;
use rand::{RngCore, thread_rng};
use thiserror::Error;

#[derive(Debug, Error)]
pub enum ShredError {
    #[error("I/O Error during shredding: {0}")]
    IoError(#[from] std::io::Error),
}

/// Performs a DoD-level 2-pass secure wipe (Random data, then Zeros) 
/// on the plaintext source file to thwart forensic recovery tools.
pub fn secure_erase(file_path: &Path) -> Result<(), ShredError> {
    if !file_path.exists() {
        return Ok(());
    }

    let metadata = std::fs::metadata(file_path)?;
    let file_size = metadata.len();

    // Open the file with write permissions without truncating it
    let mut file = OpenOptions::new().write(true).open(file_path)?;

    // Pass 1: Random Data Overwrite
    let mut rng = thread_rng();
    let mut buffer = vec![0u8; 65536]; // Process in 64KB chunks
    let mut written = 0;
    while written < file_size {
        rng.fill_bytes(&mut buffer);
        let to_write = std::cmp::min(buffer.len() as u64, file_size - written) as usize;
        file.write_all(&buffer[..to_write])?;
        written += to_write as u64;
    }
    file.sync_all()?; // Force the OS to write to the physical disk

    // Pass 2: Zero-Fill Overwrite
    file.seek(SeekFrom::Start(0))?;
    written = 0;
    buffer.fill(0);
    while written < file_size {
        let to_write = std::cmp::min(buffer.len() as u64, file_size - written) as usize;
        file.write_all(&buffer[..to_write])?;
        written += to_write as u64;
    }
    file.sync_all()?;

    // Unlink (Delete) the file from the filesystem
    std::fs::remove_file(file_path)?;

    Ok(())
}