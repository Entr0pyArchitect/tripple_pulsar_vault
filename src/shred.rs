// src/shred.rs

use rand::{thread_rng, RngCore};
use std::fs::OpenOptions;
use std::io::{Seek, SeekFrom, Write};
use std::path::Path;
use thiserror::Error;
use zeroize::Zeroize;

#[derive(Debug, Error)]
pub enum ShredError {
    #[error("I/O error during secure erase: {0}")]
    IoError(#[from] std::io::Error),
}

/// Best-effort overwrite-and-delete for plaintext source files.
///
/// Notes:
/// - This performs two overwrite passes:
///   1. random data
///   2. zeros
/// - This may reduce recoverability on some storage media.
/// - It does NOT guarantee secure deletion on SSDs or other devices that use
///   wear-leveling, journaling, snapshots, or copy-on-write behavior.
pub fn secure_erase(file_path: &Path) -> Result<(), ShredError> {
    if !file_path.exists() {
        return Ok(());
    }

    let metadata = std::fs::metadata(file_path)?;
    let file_size = metadata.len();

    if file_size == 0 {
        std::fs::remove_file(file_path)?;
        return Ok(());
    }

    let mut file = OpenOptions::new().write(true).open(file_path)?;

    let mut rng = thread_rng();
    let mut buffer = vec![0u8; 65_536];

    // Pass 1: overwrite with random bytes
    file.seek(SeekFrom::Start(0))?;
    let mut written = 0u64;
    while written < file_size {
        rng.fill_bytes(&mut buffer);
        let to_write = std::cmp::min(buffer.len() as u64, file_size - written) as usize;
        file.write_all(&buffer[..to_write])?;
        written += to_write as u64;
    }
    file.flush()?;
    file.sync_all()?;

    // Pass 2: overwrite with zeros
    file.seek(SeekFrom::Start(0))?;
    buffer.fill(0);
    written = 0;
    while written < file_size {
        let to_write = std::cmp::min(buffer.len() as u64, file_size - written) as usize;
        file.write_all(&buffer[..to_write])?;
        written += to_write as u64;
    }
    file.flush()?;
    file.sync_all()?;

    // Scrub the in-memory buffer before dropping it
    buffer.zeroize();

    // Important on Windows: close the handle before deleting the file
    drop(file);

    std::fs::remove_file(file_path)?;

    Ok(())
}