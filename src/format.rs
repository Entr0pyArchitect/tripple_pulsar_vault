// src/format.rs

use thiserror::Error;

pub const MAGIC_BYTES: &[u8; 4] = b"TPF2";
pub const CURRENT_VERSION: u8 = 1;
pub const HEADER_SIZE: usize = 62;

#[derive(Debug, Error)]
pub enum FormatError {
    #[error("Invalid magic bytes: file is not a valid TPF2 vault")]
    InvalidMagic,
    #[error("Unsupported vault version")]
    UnsupportedVersion,
    #[error("Header buffer is too short to parse")]
    HeaderTooShort,
}

/// The strict, 62-byte binary layout of the Tripple Pulsar Vault header.
#[derive(Debug, Clone)]
pub struct Tpf2Header {
    pub magic: [u8; 4],
    pub version: u8,
    pub flags: u8,
    pub alg_id: u8,
    pub kdf_id: u8,
    pub kdf_m: u32,
    pub kdf_t: u16,
    pub kdf_p: u8,
    pub tpm_flag: u8,
    pub reserved: [u8; 2],
    pub os_salt: [u8; 32],
    pub nonce: [u8; 12],
}

impl Tpf2Header {
    /// Extracts the raw bytes into a byte vector for AAD authentication.
    pub fn as_bytes(&self) -> Vec<u8> {
        let mut buffer = Vec::with_capacity(HEADER_SIZE);
        buffer.extend_from_slice(&self.magic);
        buffer.push(self.version);
        buffer.push(self.flags);
        buffer.push(self.alg_id);
        buffer.push(self.kdf_id);
        buffer.extend_from_slice(&self.kdf_m.to_le_bytes());
        buffer.extend_from_slice(&self.kdf_t.to_le_bytes());
        buffer.push(self.kdf_p);
        buffer.push(self.tpm_flag);
        buffer.extend_from_slice(&self.reserved);
        buffer.extend_from_slice(&self.os_salt);
        buffer.extend_from_slice(&self.nonce);
        buffer
    }

    /// Safely parses raw bytes from disk back into a Tpf2Header struct.
    pub fn from_bytes(data: &[u8]) -> Result<Self, FormatError> {
        if data.len() < HEADER_SIZE {
            return Err(FormatError::HeaderTooShort);
        }
        
        let mut magic = [0u8; 4];
        magic.copy_from_slice(&data[0..4]);
        if &magic != MAGIC_BYTES {
            return Err(FormatError::InvalidMagic);
        }

        let version = data[4];
        if version != CURRENT_VERSION {
            return Err(FormatError::UnsupportedVersion);
        }

        let mut kdf_m_bytes = [0u8; 4];
        kdf_m_bytes.copy_from_slice(&data[8..12]);
        
        let mut kdf_t_bytes = [0u8; 2];
        kdf_t_bytes.copy_from_slice(&data[12..14]);

        let mut reserved = [0u8; 2];
        reserved.copy_from_slice(&data[16..18]);

        let mut os_salt = [0u8; 32];
        os_salt.copy_from_slice(&data[18..50]);

        let mut nonce = [0u8; 12];
        nonce.copy_from_slice(&data[50..62]);

        Ok(Tpf2Header {
            magic,
            version,
            flags: data[5],
            alg_id: data[6],
            kdf_id: data[7],
            kdf_m: u32::from_le_bytes(kdf_m_bytes),
            kdf_t: u16::from_le_bytes(kdf_t_bytes),
            kdf_p: data[14],
            tpm_flag: data[15],
            reserved,
            os_salt,
            nonce,
        })
    }
}