// src/format.rs

use std::convert::TryFrom;

use thiserror::Error;

/* -------------------------------------------------------------------------- */
/* Legacy TPF2 constants (kept for v1/v2 compatibility)                       */
/* -------------------------------------------------------------------------- */

pub const MAGIC_BYTES: &[u8; 4] = b"TPF2";

pub const LEGACY_VERSION: u8 = 1;
pub const CURRENT_VERSION: u8 = 2;

pub const HEADER_SIZE: usize = 62;

pub const ALG_ID_AES_256_GCM: u8 = 1;
pub const KDF_ID_ARGON2ID: u8 = 1;

/* -------------------------------------------------------------------------- */
/* New TPF3 constants                                                         */
/* -------------------------------------------------------------------------- */

pub const TPF3_MAGIC_BYTES: &[u8; 4] = b"TPF3";
pub const TPF3_VERSION: u8 = 1;

/// Fixed-size prelude before variable-length TPF3 blobs.
///
/// Layout:
/// 0..4   magic
/// 4      version
/// 5..7   flags (u16 LE)
/// 7      cipher_id
/// 8      kdf_id
/// 9      wrap_mode
/// 10     nonce_len
/// 11..13 wrapped_key_len (u16 LE)
/// 13..15 kem_ct_len (u16 LE)
/// 15..17 tpm_policy_len (u16 LE)
/// 17..21 kdf_m (u32 LE)
/// 21..23 kdf_t (u16 LE)
/// 23     kdf_p
/// 24..56 os_salt (32 bytes)
pub const TPF3_FIXED_HEADER_SIZE: usize = 56;

pub const TPF3_CIPHER_AES_256_GCM: u8 = 1;
pub const TPF3_CIPHER_XCHACHA20POLY1305: u8 = 2;

pub const TPF3_KDF_ARGON2ID_HKDF_SHA256: u8 = 1;

pub const TPF3_WRAP_NONE: u8 = 0;
pub const TPF3_WRAP_TPM: u8 = 1;
pub const TPF3_WRAP_MLKEM768: u8 = 2;

#[derive(Debug, Error)]
pub enum FormatError {
    #[error("Invalid magic bytes: file is not a supported vault")]
    InvalidMagic,

    #[error("Unsupported vault version: {0}")]
    UnsupportedVersion(u8),

    #[error("Unsupported algorithm identifier: {0}")]
    UnsupportedAlgorithm(u8),

    #[error("Unsupported KDF identifier: {0}")]
    UnsupportedKdf(u8),

    #[error("Unsupported cipher suite identifier: {0}")]
    UnsupportedCipherSuite(u8),

    #[error("Unsupported TPF3 KDF identifier: {0}")]
    UnsupportedTpf3Kdf(u8),

    #[error("Unsupported TPF3 wrap mode: {0}")]
    UnsupportedWrapMode(u8),

    #[error("Header buffer is too short to parse")]
    HeaderTooShort,

    #[error("TPF3 buffer is too short to parse")]
    Tpf3HeaderTooShort,

    #[error("TPF3 blob lengths exceed available data")]
    InvalidTpf3BlobLengths,

    #[error("Invalid nonce length for cipher {cipher}: expected {expected}, got {actual}")]
    InvalidNonceLength {
        cipher: &'static str,
        expected: usize,
        actual: usize,
    },

    #[error("TPF3 length field overflow")]
    LengthOverflow,
}

/* -------------------------------------------------------------------------- */
/* Legacy TPF2 header                                                         */
/* -------------------------------------------------------------------------- */

/// The strict, 62-byte binary layout of the Tripple Pulsar Vault legacy header.
///
/// Version support:
/// - v1: legacy vaults
/// - v2: current TPV 2.0 vaults
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
    /// Creates a new TPV 2.0 header using the current legacy format and canonical IDs.
    pub fn new_v2(
        flags: u8,
        kdf_m: u32,
        kdf_t: u16,
        kdf_p: u8,
        tpm_flag: u8,
        os_salt: [u8; 32],
        nonce: [u8; 12],
    ) -> Self {
        Self {
            magic: *MAGIC_BYTES,
            version: CURRENT_VERSION,
            flags,
            alg_id: ALG_ID_AES_256_GCM,
            kdf_id: KDF_ID_ARGON2ID,
            kdf_m,
            kdf_t,
            kdf_p,
            tpm_flag,
            reserved: [0; 2],
            os_salt,
            nonce,
        }
    }

    pub fn uses_v2_key_schedule(&self) -> bool {
        self.version >= CURRENT_VERSION
    }

    pub fn algorithm_name(&self) -> &'static str {
        match self.alg_id {
            0 | ALG_ID_AES_256_GCM => "AES-256-GCM",
            _ => "Unknown",
        }
    }

    pub fn kdf_name(&self) -> &'static str {
        match self.kdf_id {
            0 | KDF_ID_ARGON2ID => "Argon2id",
            _ => "Unknown",
        }
    }

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
        if version != LEGACY_VERSION && version != CURRENT_VERSION {
            return Err(FormatError::UnsupportedVersion(version));
        }

        let alg_id = data[6];
        if alg_id != 0 && alg_id != ALG_ID_AES_256_GCM {
            return Err(FormatError::UnsupportedAlgorithm(alg_id));
        }

        let kdf_id = data[7];
        if kdf_id != 0 && kdf_id != KDF_ID_ARGON2ID {
            return Err(FormatError::UnsupportedKdf(kdf_id));
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
            alg_id,
            kdf_id,
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

/* -------------------------------------------------------------------------- */
/* TPF3 enums                                                                 */
/* -------------------------------------------------------------------------- */

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CipherSuite {
    Aes256Gcm,
    XChaCha20Poly1305,
}

impl CipherSuite {
    pub fn id(self) -> u8 {
        match self {
            Self::Aes256Gcm => TPF3_CIPHER_AES_256_GCM,
            Self::XChaCha20Poly1305 => TPF3_CIPHER_XCHACHA20POLY1305,
        }
    }

    pub fn name(self) -> &'static str {
        match self {
            Self::Aes256Gcm => "AES-256-GCM",
            Self::XChaCha20Poly1305 => "XChaCha20-Poly1305",
        }
    }

    pub fn nonce_len(self) -> usize {
        match self {
            Self::Aes256Gcm => 12,
            Self::XChaCha20Poly1305 => 24,
        }
    }
}

impl TryFrom<u8> for CipherSuite {
    type Error = FormatError;

    fn try_from(value: u8) -> Result<Self, Self::Error> {
        match value {
            TPF3_CIPHER_AES_256_GCM => Ok(Self::Aes256Gcm),
            TPF3_CIPHER_XCHACHA20POLY1305 => Ok(Self::XChaCha20Poly1305),
            other => Err(FormatError::UnsupportedCipherSuite(other)),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Tpf3Kdf {
    Argon2idHkdfSha256,
}

impl Tpf3Kdf {
    pub fn id(self) -> u8 {
        match self {
            Self::Argon2idHkdfSha256 => TPF3_KDF_ARGON2ID_HKDF_SHA256,
        }
    }

    pub fn name(self) -> &'static str {
        match self {
            Self::Argon2idHkdfSha256 => "Argon2id + HKDF-SHA256",
        }
    }
}

impl TryFrom<u8> for Tpf3Kdf {
    type Error = FormatError;

    fn try_from(value: u8) -> Result<Self, Self::Error> {
        match value {
            TPF3_KDF_ARGON2ID_HKDF_SHA256 => Ok(Self::Argon2idHkdfSha256),
            other => Err(FormatError::UnsupportedTpf3Kdf(other)),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum KeyWrapMode {
    None,
    TpmWrapped,
    MlKem768,
}

impl KeyWrapMode {
    pub fn id(self) -> u8 {
        match self {
            Self::None => TPF3_WRAP_NONE,
            Self::TpmWrapped => TPF3_WRAP_TPM,
            Self::MlKem768 => TPF3_WRAP_MLKEM768,
        }
    }

    pub fn name(self) -> &'static str {
        match self {
            Self::None => "None",
            Self::TpmWrapped => "TPM-wrapped key",
            Self::MlKem768 => "ML-KEM-768 wrapped key",
        }
    }
}

impl TryFrom<u8> for KeyWrapMode {
    type Error = FormatError;

    fn try_from(value: u8) -> Result<Self, Self::Error> {
        match value {
            TPF3_WRAP_NONE => Ok(Self::None),
            TPF3_WRAP_TPM => Ok(Self::TpmWrapped),
            TPF3_WRAP_MLKEM768 => Ok(Self::MlKem768),
            other => Err(FormatError::UnsupportedWrapMode(other)),
        }
    }
}

/* -------------------------------------------------------------------------- */
/* TPF3 header                                                                */
/* -------------------------------------------------------------------------- */

#[derive(Debug, Clone)]
pub struct Tpf3Header {
    pub magic: [u8; 4],
    pub version: u8,
    pub flags: u16,
    pub cipher_suite: CipherSuite,
    pub kdf: Tpf3Kdf,
    pub wrap_mode: KeyWrapMode,
    pub kdf_m: u32,
    pub kdf_t: u16,
    pub kdf_p: u8,
    pub os_salt: [u8; 32],
    pub nonce: Vec<u8>,
    pub wrapped_key: Vec<u8>,
    pub kem_ciphertext: Vec<u8>,
    pub tpm_policy: Vec<u8>,
}

impl Tpf3Header {
    pub fn new_v3(
        flags: u16,
        cipher_suite: CipherSuite,
        wrap_mode: KeyWrapMode,
        kdf_m: u32,
        kdf_t: u16,
        kdf_p: u8,
        os_salt: [u8; 32],
        nonce: Vec<u8>,
        wrapped_key: Vec<u8>,
        kem_ciphertext: Vec<u8>,
        tpm_policy: Vec<u8>,
    ) -> Result<Self, FormatError> {
        let header = Self {
            magic: *TPF3_MAGIC_BYTES,
            version: TPF3_VERSION,
            flags,
            cipher_suite,
            kdf: Tpf3Kdf::Argon2idHkdfSha256,
            wrap_mode,
            kdf_m,
            kdf_t,
            kdf_p,
            os_salt,
            nonce,
            wrapped_key,
            kem_ciphertext,
            tpm_policy,
        };

        header.validate()?;
        Ok(header)
    }

    pub fn cipher_name(&self) -> &'static str {
        self.cipher_suite.name()
    }

    pub fn kdf_name(&self) -> &'static str {
        self.kdf.name()
    }

    pub fn wrap_mode_name(&self) -> &'static str {
        self.wrap_mode.name()
    }

    pub fn body_offset(&self) -> usize {
        TPF3_FIXED_HEADER_SIZE
            + self.nonce.len()
            + self.wrapped_key.len()
            + self.kem_ciphertext.len()
            + self.tpm_policy.len()
    }

    pub fn as_bytes(&self) -> Result<Vec<u8>, FormatError> {
        self.validate()?;

        let nonce_len = u8::try_from(self.nonce.len()).map_err(|_| FormatError::LengthOverflow)?;
        let wrapped_key_len =
            u16::try_from(self.wrapped_key.len()).map_err(|_| FormatError::LengthOverflow)?;
        let kem_ct_len =
            u16::try_from(self.kem_ciphertext.len()).map_err(|_| FormatError::LengthOverflow)?;
        let tpm_policy_len =
            u16::try_from(self.tpm_policy.len()).map_err(|_| FormatError::LengthOverflow)?;

        let mut buffer = Vec::with_capacity(self.body_offset());

        buffer.extend_from_slice(&self.magic);
        buffer.push(self.version);
        buffer.extend_from_slice(&self.flags.to_le_bytes());
        buffer.push(self.cipher_suite.id());
        buffer.push(self.kdf.id());
        buffer.push(self.wrap_mode.id());
        buffer.push(nonce_len);
        buffer.extend_from_slice(&wrapped_key_len.to_le_bytes());
        buffer.extend_from_slice(&kem_ct_len.to_le_bytes());
        buffer.extend_from_slice(&tpm_policy_len.to_le_bytes());
        buffer.extend_from_slice(&self.kdf_m.to_le_bytes());
        buffer.extend_from_slice(&self.kdf_t.to_le_bytes());
        buffer.push(self.kdf_p);
        buffer.extend_from_slice(&self.os_salt);
        buffer.extend_from_slice(&self.nonce);
        buffer.extend_from_slice(&self.wrapped_key);
        buffer.extend_from_slice(&self.kem_ciphertext);
        buffer.extend_from_slice(&self.tpm_policy);

        Ok(buffer)
    }

    pub fn from_bytes(data: &[u8]) -> Result<Self, FormatError> {
        if data.len() < TPF3_FIXED_HEADER_SIZE {
            return Err(FormatError::Tpf3HeaderTooShort);
        }

        let mut magic = [0u8; 4];
        magic.copy_from_slice(&data[0..4]);
        if &magic != TPF3_MAGIC_BYTES {
            return Err(FormatError::InvalidMagic);
        }

        let version = data[4];
        if version != TPF3_VERSION {
            return Err(FormatError::UnsupportedVersion(version));
        }

        let mut flags_bytes = [0u8; 2];
        flags_bytes.copy_from_slice(&data[5..7]);

        let cipher_suite = CipherSuite::try_from(data[7])?;
        let kdf = Tpf3Kdf::try_from(data[8])?;
        let wrap_mode = KeyWrapMode::try_from(data[9])?;

        let nonce_len = data[10] as usize;

        let mut wrapped_key_len_bytes = [0u8; 2];
        wrapped_key_len_bytes.copy_from_slice(&data[11..13]);
        let wrapped_key_len = u16::from_le_bytes(wrapped_key_len_bytes) as usize;

        let mut kem_ct_len_bytes = [0u8; 2];
        kem_ct_len_bytes.copy_from_slice(&data[13..15]);
        let kem_ct_len = u16::from_le_bytes(kem_ct_len_bytes) as usize;

        let mut tpm_policy_len_bytes = [0u8; 2];
        tpm_policy_len_bytes.copy_from_slice(&data[15..17]);
        let tpm_policy_len = u16::from_le_bytes(tpm_policy_len_bytes) as usize;

        let mut kdf_m_bytes = [0u8; 4];
        kdf_m_bytes.copy_from_slice(&data[17..21]);

        let mut kdf_t_bytes = [0u8; 2];
        kdf_t_bytes.copy_from_slice(&data[21..23]);

        let kdf_p = data[23];

        let mut os_salt = [0u8; 32];
        os_salt.copy_from_slice(&data[24..56]);

        let total_needed =
            TPF3_FIXED_HEADER_SIZE + nonce_len + wrapped_key_len + kem_ct_len + tpm_policy_len;
        if data.len() < total_needed {
            return Err(FormatError::InvalidTpf3BlobLengths);
        }

        let mut offset = TPF3_FIXED_HEADER_SIZE;

        let nonce = data[offset..offset + nonce_len].to_vec();
        offset += nonce_len;

        let wrapped_key = data[offset..offset + wrapped_key_len].to_vec();
        offset += wrapped_key_len;

        let kem_ciphertext = data[offset..offset + kem_ct_len].to_vec();
        offset += kem_ct_len;

        let tpm_policy = data[offset..offset + tpm_policy_len].to_vec();

        let header = Tpf3Header {
            magic,
            version,
            flags: u16::from_le_bytes(flags_bytes),
            cipher_suite,
            kdf,
            wrap_mode,
            kdf_m: u32::from_le_bytes(kdf_m_bytes),
            kdf_t: u16::from_le_bytes(kdf_t_bytes),
            kdf_p,
            os_salt,
            nonce,
            wrapped_key,
            kem_ciphertext,
            tpm_policy,
        };

        header.validate()?;
        Ok(header)
    }

    fn validate(&self) -> Result<(), FormatError> {
        let expected_nonce_len = self.cipher_suite.nonce_len();
        if self.nonce.len() != expected_nonce_len {
            return Err(FormatError::InvalidNonceLength {
                cipher: self.cipher_suite.name(),
                expected: expected_nonce_len,
                actual: self.nonce.len(),
            });
        }

        match self.wrap_mode {
            KeyWrapMode::None => {
                if !self.kem_ciphertext.is_empty() || !self.tpm_policy.is_empty() {
                    return Err(FormatError::InvalidTpf3BlobLengths);
                }
            }
            KeyWrapMode::TpmWrapped => {
                if self.wrapped_key.is_empty() || !self.kem_ciphertext.is_empty() {
                    return Err(FormatError::InvalidTpf3BlobLengths);
                }
            }
            KeyWrapMode::MlKem768 => {
                if self.wrapped_key.is_empty()
                    || self.kem_ciphertext.is_empty()
                    || !self.tpm_policy.is_empty()
                {
                    return Err(FormatError::InvalidTpf3BlobLengths);
                }
            }
        }

        Ok(())
    }
}

/* -------------------------------------------------------------------------- */
/* Unified parse helper                                                       */
/* -------------------------------------------------------------------------- */

#[derive(Debug, Clone)]
pub enum ParsedVaultHeader {
    Tpf2(Tpf2Header),
    Tpf3(Tpf3Header),
}

pub fn parse_vault_header(data: &[u8]) -> Result<ParsedVaultHeader, FormatError> {
    if data.len() < 4 {
        return Err(FormatError::HeaderTooShort);
    }

    match &data[0..4] {
        b"TPF2" => Ok(ParsedVaultHeader::Tpf2(Tpf2Header::from_bytes(data)?)),
        b"TPF3" => Ok(ParsedVaultHeader::Tpf3(Tpf3Header::from_bytes(data)?)),
        _ => Err(FormatError::InvalidMagic),
    }
}