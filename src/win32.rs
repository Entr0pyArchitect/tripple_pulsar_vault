// src/win32.rs

use std::ffi::c_void;
use std::iter::once;

use thiserror::Error;
use windows::Win32::Foundation::HWND;
use windows::Win32::System::DataExchange::{CloseClipboard, EmptyClipboard, OpenClipboard};
use windows::Win32::System::Memory::{VirtualLock, VirtualUnlock};

const ERROR_SUCCESS: i32 = 0;
const NCRYPT_MACHINE_KEY_FLAG: u32 = 0x0000_0020;
const NCRYPT_PAD_OAEP_FLAG: u32 = 0x0000_0004;

const MS_PLATFORM_CRYPTO_PROVIDER: &str = "Microsoft Platform Crypto Provider";
const NCRYPT_RSA_ALGORITHM: &str = "RSA";
const BCRYPT_SHA256_ALGORITHM: &str = "SHA256";

const TPM_POLICY_MAGIC: &[u8; 4] = b"TPM1";

#[allow(non_snake_case)]
#[repr(C)]
struct BcryptOaepPaddingInfo {
    pszAlgId: *const u16,
    pbLabel: *const u8,
    cbLabel: u32,
}

#[link(name = "Ncrypt")]
unsafe extern "system" {
    fn NCryptOpenStorageProvider(
        phProvider: *mut usize,
        pszProviderName: *const u16,
        dwFlags: u32,
    ) -> i32;

    fn NCryptOpenKey(
        hProvider: usize,
        phKey: *mut usize,
        pszKeyName: *const u16,
        dwLegacyKeySpec: u32,
        dwFlags: u32,
    ) -> i32;

    fn NCryptCreatePersistedKey(
        hProvider: usize,
        phKey: *mut usize,
        pszAlgId: *const u16,
        pszKeyName: *const u16,
        dwLegacyKeySpec: u32,
        dwFlags: u32,
    ) -> i32;

    fn NCryptFinalizeKey(
        hKey: usize,
        dwFlags: u32,
    ) -> i32;

    fn NCryptEncrypt(
        hKey: usize,
        pbInput: *const u8,
        cbInput: u32,
        pPaddingInfo: *const c_void,
        pbOutput: *mut u8,
        cbOutput: u32,
        pcbResult: *mut u32,
        dwFlags: u32,
    ) -> i32;

    fn NCryptDecrypt(
        hKey: usize,
        pbInput: *const u8,
        cbInput: u32,
        pPaddingInfo: *const c_void,
        pbOutput: *mut u8,
        cbOutput: u32,
        pcbResult: *mut u32,
        dwFlags: u32,
    ) -> i32;

    fn NCryptFreeObject(
        hObject: usize,
    ) -> i32;
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TpmKeyScope {
    CurrentUser,
    LocalMachine,
}

impl TpmKeyScope {
    fn flags(self) -> u32 {
        match self {
            Self::CurrentUser => 0,
            Self::LocalMachine => NCRYPT_MACHINE_KEY_FLAG,
        }
    }

    fn id(self) -> u8 {
        match self {
            Self::CurrentUser => 0,
            Self::LocalMachine => 1,
        }
    }

    fn from_id(id: u8) -> Result<Self, Win32Error> {
        match id {
            0 => Ok(Self::CurrentUser),
            1 => Ok(Self::LocalMachine),
            _ => Err(Win32Error::InvalidTpmPolicyEncoding),
        }
    }

    pub fn label(self) -> &'static str {
        match self {
            Self::CurrentUser => "CurrentUser",
            Self::LocalMachine => "LocalMachine",
        }
    }
}

#[derive(Debug, Error)]
pub enum Win32Error {
    #[error("Failed to lock memory region: {0}")]
    MemoryLockFailed(String),

    #[error("Failed to unlock memory region: {0}")]
    MemoryUnlockFailed(String),

    #[error("Failed to clear the Windows clipboard")]
    ClipboardWipeFailed,

    #[error("TPM platform crypto provider is unavailable on this system")]
    TpmProviderUnavailable,

    #[error("NCrypt operation failed with status 0x{0:08X}")]
    NCryptStatus(i32),

    #[error("TPM key alias must not be empty")]
    InvalidTpmKeyAlias,

    #[error("Input is too large for the Windows NCrypt API")]
    InputTooLarge,

    #[error("TPM policy blob is too short")]
    TpmPolicyTooShort,

    #[error("TPM policy blob is malformed or uses an unsupported encoding")]
    InvalidTpmPolicyEncoding,
}

struct ProviderHandle(usize);

impl Drop for ProviderHandle {
    fn drop(&mut self) {
        if self.0 != 0 {
            unsafe {
                let _ = NCryptFreeObject(self.0);
            }
        }
    }
}

struct KeyHandle(usize);

impl Drop for KeyHandle {
    fn drop(&mut self) {
        if self.0 != 0 {
            unsafe {
                let _ = NCryptFreeObject(self.0);
            }
        }
    }
}

/// Best-effort request to lock a memory region into physical RAM.
///
/// Notes:
/// - This is intended to reduce the chance that sensitive buffers are paged out.
/// - It does not guarantee protection against a compromised host, kernel-level
///   access, crash dumps, or all forms of memory disclosure.
pub fn lock_memory(data: &mut [u8]) -> Result<(), Win32Error> {
    if data.is_empty() {
        return Ok(());
    }

    let ptr = data.as_mut_ptr() as *mut c_void;
    let size = data.len();

    unsafe {
        if let Err(e) = VirtualLock(ptr, size) {
            return Err(Win32Error::MemoryLockFailed(e.to_string()));
        }
    }

    Ok(())
}

/// Releases a previously locked memory region.
pub fn unlock_memory(data: &mut [u8]) -> Result<(), Win32Error> {
    if data.is_empty() {
        return Ok(());
    }

    let ptr = data.as_mut_ptr() as *mut c_void;
    let size = data.len();

    unsafe {
        if let Err(e) = VirtualUnlock(ptr, size) {
            return Err(Win32Error::MemoryUnlockFailed(e.to_string()));
        }
    }

    Ok(())
}

/// Clears the Windows clipboard contents.
///
/// This is a best-effort hygiene measure intended to reduce accidental
/// persistence of copied sensitive data.
pub fn wipe_clipboard() -> Result<(), Win32Error> {
    unsafe {
        if OpenClipboard(HWND::default()).is_err() {
            return Err(Win32Error::ClipboardWipeFailed);
        }

        let empty_result = EmptyClipboard();
        let close_result = CloseClipboard();

        if empty_result.is_err() || close_result.is_err() {
            return Err(Win32Error::ClipboardWipeFailed);
        }
    }

    Ok(())
}

/// Returns true if the Microsoft Platform Crypto Provider (TPM KSP) can be opened.
pub fn tpm_provider_available() -> bool {
    open_tpm_provider().is_ok()
}

/// Opens the Microsoft Platform Crypto Provider.
pub fn open_tpm_provider() -> Result<(), Win32Error> {
    let provider_name = to_utf16_null(MS_PLATFORM_CRYPTO_PROVIDER);
    let mut raw_provider = 0usize;

    let status = unsafe {
        NCryptOpenStorageProvider(
            &mut raw_provider as *mut usize,
            provider_name.as_ptr(),
            0,
        )
    };

    if status != ERROR_SUCCESS {
        return Err(Win32Error::TpmProviderUnavailable);
    }

    let _provider = ProviderHandle(raw_provider);
    Ok(())
}

/// Returns true if a persisted TPM-backed key with the given alias already exists.
pub fn tpm_key_exists(alias: &str, scope: TpmKeyScope) -> Result<bool, Win32Error> {
    if alias.trim().is_empty() {
        return Err(Win32Error::InvalidTpmKeyAlias);
    }

    let provider = open_tpm_provider_handle()?;
    let alias_w = to_utf16_null(alias);

    let mut raw_key = 0usize;
    let status = unsafe {
        NCryptOpenKey(
            provider.0,
            &mut raw_key as *mut usize,
            alias_w.as_ptr(),
            0,
            scope.flags(),
        )
    };

    if status == ERROR_SUCCESS {
        let _key = KeyHandle(raw_key);
        Ok(true)
    } else {
        Ok(false)
    }
}

/// Ensures that a persisted TPM-backed RSA key exists under the given alias.
///
/// Behavior:
/// - if the key already exists, this succeeds without changing it
/// - otherwise a new persisted RSA key is created and finalized
///
/// This is the Windows-side provisioning step for later TPM-wrapped vault modes.
pub fn ensure_tpm_rsa_key(alias: &str, scope: TpmKeyScope) -> Result<(), Win32Error> {
    if alias.trim().is_empty() {
        return Err(Win32Error::InvalidTpmKeyAlias);
    }

    if tpm_key_exists(alias, scope)? {
        return Ok(());
    }

    let provider = open_tpm_provider_handle()?;
    let alias_w = to_utf16_null(alias);
    let alg_w = to_utf16_null(NCRYPT_RSA_ALGORITHM);

    let mut raw_key = 0usize;
    let create_status = unsafe {
        NCryptCreatePersistedKey(
            provider.0,
            &mut raw_key as *mut usize,
            alg_w.as_ptr(),
            alias_w.as_ptr(),
            0,
            scope.flags(),
        )
    };

    if create_status != ERROR_SUCCESS {
        return Err(Win32Error::NCryptStatus(create_status));
    }

    let key = KeyHandle(raw_key);

    let finalize_status = unsafe { NCryptFinalizeKey(key.0, 0) };
    if finalize_status != ERROR_SUCCESS {
        return Err(Win32Error::NCryptStatus(finalize_status));
    }

    Ok(())
}

/// Wraps a content key using a persisted TPM-backed RSA key with OAEP-SHA256.
///
/// This is the TPM-side primitive needed for TPF3 `TpmWrapped` content-key mode.
pub fn tpm_wrap_key(
    alias: &str,
    scope: TpmKeyScope,
    content_key: &[u8],
) -> Result<Vec<u8>, Win32Error> {
    if alias.trim().is_empty() {
        return Err(Win32Error::InvalidTpmKeyAlias);
    }

    let input_len = u32::try_from(content_key.len()).map_err(|_| Win32Error::InputTooLarge)?;
    let key = open_tpm_key_handle(alias, scope)?;

    let alg_w = to_utf16_null(BCRYPT_SHA256_ALGORITHM);
    let padding_info = BcryptOaepPaddingInfo {
        pszAlgId: alg_w.as_ptr(),
        pbLabel: std::ptr::null(),
        cbLabel: 0,
    };

    let mut required = 0u32;
    let status = unsafe {
        NCryptEncrypt(
            key.0,
            content_key.as_ptr(),
            input_len,
            &padding_info as *const _ as *const c_void,
            std::ptr::null_mut(),
            0,
            &mut required as *mut u32,
            NCRYPT_PAD_OAEP_FLAG,
        )
    };

    if status != ERROR_SUCCESS {
        return Err(Win32Error::NCryptStatus(status));
    }

    let mut output = vec![0u8; required as usize];
    let status = unsafe {
        NCryptEncrypt(
            key.0,
            content_key.as_ptr(),
            input_len,
            &padding_info as *const _ as *const c_void,
            output.as_mut_ptr(),
            required,
            &mut required as *mut u32,
            NCRYPT_PAD_OAEP_FLAG,
        )
    };

    if status != ERROR_SUCCESS {
        return Err(Win32Error::NCryptStatus(status));
    }

    output.truncate(required as usize);
    Ok(output)
}

/// Unwraps a TPM-wrapped content key using the persisted TPM-backed RSA key.
pub fn tpm_unwrap_key(
    alias: &str,
    scope: TpmKeyScope,
    wrapped_key: &[u8],
) -> Result<Vec<u8>, Win32Error> {
    if alias.trim().is_empty() {
        return Err(Win32Error::InvalidTpmKeyAlias);
    }

    let input_len = u32::try_from(wrapped_key.len()).map_err(|_| Win32Error::InputTooLarge)?;
    let key = open_tpm_key_handle(alias, scope)?;

    let alg_w = to_utf16_null(BCRYPT_SHA256_ALGORITHM);
    let padding_info = BcryptOaepPaddingInfo {
        pszAlgId: alg_w.as_ptr(),
        pbLabel: std::ptr::null(),
        cbLabel: 0,
    };

    let mut required = 0u32;
    let status = unsafe {
        NCryptDecrypt(
            key.0,
            wrapped_key.as_ptr(),
            input_len,
            &padding_info as *const _ as *const c_void,
            std::ptr::null_mut(),
            0,
            &mut required as *mut u32,
            NCRYPT_PAD_OAEP_FLAG,
        )
    };

    if status != ERROR_SUCCESS {
        return Err(Win32Error::NCryptStatus(status));
    }

    let mut output = vec![0u8; required as usize];
    let status = unsafe {
        NCryptDecrypt(
            key.0,
            wrapped_key.as_ptr(),
            input_len,
            &padding_info as *const _ as *const c_void,
            output.as_mut_ptr(),
            required,
            &mut required as *mut u32,
            NCRYPT_PAD_OAEP_FLAG,
        )
    };

    if status != ERROR_SUCCESS {
        return Err(Win32Error::NCryptStatus(status));
    }

    output.truncate(required as usize);
    Ok(output)
}

/// Encodes the TPM policy metadata stored in the TPF3 header.
///
/// Current encoding:
/// - 4 bytes: magic `TPM1`
/// - 1 byte: scope id (0 = CurrentUser, 1 = LocalMachine)
/// - 2 bytes: alias length (u16 LE)
/// - N bytes: alias UTF-8
pub fn encode_tpm_policy(alias: &str, scope: TpmKeyScope) -> Result<Vec<u8>, Win32Error> {
    if alias.trim().is_empty() {
        return Err(Win32Error::InvalidTpmKeyAlias);
    }

    let alias_bytes = alias.as_bytes();
    let alias_len = u16::try_from(alias_bytes.len()).map_err(|_| Win32Error::InputTooLarge)?;

    let mut policy = Vec::with_capacity(4 + 1 + 2 + alias_bytes.len());
    policy.extend_from_slice(TPM_POLICY_MAGIC);
    policy.push(scope.id());
    policy.extend_from_slice(&alias_len.to_le_bytes());
    policy.extend_from_slice(alias_bytes);

    Ok(policy)
}

/// Decodes the TPM policy metadata stored in the TPF3 header.
pub fn decode_tpm_policy(policy: &[u8]) -> Result<(String, TpmKeyScope), Win32Error> {
    if policy.len() < 7 {
        return Err(Win32Error::TpmPolicyTooShort);
    }

    if &policy[0..4] != TPM_POLICY_MAGIC {
        return Err(Win32Error::InvalidTpmPolicyEncoding);
    }

    let scope = TpmKeyScope::from_id(policy[4])?;

    let alias_len = u16::from_le_bytes([policy[5], policy[6]]) as usize;
    let expected = 7usize
        .checked_add(alias_len)
        .ok_or(Win32Error::InvalidTpmPolicyEncoding)?;

    if policy.len() != expected {
        return Err(Win32Error::InvalidTpmPolicyEncoding);
    }

    let alias = std::str::from_utf8(&policy[7..expected])
        .map_err(|_| Win32Error::InvalidTpmPolicyEncoding)?
        .trim()
        .to_string();

    if alias.is_empty() {
        return Err(Win32Error::InvalidTpmKeyAlias);
    }

    Ok((alias, scope))
}

fn open_tpm_provider_handle() -> Result<ProviderHandle, Win32Error> {
    let provider_name = to_utf16_null(MS_PLATFORM_CRYPTO_PROVIDER);
    let mut raw_provider = 0usize;

    let status = unsafe {
        NCryptOpenStorageProvider(
            &mut raw_provider as *mut usize,
            provider_name.as_ptr(),
            0,
        )
    };

    if status != ERROR_SUCCESS {
        return Err(Win32Error::TpmProviderUnavailable);
    }

    Ok(ProviderHandle(raw_provider))
}

fn open_tpm_key_handle(alias: &str, scope: TpmKeyScope) -> Result<KeyHandle, Win32Error> {
    let provider = open_tpm_provider_handle()?;
    let alias_w = to_utf16_null(alias);

    let mut raw_key = 0usize;
    let status = unsafe {
        NCryptOpenKey(
            provider.0,
            &mut raw_key as *mut usize,
            alias_w.as_ptr(),
            0,
            scope.flags(),
        )
    };

    if status != ERROR_SUCCESS {
        return Err(Win32Error::NCryptStatus(status));
    }

    Ok(KeyHandle(raw_key))
}

fn to_utf16_null(value: &str) -> Vec<u16> {
    value.encode_utf16().chain(once(0)).collect()
}
