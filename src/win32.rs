// src/win32.rs

use std::ffi::c_void;
use std::iter::once;

use thiserror::Error;
use windows::Win32::Foundation::HWND;
use windows::Win32::System::DataExchange::{CloseClipboard, EmptyClipboard, OpenClipboard};
use windows::Win32::System::Memory::{VirtualLock, VirtualUnlock};

const ERROR_SUCCESS: i32 = 0;
const NCRYPT_MACHINE_KEY_FLAG: u32 = 0x0000_0020;

const MS_PLATFORM_CRYPTO_PROVIDER: &str = "Microsoft Platform Crypto Provider";
const NCRYPT_RSA_ALGORITHM: &str = "RSA";

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

fn to_utf16_null(value: &str) -> Vec<u16> {
    value.encode_utf16().chain(once(0)).collect()
}