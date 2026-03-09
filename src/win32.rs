// src/win32.rs

use std::ffi::c_void;
use thiserror::Error;
use windows::Win32::System::DataExchange::{CloseClipboard, EmptyClipboard, OpenClipboard};
use windows::Win32::System::Memory::{VirtualLock, VirtualUnlock};
use windows::Win32::Foundation::HWND;

#[derive(Debug, Error)]
pub enum Win32Error {
    #[error("Failed to lock memory to physical RAM: {0}")]
    MemoryLockFailed(String),
    #[error("Failed to unlock memory: {0}")]
    MemoryUnlockFailed(String),
    #[error("Failed to securely wipe the Windows clipboard")]
    ClipboardWipeFailed,
}

/// Locks a region of memory to prevent Windows from paging it to the swap file (pagefile.sys).
/// This ensures that plaintext passwords or master keys never touch the physical SSD/HDD.
pub fn lock_memory(data: &mut [u8]) -> Result<(), Win32Error> {
    let ptr = data.as_mut_ptr() as *mut c_void;
    let size = data.len();

    unsafe {
        // We use unsafe here because we are interacting directly with the C-style Win32 API.
        // VirtualLock pins the memory block into physical RAM.
        if let Err(e) = VirtualLock(ptr, size) {
            return Err(Win32Error::MemoryLockFailed(e.to_string()));
        }
    }
    Ok(())
}

/// Unlocks a previously locked region of memory so the OS can manage it normally again.
pub fn unlock_memory(data: &mut [u8]) -> Result<(), Win32Error> {
    let ptr = data.as_mut_ptr() as *mut c_void;
    let size = data.len();

    unsafe {
        if let Err(e) = VirtualUnlock(ptr, size) {
            return Err(Win32Error::MemoryUnlockFailed(e.to_string()));
        }
    }
    Ok(())
}

/// Securely empties the Windows clipboard to prevent residual secrets from leaking.
pub fn wipe_clipboard() -> Result<(), Win32Error> {
    unsafe {
        // OpenClipboard with a null handle associates it with the current thread/process
        if OpenClipboard(HWND(std::ptr::null_mut())).is_err() {
            return Err(Win32Error::ClipboardWipeFailed);
        }

        // Empty the clipboard contents
        if EmptyClipboard().is_err() {
            let _ = CloseClipboard(); // Always try to close it even if emptying failed
            return Err(Win32Error::ClipboardWipeFailed);
        }

        // Close the clipboard so other Windows applications can use it again
        if CloseClipboard().is_err() {
            return Err(Win32Error::ClipboardWipeFailed);
        }
    }
    Ok(())
}