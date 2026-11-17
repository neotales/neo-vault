//! Conservative C ABI for embedding `nsvault`.
//!
//! Every function catches panics at the boundary and reports a redacted error.
//! See `include/nsvault.h` for ownership rules. In short:
//!
//! * `nsvault_client_open` returns an owned opaque pointer; close it exactly
//!   once with `nsvault_client_close`.
//! * Every `NsvaultBytes` returned by an output parameter is owned by the
//!   caller and must be released with `nsvault_bytes_free` exactly once.
//! * Secret byte buffers are zeroed before they are freed.
//! * Strings are NUL-terminated UTF-8. Optional strings may be null.
//! * Errors are retrieved with `nsvault_last_error`; the message is redacted
//!   and is valid on the calling thread until the next FFI call.

use std::cell::RefCell;
use std::ffi::{CStr, c_char, c_int};
use std::panic::{AssertUnwindSafe, catch_unwind};
use std::path::Path;
use std::ptr;
use std::slice;

use zeroize::Zeroize;

use crate::api::Client;
use crate::error::{Error, Result};
use crate::secret::Secret;

/// Opaque client handle.
#[repr(C)]
#[derive(Debug)]
pub struct NsvaultClient {
    client: Client,
}

/// Owned byte buffer returned to C.
#[repr(C)]
pub struct NsvaultBytes {
    /// Pointer to `len` initialized bytes. Null when `len == 0`.
    pub data: *mut u8,
    /// Number of bytes.
    pub len: usize,
    /// Allocation capacity, used by `nsvault_bytes_free`.
    pub capacity: usize,
}

impl std::fmt::Debug for NsvaultBytes {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("NsvaultBytes")
            .field("len", &self.len)
            .field("capacity", &self.capacity)
            .finish_non_exhaustive()
    }
}

impl Default for NsvaultBytes {
    fn default() -> Self {
        Self {
            data: ptr::null_mut(),
            len: 0,
            capacity: 0,
        }
    }
}

thread_local! {
    static LAST_ERROR: RefCell<Option<String>> = const { RefCell::new(None) };
}

fn set_error(message: impl Into<String>) {
    LAST_ERROR.with(|slot| {
        *slot.borrow_mut() = Some(message.into());
    });
}

fn guard(f: impl FnOnce() -> Result<()>) -> c_int {
    match catch_unwind(AssertUnwindSafe(f)) {
        Ok(Ok(())) => 0,
        Ok(Err(error)) => {
            set_error(error.message());
            1
        }
        Err(_) => {
            set_error("internal error");
            1
        }
    }
}

unsafe fn optional_string(pointer: *const c_char, field: &str) -> Result<Option<String>> {
    if pointer.is_null() {
        return Ok(None);
    }
    // SAFETY: the caller contract requires a NUL-terminated UTF-8 string.
    let value = unsafe { CStr::from_ptr(pointer) }
        .to_str()
        .map_err(|_| Error::new(format!("{field} is not valid UTF-8")))?;
    Ok(Some(value.to_owned()))
}

unsafe fn required_string(pointer: *const c_char, field: &str) -> Result<String> {
    unsafe { optional_string(pointer, field) }?
        .ok_or_else(|| Error::new(format!("{field} must not be null")))
}

unsafe fn write_output(output: *mut NsvaultBytes, bytes: Vec<u8>) {
    if output.is_null() {
        return;
    }
    // SAFETY: the caller passed an output pointer it owns.
    unsafe { output.write(into_bytes(bytes)) };
}

fn into_bytes(bytes: Vec<u8>) -> NsvaultBytes {
    if bytes.is_empty() {
        return NsvaultBytes::default();
    }
    let mut bytes = bytes;
    bytes.shrink_to_fit();
    let mut bytes = std::mem::ManuallyDrop::new(bytes);
    NsvaultBytes {
        data: bytes.as_mut_ptr(),
        len: bytes.len(),
        capacity: bytes.capacity(),
    }
}

/// Opens a configuration file.
///
/// # Safety
///
/// `path` must point at a NUL-terminated UTF-8 string. `out` must be writable
/// and must not alias `path`.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn nsvault_client_open(
    path: *const c_char,
    out: *mut *mut NsvaultClient,
) -> c_int {
    if out.is_null() {
        set_error("output pointer must not be null");
        return 1;
    }
    // SAFETY: the caller supplied a writable output pointer.
    unsafe { *out = ptr::null_mut() };
    guard(|| {
        // SAFETY: the caller contract requires a valid NUL-terminated path.
        let path = unsafe { required_string(path, "config path") }?;
        let client = Client::open(Path::new(&path))?;
        let handle = Box::into_raw(Box::new(NsvaultClient { client }));
        // SAFETY: checked above and written exactly once.
        unsafe { *out = handle };
        Ok(())
    })
}

/// Closes a client. A null pointer is a no-op.
///
/// # Safety
///
/// `client` must be a pointer returned by `nsvault_client_open` that has not
/// already been closed.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn nsvault_client_close(client: *mut NsvaultClient) {
    if client.is_null() {
        return;
    }
    // SAFETY: the caller owns the pointer and closes it once.
    unsafe { drop(Box::from_raw(client)) };
}

/// Lists key names, separated by `\n`, under a prefix.
///
/// # Safety
///
/// `client` must be a live handle. `provider` may be null. `prefix` may be
/// null for the configured default. `out` must be writable.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn nsvault_list(
    client: *const NsvaultClient,
    provider: *const c_char,
    prefix: *const c_char,
    out: *mut NsvaultBytes,
) -> c_int {
    guard(|| {
        if client.is_null() {
            return Err(Error::new("client must not be null"));
        }
        if out.is_null() {
            return Err(Error::new("output pointer must not be null"));
        }
        // SAFETY: the caller contract requires valid optional strings.
        let provider = unsafe { optional_string(provider, "provider") }?;
        let prefix = unsafe { optional_string(prefix, "prefix") }?;
        // SAFETY: checked non-null above.
        let client = unsafe { &*client };
        let prefix = prefix.unwrap_or_else(|| client.client.default_prefix(None));
        let keys = client.client.list(provider.as_deref(), &prefix)?;
        let mut output = String::new();
        for key in keys {
            if key.key.contains('\n') {
                return Err(Error::new("a provider returned a key containing a newline"));
            }
            output.push_str(&key.key);
            output.push('\n');
        }
        // SAFETY: output is writable per the caller contract.
        unsafe { write_output(out, output.into_bytes()) };
        Ok(())
    })
}

/// Reads one secret. The returned bytes are the exact value.
///
/// # Safety
///
/// `client` must be a live handle. `provider` may be null. `key` must be a
/// NUL-terminated UTF-8 string. `out` must be writable.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn nsvault_get(
    client: *const NsvaultClient,
    provider: *const c_char,
    key: *const c_char,
    out: *mut NsvaultBytes,
) -> c_int {
    guard(|| {
        if client.is_null() {
            return Err(Error::new("client must not be null"));
        }
        if out.is_null() {
            return Err(Error::new("output pointer must not be null"));
        }
        // SAFETY: the caller contract requires valid optional strings.
        let provider = unsafe { optional_string(provider, "provider") }?;
        let key = unsafe { required_string(key, "key") }?;
        // SAFETY: checked non-null above.
        let client = unsafe { &*client };
        let value = client.client.get(provider.as_deref(), &key)?;
        // SAFETY: output is writable per the caller contract.
        unsafe { write_output(out, value.expose().to_vec()) };
        Ok(())
    })
}

/// Writes one secret from a byte slice.
///
/// # Safety
///
/// `client` must be a live handle. `provider` may be null. `key` must be a
/// NUL-terminated UTF-8 string. If `len` is non-zero, `value` must point at
/// `len` readable bytes. The bytes must not overlap `client` or `out`.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn nsvault_set(
    client: *const NsvaultClient,
    provider: *const c_char,
    key: *const c_char,
    value: *const u8,
    len: usize,
) -> c_int {
    guard(|| {
        if client.is_null() {
            return Err(Error::new("client must not be null"));
        }
        if len == 0 || value.is_null() {
            return Err(Error::new("refusing to store an empty secret"));
        }
        if len > 8 * 1024 * 1024 {
            return Err(Error::new("secret value exceeds the 8 MiB limit"));
        }
        // SAFETY: the caller contract requires valid optional strings.
        let provider = unsafe { optional_string(provider, "provider") }?;
        let key = unsafe { required_string(key, "key") }?;
        // SAFETY: the caller contract guarantees `len` readable bytes.
        let bytes = unsafe { slice::from_raw_parts(value, len) };
        let secret = Secret::new(bytes.to_vec());
        if secret.expose().contains(&0) {
            return Err(Error::new("secret value must not contain NUL"));
        }
        // SAFETY: checked non-null above.
        let client = unsafe { &*client };
        client.client.set(provider.as_deref(), &key, &secret)
    })
}

/// Copies the last error message for the calling thread into `out`.
///
/// Returns `1` when a message was copied and `0` when there is none.
///
/// # Safety
///
/// `out` must be writable.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn nsvault_last_error(out: *mut NsvaultBytes) -> c_int {
    if out.is_null() {
        return 0;
    }
    let message = LAST_ERROR.with(|slot| slot.borrow_mut().take());
    match message {
        Some(message) => {
            // SAFETY: output is writable per the caller contract.
            unsafe { write_output(out, message.into_bytes()) };
            1
        }
        None => {
            // SAFETY: output is writable per the caller contract.
            unsafe { write_output(out, Vec::new()) };
            0
        }
    }
}

/// Releases a byte buffer and zeroes its allocation.
///
/// # Safety
///
/// `bytes` must be a value returned through an output parameter by this
/// library and must not be freed more than once.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn nsvault_bytes_free(bytes: NsvaultBytes) {
    if bytes.data.is_null() || bytes.capacity == 0 {
        return;
    }
    // SAFETY: the buffer came from `into_bytes` and is freed exactly once.
    let mut owned = unsafe { Vec::from_raw_parts(bytes.data, bytes.len, bytes.capacity) };
    owned.zeroize();
    drop(owned);
}
