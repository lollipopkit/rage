//! The C ABI `lib/src/ffi.dart` binds.
//!
//! Inputs are borrowed `(pointer, length)` pairs the caller frees; every
//! function returns a [`RageResult`] whose buffers Rust allocated and
//! [`rage_result_free`] releases. A panic never crosses the boundary: it
//! becomes [`RageErrorKind::Internal`].

use std::panic::{self, AssertUnwindSafe};
use std::{ptr, slice};

use crate::api::{self, RageError, RageErrorKind};

/// Bytes Rust allocated: release with [`rage_result_free`].
#[repr(C)]
pub struct RageBytes {
    pub ptr: *mut u8,
    pub len: usize,
}

impl RageBytes {
    const EMPTY: Self = Self { ptr: ptr::null_mut(), len: 0 };

    fn from_vec(v: Vec<u8>) -> Self {
        if v.is_empty() {
            return Self::EMPTY;
        }
        let boxed = v.into_boxed_slice();
        let len = boxed.len();
        Self { ptr: Box::into_raw(boxed).cast(), len }
    }

    /// # Safety
    /// `self` came from [`Self::from_vec`] and is released once.
    unsafe fn free(self) {
        if !self.ptr.is_null() {
            drop(unsafe { Box::from_raw(ptr::slice_from_raw_parts_mut(self.ptr, self.len)) });
        }
    }
}

/// What every function answers. `error_kind` is 0 on success, else the
/// [`RageErrorKind`] code; `required_work_factor` is -1 unless the kind is
/// `ExcessiveWork`.
#[repr(C)]
pub struct RageResult {
    pub data: RageBytes,
    pub error_kind: i32,
    pub message: RageBytes,
    pub required_work_factor: i32,
}

/// The code a [`RageErrorKind`] crosses the boundary as; `RageErrorKind` in
/// `lib/src/errors.dart` lists them in this order.
fn code(kind: RageErrorKind) -> i32 {
    match kind {
        RageErrorKind::WrongPassphrase => 1,
        RageErrorKind::NoMatchingKeys => 2,
        RageErrorKind::ExcessiveWork => 3,
        RageErrorKind::InvalidFormat => 4,
        RageErrorKind::Corrupt => 5,
        RageErrorKind::InvalidKey => 6,
        RageErrorKind::InvalidArgument => 7,
        RageErrorKind::Io => 8,
        RageErrorKind::Internal => 9,
    }
}

fn answer(run: impl FnOnce() -> Result<Vec<u8>, RageError>) -> RageResult {
    let result = panic::catch_unwind(AssertUnwindSafe(run)).unwrap_or_else(|p| {
        let message = p
            .downcast_ref::<&str>()
            .map(|s| s.to_string())
            .or_else(|| p.downcast_ref::<String>().cloned())
            .unwrap_or_else(|| "panic".into());
        Err(RageError::new(RageErrorKind::Internal, message))
    });
    match result {
        Ok(data) => RageResult {
            data: RageBytes::from_vec(data),
            error_kind: 0,
            message: RageBytes::EMPTY,
            required_work_factor: -1,
        },
        Err(e) => RageResult {
            data: RageBytes::EMPTY,
            error_kind: code(e.kind),
            message: RageBytes::from_vec(e.message.into_bytes()),
            required_work_factor: e.required_work_factor.map_or(-1, i32::from),
        },
    }
}

/// # Safety
/// `ptr` is null with `len == 0`, or valid for `len` bytes for the call.
unsafe fn bytes<'a>(ptr: *const u8, len: usize) -> &'a [u8] {
    if ptr.is_null() || len == 0 { &[] } else { unsafe { slice::from_raw_parts(ptr, len) } }
}

/// # Safety
/// As [`bytes`].
unsafe fn text(ptr: *const u8, len: usize) -> Result<String, RageError> {
    String::from_utf8(unsafe { bytes(ptr, len) }.to_vec())
        .map_err(|_| RageError::new(RageErrorKind::InvalidArgument, "text is not UTF-8"))
}

/// Keys cross as one string, one per line.
///
/// # Safety
/// As [`bytes`].
unsafe fn lines(ptr: *const u8, len: usize) -> Result<Vec<String>, RageError> {
    Ok(unsafe { text(ptr, len) }?
        .lines()
        .map(str::trim)
        .filter(|l| !l.is_empty())
        .map(String::from)
        .collect())
}

fn work_factor(value: i32) -> Result<Option<u8>, RageError> {
    if value < 0 {
        return Ok(None);
    }
    u8::try_from(value)
        .map(Some)
        .map_err(|_| RageError::new(RageErrorKind::InvalidArgument, format!("work factor {value}")))
}

/// Releases what a function answered. Each result is released once.
///
/// # Safety
/// `result` is a [`RageResult`] one of these functions returned.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn rage_result_free(result: RageResult) {
    unsafe {
        result.data.free();
        result.message.free();
    }
}

/// `work_factor` < 0 picks the default.
///
/// # Safety
/// Every `(ptr, len)` pair is valid for the call.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn rage_encrypt_passphrase(
    plaintext: *const u8,
    plaintext_len: usize,
    passphrase: *const u8,
    passphrase_len: usize,
    work_factor_log2: i32,
    armor: bool,
) -> RageResult {
    answer(|| unsafe {
        api::encrypt_with_passphrase(
            bytes(plaintext, plaintext_len).to_vec(),
            text(passphrase, passphrase_len)?,
            work_factor(work_factor_log2)?,
            armor,
        )
    })
}

/// `max_work_factor` < 0 keeps age's bound.
///
/// # Safety
/// Every `(ptr, len)` pair is valid for the call.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn rage_decrypt_passphrase(
    ciphertext: *const u8,
    ciphertext_len: usize,
    passphrase: *const u8,
    passphrase_len: usize,
    max_work_factor: i32,
) -> RageResult {
    answer(|| unsafe {
        api::decrypt_with_passphrase(
            bytes(ciphertext, ciphertext_len).to_vec(),
            text(passphrase, passphrase_len)?,
            work_factor(max_work_factor)?,
        )
    })
}

/// Answers `identity\nrecipient`.
#[unsafe(no_mangle)]
pub extern "C" fn rage_generate_x25519() -> RageResult {
    answer(|| {
        let pair = api::generate_x25519();
        Ok(format!("{}\n{}", pair.identity, pair.recipient).into_bytes())
    })
}

/// # Safety
/// The `(ptr, len)` pair is valid for the call.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn rage_x25519_recipient_of(identity: *const u8, identity_len: usize) -> RageResult {
    answer(|| unsafe { api::x25519_recipient_of(text(identity, identity_len)?).map(String::into_bytes) })
}

/// `recipients`: one `age1…` per line.
///
/// # Safety
/// Every `(ptr, len)` pair is valid for the call.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn rage_encrypt_recipients(
    plaintext: *const u8,
    plaintext_len: usize,
    recipients: *const u8,
    recipients_len: usize,
    armor: bool,
) -> RageResult {
    answer(|| unsafe {
        api::encrypt_to_recipients(
            bytes(plaintext, plaintext_len).to_vec(),
            lines(recipients, recipients_len)?,
            armor,
        )
    })
}

/// `identities`: one `AGE-SECRET-KEY-1…` per line.
///
/// # Safety
/// Every `(ptr, len)` pair is valid for the call.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn rage_decrypt_identities(
    ciphertext: *const u8,
    ciphertext_len: usize,
    identities: *const u8,
    identities_len: usize,
) -> RageResult {
    answer(|| unsafe {
        api::decrypt_with_identities(bytes(ciphertext, ciphertext_len).to_vec(), lines(identities, identities_len)?)
    })
}

/// # Safety
/// Every `(ptr, len)` pair is valid for the call.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn rage_encrypt_file_passphrase(
    input: *const u8,
    input_len: usize,
    output: *const u8,
    output_len: usize,
    passphrase: *const u8,
    passphrase_len: usize,
    work_factor_log2: i32,
    armor: bool,
) -> RageResult {
    answer(|| unsafe {
        api::encrypt_file_with_passphrase(
            text(input, input_len)?,
            text(output, output_len)?,
            text(passphrase, passphrase_len)?,
            work_factor(work_factor_log2)?,
            armor,
        )
        .map(|()| Vec::new())
    })
}

/// # Safety
/// Every `(ptr, len)` pair is valid for the call.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn rage_decrypt_file_passphrase(
    input: *const u8,
    input_len: usize,
    output: *const u8,
    output_len: usize,
    passphrase: *const u8,
    passphrase_len: usize,
    max_work_factor: i32,
) -> RageResult {
    answer(|| unsafe {
        api::decrypt_file_with_passphrase(
            text(input, input_len)?,
            text(output, output_len)?,
            text(passphrase, passphrase_len)?,
            work_factor(max_work_factor)?,
        )
        .map(|()| Vec::new())
    })
}

/// # Safety
/// Every `(ptr, len)` pair is valid for the call.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn rage_encrypt_file_recipients(
    input: *const u8,
    input_len: usize,
    output: *const u8,
    output_len: usize,
    recipients: *const u8,
    recipients_len: usize,
    armor: bool,
) -> RageResult {
    answer(|| unsafe {
        api::encrypt_file_to_recipients(
            text(input, input_len)?,
            text(output, output_len)?,
            lines(recipients, recipients_len)?,
            armor,
        )
        .map(|()| Vec::new())
    })
}

/// # Safety
/// Every `(ptr, len)` pair is valid for the call.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn rage_decrypt_file_identities(
    input: *const u8,
    input_len: usize,
    output: *const u8,
    output_len: usize,
    identities: *const u8,
    identities_len: usize,
) -> RageResult {
    answer(|| unsafe {
        api::decrypt_file_with_identities(
            text(input, input_len)?,
            text(output, output_len)?,
            lines(identities, identities_len)?,
        )
        .map(|()| Vec::new())
    })
}
