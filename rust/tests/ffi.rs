//! The C ABI: buffers in and out, error codes, release.

use rage_ffi::ffi::*;

fn take(r: RageResult) -> Result<Vec<u8>, (i32, String, i32)> {
    let out = if r.error_kind == 0 {
        Ok(if r.data.len == 0 { vec![] } else { unsafe { std::slice::from_raw_parts(r.data.ptr, r.data.len) }.to_vec() })
    } else {
        let m = unsafe { std::slice::from_raw_parts(r.message.ptr, r.message.len) };
        Err((r.error_kind, String::from_utf8_lossy(m).into_owned(), r.required_work_factor))
    };
    unsafe { rage_result_free(r) };
    out
}

#[test]
fn a_round_trip_through_the_c_abi() {
    let pass = b"pw";
    let ct = take(unsafe { rage_encrypt_passphrase(b"hi".as_ptr(), 2, pass.as_ptr(), 2, 10, false) }).unwrap();
    let pt = take(unsafe { rage_decrypt_passphrase(ct.as_ptr(), ct.len(), pass.as_ptr(), 2, -1) }).unwrap();
    assert_eq!(pt, b"hi");
}

#[test]
fn errors_cross_as_codes() {
    let ct = take(unsafe { rage_encrypt_passphrase(std::ptr::null(), 0, b"pw".as_ptr(), 2, 14, false) }).unwrap();
    let (kind, _, _) = take(unsafe { rage_decrypt_passphrase(ct.as_ptr(), ct.len(), b"no".as_ptr(), 2, -1) }).unwrap_err();
    assert_eq!(kind, 1);
    let (kind, _, required) = take(unsafe { rage_decrypt_passphrase(ct.as_ptr(), ct.len(), b"pw".as_ptr(), 2, 12) }).unwrap_err();
    assert_eq!((kind, required), (3, 14));
    let (kind, _, _) = take(unsafe { rage_encrypt_passphrase(b"x".as_ptr(), 1, [0xff].as_ptr(), 1, 10, false) }).unwrap_err();
    assert_eq!(kind, 7, "a passphrase that is not UTF-8 is an invalid argument");
}

#[test]
fn keys_cross_one_per_line() {
    let pair = String::from_utf8(take(rage_generate_x25519()).unwrap()).unwrap();
    let (identity, recipient) = pair.split_once('\n').unwrap();
    let rs = format!("{recipient}\n");
    let ct = take(unsafe { rage_encrypt_recipients(b"k".as_ptr(), 1, rs.as_ptr(), rs.len(), false) }).unwrap();
    let pt = take(unsafe { rage_decrypt_identities(ct.as_ptr(), ct.len(), identity.as_ptr(), identity.len()) }).unwrap();
    assert_eq!(pt, b"k");
}
