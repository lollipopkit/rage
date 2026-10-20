//! The bridge's functions, through the Rust API the Dart side calls.
//! `test/fixtures/go_*` were written by the Go reference implementation
//! (`tool/fixtures`), so reading them checks interoperability, not round trips.

use std::fs;
use std::path::PathBuf;

use rage_ffi::api::*;

const PASS: &str = "correct horse battery staple";

/// A low work factor keeps the suite fast; the default is calibrated per device.
const FAST: Option<u8> = Some(10);

fn fixture(name: &str) -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../test/fixtures").join(name)
}

fn go_plaintext() -> Vec<u8> {
    fs::read(fixture("plaintext.txt")).unwrap()
}

#[test]
fn a_passphrase_round_trip_returns_the_plaintext() {
    for armor in [false, true] {
        let ct = encrypt_with_passphrase(b"hello".to_vec(), PASS.into(), FAST, armor).unwrap();
        assert_eq!(ct.starts_with(b"-----BEGIN AGE ENCRYPTED FILE-----"), armor);
        assert_eq!(decrypt_with_passphrase(ct, PASS.into(), None).unwrap(), b"hello");
    }
}

#[test]
fn an_empty_plaintext_round_trips() {
    let ct = encrypt_with_passphrase(vec![], PASS.into(), FAST, false).unwrap();
    assert!(decrypt_with_passphrase(ct, PASS.into(), None).unwrap().is_empty());
}

#[test]
fn a_wrong_passphrase_is_named() {
    let ct = encrypt_with_passphrase(b"hello".to_vec(), PASS.into(), FAST, false).unwrap();
    let e = decrypt_with_passphrase(ct, "nope".into(), None).unwrap_err();
    assert_eq!(e.kind, RageErrorKind::WrongPassphrase);
}

#[test]
fn a_modified_payload_is_corrupt() {
    let mut ct = encrypt_with_passphrase(vec![7; 1000], PASS.into(), FAST, false).unwrap();
    let last = ct.len() - 1;
    ct[last] ^= 1;
    let e = decrypt_with_passphrase(ct, PASS.into(), None).unwrap_err();
    assert_eq!(e.kind, RageErrorKind::Corrupt);
}

#[test]
fn a_cut_short_file_is_corrupt() {
    let ct = encrypt_with_passphrase(vec![7; 100_000], PASS.into(), FAST, false).unwrap();
    let e = decrypt_with_passphrase(ct[..ct.len() - 20].to_vec(), PASS.into(), None).unwrap_err();
    assert_eq!(e.kind, RageErrorKind::Corrupt);
}

#[test]
fn something_else_is_not_an_age_file() {
    let e = decrypt_with_passphrase(b"LKFL_ENC_V01 not age".to_vec(), PASS.into(), None).unwrap_err();
    assert_eq!(e.kind, RageErrorKind::InvalidFormat);
}

#[test]
fn a_file_asking_too_much_work_is_refused_before_doing_it() {
    let ct = encrypt_with_passphrase(b"hello".to_vec(), PASS.into(), Some(14), false).unwrap();
    let e = decrypt_with_passphrase(ct, PASS.into(), Some(12)).unwrap_err();
    assert_eq!(e.kind, RageErrorKind::ExcessiveWork);
    assert_eq!(e.required_work_factor, Some(14));
}

#[test]
fn bad_arguments_are_refused() {
    for wf in [0, MAX_ENCRYPT_WORK_FACTOR + 1] {
        let e = encrypt_with_passphrase(b"x".to_vec(), PASS.into(), Some(wf), false).unwrap_err();
        assert_eq!(e.kind, RageErrorKind::InvalidArgument);
    }
    let e = encrypt_with_passphrase(b"x".to_vec(), String::new(), FAST, false).unwrap_err();
    assert_eq!(e.kind, RageErrorKind::InvalidArgument);
    let e = encrypt_to_recipients(b"x".to_vec(), vec![], false).unwrap_err();
    assert_eq!(e.kind, RageErrorKind::InvalidArgument);
    let e = encrypt_to_recipients(b"x".to_vec(), vec!["age1nope".into()], false).unwrap_err();
    assert_eq!(e.kind, RageErrorKind::InvalidKey);
}

#[test]
fn x25519_keys_encrypt_and_decrypt() {
    let a = generate_x25519();
    let b = generate_x25519();
    assert!(a.identity.starts_with("AGE-SECRET-KEY-1"));
    assert_eq!(x25519_recipient_of(a.identity.clone()).unwrap(), a.recipient);

    let ct = encrypt_to_recipients(b"hi".to_vec(), vec![a.recipient.clone(), b.recipient.clone()], true).unwrap();
    assert_eq!(decrypt_with_identities(ct.clone(), vec![b.identity.clone()]).unwrap(), b"hi");

    let other = generate_x25519();
    let e = decrypt_with_identities(ct, vec![other.identity]).unwrap_err();
    assert_eq!(e.kind, RageErrorKind::NoMatchingKeys);
}

#[test]
fn files_from_the_go_implementation_are_read() {
    for name in ["go_passphrase.age", "go_passphrase_armor.age"] {
        let ct = fs::read(fixture(name)).unwrap();
        assert_eq!(decrypt_with_passphrase(ct, PASS.into(), None).unwrap(), go_plaintext(), "{name}");
    }
    let key = fs::read_to_string(fixture("go_x25519.key")).unwrap();
    let ct = fs::read(fixture("go_x25519.age")).unwrap();
    assert_eq!(decrypt_with_identities(ct, vec![key]).unwrap(), go_plaintext());
}

#[test]
fn files_stream_and_a_failure_leaves_nothing() {
    let dir = tempfile::tempdir().unwrap();
    let plain = dir.path().join("plain.bin");
    let enc = dir.path().join("plain.bin.age");
    let out = dir.path().join("out.bin");
    let data: Vec<u8> = (0..3_000_000u32).map(|i| (i % 251) as u8).collect();
    fs::write(&plain, &data).unwrap();
    let s = |p: &PathBuf| p.to_string_lossy().into_owned();

    encrypt_file_with_passphrase(s(&plain), s(&enc), PASS.into(), FAST, false).unwrap();
    decrypt_file_with_passphrase(s(&enc), s(&out), PASS.into(), None).unwrap();
    assert_eq!(fs::read(&out).unwrap(), data);
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        assert_eq!(fs::metadata(&out).unwrap().permissions().mode() & 0o777, 0o600);
    }

    // A wrong passphrase keeps the previous output and leaves no staged copy.
    fs::write(&out, b"previous").unwrap();
    let e = decrypt_file_with_passphrase(s(&enc), s(&out), "nope".into(), None).unwrap_err();
    assert_eq!(e.kind, RageErrorKind::WrongPassphrase);
    assert_eq!(fs::read(&out).unwrap(), b"previous");
    let names: Vec<_> = fs::read_dir(dir.path()).unwrap().map(|e| e.unwrap().file_name()).collect();
    assert_eq!(names.len(), 3, "{names:?}");

    let key = generate_x25519();
    encrypt_file_to_recipients(s(&plain), s(&enc), vec![key.recipient], true).unwrap();
    decrypt_file_with_identities(s(&enc), s(&out), vec![key.identity]).unwrap();
    assert_eq!(fs::read(&out).unwrap(), data);

    let e = decrypt_file_with_passphrase(s(&dir.path().join("missing")), s(&out), PASS.into(), None).unwrap_err();
    assert_eq!(e.kind, RageErrorKind::Io);
}
