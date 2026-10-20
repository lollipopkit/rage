//! The Rust `age` crate for Dart: `api` is the safe Rust surface (tested in
//! `tests/`), `ffi` the C ABI `lib/src/ffi.dart` binds with `@Native`.

pub mod api;
pub mod ffi;
