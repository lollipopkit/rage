## 0.1.1

- Reproducible builds: the library no longer records the Cargo home or package path, nor the unpack time of the files `age` embeds.

## 0.1.0

- age encryption through the Rust `age` crate 0.11: passphrases (scrypt), X25519 keys, ASCII armor, file-to-file streaming.
- Plain C ABI and `dart:ffi` (native assets through `native_toolchain_rust`); calls run in a short-lived isolate.
- Typed errors (`RageError.kind`): wrong passphrase, no matching keys, excessive work, invalid format, corrupt, invalid key, invalid argument, IO, internal.
