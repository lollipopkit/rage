## 0.1.0

- age encryption through the Rust `age` crate 0.11: passphrases (scrypt), X25519 keys, ASCII armor, file-to-file streaming.
- Typed errors (`RageError.kind`): wrong passphrase, no matching keys, excessive work, invalid format, corrupt, invalid key, invalid argument, IO.
