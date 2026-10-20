# rage

[age](https://age-encryption.org) file encryption for Dart and Flutter, through the Rust `age` crate from [str4d/rage](https://github.com/str4d/rage).

Not affiliated with the rage project. This package is Dart bindings to its `age` crate.

- Passphrases (scrypt) and X25519 keys, binary or ASCII armor.
- Interoperable: files written here open with `age`, `rage` and other age implementations, and the other way round. The tests read files written by the Go reference implementation.
- Every call is asynchronous and runs off the Dart isolate.
- File-to-file streaming for large files; the output is written whole or not at all, and a decrypted file is owner-only on Unix.
- Built from source by a Dart build hook (native assets): no podspec, Swift package or Gradle plugin to add. Needs a Rust toolchain (rustup) where the app is built.

## Usage

```dart
import 'package:rage/rage.dart';

final ciphertext = await Rage.encryptWithPassphrase(bytes, passphrase);
final plaintext = await Rage.decryptWithPassphrase(ciphertext, passphrase);

final key = await Rage.generateX25519();
final sealed = await Rage.encryptToRecipients(bytes, [key.recipient]);
final opened = await Rage.decryptWithIdentities(sealed, [key.identity]);

await Rage.encryptFileWithPassphrase('backup.tar', 'backup.tar.age', passphrase);
```

Failures throw `RageError`; `kind` says which (`wrongPassphrase`, `corrupt`, `excessiveWork`, …).

## Passphrases and work factor

age derives the key with scrypt. When encrypting, the work factor (`log2(N)`) defaults to what takes about a second on the encrypting device; `workFactor` sets it (up to 22). When decrypting, age refuses a file that asks more than four above what takes a second on the reading device, so a hostile file cannot make it run for hours; `maxWorkFactor` changes that bound. A file encrypted with a high factor on a fast computer can therefore be refused on a slow phone: pick `workFactor` for the slowest device that has to read it.

## Development

```sh
cargo test --release --manifest-path rust/Cargo.toml
cargo build --release --manifest-path rust/Cargo.toml   # dart test loads rust/target/release
dart test
flutter_rust_bridge_codegen generate                    # after changing rust/src/api (version 2.13.0)
```

`test/fixtures/go_*` are written by `tool/fixtures` (`go run . ../../test/fixtures`) with filippo.io/age.

## License

Apache-2.0.
