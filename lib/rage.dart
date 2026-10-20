/// age file encryption (<https://age-encryption.org/v1>) through the Rust
/// `age` crate from [str4d/rage](https://github.com/str4d/rage).
///
/// Every call is asynchronous and runs off the Dart isolate. Files written
/// here are read by `age`, `rage` and every other age implementation, and the
/// other way round.
library;

import 'dart:typed_data';

import 'package:flutter_rust_bridge/flutter_rust_bridge_for_generated.dart'
    show ExternalLibrary;

import 'src/rust/api.dart' as api;
import 'src/rust/frb_generated.dart';

export 'src/rust/api.dart' show RageError, RageErrorKind, X25519KeyPair;
export 'package:flutter_rust_bridge/flutter_rust_bridge_for_generated.dart'
    show ExternalLibrary;

/// age encryption. Loads the native library on first use.
abstract final class Rage {
  static Future<void>? _init;

  /// The highest scrypt work factor (`log2(N)`) accepted when encrypting.
  /// age decryptors refuse a factor more than four above what takes about a
  /// second on the device reading it.
  static const maxEncryptWorkFactor = 22;

  /// Loads the native library. Called by every method; call it yourself only
  /// to load a [library] of your own (tests load the one cargo built).
  static Future<void> ensureInitialized({ExternalLibrary? library}) =>
      _init ??= RustLib.init(externalLibrary: library);

  /// Encrypts [plaintext] with [passphrase].
  ///
  /// [workFactor] is scrypt's `log2(N)`; null picks what takes about a second
  /// on this device. [armor] writes the text form
  /// (`-----BEGIN AGE ENCRYPTED FILE-----`) instead of binary.
  static Future<Uint8List> encryptWithPassphrase(
    List<int> plaintext,
    String passphrase, {
    int? workFactor,
    bool armor = false,
  }) async {
    await ensureInitialized();
    return api.encryptWithPassphrase(
      plaintext: _bytes(plaintext),
      passphrase: passphrase,
      workFactor: workFactor,
      armor: armor,
    );
  }

  /// Decrypts a passphrase-encrypted file, binary or armored.
  ///
  /// [maxWorkFactor] bounds the scrypt work a file may ask for, so a hostile
  /// file cannot make this take hours; null is age's default (four above what
  /// takes a second here). Throws [RageError].
  static Future<Uint8List> decryptWithPassphrase(
    List<int> ciphertext,
    String passphrase, {
    int? maxWorkFactor,
  }) async {
    await ensureInitialized();
    return api.decryptWithPassphrase(
      ciphertext: _bytes(ciphertext),
      passphrase: passphrase,
      maxWorkFactor: maxWorkFactor,
    );
  }

  /// A new X25519 key pair.
  static Future<api.X25519KeyPair> generateX25519() async {
    await ensureInitialized();
    return api.generateX25519();
  }

  /// The public key (`age1…`) of [identity] (`AGE-SECRET-KEY-1…`).
  static Future<String> recipientOf(String identity) async {
    await ensureInitialized();
    return api.x25519RecipientOf(identity: identity);
  }

  /// Encrypts [plaintext] to [recipients] (`age1…`).
  static Future<Uint8List> encryptToRecipients(
    List<int> plaintext,
    List<String> recipients, {
    bool armor = false,
  }) async {
    await ensureInitialized();
    return api.encryptToRecipients(
      plaintext: _bytes(plaintext),
      recipients: recipients,
      armor: armor,
    );
  }

  /// Decrypts with any of [identities] (`AGE-SECRET-KEY-1…`).
  static Future<Uint8List> decryptWithIdentities(
    List<int> ciphertext,
    List<String> identities,
  ) async {
    await ensureInitialized();
    return api.decryptWithIdentities(
      ciphertext: _bytes(ciphertext),
      identities: identities,
    );
  }

  /// [encryptWithPassphrase] from file to file, streaming. [output] is written
  /// whole or not at all.
  static Future<void> encryptFileWithPassphrase(
    String input,
    String output,
    String passphrase, {
    int? workFactor,
    bool armor = false,
  }) async {
    await ensureInitialized();
    return api.encryptFileWithPassphrase(
      input: input,
      output: output,
      passphrase: passphrase,
      workFactor: workFactor,
      armor: armor,
    );
  }

  /// [decryptWithPassphrase] from file to file, streaming. [output] is
  /// written whole or not at all, and owner-only on Unix.
  static Future<void> decryptFileWithPassphrase(
    String input,
    String output,
    String passphrase, {
    int? maxWorkFactor,
  }) async {
    await ensureInitialized();
    return api.decryptFileWithPassphrase(
      input: input,
      output: output,
      passphrase: passphrase,
      maxWorkFactor: maxWorkFactor,
    );
  }

  /// [encryptToRecipients] from file to file, streaming.
  static Future<void> encryptFileToRecipients(
    String input,
    String output,
    List<String> recipients, {
    bool armor = false,
  }) async {
    await ensureInitialized();
    return api.encryptFileToRecipients(
      input: input,
      output: output,
      recipients: recipients,
      armor: armor,
    );
  }

  /// [decryptWithIdentities] from file to file, streaming. Owner-only on Unix.
  static Future<void> decryptFileWithIdentities(
    String input,
    String output,
    List<String> identities,
  ) async {
    await ensureInitialized();
    return api.decryptFileWithIdentities(
      input: input,
      output: output,
      identities: identities,
    );
  }

  static Uint8List _bytes(List<int> data) =>
      data is Uint8List ? data : Uint8List.fromList(data);
}
