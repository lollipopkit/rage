/// age file encryption (<https://age-encryption.org/v1>) through the Rust
/// `age` crate from [str4d/rage](https://github.com/str4d/rage).
///
/// Every call is asynchronous: the work runs in a short-lived isolate, never
/// on the caller's. Files written here are read by `age`, `rage` and every
/// other age implementation, and the other way round.
library;

import 'dart:convert';
import 'dart:ffi';
import 'dart:isolate';
import 'dart:typed_data';

import 'package:ffi/ffi.dart';

import 'src/errors.dart';
import 'src/ffi.dart' as ffi;

export 'src/errors.dart';

/// age encryption.
abstract final class Rage {
  /// The highest scrypt work factor (`log2(N)`) accepted when encrypting.
  /// age decryptors refuse a factor more than four above what takes about a
  /// second on the device reading it.
  static const maxEncryptWorkFactor = 22;

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
  }) {
    final data = _bytes(plaintext);
    return Isolate.run(() => _run((a) {
          final (p, pl) = _in(a, data);
          final (s, sl) = _text(a, passphrase);
          return ffi.encryptPassphrase(p, pl, s, sl, workFactor ?? -1, armor);
        }));
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
  }) {
    final data = _bytes(ciphertext);
    return Isolate.run(() => _run((a) {
          final (c, cl) = _in(a, data);
          final (s, sl) = _text(a, passphrase);
          return ffi.decryptPassphrase(c, cl, s, sl, maxWorkFactor ?? -1);
        }));
  }

  /// A new X25519 key pair.
  static Future<X25519KeyPair> generateX25519() async {
    final out = utf8.decode(await Isolate.run(() => _run((_) => ffi.generateX25519())));
    final [identity, recipient] = out.split('\n');
    return X25519KeyPair(identity: identity, recipient: recipient);
  }

  /// The public key (`age1…`) of [identity] (`AGE-SECRET-KEY-1…`).
  static Future<String> recipientOf(String identity) async => utf8.decode(
        await Isolate.run(() => _run((a) {
              final (i, il) = _text(a, identity);
              return ffi.x25519RecipientOf(i, il);
            })),
      );

  /// Encrypts [plaintext] to [recipients] (`age1…`).
  static Future<Uint8List> encryptToRecipients(
    List<int> plaintext,
    List<String> recipients, {
    bool armor = false,
  }) async {
    final data = _bytes(plaintext);
    final keys = _keys(recipients);
    return Isolate.run(() => _run((a) {
          final (p, pl) = _in(a, data);
          final (k, kl) = _text(a, keys);
          return ffi.encryptRecipients(p, pl, k, kl, armor);
        }));
  }

  /// Decrypts with any of [identities] (`AGE-SECRET-KEY-1…`).
  static Future<Uint8List> decryptWithIdentities(
    List<int> ciphertext,
    List<String> identities,
  ) async {
    final data = _bytes(ciphertext);
    final keys = _keys(identities);
    return Isolate.run(() => _run((a) {
          final (c, cl) = _in(a, data);
          final (k, kl) = _text(a, keys);
          return ffi.decryptIdentities(c, cl, k, kl);
        }));
  }

  /// [encryptWithPassphrase] from file to file, streaming. [output] is written
  /// whole or not at all.
  static Future<void> encryptFileWithPassphrase(
    String input,
    String output,
    String passphrase, {
    int? workFactor,
    bool armor = false,
  }) =>
      Isolate.run(() => _run((a) {
            final (i, il) = _text(a, input);
            final (o, ol) = _text(a, output);
            final (s, sl) = _text(a, passphrase);
            return ffi.encryptFilePassphrase(i, il, o, ol, s, sl, workFactor ?? -1, armor);
          }));

  /// [decryptWithPassphrase] from file to file, streaming. [output] is
  /// written whole or not at all, and owner-only on Unix.
  static Future<void> decryptFileWithPassphrase(
    String input,
    String output,
    String passphrase, {
    int? maxWorkFactor,
  }) =>
      Isolate.run(() => _run((a) {
            final (i, il) = _text(a, input);
            final (o, ol) = _text(a, output);
            final (s, sl) = _text(a, passphrase);
            return ffi.decryptFilePassphrase(i, il, o, ol, s, sl, maxWorkFactor ?? -1);
          }));

  /// [encryptToRecipients] from file to file, streaming.
  static Future<void> encryptFileToRecipients(
    String input,
    String output,
    List<String> recipients, {
    bool armor = false,
  }) async {
    final keys = _keys(recipients);
    return Isolate.run(() => _run((a) {
          final (i, il) = _text(a, input);
          final (o, ol) = _text(a, output);
          final (k, kl) = _text(a, keys);
          return ffi.encryptFileRecipients(i, il, o, ol, k, kl, armor);
        }));
  }

  /// [decryptWithIdentities] from file to file, streaming. Owner-only on Unix.
  static Future<void> decryptFileWithIdentities(
    String input,
    String output,
    List<String> identities,
  ) async {
    final keys = _keys(identities);
    return Isolate.run(() => _run((a) {
          final (i, il) = _text(a, input);
          final (o, ol) = _text(a, output);
          final (k, kl) = _text(a, keys);
          return ffi.decryptFileIdentities(i, il, o, ol, k, kl);
        }));
  }

  static Uint8List _bytes(List<int> data) => data is Uint8List ? data : Uint8List.fromList(data);

  /// Keys cross the boundary one per line. Surrounding whitespace is dropped
  /// (a key read from a file ends with a line break); a line break inside a
  /// key is refused rather than split into two keys.
  static String _keys(List<String> keys) {
    final trimmed = [for (final k in keys) k.trim()];
    if (trimmed.any((k) => k.contains('\n') || k.contains('\r'))) {
      throw const RageError(RageErrorKind.invalidKey, 'a key contains a line break');
    }
    return trimmed.join('\n');
  }

  static (Pointer<Uint8>, int) _in(Arena a, Uint8List data) {
    if (data.isEmpty) return (nullptr, 0);
    final p = a<Uint8>(data.length);
    p.asTypedList(data.length).setAll(0, data);
    return (p, data.length);
  }

  static (Pointer<Uint8>, int) _text(Arena a, String s) => _in(a, utf8.encode(s));

  /// Calls into Rust with an arena for the inputs, copies the answer out,
  /// releases Rust's buffers, and throws its error.
  static Uint8List _run(ffi.RageResult Function(Arena) call) => using((a) {
        final result = call(a);
        try {
          if (result.errorKind != 0) {
            final message = result.message.len == 0
                ? ''
                : utf8.decode(result.message.ptr.asTypedList(result.message.len), allowMalformed: true);
            throw RageError(
              RageErrorKind.values[result.errorKind - 1],
              message,
              requiredWorkFactor: result.requiredWorkFactor < 0 ? null : result.requiredWorkFactor,
            );
          }
          return result.data.len == 0
              ? Uint8List(0)
              : Uint8List.fromList(result.data.ptr.asTypedList(result.data.len));
        } finally {
          ffi.resultFree(result);
        }
      });
}
