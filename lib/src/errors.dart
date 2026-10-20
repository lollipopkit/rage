/// Why an operation failed. In the order of the codes `rust/src/ffi.rs` sends
/// (1 is [wrongPassphrase]).
enum RageErrorKind {
  /// The passphrase does not open the file.
  wrongPassphrase,

  /// None of the given identities is a recipient of the file.
  noMatchingKeys,

  /// The file asks for more scrypt work than `maxWorkFactor` allows.
  excessiveWork,

  /// Not an age file, or a header this version does not understand.
  invalidFormat,

  /// The file was modified or cut short.
  corrupt,

  /// A recipient or identity string could not be parsed.
  invalidKey,

  /// An argument outside what is accepted (an empty passphrase, a work factor
  /// out of range, no recipients).
  invalidArgument,

  /// Reading or writing a file failed.
  io,

  /// A bug in rage (a Rust panic). Please report it.
  internal,
}

/// An error from rage.
final class RageError implements Exception {
  const RageError(this.kind, this.message, {this.requiredWorkFactor});

  final RageErrorKind kind;
  final String message;

  /// For [RageErrorKind.excessiveWork]: the work factor the file needs.
  final int? requiredWorkFactor;

  @override
  String toString() => 'RageError(${kind.name}): $message';
}

/// An X25519 key pair in age's text form.
final class X25519KeyPair {
  const X25519KeyPair({required this.identity, required this.recipient});

  /// The secret key, `AGE-SECRET-KEY-1…`. Keep it like a password.
  final String identity;

  /// The public key, `age1…`, what others encrypt to.
  final String recipient;
}
