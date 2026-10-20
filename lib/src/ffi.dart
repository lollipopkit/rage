// The C ABI of `rust/src/ffi.rs`. Bound by asset id: `hook/build.dart` builds
// the library as this file's code asset.
@DefaultAsset('package:rage/src/ffi.dart')
library;

import 'dart:ffi';

final class RageBytes extends Struct {
  external Pointer<Uint8> ptr;
  @Size()
  external int len;
}

final class RageResult extends Struct {
  external RageBytes data;
  @Int32()
  external int errorKind;
  external RageBytes message;
  @Int32()
  external int requiredWorkFactor;
}

@Native<Void Function(RageResult)>(symbol: 'rage_result_free')
external void resultFree(RageResult result);

@Native<RageResult Function(Pointer<Uint8>, Size, Pointer<Uint8>, Size, Int32, Bool)>(
    symbol: 'rage_encrypt_passphrase')
external RageResult encryptPassphrase(Pointer<Uint8> plaintext, int plaintextLen,
    Pointer<Uint8> passphrase, int passphraseLen, int workFactor, bool armor);

@Native<RageResult Function(Pointer<Uint8>, Size, Pointer<Uint8>, Size, Int32)>(
    symbol: 'rage_decrypt_passphrase')
external RageResult decryptPassphrase(Pointer<Uint8> ciphertext, int ciphertextLen,
    Pointer<Uint8> passphrase, int passphraseLen, int maxWorkFactor);

@Native<RageResult Function()>(symbol: 'rage_generate_x25519')
external RageResult generateX25519();

@Native<RageResult Function(Pointer<Uint8>, Size)>(symbol: 'rage_x25519_recipient_of')
external RageResult x25519RecipientOf(Pointer<Uint8> identity, int identityLen);

@Native<RageResult Function(Pointer<Uint8>, Size, Pointer<Uint8>, Size, Bool)>(
    symbol: 'rage_encrypt_recipients')
external RageResult encryptRecipients(Pointer<Uint8> plaintext, int plaintextLen,
    Pointer<Uint8> recipients, int recipientsLen, bool armor);

@Native<RageResult Function(Pointer<Uint8>, Size, Pointer<Uint8>, Size)>(
    symbol: 'rage_decrypt_identities')
external RageResult decryptIdentities(Pointer<Uint8> ciphertext, int ciphertextLen,
    Pointer<Uint8> identities, int identitiesLen);

@Native<
        RageResult Function(
            Pointer<Uint8>, Size, Pointer<Uint8>, Size, Pointer<Uint8>, Size, Int32, Bool)>(
    symbol: 'rage_encrypt_file_passphrase')
external RageResult encryptFilePassphrase(Pointer<Uint8> input, int inputLen, Pointer<Uint8> output,
    int outputLen, Pointer<Uint8> passphrase, int passphraseLen, int workFactor, bool armor);

@Native<RageResult Function(Pointer<Uint8>, Size, Pointer<Uint8>, Size, Pointer<Uint8>, Size, Int32)>(
    symbol: 'rage_decrypt_file_passphrase')
external RageResult decryptFilePassphrase(Pointer<Uint8> input, int inputLen, Pointer<Uint8> output,
    int outputLen, Pointer<Uint8> passphrase, int passphraseLen, int maxWorkFactor);

@Native<RageResult Function(Pointer<Uint8>, Size, Pointer<Uint8>, Size, Pointer<Uint8>, Size, Bool)>(
    symbol: 'rage_encrypt_file_recipients')
external RageResult encryptFileRecipients(Pointer<Uint8> input, int inputLen, Pointer<Uint8> output,
    int outputLen, Pointer<Uint8> recipients, int recipientsLen, bool armor);

@Native<RageResult Function(Pointer<Uint8>, Size, Pointer<Uint8>, Size, Pointer<Uint8>, Size)>(
    symbol: 'rage_decrypt_file_identities')
external RageResult decryptFileIdentities(Pointer<Uint8> input, int inputLen, Pointer<Uint8> output,
    int outputLen, Pointer<Uint8> identities, int identitiesLen);
