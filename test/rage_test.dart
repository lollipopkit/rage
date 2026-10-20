// Loads the library cargo built (`cargo build --release --manifest-path
// rust/Cargo.toml`), the bridge's default `rust/target/release/`.
import 'dart:convert';
import 'dart:io';

import 'package:rage/rage.dart';
import 'package:test/test.dart';

const pass = 'correct horse battery staple';
const fast = 10;

void main() {
  setUpAll(Rage.ensureInitialized);

  test('a passphrase round trip returns the plaintext, binary and armored', () async {
    for (final armor in [false, true]) {
      final ct = await Rage.encryptWithPassphrase(utf8.encode('hello'), pass, workFactor: fast, armor: armor);
      expect(latin1.decode(ct).startsWith('-----BEGIN AGE ENCRYPTED FILE-----'), armor);
      expect(utf8.decode(await Rage.decryptWithPassphrase(ct, pass)), 'hello');
    }
  });

  test('a wrong passphrase throws WrongPassphrase', () async {
    final ct = await Rage.encryptWithPassphrase([1, 2, 3], pass, workFactor: fast);
    await expectLater(
      Rage.decryptWithPassphrase(ct, 'nope'),
      throwsA(isA<RageError>().having((e) => e.kind, 'kind', RageErrorKind.wrongPassphrase)),
    );
  });

  test('a modified file throws Corrupt', () async {
    final ct = await Rage.encryptWithPassphrase(List.filled(1000, 7), pass, workFactor: fast);
    ct[ct.length - 1] ^= 1;
    await expectLater(
      Rage.decryptWithPassphrase(ct, pass),
      throwsA(isA<RageError>().having((e) => e.kind, 'kind', RageErrorKind.corrupt)),
    );
  });

  test('too much work is refused and says how much', () async {
    final ct = await Rage.encryptWithPassphrase([1], pass, workFactor: 14);
    await expectLater(
      Rage.decryptWithPassphrase(ct, pass, maxWorkFactor: 12),
      throwsA(isA<RageError>()
          .having((e) => e.kind, 'kind', RageErrorKind.excessiveWork)
          .having((e) => e.requiredWorkFactor, 'required', 14)),
    );
  });

  test('X25519 keys encrypt and decrypt', () async {
    final key = await Rage.generateX25519();
    expect(await Rage.recipientOf(key.identity), key.recipient);
    final ct = await Rage.encryptToRecipients(utf8.encode('hi'), [key.recipient], armor: true);
    expect(utf8.decode(await Rage.decryptWithIdentities(ct, [key.identity])), 'hi');
  });

  test('files from the Go implementation are read', () async {
    final plain = File('test/fixtures/plaintext.txt').readAsStringSync();
    for (final name in ['go_passphrase.age', 'go_passphrase_armor.age']) {
      final ct = File('test/fixtures/$name').readAsBytesSync();
      expect(utf8.decode(await Rage.decryptWithPassphrase(ct, pass)), plain, reason: name);
    }
    final key = File('test/fixtures/go_x25519.key').readAsStringSync();
    final ct = File('test/fixtures/go_x25519.age').readAsBytesSync();
    expect(utf8.decode(await Rage.decryptWithIdentities(ct, [key])), plain);
  });

  test('files stream from path to path', () async {
    final dir = Directory.systemTemp.createTempSync('rage_test');
    addTearDown(() => dir.deleteSync(recursive: true));
    final plain = File('${dir.path}/plain')..writeAsBytesSync(List.generate(2000000, (i) => i % 251));
    final enc = '${dir.path}/plain.age';
    final out = '${dir.path}/out';
    await Rage.encryptFileWithPassphrase(plain.path, enc, pass, workFactor: fast);
    await Rage.decryptFileWithPassphrase(enc, out, pass);
    expect(File(out).readAsBytesSync(), plain.readAsBytesSync());
  });
}
