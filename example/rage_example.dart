import 'dart:convert';

import 'package:rage/rage.dart';

Future<void> main() async {
  final ciphertext = await Rage.encryptWithPassphrase(
    utf8.encode('hello'),
    'correct horse battery staple',
    armor: true,
  );
  print(utf8.decode(ciphertext));

  final plaintext = await Rage.decryptWithPassphrase(
    ciphertext,
    'correct horse battery staple',
  );
  print(utf8.decode(plaintext));

  final key = await Rage.generateX25519();
  final sealed = await Rage.encryptToRecipients(utf8.encode('hi'), [key.recipient]);
  print(utf8.decode(await Rage.decryptWithIdentities(sealed, [key.identity])));
}
