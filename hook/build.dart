import 'dart:io';

import 'package:hooks/hooks.dart';
import 'package:native_toolchain_rust/native_toolchain_rust.dart';

import 'rust_build_environment.dart';

/// Builds `rust/` and hands the library to the Dart or Flutter SDK as the code
/// asset `lib/src/ffi.dart` binds: no podspec, Swift package or Gradle plugin
/// for an app to add.
void main(List<String> args) async {
  await build(args, (input, output) async {
    await RustBuilder(
      assetName: 'src/ffi.dart',
      extraCargoEnvironmentVariables: reproducibleCargoEnvironment(
        environment: Platform.environment,
        packageRoot: Directory.fromUri(input.packageRoot).path,
        isWindows: Platform.isWindows,
      ),
    ).run(input: input, output: output);
  });
}
