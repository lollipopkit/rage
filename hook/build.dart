import 'package:flutter_rust_bridge_hooks/flutter_rust_bridge_hooks.dart';

/// Builds `rust/` and hands the library to the Dart or Flutter SDK as a code
/// asset: no podspec, Swift package or Gradle plugin for an app to add.
void main(List<String> args) async {
  await build(args, (input, output) async {
    await FlutterRustBridgeNativeAssetsBuilder(cratePath: 'rust')
        .run(input: input, output: output);
  });
}
