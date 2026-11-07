import 'package:flutter/foundation.dart';
import 'package:flutter/services.dart';

import 'exceptions.dart';

/// D-14b: why a sealed read failed (contracts/devsecops/cli-v1.md, asset-encryption, "Leitura").
enum SentomaruSealedError {
  /// No `header.bin` in the package (and no plain fallback), no sealed entry for the key, or `string` in a package
  /// sealed without a strings file.
  notSealed('not-sealed'),

  /// A size out of the format's bounds, a tag that does not verify (corrupt, swapped or copied from another build), an
  /// invalid compressed stream, or a strings file that is not a flat JSON object of texts. Never a tamper verdict.
  integrity('integrity'),

  /// A magic or a format version this plugin does not know.
  formatUnsupported('format-unsupported');

  const SentomaruSealedError(this.wire);

  /// The contract's code, as the native side sends it.
  final String wire;

  static SentomaruSealedError? fromWire(String code) {
    for (final e in values) {
      if (e.wire == code) return e;
    }
    return null;
  }
}

/// D-14b: a typed failure of [SentomaruSealed.load] or [SentomaruSealed.string].
class SentomaruSealedException implements Exception {
  final SentomaruSealedError error;

  const SentomaruSealedException(this.error);

  @override
  String toString() => 'SentomaruSealedException(${error.wire})';
}

/// D-14b: reads the assets `sentomaru protect` (control `asset-encryption`) sealed. The app replaces
/// `rootBundle.load('assets/dados/x.bin')` by `SentomaruSealed.load('assets/dados/x.bin')`, with the same key of the
/// `pubspec.yaml`; the plugin decrypts on the Android side with the SDK's sealed reader (no cryptography in Dart).
///
/// Data obfuscation, not secrecy: whoever has the APK recovers the files (D-14x1). `Image.asset`, `rootBundle` and
/// fonts read without the plugin and cannot read a sealed file. Android only; elsewhere every call throws
/// [UnsupportedError].
class SentomaruSealed {
  SentomaruSealed._();

  static const MethodChannel _channel = MethodChannel('sentomaru_flutter');

  static void _android() {
    if (kIsWeb || defaultTargetPlatform != TargetPlatform.android) {
      throw UnsupportedError('SentomaruSealed is Android only in v1');
    }
  }

  /// `pubspec.yaml` keys are relative, without empty, `.` or `..` segments; checked before the channel.
  static void _checkKey(String key, String name) {
    final bad = key.isEmpty || key.length > 512 || key.split('/').any((s) => s.isEmpty || s == '.' || s == '..');
    if (bad) throw ArgumentError.value(key, name, 'a pubspec.yaml asset key is expected');
  }

  /// Builds without the CLI (`flutter run`, tests): with [allowPlainFallback] the plain asset is read when the package
  /// has no `header.bin`, and [plainStringsKey] (a `pubspec.yaml` key) is the strings file [string] reads then. Off by
  /// default; turn it on only with `kDebugMode`. In a sealed package it has no effect.
  static Future<void> configure({required bool allowPlainFallback, String? plainStringsKey}) async {
    _android();
    if (plainStringsKey != null) _checkKey(plainStringsKey, 'plainStringsKey');
    await _invoke<void>('sealedConfigure', {'allowPlainFallback': allowPlainFallback, 'plainStringsKey': plainStringsKey});
  }

  /// The plaintext of the asset of [key] (the `pubspec.yaml` key). Whole file in memory, not a stream.
  static Future<Uint8List> load(String key) async {
    _android();
    _checkKey(key, 'key');
    final value = await _invoke<Uint8List>('sealedLoad', {'key': key});
    if (value == null) throw SentomaruException.channelError('Null response from native sealedLoad');
    return value;
  }

  /// The value of [key] in the profile's strings file, or null when the file has no such key.
  static Future<String?> string(String key) async {
    _android();
    if (key.isEmpty) throw ArgumentError.value(key, 'key', 'a strings key is expected');
    return _invoke<String>('sealedString', {'key': key});
  }

  static Future<T?> _invoke<T>(String method, Map<String, Object?> args) async {
    try {
      return await _channel.invokeMethod<T>(method, args);
    } on PlatformException catch (e) {
      final sealed = SentomaruSealedError.fromWire(e.code);
      if (sealed != null) throw SentomaruSealedException(sealed);
      // `AssetNotFound` (plain fallback only, the asset is not in the package) and channel failures.
      throw SentomaruException.fromPlatformException(e);
    } on MissingPluginException {
      throw SentomaruException.channelError('Native sealed reader not available');
    }
  }
}
