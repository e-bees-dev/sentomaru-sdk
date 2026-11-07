import 'dart:convert';
import 'dart:io';

import 'package:flutter_test/flutter_test.dart';

/// D-22a: contracts/sdk/hybrid-bridge-v1.json is the set of calls the hybrid layers (React Native, Capacitor, MAUI)
/// replicate. It must stay equal to what this plugin sends from Dart and answers in Kotlin, or a hybrid layer would
/// copy a surface that no longer exists.
void main() {
  final contractFile = File('../../../contracts/sdk/hybrid-bridge-v1.json');
  // D-22a1: the calls are answered by the shared core; the sealed reader stays in the plugin.
  const kotlinDirs = ['android/src/main/kotlin/br/com/ebees/sentomaru/sentomaru_flutter', '../../hybrid-core/src/main/kotlin'];

  late Map<String, dynamic> contract;
  late Set<String> names;

  setUpAll(() {
    expect(contractFile.existsSync(), isTrue, reason: 'run from sdk/flutter/sentomaru_flutter in a full checkout');
    contract = jsonDecode(contractFile.readAsStringSync()) as Map<String, dynamic>;
    names = (contract['methods'] as List).map((m) => (m as Map)['name'] as String).toSet();
  });

  test('method names are unique', () {
    expect(names.length, (contract['methods'] as List).length);
  });

  test('every Dart call is in the contract and the contract has nothing else', () {
    final called = <String>{};
    for (final f in ['sentomaru_flutter_method_channel.dart', 'sentomaru_sealed.dart']) {
      final text = File('lib/src/$f').readAsStringSync();
      called.addAll(RegExp(r"_invoke(?:<[^>]*>)?\('(\w+)'").allMatches(text).map((m) => m.group(1)!));
    }
    // sealed.dart reaches the channel through its own helper with names kept in constants.
    final sealed = File('lib/src/sentomaru_sealed.dart').readAsStringSync();
    called.addAll(RegExp(r"'(sealed\w+)'").allMatches(sealed).map((m) => m.group(1)!));
    final flutterOnly = (contract['flutterOnly'] as List).cast<String>().toSet();
    expect(called.difference(flutterOnly), names);
  });

  test('every contract method is answered by the Kotlin side', () {
    final kotlin = kotlinDirs
        .expand((d) => Directory(d).listSync(recursive: true))
        .whereType<File>()
        .where((f) => f.path.endsWith('.kt'))
        .map((f) => f.readAsStringSync())
        .join('\n');
    final answered = RegExp(r'^\s*"(\w+)" ->', multiLine: true).allMatches(kotlin).map((m) => m.group(1)!).toSet()
      ..addAll(RegExp(r'const val (?:CONFIGURE|LOAD|STRING) = "(\w+)"').allMatches(kotlin).map((m) => m.group(1)!));
    expect(answered.containsAll(names), isTrue, reason: 'missing: ${names.difference(answered)}');
  });

  test('the bridge error codes are the ones the Kotlin side emits', () {
    final kotlin = kotlinDirs
        .expand((d) => Directory(d).listSync(recursive: true))
        .whereType<File>()
        .where((f) => f.path.endsWith('.kt'))
        .map((f) => f.readAsStringSync())
        .join('\n');
    for (final code in (contract['bridgeErrorCodes'] as List).cast<String>()) {
      expect(kotlin.contains('"$code"'), isTrue, reason: '$code is not in the Kotlin sources');
    }
  });
}
