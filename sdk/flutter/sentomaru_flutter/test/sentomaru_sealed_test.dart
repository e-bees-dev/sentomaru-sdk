import 'dart:convert';
import 'dart:io';

import 'package:flutter/foundation.dart';
import 'package:flutter/services.dart';
import 'package:flutter_test/flutter_test.dart';
import 'package:sentomaru_flutter/sentomaru_flutter.dart';

/// D-14b: the Dart side of the sealed reader. Failure classes: a key that is not sent as the pubspec key (the native
/// side translates it), a contract code that does not become its typed error, another failure confused with a contract
/// code, a bad key or a non-Android platform that reaches the channel. The decryption is native (sealed module tests).
void main() {
  TestWidgetsFlutterBinding.ensureInitialized();
  const channel = MethodChannel('sentomaru_flutter');
  final messenger = TestDefaultBinaryMessengerBinding.instance.defaultBinaryMessenger;
  final calls = <MethodCall>[];

  final vectors = jsonDecode(File('../../../contracts/devsecops/sealed-v1-vectors.json').readAsStringSync())
      as Map<String, dynamic>;

  Uint8List hex(String s) =>
      Uint8List.fromList([for (var i = 0; i < s.length; i += 2) int.parse(s.substring(i, i + 2), radix: 16)]);

  void answer(Future<Object?> Function(MethodCall call) handler) {
    messenger.setMockMethodCallHandler(channel, (call) {
      calls.add(call);
      return handler(call);
    });
  }

  setUp(calls.clear);
  tearDown(() {
    messenger.setMockMethodCallHandler(channel, null);
    debugDefaultTargetPlatformOverride = null;
  });

  test('load sends the pubspec key and returns the native plaintext (Flutter case of the vectors)', () async {
    final flutter = [
      for (final c in vectors['cases'] as List)
        for (final f in (c as Map)['files'] as List)
          if ((f as Map).containsKey('flutterKey')) f
    ];
    expect(flutter, hasLength(1));
    final f = flutter.single;
    answer((call) async => hex(f['plainHex'] as String));
    final got = await SentomaruSealed.load(f['flutterKey'] as String);
    expect(got, hex(f['plainHex'] as String));
    expect(calls.single.method, 'sealedLoad');
    expect(calls.single.arguments, {'key': 'assets/dados/catalogo.bin'});
  });

  test('string returns the value or null for an absent key', () async {
    answer((call) async => (call.arguments as Map)['key'] == 'ausente' ? null : 'Olá, técnico');
    expect(await SentomaruSealed.string('saudacao'), 'Olá, técnico');
    expect(await SentomaruSealed.string('ausente'), isNull);
    expect(calls.map((c) => c.method), ['sealedString', 'sealedString']);
  });

  test('configure sends the fallback flag and the strings key', () async {
    answer((call) async => null);
    await SentomaruSealed.configure(allowPlainFallback: true, plainStringsKey: 'assets/textos.json');
    await SentomaruSealed.configure(allowPlainFallback: false);
    expect(calls.map((c) => c.arguments), [
      {'allowPlainFallback': true, 'plainStringsKey': 'assets/textos.json'},
      {'allowPlainFallback': false, 'plainStringsKey': null},
    ]);
  });

  test('every contract code becomes its typed error', () async {
    final listed = {for (final n in vectors['negative'] as List) (n as Map)['error'] as String};
    expect(SentomaruSealedError.values.map((e) => e.wire).toSet(), listed);
    for (final e in SentomaruSealedError.values) {
      answer((call) async => throw PlatformException(code: e.wire, message: e.wire));
      await expectLater(SentomaruSealed.load('assets/x.bin'),
          throwsA(isA<SentomaruSealedException>().having((x) => x.error, 'error', e)));
      await expectLater(SentomaruSealed.string('k'),
          throwsA(isA<SentomaruSealedException>().having((x) => x.error, 'error', e)));
    }
  });

  test('other failures are SentomaruException, not a contract code', () async {
    answer((call) async =>
        throw PlatformException(code: 'AssetNotFound', message: 'Asset not found', details: 'AssetNotFound'));
    await expectLater(SentomaruSealed.load('assets/x.bin'),
        throwsA(isA<SentomaruException>().having((x) => x.details, 'details', 'AssetNotFound')));
    answer((call) async => throw PlatformException(code: 'ChannelError'));
    await expectLater(SentomaruSealed.load('assets/x.bin'),
        throwsA(isA<SentomaruException>().having((x) => x.code, 'code', SentomaruErrorCode.channelError)));
    answer((call) async => null);
    await expectLater(SentomaruSealed.load('assets/x.bin'),
        throwsA(isA<SentomaruException>().having((x) => x.code, 'code', SentomaruErrorCode.channelError)));
  });

  test('bad keys never reach the channel', () async {
    answer((call) async => Uint8List(0));
    for (final key in ['', '/abs', 'a//b', 'a/./b', '../x', 'a/..', 'a/', 'x' * 513]) {
      expect(() => SentomaruSealed.load(key), throwsArgumentError, reason: key);
    }
    expect(() => SentomaruSealed.string(''), throwsArgumentError);
    expect(() => SentomaruSealed.configure(allowPlainFallback: true, plainStringsKey: '../x'), throwsArgumentError);
    expect(calls, isEmpty);
  });

  test('other platforms: UnsupportedError without the channel', () async {
    answer((call) async => Uint8List(0));
    for (final platform in [TargetPlatform.iOS, TargetPlatform.macOS]) {
      debugDefaultTargetPlatformOverride = platform;
      expect(() => SentomaruSealed.load('assets/x.bin'), throwsUnsupportedError);
      expect(() => SentomaruSealed.string('k'), throwsUnsupportedError);
      expect(() => SentomaruSealed.configure(allowPlainFallback: true), throwsUnsupportedError);
    }
    debugDefaultTargetPlatformOverride = null;
    expect(calls, isEmpty);
  });
}
