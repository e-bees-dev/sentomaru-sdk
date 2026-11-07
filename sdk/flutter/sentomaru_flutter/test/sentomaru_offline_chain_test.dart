
import 'dart:convert';
import 'dart:io';

import 'package:flutter/foundation.dart';
import 'package:flutter/services.dart';
import 'package:flutter_test/flutter_test.dart';
import 'package:sentomaru_flutter/sentomaru_flutter.dart';

void main() {
  TestWidgetsFlutterBinding.ensureInitialized();
  const channel = MethodChannel('sentomaru_flutter');
  final calls = <MethodCall>[];
  Object? Function(MethodCall)? reply;

  const permitJson = '{"permitId":"6F1C0000-0000-4000-8000-00000000D026","chainSeed":"AQID","issuedAt":"2026-11-05T08:00:00Z",'
      '"validUntil":"2026-11-06T08:00:00Z","maxItems":50,"driftToleranceSeconds":120}';

  setUp(() {
    calls.clear();
    reply = null;
    debugDefaultTargetPlatformOverride = TargetPlatform.iOS;
    SentomaruFlutterPlatform.instance = MethodChannelSentomaruFlutter();
    TestDefaultBinaryMessengerBinding.instance.defaultBinaryMessenger.setMockMethodCallHandler(channel, (call) async {
      calls.add(call);
      return reply?.call(call);
    });
  });
  tearDown(() {
    debugDefaultTargetPlatformOverride = null;
    TestDefaultBinaryMessengerBinding.instance.defaultBinaryMessenger.setMockMethodCallHandler(channel, null);
  });

  Matcher offline(SentomaruOfflineError e) =>
      throwsA(isA<SentomaruOfflineException>().having((x) => x.error, 'error', e));

  test('the permit response is parsed, kept as received, and anything else is refused', () {
    final permit = SentomaruOfflinePermit.parse(permitJson);
    expect(permit.permitId, '6f1c0000-0000-4000-8000-00000000d026');
    expect(permit.maxItems, 50);
    expect(permit.json, permitJson);
    for (final bad in ['', '[]', '{}', permitJson.replaceAll('"maxItems":50', '"maxItems":"50"')]) {
      expect(() => SentomaruOfflinePermit.parse(bad), offline(SentomaruOfflineError.permitInvalid));
    }
  });

  test('outside iOS it is unsupported and never reaches the channel', () async {
    debugDefaultTargetPlatformOverride = TargetPlatform.android;
    await expectLater(
      const SentomaruOfflineChain().sealOperation(permit: SentomaruOfflinePermit.parse(permitJson), operationDigest: Uint8List(32)),
      offline(SentomaruOfflineError.unsupported),
    );
    expect(calls, isEmpty);
  });

  test('sealOperation sends the permit text and the digest and returns the seal fields', () async {
    reply = (_) => {'seq': 0, 'bootCount': 1, 'elapsedRealtimeNanos': 5, 'wallClockMillis': 6, 'operationDigest': 'a', 'prevHash': 'b', 'hash': 'c', 'signature': 'd'};
    final seal = await const SentomaruOfflineChain()
        .sealOperation(permit: SentomaruOfflinePermit.parse(permitJson), operationDigest: Uint8List(32));
    expect(seal.seq, 0);
    expect(seal.bootCount, 1);
    expect(calls.single.method, 'offlineSeal');
    expect(calls.single.arguments['permit'], permitJson);
  });

  test('the native codes become typed errors', () async {
    final permit = SentomaruOfflinePermit.parse(permitJson);
    const expected = {
      'Offline:PERMIT_EXPIRED': SentomaruOfflineError.permitExpired,
      'Offline:CHAIN_FULL': SentomaruOfflineError.chainFull,
      'Offline:INVALID_DIGEST': SentomaruOfflineError.invalidDigest,
      'Offline:CLOCK_UNAVAILABLE': SentomaruOfflineError.clockUnavailable,
      'NotEnrolled': SentomaruOfflineError.notEnrolled,
      'InvalidRequest:PARAMS': SentomaruOfflineError.invalidRequest,
      'Weird': SentomaruOfflineError.channelError,
    };
    for (final entry in expected.entries) {
      reply = (_) => throw PlatformException(code: entry.key);
      await expectLater(const SentomaruOfflineChain().sealOperation(permit: permit, operationDigest: Uint8List(32)), offline(entry.value));
    }
  });

  test('reconcileBody sends the seal fields in order and returns the bytes', () async {
    reply = (_) => Uint8List.fromList([123, 125]);
    final seals = [
      const SentomaruOfflineSeal({'seq': 0}),
      const SentomaruOfflineSeal({'seq': 1}),
    ];
    final body = await const SentomaruOfflineChain().reconcileBody(permit: SentomaruOfflinePermit.parse(permitJson), seals: seals);
    expect(body, Uint8List.fromList([123, 125]));
    expect((calls.single.arguments['seals'] as List).map((s) => (s as Map)['seq']), [0, 1]);
  });

  // The plugin signs nothing and hashes nothing (the native SDK does, and the server verifies): what it owns is the permit text it parses and the
  // seal fields it passes through. These read the shared vectors of contracts/sdk/ for that: the permit made from a vector's fields is accepted
  // as received, and every vector seal is carried to the native reconciliation unchanged, in order, with its `seq` and `bootCount` readable
  // (4294967295 is the unavailable boot of the iOS vectors). The chain hashes and signatures of the vectors are checked by the Kotlin, Swift,
  // C# and Python readers, not here (the vendor's shared-vectors matrix).
  for (final file in ['offline-proof-chain-v1-vectors.json', 'offline-proof-chain-v1-unavailable-vectors.json']) {
    test('the shared vectors of $file: permit parsed as received, seals carried unchanged', () async {
      final vectors = jsonDecode(File('../../../contracts/sdk/$file').readAsStringSync()) as Map<String, dynamic>;
      final permitText = jsonEncode({
        'permitId': (vectors['permitId'] as String).toUpperCase(),
        'chainSeed': vectors['chainSeed'],
        'issuedAt': vectors['issuedAt'],
        'validUntil': vectors['validUntil'],
        'maxItems': 50,
        'driftToleranceSeconds': vectors['driftToleranceSeconds'],
      });
      final permit = SentomaruOfflinePermit.parse(permitText);
      expect(permit.permitId, vectors['permitId']);
      expect(permit.json, permitText);
      expect(permit.driftToleranceSeconds, vectors['driftToleranceSeconds']);
      expect(permit.validUntil.isAfter(permit.issuedAt), isTrue);
      var cases = 0;
      for (final c in vectors['cases'] as List) {
        final items = [for (final i in (c as Map)['items'] as List) Map<String, Object>.from(i as Map)];
        if (items.isEmpty) continue;
        cases++;
        final seals = [for (final i in items) SentomaruOfflineSeal(i)];
        expect([for (final s in seals) s.seq], [for (final i in items) i['seq']]);
        expect([for (final s in seals) s.bootCount], [for (final i in items) i['bootCount']]);
        calls.clear();
        reply = (_) => Uint8List(0);
        await const SentomaruOfflineChain().reconcileBody(permit: permit, seals: seals);
        expect((calls.single.arguments['seals'] as List).map((s) => Map<String, Object>.from(s as Map)).toList(), items);
      }
      expect(cases, greaterThan(0));
    });
  }
}
