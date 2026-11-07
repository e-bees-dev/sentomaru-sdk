import 'dart:convert';
import 'dart:io';

import 'package:flutter/foundation.dart';
import 'package:flutter/services.dart';
import 'package:flutter_test/flutter_test.dart';
import 'package:sentomaru_flutter/sentomaru_flutter.dart';

/// D-12e: the app integrity signals (catalog 1.5.0) and the reattestation (D-12b/D-12c) in the plugin, by doubles of the
/// native side. No failure becomes NOT_DETECTED, and the calls without the new options are the ones of 0.12.0.
void main() {
  TestWidgetsFlutterBinding.ensureInitialized();

  const channel = MethodChannel('sentomaru_flutter');
  final messenger = TestDefaultBinaryMessengerBinding.instance.defaultBinaryMessenger;
  final platform = MethodChannelSentomaruFlutter();
  final catalog = jsonDecode(_contract('signals-catalog-v1.json')) as Map<String, dynamic>;
  final caps = (catalog['capabilities'] as List).cast<Map<String, dynamic>>();
  Map<String, dynamic> cap(String id) => caps.firstWhere((c) => c['capabilityId'] == id);

  final digest = 'a' * 64;

  tearDown(() {
    messenger.setMockMethodCallHandler(channel, null);
    debugDefaultTargetPlatformOverride = null;
  });

  Map<String, Object?> obs(String id, Object? state, [Map<String, String>? data]) => {
        'capabilityId': id,
        'version': '1.0.0',
        'state': state,
        'source': 'client_observed',
        'observedAt': '2026-10-23T10:00:00.004Z',
        'data': data ?? <String, String>{},
      };

  Map<String, Object?> snapshotReply(List<Map<String, Object?>> observations) =>
      {'collectedAt': '2026-10-23T10:00:00Z', 'durationMs': 4, 'observations': observations};

  List<MethodCall> recordCalls(Object? Function(MethodCall call) reply) {
    final calls = <MethodCall>[];
    messenger.setMockMethodCallHandler(channel, (call) async {
      calls.add(call);
      return reply(call);
    });
    return calls;
  }

  group('app integrity signals', () {
    test('the call without appIntegrity is the 0.12.0 one, with and without rasp', () async {
      final calls = recordCalls((_) => snapshotReply([]));
      await platform.collectSignalsSnapshot();
      await platform.collectSignalsSnapshot(rasp: true);
      expect(calls.map((c) => c.arguments), [
        {'rasp': false},
        {'rasp': true},
      ]);
    });

    test('collectSignals() is unchanged: same method, no arguments, same list', () async {
      final calls = recordCalls((_) => [obs('root_indicated', 'not_detected')]);
      final list = await platform.collectSignals();
      expect(calls.single.method, 'collectSignals');
      expect(calls.single.arguments, isNull);
      expect(list.single.capabilityId, 'root_indicated');
    });

    for (final rasp in [false, true]) {
      test('appIntegrity sends the expected signers as given (rasp=$rasp)', () async {
        final keytool = digest.toUpperCase().replaceAllMapped(RegExp('..'), (m) => '${m[0]}:');
        final calls = recordCalls((_) => snapshotReply([]));
        await platform.collectSignalsSnapshot(
            rasp: rasp, appIntegrity: AppIntegritySignals(expectedSignerDigests: [digest, keytool.substring(0, keytool.length - 1)]));
        expect(calls.single.method, 'collectSignalsSnapshot');
        expect(calls.single.arguments, {
          'rasp': rasp,
          'expectedSignerDigests': [digest, keytool.substring(0, keytool.length - 1)],
        });
      });
    }

    test('an empty list goes to the native side (UNKNOWN no_reference there)', () async {
      final calls = recordCalls((_) => snapshotReply([
            obs('app_signer_mismatch', 'unknown', {'result': 'no_reference'}),
          ]));
      final s = await platform.collectSignalsSnapshot(appIntegrity: AppIntegritySignals(expectedSignerDigests: const []));
      expect((calls.single.arguments as Map)['expectedSignerDigests'], isEmpty);
      expect(s.observations.single.state, SignalState.unknown);
    });

    for (final targetPlatform in [TargetPlatform.android, TargetPlatform.iOS]) {
      for (final bad in ['', 'abc', 'g' * 64, 'a' * 63, 'a' * 65, '${'a' * 64} ']) {
        test('a signer that is not a SHA-256 ("$bad") is configurationError before any call (${targetPlatform.name})',
            () async {
          debugDefaultTargetPlatformOverride = targetPlatform;
          final calls = recordCalls((_) => snapshotReply([]));
          await expectLater(
            platform.collectSignalsSnapshot(appIntegrity: AppIntegritySignals(expectedSignerDigests: [digest, bad])),
            throwsA(isA<SentomaruException>().having((e) => e.code, 'code', SentomaruErrorCode.configurationError)),
          );
          expect(calls, isEmpty);
        });
      }
    }

    test('the native refusal of the list is configurationError, not a signal state', () async {
      messenger.setMockMethodCallHandler(channel, (call) async {
        throw PlatformException(code: 'ConfigurationError', message: 'Invalid expectedSignerDigests');
      });
      await expectLater(
        platform.collectSignalsSnapshot(appIntegrity: AppIntegritySignals(expectedSignerDigests: [digest])),
        throwsA(isA<SentomaruException>().having((e) => e.code, 'code', SentomaruErrorCode.configurationError)),
      );
    });

    // Every state the SDK reports for the three ids (AppIntegrityDetectorsTest, CodeIntegrityTest), as the wire has it.
    final states = <String, List<(String, Map<String, String>, String)>>{
      'app_signer_mismatch': [
        ('not_detected', {'result': 'match', 'signers': '1', 'unexpected': '0'}, 'NOT_DETECTED'),
        ('detected', {'result': 'mismatch', 'signers': '2', 'unexpected': '1'}, 'DETECTED'),
        ('unknown', {'result': 'no_reference'}, 'UNKNOWN'),
        ('unknown', {'result': 'unreadable'}, 'UNKNOWN'),
        ('error', {}, 'ERROR'),
        ('unknown', {'reason': 'timeout'}, 'UNKNOWN'),
      ],
      'installer_class': [
        ('detected', {'class': 'play', 'initiator': 'play'}, 'DETECTED'),
        ('detected', {'class': 'none', 'initiator': 'other'}, 'DETECTED'),
        ('unknown', {'class': 'unknown'}, 'UNKNOWN'),
        ('error', {}, 'ERROR'),
      ],
      'code_integrity': [
        ('unknown', {'reason': 'not_compared', 'algorithm': 'apk-code-sha256-v1', 'aggregate': 'b' * 64, 'files': '13'}, 'UNKNOWN'),
        ('unknown', {'reason': 'timeout'}, 'UNKNOWN'),
        ('unknown', {'reason': 'partial', 'cause': 'apk_unreadable'}, 'UNKNOWN'),
        ('unknown', {'reason': 'main_thread'}, 'UNKNOWN'),
        ('error', {}, 'ERROR'),
      ],
    };
    states.forEach((id, cases) {
      for (final (native, detail, wire) in cases) {
        test('$id $native ${detail.values.join('/')} reaches the wire as $wire with its detail', () async {
          recordCalls((_) => snapshotReply([obs(id, native, detail)]));
          final s = await platform.collectSignalsSnapshot(appIntegrity: AppIntegritySignals(expectedSignerDigests: [digest]));
          final o = (s.toMap()['observations'] as List).single as Map;
          expect(o['state'], wire);
          expect(o['detail'], detail);
          expect(cap(id)['supportedStates'], contains(wire));
        });
      }
    });

    for (final weird in [null, '', 'clean', 'NOT-DETECTED', 'notdetected']) {
      test('a native state the plugin does not know ($weird) is UNKNOWN, never NOT_DETECTED', () async {
        recordCalls((_) => snapshotReply([obs('app_signer_mismatch', weird)]));
        final s = await platform.collectSignalsSnapshot(appIntegrity: AppIntegritySignals(expectedSignerDigests: [digest]));
        expect(s.observations.single.state, SignalState.unknown);
      });
    }

    test('a state that is not text is channelError, never a state', () async {
      recordCalls((_) => snapshotReply([obs('code_integrity', 7)]));
      await expectLater(
        platform.collectSignalsSnapshot(appIntegrity: AppIntegritySignals(expectedSignerDigests: [digest])),
        throwsA(isA<SentomaruException>().having((e) => e.code, 'code', SentomaruErrorCode.channelError)),
      );
    });

    test('a native failure of the collection is an error, never a snapshot', () async {
      messenger.setMockMethodCallHandler(channel, (call) async {
        throw PlatformException(code: 'ChannelError', message: 'Native error');
      });
      await expectLater(
        platform.collectSignalsSnapshot(appIntegrity: AppIntegritySignals(expectedSignerDigests: [digest])),
        throwsA(isA<SentomaruException>().having((e) => e.code, 'code', SentomaruErrorCode.channelError)),
      );
    });

    test('the fifteen client capabilities over the channel fit in the 4 KiB header (worst details)', () async {
      // Long-form details: the D-12c ones at their longest, the others as the catalog fixtures; microsecond instants.
      final longest = <String, Map<String, String>>{
        'app_signer_mismatch': {'result': 'mismatch', 'signers': '16', 'unexpected': '16'},
        'installer_class': {'class': 'unknown', 'initiator': 'other'},
        'code_integrity': {'reason': 'not_compared', 'algorithm': 'apk-code-sha256-v1', 'aggregate': 'f' * 64, 'files': '4096'},
      };
      final ids = [
        ...SentomaruSignalsCatalog.defaultCapabilityIds,
        ...SentomaruSignalsCatalog.raspCapabilityIds,
        ...SentomaruSignalsCatalog.appIntegrityCapabilityIds,
      ];
      expect(ids, hasLength(15));
      recordCalls((_) => {
            'collectedAt': '2026-10-23T10:00:00.123456Z',
            'durationMs': 135,
            'observations': [
              for (final id in ids)
                {
                  ...obs(id, (cap(id)['fixture']['state'] as String).toLowerCase(),
                      longest[id] ?? (cap(id)['fixture']['detail'] as Map).cast<String, String>()),
                  'observedAt': '2026-10-23T10:00:00.123456Z',
                },
            ],
          });
      final s = await platform.collectSignalsSnapshot(
          rasp: true, appIntegrity: AppIntegritySignals(expectedSignerDigests: [digest]));
      final header = encodeSignalsHeader(s.toJson());
      expect(header.length, lessThanOrEqualTo(4 * 1024));
      expect(header.length, greaterThan(3 * 1024 - 400)); // the test really carries fifteen observations
      expect(header, isNot(contains(digest)));
    });

    // D-10e: iOS now goes to the native side (ios_platform_test.dart); a platform without native signals keeps this.
    test('no native signals (macOS): no call; the three ids UNSUPPORTED (with rasp, the nine), valid for the catalog', () async {
      debugDefaultTargetPlatformOverride = TargetPlatform.macOS;
      final calls = recordCalls((_) => null);
      final only = await platform.collectSignalsSnapshot(appIntegrity: AppIntegritySignals(expectedSignerDigests: [digest]));
      final both = await platform.collectSignalsSnapshot(
          rasp: true, appIntegrity: AppIntegritySignals(expectedSignerDigests: [digest]));
      final plain = await platform.collectSignalsSnapshot();
      expect(calls, isEmpty);
      expect(only.observations.map((o) => o.capabilityId), SentomaruSignalsCatalog.appIntegrityCapabilityIds);
      expect(both.observations.map((o) => o.capabilityId),
          [...SentomaruSignalsCatalog.raspCapabilityIds, ...SentomaruSignalsCatalog.appIntegrityCapabilityIds]);
      expect(plain.observations, isEmpty);
      for (final o in jsonDecode(both.toJson())['observations'] as List) {
        expect(o['state'], 'UNSUPPORTED');
        expect(cap(o['capabilityId'] as String)['supportedStates'], contains('UNSUPPORTED'));
      }
    });
  });

  group('reattestation over the channel', () {
    Map<String, Object?> result([Map<String, Object?> extra = const {}]) => {
          'installationId': '0b8f2a7e-6d1c-4f7a-9e3b-2c5d8a1f4e60',
          'challengeId': '5f0c7a9e-3b2d-4e1f-8a6c-9d7e2b1f0a34',
          'reattestedAt': '2026-10-23T10:00:01.234Z',
          'hardwareStatus': 'hardware',
          'attestationStatus': 'verified',
          'attestationReason': null,
          'buildMatchState': 'NOT_DETECTED',
          'buildMatchReason': 'build_registered',
          'appIdentityState': 'NOT_DETECTED',
          'appIdentityReason': null,
          'replayed': false,
          ...extra,
        };

    test('reattestIfDue sends strongBox (false by default) and reads a completed result', () async {
      final calls = recordCalls((_) => {'outcome': 'completed', 'result': result()});
      final outcome = await platform.reattestIfDue();
      await platform.reattestIfDue(strongBox: true);
      expect(calls.map((c) => c.method), ['reattestIfDue', 'reattestIfDue']);
      expect(calls.map((c) => c.arguments), [
        {'strongBox': false},
        {'strongBox': true},
      ]);
      final r = (outcome as ReattestationCompleted).result;
      expect(r.installationId, '0b8f2a7e-6d1c-4f7a-9e3b-2c5d8a1f4e60');
      expect(r.reattestedAt, DateTime.utc(2026, 10, 23, 10, 0, 1, 234));
      expect(r.attestationReason, isNull);
      expect(r.buildMatchReason, 'build_registered');
      expect(r.replayed, isFalse);
    });

    final waits = {
      'RATE_LIMITED': ReattestationWait.rateLimited,
      'VERIFIER_UNAVAILABLE': ReattestationWait.verifierUnavailable,
      'UNAVAILABLE': ReattestationWait.unavailable,
      'NOT_DUE': ReattestationWait.notDue,
      'SOMETHING_NEW': ReattestationWait.unknown,
    };
    waits.forEach((native, wait) {
      test('"not now" $native -> $wait with its wait', () async {
        recordCalls((_) => {'outcome': 'notNow', 'reason': native, 'retryAfterMs': 3600000});
        final outcome = await platform.reattestIfDue() as ReattestationNotNow;
        expect(outcome.reason, wait);
        expect(outcome.retryAfter, const Duration(hours: 1));
      });
    });

    for (final (code, status) in [
      ('reattestation-disabled', 403),
      ('session-expired', 403),
      ('installation-suspended', 403),
      ('challenge-invalid', 0),
      ('replay', 409),
      ('unexpected-answer', 200),
    ]) {
      test('refusal $code ($status) keeps the server code and status', () async {
        recordCalls((_) => {'outcome': 'refused', 'code': code, 'status': status});
        final outcome = await platform.reattestIfDue() as ReattestationRefused;
        expect(outcome.code, code);
        expect(outcome.status, status);
      });
    }

    final malformed = <String, Object?>{
      'null': null,
      'unknown outcome': {'outcome': 'maybe'},
      'completed without result': {'outcome': 'completed'},
      'result without installationId': {'outcome': 'completed', 'result': result({'installationId': null})},
      'result with a bad date': {'outcome': 'completed', 'result': result({'reattestedAt': 'tomorrow'})},
      'result with replayed as text': {'outcome': 'completed', 'result': result({'replayed': 'false'})},
      'result with an empty reason': {'outcome': 'completed', 'result': result({'buildMatchReason': ''})},
      'not now without wait': {'outcome': 'notNow', 'reason': 'RATE_LIMITED'},
      'not now with a negative wait': {'outcome': 'notNow', 'reason': 'RATE_LIMITED', 'retryAfterMs': -1},
      'refused without code': {'outcome': 'refused', 'status': 403},
      'refused without status': {'outcome': 'refused', 'code': 'replay'},
    };
    malformed.forEach((name, reply) {
      test('a malformed native reply ($name) is channelError, never a made-up outcome', () async {
        recordCalls((_) => reply);
        await expectLater(
          platform.reattestIfDue(),
          throwsA(isA<SentomaruException>().having((e) => e.code, 'code', SentomaruErrorCode.channelError)),
        );
      });
    });

    final failures = {
      'NotInitialized': SentomaruErrorCode.notInitialized,
      'InvalidRequest:PARAMS': SentomaruErrorCode.invalidRequest, // no reattestation routes in the configuration
      'NotEnrolled': SentomaruErrorCode.notEnrolled,
      'StrongBoxUnavailable': SentomaruErrorCode.strongBoxUnavailable,
      'Cancelled': SentomaruErrorCode.cancelled,
      'KeyUnavailable': SentomaruErrorCode.unknown,
      'HostNotAllowed': SentomaruErrorCode.hostNotAllowed,
      'ChannelError': SentomaruErrorCode.channelError,
    };
    failures.forEach((native, code) {
      test('a local failure $native is thrown as $code', () async {
        messenger.setMockMethodCallHandler(channel, (call) async => throw PlatformException(code: native, message: native));
        await expectLater(
          platform.reattestIfDue(),
          throwsA(isA<SentomaruException>()
              .having((e) => e.code, 'code', code)
              .having((e) => e.message, 'message', native)),
        );
      });
    });

    test('reattestationDue reads the native answer; null is channelError', () async {
      bool? answer = true;
      final calls = recordCalls((_) => answer);
      expect(await platform.reattestationDue(), isTrue);
      answer = false;
      expect(await platform.reattestationDue(), isFalse);
      expect(calls.map((c) => [c.method, c.arguments]), [
        ['reattestationDue', null],
        ['reattestationDue', null],
      ]);
      answer = null;
      await expectLater(platform.reattestationDue(),
          throwsA(isA<SentomaruException>().having((e) => e.code, 'code', SentomaruErrorCode.channelError)));
    });

    test('D-06h: reattest calls the native reattest with strongBox and reads the same outcomes', () async {
      final calls = recordCalls((c) => c.method == 'reattest' && (c.arguments as Map)['strongBox'] == true
          ? {'outcome': 'notNow', 'reason': 'RATE_LIMITED', 'retryAfterMs': 3600000}
          : {'outcome': 'completed', 'result': result()});
      expect(await platform.reattest(), isA<ReattestationCompleted>());
      final later = await platform.reattest(strongBox: true) as ReattestationNotNow;
      expect(later.retryAfter, const Duration(hours: 1));
      expect(calls.map((c) => c.method), ['reattest', 'reattest']);
      expect(calls.map((c) => c.arguments), [
        {'strongBox': false},
        {'strongBox': true},
      ]);
    });

    test('iOS: UNSUPPORTED without a call, and never due', () async {
      debugDefaultTargetPlatformOverride = TargetPlatform.iOS;
      final calls = recordCalls((_) => {'outcome': 'completed', 'result': result()});
      expect(await platform.reattest(), isA<ReattestationUnsupported>());
      expect(await platform.reattestIfDue(), isA<ReattestationUnsupported>());
      expect(await platform.reattestationDue(), isFalse);
      expect(calls, isEmpty);
    });
  });

  group('reattestation configuration', () {
    const base = SentomaruConfig(
      organization: 'ebees',
      app: 'sample',
      environment: 'hml',
      enrollmentUrl: 'https://api.example.test/enroll',
      allowedHosts: {'api.example.test'},
    );
    SentomaruConfig withReattestation(SentomaruReattestationConfig r) => SentomaruConfig(
          organization: base.organization,
          app: base.app,
          environment: base.environment,
          enrollmentUrl: base.enrollmentUrl,
          allowedHosts: base.allowedHosts,
          reattestation: r,
        );

    test('absent: initialize sends no reattestation key', () {
      expect(base.toMap().keys.where((k) => k.startsWith('reattestation')), isEmpty);
    });

    test('present: the two routes and the interval in seconds (24 h by default), and back', () {
      final c = withReattestation(const SentomaruReattestationConfig(
          challengeUrl: 'https://api.example.test/reattest/challenge', submitUrl: 'https://api.example.test/reattest'));
      c.validate();
      final map = c.toMap();
      expect(map['reattestationChallengeUrl'], 'https://api.example.test/reattest/challenge');
      expect(map['reattestationSubmitUrl'], 'https://api.example.test/reattest');
      expect(map['reattestationMinIntervalSeconds'], 86400);
      final back = SentomaruConfig.fromMap(map.cast<String, dynamic>());
      expect(back.reattestation!.submitUrl, 'https://api.example.test/reattest');
      expect(back.reattestation!.minInterval, const Duration(hours: 24));
    });

    for (final (name, r) in [
      ('http', const SentomaruReattestationConfig(
          challengeUrl: 'http://api.example.test/c', submitUrl: 'https://api.example.test/s')),
      ('host outside the allowlist', const SentomaruReattestationConfig(
          challengeUrl: 'https://api.example.test/c', submitUrl: 'https://other.example.test/s')),
      ('user info', const SentomaruReattestationConfig(
          challengeUrl: 'https://u@api.example.test/c', submitUrl: 'https://api.example.test/s')),
      ('zero interval', const SentomaruReattestationConfig(
          challengeUrl: 'https://api.example.test/c', submitUrl: 'https://api.example.test/s', minInterval: Duration.zero)),
      ('sub-second interval', const SentomaruReattestationConfig(
          challengeUrl: 'https://api.example.test/c',
          submitUrl: 'https://api.example.test/s',
          minInterval: Duration(milliseconds: 1500))),
    ]) {
      test('$name is configurationError', () {
        expect(() => withReattestation(r).validate(),
            throwsA(isA<SentomaruException>().having((e) => e.code, 'code', SentomaruErrorCode.configurationError)));
      });
    }
  });
}

String _contract(String name) {
  var dir = Directory.current;
  while (true) {
    final f = File('${dir.path}/contracts/sdk/$name');
    if (f.existsSync()) return f.readAsStringSync();
    final parent = dir.parent;
    if (parent.path == dir.path) throw StateError('contracts/sdk/$name not found');
    dir = parent;
  }
}
