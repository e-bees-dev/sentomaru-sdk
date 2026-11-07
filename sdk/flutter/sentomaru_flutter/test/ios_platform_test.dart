import 'package:flutter/foundation.dart';
import 'package:flutter/services.dart';
import 'package:flutter_test/flutter_test.dart';
import 'package:sentomaru_flutter/sentomaru_flutter.dart';

/// D-10b: what the Dart side does on iOS. The native iOS side (ios/Classes) answers the lifecycle methods like Android
/// and, since the D-10e, the signals (`collectSignals`, `collectSignalsSnapshot`); reattestation and signal events are
/// decided here, before the channel.
void main() {
  TestWidgetsFlutterBinding.ensureInitialized();

  final platform = MethodChannelSentomaruFlutter();
  const channel = MethodChannel('sentomaru_flutter');
  final calls = <MethodCall>[];

  setUp(() {
    calls.clear();
    debugDefaultTargetPlatformOverride = TargetPlatform.iOS;
    TestDefaultBinaryMessengerBinding.instance.defaultBinaryMessenger.setMockMethodCallHandler(channel, (call) async {
      calls.add(call);
      switch (call.method) {
        case 'collectSignals':
          return [_native('root_indicated', 'not_detected', {'jb_path': 'false'})];
        case 'collectSignalsSnapshot':
          final rasp = call.arguments['rasp'] == true;
          final integrity = (call.arguments as Map).containsKey('expectedSignerDigests');
          return {
            'collectedAt': '2026-10-29T12:00:00.000Z',
            'durationMs': 0,
            'observations': [
              _native('root_indicated', 'not_detected', {'jb_path': 'false'}),
              if (rasp) _native('root_artifacts', 'unsupported', {}),
              if (integrity) _native('code_integrity', 'unsupported', {}),
            ],
          };
        case 'enroll':
          return {
            'installationId': 'i',
            'keyId': 'k',
            'sessionId': 's',
            'hardwareStatus': 'device_attested',
            'attestationStatus': 'verified',
          };
      }
      return null;
    });
  });

  tearDown(() {
    debugDefaultTargetPlatformOverride = null;
    TestDefaultBinaryMessengerBinding.instance.defaultBinaryMessenger.setMockMethodCallHandler(channel, null);
  });

  test('D-10e: collectSignals asks the native side, which answers the iOS observations', () async {
    final signals = await platform.collectSignals();
    expect(signals.single.capabilityId, 'root_indicated');
    expect(signals.single.state, SignalState.notDetected);
    expect(signals.single.data, {'jb_path': 'false'});
    expect(calls.map((c) => c.method), ['collectSignals']);
  });

  test('D-10e: collectSignalsSnapshot goes to the native side with the Android arguments', () async {
    final snapshot = await platform.collectSignalsSnapshot();
    expect(snapshot.observations.map((o) => o.capabilityId), ['root_indicated']);
    expect(snapshot.collectedAt, DateTime.utc(2026, 10, 29, 12));
    final both = await platform.collectSignalsSnapshot(
      rasp: true,
      appIntegrity: AppIntegritySignals(expectedSignerDigests: ['ab' * 32]),
    );
    expect(both.observations.map((o) => o.capabilityId), ['root_indicated', 'root_artifacts', 'code_integrity']);
    expect(calls.map((c) => c.method), ['collectSignalsSnapshot', 'collectSignalsSnapshot']);
    expect(calls.first.arguments, {'rasp': false});
    expect(calls.last.arguments, {'rasp': true, 'expectedSignerDigests': ['ab' * 32]});
    expect(SignalsSnapshot(collectedAt: both.collectedAt, durationMs: 0, observations: both.observations).toMap()
        ['observations'], hasLength(3));
  });

  test('D-10e: a refused digest never reaches the channel', () async {
    expect(
      () => platform.collectSignalsSnapshot(appIntegrity: AppIntegritySignals(expectedSignerDigests: ['abc'])),
      throwsA(isA<SentomaruException>()),
    );
    expect(calls, isEmpty);
  });

  test('reattestation and signal events never reach the channel on iOS', () async {
    expect(await platform.reattestationDue(), isFalse);
    expect(await platform.reattestIfDue(), isA<ReattestationUnsupported>());
    expect(await platform.reattest(), isA<ReattestationUnsupported>());
    expect(platform.signalEventsSupported, isFalse);
    expect(calls, isEmpty);
  });

  test('enroll goes to the native side with the same arguments as on Android (it ignores strongBox)', () async {
    final grant = await platform.enroll(
      EnrollmentChallenge(id: 'c', token: 't', expiresAt: DateTime.utc(2030), attestationChallenge: Uint8List(32)),
      strongBox: true,
    );
    expect(grant.hardwareStatus, 'device_attested');
    expect(grant.isHardware, isFalse, reason: 'App Attest is never hardware (D-IOS7)');
    expect(calls.single.arguments['strongBox'], isTrue);
    expect(calls.single.arguments['requiresHardware'], isFalse);
  });
}

Map<String, Object?> _native(String id, String state, Map<String, String> data) => {
      'capabilityId': id,
      'version': '1.0.0',
      'state': state,
      'source': 'client_observed',
      'observedAt': '2026-10-29T12:00:00.000Z',
      'data': data,
    };
