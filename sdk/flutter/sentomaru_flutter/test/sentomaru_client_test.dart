import 'dart:isolate';
import 'dart:typed_data';

import 'package:flutter_test/flutter_test.dart';
import 'package:sentomaru_flutter/sentomaru_flutter.dart';

class TestFakePlatform implements SentomaruFlutterPlatform {
  @override
  bool get signalEventsSupported => false;

  @override
  Stream<Object?> signalEvents() => const Stream.empty();

  SentomaruConfig? config;
  InstallationState currentState = InstallationState.notEnrolled;
  bool throwNoActivity = false;
  String? currentSessionId;
  int enrollCallCount = 0;
  int rotateCallCount = 0;
  int signCallCount = 0;
  ReenrollmentReason? reenrollment;

  @override
  Future<String?> scaffoldInfo() async => 'fake:0.0.1';

  @override
  Future<ReenrollmentReason?> reenrollmentReason() async => reenrollment;

  @override
  Future<void> initialize(SentomaruConfig config) async {
    this.config = config;
  }

  @override
  Future<InstallationState> state() async {
    if (throwNoActivity) {
      throw const SentomaruException(
        SentomaruErrorCode.noActivity,
        'No activity attached',
      );
    }
    return currentState;
  }

  @override
  Future<EnrollmentGrant> enroll(
    EnrollmentChallenge challenge, {
    bool strongBox = false,
    bool requiresHardware = false,
  }) async {
    enrollCallCount++;
    currentState = InstallationState.enrolled;
    currentSessionId = 'sess-123';
    return EnrollmentGrant(
      installationId: 'inst-123',
      keyId: challenge.id,
      sessionId: currentSessionId!,
      hardwareStatus: 'hardware',
      attestationStatus: 'verified',
    );
  }

  @override
  Future<EnrollmentGrant> rotate(
    EnrollmentChallenge challenge, {
    bool strongBox = false,
    bool requiresHardware = false,
  }) async {
    rotateCallCount++;
    currentState = InstallationState.enrolled;
    return EnrollmentGrant(
      installationId: 'inst-123',
      keyId: challenge.id,
      sessionId: currentSessionId!,
      hardwareStatus: 'hardware',
      attestationStatus: 'verified',
    );
  }

  @override
  Future<SignedMessageHeaders> sign({
    required String method,
    required String targetUri,
    required String operation,
    required Uint8List bodyBytes,
    Map<String, String> optionalHeaders = const {},
  }) async {
    signCallCount++;
    return const SignedMessageHeaders({
      'Signature': 'sig1=:test:',
      'Signature-Input': 'sig1=("@method" "@target-uri");created=10',
      'Content-Digest': 'sha-256=:test:',
      'x-sentomaru-operation': 'test_op',
      'x-sentomaru-session': 'sess-123',
    });
  }

  @override
  Future<void> reset() async {
    currentState = InstallationState.notEnrolled;
    currentSessionId = null;
  }

  @override
  Future<List<SignalObservation>> collectSignals() async {
    return [
      SignalObservation(
        capabilityId: 'os_version',
        version: '1.0.0',
        state: SignalState.detected,
        source: 'client_observed',
        observedAt: DateTime.now(),
        data: const {'sdk': '35'},
      )
    ];
  }

  /// D-05e: the last `rasp` asked for, and a snapshot built from [collectSignals].
  bool? lastRasp;

  @override
  Future<T?> invokeOffline<T>(String method, Map<String, Object?>? arguments) async => null;

  @override
  Future<T?> invokeTransaction<T>(String method, Map<String, Object?>? arguments) async => null;

  bool lastScreen = false;

  @override
  Future<SignalsSnapshot> collectSignalsSnapshot({bool rasp = false, AppIntegritySignals? appIntegrity, bool screen = false}) async {
    lastRasp = rasp;
    lastScreen = screen;
    lastAppIntegrity = appIntegrity;
    return SignalsSnapshot(collectedAt: DateTime.utc(2026, 10, 21), durationMs: 3, observations: await collectSignals());
  }

  @override
  Future<String?> sessionId() async => currentSessionId;

  @override
  Future<String> renewSession() async => 'renewed-session';

  AppIntegritySignals? lastAppIntegrity;
  bool? lastStrongBox;
  ReattestationOutcome outcome = const ReattestationNotNow(ReattestationWait.notDue, Duration(hours: 1));

  @override
  Future<bool> reattestationDue() async => false;

  @override
  Future<ReattestationOutcome> reattestIfDue({bool strongBox = false}) async {
    lastStrongBox = strongBox;
    calls.add('reattestIfDue');
    return outcome;
  }

  final calls = <String>[];

  @override
  Future<ReattestationOutcome> reattest({bool strongBox = false}) async {
    lastStrongBox = strongBox;
    calls.add('reattest');
    return outcome;
  }
}

void main() {
  const testConfig = SentomaruConfig(
    organization: 'ebees',
    app: 'example-app',
    environment: 'dev',
    enrollmentUrl: 'https://api.ebees.com.br/enroll',
    allowedHosts: {'api.ebees.com.br'},
  );

  final testChallenge = EnrollmentChallenge(
    id: '00000000-0000-0000-0000-000000000001',
    token: 'token123',
    expiresAt: DateTime.now().add(const Duration(minutes: 5)),
    attestationChallenge: Uint8List(32),
  );

  group('FLT-1 (fake platform): Futures and reactive streams', () {
    test('D-04b: reenrollmentReason passes through and leaves the state alone', () async {
      final fakePlatform = TestFakePlatform();
      final client = SentomaruClient(platform: fakePlatform);
      await client.initialize(testConfig);
      await client.enroll(testChallenge);
      expect(await client.reenrollmentReason(), isNull);
      fakePlatform.reenrollment = ReenrollmentReason.appUpdated;
      expect(await client.reenrollmentReason(), ReenrollmentReason.appUpdated);
      expect(await client.state(), InstallationState.enrolled);
    });

    test('initialization, state enquiry and reactive state stream', () async {
      final fakePlatform = TestFakePlatform();
      final client = SentomaruClient(platform: fakePlatform);

      final stateList = <InstallationState>[];
      final subscription = client.stateChanges.listen(stateList.add);

      expect(client.isInitialized, isFalse);
      await client.initialize(testConfig);
      expect(client.isInitialized, isTrue);

      expect(await client.state(), InstallationState.notEnrolled);

      // Enroll transitions to Enrolled
      final grant = await client.enroll(testChallenge);
      expect(grant.keyId, testChallenge.id);
      expect(await client.state(), InstallationState.enrolled);

      // Rotate keeps Enrolled
      await client.rotate(testChallenge);
      expect(await client.state(), InstallationState.enrolled);

      // Reset transitions to NotEnrolled
      await client.reset();
      expect(await client.state(), InstallationState.notEnrolled);

      await Future.delayed(const Duration(milliseconds: 10));
      expect(stateList, [
        InstallationState.notEnrolled,
        InstallationState.enrolled,
        InstallationState.enrolled,
        InstallationState.notEnrolled,
      ]);

      await subscription.cancel();
      client.dispose();
    });
  });

  group('FLT-4 (fake platform only; real channel: integration_test on device)', () {
    test('Keystore operations and signing succeed in headless/background without Activity', () async {
      final fakePlatform = TestFakePlatform();
      final client = SentomaruClient(platform: fakePlatform);
      await client.initialize(testConfig);
      await client.enroll(testChallenge);

      // Background sign succeeds without requiring Activity (Decision E4)
      final signed = await client.sign(
        method: 'POST',
        targetUri: 'https://api.ebees.com.br/telemetry',
        operation: 'telemetry',
        bodyBytes: Uint8List(0),
      );
      expect(signed.signature, isNotNull);
    });

    test('If platform requires Activity and none is attached, throws categorized NoActivity error', () async {
      final fakePlatform = TestFakePlatform();
      final client = SentomaruClient(platform: fakePlatform);
      await client.initialize(testConfig);
      fakePlatform.throwNoActivity = true;

      expect(
        () => client.state(),
        throwsA(isA<SentomaruException>().having(
          (e) => e.code,
          'code',
          SentomaruErrorCode.noActivity,
        )),
      );
    });
  });

  group('FLT-5 (fake platform in a Dart isolate; real channel: integration_test on device)', () {
    test('Execution in separate isolate succeeds with persistent state', () async {
      // Run async function in a separate isolate
      final result = await Isolate.run(() async {
        final platform = TestFakePlatform();
        final client = SentomaruClient(platform: platform);
        await client.initialize(testConfig);
        final grant = await client.enroll(testChallenge);
        final signed = await client.sign(
          method: 'POST',
          targetUri: 'https://api.ebees.com.br/ping',
          operation: 'ping',
          bodyBytes: Uint8List.fromList([1, 2, 3]),
        );
        return {
          'grantKeyId': grant.keyId,
          'signature': signed.signature,
        };
      });

      expect(result['grantKeyId'], testChallenge.id);
      expect(result['signature'], 'sig1=:test:');
    });
  });

  group('FLT-6 (fake platform: same fake object reused; not a real hot restart)', () {
    test('Re-instantiating client preserves persisted platform state without re-enrollment', () async {
      final fakePlatform = TestFakePlatform();

      // Session 1: Client enrolls
      final client1 = SentomaruClient(platform: fakePlatform);
      await client1.initialize(testConfig);
      await client1.enroll(testChallenge);
      expect(await client1.state(), InstallationState.enrolled);
      expect(fakePlatform.enrollCallCount, 1);
      client1.dispose();

      // Hot restart simulation: new Dart client instance attaching to existing engine state
      final client2 = SentomaruClient(platform: fakePlatform);
      await client2.initialize(testConfig);
      expect(await client2.state(), InstallationState.enrolled);
      expect(fakePlatform.enrollCallCount, 1); // No re-enrollment required!
      expect(await client2.sessionId(), 'sess-123');
      client2.dispose();
    });
  });

  group('FLT-7 (fake platform): Channel format and platform error handling', () {
    test('Uninitialized client throws typed notInitialized exception', () {
      final client = SentomaruClient(platform: TestFakePlatform());
      expect(
        () => client.config,
        throwsA(isA<SentomaruException>().having(
          (e) => e.code,
          'code',
          SentomaruErrorCode.notInitialized,
        )),
      );
    });

    test('Signals collection returns typed SignalObservation models', () async {
      final client = SentomaruClient(platform: TestFakePlatform());
      await client.initialize(testConfig);
      final signals = await client.collectSignals();
      expect(signals.length, 1);
      expect(signals.first.capabilityId, 'os_version');
      expect(signals.first.state, SignalState.detected);
    });

    test('collectSignalsSnapshot forwards rasp (false by default)', () async {
      final platform = TestFakePlatform();
      final client = SentomaruClient(platform: platform);
      final snapshot = await client.collectSignalsSnapshot();
      expect(platform.lastRasp, isFalse);
      expect(snapshot.catalogVersion, SentomaruSignalsCatalog.version);
      expect(snapshot.durationMs, 3);
      await client.collectSignalsSnapshot(rasp: true);
      expect(platform.lastRasp, isTrue);
      expect(platform.lastAppIntegrity, isNull);
      expect(platform.lastScreen, isFalse);
      await client.collectSignalsSnapshot(screen: true);
      expect(platform.lastScreen, isTrue);
    });

    test('D-12e: collectSignalsSnapshot forwards appIntegrity; reattestIfDue forwards strongBox and the outcome', () async {
      final platform = TestFakePlatform();
      final client = SentomaruClient(platform: platform);
      final integrity = AppIntegritySignals(expectedSignerDigests: ['a' * 64]);
      await client.collectSignalsSnapshot(appIntegrity: integrity);
      expect(platform.lastAppIntegrity, same(integrity));
      expect(platform.lastRasp, isFalse);
      expect(await client.reattestIfDue(), same(platform.outcome));
      expect(platform.lastStrongBox, isFalse);
      await client.reattestIfDue(strongBox: true);
      expect(platform.lastStrongBox, isTrue);
      expect(await client.reattestationDue(), isFalse);
    });

    test('D-06h: reattest forwards strongBox and the outcome, through the native reattest (not reattestIfDue)', () async {
      final platform = TestFakePlatform();
      final client = SentomaruClient(platform: platform);
      expect(await client.reattest(), same(platform.outcome));
      expect(platform.lastStrongBox, isFalse);
      await client.reattest(strongBox: true);
      expect(platform.lastStrongBox, isTrue);
      expect(platform.calls, ['reattest', 'reattest']);
    });
  });

  group('FLT-8 (fake platform; timing of a fake proves nothing about native biometrics)', () {
    test('Signing is completely non-interactive and executes without UI thread delays', () async {
      final fakePlatform = TestFakePlatform();
      final client = SentomaruClient(platform: fakePlatform);
      await client.initialize(testConfig);
      await client.enroll(testChallenge);

      final stopwatch = Stopwatch()..start();
      final signed = await client.sign(
        method: 'POST',
        targetUri: 'https://api.ebees.com.br/sync',
        operation: 'sync',
        bodyBytes: Uint8List.fromList([42]),
      );
      stopwatch.stop();

      expect(signed.signature, isNotNull);
      // Completes instantly with zero UI prompt blocks
      expect(stopwatch.elapsedMilliseconds, lessThan(500));
    });
  });

  group('R4: no silent default scope', () {
    for (final field in ['organization', 'app', 'environment']) {
      test('missing $field is a typed configurationError before any native call', () async {
        final platform = TestFakePlatform();
        final client = SentomaruClient(platform: platform);
        final config = SentomaruConfig(
          organization: field == 'organization' ? '' : 'ebees',
          app: field == 'app' ? '' : 'example-app',
          environment: field == 'environment' ? ' ' : 'dev',
          enrollmentUrl: 'https://api.ebees.com.br/enroll',
          allowedHosts: const {'api.ebees.com.br'},
        );
        await expectLater(
          client.initialize(config),
          throwsA(isA<SentomaruException>().having((e) => e.code, 'code', SentomaruErrorCode.configurationError)),
        );
        expect(platform.config, isNull);
        expect(client.isInitialized, isFalse);
      });
    }

    test('fromMap never falls back to ebees/example-app/dev', () {
      expect(
        () => SentomaruConfig.fromMap({'enrollmentUrl': 'https://a.b/e', 'allowedHosts': ['a.b']}),
        throwsA(isA<SentomaruException>().having((e) => e.code, 'code', SentomaruErrorCode.configurationError)),
      );
    });

    test('native ConfigurationError and ServerRejected:<reason> map to typed codes', () {
      expect(SentomaruErrorCode.fromString('ConfigurationError'), SentomaruErrorCode.configurationError);
      expect(SentomaruErrorCode.fromString('NotInitialized'), SentomaruErrorCode.notInitialized);
      expect(SentomaruErrorCode.fromString('ServerRejected:EXPIRED'), SentomaruErrorCode.serverRejected);
      expect(SentomaruErrorCode.fromString('ServerRejected:SUSPENDED'), SentomaruErrorCode.serverRejected);
      expect(SentomaruErrorCode.fromString('InvalidRequest:CONTENT_DIGEST'), SentomaruErrorCode.invalidRequest);
    });
  });
}
