import 'dart:typed_data';

import 'package:flutter/material.dart';
import 'package:flutter_test/flutter_test.dart';
import 'package:sentomaru_flutter/sentomaru_flutter.dart';
import 'package:sentomaru_flutter_sample/main.dart';

class SampleFakePlatform implements SentomaruFlutterPlatform {
  @override
  Future<String?> scaffoldInfo() async => 'sample:0.0.1';

  @override
  Future<void> initialize(SentomaruConfig config) async {}

  @override
  Future<InstallationState> state() async => InstallationState.enrolled;

  @override
  Future<EnrollmentGrant> enroll(
    EnrollmentChallenge challenge, {
    bool strongBox = false,
    bool requiresHardware = false,
  }) async {
    return const EnrollmentGrant(
      installationId: 'inst-1',
      keyId: 'key-1',
      sessionId: 'sess-1',
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
    return const EnrollmentGrant(
      installationId: 'inst-1',
      keyId: 'key-1',
      sessionId: 'sess-1',
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
    return const SignedMessageHeaders({
      'Signature': 'sig1=:mock:',
    });
  }

  @override
  Future<void> reset() async {}

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
  Future<SignalsSnapshot> collectSignalsSnapshot({bool rasp = false, AppIntegritySignals? appIntegrity}) async {
    lastRasp = rasp;
    return SignalsSnapshot(collectedAt: DateTime.utc(2026, 10, 21), durationMs: 3, observations: await collectSignals());
  }

  @override
  Future<bool> reattestationDue() async => false;

  @override
  Future<ReattestationOutcome> reattestIfDue({bool strongBox = false}) async => const ReattestationUnsupported();

  @override
  Future<String?> sessionId() async => 'sess-1';

  @override
  Future<ReenrollmentReason?> reenrollmentReason() async => null;

  @override
  Future<String> renewSession() async => 'sess-2';
}

void main() {
  testWidgets('Sample app initializes and displays enrolled state', (tester) async {
    final client = SentomaruClient(platform: SampleFakePlatform());

    await tester.pumpWidget(SentomaruSampleApp(client: client));
    await tester.pumpAndSettle();

    expect(find.byKey(const Key('state_text')), findsOneWidget);
    expect(find.text('Installation State: enrolled'), findsOneWidget);

    // Tap collect signals button
    await tester.tap(find.byKey(const Key('collect_signals_button')));
    await tester.pumpAndSettle();

    expect(find.text('os_version'), findsOneWidget);
    expect(find.text('detected (client_observed)'), findsOneWidget);
  });
}
