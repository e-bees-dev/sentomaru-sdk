import 'dart:typed_data';

import 'package:flutter_test/flutter_test.dart';
import 'package:plugin_platform_interface/plugin_platform_interface.dart';
import 'package:sentomaru_flutter/sentomaru_flutter.dart';

class MockSentomaruFlutterPlatform
    with MockPlatformInterfaceMixin
    implements SentomaruFlutterPlatform {

  @override
  bool get signalEventsSupported => false;

  @override
  Stream<Object?> signalEvents() => const Stream.empty();

  InstallationState currentState = InstallationState.notEnrolled;

  @override
  Future<String?> scaffoldInfo() => Future.value('sentomaru_flutter:0.0.1');

  @override
  Future<void> initialize(SentomaruConfig config) async {}

  @override
  Future<InstallationState> state() async => currentState;

  @override
  Future<ReenrollmentReason?> reenrollmentReason() async => null;

  @override
  Future<EnrollmentGrant> enroll(
    EnrollmentChallenge challenge, {
    bool strongBox = false,
    bool requiresHardware = false,
  }) async {
    currentState = InstallationState.enrolled;
    return const EnrollmentGrant(
      installationId: '00000000-0000-0000-0000-000000000001',
      keyId: '00000000-0000-0000-0000-000000000002',
      sessionId: '00000000-0000-0000-0000-000000000003',
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
      installationId: '00000000-0000-0000-0000-000000000001',
      keyId: '00000000-0000-0000-0000-000000000004',
      sessionId: '00000000-0000-0000-0000-000000000003',
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
      'Signature-Input': 'sig1=("@method" "@target-uri");created=1000',
      'Content-Digest': 'sha-256=:mock:',
      'x-sentomaru-operation': 'test',
    });
  }

  @override
  Future<void> reset() async {
    currentState = InstallationState.notEnrolled;
  }

  @override
  Future<List<SignalObservation>> collectSignals() async => [];

  @override
  Future<T?> invokeOffline<T>(String method, Map<String, Object?>? arguments) async => null;

  @override
  Future<T?> invokeTransaction<T>(String method, Map<String, Object?>? arguments) async => null;

  bool lastScreen = false;

  @override
  Future<SignalsSnapshot> collectSignalsSnapshot({bool rasp = false, AppIntegritySignals? appIntegrity, bool screen = false}) async =>
      SignalsSnapshot(collectedAt: DateTime.utc(2026, 10, 21), durationMs: 0, observations: const []);

  @override
  Future<bool> reattestationDue() async => false;

  @override
  Future<ReattestationOutcome> reattestIfDue({bool strongBox = false}) async => const ReattestationUnsupported();

  @override
  Future<ReattestationOutcome> reattest({bool strongBox = false}) async => const ReattestationUnsupported();

  @override
  Future<String?> sessionId() async => '00000000-0000-0000-0000-000000000003';

  @override
  Future<String> renewSession() async => 'renewed-session';
}

void main() {
  final SentomaruFlutterPlatform initialPlatform = SentomaruFlutterPlatform.instance;

  test('$MethodChannelSentomaruFlutter is the default instance', () {
    expect(initialPlatform, isInstanceOf<MethodChannelSentomaruFlutter>());
  });

  test('scaffoldInfo', () async {
    final sentomaruFlutterPlugin = SentomaruFlutter();
    final fakePlatform = MockSentomaruFlutterPlatform();
    SentomaruFlutterPlatform.instance = fakePlatform;

    expect(await sentomaruFlutterPlugin.scaffoldInfo(), 'sentomaru_flutter:0.0.1');
  });
}
