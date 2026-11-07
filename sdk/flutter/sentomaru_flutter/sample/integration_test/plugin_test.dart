// Real SentomaruFlutterPlugin on a device: real MethodChannel, real native SDK, real Keystore, real isolates.
// No network is needed (the device is not given a route to a lab server); enrollment is exercised up to the
// transport failure. Run: see sdk/flutter/README.md ("Teste em aparelho").
import 'dart:isolate';

import 'package:dio/dio.dart';
import 'package:flutter/services.dart';
import 'package:flutter_test/flutter_test.dart';
import 'package:integration_test/integration_test.dart';
import 'package:sentomaru_flutter/sentomaru_flutter.dart';

const _host = '127.0.0.1';
const _config = SentomaruConfig(
  organization: 'ebees',
  app: 'flutter-device-test',
  environment: 'lab',
  enrollmentUrl: 'https://$_host:9/v1/ebees/flutter-device-test/lab/installations',
  allowedHosts: {_host},
);

const _catalog = {
  'debug_attached',
  'emulator_detected',
  'root_indicated',
  'app_signing_digest',
  'installer_source',
  'os_version',
};

Matcher _code(SentomaruErrorCode code) => isA<SentomaruException>().having((e) => e.code, 'code', code);

/// Background isolate with the real plugin channel (BackgroundIsolateBinaryMessenger), as a WorkManager-style job.
Future<List<String>> _backgroundIsolate(RootIsolateToken token) async {
  BackgroundIsolateBinaryMessenger.ensureInitialized(token);
  final out = <String>[];
  final uninitialized = Dio()..addSentomaru(SentomaruClient());
  try {
    await uninitialized.post('https://$_host:9/x', data: {}, options: Options(headers: {'x-sentomaru-operation': 'sync'}));
    out.add('sent');
  } on DioException catch (e) {
    out.add((e.error as SentomaruException).code.name);
  }
  final client = SentomaruClient();
  await client.initialize(_config);
  out.add((await client.state()).name);
  try {
    await client.sign(method: 'POST', targetUri: 'https://$_host:9/x', operation: 'sync', bodyBytes: Uint8List(0));
    out.add('signed');
  } on SentomaruException catch (e) {
    out.add(e.code.name);
  }
  out.add((await client.collectSignals()).length.toString());
  return out;
}

class _Job {
  final RootIsolateToken token;
  _Job(this.token);
  Future<List<String>> run() => _backgroundIsolate(token);
}

void main() {
  IntegrationTestWidgetsFlutterBinding.ensureInitialized();
  final channel = MethodChannelSentomaruFlutter().methodChannel;

  testWidgets('FLT-device: native refuses missing scope with ConfigurationError (no default ebees/exampleapp/dev)',
      (tester) async {
    final args = Map<String, dynamic>.from(_config.toMap())..remove('organization');
    await expectLater(
      channel.invokeMethod('initialize', args),
      throwsA(isA<PlatformException>().having((e) => e.code, 'code', 'ConfigurationError')),
    );
  });

  testWidgets('FLT-device: real lifecycle, typed errors, signals, isolate and re-init', (tester) async {
    // Fresh engine: native client not initialized yet.
    await expectLater(SentomaruClient().state(), throwsA(_code(SentomaruErrorCode.notInitialized)));

    final client = SentomaruClient();
    await client.reset().catchError((_) {});
    await client.initialize(_config);
    expect(await client.state(), InstallationState.notEnrolled);

    await expectLater(
      client.sign(method: 'POST', targetUri: 'https://$_host:9/x', operation: 'op', bodyBytes: Uint8List(0)),
      throwsA(_code(SentomaruErrorCode.notEnrolled)),
    );

    // Real signals: exactly the catalog, unique ids, observedAt from native (never invented).
    final signals = await client.collectSignals();
    expect(signals.map((s) => s.capabilityId).toSet(), _catalog);
    expect(signals.length, _catalog.length);

    // D-05e: the snapshot. Without rasp the same six; with rasp the D-05 ones too, collected off the main thread
    // with the deadline. This host does not declare signals-rasp, so root_artifacts is never NOT_DETECTED.
    final plain = await client.collectSignalsSnapshot();
    expect(plain.observations.map((o) => o.capabilityId).toSet(), _catalog);
    final rasp = await client.collectSignalsSnapshot(rasp: true);
    expect(rasp.observations.map((o) => o.capabilityId).toList(),
        [...SentomaruSignalsCatalog.defaultCapabilityIds, ...SentomaruSignalsCatalog.raspCapabilityIds]);
    expect(rasp.durationMs, greaterThanOrEqualTo(0));
    final rootArtifacts = rasp.observations.singleWhere((o) => o.capabilityId == 'root_artifacts');
    expect(rootArtifacts.state, isNot(SignalState.notDetected));
    expect(encodeSignalsHeader(rasp.toJson()).length, lessThanOrEqualTo(3 * 1024));

    // Enrollment reaches the real transport; nothing listens on :9 -> NetworkUnavailable (not ServerRejected).
    final challenge = EnrollmentChallenge(
      id: '11111111-2222-4333-8444-555555555555',
      token: 'AQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQE=',
      expiresAt: DateTime.now().add(const Duration(minutes: 5)),
      attestationChallenge: Uint8List(32),
    );
    await expectLater(client.enroll(challenge), throwsA(_code(SentomaruErrorCode.networkUnavailable)));
    final afterAttempt = await client.state();

    // Hot-restart analogue: a new Dart client (fresh Dart state) re-initializes; native state is preserved.
    final restarted = SentomaruClient();
    await restarted.initialize(_config);
    expect(await restarted.state(), afterAttempt);

    // Background isolate on the real channel.
    final token = RootIsolateToken.instance!;
    final background = await Isolate.run(_Job(token).run);
    expect(background, [
      SentomaruErrorCode.notInitialized.name,
      afterAttempt.name,
      // pending enrollment (EnrollmentRequired) or nothing (NotEnrolled): never signs without a grant
      afterAttempt == InstallationState.enrollmentRequired
          ? SentomaruErrorCode.enrollmentRequired.name
          : SentomaruErrorCode.notEnrolled.name,
      '${_catalog.length}',
    ]);

    await restarted.reset();
    expect(await restarted.state(), InstallationState.notEnrolled);
  });

  // D-12e (not run on a device yet): the app integrity signals and the reattestation on the real native side.
  testWidgets('FLT-device D-12e: app integrity signals and reattestation without a server', (tester) async {
    // A route outside the allowlist is refused natively (ConfigurationError), never kept.
    final bad = Map<String, dynamic>.from(_config.toMap())
      ..['reattestationChallengeUrl'] = 'https://other.example/c'
      ..['reattestationSubmitUrl'] = 'https://$_host:9/s';
    await expectLater(
      channel.invokeMethod('initialize', bad),
      throwsA(isA<PlatformException>().having((e) => e.code, 'code', 'ConfigurationError')),
    );

    final client = SentomaruClient();
    await client.reset().catchError((_) {});
    await client.initialize(_config);
    // Without the routes in the configuration: invalidRequest, nothing sent.
    await expectLater(client.reattestIfDue(), throwsA(_code(SentomaruErrorCode.invalidRequest)));
    await expectLater(client.reattestationDue(), throwsA(_code(SentomaruErrorCode.invalidRequest)));

    // The 15 client capabilities; the sample is debug-signed, so a list without its certificate is DETECTED mismatch.
    final integrity = AppIntegritySignals(expectedSignerDigests: ['0' * 64]);
    final first = await client.collectSignalsSnapshot(rasp: true, appIntegrity: integrity);
    expect(first.observations.map((o) => o.capabilityId).toList(), [
      ...SentomaruSignalsCatalog.defaultCapabilityIds,
      ...SentomaruSignalsCatalog.raspCapabilityIds,
      ...SentomaruSignalsCatalog.appIntegrityCapabilityIds,
    ]);
    SignalObservation of(SignalsSnapshot s, String id) => s.observations.singleWhere((o) => o.capabilityId == id);
    // Cold, with rasp, a detector may pass the deadline (UNKNOWN timeout); never NOT_DETECTED with a foreign list.
    final signer = of(first, 'app_signer_mismatch');
    expect(
        signer.state == SignalState.detected ||
            (signer.state == SignalState.unknown && signer.data['reason'] == 'timeout'),
        isTrue,
        reason: '${signer.state} ${signer.data}');
    expect(of(first, 'installer_class').state, isNot(SignalState.notDetected));
    expect(of(first, 'code_integrity').state, SignalState.unknown);
    expect(encodeSignalsHeader(first.toJson()).length, lessThanOrEqualTo(4 * 1024));
    // The hash runs in the background: collect again (at most 10 s in all) until code_integrity leaves `timeout`. It
    // ends `not_compared` with the aggregate, or `partial` with a fixed cause; never a verdict from the app.
    final deadline = DateTime.now().add(const Duration(seconds: 10));
    final loop = Stopwatch()..start();
    // ignore: avoid_print
    print('D12E first code_integrity=${of(first, 'code_integrity').data} signer=${signer.state.name}/${signer.data['result'] ?? signer.data['reason']} durationMs=${first.durationMs} header=${encodeSignalsHeader(first.toJson()).length}');
    late SignalsSnapshot later;
    for (var attempt = 1;; attempt++) {
      later = await client.collectSignalsSnapshot(appIntegrity: integrity);
      final reason = of(later, 'code_integrity').data['reason'];
      // ignore: avoid_print
      print('D12E loop attempt=$attempt elapsedMs=${loop.elapsedMilliseconds} reason=$reason durationMs=${later.durationMs}');
      if (reason != 'timeout' || DateTime.now().isAfter(deadline)) break;
      await Future<void>.delayed(const Duration(milliseconds: 250));
    }
    expect(of(later, 'code_integrity').state, SignalState.unknown);
    expect(of(later, 'code_integrity').data['reason'], isIn(['not_compared', 'partial']));
    expect(of(later, 'app_signer_mismatch').state, SignalState.detected);
    expect(of(later, 'app_signer_mismatch').data['result'], 'mismatch');
    expect(later.toJson(), isNot(contains('0' * 64)));
    // Without appIntegrity, the six of 0.12.0.
    expect((await client.collectSignalsSnapshot()).observations.map((o) => o.capabilityId).toSet(), _catalog);

    // With the routes: due, and the flow runs on the worker thread up to the first signature (not enrolled).
    final withRoutes = SentomaruClient();
    await withRoutes.initialize(SentomaruConfig(
      organization: _config.organization,
      app: _config.app,
      environment: _config.environment,
      enrollmentUrl: _config.enrollmentUrl,
      allowedHosts: _config.allowedHosts,
      reattestation: const SentomaruReattestationConfig(
          challengeUrl: 'https://$_host:9/reattest/challenge', submitUrl: 'https://$_host:9/reattest'),
    ));
    expect(await withRoutes.reattestationDue(), isTrue);
    await expectLater(withRoutes.reattestIfDue(), throwsA(_code(SentomaruErrorCode.notEnrolled)));
    expect(await withRoutes.reattestationDue(), isTrue); // a local failure starts no wait
    await withRoutes.reset();
  });
}
