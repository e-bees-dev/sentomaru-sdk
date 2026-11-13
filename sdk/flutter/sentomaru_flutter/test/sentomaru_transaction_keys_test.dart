import 'dart:convert';
import 'dart:io' show HttpDate;

import 'package:dio/dio.dart';
import 'package:flutter/foundation.dart';
import 'package:flutter/services.dart' show PlatformException;
import 'package:flutter_test/flutter_test.dart';
import 'package:sentomaru_flutter/sentomaru_flutter.dart';

/// Signs every request (recording the operation and the optional headers) and answers the transaction methods.
class _TxFakePlatform extends SentomaruFlutterPlatform {
  final signed = <Map<String, Object?>>[];
  final tx = <MethodCallRecord>[];
  Object? Function(String method, Map<String, Object?>? args)? txReply;

  @override
  Future<void> initialize(SentomaruConfig config) async {}

  @override
  Future<InstallationState> state() async => InstallationState.enrolled;

  @override
  Future<String?> sessionId() async => 'sess-1';

  @override
  Future<SignedMessageHeaders> sign({
    required String method,
    required String targetUri,
    required String operation,
    required Uint8List bodyBytes,
    Map<String, String> optionalHeaders = const {},
  }) async {
    signed.add({'operation': operation, 'targetUri': targetUri, 'body': bodyBytes, 'optional': optionalHeaders});
    return SignedMessageHeaders({
      ...optionalHeaders,
      'Signature': 'sig1=:x:',
      'Signature-Input': 'sig1=("@method" "@target-uri" "content-digest");created=1000',
      'Content-Digest': 'sha-256=:x:',
      'x-sentomaru-operation': operation,
      'x-sentomaru-session': 'sess-1',
    });
  }

  @override
  Future<T?> invokeTransaction<T>(String method, Map<String, Object?>? arguments) async {
    tx.add(MethodCallRecord(method, arguments));
    return txReply?.call(method, arguments) as T?;
  }
}

class MethodCallRecord {
  MethodCallRecord(this.method, this.args);
  final String method;
  final Map<String, Object?>? args;
}

/// Answers the scripted (status, body, headers) in order and records the bytes Dio streamed.
class _Adapter implements HttpClientAdapter {
  _Adapter(this.answers);
  final List<(int, String, Map<String, List<String>>)> answers;
  final seen = <RequestOptions>[];
  final bodies = <List<int>>[];

  @override
  Future<ResponseBody> fetch(RequestOptions options, Stream<Uint8List>? requestStream, Future<void>? cancelFuture) async {
    bodies.add(requestStream == null ? <int>[] : await requestStream.fold<List<int>>(<int>[], (a, c) => a..addAll(c)));
    seen.add(options);
    final (status, body, headers) = answers[seen.length - 1];
    return ResponseBody.fromString(body, status, headers: {
      Headers.contentTypeHeader: [Headers.jsonContentType],
      ...headers,
    });
  }

  @override
  void close({bool force = false}) {}
}

const _challengeJson = '{"challengeId":"11111111-1111-4111-8111-111111111111","token":"tok-1",'
    '"attestationChallenge":"BwcHBwcHBwcHBwcHBwcHBwcHBwcHBwcHBwcHBwcHBwc=","expiresAt":"2026-11-13T10:05:00+00:00"}';
const _enrolledJson = '{"txKeyId":"tx-1","userAuthentication":"biometric-strong","attestationStatus":"verified",'
    '"enrolledAt":"2026-11-13T10:00:00+00:00"}';

void main() {
  TestWidgetsFlutterBinding.ensureInitialized();
  late _TxFakePlatform platform;
  late Dio dio;
  late _Adapter adapter;

  Future<SentomaruTransactionKeys> keys(List<(int, String, Map<String, List<String>>)> answers) async {
    final client = SentomaruClient(platform: platform);
    await client.initialize(const SentomaruConfig(
      organization: 'ebees',
      app: 'example-app',
      environment: 'dev',
      enrollmentUrl: 'https://api.ebees.com.br/enroll',
      allowedHosts: {'api.ebees.com.br'},
    ));
    adapter = _Adapter(answers);
    dio = Dio(BaseOptions(baseUrl: 'https://api.ebees.com.br'))..httpClientAdapter = adapter;
    dio.addSentomaru(client);
    return SentomaruTransactionKeys(dio: dio);
  }

  setUp(() {
    platform = _TxFakePlatform();
    SentomaruFlutterPlatform.instance = platform;
  });
  tearDown(() => debugDefaultTargetPlatformOverride = null);

  group('Android', () {
    setUp(() => debugDefaultTargetPlatformOverride = TargetPlatform.android);

    test('enroll: signed challenge, native body as is, 201 commits the staged key', () async {
      final native = Uint8List.fromList(utf8.encode('{"challenge":"tok-1","publicKey":"AA==","attestationChain":["AA=="],'
          '"userAuthentication":"biometric-strong"}'));
      platform.txReply = (method, _) => method == 'txKeyCreate' ? native : null;
      final k = await keys([(201, _challengeJson, const {}), (201, _enrolledJson, const {})]);

      final enrollment = await k.enroll(biometricOnly: true, strongBox: true);

      expect(enrollment.txKeyId, 'tx-1');
      expect(enrollment.attestationStatus, 'verified');
      expect(platform.signed.map((s) => s['operation']), ['tx_key_challenge', 'tx_key_enroll']);
      expect(adapter.seen.map((o) => o.path), [
        SentomaruTransactionKeys.defaultChallengePath,
        SentomaruTransactionKeys.defaultEnrollPath,
      ]);
      expect(adapter.bodies[0], isEmpty);
      expect(adapter.bodies[1], native);
      expect(platform.tx.map((c) => c.method), ['txKeyCreate', 'txKeyCommit']);
      final args = platform.tx.first.args!;
      expect(args['biometricOnly'], isTrue);
      expect(args['strongBox'], isTrue);
      final challenge = args['challenge'] as Map;
      expect(challenge['token'], 'tok-1');
      expect(challenge['attestationChallenge'], Uint8List.fromList(List.filled(32, 7)));
    });

    test('enroll: biometricOnly false asks the native side for the credential class', () async {
      platform.txReply = (method, _) => method == 'txKeyCreate' ? Uint8List.fromList([123, 125]) : null;
      final k = await keys([(201, _challengeJson, const {}), (201, _enrolledJson, const {})]);
      await k.enroll();
      expect(platform.tx.first.args!['biometricOnly'], isFalse);
      expect(platform.tx.first.args!.containsKey('strongBox'), isFalse);
    });

    test('enroll: 422 user-auth-not-proven aborts the staged key and surfaces code and reason', () async {
      platform.txReply = (method, _) => method == 'txKeyCreate' ? Uint8List.fromList([123, 125]) : null;
      final k = await keys([
        (201, _challengeJson, const {}),
        (422, '{"code":"user-auth-not-proven","attestationReason":"auth_type_mismatch"}', const {}),
      ]);
      await expectLater(
        k.enroll(),
        throwsA(isA<SentomaruTransactionKeyException>()
            .having((e) => e.statusCode, 'statusCode', 422)
            .having((e) => e.code, 'code', 'user-auth-not-proven')
            .having((e) => e.reason, 'reason', 'auth_type_mismatch')
            .having((e) => e.retryAfter, 'retryAfter', isNull)),
      );
      expect(platform.tx.map((c) => c.method), ['txKeyCreate', 'txKeyAbort']);
    });

    test('enroll: a commit failure also aborts and rethrows the native error', () async {
      platform.txReply = (method, _) => switch (method) {
            'txKeyCreate' => Uint8List.fromList([123, 125]),
            'txKeyCommit' => throw PlatformException(code: 'Transaction:NOT_ENROLLED'),
            _ => null,
          };
      final k = await keys([(201, _challengeJson, const {}), (201, _enrolledJson, const {})]);
      await expectLater(
        k.enroll(),
        throwsA(isA<SentomaruTransactionException>().having((e) => e.error, 'error', SentomaruTransactionError.notEnrolled)),
      );
      expect(platform.tx.map((c) => c.method), ['txKeyCreate', 'txKeyCommit', 'txKeyAbort']);
    });

    test('challenge 429 exposes Retry-After in seconds and never stages a key', () async {
      final k = await keys([
        (429, '{"code":"rate-limited"}', const {'retry-after': ['120']}),
      ]);
      await expectLater(
        k.enroll(),
        throwsA(isA<SentomaruTransactionKeyException>()
            .having((e) => e.statusCode, 'statusCode', 429)
            .having((e) => e.code, 'code', 'rate-limited')
            .having((e) => e.retryAfter, 'retryAfter', const Duration(seconds: 120))),
      );
      expect(platform.tx, isEmpty);
      expect(adapter.seen, hasLength(1));
    });
  });

  test('iOS enroll: body is challenge, SPKI and advisory-ios, without attestationChain', () async {
    debugDefaultTargetPlatformOverride = TargetPlatform.iOS;
    final spki = Uint8List.fromList([48, 89, 1, 2, 3]);
    platform.txReply = (method, _) => method == 'txKeyCreate' ? spki : null;
    final k = await keys([
      (201, _challengeJson, const {}),
      (201, _enrolledJson.replaceFirst('biometric-strong', 'advisory-ios').replaceFirst('verified', 'unattested'), const {}),
    ]);

    final enrollment = await k.enroll(strongBox: true);

    expect(enrollment.userAuthentication, 'advisory-ios');
    final sent = jsonDecode(utf8.decode(adapter.bodies[1])) as Map<String, Object?>;
    expect(sent, {'challenge': 'tok-1', 'publicKey': base64.encode(spki), 'userAuthentication': 'advisory-ios'});
    expect(sent.containsKey('attestationChain'), isFalse);
    expect(utf8.decode(adapter.bodies[1]), '{"challenge":"tok-1","publicKey":"${base64.encode(spki)}","userAuthentication":"advisory-ios"}');
    final create = platform.tx.first.args!;
    expect(create.containsKey('challenge'), isFalse);
    expect(create.containsKey('strongBox'), isFalse);
    expect(platform.tx.map((c) => c.method), ['txKeyCreate', 'txKeyCommit']);
  });

  group('status', () {
    setUp(() => debugDefaultTargetPlatformOverride = TargetPlatform.android);

    test('without signatureVersions the server is v1 only and the plugin signatures are refused', () async {
      final k = await keys([(200, '{"enrolled":true,"txKeyId":"tx-1","userAuthentication":"biometric-strong"}', const {})]);
      final status = await k.status();
      expect(platform.signed.single['operation'], 'tx_key_status');
      expect(status.enrolled, isTrue);
      expect(status.txKeyId, 'tx-1');
      expect(status.signatureVersionsDeclared, isFalse);
      expect(status.signatureVersions, ['v1']);
      expect(status.acceptsPluginSignatures, isFalse);
    });

    test('with v2 listed the plugin signatures are accepted', () async {
      final k = await keys([(200, '{"enrolled":false,"signatureVersions":["v1","v2"]}', const {})]);
      final status = await k.status();
      expect(status.enrolled, isFalse);
      expect(status.signatureVersionsDeclared, isTrue);
      expect(status.acceptsPluginSignatures, isTrue);
    });
  });

  test('revoke posts the revocation, then discards the local key', () async {
    debugDefaultTargetPlatformOverride = TargetPlatform.android;
    final k = await keys([(204, '', const {})]);
    await k.revoke();
    expect(platform.signed.single['operation'], 'tx_key_revoke');
    expect(adapter.seen.single.path, SentomaruTransactionKeys.defaultRevocationsPath);
    expect(platform.tx.map((c) => c.method), ['txDiscard']);
  });

  test('revoke failure keeps the local key', () async {
    debugDefaultTargetPlatformOverride = TargetPlatform.android;
    final k = await keys([(503, '{"code":"sentomaru-unavailable"}', const {})]);
    await expectLater(k.revoke(), throwsA(isA<SentomaruTransactionKeyException>().having((e) => e.code, 'code', 'sentomaru-unavailable')));
    expect(platform.tx, isEmpty);
  });

  test('signedExtra signs the exact bytes and returns the interceptor extra entries', () async {
    debugDefaultTargetPlatformOverride = TargetPlatform.android;
    const header = 'sentomaru-tx-v2.AAAAAAAAAAAAAAAAAAAAAA.1763028000.sig';
    platform.txReply = (method, _) => method == 'txSign' ? header : null;
    final k = await keys([(200, '{}', const {})]);
    final body = Uint8List.fromList(utf8.encode('{"valor":"10.00"}'));

    final extra = await k.signedExtra(operationId: 'op-1', body: body, reason: 'Confirmar');
    expect(extra, {'sentomaru_tx_signature': header, 'sentomaru_operation_id': 'op-1'});
    final sign = platform.tx.single.args!;
    expect(sign['operationId'], 'op-1');
    expect(sign['body'], body);

    await dio.post<Object?>('/api/pagamentos', data: body, options: Options(extra: {'sentomaru_operation': 'pagar', ...extra}));
    expect(adapter.bodies.single, body);
    expect(platform.signed.single['optional'], {'x-sentomaru-operation-id': 'op-1', 'x-sentomaru-tx-signature': header});
  });

  group('Retry-After', () {
    final now = DateTime.utc(2026, 11, 13, 10);

    test('seconds, clamped to 1 s..24 h; negative or garbage is null', () {
      Duration? p(String? v) => SentomaruTransactionKeyException.parseRetryAfter(v, now: now);
      expect(p('30'), const Duration(seconds: 30));
      expect(p(' 0 '), const Duration(seconds: 1));
      expect(p('999999'), const Duration(hours: 24));
      expect(p('-5'), isNull);
      expect(p('soon'), isNull);
      expect(p(''), isNull);
      expect(p(null), isNull);
    });

    test('HTTP-date relative to now; a past date is null', () {
      Duration? p(String v) => SentomaruTransactionKeyException.parseRetryAfter(v, now: now);
      expect(p(HttpDate.format(now.add(const Duration(minutes: 2)))), const Duration(minutes: 2));
      expect(p('Fri, 13 Nov 2026 10:00:30 GMT'), const Duration(seconds: 30));
      expect(p(HttpDate.format(now.subtract(const Duration(minutes: 1)))), isNull);
    });
  });
}
