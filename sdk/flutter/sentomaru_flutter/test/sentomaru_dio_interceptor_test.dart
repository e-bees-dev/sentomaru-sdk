import 'dart:convert';
import 'dart:typed_data';

import 'package:dio/dio.dart';
import 'package:flutter/services.dart' show PlatformException;
import 'package:flutter_test/flutter_test.dart';
import 'package:sentomaru_flutter/sentomaru_flutter.dart';

class InterceptorFakePlatform implements SentomaruFlutterPlatform {
  @override
  bool get signalEventsSupported => false;

  @override
  Stream<Object?> signalEvents() => const Stream.empty();

  @override
  Future<ReenrollmentReason?> reenrollmentReason() async => null;

  final List<Map<String, dynamic>> signedCalls = [];

  @override
  Future<String?> scaffoldInfo() async => 'fake:0.0.1';

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
    signedCalls.add({
      'method': method,
      'targetUri': targetUri,
      'operation': operation,
      'bodyBytes': bodyBytes,
      'optional': optionalHeaders,
    });

    return SignedMessageHeaders({
      ...optionalHeaders, // the native core returns the optional headers it signed
      'Signature': 'sig1=:mock_signature:',
      'Signature-Input': 'sig1=("@method" "@target-uri" "content-digest");created=1000',
      'Content-Digest': 'sha-256=:mock_digest:',
      'x-sentomaru-operation': operation,
      'x-sentomaru-session': 'sess-1',
    });
  }

  @override
  Future<void> reset() async {}

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
  Future<String?> sessionId() async => 'sess-1';

  /// J-04r: renewals answered by the fake (count) and whether the next renewal fails.
  int renewals = 0;
  bool renewalFails = false;

  /// When set, the next renewals throw this error (as the native side would map it).
  SentomaruException? renewalError;

  @override
  Future<String> renewSession() async {
    renewals++;
    final error = renewalError;
    if (error != null) throw error;
    if (renewalFails) throw const SentomaruException(SentomaruErrorCode.channelError, 'renewal failed');
    return 'sess-2';
  }
}

/// Dio adapter without network I/O that records the options AND the bytes Dio actually streamed (requestStream).
class EchoHttpClientAdapter implements HttpClientAdapter {
  RequestOptions? lastRequest;
  List<int>? lastBodyBytes;

  @override
  Future<ResponseBody> fetch(
    RequestOptions options,
    Stream<Uint8List>? requestStream,
    Future<void>? cancelFuture,
  ) async {
    lastRequest = options;
    lastBodyBytes = requestStream == null
        ? null
        : await requestStream.fold<List<int>>(<int>[], (acc, chunk) => acc..addAll(chunk));
    return ResponseBody.fromString(
      '{"status":"ok"}',
      200,
      headers: {
        Headers.contentTypeHeader: [Headers.jsonContentType],
      },
    );
  }

  @override
  void close({bool force = false}) {}
}

class _MockErrorAdapter implements HttpClientAdapter {
  final int statusCode;
  final String responseJson;

  _MockErrorAdapter({required this.statusCode, required this.responseJson});

  @override
  Future<ResponseBody> fetch(
    RequestOptions options,
    Stream<Uint8List>? requestStream,
    Future<void>? cancelFuture,
  ) async {
    return ResponseBody.fromString(
      responseJson,
      statusCode,
      headers: {
        Headers.contentTypeHeader: [Headers.jsonContentType],
      },
    );
  }

  @override
  void close({bool force = false}) {}
}

void main() {
  const testConfig = SentomaruConfig(
    organization: 'ebees',
    app: 'example-app',
    environment: 'dev',
    enrollmentUrl: 'https://api.ebees.com.br/enroll',
    allowedHosts: {'api.ebees.com.br'},
  );

  late InterceptorFakePlatform fakePlatform;
  late SentomaruClient client;
  late EchoHttpClientAdapter adapter;
  late Dio dio;

  setUp(() async {
    fakePlatform = InterceptorFakePlatform();
    client = SentomaruClient(platform: fakePlatform);
    await client.initialize(testConfig);

    adapter = EchoHttpClientAdapter();
    dio = Dio()..httpClientAdapter = adapter;
    dio.addSentomaru(client);
  });

  group('FLT-2 (fake platform): Dio interceptor signs final bytes and attaches headers', () {
    test('POST with JSON map is frozen to exact bytes, signed, and has headers attached', () async {
      final payload = {'action': 'ping', 'count': 42};

      final response = await dio.post(
        'https://api.ebees.com.br/v1/ping',
        data: payload,
        options: Options(
          headers: {'x-sentomaru-operation': 'test_ping'},
        ),
      );

      expect(response.statusCode, 200);

      // Verify sign was called on native client
      expect(fakePlatform.signedCalls.length, 1);
      final call = fakePlatform.signedCalls.first;
      expect(call['method'], 'POST');
      expect(call['targetUri'], 'https://api.ebees.com.br/v1/ping');
      expect(call['operation'], 'test_ping');

      final expectedBytes = Uint8List.fromList(utf8.encode(jsonEncode(payload)));
      expect(call['bodyBytes'], expectedBytes);

      // Verify final request sent over the wire
      final sentReq = adapter.lastRequest!;
      expect(sentReq.headers['Signature'], 'sig1=:mock_signature:');
      expect(sentReq.headers['Signature-Input'], 'sig1=("@method" "@target-uri" "content-digest");created=1000');
      expect(sentReq.headers['Content-Digest'], 'sha-256=:mock_digest:');
      expect(sentReq.headers['content-type'], 'application/json');

      // Crucial: the bytes Dio streamed to the adapter are exactly the signed bytes (Decision E2)
      expect(adapter.lastBodyBytes, expectedBytes);
    });

    test('POST with String body freezes exact UTF-8 bytes', () async {
      const payloadString = '{"user":"technician"}';

      await dio.post(
        'https://api.ebees.com.br/v1/update',
        data: payloadString,
        options: Options(
          extra: {'sentomaru_operation': 'update_user'},
        ),
      );

      expect(fakePlatform.signedCalls.length, 1);
      final call = fakePlatform.signedCalls.first;
      expect(call['operation'], 'update_user');
      expect(call['bodyBytes'], Uint8List.fromList(utf8.encode(payloadString)));
      expect(adapter.lastBodyBytes, Uint8List.fromList(utf8.encode(payloadString)));
    });

    test('Empty body POST freezes zero bytes', () async {
      await dio.post(
        'https://api.ebees.com.br/v1/empty',
        options: Options(
          headers: {'x-sentomaru-operation': 'empty_op'},
        ),
      );

      expect(fakePlatform.signedCalls.length, 1);
      final call = fakePlatform.signedCalls.first;
      expect(call['bodyBytes'], Uint8List(0));
    });
  });

  group('J-01f2: optional covered headers are signed by the native core', () {
    test('signals and the operation id go to the native signer and come back signed', () async {
      await dio.post(
        'https://api.ebees.com.br/v1/charge',
        data: {'v': 1},
        options: Options(headers: {
          'x-sentomaru-operation': 'charge',
          'x-sentomaru-operation-id': 'op-0123456789abcdef',
          'x-sentomaru-signals': '{"catalogVersion":"1.1.0","observations":[]}',
        }),
      );
      final optional = fakePlatform.signedCalls.single['optional'] as Map<String, String>;
      expect(optional['x-sentomaru-operation-id'], 'op-0123456789abcdef');
      expect(optional['x-sentomaru-signals'], '{"catalogVersion":"1.1.0","observations":[]}');
      expect(adapter.lastRequest!.headers['x-sentomaru-operation-id'], 'op-0123456789abcdef');
    });
  });

  group('D-25: the transaction signature is a covered optional header', () {
    final tx = 'sentomaru-tx-v1.${'A' * 22}.${'B' * 86}';

    test('the header (or extra) goes to the native signer and comes back signed', () async {
      await dio.post(
        'https://api.ebees.com.br/v1/charge',
        data: {'v': 1},
        options: Options(headers: {
          'x-sentomaru-operation': 'charge',
          'x-sentomaru-operation-id': 'op-0123456789abcdef',
          'X-Sentomaru-Tx-Signature': tx,
        }),
      );
      final optional = fakePlatform.signedCalls.single['optional'] as Map<String, String>;
      expect(optional['x-sentomaru-tx-signature'], tx);
      expect(adapter.lastRequest!.headers['x-sentomaru-tx-signature'], tx);

      fakePlatform.signedCalls.clear();
      await dio.post(
        'https://api.ebees.com.br/v1/charge',
        data: {'v': 2},
        options: Options(headers: {'x-sentomaru-operation': 'charge'}, extra: {'sentomaru_tx_signature': tx}),
      );
      expect((fakePlatform.signedCalls.single['optional'] as Map<String, String>)['x-sentomaru-tx-signature'], tx);
    });

    test('a request without it sends no such optional header', () async {
      await dio.post('https://api.ebees.com.br/v1/charge', data: {'v': 1}, options: Options(headers: {'x-sentomaru-operation': 'charge'}));
      expect((fakePlatform.signedCalls.single['optional'] as Map<String, String>).containsKey('x-sentomaru-tx-signature'), isFalse);
    });
  });

  group('FLT-3 (fake platform): Multiple Dio clients and explicit coverage declaration', () {
    test('Two distinct Dio instances sharing SentomaruClient sign concurrently without interference', () async {
      final adapter1 = EchoHttpClientAdapter();
      final adapter2 = EchoHttpClientAdapter();

      final dio1 = Dio()..httpClientAdapter = adapter1;
      dio1.addSentomaru(client);

      final dio2 = Dio()..httpClientAdapter = adapter2;
      dio2.addSentomaru(client);

      // Execute concurrent requests on both Dio instances
      final future1 = dio1.post(
        'https://api.ebees.com.br/v1/flow1',
        data: {'flow': 1},
        options: Options(headers: {'x-sentomaru-operation': 'flow_one'}),
      );

      final future2 = dio2.post(
        'https://api.ebees.com.br/v1/flow2',
        data: {'flow': 2},
        options: Options(headers: {'x-sentomaru-operation': 'flow_two'}),
      );

      await Future.wait([future1, future2]);

      expect(adapter1.lastRequest!.headers['x-sentomaru-operation'], 'flow_one');
      expect(adapter2.lastRequest!.headers['x-sentomaru-operation'], 'flow_two');
      expect(adapter1.lastRequest!.headers['Signature'], isNotNull);
      expect(adapter2.lastRequest!.headers['Signature'], isNotNull);
    });

    test('Unconfigured Dio instance remains unsigned (Coverage Declaration per Decision E6)', () async {
      final unconfiguredAdapter = EchoHttpClientAdapter();
      final unconfiguredDio = Dio()..httpClientAdapter = unconfiguredAdapter;

      await unconfiguredDio.post(
        'https://api.ebees.com.br/v1/unprotected',
        data: {'unprotected': true},
        options: Options(headers: {'x-sentomaru-operation': 'should_be_ignored'}),
      );

      // Interceptor was never added: no signing occurred
      expect(fakePlatform.signedCalls, isEmpty);
      expect(unconfiguredAdapter.lastRequest!.headers['Signature'], isNull);
      expect(unconfiguredAdapter.lastRequest!.headers['Signature-Input'], isNull);
      expect(unconfiguredAdapter.lastRequest!.headers['Content-Digest'], isNull);
    });
  });

  group('Security and Allowlist Enforcement (Decision E6)', () {
    test('Host outside allowlist: undeclared request passes unsigned with Sentomaru headers stripped (SDK-NET-1)',
        () async {
      await dio.post(
        'https://third-party.example.com/analytics',
        data: {'event': 'click'},
        options: Options(headers: {'Signature': 'should_be_stripped', 'Content-Digest': 'should_be_stripped'}),
      );
      expect(fakePlatform.signedCalls, isEmpty);
      final sentHeaders = adapter.lastRequest!.headers;
      expect(sentHeaders['Signature'], isNull);
      expect(sentHeaders['Content-Digest'], isNull);
    });

    test('Host outside allowlist: declared operation is refused with hostNotAllowed, never sent (M1)', () async {
      await expectLater(
        dio.post('https://third-party.example.com/x',
            data: {'a': 1}, options: Options(headers: {'x-sentomaru-operation': 'leaked_op'})),
        throwsA(isA<DioException>().having(
            (e) => (e.error as SentomaruException).code, 'code', SentomaruErrorCode.hostNotAllowed)),
      );
      expect(adapter.lastRequest, isNull);
      expect(fakePlatform.signedCalls, isEmpty);
    });

    test('Allowed host with HTTP scheme is rejected with HostNotAllowed (SDK-NET-3)', () async {
      expect(
        () => dio.post(
          'http://api.ebees.com.br/v1/insecure',
          data: {'data': 1},
          options: Options(headers: {'x-sentomaru-operation': 'insecure_op'}),
        ),
        throwsA(isA<DioException>().having(
          (e) => (e.error as SentomaruException).code,
          'error.code',
          SentomaruErrorCode.hostNotAllowed,
        )),
      );
    });

    test('Allowed host without operation proceeds unsigned', () async {
      await dio.get('https://api.ebees.com.br/v1/health');

      expect(fakePlatform.signedCalls, isEmpty);
      expect(adapter.lastRequest!.headers['Signature'], isNull);
    });

    test('Percent-encoded URI is signed with exactly the URI Dio sends (SDK-SIGN-7)', () async {
      // Dio hands the interceptor an already-parsed Uri, so its canonical re-parse check cannot diverge for Dio;
      // what matters is that the signed @target-uri equals the URI on the wire.
      await dio.post(
        'https://api.ebees.com.br/v1/test%20space?q=a%2Fb',
        data: {},
        options: Options(headers: {'x-sentomaru-operation': 'test'}),
      );
      expect(fakePlatform.signedCalls.single['targetUri'], 'https://api.ebees.com.br/v1/test%20space?q=a%2Fb');
      expect(adapter.lastRequest!.uri.toString(), fakePlatform.signedCalls.single['targetUri']);
    });

    test('Invalid Content-Type is rejected with invalidRequest (Task 1 review M7 / SIGN-6)', () async {
      expect(
        () => dio.post(
          'https://api.ebees.com.br/v1/upload',
          data: 'text',
          options: Options(
            headers: {
              'x-sentomaru-operation': 'upload',
              'content-type': 'text/plain',
            },
          ),
        ),
        throwsA(isA<DioException>().having(
          (e) => (e.error as SentomaruException).code,
          'error.code',
          SentomaruErrorCode.invalidRequest,
        )),
      );
    });

    test('Body exceeding 64 KiB is rejected with BodyTooLarge (Decision E2 / SDK-SIGN-2)', () async {
      final hugeData = Uint8List(65537); // 64 KiB + 1 byte

      expect(
        () => dio.post(
          'https://api.ebees.com.br/v1/huge',
          data: hugeData,
          options: Options(headers: {'x-sentomaru-operation': 'huge_op'}),
        ),
        throwsA(isA<DioException>().having(
          (e) => (e.error as SentomaruException).code,
          'error.code',
          SentomaruErrorCode.bodyTooLarge,
        )),
      );
    });
  });

  group('FLT-8 (fake platform; proves no Dart-side UI dependency, not native biometrics)', () {
    test('Interceptor signs completely synchronously/asynchronously without UI thread blocking', () async {
      final stopwatch = Stopwatch()..start();

      await dio.post(
        'https://api.ebees.com.br/v1/fast',
        data: {'fast': true},
        options: Options(headers: {'x-sentomaru-operation': 'fast_op'}),
      );

      stopwatch.stop();
      expect(stopwatch.elapsedMilliseconds, lessThan(500));
      expect(adapter.lastRequest!.headers['Signature'], isNotNull);
    });
  });

  group('P3: Signals envelope propagation in Flutter Dio interceptor', () {
    test('signals header is single printable ASCII, escaped, bounded (Minor 3)', () async {
      await dio.post(
        'https://api.ebees.com.br/v1/signals',
        data: {'test': true},
        options: Options(extra: {
          'sentomaru_operation': 'submit',
          'sentomaru_signals': {'installer': 'lojação ✓ 😀'},
        }),
      );
      final header = adapter.lastRequest!.headers['x-sentomaru-signals'] as String;
      const bs = r'\';
      expect(header, '{"installer":"loja${bs}u00e7${bs}u00e3o ${bs}u2713 ${bs}ud83d${bs}ude00"}');
      expect(header.codeUnits.every((u) => u >= 0x20 && u <= 0x7E), isTrue);
      expect(jsonDecode(header), {'installer': 'lojação ✓ 😀'});

      expect(encodeSignalsHeader('"${'x' * (maxSignalsHeaderLength - 2)}"').length, maxSignalsHeaderLength);
      for (final bad in ['{"a":"x\ny"}', '"${'x' * maxSignalsHeaderLength}"']) {
        expect(() => encodeSignalsHeader(bad),
            throwsA(isA<SentomaruException>().having((e) => e.code, 'code', SentomaruErrorCode.invalidRequest)));
      }

      final sent = adapter.lastRequest;
      Object? error;
      try {
        await dio.post('https://api.ebees.com.br/v1/signals',
            data: {'test': true},
            options: Options(extra: {
              'sentomaru_operation': 'submit',
              'sentomaru_signals': {'pad': 'x' * maxSignalsHeaderLength},
            }));
      } on DioException catch (e) {
        error = e.error;
      }
      expect(error, isA<SentomaruException>().having((e) => e.code, 'code', SentomaruErrorCode.invalidRequest));
      expect(identical(adapter.lastRequest, sent), isTrue, reason: 'refused before sending');
    });

    test('Attaches signals from options.extra to x-sentomaru-signals header', () async {
      final signals = {
        'catalogVersion': '1.0.0',
        'collectedAt': '2026-10-09T10:00:00Z',
        'observations': [
          {'capabilityId': 'root_indicated', 'state': 'NOT_DETECTED'}
        ]
      };

      await dio.post(
        'https://api.ebees.com.br/v1/signals',
        data: {'test': true},
        options: Options(
          extra: {
            'sentomaru_operation': 'submit',
            'sentomaru_signals': signals,
          },
        ),
      );

      expect(adapter.lastRequest, isNotNull);
      final signalsHeader = adapter.lastRequest!.headers['x-sentomaru-signals'];
      expect(signalsHeader, isNotNull);
      expect(signalsHeader, contains('root_indicated'));
      expect(signalsHeader, contains('NOT_DETECTED'));
    });

    test('RiskEvent callback triggers on challenge/deny response (contract 0.3.0)', () async {
      SentomaruRiskEvent? capturedEvent;
      final errorDio = Dio();
      errorDio.addSentomaru(
        client,
        onRiskEvent: (event) {
          capturedEvent = event;
        },
      );
      final errorAdapter = _MockErrorAdapter(
        statusCode: 401,
        responseJson: jsonEncode({
          'status': 'CHALLENGE',
          'riskEvent': {
            'code': 'STEP_UP_BIOMETRIC_REQUIRED',
            'riskIndex': 55,
            'riskBand': 'MEDIUM',
            'reason': 'ROOT_INDICATED',
            'challengeNonce': 'abc-123-nonce',
          }
        }),
      );
      errorDio.httpClientAdapter = errorAdapter;

      try {
        await errorDio.post(
          'https://api.ebees.com.br/v1/protected',
          data: {'amount': 100},
          options: Options(headers: {'x-sentomaru-operation': 'transfer'}),
        );
      } catch (_) {}

      expect(capturedEvent, isNotNull);
      expect(capturedEvent!.code, equals('STEP_UP_BIOMETRIC_REQUIRED'));
      expect(capturedEvent!.riskIndex, equals(55));
      expect(capturedEvent!.riskBand, equals('MEDIUM'));
      expect(capturedEvent!.reason, equals('ROOT_INDICATED'));
      expect(capturedEvent!.challengeNonce, equals('abc-123-nonce'));
    });

    test('legacy threatEvent key is not accepted and absent riskIndex stays null', () async {
      final events = <SentomaruRiskEvent>[];
      final errorDio = Dio();
      errorDio.addSentomaru(client, onRiskEvent: events.add);
      errorDio.httpClientAdapter = _MockErrorAdapter(
        statusCode: 403,
        responseJson: jsonEncode({
          'threatEvent': {'code': 'OLD', 'threatScore': 90, 'reason': 'x'},
        }),
      );
      try {
        await errorDio.post('https://api.ebees.com.br/v1/protected',
            data: {'amount': 1}, options: Options(headers: {'x-sentomaru-operation': 'transfer'}));
      } catch (_) {}
      expect(events, isEmpty);

      final parsed = SentomaruRiskEvent.fromMap({'code': 'C', 'reason': 'r'});
      expect(parsed.riskIndex, isNull);
      expect(parsed.riskBand, isNull);
      expect(parsed.toMap().containsKey('riskIndex'), isFalse);
    });
  });

  group('G-03c: route table of addSentomaru(client, routes: ...) (profile network-signing section)', () {
    SentomaruRoutes routes([List<String> hosts = const ['api.ebees.com.br']]) => SentomaruRoutes(
        hosts: hosts, routes: [SentomaruRoute('/v1/demandas/*/concluir', 'concluir_demanda')]);

    test('a request on a profile route is signed without being tagged', () async {
      final routed = Dio()..httpClientAdapter = adapter;
      routed.addSentomaru(client, routes: routes());
      await routed.post('https://api.ebees.com.br/V1/demandas/42/concluir/', data: {'ok': true});
      expect(fakePlatform.signedCalls.single['operation'], 'concluir_demanda');
      expect(adapter.lastRequest!.headers['Signature'], isNotNull);
    });

    test('a declared operation wins and an uncovered path passes unsigned', () async {
      final routed = Dio()..httpClientAdapter = adapter;
      routed.addSentomaru(client, routes: routes());
      await routed.post('https://api.ebees.com.br/v1/demandas/42/concluir',
          data: {'a': 1}, options: Options(headers: {'x-sentomaru-operation': 'submit'}));
      expect(fakePlatform.signedCalls.single['operation'], 'submit');
      await routed.get('https://api.ebees.com.br/v1/demandas/42/concluir/extra');
      expect(fakePlatform.signedCalls, hasLength(1));
      expect(adapter.lastRequest!.headers['Signature'], isNull);
    });

    test('a route outside the allowlist is refused at installation; before initialize it fails closed', () async {
      expect(() => (Dio()..httpClientAdapter = adapter).addSentomaru(client, routes: routes(['other.example'])),
          throwsArgumentError);
      final cold = Dio()..httpClientAdapter = adapter;
      cold.addSentomaru(SentomaruClient(platform: fakePlatform), routes: routes());
      await expectLater(cold.post('https://api.ebees.com.br/v1/demandas/1/concluir', data: {'a': 1}),
          throwsA(isA<DioException>().having(
              (e) => (e.error as SentomaruException).code, 'code', SentomaruErrorCode.notInitialized)));
      expect(adapter.lastRequest, isNull);
      expect(fakePlatform.signedCalls, isEmpty);
    });

    test('a trailing-dot host is covered and refused; a percent-encoded path is matched decoded', () async {
      final routed = Dio()..httpClientAdapter = adapter;
      routed.addSentomaru(client, routes: routes());
      await expectLater(routed.post('https://api.ebees.com.br./v1/demandas/1/concluir', data: {'a': 1}),
          throwsA(isA<DioException>().having(
              (e) => (e.error as SentomaruException).code, 'code', SentomaruErrorCode.hostNotAllowed)));
      expect(adapter.lastRequest, isNull);
      expect(routes().operationFor(Uri.parse('https://api.ebees.com.br/v1/%64emandas/1/concluir')), 'concluir_demanda');
      expect(routes().operationFor(Uri.parse('https://api.ebees.com.br:8443/v1/demandas/1/concluir')), 'concluir_demanda');
    });

    test('the first matching route wins', () {
      final ordered = SentomaruRoutes(hosts: ['a.example'], routes: [
        SentomaruRoute('/v1/demandas/novo', 'criar_demanda'),
        SentomaruRoute('/v1/demandas/*', 'ler_demanda'),
      ]);
      expect(ordered.operationFor(Uri.parse('https://a.example/v1/demandas/novo')), 'criar_demanda');
      expect(ordered.operationFor(Uri.parse('https://a.example/v1/demandas/7')), 'ler_demanda');
    });

    test('the table follows the profile rules', () {
      final t = SentomaruRoutes.fromProfileSection({
        'version': '1',
        'hosts': ['api.example'],
        'routes': [
          {'path': '/v1/demandas', 'operation': 'criar_demanda'},
          {'path': '/v1/demandas/*', 'operation': 'ler_demanda'},
        ],
      });
      expect(t.operationFor(Uri.parse('https://api.example/v1/demandas/')), 'criar_demanda');
      expect(t.operationFor(Uri.parse('https://api.example/v1/demandas/7?x=1')), 'ler_demanda');
      expect(t.operationFor(Uri.parse('https://api.example/v1/demandas//')), isNull);
      expect(t.operationFor(Uri.parse('https://other.example/v1/demandas')), isNull);
      void refused(List<String> hosts, List<List<String>> rs) => expect(
          () => SentomaruRoutes(hosts: hosts, routes: rs.map((r) => SentomaruRoute(r[0], r[1])).toList()),
          throwsArgumentError);
      refused([], [['/a', 'op']]);
      refused(['API.example'], [['/a', 'op']]);
      refused(['a.example', 'a.example'], [['/a', 'op']]);
      refused(['a.example'], []);
      refused(['a.example'], [['a', 'op']]);
      refused(['a.example'], [['/a?x', 'op']]);
      refused(['a.example'], [['/a*', 'op']]);
      refused(['a.example'], [['/a//b', 'op']]);
      refused(['a.example'], [['/a', 'Op']]);
      refused(['a.example'], [['/a', 'one'], ['/A/', 'two']]);
      expect(() => SentomaruRoutes.fromProfileSection({'version': '2', 'hosts': ['a.example'], 'routes': []}),
          throwsArgumentError);
    });
  });

  group('J-04r: renewal and one resend on session-expired', () {
    const renewing = SentomaruConfig(
      organization: 'ebees',
      app: 'example-app',
      environment: 'hml',
      enrollmentUrl: 'https://api.ebees.com.br/enroll',
      allowedHosts: {'api.ebees.com.br'},
      renewalUrl: 'https://api.ebees.com.br/api/v1/integridade/sessions',
    );

    Future<(Dio, _ScriptedAdapter, InterceptorFakePlatform)> scripted(SentomaruConfig config, List<(int, String)> answers) async {
      final platform = InterceptorFakePlatform();
      final sdk = SentomaruClient(platform: platform);
      await sdk.initialize(config);
      final scriptedAdapter = _ScriptedAdapter(answers);
      final d = Dio()..httpClientAdapter = scriptedAdapter;
      d.addSentomaru(sdk);
      return (d, scriptedAdapter, platform);
    }

    Options op() => Options(extra: {'sentomaru_operation': 'concluir_demanda'});

    test('session-expired renews once and resends once with a fresh signature', () async {
      final (d, a, platform) = await scripted(renewing, [(403, '{"code":"session-expired"}'), (200, '{"ok":true}')]);
      final response = await d.post('https://api.ebees.com.br/v1/demandas/1/concluir', data: {'x': 1}, options: op());
      expect(response.statusCode, 200);
      expect(platform.renewals, 1);
      expect(platform.signedCalls.length, 2);
      expect(a.seen.length, 2);
      expect(a.seen.last.extra['sentomaru_renewed'], isTrue);
    });

    test('a second session-expired goes back to the caller (no loop)', () async {
      final (d, a, platform) = await scripted(renewing, [(403, '{"code":"session-expired"}'), (403, '{"code":"session-expired"}')]);
      await expectLater(d.post('https://api.ebees.com.br/v1/demandas/1/concluir', data: {'x': 1}, options: op()),
          throwsA(isA<DioException>().having((e) => e.response?.statusCode, 'status', 403)));
      expect(platform.renewals, 1);
      expect(a.seen.length, 2);
    });

    test('a failed renewal returns the original refusal; other 403s and no renewalUrl never renew', () async {
      final (d, a, platform) = await scripted(renewing, [(403, '{"code":"session-expired"}')]);
      platform.renewalFails = true;
      await expectLater(d.post('https://api.ebees.com.br/v1/demandas/1/concluir', data: {'x': 1}, options: op()),
          throwsA(isA<DioException>()));
      expect(a.seen.length, 1);

      final (d2, a2, p2) = await scripted(renewing, [(403, '{"code":"operation-context"}')]);
      await expectLater(d2.post('https://api.ebees.com.br/v1/x', data: {'x': 1}, options: op()), throwsA(isA<DioException>()));
      expect((p2.renewals, a2.seen.length), (0, 1));

      final (d3, a3, p3) = await scripted(testConfig, [(403, '{"code":"session-expired"}')]);
      await expectLater(d3.post('https://api.ebees.com.br/v1/x', data: {'x': 1}, options: op()), throwsA(isA<DioException>()));
      expect((p3.renewals, a3.seen.length), (0, 1));
    });

    // Contract v1.5: a suspended installation (operator) refuses the renewal; once released, the user's retry
    // ("Tentar de novo") renews. Neither the suspension nor the backoff refusal may crash the request: the caller gets
    // the original 403 back.
    test('renewSession throwing serverRejected/SUSPENDED returns the original 403; the next try renews', () async {
      final (d, a, platform) = await scripted(renewing, [
        (403, '{"code":"session-expired"}'),
        (403, '{"code":"session-expired"}'),
        (200, '{"ok":true}'),
      ]);
      platform.renewalError = const SentomaruException(
          SentomaruErrorCode.serverRejected, 'ServerRejected:SUSPENDED', 'ServerRejected:SUSPENDED');
      await expectLater(
          d.post('https://api.ebees.com.br/v1/demandas/1/concluir', data: {'x': 1}, options: op()),
          throwsA(isA<DioException>()
              .having((e) => e.response?.statusCode, 'status', 403)
              .having((e) => '${e.response?.data}', 'data', contains('session-expired'))));
      expect((platform.renewals, a.seen.length), (1, 1));

      platform.renewalError = null; // released by the operator
      final response = await d.post('https://api.ebees.com.br/v1/demandas/1/concluir', data: {'x': 1}, options: op());
      expect(response.statusCode, 200);
      expect((platform.renewals, a.seen.length), (2, 3));
    });

    test('renewSession throwing renewalBackoff returns the original 403', () async {
      final (d, a, platform) = await scripted(renewing, [(403, '{"code":"session-expired"}')]);
      platform.renewalError = SentomaruException.fromPlatformException(
          PlatformException(code: 'RenewalBackoff', message: 'RenewalBackoff'));
      expect(platform.renewalError!.code, SentomaruErrorCode.renewalBackoff);
      await expectLater(
          d.post('https://api.ebees.com.br/v1/demandas/1/concluir', data: {'x': 1}, options: op()),
          throwsA(isA<DioException>()
              .having((e) => e.response?.statusCode, 'status', 403)
              .having((e) => '${e.response?.data}', 'data', contains('session-expired'))));
      expect((platform.renewals, a.seen.length), (1, 1));
    });

    test('an unsigned request is never renewed', () async {
      final (d, a, platform) = await scripted(renewing, [(403, '{"code":"session-expired"}')]);
      await expectLater(d.get('https://api.ebees.com.br/v1/public'), throwsA(isA<DioException>()));
      expect((platform.renewals, a.seen.length), (0, 1));
    });

    test('renewalUrl must be https on an allowed host', () {
      for (final bad in ['http://api.ebees.com.br/s', 'https://other.example/s', 'https://u@api.ebees.com.br/s']) {
        final config = SentomaruConfig(organization: 'o', app: 'a', environment: 'e',
            enrollmentUrl: 'https://api.ebees.com.br/enroll', allowedHosts: const {'api.ebees.com.br'}, renewalUrl: bad);
        expect(config.validate, throwsA(isA<SentomaruException>()));
      }
      expect(renewing.toMap()['renewalUrl'], renewing.renewalUrl);
    });
  });
}

/// Answers the scripted (status, json) pairs in order and records every request it saw.
class _ScriptedAdapter implements HttpClientAdapter {
  final List<(int, String)> answers;
  final List<RequestOptions> seen = [];
  _ScriptedAdapter(this.answers);

  @override
  Future<ResponseBody> fetch(RequestOptions options, Stream<Uint8List>? requestStream, Future<void>? cancelFuture) async {
    if (requestStream != null) await requestStream.drain<void>();
    seen.add(options);
    final (status, body) = answers[seen.length - 1];
    return ResponseBody.fromString(body, status, headers: {
      Headers.contentTypeHeader: [Headers.jsonContentType],
    });
  }

  @override
  void close({bool force = false}) {}
}
