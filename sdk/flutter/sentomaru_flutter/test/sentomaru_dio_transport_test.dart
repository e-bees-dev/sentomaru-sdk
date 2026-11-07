// Real-transport tests for SentomaruDioInterceptor: real Dio + IOHttpClientAdapter + loopback TLS servers.
// Only the native signer is replaced (unit tests have no Android Keystore); redirect handling, header policy,
// fail-closed initialization and the bytes on the wire are the production code paths.
//
// Hosts: 127.0.0.1 and 127.0.0.2 are allowlisted, 127.0.0.3 is outside the allowlist (Linux routes 127/8 to lo).
import 'dart:convert';
import 'dart:io';
import 'dart:isolate';
import 'dart:typed_data';

import 'package:dio/dio.dart';
import 'package:dio/io.dart';
import 'package:flutter_test/flutter_test.dart';
import 'package:sentomaru_flutter/sentomaru_flutter.dart';

import 'support/loopback_tls.dart';

const _allowedA = '127.0.0.1';
const _allowedB = '127.0.0.2';
const _external = '127.0.0.3';

class _Recorded {
  final String method;
  final Uri uri;
  final HttpHeaders headers;
  final List<int> body;
  _Recorded(this.method, this.uri, this.headers, this.body);
  String? header(String name) => headers.value(name);
}

typedef _Responder = void Function(HttpResponse response);

class _TlsServer {
  final HttpServer _server;
  final List<_Recorded> requests = [];
  final List<_Responder> _queue = [];

  _TlsServer._(this._server) {
    _server.listen((request) async {
      final body = await request.fold<List<int>>(<int>[], (acc, chunk) => acc..addAll(chunk));
      requests.add(_Recorded(request.method, request.requestedUri, request.headers, body));
      final responder = _queue.isEmpty ? _ok : _queue.removeAt(0);
      responder(request.response);
      await request.response.close();
    });
  }

  static Future<_TlsServer> start(String address) async =>
      _TlsServer._(await HttpServer.bindSecure(address, 0, loopbackServerContext()));

  int get port => _server.port;
  String url(String host, String path) => 'https://$host:$port$path';
  void enqueue(_Responder responder) => _queue.add(responder);
  Future<void> close() => _server.close(force: true);

  static void _ok(HttpResponse r) {
    r.statusCode = 200;
    r.headers.contentType = ContentType.json;
    r.write('{"ok":true}');
  }
}

_Responder _redirect(int code, String location) => (r) {
      r.statusCode = code;
      r.headers.set('location', location);
    };

/// Stands in for the Android Keystore only. Records what it was asked to sign.
class _RecordingSigner extends SentomaruFlutterPlatform {
  final List<Map<String, Object>> calls = [];
  bool failInitialize = false;

  @override
  Future<void> initialize(SentomaruConfig config) async {
    if (failInitialize) {
      throw const SentomaruException(SentomaruErrorCode.channelError, 'native initialize failed');
    }
  }

  @override
  Future<InstallationState> state() async => InstallationState.enrolled;

  @override
  Future<SignedMessageHeaders> sign({
    required String method,
    required String targetUri,
    required String operation,
    required Uint8List bodyBytes,
    Map<String, String> optionalHeaders = const {},
  }) async {
    calls.add({'method': method, 'targetUri': targetUri, 'operation': operation, 'body': bodyBytes});
    return SignedMessageHeaders({
      ...optionalHeaders, // the native core returns the optional headers it signed
      'Signature': 'sig1=:${calls.length}:',
      'Signature-Input': 'sig1=("@method" "@target-uri");nonce="n${calls.length}"',
      'Content-Digest': 'sha-256=:d:',
      'x-sentomaru-profile': 'sentomaru-p0',
      'x-sentomaru-org': 'ebees',
      'x-sentomaru-app': 'example-app',
      'x-sentomaru-environment': 'dev',
      'x-sentomaru-session': 'sess-1',
      'x-sentomaru-operation': operation,
    });
  }
}

Dio _realDio() => Dio()
  ..httpClientAdapter = IOHttpClientAdapter(
    createHttpClient: () => HttpClient()..badCertificateCallback = (cert, host, port) => true,
  );

void _expectNoSentomaruHeaders(_Recorded r) {
  for (final name in [
    'signature',
    'signature-input',
    'content-digest',
    'x-sentomaru-profile',
    'x-sentomaru-org',
    'x-sentomaru-app',
    'x-sentomaru-environment',
    'x-sentomaru-session',
    'x-sentomaru-operation',
    'x-sentomaru-signals',
  ]) {
    expect(r.header(name), isNull, reason: '$name must not be sent');
  }
}

/// Entry point of a fresh isolate: only the URL crosses over, as in a WorkManager engine.
class _BackgroundJob {
  final String url;
  _BackgroundJob(this.url);
  Future<String> run() => _backgroundJob(url);
}

Future<String> _backgroundJob(String url) async {
  final background = Dio()
    ..httpClientAdapter = IOHttpClientAdapter(
      createHttpClient: () => HttpClient()..badCertificateCallback = (c, h, p) => true,
    )
    ..addSentomaru(SentomaruClient()); // real default platform; this isolate never called initialize()
  try {
    await background.post(url, data: {'job': 1}, options: Options(headers: {'x-sentomaru-operation': 'sync'}));
    return 'sent';
  } on DioException catch (e) {
    final err = e.error;
    return err is SentomaruException ? err.code.name : 'other:${e.type}';
  }
}

SentomaruErrorCode? _codeOf(Object e) =>
    e is DioException && e.error is SentomaruException ? (e.error as SentomaruException).code : null;

void main() {
  late _TlsServer a;
  late _TlsServer b;
  late _TlsServer ext;
  late _RecordingSigner signer;
  late SentomaruClient client;
  late Dio dio;

  setUp(() async {
    a = await _TlsServer.start(_allowedA);
    b = await _TlsServer.start(_allowedB);
    ext = await _TlsServer.start(_external);
    signer = _RecordingSigner();
    client = SentomaruClient(platform: signer);
    await client.initialize(SentomaruConfig(
      organization: 'ebees',
      app: 'example-app',
      environment: 'dev',
      enrollmentUrl: a.url(_allowedA, '/enroll'),
      allowedHosts: const {_allowedA, _allowedB},
    ));
    dio = _realDio()..addSentomaru(client);
  });

  tearDown(() async {
    await a.close();
    await b.close();
    await ext.close();
  });

  Future<Response<dynamic>> signedPost(String url, Object body) => dio.post(
        url,
        data: body,
        options: Options(headers: {
          'x-sentomaru-operation': 'submit',
          'Authorization': 'Bearer user-token',
          'Cookie': 'session=user-cookie',
        }),
      );

  group('FLT-2 (real transport): bytes on the wire are the signed bytes', () {
    test('POST body received by the server equals the frozen bytes passed to the signer', () async {
      final payload = {'b': 'é', 'a': 1, 'nested': [1, 2]};
      await signedPost(a.url(_allowedA, '/v1/ping'), payload);

      expect(signer.calls, hasLength(1));
      final signedBytes = signer.calls.single['body'] as Uint8List;
      final received = a.requests.single;
      expect(received.body, signedBytes, reason: 'Content-Digest covers exactly what Dio wrote');
      expect(utf8.decode(received.body), jsonEncode(payload));
      expect(received.header('content-type'), 'application/json');
      expect(received.header('signature'), 'sig1=:1:');
    });
  });

  group('R2 redirects (real transport)', () {
    test('307 to another allowed host: POST + same bytes re-signed for the new target, credentials dropped',
        () async {
      final target = b.url(_allowedB, '/v1/moved?x=1');
      a.enqueue(_redirect(307, target));

      final response = await signedPost(a.url(_allowedA, '/v1/source'), {'id': 7});
      expect(response.statusCode, 200);

      final second = b.requests.single;
      expect(second.uri.scheme, 'https');
      expect(second.method, 'POST');
      expect(second.body, a.requests.single.body);
      expect(utf8.decode(second.body), '{"id":7}');
      expect(signer.calls, hasLength(2));
      expect(signer.calls.last['targetUri'], target);
      expect(second.header('signature'), 'sig1=:2:', reason: 'fresh signature for the new @target-uri');
      expect(second.header('authorization'), isNull);
      expect(second.header('cookie'), isNull);
    });

    for (final code in [301, 302, 303]) {
      test('$code on the same allowed host becomes an unsigned GET without body', () async {
        a.enqueue(_redirect(code, '/v1/result'));

        final response = await signedPost(a.url(_allowedA, '/v1/submit'), {'id': 1});
        expect(response.statusCode, 200);

        expect(a.requests, hasLength(2));
        final second = a.requests[1];
        expect(second.uri.scheme, 'https');
        expect(second.uri.path, '/v1/result');
        expect(second.method, 'GET');
        expect(second.body, isEmpty);
        expect(second.header('content-type'), isNull);
        _expectNoSentomaruHeaders(second);
        expect(second.header('authorization'), 'Bearer user-token', reason: 'same host keeps caller auth');
        expect(signer.calls, hasLength(1), reason: 'the GET is not the signed operation');
      });
    }

    test('303 then 307 keeps GET and resolves Location against the current hop', () async {
      a.enqueue(_redirect(303, '/b/hop'));
      a.enqueue(_redirect(307, 'c'));

      await signedPost(a.url(_allowedA, '/a/start'), {'id': 1});

      expect(a.requests.map((r) => r.method), ['POST', 'GET', 'GET']);
      expect(a.requests[2].uri.path, '/b/c');
      expect(a.requests[2].body, isEmpty);
      _expectNoSentomaruHeaders(a.requests[2]);
    });

    for (final code in [302, 307]) {
      test('$code to a host outside the allowlist is not followed; nothing reaches it', () async {
        a.enqueue(_redirect(code, ext.url(_external, '/landing')));

        await expectLater(
          signedPost(a.url(_allowedA, '/v1/out'), {'secret': true}),
          throwsA(isA<DioException>().having((e) => e.response?.statusCode, 'status', code)),
        );
        expect(ext.requests, isEmpty);
      });
    }

    test('redirect downgrade to http on an allowed host is refused before sending', () async {
      a.enqueue(_redirect(302, 'http://$_allowedB:${b.port}/plain'));

      await expectLater(
        signedPost(a.url(_allowedA, '/v1/downgrade'), {'id': 1}),
        throwsA(predicate((e) => _codeOf(e!) == SentomaruErrorCode.hostNotAllowed)),
      );
      expect(a.requests, hasLength(1));
      expect(b.requests, isEmpty);
    });

    test('308 to another allowed host keeps POST and bytes and is re-signed', () async {
      final target = b.url(_allowedB, '/v1/permanent');
      a.enqueue(_redirect(308, target));
      await signedPost(a.url(_allowedA, '/v1/old'), {'id': 9});
      final second = b.requests.single;
      expect(second.method, 'POST');
      expect(utf8.decode(second.body), '{"id":9}');
      expect(signer.calls.last['targetUri'], target);
      expect(second.header('authorization'), isNull);
      expect(second.header('cookie'), isNull);
    });

    for (final code in [301, 302]) {
      test('$code to another allowed host: unsigned GET, Authorization and Cookie dropped', () async {
        a.enqueue(_redirect(code, b.url(_allowedB, '/landing')));
        await signedPost(a.url(_allowedA, '/v1/submit'), {'id': 1});
        final second = b.requests.single;
        expect(second.method, 'GET');
        expect(second.body, isEmpty);
        expect(second.header('authorization'), isNull);
        expect(second.header('cookie'), isNull);
        _expectNoSentomaruHeaders(second);
      });
    }

    test('307 downgrade to http on an allowed host is refused', () async {
      a.enqueue(_redirect(307, 'http://$_allowedB:${b.port}/plain'));
      await expectLater(
        signedPost(a.url(_allowedA, '/v1/d307'), {'id': 1}),
        throwsA(predicate((e) => _codeOf(e!) == SentomaruErrorCode.hostNotAllowed)),
      );
      expect(b.requests, isEmpty);
    });

    test('hop limit is 5 (same as OkHttp): the 6th 3xx goes back to the caller', () async {
      for (var i = 0; i < SentomaruDioInterceptor.maxRedirects + 1; i++) {
        a.enqueue(_redirect(302, '/loop$i'));
      }
      await expectLater(
        signedPost(a.url(_allowedA, '/loop'), {'id': 1}),
        throwsA(isA<DioException>().having((e) => e.response?.statusCode, 'status', 302)),
      );
      expect(SentomaruDioInterceptor.maxRedirects, 5);
      expect(a.requests, hasLength(6));
    });

    test('follow-up hops do not re-run app interceptors, so none can re-add credentials cross-host', () async {
      var authRuns = 0;
      final appDio = _realDio()
        ..addSentomaru(client)
        ..interceptors.add(InterceptorsWrapper(onRequest: (o, h) {
          authRuns++;
          o.headers['Authorization'] = 'Bearer from-app-interceptor';
          h.next(o);
        }));
      a.enqueue(_redirect(307, b.url(_allowedB, '/v1/next')));

      await appDio.post(a.url(_allowedA, '/v1/start'),
          data: {'id': 1}, options: Options(headers: {'x-sentomaru-operation': 'submit'}));

      expect(a.requests.single.header('authorization'), 'Bearer from-app-interceptor');
      expect(b.requests.single.header('authorization'), isNull);
      expect(authRuns, 1);
      expect(b.requests.single.header('signature'), isNotNull);
    });
  });

  group('R1 fail closed when the Dart client is not initialized (real transport)', () {
    test('boot: declared operation is refused with notInitialized and never sent', () async {
      final uninitialized = SentomaruClient(); // real MethodChannel platform, initialize() not called yet
      final bootDio = _realDio()..addSentomaru(uninitialized);

      await expectLater(
        bootDio.post(a.url(_allowedA, '/v1/protected'),
            data: {'a': 1}, options: Options(extra: {'sentomaru_operation': 'submit'})),
        throwsA(predicate((e) => _codeOf(e!) == SentomaruErrorCode.notInitialized)),
      );
      expect(a.requests, isEmpty);
    });

    test('boot: undeclared request passes through with Sentomaru headers stripped (not covered)', () async {
      final bootDio = _realDio()..addSentomaru(SentomaruClient());
      await bootDio.get(a.url(_allowedA, '/public'), options: Options(headers: {'Signature': 'forged'}));
      _expectNoSentomaruHeaders(a.requests.single);
    });

    test('hot restart: a fresh Dart client (new heap) refuses until re-initialized', () async {
      // Before restart the app was initialized and signing (setUp). A hot restart discards Dart state; the
      // re-created client starts uninitialized while the native installation persists.
      final afterRestart = SentomaruClient(platform: signer);
      final restartedDio = _realDio()..addSentomaru(afterRestart);

      await expectLater(
        restartedDio.post(a.url(_allowedA, '/v1/p'), data: {}, options: Options(headers: {'x-sentomaru-operation': 's'})),
        throwsA(predicate((e) => _codeOf(e!) == SentomaruErrorCode.notInitialized)),
      );
      expect(a.requests, isEmpty);
      expect(signer.calls, isEmpty);
    });

    test('failed native initialize leaves the client uninitialized (no half-initialized signing)', () async {
      final failing = _RecordingSigner()..failInitialize = true;
      final c = SentomaruClient(platform: failing);
      await expectLater(
        c.initialize(SentomaruConfig(
          organization: 'ebees',
          app: 'example-app',
          environment: 'dev',
          enrollmentUrl: a.url(_allowedA, '/enroll'),
          allowedHosts: const {_allowedA},
        )),
        throwsA(isA<SentomaruException>()),
      );
      expect(c.isInitialized, isFalse);
      final d = _realDio()..addSentomaru(c);
      await expectLater(
        d.post(a.url(_allowedA, '/v1/p'), data: {}, options: Options(headers: {'x-sentomaru-operation': 's'})),
        throwsA(predicate((e) => _codeOf(e!) == SentomaruErrorCode.notInitialized)),
      );
      expect(a.requests, isEmpty);
    });

    test('background isolate (WorkManager-style) without initialize: refused, never sent', () async {
      final url = a.url(_allowedA, '/v1/background');
      final code = await Isolate.run(_BackgroundJob(url).run);
      expect(code, SentomaruErrorCode.notInitialized.name);
      expect(a.requests, isEmpty);
    });
  });

  group('G-03c: route table and redirects (real transport)', () {
    late Dio routed;
    setUp(() {
      routed = _realDio()
        ..addSentomaru(client,
            routes: SentomaruRoutes(hosts: const [_allowedA, _allowedB], routes: [SentomaruRoute('/v1/demandas/*', 'concluir')]));
    });

    for (final code in [307, 308]) {
      test('$code of a route-derived operation is re-signed for the new target with the same operation', () async {
        final target = b.url(_allowedB, '/v1/demandas/9');
        a.enqueue(_redirect(code, target));
        expect((await routed.post(a.url(_allowedA, '/v1/demandas/1'), data: {'id': 1})).statusCode, 200);
        expect(signer.calls.map((c) => c['operation']), ['concluir', 'concluir']);
        expect(signer.calls.last['targetUri'], target);
        expect(b.requests.single.method, 'POST');
        expect(b.requests.single.header('x-sentomaru-operation'), 'concluir');
        expect(b.requests.single.header('signature'), 'sig1=:2:');
      });
    }

    test('302 to a path that also matches a route stays an unsigned GET (the hop never takes the table)', () async {
      a.enqueue(_redirect(302, '/v1/demandas/9'));
      expect((await routed.post(a.url(_allowedA, '/v1/demandas/1'), data: {'id': 1})).statusCode, 200);
      expect(a.requests, hasLength(2));
      expect(a.requests[1].method, 'GET');
      _expectNoSentomaruHeaders(a.requests[1]);
      expect(signer.calls, hasLength(1), reason: 'only the caller request is the signed operation');
    });
  });
}
