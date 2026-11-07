// C-03a: pinning on the Dart side with a real Dio + IOHttpClientAdapter + HttpClient against loopback servers that
// count every byte they receive. Only DNS is replaced (the TCP seam maps the lab names to 127.0.0.1); the TLS
// handshake, host name check, SPKI hash, pin decision and the moment the HttpClient writes are the production paths.
import 'dart:io';
import 'dart:typed_data';

import 'package:dio/dio.dart';
import 'package:dio/io.dart';
import 'package:flutter_test/flutter_test.dart';
import 'package:sentomaru_flutter/sentomaru_flutter.dart';
import 'package:sentomaru_flutter/src/pinning/pinning_install.dart' show installSentomaruPinning;

import 'support/pinning_lab.dart';

late LabPki pki;

Map<String, Object?> _section({bool includeSubdomains = false, String expiration = '2027-03-31'}) => {
      'version': '1',
      'expiration': expiration,
      'domains': [
        {
          'host': 'lab-pin.test',
          'includeSubdomains': includeSubdomains,
          'pins': [pki['a'].opensslPin],
          'backupPins': [pki['b'].opensslPin],
        }
      ],
    };

final _beforeExpiration = DateTime(2027, 3, 30, 12);

SentomaruPins _pins({bool includeSubdomains = false, DateTime? now}) => SentomaruPins.fromProfileSection(
    _section(includeSubdomains: includeSubdomains),
    clock: () => now ?? _beforeExpiration);

Dio _dio(SentomaruPins pins, {CreateHttpClient? createHttpClient}) {
  final dio = Dio()..httpClientAdapter = IOHttpClientAdapter(createHttpClient: createHttpClient);
  final outcome = installSentomaruPinning(dio, pins,
      context: pki.clientContext(), platformSupported: true, connector: loopbackConnector, tlsConnector: loopbackTlsConnector);
  expect(outcome, SentomaruPinningInstall.installed);
  return dio;
}

String? _reason(Object e) {
  if (e is! DioException) return null;
  final err = e.error;
  return err is SentomaruException && err.code == SentomaruErrorCode.pinningRefused ? err.details as String? : null;
}

Future<Object> _failure(Future<Object?> call) async {
  try {
    await call;
  } catch (e) {
    return e;
  }
  fail('the request should have failed');
}

/// A POST with everything a signed request carries: if any of it leaves, the server's byte counter sees it.
Future<Response<dynamic>> _post(Dio dio, String url) => dio.post(url,
    data: Uint8List.fromList(List.filled(512, 0x41)),
    options: Options(headers: {
      'content-type': 'application/json',
      'Authorization': 'Bearer user-token',
      'Signature': 'sig1=:abc:',
      'Signature-Input': 'sig1=("@method");nonce="n1"',
      'x-sentomaru-operation': 'submit',
    }));

void main() {
  setUpAll(() async => pki = await LabPki.create());
  tearDownAll(() => pki.dispose());

  group('pinned host, pin-set active', () {
    for (final key in ['a', 'b']) {
      test('leaf key ${key == 'a' ? 'in pins' : 'in backupPins'} -> the request is sent and answered', () async {
        final server = await CountingServer.tls(pki[key].serverContext());
        addTearDown(server.close);
        final pins = _pins();
        final events = <SentomaruTransportEvent>[];
        pins.events.listen(events.add);

        final response = await _post(_dio(pins), 'https://lab-pin.test:${server.port}/v1/ping');

        expect(response.statusCode, 200);
        expect(server.text.toString(), contains('POST /v1/ping'));
        expect(server.text.toString(), contains('Bearer user-token'));
        await Future<void>.delayed(Duration.zero);
        expect(events, isEmpty);
      });
    }

    test('valid chain for a key that is not pinned -> refused with ZERO request bytes at the server', () async {
      final server = await CountingServer.tls(pki['x'].serverContext());
      addTearDown(server.close);
      final pins = _pins();
      final events = <SentomaruTransportEvent>[];
      pins.events.listen(events.add);

      final e = await _failure(_post(_dio(pins), 'https://lab-pin.test:${server.port}/v1/ping'));

      expect(_reason(e), 'pin_mismatch');
      // The handshake reached the server (so the zero below is about the request, not a connection that never was).
      await eventually(() => server.connections == 1);
      expect(server.connections, 1);
      await Future<void>.delayed(const Duration(milliseconds: 100));
      expect(server.bytes, 0, reason: 'no byte of the request (line, headers, signature, body) may reach the peer');
      expect(events.map((e) => (e.reason, e.host, e.sequence)), [(SentomaruTransportEventReason.pinMismatch, 'lab-pin.test', 1)]);
      expect(SentomaruTransportEvent.kind, 'transport');
      expect(SentomaruTransportEvent.type, 'pin_failure');
    });

    test("negative control: Dio's validateCertificate refuses only AFTER the request reached the peer", () async {
      final server = await CountingServer.tls(pki['x'].serverContext());
      addTearDown(server.close);
      final dio = Dio()
        ..httpClientAdapter = IOHttpClientAdapter(
          createHttpClient: () => HttpClient()..badCertificateCallback = (c, h, p) => true,
          validateCertificate: (cert, host, port) => false,
        );

      final e = await _failure(_post(dio, 'https://127.0.0.1:${server.port}/v1/ping'));

      expect((e as DioException).type, DioExceptionType.badCertificate);
      expect(server.text.toString(), contains('Bearer user-token'), reason: 'why the plugin does not use it');
    });

    test('the refusal holds on the next request too (nothing cached as trusted)', () async {
      final server = await CountingServer.tls(pki['x'].serverContext());
      addTearDown(server.close);
      final dio = _dio(_pins());
      for (var i = 0; i < 2; i++) {
        expect(_reason(await _failure(dio.get('https://lab-pin.test:${server.port}/'))), 'pin_mismatch');
      }
      await eventually(() => server.connections == 2);
      expect(server.connections, 2);
      expect(server.bytes, 0);
    });

    test('certificate the TLS stack refuses (self-signed / wrong name) -> tls_untrusted, zero bytes', () async {
      for (final key in ['self', 'wrong']) {
        final server = await CountingServer.tls(pki[key].serverContext());
        addTearDown(server.close);
        final pins = _pins();
        final events = <SentomaruTransportEvent>[];
        pins.events.listen(events.add);

        final e = await _failure(_post(_dio(pins), 'https://lab-pin.test:${server.port}/'));

        expect(_reason(e), isNull, reason: 'the platform refusal keeps its own error ($key)');
        expect(e, isA<DioException>());
        await Future<void>.delayed(const Duration(milliseconds: 50));
        expect(server.bytes, 0);
        expect(events.single.reason, SentomaruTransportEventReason.tlsUntrusted, reason: key);
      }
    });

    test('a trailing dot does not step around the pinned entry', () async {
      final server = await CountingServer.tls(pki['x'].serverContext());
      addTearDown(server.close);
      final pins = _pins();
      final events = <SentomaruTransportEvent>[];
      pins.events.listen(events.add);

      await _failure(_dio(pins).get('https://lab-pin.test.:${server.port}/'));

      // The event proves domainFor matched `lab-pin.test.` (an unmatched host emits nothing); the refusal itself comes
      // from the name check of the TLS stack, before the pin (the matching is unit-tested in pinning_pins_test).
      await Future<void>.delayed(const Duration(milliseconds: 50));
      expect(server.bytes, 0);
      expect(events.single.host, 'lab-pin.test');
      expect(events.single.reason, SentomaruTransportEventReason.tlsUntrusted);
    });
  });

  group('includeSubdomains', () {
    test('true: a subdomain is pinned and the event names the profile host, not the subdomain', () async {
      final server = await CountingServer.tls(pki['x'].serverContext());
      addTearDown(server.close);
      final pins = _pins(includeSubdomains: true);
      final events = <SentomaruTransportEvent>[];
      pins.events.listen(events.add);

      final e = await _failure(_dio(pins).get('https://api.lab-pin.test:${server.port}/'));

      expect(_reason(e), 'pin_mismatch');
      expect(server.bytes, 0);
      await Future<void>.delayed(Duration.zero);
      expect(events.single.host, 'lab-pin.test');
      expect(events.single.toString(), isNot(contains('api.')));
    });

    test('false: the subdomain is not pinned and connects as before', () async {
      final server = await CountingServer.tls(pki['x'].serverContext());
      addTearDown(server.close);
      final response = await _dio(_pins()).get('https://api.lab-pin.test:${server.port}/');
      expect(response.statusCode, 200);
    });
  });

  group('proxy and http to a pinned host are refused before connecting', () {
    test('proxy configured by the app: pinned host refused, the proxy gets nothing', () async {
      final proxy = await CountingServer.plain();
      addTearDown(proxy.close);
      final dio = _dio(_pins(),
          createHttpClient: () => HttpClient()..findProxy = (uri) => 'PROXY 127.0.0.1:${proxy.port}');

      final e = await _failure(dio.get('https://lab-pin.test:4443/'));

      expect(_reason(e), 'proxy');
      await Future<void>.delayed(const Duration(milliseconds: 50));
      expect(proxy.connections, 0);
      expect(proxy.bytes, 0);
    });

    test('proxy configured by the app: an unpinned host still goes through the proxy (unchanged)', () async {
      final proxy = await CountingServer.plain();
      addTearDown(proxy.close);
      final dio = _dio(_pins(),
          createHttpClient: () => HttpClient()..findProxy = (uri) => 'PROXY 127.0.0.1:${proxy.port}');

      await _failure(dio.get('https://other.test:4443/'));

      await eventually(() => proxy.text.toString().contains('CONNECT other.test:4443'));
      expect(proxy.text.toString(), startsWith('CONNECT other.test:4443'));
    });

    test('http to a pinned host: refused, zero connections; http to another host: sent', () async {
      final plain = await CountingServer.plain();
      addTearDown(plain.close);
      final dio = _dio(_pins());

      expect(_reason(await _failure(_post(dio, 'http://lab-pin.test:${plain.port}/'))), 'cleartext');
      await Future<void>.delayed(const Duration(milliseconds: 50));
      expect(plain.connections, 0);

      final response = await dio.get('http://other.test:${plain.port}/');
      expect(response.statusCode, 200);
      expect(plain.connections, 1);
    });
  });

  group('review R (I1, I2, I4): proxy list, cancellation, HttpClient redirects, keep-alive', () {
    test("findProxy 'PROXY ...; DIRECT': the proxy is refused, the DIRECT retry is checked", () async {
      final proxy = await CountingServer.plain();
      addTearDown(proxy.close);
      for (final (key, ok) in [('x', false), ('a', true)]) {
        final server = await CountingServer.tls(pki[key].serverContext());
        addTearDown(server.close);
        final dio = _dio(_pins(),
            createHttpClient: () => HttpClient()..findProxy = (uri) => 'PROXY 127.0.0.1:${proxy.port}; DIRECT');
        if (ok) {
          expect((await dio.get('https://lab-pin.test:${server.port}/')).statusCode, 200);
        } else {
          expect(_reason(await _failure(dio.get('https://lab-pin.test:${server.port}/'))), 'pin_mismatch');
          expect(server.bytes, 0);
        }
      }
      expect(proxy.connections, 0);
    });

    test('connection timeout before the handshake ends: the late socket is destroyed, never handed over', () async {
      final server = await CountingServer.tls(pki['a'].serverContext());
      addTearDown(server.close);
      // A handshake that completes after the HttpClient gave up (connectionTimeout -> task.cancel()).
      Future<ConnectionTask<SecureSocket>> slow(
          String host, int port, SecurityContext? context, bool Function(X509Certificate)? cb) async {
        final tcp = await Socket.startConnect(InternetAddress.loopbackIPv4, port);
        Future<SecureSocket> late() async {
          final raw = await tcp.socket;
          await Future<void>.delayed(const Duration(milliseconds: 600));
          return SecureSocket.secure(raw, host: host, context: context, onBadCertificate: cb);
        }

        return ConnectionTask.fromSocket(late(), tcp.cancel);
      }

      final dio = Dio()..options.connectTimeout = const Duration(milliseconds: 200);
      installSentomaruPinning(dio, _pins(),
          context: pki.clientContext(), platformSupported: true, connector: loopbackConnector, tlsConnector: slow);

      final e = await _failure(dio.get('https://lab-pin.test:${server.port}/'));

      expect((e as DioException).type, DioExceptionType.connectionTimeout);
      await eventually(() => server.closed == 1);
      expect(server.connections, 1, reason: 'the handshake did complete');
      expect(server.closed, 1, reason: 'and the socket was destroyed instead of being kept or used');
      expect(server.bytes, 0);
    });

    test("the HttpClient's own redirect (Dio followRedirects, no interceptor) to a pinned host is checked", () async {
      final pinned = await CountingServer.tls(pki['x'].serverContext());
      final start = await CountingServer.tls(pki['x'].serverContext());
      addTearDown(pinned.close);
      addTearDown(start.close);
      start.response = 'HTTP/1.1 302 Found\r\nLocation: https://lab-pin.test:${pinned.port}/next\r\n'
          'Content-Length: 0\r\nConnection: close\r\n\r\n';

      final e = await _failure(_dio(_pins()).get('https://other.test:${start.port}/first'));

      expect(start.text.toString(), contains('GET /first'));
      expect(_reason(e), 'pin_mismatch');
      await eventually(() => pinned.connections == 1);
      expect(pinned.bytes, 0);
    });

    test('keep-alive: a checked connection is reused for the same pinned host', () async {
      final server = await CountingServer.tls(pki['a'].serverContext())..keepAlive = true;
      addTearDown(server.close);
      final dio = _dio(_pins());
      for (var i = 0; i < 3; i++) {
        expect((await dio.get('https://lab-pin.test:${server.port}/$i')).statusCode, 200);
      }
      expect(server.connections, 1);
    });
  });

  test('production connectors (no seam) for an unpinned host: https and http as before', () async {
    final tls = await CountingServer.tls(pki['self'].serverContext());
    final plain = await CountingServer.plain();
    addTearDown(tls.close);
    addTearDown(plain.close);
    final dio = Dio();
    installSentomaruPinning(dio, _pins(), onBadCertificate: (c, h, p) => true, platformSupported: true);
    expect((await dio.get('https://127.0.0.1:${tls.port}/')).statusCode, 200);
    expect((await dio.get('http://127.0.0.1:${plain.port}/')).statusCode, 200);
  });

  group('review R (I3): trust for hosts outside the section', () {
    test("the app's HttpClient(context:) is not read: pass it to addSentomaruPinning", () async {
      final server = await CountingServer.tls(pki['x'].serverContext());
      addTearDown(server.close);
      HttpClient appClient() => HttpClient(context: pki.clientContext());

      final notPassed = Dio()..httpClientAdapter = IOHttpClientAdapter(createHttpClient: appClient);
      installSentomaruPinning(notPassed, _pins(), platformSupported: true, connector: loopbackConnector, tlsConnector: loopbackTlsConnector);
      await _failure(notPassed.get('https://other.test:${server.port}/'));

      final passed = Dio()..httpClientAdapter = IOHttpClientAdapter(createHttpClient: appClient);
      installSentomaruPinning(passed, _pins(),
          context: pki.clientContext(), platformSupported: true, connector: loopbackConnector, tlsConnector: loopbackTlsConnector);
      expect((await passed.get('https://other.test:${server.port}/')).statusCode, 200);
    });

    test('after the expiration onBadCertificate still never applies to a host of the section', () async {
      final server = await CountingServer.tls(pki['self'].serverContext());
      addTearDown(server.close);
      final dio = Dio()..httpClientAdapter = IOHttpClientAdapter();
      installSentomaruPinning(dio, _pins(now: DateTime(2027, 4, 1)),
          context: pki.clientContext(),
          onBadCertificate: (c, h, p) => true,
          platformSupported: true,
          connector: loopbackConnector, tlsConnector: loopbackTlsConnector);

      await _failure(dio.get('https://lab-pin.test:${server.port}/'));
      expect((await dio.get('https://other.test:${server.port}/')).statusCode, 200);
    });
  });

  group('host outside the section is unchanged', () {
    test('any key the chain trusts is accepted, no event', () async {
      final server = await CountingServer.tls(pki['x'].serverContext());
      addTearDown(server.close);
      final pins = _pins();
      final events = <SentomaruTransportEvent>[];
      pins.events.listen(events.add);

      final response = await _post(_dio(pins), 'https://other.test:${server.port}/v1/x');

      expect(response.statusCode, 200);
      expect(server.text.toString(), contains('POST /v1/x'));
      await Future<void>.delayed(Duration.zero);
      expect(events, isEmpty);
    });

    test('onBadCertificate applies to unpinned hosts only', () async {
      final server = await CountingServer.tls(pki['self'].serverContext());
      addTearDown(server.close);
      final dio = Dio()..httpClientAdapter = IOHttpClientAdapter();
      installSentomaruPinning(dio, _pins(),
          context: pki.clientContext(),
          onBadCertificate: (c, h, p) => true,
          platformSupported: true,
          connector: loopbackConnector, tlsConnector: loopbackTlsConnector);

      expect((await dio.get('https://other.test:${server.port}/')).statusCode, 200);
      await _failure(dio.get('https://lab-pin.test:${server.port}/'));
      expect(server.text.toString(), isNot(contains('Host: lab-pin.test')));
    });
  });

  group('expiration (midnight in the device time zone, pinned while now <= expiration)', () {
    test('at 00:00:00.000 of the expiration day the pin-set still holds', () async {
      final server = await CountingServer.tls(pki['x'].serverContext());
      addTearDown(server.close);
      final e = await _failure(_dio(_pins(now: DateTime(2027, 3, 31))).get('https://lab-pin.test:${server.port}/'));
      expect(_reason(e), 'pin_mismatch');
      expect(server.bytes, 0);
    });

    test('one millisecond later it is off: an unpinned key is accepted (fail open by design)', () async {
      final server = await CountingServer.tls(pki['x'].serverContext());
      addTearDown(server.close);
      final pins = _pins(now: DateTime(2027, 3, 31, 0, 0, 0, 1));
      expect(pins.isActive, isFalse);
      final response = await _dio(pins).get('https://lab-pin.test:${server.port}/');
      expect(response.statusCode, 200);
    });

    test('after the expiration http to the pinned host stays refused (as the Android domain-config)', () async {
      final plain = await CountingServer.plain();
      addTearDown(plain.close);
      final dio = _dio(_pins(now: DateTime(2027, 4, 1)));
      expect(_reason(await _failure(dio.get('http://lab-pin.test:${plain.port}/'))), 'cleartext');
      expect(plain.connections, 0);
    });
  });

  group('installation', () {
    test('a Dio already used before the installation is still pinned (fresh adapter, no cached HttpClient)', () async {
      final ok = await CountingServer.tls(pki['x'].serverContext());
      addTearDown(ok.close);
      final dio = Dio()
        ..httpClientAdapter = IOHttpClientAdapter(
          createHttpClient: () => HttpClient()..badCertificateCallback = (c, h, p) => true,
        );
      expect((await dio.get('https://127.0.0.1:${ok.port}/')).statusCode, 200);
      final old = dio.httpClientAdapter;

      installSentomaruPinning(dio, _pins(),
          context: pki.clientContext(), platformSupported: true, connector: loopbackConnector, tlsConnector: loopbackTlsConnector);

      expect(identical(dio.httpClientAdapter, old), isFalse);
      final before = ok.bytes;
      expect(_reason(await _failure(dio.get('https://lab-pin.test:${ok.port}/'))), 'pin_mismatch');
      expect(ok.bytes, before);
    });

    test("the app's createHttpClient and validateCertificate are kept", () async {
      final server = await CountingServer.tls(pki['a'].serverContext());
      addTearDown(server.close);
      bool validate(X509Certificate? c, String h, int p) => true;
      final dio = Dio()
        ..httpClientAdapter = IOHttpClientAdapter(
          createHttpClient: () => HttpClient()..userAgent = 'app-ua/1',
          validateCertificate: validate,
        );
      installSentomaruPinning(dio, _pins(),
          context: pki.clientContext(), platformSupported: true, connector: loopbackConnector, tlsConnector: loopbackTlsConnector);

      await dio.get('https://lab-pin.test:${server.port}/');

      expect(server.text.toString().toLowerCase(), contains('user-agent: app-ua/1'));
      expect((dio.httpClientAdapter as IOHttpClientAdapter).validateCertificate, same(validate));
    });

    test('another adapter type is refused', () {
      final dio = Dio()..httpClientAdapter = _OtherAdapter();
      expect(() => installSentomaruPinning(dio, _pins(), platformSupported: true), throwsArgumentError);
    });

    test('twice on the same Dio, or after addSentomaru, is refused', () async {
      final dio = Dio();
      installSentomaruPinning(dio, _pins(), platformSupported: true);
      expect(() => installSentomaruPinning(dio, _pins(), platformSupported: true), throwsStateError);

      final client = SentomaruClient(platform: _Platform());
      final signed = Dio()..addSentomaru(client);
      expect(() => installSentomaruPinning(signed, _pins(), platformSupported: true), throwsStateError);
    });

    test('not Android: the line does nothing and says so', () {
      final dio = Dio();
      final adapter = dio.httpClientAdapter;
      expect(installSentomaruPinning(dio, _pins(), platformSupported: false), SentomaruPinningInstall.unsupportedPlatform);
      expect(identical(dio.httpClientAdapter, adapter), isTrue);
      // The public line on this host (Linux, not Android) and the pins: parameter of addSentomaru are no-ops too.
      expect(Dio().addSentomaruPinning(_pins()), SentomaruPinningInstall.unsupportedPlatform);
      final signed = Dio();
      final before = signed.httpClientAdapter;
      signed.addSentomaru(SentomaruClient(platform: _Platform()), pins: _pins());
      expect(identical(signed.httpClientAdapter, before), isTrue);
    });

    test('pinning before addSentomaru: a redirect followed by the interceptor to a pinned host is checked', () async {
      final pinned = await CountingServer.tls(pki['x'].serverContext());
      final start = await CountingServer.tls(pki['x'].serverContext());
      addTearDown(pinned.close);
      addTearDown(start.close);
      start.response = 'HTTP/1.1 307 Temporary Redirect\r\nLocation: https://lab-pin.test:${pinned.port}/next\r\n'
          'Content-Length: 0\r\nConnection: close\r\n\r\n';
      final client = SentomaruClient(platform: _Platform());
      await client.initialize(const SentomaruConfig(
        organization: 'ebees',
        app: 'pin-lab',
        environment: 'dev',
        enrollmentUrl: 'https://other.test/enroll',
        allowedHosts: {'other.test', 'lab-pin.test'},
      ));
      final dio = _dio(_pins())..addSentomaru(client);

      final e = await _failure(dio.get('https://other.test:${start.port}/first'));

      expect(start.text.toString(), contains('GET /first'));
      expect(_reason(e), 'pin_mismatch');
      await eventually(() => pinned.connections == 1);
      expect(pinned.connections, 1);
      expect(pinned.bytes, 0);
    });
  });
}

class _OtherAdapter implements HttpClientAdapter {
  @override
  void close({bool force = false}) {}

  @override
  Future<ResponseBody> fetch(RequestOptions options, Stream<Uint8List>? requestStream, Future<void>? cancelFuture) =>
      throw UnimplementedError();
}

class _Platform extends SentomaruFlutterPlatform {
  @override
  Future<void> initialize(SentomaruConfig config) async {}

  @override
  Future<InstallationState> state() async => InstallationState.enrolled;
}
