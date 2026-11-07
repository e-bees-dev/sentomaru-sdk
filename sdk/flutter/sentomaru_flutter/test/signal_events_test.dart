import 'dart:async';
import 'dart:convert';
import 'dart:io';

import 'package:dio/dio.dart';
import 'package:flutter/foundation.dart';
import 'package:flutter/services.dart';
import 'package:flutter_test/flutter_test.dart';
import 'package:sentomaru_flutter/sentomaru_flutter.dart';
// ignore: implementation_imports
import 'package:sentomaru_flutter/src/server_response_sink.dart';

/// D-15c: signal events over the EventChannel (Android), none on iOS, and `server_response` events from the Dio
/// interceptor. Failure classes: a field outside the closed vocabulary reaches the app, the Dart vocabulary drifts from
/// the Android `SignalsCatalog`, an unsigned request (or a body with only free text / a `riskEvent` / a nested `code`)
/// becomes an event, a followed redirect or a renewal is reported twice, the native side is subscribed while nobody
/// listens, and iOS claims signal events.
class _EventsPlatform extends SentomaruFlutterPlatform {
  final native = StreamController<Object?>.broadcast();
  int listens = 0;
  bool supported = true;
  int signs = 0;

  @override
  bool get signalEventsSupported => supported;

  @override
  Stream<Object?> signalEvents() {
    listens++;
    return native.stream;
  }

  @override
  Future<void> initialize(SentomaruConfig config) async {}

  @override
  Future<InstallationState> state() async => InstallationState.enrolled;

  @override
  Future<String> renewSession() async => 'sess-2';

  @override
  Future<SignedMessageHeaders> sign({
    required String method,
    required String targetUri,
    required String operation,
    required Uint8List bodyBytes,
    Map<String, String> optionalHeaders = const {},
  }) async {
    signs++;
    return SignedMessageHeaders({
      ...optionalHeaders,
      'Signature': 'sig1=:s:',
      'Signature-Input': 'sig1=("@method");created=1',
      'Content-Digest': 'sha-256=:d:',
      'x-sentomaru-operation': operation,
      'x-sentomaru-session': 'sess-1',
    });
  }
}

/// Answers scripted (status, body, headers) in order.
class _Adapter implements HttpClientAdapter {
  final List<(int, String, Map<String, List<String>>)> answers;
  final List<RequestOptions> seen = [];
  _Adapter(this.answers);

  @override
  Future<ResponseBody> fetch(RequestOptions options, Stream<Uint8List>? requestStream, Future<void>? cancelFuture) async {
    if (requestStream != null) await requestStream.drain<void>();
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

Map<String, Object?> _signal({
  String id = 'root_artifacts',
  String? type,
  String state = 'DETECTED',
  List<Object?> codes = const ['su_path'],
  String version = '1.0.0',
  String catalog = '1.6.0',
}) =>
    {
      'kind': 'signal',
      'type': type ?? SentomaruSignalEventsCatalog.eventTypes[id] ?? 'x',
      'capabilityId': id,
      'capabilityVersion': version,
      'state': state,
      'reasonCodes': codes,
      'catalogVersion': catalog,
      'sequence': 99,
    };

void main() {
  TestWidgetsFlutterBinding.ensureInitialized();

  test('the mapping of the integration guide (7d)', () {
    SentomaruSignalEvent server(int status, Map<String, Object?> body) =>
        SentomaruSignalEvent.fromServerResponse(status, body, 1)!;
    expect(appReaction(SentomaruSignalEvent.fromPlatform(_signal(), 1)!), 'warn_and_log');
    expect(appReaction(server(401, {'code': 'challenge-required', 'challengeKind': 'step_up'})), 'reauthenticate');
    expect(appReaction(server(401, {'code': 'challenge-required', 'challengeKind': 'reattest'})), 'reattest_then_repeat_once');
    expect(appReaction(server(401, {'code': 'challenge-required', 'challengeKind': 'fresh_signals'})), 'retry_with_fresh_signals');
    expect(appReaction(server(401, {'code': 'challenge-required'})), 'retry_with_fresh_signals');
    expect(appReaction(server(403, {'code': 'installation-suspended'})), 'suspension_screen_keeping_drafts');
    expect(appReaction(server(403, {'code': 'installation-revoked'})), 'enroll_again');
    expect(appReaction(server(403, {'code': 'RASP_ROOT_ARTIFACTS'})), 'show_the_refusal');
  });

  group('vocabulary', () {
    test('the Dart copy equals EVENT_TYPES and EVENT_REASON_CODES of the Android SignalsCatalog.kt', () {
      final kt = _androidFile('SignalsCatalog.kt');
      final types = RegExp(r'val EVENT_TYPES[^=]*= linkedMapOf\(([\s\S]*?)\n    \)').firstMatch(kt)!.group(1)!;
      final parsedTypes = {
        for (final m in RegExp(r'"([a-z0-9_]+)" to "([a-z0-9_]+)"').allMatches(types)) m.group(1)!: m.group(2)!,
      };
      expect(parsedTypes, SentomaruSignalEventsCatalog.eventTypes);
      expect(parsedTypes.keys.toList(), SentomaruSignalEventsCatalog.eventTypes.keys.toList()); // same order

      final reasons = RegExp(r'val EVENT_REASON_CODES[^=]*= linkedMapOf\(([\s\S]*?)\n    \)\n').firstMatch(kt)!.group(1)!;
      final parsedReasons = <String, Set<String>>{};
      for (final m in RegExp(r'"([a-z0-9_]+)" to setOf\(([\s\S]*?)\)').allMatches(reasons)) {
        parsedReasons[m.group(1)!] = {for (final c in RegExp(r'"([^"]+)"').allMatches(m.group(2)!)) c.group(1)!};
      }
      expect(parsedReasons, SentomaruSignalEventsCatalog.eventReasonCodes);
    });

    test('the server_response vocabulary equals ServerResponseCodes of SentomaruServerResponseEvent.kt (review R M-3)', () {
      final kt = _androidFile('SentomaruServerResponseEvent.kt');
      String constant(String name) => RegExp('const val $name = "([^"]+)"').firstMatch(kt)!.group(1)!;
      final closed = RegExp(r'val CLOSED: Set<String> = setOf\(([\s\S]*?)\)').firstMatch(kt)!.group(1)!;
      final closedCodes = {
        for (final m in RegExp(r'"([^"]+)"|\b([A-Z_]+)\b').allMatches(closed))
          m.group(1) ?? constant(m.group(2)!),
      };
      expect(closedCodes, SentomaruServerResponseCodes.closed);
      final only401 = RegExp(r'ONLY_401 = setOf\(([^)]*)\)').firstMatch(kt)!.group(1)!;
      expect(
          {for (final m in RegExp(r'"([^"]+)"|\b([A-Z_0-9]+)\b').allMatches(only401)) m.group(1) ?? constant(m.group(2)!)},
          {'challenge-required', 'proof-required'});
      expect(RegExp(r'POLICY_REASON = Regex\("([^"]+)"\)').firstMatch(kt)!.group(1), r'^[A-Z0-9_]{3,64}$');
      expect(RegExp(r'CHALLENGE_KIND = Regex\("([^"]+)"\)').firstMatch(kt)!.group(1), r'^[a-z][a-z0-9_]{0,31}$');
      // D-06h: the closed list of challenge kinds (with reattest) is the Kotlin CHALLENGE_KINDS.
      final kinds = RegExp(r'val CHALLENGE_KINDS: Set<String> = setOf\(([^)]*)\)').firstMatch(kt)!.group(1)!;
      expect({for (final m in RegExp(r'"([^"]+)"|\b([A-Z_]+)\b').allMatches(kinds)) m.group(1) ?? constant(m.group(2)!)},
          SentomaruServerResponseCodes.challengeKinds);
      expect(SentomaruServerResponseCodes.challengeKinds, {'fresh_signals', 'step_up', 'reattest'});
      expect(RegExp(r'const val MAX_BODY_CHARS = (\d+)').firstMatch(kt)!.group(1), '${SentomaruServerResponseCodes.maxBodyChars}');
      // The Dart side, read through its behaviour: every closed code passes, 401-only ones fail on 403.
      for (final c in SentomaruServerResponseCodes.closed) {
        expect(SentomaruServerResponseCodes.read(401, {'code': c}), isNotNull, reason: c);
        expect(SentomaruServerResponseCodes.read(403, {'code': c}) == null,
            {'challenge-required', 'proof-required'}.contains(c), reason: c);
      }
    });

    test('every capability with events is a client_observed one of the catalog, outside the six of collectSignals', () {
      for (final id in SentomaruSignalEventsCatalog.eventTypes.keys) {
        expect(SentomaruSignalsCatalog.byId(id)?.source, 'client_observed', reason: id);
        expect(SentomaruSignalsCatalog.defaultCapabilityIds, isNot(contains(id)));
      }
      expect(SentomaruSignalEventsCatalog.eventReasonCodes.keys.toSet(),
          SentomaruSignalEventsCatalog.eventTypes.keys.toSet());
    });
  });

  group('SentomaruSignalEvent.fromPlatform', () {
    test('a signal event in the closed vocabulary, renumbered by the client', () {
      final e = SentomaruSignalEvent.fromPlatform(_signal(codes: ['su_path', 'build_type']), 3)!;
      expect(e.kind, SentomaruSignalEventKind.signal);
      expect(e.kind.wireName, 'signal');
      expect(e.sequence, 3);
      expect(e.type, 'root_artifacts');
      expect(e.capabilityId, 'root_artifacts');
      expect(e.capabilityVersion, '1.0.0');
      expect(e.state, SignalState.detected);
      expect(e.reasonCodes, ['su_path', 'build_type']);
      expect(e.catalogVersion, '1.6.0');
      expect(e.code, isNull);
      expect(e.httpStatus, isNull);
      expect(() => e.reasonCodes.add('x'), throwsUnsupportedError);
      expect(SentomaruSignalEvent.fromPlatform(_signal(state: 'NOT_DETECTED', codes: []), 1)!.state, SignalState.notDetected);
    });

    test('anything outside the vocabulary is dropped whole, never passed on partly', () {
      final bad = <Object?>[
        null,
        'signal',
        {'kind': 'threat'},
        _signal(id: 'installer_source'), // one of the six: never an event
        _signal(id: 'app_signing_digest'),
        _signal(type: 'emulator'), // type of another capability
        _signal(codes: ['su_path', '/system/xbin/su']),
        _signal(codes: ['com.topjohnwu.magisk']),
        _signal(codes: [1]),
        _signal(state: 'STALE'),
        _signal(state: 'COMPROMISED'),
        _signal(version: '1.0.0; rm'),
        _signal(catalog: 'latest'),
        {..._signal(), 'reasonCodes': 'su_path'},
      ];
      for (final raw in bad) {
        expect(SentomaruSignalEvent.fromPlatform(raw, 1), isNull, reason: '$raw');
      }
    });

    test('a native server_response passes the same closed codes', () {
      final e = SentomaruSignalEvent.fromPlatform(
          {'kind': 'server_response', 'code': 'challenge-required', 'challengeKind': 'step_up', 'httpStatus': 401}, 7)!;
      expect((e.kind, e.code, e.challengeKind, e.httpStatus, e.sequence),
          (SentomaruSignalEventKind.serverResponse, 'challenge-required', 'step_up', 401, 7));
      expect(e.kind.wireName, 'server_response');
      expect(e.type, isNull);
      expect(e.reasonCodes, isEmpty);
      for (final raw in [
        {'kind': 'server_response', 'code': 'invalid-signature', 'httpStatus': 401},
        {'kind': 'server_response', 'code': 'challenge-required', 'httpStatus': 403},
        {'kind': 'server_response', 'code': 'challenge-required', 'httpStatus': '401'},
        {'kind': 'server_response', 'code': 'challenge-required', 'challengeKind': 3, 'httpStatus': 401},
      ]) {
        expect(SentomaruSignalEvent.fromPlatform(raw, 1), isNull, reason: '$raw');
      }
    });
  });

  test('fromServerResponse builds only checked codes', () {
    final e = SentomaruSignalEvent.fromServerResponse(403, {'code': 'policy-denied', 'detail': 'x'}, 4)!;
    expect((e.kind, e.code, e.challengeKind, e.httpStatus, e.sequence),
        (SentomaruSignalEventKind.serverResponse, 'policy-denied', null, 403, 4));
    expect(SentomaruSignalEvent.fromServerResponse(403, {'code': 'free text'}, 1), isNull);
  });

  group('SentomaruServerResponseCodes.read', () {
    test('closed codes on 401/403, challenge-required and proof-required on 401 only', () {
      expect(SentomaruServerResponseCodes.read(401, {'code': 'challenge-required', 'challengeKind': 'step_up'}),
          ('challenge-required', 'step_up'));
      expect(SentomaruServerResponseCodes.read(401, {'code': 'challenge-required', 'challengeKind': 'fresh_signals'}),
          ('challenge-required', 'fresh_signals'));
      expect(SentomaruServerResponseCodes.read(401, {'code': 'challenge-required'}), ('challenge-required', null));
      expect(SentomaruServerResponseCodes.read(401, {'code': 'proof-required'}), ('proof-required', null));
      expect(SentomaruServerResponseCodes.read(403, {'code': 'challenge-required'}), isNull);
      expect(SentomaruServerResponseCodes.read(403, {'code': 'proof-required'}), isNull);
      for (final c in ['installation-suspended', 'installation-revoked', 'session-unavailable', 'policy-denied']) {
        expect(SentomaruServerResponseCodes.read(403, {'code': c}), (c, null), reason: c);
        expect(SentomaruServerResponseCodes.read(401, {'code': c}), (c, null), reason: c);
      }
      expect(SentomaruServerResponseCodes.read(500, {'code': 'installation-suspended'}), isNull);
      expect(SentomaruServerResponseCodes.read(null, {'code': 'installation-suspended'}), isNull);
    });

    test('a policy reason code only on 403 and only with the validator pattern', () {
      expect(SentomaruServerResponseCodes.read(403, {'code': 'RASP_ROOT_ARTIFACTS'}), ('RASP_ROOT_ARTIFACTS', null));
      expect(SentomaruServerResponseCodes.read(401, {'code': 'RASP_ROOT_ARTIFACTS'}), isNull);
      expect(SentomaruServerResponseCodes.read(403, {'code': 'AB'}), isNull);
      expect(SentomaruServerResponseCodes.read(403, {'code': 'A' * 65}), isNull);
      expect(SentomaruServerResponseCodes.read(403, {'code': 'Fulano da Silva'}), isNull);
      expect(SentomaruServerResponseCodes.read(403, {'code': 'session-expired'}), isNull);
    });

    test('challengeKind only next to challenge-required and only as a token', () {
      expect(SentomaruServerResponseCodes.read(401, {'code': 'challenge-required', 'challengeKind': 'reattest'}),
          ('challenge-required', 'reattest'));
      expect(SentomaruServerResponseCodes.read(401, {'code': 'challenge-required', 'challengeKind': 'future_kind'}),
          ('challenge-required', 'future_kind'));
      expect(SentomaruServerResponseCodes.read(401, {'code': 'challenge-required', 'challengeKind': 'Reattest'}),
          ('challenge-required', null));
      expect(SentomaruServerResponseCodes.read(403, {'code': 'challenge-required', 'challengeKind': 'reattest'}), isNull);
      SentomaruSignalEvent event(Map<String, Object?> body) => SentomaruSignalEvent.fromServerResponse(401, body, 1)!;
      expect(event({'code': 'challenge-required', 'challengeKind': 'reattest'}).isReattestChallenge, isTrue);
      expect(event({'code': 'challenge-required', 'challengeKind': 'step_up'}).isReattestChallenge, isFalse);
      expect(event({'code': 'challenge-required'}).isReattestChallenge, isFalse);
      expect(SentomaruSignalEvent.fromPlatform(_signal(), 1)!.isReattestChallenge, isFalse);
      expect(SentomaruServerResponseCodes.read(401, {'code': 'challenge-required', 'challengeKind': 'Step Up!'}),
          ('challenge-required', null));
      expect(SentomaruServerResponseCodes.read(401, {'code': 'challenge-required', 'challengeKind': 's' * 33}),
          ('challenge-required', null));
      expect(SentomaruServerResponseCodes.read(403, {'code': 'installation-suspended', 'challengeKind': 'step_up'}),
          ('installation-suspended', null));
    });

    test('only the top-level code: free text, a riskEvent or a nested code never become an event', () {
      expect(SentomaruServerResponseCodes.read(403, {'message': 'installation-suspended'}), isNull);
      expect(SentomaruServerResponseCodes.read(403, {'riskEvent': {'code': 'installation-suspended'}}), isNull);
      expect(SentomaruServerResponseCodes.read(403, {'error': {'code': 'policy-denied'}}), isNull);
      expect(SentomaruServerResponseCodes.read(403, {'code': ['policy-denied']}), isNull);
      expect(SentomaruServerResponseCodes.read(403, 'installation-suspended'), isNull);
      expect(SentomaruServerResponseCodes.read(403, '[{"code":"policy-denied"}]'), isNull);
      expect(SentomaruServerResponseCodes.read(403, null), isNull);
    });

    test('a text or byte body is parsed up to maxBodyChars; longer or malformed gives no event', () {
      const body = '{"code":"installation-revoked","detail":"x"}';
      expect(SentomaruServerResponseCodes.read(403, body), ('installation-revoked', null));
      expect(SentomaruServerResponseCodes.read(403, utf8.encode(body)), ('installation-revoked', null));
      final long = '{"code":"installation-revoked","pad":"${'x' * SentomaruServerResponseCodes.maxBodyChars}"}';
      expect(SentomaruServerResponseCodes.read(403, long), isNull);
      expect(SentomaruServerResponseCodes.read(403, utf8.encode(long)), isNull);
      expect(SentomaruServerResponseCodes.read(403, '{"code":"installation-revoked"'), isNull);
      expect(SentomaruServerResponseCodes.read(403, [0xff, 0xfe]), isNull);
    });
  });

  group('SentomaruClient.signalEvents', () {
    test('the native stream is subscribed only while the app listens; sequence spans both kinds', () async {
      final platform = _EventsPlatform();
      final client = SentomaruClient(platform: platform);
      expect(client.signalEventsSupported, isTrue);
      expect(platform.listens, 0);
      expect(platform.native.hasListener, isFalse);

      final got = <SentomaruSignalEvent>[];
      final sub = client.signalEvents.listen(got.add);
      expect(platform.listens, 1);
      platform.native.add(_signal());
      platform.native.add(_signal(codes: ['not_a_code'])); // dropped, consumes no sequence
      await pumpEventQueue(); // numbered in the order events reach the client stream
      serverResponseSinks[client]!(403, {'code': 'installation-suspended'});
      platform.native.add(_signal(id: 'emulator_indicated', state: 'NOT_DETECTED', codes: []));
      await pumpEventQueue();
      expect(got.map((e) => (e.sequence, e.kind)), [
        (1, SentomaruSignalEventKind.signal),
        (2, SentomaruSignalEventKind.serverResponse),
        (3, SentomaruSignalEventKind.signal),
      ]);
      expect(got[1].code, 'installation-suspended');

      await sub.cancel();
      expect(platform.native.hasListener, isFalse);
      serverResponseSinks[client]!(403, {'code': 'installation-suspended'}); // nobody listens: nothing built
      final again = <SentomaruSignalEvent>[];
      final sub2 = client.signalEvents.listen(again.add);
      expect(platform.listens, 2);
      await pumpEventQueue();
      expect(again, isEmpty);
      await sub2.cancel();
      client.dispose();
      expect(serverResponseSinks[client], isNull); // after dispose the receiver is gone
    });

    test('a platform error on the stream is dropped and the stream goes on', () async {
      final platform = _EventsPlatform();
      final client = SentomaruClient(platform: platform);
      final got = <SentomaruSignalEvent>[];
      final errors = <Object>[];
      final sub = client.signalEvents.listen(got.add, onError: errors.add);
      platform.native.addError(PlatformException(code: 'x'));
      platform.native.add(_signal());
      await pumpEventQueue();
      expect(errors, isEmpty);
      expect(got, hasLength(1));
      await sub.cancel();
    });
  });

  group('SentomaruDioInterceptor server_response', () {
    const config = SentomaruConfig(
      organization: 'org-x',
      app: 'app-x',
      environment: 'hml',
      enrollmentUrl: 'https://api.example.test/enroll',
      allowedHosts: {'api.example.test', 'b.example.test'},
      renewalUrl: 'https://api.example.test/sessions',
    );

    Future<(Dio, _Adapter, List<SentomaruSignalEvent>, List<SentomaruRiskEvent>, _EventsPlatform)> setup(
        List<(int, String, Map<String, List<String>>)> answers) async {
      final platform = _EventsPlatform();
      final client = SentomaruClient(platform: platform);
      await client.initialize(config);
      final events = <SentomaruSignalEvent>[];
      client.signalEvents.listen(events.add);
      final risks = <SentomaruRiskEvent>[];
      final adapter = _Adapter(answers);
      final dio = Dio()..httpClientAdapter = adapter;
      dio.addSentomaru(client, onRiskEvent: risks.add);
      return (dio, adapter, events, risks, platform);
    }

    Options op({ValidateStatus? validateStatus}) =>
        Options(extra: {'sentomaru_operation': 'op_x'}, validateStatus: validateStatus);

    test('a signed request answered 401 challenge-required step_up is one event', () async {
      final (dio, _, events, _, _) =
          await setup([(401, '{"code":"challenge-required","challengeKind":"step_up","detail":"x"}', {})]);
      await expectLater(dio.post('https://api.example.test/v1/a', data: {'a': 1}, options: op()),
          throwsA(isA<DioException>()));
      await pumpEventQueue();
      expect(events.map((e) => (e.code, e.challengeKind, e.httpStatus)), [('challenge-required', 'step_up', 401)]);
    });

    test('also when the app accepts the status (onResponse path)', () async {
      final (dio, _, events, _, _) = await setup([(403, '{"code":"RASP_ROOT_ARTIFACTS"}', {})]);
      final r = await dio.post('https://api.example.test/v1/a', data: {'a': 1}, options: op(validateStatus: (_) => true));
      expect(r.statusCode, 403);
      await pumpEventQueue();
      expect(events.map((e) => e.code), ['RASP_ROOT_ARTIFACTS']);
    });

    test('an unsigned request, even with a forged marker or Signature-Input, is never an event', () async {
      final (dio, _, events, _, platform) = await setup([
        (401, '{"code":"challenge-required"}', {}),
        (403, '{"code":"installation-suspended"}', {}),
      ]);
      await expectLater(
          dio.get('https://api.example.test/v1/free',
              options: Options(extra: {'sentomaru_signed': true}, headers: {'Signature-Input': 'sig1=()'})),
          throwsA(isA<DioException>()));
      await expectLater(dio.get('https://other.example.test/v1/free', options: Options(extra: {'sentomaru_signed': true})),
          throwsA(isA<DioException>()));
      await pumpEventQueue();
      expect(platform.signs, 0);
      expect(events, isEmpty);
    });

    test('riskEvent stays on onRiskEvent and a body with only a riskEvent is no server_response', () async {
      final (dio, _, events, risks, _) = await setup([
        (403, '{"riskEvent":{"type":"x","severity":"high","code":"installation-suspended"}}', {}),
      ]);
      await expectLater(dio.post('https://api.example.test/v1/a', data: {'a': 1}, options: op()),
          throwsA(isA<DioException>()));
      await pumpEventQueue();
      expect(risks, hasLength(1));
      expect(events, isEmpty);
    });

    test('a session-expired renewal reports only the resend, once', () async {
      final (dio, adapter, events, _, _) = await setup([
        (403, '{"code":"session-expired"}', {}),
        (403, '{"code":"installation-suspended"}', {}),
      ]);
      await expectLater(dio.post('https://api.example.test/v1/a', data: {'a': 1}, options: op()),
          throwsA(isA<DioException>()));
      await pumpEventQueue();
      expect(adapter.seen, hasLength(2));
      expect(events.map((e) => (e.sequence, e.code)), [(1, 'installation-suspended')]);
    });

    test('a followed 307 reports the hop that answered, once', () async {
      final (dio, adapter, events, _, platform) = await setup([
        (307, '', {'location': ['https://b.example.test/v1/a']}),
        (401, '{"code":"proof-required"}', {}),
      ]);
      await expectLater(dio.post('https://api.example.test/v1/a', data: {'a': 1}, options: op()),
          throwsA(isA<DioException>()));
      await pumpEventQueue();
      expect(adapter.seen, hasLength(2));
      expect(platform.signs, 2); // re-signed for the new target
      expect(events.map((e) => e.code), ['proof-required']);
    });

    test('a 303 hop is an unsigned GET: its 401 is no event', () async {
      final (dio, adapter, events, _, _) = await setup([
        (303, '', {'location': ['https://b.example.test/v1/b']}),
        (401, '{"code":"challenge-required"}', {}),
      ]);
      await expectLater(dio.post('https://api.example.test/v1/a', data: {'a': 1}, options: op()),
          throwsA(isA<DioException>()));
      await pumpEventQueue();
      expect(adapter.seen, hasLength(2));
      expect(events, isEmpty);
    });
  });

  group('MethodChannelSentomaruFlutter.signalEvents', () {
    const eventChannel = EventChannel('sentomaru_flutter/signal_events');
    tearDown(() {
      debugDefaultTargetPlatformOverride = null;
      TestDefaultBinaryMessengerBinding.instance.defaultBinaryMessenger.setMockStreamHandler(eventChannel, null);
    });

    test('Android: the EventChannel, subscribed on listen and cancelled with the app', () async {
      debugDefaultTargetPlatformOverride = TargetPlatform.android;
      MethodChannelSentomaruFlutter.resetSignalEventsForTesting();
      var listened = 0, cancelled = 0;
      TestDefaultBinaryMessengerBinding.instance.defaultBinaryMessenger.setMockStreamHandler(
        eventChannel,
        MockStreamHandler.inline(
          onListen: (args, sink) {
            listened++;
            sink.success(_signal());
            sink.success({'kind': 'server_response', 'code': 'installation-revoked', 'httpStatus': 403});
            sink.success({'kind': 'other'});
          },
          onCancel: (_) => cancelled++,
        ),
      );
      final client = SentomaruClient(platform: MethodChannelSentomaruFlutter());
      expect(client.signalEventsSupported, isTrue);
      final got = <SentomaruSignalEvent>[];
      final sub = client.signalEvents.listen(got.add);
      await pumpEventQueue();
      expect(listened, 1);
      expect(got.map((e) => (e.sequence, e.kind.wireName, e.capabilityId ?? e.code)), [
        (1, 'signal', 'root_artifacts'),
        (2, 'server_response', 'installation-revoked'),
      ]);
      await sub.cancel();
      await pumpEventQueue();
      expect(cancelled, 1);
    });

    test('two clients of one engine share the channel: one cancel does not silence the other (review R I-2)', () async {
      debugDefaultTargetPlatformOverride = TargetPlatform.android;
      MethodChannelSentomaruFlutter.resetSignalEventsForTesting();
      var listened = 0, cancelled = 0;
      MockStreamHandlerEventSink? sink;
      TestDefaultBinaryMessengerBinding.instance.defaultBinaryMessenger.setMockStreamHandler(
        eventChannel,
        MockStreamHandler.inline(onListen: (args, s) {
          listened++;
          sink = s;
        }, onCancel: (_) => cancelled++),
      );
      final a = SentomaruClient(platform: MethodChannelSentomaruFlutter());
      final b = SentomaruClient(platform: MethodChannelSentomaruFlutter());
      final gotA = <SentomaruSignalEvent>[], gotB = <SentomaruSignalEvent>[];
      final subA = a.signalEvents.listen(gotA.add);
      final subB = b.signalEvents.listen(gotB.add);
      await pumpEventQueue();
      expect(listened, 1);
      await subA.cancel();
      await pumpEventQueue();
      expect(cancelled, 0);
      sink!.success(_signal());
      await pumpEventQueue();
      expect(gotA, isEmpty);
      expect(gotB, hasLength(1));
      await subB.cancel();
      await pumpEventQueue();
      expect(cancelled, 1);
      MethodChannelSentomaruFlutter.resetSignalEventsForTesting();
    });

    test('iOS: no signal events, signalEventsSupported false, the channel is never touched', () async {
      debugDefaultTargetPlatformOverride = TargetPlatform.iOS;
      var listened = 0;
      TestDefaultBinaryMessengerBinding.instance.defaultBinaryMessenger.setMockStreamHandler(
        eventChannel,
        MockStreamHandler.inline(onListen: (args, sink) => listened++),
      );
      final platform = MethodChannelSentomaruFlutter();
      final client = SentomaruClient(platform: platform);
      expect(platform.signalEventsSupported, isFalse);
      expect(client.signalEventsSupported, isFalse);
      final got = <SentomaruSignalEvent>[];
      final sub = client.signalEvents.listen(got.add);
      serverResponseSinks[client]!(401, {'code': 'challenge-required', 'challengeKind': 'step_up'}); // Dio still reports
      await pumpEventQueue();
      expect(listened, 0);
      expect(got.map((e) => e.kind), [SentomaruSignalEventKind.serverResponse]);
      await sub.cancel();
    });
  });
}

// guide:begin signal-events
/// What the app does with an event (integration guide, 7d). Informative only: the server already decided the request.
String appReaction(SentomaruSignalEvent e) => switch ((e.kind, e.code, e.challengeKind)) {
      (SentomaruSignalEventKind.signal, _, _) => 'warn_and_log', // leaving the app on a signal alone is discouraged
      (_, 'challenge-required', 'step_up') => 'reauthenticate',
      // D-06h: client.reattest() once, then the operation once with a new nonce; if challenged again, no new reattest.
      (_, 'challenge-required', 'reattest') => 'reattest_then_repeat_once',
      (_, 'challenge-required', _) => 'retry_with_fresh_signals', // no kind or fresh_signals
      (_, 'installation-suspended', _) => 'suspension_screen_keeping_drafts',
      (_, 'installation-revoked', _) => 'enroll_again',
      _ => 'show_the_refusal',
    };
// guide:end signal-events

String _androidFile(String name) {
  var dir = Directory.current;
  final rel = 'sdk/android/signals/src/main/kotlin/br/com/ebees/sentomaru/signals/$name';
  while (true) {
    final f = File('${dir.path}/$rel');
    if (f.existsSync()) return f.readAsStringSync();
    final parent = dir.parent;
    if (parent.path == dir.path) throw StateError('$rel not found above ${Directory.current.path}');
    dir = parent;
  }
}
