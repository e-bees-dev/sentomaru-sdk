import 'dart:convert';
import 'dart:io';

import 'package:dio/dio.dart';
import 'package:flutter_test/flutter_test.dart';
import 'package:sentomaru_flutter/sentomaru_flutter.dart';

Map<String, dynamic> answer({bool enabled = true, List<Map<String, Object>>? operations}) => {
      'schemaVersion': '1',
      'enabled': enabled,
      'operations': operations ??
          [
            {'operation': 'concluir_demanda', 'enforced': true},
            {'operation': 'criar_demanda', 'enforced': true},
          ],
    };

SentomaruCapabilityGate gate({bool enforce = true, SentomaruMismatchPolicy policy = SentomaruMismatchPolicy.degrade}) =>
    SentomaruCapabilityGate(appEnforces: enforce, operations: const ['criar_demanda', 'concluir_demanda'], policy: policy);

/// Guide (docs/api/INTEGRATION_GUIDE.md §7a): what an app does at bootstrap. [log] stands in for the app's logger.
Future<SentomaruCapabilityGate> bootstrapGate(Dio dio, String apiBase, {required bool enforce, required void Function(String) log}) async {
  // guide:begin capabilities-bootstrap
  // Once at bootstrap: does the backend verify what this build marks? (Sentomaru.AspNetCore 4.x capabilities route)
  final capabilities = await SentomaruCapabilities.fetch(dio, Uri.parse('$apiBase/integrity/capabilities'));
  final gate = SentomaruCapabilityGate(
    appEnforces: enforce, // e.g. your SENTOMARU_ENFORCE build flag
    operations: const ['criar_demanda', 'concluir_demanda'],
    onMismatch: (m) => log('sentomaru capabilities mismatch: ${m.name}'), // a log, never a user-facing error
  )..evaluate(capabilities);
  // Per request: mark the operation only when the gate says so (backend off = plain call, the user is not blocked).
  // options.extra['sentomaru_operation'] = gate.shouldMark('criar_demanda') ? 'criar_demanda' : null;
  // guide:end capabilities-bootstrap
  return gate;
}

/// Guide §7b: a SAFE use of an advisory risk event. The app never decides on its own; the server decides every request.
bool needsReconfirmation(SentomaruRiskEvent event) {
  // guide:begin risk-event
  // Advisory only: ask the user to confirm a sensitive action again (friction), never block, never trust it as "safe".
  // The server already decided this request; an absent or low event proves nothing.
  return event.riskBand == 'high' || (event.riskIndex ?? 0) >= 80;
  // guide:end risk-event
}

void main() {
  test('parses the backend answer and refuses malformed ones', () {
    final c = SentomaruCapabilities.fromJson(answer());
    expect(c.enabled, isTrue);
    expect(c.operations['criar_demanda'], isTrue);
    expect(() => SentomaruCapabilities.fromJson({...answer(), 'schemaVersion': '2'}), throwsFormatException);
    expect(() => SentomaruCapabilities.fromJson({...answer(), 'enabled': 'yes'}), throwsFormatException);
    expect(
        () => SentomaruCapabilities.fromJson(answer(operations: [
              {'operation': 'x', 'enforced': 'yes'}
            ])),
        throwsFormatException);
  });

  test('the app with enforce on degrades when the backend is off (the issue #143 case)', () {
    final mismatches = <SentomaruCapabilityMismatch>[];
    final g = SentomaruCapabilityGate(appEnforces: true, operations: const ['criar_demanda'], onMismatch: mismatches.add);
    expect(g.evaluate(SentomaruCapabilities.fromJson(answer(enabled: false, operations: []))),
        SentomaruCapabilityMismatch.backendDisabled);
    expect(mismatches, [SentomaruCapabilityMismatch.backendDisabled]);
    expect(g.shouldMark('criar_demanda'), isFalse);
  });

  test('unprotected operations are not marked; observe-only is reported but still marked; keep always marks', () {
    final few = gate()..evaluate(SentomaruCapabilities.fromJson(answer(operations: [
          {'operation': 'criar_demanda', 'enforced': true}
        ])));
    expect(few.mismatch, SentomaruCapabilityMismatch.operationNotProtected);
    expect(few.shouldMark('criar_demanda'), isTrue);
    expect(few.shouldMark('concluir_demanda'), isFalse);
    final warned = <SentomaruCapabilityWarning>[];
    final observe = SentomaruCapabilityGate(appEnforces: true, operations: const ['criar_demanda', 'concluir_demanda'],
        onWarning: warned.add)
      ..evaluate(SentomaruCapabilities.fromJson(answer(operations: [
        {'operation': 'criar_demanda', 'enforced': true},
        {'operation': 'concluir_demanda', 'enforced': false},
      ])));
    expect(observe.mismatch, SentomaruCapabilityMismatch.none); // a warning, not a mismatch
    expect(warned, [SentomaruCapabilityWarning.operationObserveOnly]);
    expect(observe.shouldMark('concluir_demanda'), isTrue);
    final keep = gate(policy: SentomaruMismatchPolicy.keep)
      ..evaluate(SentomaruCapabilities.fromJson(answer(enabled: false, operations: [])));
    expect(keep.shouldMark('criar_demanda'), isTrue);
  });

  test('consistent configuration marks; unknown keeps the app setting; enforce off never marks', () {
    final g = gate()..evaluate(SentomaruCapabilities.fromJson(answer()));
    expect(g.mismatch, SentomaruCapabilityMismatch.none);
    expect(g.shouldMark('criar_demanda'), isTrue);
    expect(g.shouldMark('outra'), isFalse);
    expect((gate()..evaluate(null)).shouldMark('criar_demanda'), isTrue);
    expect((gate(enforce: false)..evaluate(SentomaruCapabilities.fromJson(answer()))).shouldMark('criar_demanda'), isFalse);
  });

  test('fetch reads the route over loopback and returns null on errors or plain http elsewhere', () async {
    final server = await HttpServer.bind(InternetAddress.loopbackIPv4, 0);
    server.listen((request) {
      if (request.uri.path == '/redirect') {
        request.response.statusCode = 302;
        request.response.headers.set('location', '/integrity/capabilities');
      } else if (request.uri.path == '/integrity/capabilities') {
        request.response.headers.contentType = ContentType.json;
        request.response.write(jsonEncode(answer()));
      } else {
        request.response.statusCode = 404;
      }
      request.response.close();
    });
    addTearDown(() => server.close(force: true));
    final dio = Dio();
    final base = 'http://127.0.0.1:${server.port}';
    final c = await SentomaruCapabilities.fetch(dio, Uri.parse('$base/integrity/capabilities'));
    expect(c?.operations['criar_demanda'], isTrue);
    expect(await SentomaruCapabilities.fetch(dio, Uri.parse('$base/nao-existe')), isNull);
    expect(await SentomaruCapabilities.fetch(dio, Uri.parse('http://api.example/integrity/capabilities')), isNull);
    expect(await SentomaruCapabilities.fetch(dio, Uri.parse('$base/redirect')), isNull); // a 302 is not followed
  });

  test('bootstrap snippet of the guide degrades against a disabled backend', () async {
    final server = await HttpServer.bind(InternetAddress.loopbackIPv4, 0);
    server.listen((request) {
      request.response.headers.contentType = ContentType.json;
      request.response.write(jsonEncode(answer(enabled: false, operations: [])));
      request.response.close();
    });
    addTearDown(() => server.close(force: true));
    final logs = <String>[];
    final g = await bootstrapGate(Dio(), 'http://127.0.0.1:${server.port}', enforce: true, log: logs.add);
    expect(g.shouldMark('criar_demanda'), isFalse);
    expect(logs, ['sentomaru capabilities mismatch: backendDisabled']);
  });

  test('risk event snippet only adds friction for a high event', () {
    expect(needsReconfirmation(const SentomaruRiskEvent(code: 'X', riskBand: 'high', reason: '')), isTrue);
    expect(needsReconfirmation(const SentomaruRiskEvent(code: 'X', riskIndex: 10, reason: '')), isFalse);
  });
}
