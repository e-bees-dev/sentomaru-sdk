// D-07e / C-03b lab-only entrypoint. NOT the app's `main` (that is lib/main.dart, unchanged):
// verification/run_d07e_device.py builds this target on its own with
//   flutter build appbundle --release --target lib/d07e_pinning_main.dart --dart-define=D07E_SECTION=<base64url JSON>
// and never ships it. On launch it runs one fixed pass and prints one `d07eCase=<json>` line per case to logcat (tag
// `flutter`), then `d07eDone=<json>`; the runner reads only those lines, by the app's pid.
//
// Cases (spec C-03/D-07, item 4 and item 7):
//   - `dio-pinned`: a Dio with the one line `addSentomaruPinning(pins)` (only when D07E_SECTION is set): the leaf is
//     checked after the handshake and BEFORE any byte of the request; a refused connection must leave zero requests at
//     the peer (MITM or the lab-pin echo), which is what C-03b proves on the device;
//   - `dio-plain`: a Dio without the line, in the same app: Dart's TLS stack does not read the Android
//     network_security_config, so this one connects even when the native side of the same APK refuses;
//   - `dio-http-pinned` / `dio-http-other` (only with D07E_HTTP_OTHER): http to the pinned host (the plugin refuses it
//     when the section is set) and http to another host (informative: Dart's own cleartext behaviour).
// Every line has fields of limited format only (case id, ok/refused, status, the type names of the failure, the event
// reason, whether the event names the pinned host, the start time). Never a URL, host, address, certificate or
// exception message. The run id (random, per launch) is in the request paths so the runner counts this launch's
// requests at the peer; it is not a secret.

import 'dart:async';
import 'dart:convert';
import 'dart:math';

import 'package:dio/dio.dart';
import 'package:flutter/widgets.dart';
import 'package:sentomaru_flutter/sentomaru_flutter.dart';

const String _section = String.fromEnvironment('D07E_SECTION');
const String _base = String.fromEnvironment('D07E_BASE', defaultValue: 'https://lab-pin.sentomaru.com.br');
const String _httpOther = String.fromEnvironment('D07E_HTTP_OTHER');

/// I-6: the runner links the MITM connection of `dio-pinned` to the case by its time window; the gap keeps the
/// windows of two cases apart even with a clock skew of a couple of seconds.
const Duration _caseGap = Duration(seconds: 5);

final RegExp _typeName = RegExp(r'^[A-Za-z_][A-Za-z0-9_<>]{0,63}$');

void main() {
  WidgetsFlutterBinding.ensureInitialized();
  runApp(const _D07eApp());
  unawaited(_pass());
}

String _name(Object? value) {
  final text = value.runtimeType.toString();
  return _typeName.hasMatch(text) ? text : 'Other';
}

/// Type names of the failure, `DioException<SentomaruException:pinningRefused>`; never a message.
String _failure(Object e) {
  final parts = <String>[_name(e)];
  Object? inner = e is DioException ? e.error : null;
  if (inner != null) {
    parts.add(_name(inner) + (inner is SentomaruException ? ':${inner.code.name}' : ''));
  } else if (e is SentomaruException) {
    parts[0] = '${parts[0]}:${e.code.name}';
  }
  return parts.join('<');
}

void _emit(String key, Map<String, Object?> line) {
  // ignore: avoid_print
  print('$key=${jsonEncode(line)}');
}

Dio _dio() => Dio(BaseOptions(
      connectTimeout: const Duration(seconds: 15),
      receiveTimeout: const Duration(seconds: 15),
      responseType: ResponseType.plain,
    ));

Future<void> _pass() async {
  final random = Random.secure();
  final run = List.generate(12, (_) => random.nextInt(36).toRadixString(36)).join();
  final pinnedHost = Uri.parse(_base).host;
  SentomaruPins? pins;
  String? sectionError;
  if (_section.isNotEmpty) {
    try {
      pins = SentomaruPins.fromProfileSection(jsonDecode(utf8.decode(base64Url.decode(base64Url.normalize(_section)))));
    } on FormatException catch (e) {
      sectionError = e.message.startsWith('network-pinning') ? e.message : 'format';
    }
  }
  final pinned = _dio();
  String install = 'none';
  final seen = <SentomaruTransportEvent>[];
  if (pins != null) {
    install = pinned.addSentomaruPinning(pins).name;
    pins.events.listen(seen.add);
  }
  final plain = _dio();
  _emit('d07eCase', {
    'id': 'meta',
    'run': run,
    'section': pins != null,
    'sectionError': sectionError,
    'install': install,
    'domains': pins?.domains.length ?? 0,
    'pinnedHostListed': pins?.domains.any((d) => d.host == pinnedHost) ?? false,
  });

  final cases = <(String, Dio, String)>[
    if (pins != null) ('dio-pinned', pinned, '$_base/d07e/$run/dio-pinned'),
    ('dio-plain', plain, '$_base/d07e/$run/dio-plain'),
    if (_httpOther.isNotEmpty) ...[
      ('dio-http-pinned', pins != null ? pinned : plain, 'http://$pinnedHost/d07e/$run/dio-http-pinned'),
      ('dio-http-other', pins != null ? pinned : plain, '$_httpOther/d07e/$run/dio-http-other'),
    ],
  ];
  var count = 0;
  for (final (id, dio, url) in cases) {
    if (count > 0) await Future<void>.delayed(_caseGap);
    final before = seen.length;
    final watch = Stopwatch()..start();
    final line = <String, Object?>{'id': id, 'startedAt': DateTime.now().millisecondsSinceEpoch};
    try {
      final response = await dio.get<String>(url);
      line['outcome'] = 'ok';
      line['status'] = response.statusCode;
    } catch (e) {
      line['outcome'] = 'refused';
      line['error'] = _failure(e);
    }
    // Events are delivered on a microtask after the failure; give the stream one turn before reading them.
    await Future<void>.delayed(const Duration(milliseconds: 50));
    line['ms'] = watch.elapsedMilliseconds;
    final fresh = seen.sublist(before);
    line['event'] = fresh.isEmpty ? 'none' : fresh.first.reason.wireName;
    line['events'] = fresh.length;
    // M-1: like the native line, whether every event names the pinned host of the section (never the URL).
    if (fresh.isNotEmpty) {
      line['eventHostPinned'] = fresh.every((e) => e.host == pinnedHost);
    }
    _emit('d07eCase', line);
    count++;
  }
  _emit('d07eDone', {'cases': count});
}

class _D07eApp extends StatelessWidget {
  const _D07eApp();

  @override
  Widget build(BuildContext context) => const SizedBox.shrink();
}
