import 'dart:convert';
import 'dart:io';

import 'package:flutter/foundation.dart';
import 'package:flutter/services.dart';
import 'package:flutter_test/flutter_test.dart';
import 'package:sentomaru_flutter/sentomaru_flutter.dart';

/// D-05e: the snapshot the plugin builds, against the contract catalog and the observation schema of the repository.
void main() {
  TestWidgetsFlutterBinding.ensureInitialized();

  final catalog = _contract('signals-catalog-v1.json');
  final schema = _contract('signals-observation-schema-v1.json');
  final contractCaps = (catalog['capabilities'] as List).cast<Map<String, dynamic>>();

  group('catalog copy', () {
    test('version, ids, versions, sources and order equal the contract JSON', () {
      expect(SentomaruSignalsCatalog.version, catalog['version']);
      expect(
        [for (final c in SentomaruSignalsCatalog.capabilities) [c.capabilityId, c.version, c.source]],
        [for (final c in contractCaps) [c['capabilityId'], c['version'], c['source']]],
      );
    });

    test('server-only ids come from the catalog sources', () {
      expect(SentomaruSignalsCatalog.serverVerifiedIds,
          {for (final c in contractCaps) if (c['source'] == 'server_verified') c['capabilityId']});
      expect(SentomaruSignalsCatalog.serverVerifiedIds, containsAll(['play_integrity_failed', 'build_unregistered', 'app_identity_mismatch']));
    });

    test('default + rasp + app integrity + device threat ids are exactly the client_observed ones, disjoint', () {
      final client = [for (final c in contractCaps) if (c['source'] == 'client_observed') c['capabilityId']];
      expect([
        ...SentomaruSignalsCatalog.defaultCapabilityIds,
        ...SentomaruSignalsCatalog.raspCapabilityIds,
        ...SentomaruSignalsCatalog.appIntegrityCapabilityIds,
        ...SentomaruSignalsCatalog.deviceThreatCapabilityIds,
        ...SentomaruSignalsCatalog.screenCapabilityIds,
        ...SentomaruSignalsCatalog.sessionCapabilityIds,
      ], client);
      expect(SentomaruSignalsCatalog.defaultCapabilityIds.toSet().intersection(
          SentomaruSignalsCatalog.raspCapabilityIds.toSet()), isEmpty);
    });
  });

  group('wire JSON', () {
    // Every catalog fixture (server ones included), observed in another time zone, with a null detail value.
    final observedAt = DateTime.parse('2026-10-21T07:00:00.123-03:00');
    final observations = [
      for (final c in contractCaps)
        SignalObservation(
          capabilityId: c['capabilityId'] as String,
          version: c['fixture']['version'] as String,
          state: SignalState.fromString(c['fixture']['state'] as String),
          source: c['fixture']['source'] as String,
          observedAt: observedAt,
          data: {...(c['fixture']['detail'] as Map).cast<String, dynamic>(), 'dropped': null, 'count': 2},
        ),
    ];
    final snapshot = SignalsSnapshot(
        collectedAt: DateTime.parse('2026-10-21T07:00:00-03:00'), durationMs: 12, observations: observations);
    final wire = jsonDecode(snapshot.toJson()) as Map<String, dynamic>;

    test('validates against signals-observation-schema-v1.json', () {
      expect(_validate(schema, wire, r'$'), isEmpty);
    });

    test('catalogVersion from the catalog, collectedAt and observedAt in UTC, durationMs kept', () {
      expect(wire['catalogVersion'], '1.15.0');
      expect(wire['collectedAt'], '2026-10-21T10:00:00.000Z');
      expect(wire['durationMs'], 12);
      for (final o in wire['observations'] as List) {
        expect(o['observedAt'], '2026-10-21T10:00:00.123Z');
      }
    });

    test('drops the server_verified ids; keeps the twenty-three client ones with wire states and string details', () {
      final items = (wire['observations'] as List).cast<Map<String, dynamic>>();
      expect(items.map((o) => o['capabilityId']), [
        ...SentomaruSignalsCatalog.defaultCapabilityIds,
        ...SentomaruSignalsCatalog.raspCapabilityIds,
        ...SentomaruSignalsCatalog.appIntegrityCapabilityIds,
        ...SentomaruSignalsCatalog.deviceThreatCapabilityIds,
        ...SentomaruSignalsCatalog.screenCapabilityIds,
        ...SentomaruSignalsCatalog.sessionCapabilityIds,
      ]);
      for (final o in items) {
        final fixture = contractCaps.firstWhere((c) => c['capabilityId'] == o['capabilityId'])['fixture'];
        expect(o['state'], fixture['state']);
        expect(o['source'], 'client_observed');
        expect(o['detail'], {...fixture['detail'] as Map, 'count': '2'});
        expect((o['detail'] as Map).containsKey('dropped'), isFalse);
      }
    });

    test('a server id is dropped in any case, a negative duration is 0', () {
      final s = SignalsSnapshot(collectedAt: observedAt, durationMs: -5, observations: [
        SignalObservation(capabilityId: 'Build_Unregistered', version: '1.0.0', state: SignalState.notDetected,
            source: 'client_observed', observedAt: observedAt),
      ]);
      expect(s.toMap()['observations'], isEmpty);
      expect(s.toMap()['durationMs'], 0);
    });

    test('the twelve client fixtures the plugin collects fit in 3 KiB as a header value', () {
      final collected = {...SentomaruSignalsCatalog.defaultCapabilityIds, ...SentomaruSignalsCatalog.raspCapabilityIds};
      final twelve = SignalsSnapshot(collectedAt: snapshot.collectedAt, durationMs: 12,
          observations: [for (final o in observations) if (collected.contains(o.capabilityId)) o]);
      expect(encodeSignalsHeader(twelve.toJson()).length, lessThanOrEqualTo(3 * 1024));
    });

    test('the fifteen client fixtures the plugin can collect (D-12c included) fit in the 4 KiB header limit', () {
      // The nine D-24, D-20 and F-07/F-08 ids are opt-in on the Android SDK and not collected by the plugin: all twenty-three client fixtures
      // together do not fit in 4 KiB, so an app that turns on every detector chooses a subset for the header.
      final collected = {
        ...SentomaruSignalsCatalog.defaultCapabilityIds,
        ...SentomaruSignalsCatalog.raspCapabilityIds,
        ...SentomaruSignalsCatalog.appIntegrityCapabilityIds,
      };
      final fifteen = SignalsSnapshot(collectedAt: snapshot.collectedAt, durationMs: 15,
          observations: [for (final o in observations) if (collected.contains(o.capabilityId)) o]);
      expect(encodeSignalsHeader(fifteen.toJson()).length, lessThanOrEqualTo(4 * 1024));
    });

    test('every SignalState has the schema name', () {
      final names = (schema['properties']['observations']['items']['properties']['state']['enum'] as List).toList();
      expect(SignalState.values.map((s) => s.wireName).toList(), names);
    });
  });

  group('collectSignalsSnapshot over the channel', () {
    final platform = MethodChannelSentomaruFlutter();
    const channel = MethodChannel('sentomaru_flutter');
    final messenger = TestDefaultBinaryMessengerBinding.instance.defaultBinaryMessenger;

    tearDown(() {
      messenger.setMockMethodCallHandler(channel, null);
      debugDefaultTargetPlatformOverride = null;
    });

    Map<String, Object?> obs(String id, String state, [Map<String, String>? data]) => {
          'capabilityId': id,
          'version': '1.0.0',
          'state': state,
          'source': 'client_observed',
          'observedAt': '2026-10-21T10:00:00.004Z',
          'data': data ?? <String, String>{},
        };

    for (final rasp in [false, true]) {
      test('asks the native side with rasp=$rasp and builds the snapshot', () async {
        final calls = <MethodCall>[];
        messenger.setMockMethodCallHandler(channel, (call) async {
          calls.add(call);
          return {
            'collectedAt': '2026-10-21T10:00:00Z',
            'durationMs': 9,
            'observations': [
              obs('root_indicated', 'not_detected'),
              if (rasp) obs('root_artifacts', 'unknown', {'partial': 'root_package'}),
            ],
          };
        });
        final snapshot = await platform.collectSignalsSnapshot(rasp: rasp);
        expect(calls.single.method, 'collectSignalsSnapshot');
        expect(calls.single.arguments, {'rasp': rasp});
        expect(snapshot.collectedAt, DateTime.utc(2026, 10, 21, 10));
        expect(snapshot.durationMs, 9);
        final wire = snapshot.toMap();
        expect(_validate(schema, jsonDecode(jsonEncode(wire)), r'$'), isEmpty);
        if (rasp) {
          expect((wire['observations'] as List).last,
              containsPair('detail', {'partial': 'root_package'}));
          expect((wire['observations'] as List).last, containsPair('state', 'UNKNOWN'));
        }
      });
    }

    test('rasp defaults to false', () async {
      Object? args;
      messenger.setMockMethodCallHandler(channel, (call) async {
        args = call.arguments;
        return {'collectedAt': '2026-10-21T10:00:00Z', 'durationMs': 1, 'observations': []};
      });
      await platform.collectSignalsSnapshot();
      expect(args, {'rasp': false});
    });

    final malformed = <String, Map<String, Object?>>{
      'no collectedAt': {'durationMs': 1, 'observations': []},
      'bad collectedAt': {'collectedAt': 'yesterday', 'durationMs': 1, 'observations': []},
      'no durationMs': {'collectedAt': '2026-10-21T10:00:00Z', 'observations': []},
      'no observations': {'collectedAt': '2026-10-21T10:00:00Z', 'durationMs': 1},
      'observation without observedAt': {
        'collectedAt': '2026-10-21T10:00:00Z',
        'durationMs': 1,
        'observations': [
          {'capabilityId': 'root_artifacts', 'version': '1.0.0', 'state': 'unknown', 'source': 'client_observed'},
        ],
      },
      'duplicate ids': {
        'collectedAt': '2026-10-21T10:00:00Z',
        'durationMs': 1,
        'observations': [obs('root_artifacts', 'unknown'), obs('ROOT_ARTIFACTS', 'unknown')],
      },
    };
    malformed.forEach((name, reply) {
      test('a malformed native reply is a channelError ($name), never a made-up value', () async {
        messenger.setMockMethodCallHandler(channel, (call) async => reply);
        await expectLater(
          platform.collectSignalsSnapshot(rasp: true),
          throwsA(isA<SentomaruException>().having((e) => e.code, 'code', SentomaruErrorCode.channelError)),
        );
      });
    });

    test('collectSignals() is unchanged: same method, no arguments', () async {
      final calls = <MethodCall>[];
      messenger.setMockMethodCallHandler(channel, (call) async {
        calls.add(call);
        return [obs('root_indicated', 'not_detected')];
      });
      final list = await platform.collectSignals();
      expect(calls.single.method, 'collectSignals');
      expect(calls.single.arguments, isNull);
      expect(list.single.state, SignalState.notDetected);
    });

    // D-10e: iOS now goes to the native side (ios_platform_test.dart); a platform without native signals keeps this.
    test('no native signals (macOS): no channel call; the D-05 ids come back UNSUPPORTED, the six old ones are not invented', () async {
      debugDefaultTargetPlatformOverride = TargetPlatform.macOS;
      var called = false;
      messenger.setMockMethodCallHandler(channel, (call) async {
        called = true;
        return null;
      });
      final rasp = await platform.collectSignalsSnapshot(rasp: true);
      final plain = await platform.collectSignalsSnapshot();
      debugDefaultTargetPlatformOverride = null;
      expect(called, isFalse);
      expect(rasp.observations.map((o) => o.capabilityId), SentomaruSignalsCatalog.raspCapabilityIds);
      expect(rasp.observations.map((o) => o.state).toSet(), {SignalState.unsupported});
      expect(plain.observations, isEmpty);
      expect(_validate(schema, jsonDecode(rasp.toJson()), r'$'), isEmpty);
      for (final o in jsonDecode(rasp.toJson())['observations'] as List) {
        final cap = contractCaps.firstWhere((c) => c['capabilityId'] == o['capabilityId']);
        expect(cap['supportedStates'], contains(o['state']));
      }
    });
  });
}

Map<String, dynamic> _contract(String name) {
  var dir = Directory.current;
  while (true) {
    final f = File('${dir.path}/contracts/sdk/$name');
    if (f.existsSync()) return jsonDecode(f.readAsStringSync()) as Map<String, dynamic>;
    final parent = dir.parent;
    if (parent.path == dir.path) throw StateError('contracts/sdk/$name not found above ${Directory.current.path}');
    dir = parent;
  }
}

final _dateTime = RegExp(r'^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(\.\d+)?(Z|[+-]\d{2}:\d{2})$');
const _known = {
  r'$schema', r'$id', 'title', 'type', 'required', 'properties', 'additionalProperties', 'items', 'pattern', 'enum',
  'minimum', 'format',
};

/// The JSON Schema keywords the observation schema uses; an unknown keyword fails instead of being skipped.
List<String> _validate(Map<String, dynamic> s, Object? v, String at) {
  final errors = <String>[];
  for (final k in s.keys) {
    if (!_known.contains(k)) errors.add('$at: schema keyword $k not supported by this validator');
  }
  switch (s['type']) {
    case 'object':
      if (v is! Map) return [...errors, '$at: not an object'];
      for (final r in (s['required'] as List? ?? const [])) {
        if (!v.containsKey(r)) errors.add('$at: missing $r');
      }
      final props = (s['properties'] as Map? ?? const {}).cast<String, dynamic>();
      v.forEach((key, value) {
        final p = props[key];
        if (p != null) {
          errors.addAll(_validate(p as Map<String, dynamic>, value, '$at.$key'));
        } else if (s['additionalProperties'] == false) {
          errors.add('$at: unexpected $key');
        } else if (s['additionalProperties'] is Map) {
          errors.addAll(_validate(s['additionalProperties'] as Map<String, dynamic>, value, '$at.$key'));
        }
      });
    case 'array':
      if (v is! List) return [...errors, '$at: not an array'];
      for (var i = 0; i < v.length; i++) {
        errors.addAll(_validate(s['items'] as Map<String, dynamic>, v[i], '$at[$i]'));
      }
    case 'string':
      if (v is! String) return [...errors, '$at: not a string'];
      if (s['pattern'] != null && !RegExp(s['pattern'] as String).hasMatch(v)) errors.add('$at: pattern');
      if (s['format'] == 'date-time' && (!_dateTime.hasMatch(v) || DateTime.tryParse(v) == null)) {
        errors.add('$at: not a date-time');
      }
    case 'integer':
      if (v is! int) return [...errors, '$at: not an integer'];
      if (s['minimum'] != null && v < (s['minimum'] as num)) errors.add('$at: below minimum');
    default:
      errors.add('$at: unsupported type ${s['type']}');
  }
  if (s['enum'] != null && !(s['enum'] as List).contains(v)) errors.add('$at: not in enum');
  return errors;
}
