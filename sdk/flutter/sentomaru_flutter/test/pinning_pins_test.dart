// C-03a: the SPKI hash against openssl (RSA 2048, EC P-256, EC P-384, generated at test time) and the validation of
// the `network-pinning` v1 section with the CLI's field paths (contracts/devsecops/cli-v1.md, network-pinning).
import 'dart:convert';
import 'dart:io';
import 'dart:typed_data';

import 'package:flutter_test/flutter_test.dart';
import 'package:sentomaru_flutter/sentomaru_flutter.dart';
import 'package:sentomaru_flutter/src/pinning/spki.dart';

import 'support/pinning_lab.dart';

const _pinA = 'sha256/wiHsTSryBCSSgeMtp2iGevQhCi4C1T6dp5yPxEgMS5s=';
const _pinB = 'sha256/jl0tsLo4WkI1z7aBKcSTL/z72E7fhJsNkpqjetYrShI=';

Map<String, Object?> _domain([Map<String, Object?> override = const {}]) => {
      'host': 'lab-pin.sentomaru.com.br',
      'includeSubdomains': false,
      'pins': [_pinA],
      'backupPins': [_pinB],
      ...override,
    };

Map<String, Object?> _section([Map<String, Object?> override = const {}]) => {
      'version': '1',
      'expiration': '2027-03-31',
      'domains': [_domain()],
      ...override,
    };

String _pin(int seed) => 'sha256/${base64.encode(List.filled(32, seed))}';

Matcher _formatError(String path) =>
    throwsA(isA<FormatException>().having((e) => e.message, 'message', path));

void main() {
  group('SPKI pin equals openssl', () {
    late LabPki pki;
    setUpAll(() async => pki = await LabPki.create());
    tearDownAll(() => pki.dispose());

    for (final (key, kind) in [('a', 'RSA 2048'), ('b', 'EC P-256'), ('x', 'EC P-384')]) {
      test(kind, () {
        final leaf = pki[key];
        expect(spkiPin(leaf.der), leaf.opensslPin);
      });
    }

    test('malformed DER -> null, never a pin', () {
      final der = pki['b'].der;
      expect(spkiPin(Uint8List(0)), isNull);
      expect(spkiPin(Uint8List.fromList([0x30, 0x80, 0, 0])), isNull, reason: 'indefinite length');
      expect(spkiPin(Uint8List.sublistView(der, 0, der.length - 1)), isNull, reason: 'truncated');
      expect(spkiPin(Uint8List.fromList([...der, 0])), isNull, reason: 'trailing byte');
      final wrongTag = Uint8List.fromList(der)..[0] = 0x31;
      expect(spkiPin(wrongTag), isNull);
      expect(spkiPin(Uint8List.fromList(List.filled(64, 0x30))), isNull);
    });
  });

  group('fromProfileSection', () {
    test('the contract example parses', () {
      // From the repository root, wherever `flutter test` runs inside it.
      var dir = Directory.current;
      while (!Directory('${dir.path}/contracts/devsecops').existsSync() && dir.parent.path != dir.path) {
        dir = dir.parent;
      }
      final example = File('${dir.path}/contracts/devsecops/examples/protect-profile-network-pinning-v1.example.json');
      final profile = jsonDecode(example.readAsStringSync()) as Map;
      final pins = SentomaruPins.fromProfileSection(profile['controls']['network-pinning']);
      expect(pins.expiration, '2027-03-31');
      expect(pins.domains.single.host, 'lab-pin.sentomaru.com.br');
      expect(pins.domains.single.accepts(_pinA), isTrue);
      expect(pins.domains.single.accepts(_pinB), isTrue);
      expect(pins.domains.single.accepts(_pin(1)), isFalse);
    });

    final cases = <String, (Object?, String)>{
      'not a map': (<Object>[], 'network-pinning'),
      'unknown field': (_section({'extra': 1}), 'network-pinning.extra'),
      'unknown field, long name': (_section({'x' * 65: 1}), 'network-pinning.unknown-field'),
      'missing domains': (Map.of(_section())..remove('domains'), 'network-pinning.domains'),
      'version 2': (_section({'version': '2'}), 'network-pinning.version'),
      'version number': (_section({'version': 1}), 'network-pinning.version'),
      'expiration format': (_section({'expiration': '2027-3-31'}), 'network-pinning.expiration'),
      'expiration not in calendar': (_section({'expiration': '2027-02-30'}), 'network-pinning.expiration'),
      'expiration with newline': (_section({'expiration': '2027-03-31\n'}), 'network-pinning.expiration'),
      'domains empty': (_section({'domains': []}), 'network-pinning.domains'),
      'domains > 16': (
        _section({'domains': [for (var i = 0; i < 17; i++) _domain({'host': 'h$i.example.com'})]}),
        'network-pinning.domains'
      ),
      'host repeated': (_section({'domains': [_domain(), _domain()]}), 'network-pinning.domains'),
      'host repeated and a bad pin later: the pin first (CLI order)': (
        _section({'domains': [_domain(), _domain({'pins': ['x']})]}),
        'network-pinning.domains.pins'
      ),
      'over 16 pins and overlap: the total first (CLI order)': (
        _section({'domains': [_domain({'pins': [for (var i = 0; i < 9; i++) _pin(i)], 'backupPins': [for (var i = 8; i < 16; i++) _pin(i)]})]}),
        'network-pinning.domains.pins'
      ),
      'domain unknown field': (_section({'domains': [_domain({'port': 443})]}), 'network-pinning.domains.port'),
      'domain missing pins': (
        _section({'domains': [Map.of(_domain())..remove('pins')]}),
        'network-pinning.domains.pins'
      ),
      'host wildcard': (_section({'domains': [_domain({'host': '*.sentomaru.com.br'})]}), 'network-pinning.domains.host'),
      'host IP': (_section({'domains': [_domain({'host': '10.0.0.1'})]}), 'network-pinning.domains.host'),
      'host one label': (_section({'domains': [_domain({'host': 'localhost'})]}), 'network-pinning.domains.host'),
      'host port': (_section({'domains': [_domain({'host': 'a.com:443'})]}), 'network-pinning.domains.host'),
      'host trailing dot': (_section({'domains': [_domain({'host': 'a.com.'})]}), 'network-pinning.domains.host'),
      'host uppercase': (_section({'domains': [_domain({'host': 'A.com'})]}), 'network-pinning.domains.host'),
      'includeSubdomains string': (
        _section({'domains': [_domain({'includeSubdomains': 'false'})]}),
        'network-pinning.domains.includeSubdomains'
      ),
      'pins empty': (_section({'domains': [_domain({'pins': []})]}), 'network-pinning.domains.pins'),
      'pin without prefix': (
        _section({'domains': [_domain({'pins': [_pinA.substring(7)]})]}),
        'network-pinning.domains.pins'
      ),
      'pin url-safe base64': (
        _section({'domains': [_domain({'pins': ['sha256/${'_' * 43}=']})]}),
        'network-pinning.domains.pins'
      ),
      'pin not canonical (spare bits)': (
        _section({'domains': [_domain({'pins': ['${_pinA.substring(0, 49)}t=']})]}),
        'network-pinning.domains.pins'
      ),
      'pin repeated': (_section({'domains': [_domain({'pins': [_pinA, _pinA]})]}), 'network-pinning.domains.pins'),
      'no backup': (_section({'domains': [_domain({'backupPins': []})]}), 'network-pinning.domains.backupPins'),
      'pin in both lists': (
        _section({'domains': [_domain({'backupPins': [_pinA]})]}),
        'network-pinning.domains.backupPins'
      ),
      'more than 16 pins': (
        _section({'domains': [_domain({'pins': [for (var i = 0; i < 9; i++) _pin(i)], 'backupPins': [for (var i = 10; i < 18; i++) _pin(i)]})]}),
        'network-pinning.domains.pins'
      ),
    };
    for (final MapEntry(key: name, value: (section, path)) in cases.entries) {
      test('refuses: $name -> $path', () => expect(() => SentomaruPins.fromProfileSection(section), _formatError(path)));
    }

    test('16 pins and 16 domains are accepted', () {
      SentomaruPins.fromProfileSection(_section({'domains': [_domain({'pins': [for (var i = 0; i < 8; i++) _pin(i)], 'backupPins': [for (var i = 10; i < 18; i++) _pin(i)]})]}));
      SentomaruPins.fromProfileSection(
          _section({'domains': [for (var i = 0; i < 16; i++) _domain({'host': 'h$i.example.com'})]}));
    });

    test('the refusal never carries a value of the profile', () {
      try {
        SentomaruPins.fromProfileSection(_section({'domains': [_domain({'host': 'secret-tenant.Example.com'})]}));
        fail('should refuse');
      } on FormatException catch (e) {
        expect(e.toString(), isNot(contains('secret')));
      }
    });

    test('past expiration is accepted and inactive (fail open); the 180-day cap is the CLI rule', () {
      final past = SentomaruPins.fromProfileSection(_section({'expiration': '2020-01-01'}));
      expect(past.isActive, isFalse);
      final far = SentomaruPins.fromProfileSection(_section({'expiration': '2099-01-01'}));
      expect(far.isActive, isTrue);
    });
  });

  group('domainFor', () {
    final pins = SentomaruPins.fromProfileSection(_section({
      'domains': [
        _domain({'host': 'example.com', 'includeSubdomains': true}),
        _domain({'host': 'api.example.com', 'includeSubdomains': false, 'pins': [_pin(1)], 'backupPins': [_pin(2)]}),
        _domain({'host': 'exact.org'}),
      ]
    }));

    test('exact entry first, then the longest includeSubdomains parent', () {
      expect(pins.domainFor('api.example.com')!.host, 'api.example.com');
      expect(pins.domainFor('v2.api.example.com')!.host, 'example.com');
      expect(pins.domainFor('example.com')!.host, 'example.com');
      expect(pins.domainFor('exact.org')!.host, 'exact.org');
      expect(pins.domainFor('sub.exact.org'), isNull);
      expect(pins.domainFor('notexample.com'), isNull);
      expect(pins.domainFor('example.com.evil.net'), isNull);
    });

    test('case and one trailing dot are normalized', () {
      expect(pins.domainFor('EXACT.org.')!.host, 'exact.org');
      expect(pins.domainFor('exact.org..'), isNull);
    });
  });
}
