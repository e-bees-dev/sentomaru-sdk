// sdk-user-message-v1: the default text, the language resolution, the host override and the code map are pinned by the shared vector
// (contracts/sdk/user-message-vectors-v1.json).
import 'dart:convert';
import 'dart:io';

import 'package:flutter_test/flutter_test.dart';
import 'package:sentomaru_flutter/sentomaru_flutter.dart';

void main() {
  final vectors = jsonDecode(File('../../../contracts/sdk/user-message-vectors-v1.json').readAsStringSync()) as Map<String, dynamic>;

  test('the default texts are the ones of the vector, under the stable key', () {
    expect(SentomaruUserMessage.key, vectors['key']);
    final texts = (vectors['texts'] as Map<String, dynamic>).cast<String, String>();
    expect(SentomaruUserMessage.defaults, texts);
    texts.forEach((locale, text) => expect(SentomaruUserMessage.resolve(locale: locale), text));
  });

  test('the language resolution matches the vector', () {
    final cases = (vectors['localeResolution'] as List).cast<Map<String, dynamic>>();
    expect(cases.length, greaterThanOrEqualTo(10));
    for (final c in cases) {
      expect(SentomaruUserMessage.resolveLocale(c['tag'] as String?), c['locale'], reason: '${c['tag']}');
    }
  });

  test('the host override behaves as the vector says', () {
    final cases = (vectors['overrides'] as List).cast<Map<String, dynamic>>();
    expect(cases.length, 5);
    for (final c in cases) {
      final overrides = (c['overrides'] as Map<String, dynamic>?)?.cast<String, String>();
      expect(SentomaruUserMessage.resolve(locale: c['locale'] as String, overrides: overrides), c['expected'], reason: '${c['name']}');
    }
  });

  test('the code map matches the vector and a non-block gives nothing', () {
    final map = ((vectors['mobileCodes'] as Map<String, dynamic>)['map'] as Map<String, dynamic>);
    expect(map.length, greaterThanOrEqualTo(25));
    map.forEach((code, situation) {
      final got = SentomaruUserMessage.situationFor(code);
      expect(got?.name.toLowerCase(), situation == null ? null : (situation as String).replaceAll('_', '').toLowerCase(), reason: code);
      expect(SentomaruUserMessage.forCode(code, locale: 'en') != null, situation != null, reason: code);
    });
    expect(SentomaruUserMessage.forCode('NeverSeenBefore'), isNull);
    expect(SentomaruUserMessage.forCode(null), isNull);
  });

  test('the text never carries an internal detail', () {
    final words = (vectors['forbiddenInText'] as List).cast<String>();
    for (final text in SentomaruUserMessage.defaults.values) {
      for (final w in words) {
        expect(text.toLowerCase().contains(w.toLowerCase()), isFalse, reason: '$w in $text');
      }
    }
  });

  group('SentomaruException.userMessage', () {
    test('a blocking failure gets the text, in the language asked, without code or detail', () {
      const e = SentomaruException(SentomaruErrorCode.serverRejected, 'secret reason', 'ServerRejected:REVOKED');
      final text = e.userMessage(locale: 'pt-BR')!;
      expect(text, SentomaruUserMessage.defaults['pt-BR']);
      expect(text.contains('REVOKED'), isFalse);
      expect(text.contains('secret'), isFalse);
      expect(const SentomaruException(SentomaruErrorCode.networkUnavailable, 'x').userMessage(), SentomaruUserMessage.defaults['en']);
      expect(const SentomaruException(SentomaruErrorCode.unsupported, 'x', 'Unsupported:APP_ATTEST').userMessage(locale: 'es'),
          SentomaruUserMessage.defaults['es']);
    });

    test('the host override replaces the default of its language only', () {
      const e = SentomaruException(SentomaruErrorCode.notEnrolled, 'x');
      expect(e.userMessage(locale: 'en', overrides: {'en': 'Custom.'}), 'Custom.');
      expect(e.userMessage(locale: 'es', overrides: {'en': 'Custom.'}), SentomaruUserMessage.defaults['es']);
    });

    test('a failure that is not a block gives nothing, and the codes are unchanged', () {
      expect(const SentomaruException(SentomaruErrorCode.cancelled, 'x').userMessage(), isNull);
      expect(const SentomaruException(SentomaruErrorCode.configurationError, 'x').userMessage(), isNull);
      expect(const SentomaruException(SentomaruErrorCode.serverRejected, 'x').userMessage(), isNull);
      expect(SentomaruErrorCode.fromString('ServerRejected:SUSPENDED'), SentomaruErrorCode.serverRejected);
    });
  });
}
