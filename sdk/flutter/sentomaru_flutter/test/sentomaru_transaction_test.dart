import 'package:flutter/foundation.dart';
import 'package:flutter/services.dart';
import 'package:flutter_test/flutter_test.dart';
import 'package:sentomaru_flutter/sentomaru_flutter.dart';

void main() {
  TestWidgetsFlutterBinding.ensureInitialized();
  final channel = const MethodChannel('sentomaru_flutter');
  final calls = <MethodCall>[];
  Object? Function(MethodCall)? reply;

  setUp(() {
    calls.clear();
    SentomaruFlutterPlatform.instance = MethodChannelSentomaruFlutter();
    TestDefaultBinaryMessengerBinding.instance.defaultBinaryMessenger.setMockMethodCallHandler(channel, (call) async {
      calls.add(call);
      return reply?.call(call);
    });
  });
  tearDown(() {
    debugDefaultTargetPlatformOverride = null;
    TestDefaultBinaryMessengerBinding.instance.defaultBinaryMessenger.setMockMethodCallHandler(channel, null);
  });

  test('outside iOS and Android it is unsupported and never reaches the channel', () async {
    for (final platform in [TargetPlatform.fuchsia, TargetPlatform.linux, TargetPlatform.macOS, TargetPlatform.windows]) {
      debugDefaultTargetPlatformOverride = platform;
      await expectLater(
        const SentomaruTransactionSigner().isEnrolled(),
        throwsA(isA<SentomaruTransactionException>().having((e) => e.error, 'error', SentomaruTransactionError.unsupported)),
      );
    }
    expect(calls, isEmpty);
  });

  group('Android', () {
    final challenge = SentomaruTransactionChallenge(
      challengeId: '11111111-1111-4111-8111-111111111111',
      token: 'dG9rZW4=',
      attestationChallenge: Uint8List.fromList(List.filled(32, 7)),
      expiresAt: '2026-11-04T10:05:00+00:00',
    );

    setUp(() => debugDefaultTargetPlatformOverride = TargetPlatform.android);

    test('isEnrolled and discard reach the channel', () async {
      reply = (_) => true;
      expect(await const SentomaruTransactionSigner().isEnrolled(), isTrue);
      reply = (_) => null;
      await const SentomaruTransactionSigner().discard();
      expect(calls.map((c) => c.method), ['txIsEnrolled', 'txDiscard']);
    });

    test('createKey sends the challenge, biometricOnly and strongBox, and returns the native bytes', () async {
      reply = (_) => Uint8List.fromList([1, 2, 3]);
      final body = await const SentomaruTransactionSigner().createKey(challenge: challenge, strongBox: true);
      expect(body, Uint8List.fromList([1, 2, 3]));
      final args = calls.single.arguments as Map;
      expect(args['biometricOnly'], isTrue);
      expect(args['strongBox'], isTrue);
      expect((args['challenge'] as Map)['challengeId'], challenge.challengeId);
      expect((args['challenge'] as Map)['attestationChallenge'], challenge.attestationChallenge);
    });

    test('createKey without the challenge sends none, so the native side refuses with a typed error', () async {
      reply = (_) => throw PlatformException(code: 'InvalidRequest:PARAMS');
      await expectLater(
        const SentomaruTransactionSigner().createKey(),
        throwsA(isA<SentomaruTransactionException>().having((e) => e.error, 'error', SentomaruTransactionError.invalidRequest)),
      );
      expect((calls.single.arguments as Map).containsKey('challenge'), isFalse);
    });

    test('sign sends biometricOnly and the cancel label; the iOS call does not', () async {
      reply = (_) => 'sentomaru-tx-v1.x.y';
      await const SentomaruTransactionSigner()
          .sign(operationId: 'op-1', body: Uint8List(0), reason: 'Confirmar', cancelLabel: 'Voltar', biometricOnly: false);
      final args = calls.single.arguments as Map;
      expect(args['biometricOnly'], isFalse);
      expect(args['cancelLabel'], 'Voltar');
      calls.clear();
      debugDefaultTargetPlatformOverride = TargetPlatform.iOS;
      await const SentomaruTransactionSigner().sign(operationId: 'op-1', body: Uint8List(0));
      final ios = calls.single.arguments as Map;
      expect(ios.containsKey('biometricOnly'), isFalse);
      expect(ios.containsKey('cancelLabel'), isFalse);
    });

    test('commitKey and abortKey reach the channel on Android and on iOS', () async {
      reply = (_) => null;
      await const SentomaruTransactionSigner().commitKey();
      await const SentomaruTransactionSigner().abortKey();
      expect(calls.map((c) => c.method), ['txKeyCommit', 'txKeyAbort']);
      calls.clear();
      debugDefaultTargetPlatformOverride = TargetPlatform.iOS;
      await const SentomaruTransactionSigner().commitKey();
      await const SentomaruTransactionSigner().abortKey();
      expect(calls.map((c) => c.method), ['txKeyCommit', 'txKeyAbort']);
    });

    test('every native code the Android plugin sends becomes its typed error, never a success', () async {
      const expected = {
        'Transaction:NOT_ENROLLED': SentomaruTransactionError.notEnrolled,
        'Transaction:KEY_INVALIDATED': SentomaruTransactionError.keyInvalidated,
        'Transaction:CANCELLED': SentomaruTransactionError.cancelled,
        'Transaction:LOCKED_OUT': SentomaruTransactionError.lockedOut,
        'Transaction:NO_USER_AUTHENTICATION': SentomaruTransactionError.noUserAuthentication,
        'Transaction:UNAVAILABLE': SentomaruTransactionError.unavailable,
        'Transaction:SIGNING_FAILED': SentomaruTransactionError.signingFailed,
        'NotInitialized': SentomaruTransactionError.notInitialized,
        'InvalidRequest:PARAMS': SentomaruTransactionError.invalidRequest,
        'ChannelError': SentomaruTransactionError.channelError,
      };
      for (final entry in expected.entries) {
        reply = (_) => throw PlatformException(code: entry.key);
        await expectLater(
          const SentomaruTransactionSigner().sign(operationId: 'op-1', body: Uint8List(0)),
          throwsA(isA<SentomaruTransactionException>().having((e) => e.error, entry.key, entry.value)),
        );
      }
    });

    test('a null signature reply is a channel error, not a value', () async {
      reply = (_) => null;
      await expectLater(
        const SentomaruTransactionSigner().sign(operationId: 'op-1', body: Uint8List(0)),
        throwsA(isA<SentomaruTransactionException>().having((e) => e.error, 'error', SentomaruTransactionError.channelError)),
      );
    });
  });

  test('on iOS sign sends the operation id and the body and returns the header value', () async {
    debugDefaultTargetPlatformOverride = TargetPlatform.iOS;
    reply = (_) => 'sentomaru-tx-v1.x.y';
    final value = await const SentomaruTransactionSigner()
        .sign(operationId: 'op-1', body: Uint8List.fromList([1, 2]), reason: 'Confirmar');
    expect(value, 'sentomaru-tx-v1.x.y');
    expect(calls.single.method, 'txSign');
    expect(calls.single.arguments['operationId'], 'op-1');
    expect(calls.single.arguments['reason'], 'Confirmar');
  });

  test('the native codes become typed errors, cancelled included', () async {
    debugDefaultTargetPlatformOverride = TargetPlatform.iOS;
    reply = (_) => throw PlatformException(code: 'Transaction:CANCELLED');
    await expectLater(
      const SentomaruTransactionSigner().sign(operationId: 'op-1', body: Uint8List(0)),
      throwsA(isA<SentomaruTransactionException>().having((e) => e.error, 'error', SentomaruTransactionError.cancelled)),
    );
    reply = (_) => throw PlatformException(code: 'Weird');
    await expectLater(
      const SentomaruTransactionSigner().isEnrolled(),
      throwsA(isA<SentomaruTransactionException>().having((e) => e.error, 'error', SentomaruTransactionError.channelError)),
    );
  });

  test('createKey defaults to biometric only; discard accepts a null reply', () async {
    debugDefaultTargetPlatformOverride = TargetPlatform.iOS;
    reply = (_) => Uint8List.fromList([9]);
    expect(await const SentomaruTransactionSigner().createKey(), Uint8List.fromList([9]));
    expect(calls.single.arguments['biometricOnly'], isTrue);
    reply = (_) => null;
    await const SentomaruTransactionSigner().discard();
    expect(calls.last.method, 'txDiscard');
  });

  test('commitKey and abortKey accept a null reply and send the staged-key methods', () async {
    debugDefaultTargetPlatformOverride = TargetPlatform.iOS;
    reply = (_) => null;
    await const SentomaruTransactionSigner().commitKey();
    await const SentomaruTransactionSigner().abortKey();
    expect(calls.map((c) => c.method), ['txKeyCommit', 'txKeyAbort']);
    reply = (_) => throw PlatformException(code: 'Transaction:NOT_ENROLLED');
    await expectLater(
      const SentomaruTransactionSigner().commitKey(),
      throwsA(isA<SentomaruTransactionException>().having((e) => e.error, 'error', SentomaruTransactionError.notEnrolled)),
    );
  });

  test('collectSignalsSnapshot sends screen only when asked', () async {
    debugDefaultTargetPlatformOverride = TargetPlatform.iOS;
    reply = (_) => {'collectedAt': '2026-11-04T10:00:00Z', 'durationMs': 1, 'observations': <Object?>[]};
    await MethodChannelSentomaruFlutter().collectSignalsSnapshot();
    await MethodChannelSentomaruFlutter().collectSignalsSnapshot(screen: true);
    expect(calls[0].arguments.containsKey('screen'), isFalse);
    expect(calls[1].arguments['screen'], isTrue);
  });
}
