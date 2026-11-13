import 'dart:convert';

import 'package:flutter/services.dart';
import 'package:flutter_test/flutter_test.dart';
import 'package:sentomaru_flutter/sentomaru_flutter.dart';

void main() {
  TestWidgetsFlutterBinding.ensureInitialized();

  final platform = MethodChannelSentomaruFlutter();
  const channel = MethodChannel('sentomaru_flutter');

  tearDown(() {
    TestDefaultBinaryMessengerBinding.instance.defaultBinaryMessenger
        .setMockMethodCallHandler(channel, null);
  });

  group('MethodChannel serialization and execution', () {
    test('scaffoldInfo', () async {
      TestDefaultBinaryMessengerBinding.instance.defaultBinaryMessenger
          .setMockMethodCallHandler(channel, (MethodCall call) async {
        return 'sentomaru_flutter:0.0.1';
      });

      expect(await platform.scaffoldInfo(), 'sentomaru_flutter:0.0.1');
    });

    test('initialize serializes SentomaruConfig', () async {
      Map<dynamic, dynamic>? receivedArgs;
      TestDefaultBinaryMessengerBinding.instance.defaultBinaryMessenger
          .setMockMethodCallHandler(channel, (MethodCall call) async {
        if (call.method == 'initialize') {
          receivedArgs = call.arguments as Map<dynamic, dynamic>;
          return null;
        }
        return null;
      });

      const config = SentomaruConfig(
        organization: 'ebees',
        app: 'example-app',
        environment: 'dev',
        enrollmentUrl: 'https://api.ebees.com.br/enroll',
        allowedHosts: {'api.ebees.com.br'},
      );

      await platform.initialize(config);

      expect(receivedArgs, isNotNull);
      expect(receivedArgs!['organization'], 'ebees');
      expect(receivedArgs!['app'], 'example-app');
      expect(receivedArgs!['environment'], 'dev');
      expect(receivedArgs!['enrollmentUrl'], 'https://api.ebees.com.br/enroll');
      expect(receivedArgs!['allowedHosts'], ['api.ebees.com.br']);
      expect(receivedArgs!['rotationGracePeriodDays'], 7);
      expect(receivedArgs!.containsKey('playIntegrityCloudProjectNumber'), isFalse); // C-04b: off by default
      // D-F1: unlike playIntegrityCloudProjectNumber, always sent — false is itself the declaration, not an absence.
      expect(receivedArgs!['declaredEnforce'], false);
      expect(receivedArgs!['declaredInstallationResponse'], false);
    });

    test('initialize sends the app self-declaration when configured (D-F1)', () async {
      Map<dynamic, dynamic>? receivedArgs;
      TestDefaultBinaryMessengerBinding.instance.defaultBinaryMessenger
          .setMockMethodCallHandler(channel, (MethodCall call) async {
        if (call.method == 'initialize') receivedArgs = call.arguments as Map<dynamic, dynamic>;
        return null;
      });
      const config = SentomaruConfig(
        organization: 'ebees',
        app: 'example-app',
        environment: 'prod',
        enrollmentUrl: 'https://api.ebees.com.br/enroll',
        allowedHosts: {'api.ebees.com.br'},
        declaredEnforce: true,
        declaredInstallationResponse: true,
      );
      await platform.initialize(config);
      expect(receivedArgs!['declaredEnforce'], true);
      expect(receivedArgs!['declaredInstallationResponse'], true);
      final roundTripped = SentomaruConfig.fromMap(Map<String, dynamic>.from(config.toMap()));
      expect(roundTripped.declaredEnforce, true);
      expect(roundTripped.declaredInstallationResponse, true);
    });

    test('initialize sends the Play Integrity project number when configured (C-04b)', () async {
      Map<dynamic, dynamic>? receivedArgs;
      TestDefaultBinaryMessengerBinding.instance.defaultBinaryMessenger
          .setMockMethodCallHandler(channel, (MethodCall call) async {
        if (call.method == 'initialize') receivedArgs = call.arguments as Map<dynamic, dynamic>;
        return null;
      });
      const config = SentomaruConfig(
        organization: 'ebees',
        app: 'example-app',
        environment: 'hml',
        enrollmentUrl: 'https://api.ebees.com.br/enroll',
        allowedHosts: {'api.ebees.com.br'},
        playIntegrityCloudProjectNumber: 123456789012,
      );
      await platform.initialize(config);
      expect(receivedArgs!['playIntegrityCloudProjectNumber'], 123456789012);
      expect(SentomaruConfig.fromMap(Map<String, dynamic>.from(config.toMap())).playIntegrityCloudProjectNumber, 123456789012);
    });

    test('state parses InstallationState', () async {
      TestDefaultBinaryMessengerBinding.instance.defaultBinaryMessenger
          .setMockMethodCallHandler(channel, (MethodCall call) async {
        return 'Enrolled';
      });

      final state = await platform.state();
      expect(state, InstallationState.enrolled);
    });

    test('reenrollmentReason maps the native name, null and an unknown name (D-04b)', () async {
      Object? answer;
      String? method;
      TestDefaultBinaryMessengerBinding.instance.defaultBinaryMessenger
          .setMockMethodCallHandler(channel, (MethodCall call) async {
        method = call.method;
        return answer;
      });
      answer = 'APP_UPDATED';
      expect(await platform.reenrollmentReason(), ReenrollmentReason.appUpdated);
      expect(method, 'reenrollmentReason');
      answer = null;
      expect(await platform.reenrollmentReason(), isNull); // same version, unknown version or not enrolled
      answer = 'SOMETHING_NEWER';
      expect(await platform.reenrollmentReason(), ReenrollmentReason.unknown);
    });

    test('reenrollmentReason: a native error stays typed (D-04b)', () async {
      TestDefaultBinaryMessengerBinding.instance.defaultBinaryMessenger
          .setMockMethodCallHandler(channel, (MethodCall call) async {
        throw PlatformException(code: 'NotInitialized', message: 'Sentomaru native client not initialized');
      });
      await expectLater(
        platform.reenrollmentReason(),
        throwsA(isA<SentomaruException>().having((e) => e.code, 'code', SentomaruErrorCode.notInitialized)),
      );
    });

    test('enroll serializes challenge and returns EnrollmentGrant', () async {
      Map<dynamic, dynamic>? receivedArgs;
      TestDefaultBinaryMessengerBinding.instance.defaultBinaryMessenger
          .setMockMethodCallHandler(channel, (MethodCall call) async {
        receivedArgs = call.arguments as Map<dynamic, dynamic>;
        return {
          'installationId': 'inst-1',
          'keyId': 'key-1',
          'sessionId': 'sess-1',
          'hardwareStatus': 'hardware',
          'attestationStatus': 'verified',
        };
      });

      final challenge = EnrollmentChallenge(
        id: 'chal-1',
        token: 'token-abc',
        expiresAt: DateTime.fromMillisecondsSinceEpoch(1700000000000),
        attestationChallenge: Uint8List.fromList([1, 2, 3]),
      );

      final grant = await platform.enroll(challenge, strongBox: true, requiresHardware: true);

      expect(grant.installationId, 'inst-1');
      expect(grant.keyId, 'key-1');
      expect(grant.sessionId, 'sess-1');
      expect(grant.isHardware, isTrue);
      expect(grant.attestationStatus, 'verified');

      expect(receivedArgs!['strongBox'], isTrue);
      expect(receivedArgs!['requiresHardware'], isTrue);
      final chMap = receivedArgs!['challenge'] as Map;
      expect(chMap['id'], 'chal-1');
      expect(chMap['token'], 'token-abc');
      expect(chMap['expiresAtEpochMs'], 1700000000000);
      expect(chMap['attestationChallengeB64'], base64Encode([1, 2, 3]));
    });

    test('sign passes arguments and returns SignedMessageHeaders', () async {
      Map<dynamic, dynamic>? receivedArgs;
      TestDefaultBinaryMessengerBinding.instance.defaultBinaryMessenger
          .setMockMethodCallHandler(channel, (MethodCall call) async {
        receivedArgs = call.arguments as Map<dynamic, dynamic>;
        return {
          'Signature': 'sig1=:abc:',
          'Signature-Input': 'sig1=("@method");created=10',
          'Content-Digest': 'sha-256=:xyz:',
          'x-sentomaru-operation': 'test_op',
        };
      });

      final body = Uint8List.fromList([10, 20, 30]);
      final signed = await platform.sign(
        method: 'POST',
        targetUri: 'https://api.ebees.com.br/test',
        operation: 'test_op',
        bodyBytes: body,
      );

      expect(receivedArgs!['method'], 'POST');
      expect(receivedArgs!['targetUri'], 'https://api.ebees.com.br/test');
      expect(receivedArgs!['operation'], 'test_op');
      expect(receivedArgs!['body'], body);

      expect(signed.signature, 'sig1=:abc:');
      expect(signed.signatureInput, 'sig1=("@method");created=10');
      expect(signed.contentDigest, 'sha-256=:xyz:');
    });

    test('collectSignals parses observations', () async {
      TestDefaultBinaryMessengerBinding.instance.defaultBinaryMessenger
          .setMockMethodCallHandler(channel, (MethodCall call) async {
        return [
          {
            'capabilityId': 'debug_attached',
            'version': '1.0.0',
            'state': 'not_detected',
            'source': 'client_observed',
            'observedAt': 1700000000000,
            'data': {'debug': 'false'},
          }
        ];
      });

      final list = await platform.collectSignals();
      expect(list.length, 1);
      expect(list.first.capabilityId, 'debug_attached');
      expect(list.first.state, SignalState.notDetected);
      expect(list.first.source, 'client_observed');
      expect(list.first.observedAt, DateTime.fromMillisecondsSinceEpoch(1700000000000, isUtc: true));
    });

    Map<String, Object?> obs(String id, {Object? observedAt = '2026-10-09T10:00:00Z'}) => {
          'capabilityId': id,
          'version': '1.0.0',
          'state': 'not_detected',
          'source': 'client_observed',
          'observedAt': observedAt,
        };

    for (final bad in [null, 'not-a-date']) {
      test('collectSignals never invents observedAt (value: $bad)', () async {
        TestDefaultBinaryMessengerBinding.instance.defaultBinaryMessenger
            .setMockMethodCallHandler(channel, (MethodCall call) async => [obs('root_indicated', observedAt: bad)]);
        await expectLater(
          platform.collectSignals(),
          throwsA(isA<SentomaruException>().having((e) => e.code, 'code', SentomaruErrorCode.channelError)),
        );
      });
    }

    test('collectSignals rejects duplicate capabilityIds (case-insensitive)', () async {
      TestDefaultBinaryMessengerBinding.instance.defaultBinaryMessenger.setMockMethodCallHandler(
          channel, (MethodCall call) async => [obs('root_indicated'), obs('ROOT_INDICATED')]);
      await expectLater(
        platform.collectSignals(),
        throwsA(isA<SentomaruException>().having((e) => e.code, 'code', SentomaruErrorCode.channelError)),
      );
    });
  });

  group('MethodChannel categorized error mapping (Decision E7 / FLT-7)', () {
    final errorMatrix = {
      'NotEnrolled': SentomaruErrorCode.notEnrolled,
      'EnrollmentRequired': SentomaruErrorCode.enrollmentRequired,
      'KeyInvalidated': SentomaruErrorCode.keyInvalidated,
      'StrongBoxUnavailable': SentomaruErrorCode.strongBoxUnavailable,
      'ChallengeExpired': SentomaruErrorCode.challengeExpired,
      'NetworkUnavailable': SentomaruErrorCode.networkUnavailable,
      'ServerRejected': SentomaruErrorCode.serverRejected,
      'NoActivity': SentomaruErrorCode.noActivity,
      'Cancelled': SentomaruErrorCode.cancelled,
      'HostNotAllowed': SentomaruErrorCode.hostNotAllowed,
      'BodyTooLarge': SentomaruErrorCode.bodyTooLarge,
      'InvalidRequest': SentomaruErrorCode.invalidRequest,
      'InvalidRequest:TARGET_URI': SentomaruErrorCode.invalidRequest,
      'InvalidRequest:HEADER_VALUE': SentomaruErrorCode.invalidRequest,
    };

    errorMatrix.forEach((platformCode, expectedCode) {
      test('maps platform error $platformCode -> $expectedCode', () async {
        TestDefaultBinaryMessengerBinding.instance.defaultBinaryMessenger
            .setMockMethodCallHandler(channel, (MethodCall call) async {
          throw PlatformException(
            code: platformCode,
            message: 'Failure under $platformCode',
          );
        });

        expect(
          () => platform.state(),
          throwsA(isA<SentomaruException>().having(
            (e) => e.code,
            'code',
            expectedCode,
          )),
        );
      });
    });

    // Contract v1.5: a suspended renewal keeps its reason in details so the app can tell it from a refusal.
    test('renewSession: ServerRejected:SUSPENDED -> serverRejected with the reason in details', () async {
      TestDefaultBinaryMessengerBinding.instance.defaultBinaryMessenger.setMockMethodCallHandler(channel, (call) async {
        throw PlatformException(code: 'ServerRejected:SUSPENDED', message: 'ServerRejected:SUSPENDED');
      });
      await expectLater(
        platform.renewSession(),
        throwsA(isA<SentomaruException>()
            .having((e) => e.code, 'code', SentomaruErrorCode.serverRejected)
            .having((e) => e.details, 'details', 'ServerRejected:SUSPENDED')),
      );
    });

    test('ReenrollmentRefused -> reenrollmentRefused (D-04d: reset() + enroll(), not a generic refusal)', () async {
      expect(SentomaruErrorCode.fromString('ReenrollmentRefused'), SentomaruErrorCode.reenrollmentRefused);
      // Appended: ordinals unchanged (C-03a appended pinningRefused after it, D-10b unsupported after that).
      expect(SentomaruErrorCode.values.last, SentomaruErrorCode.unsupported);
      expect(SentomaruErrorCode.pinningRefused.index, SentomaruErrorCode.values.length - 2);
      expect(SentomaruErrorCode.reenrollmentRefused.index, SentomaruErrorCode.values.length - 3);
      expect(SentomaruErrorCode.renewalBackoff.index, SentomaruErrorCode.values.length - 4);
      expect(SentomaruErrorCode.fromString('PinningRefused'), SentomaruErrorCode.unknown, reason: 'Dart only');
    });

    // D-10b: the iOS SDK refuses to enroll without App Attest or the Secure Enclave; the capability stays in details.
    for (final capability in ['APP_ATTEST', 'SECURE_ENCLAVE']) {
      test('enroll: Unsupported:$capability -> unsupported with the native code in details (D-10b)', () async {
        TestDefaultBinaryMessengerBinding.instance.defaultBinaryMessenger.setMockMethodCallHandler(channel, (call) async {
          throw PlatformException(code: 'Unsupported:$capability', message: 'Unsupported:$capability');
        });
        await expectLater(
          platform.enroll(EnrollmentChallenge(
              id: 'c', token: 't', expiresAt: DateTime.utc(2030), attestationChallenge: Uint8List(32))),
          throwsA(isA<SentomaruException>()
              .having((e) => e.code, 'code', SentomaruErrorCode.unsupported)
              .having((e) => e.details, 'details', 'Unsupported:$capability')),
        );
      });
    }

    test('renewSession: RenewalBackoff -> renewalBackoff (its own code, not invalidRequest)', () async {
      TestDefaultBinaryMessengerBinding.instance.defaultBinaryMessenger.setMockMethodCallHandler(channel, (call) async {
        throw PlatformException(code: 'RenewalBackoff', message: 'RenewalBackoff');
      });
      await expectLater(
        platform.renewSession(),
        throwsA(isA<SentomaruException>()
            .having((e) => e.code, 'code', SentomaruErrorCode.renewalBackoff)
            .having((e) => e.details, 'details', isNull)),
      );
    });

    // 0.9.2: the backoff refusal carries the code of the failure that started it (the silent renewal of sign may
    // have been the one that failed), so a suspension is still told apart from a transient failure.
    test('renewSession: RenewalBackoff with details ServerRejected:SUSPENDED keeps the reason', () async {
      TestDefaultBinaryMessengerBinding.instance.defaultBinaryMessenger.setMockMethodCallHandler(channel, (call) async {
        throw PlatformException(
            code: 'RenewalBackoff', message: 'RenewalBackoff', details: 'ServerRejected:SUSPENDED');
      });
      await expectLater(
        platform.renewSession(),
        throwsA(isA<SentomaruException>()
            .having((e) => e.code, 'code', SentomaruErrorCode.renewalBackoff)
            .having((e) => e.details, 'details', 'ServerRejected:SUSPENDED')),
      );
    });

    test('renewSession: InvalidRequest:PARAMS stays invalidRequest without a ServerRejected reason', () async {
      TestDefaultBinaryMessengerBinding.instance.defaultBinaryMessenger.setMockMethodCallHandler(channel, (call) async {
        throw PlatformException(code: 'InvalidRequest:PARAMS', message: 'InvalidRequest:PARAMS');
      });
      await expectLater(
        platform.renewSession(),
        throwsA(isA<SentomaruException>()
            .having((e) => e.code, 'code', SentomaruErrorCode.invalidRequest)
            .having((e) => e.details, 'details', isNull)),
      );
    });

    test('null response on required grant throws channelError', () async {
      TestDefaultBinaryMessengerBinding.instance.defaultBinaryMessenger
          .setMockMethodCallHandler(channel, (MethodCall call) async {
        return null;
      });

      final challenge = EnrollmentChallenge(
        id: 'chal-1',
        token: 'token-abc',
        expiresAt: DateTime.now().add(const Duration(minutes: 5)),
        attestationChallenge: Uint8List(32),
      );

      expect(
        () => platform.enroll(challenge),
        throwsA(isA<SentomaruException>().having(
          (e) => e.code,
          'code',
          SentomaruErrorCode.channelError,
        )),
      );
    });
  });
}
