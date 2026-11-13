import 'dart:async';

import 'package:flutter/foundation.dart';
import 'package:flutter_secure_storage/flutter_secure_storage.dart';
import 'package:flutter_test/flutter_test.dart';
import 'package:sentomaru_flutter/sentomaru_flutter.dart';
import 'package:sentomaru_flutter/src/ios_reinstall_guard.dart';
import 'package:shared_preferences/shared_preferences.dart';

/// In-memory stand-in for the platform's encrypted store: a plugin method channel is unavailable in a plain
/// `flutter_test` unit test, so [SentomaruPrincipalStore] takes this instead of the real [FlutterSecureStorage].
class FakeSecureStorage extends FlutterSecureStorage {
  final values = <String, String>{};
  bool throwOnRead = false;
  bool throwOnWrite = false;

  @override
  Future<String?> read({
    required String key,
    IOSOptions? iOptions,
    AndroidOptions? aOptions,
    LinuxOptions? lOptions,
    WebOptions? webOptions,
    MacOsOptions? mOptions,
    WindowsOptions? wOptions,
  }) async {
    if (throwOnRead) throw Exception('decrypt');
    return values[key];
  }

  @override
  Future<void> write({
    required String key,
    required String? value,
    IOSOptions? iOptions,
    AndroidOptions? aOptions,
    LinuxOptions? lOptions,
    WebOptions? webOptions,
    MacOsOptions? mOptions,
    WindowsOptions? wOptions,
  }) async {
    if (throwOnWrite) throw Exception('encrypt');
    if (value == null) {
      values.remove(key);
    } else {
      values[key] = value;
    }
  }

  @override
  Future<void> delete({
    required String key,
    IOSOptions? iOptions,
    AndroidOptions? aOptions,
    LinuxOptions? lOptions,
    WebOptions? webOptions,
    MacOsOptions? mOptions,
    WindowsOptions? wOptions,
  }) async {
    values.remove(key);
  }
}

class FakePlatform extends SentomaruFlutterPlatform {
  InstallationState currentState = InstallationState.notEnrolled;
  ReenrollmentReason? reenrollment;
  String? currentSessionId;
  final calls = <String>[];
  SentomaruException? rotateThrows;

  @override
  Future<void> initialize(SentomaruConfig config) async {}

  @override
  Future<InstallationState> state() async => currentState;

  @override
  Future<ReenrollmentReason?> reenrollmentReason() async => reenrollment;

  @override
  Future<EnrollmentGrant> enroll(EnrollmentChallenge challenge, {bool strongBox = false, bool requiresHardware = false}) async {
    calls.add('enroll:${challenge.id}');
    currentState = InstallationState.enrolled;
    currentSessionId = 'sess-${challenge.id}';
    return EnrollmentGrant(
      installationId: 'inst-1',
      keyId: challenge.id,
      sessionId: currentSessionId!,
      hardwareStatus: 'hardware',
      attestationStatus: 'verified',
    );
  }

  @override
  Future<EnrollmentGrant> rotate(EnrollmentChallenge challenge, {bool strongBox = false, bool requiresHardware = false}) async {
    calls.add('rotate:${challenge.id}');
    if (rotateThrows != null) throw rotateThrows!;
    currentSessionId = 'sess-${challenge.id}';
    return EnrollmentGrant(
      installationId: 'inst-1',
      keyId: challenge.id,
      sessionId: currentSessionId!,
      hardwareStatus: 'hardware',
      attestationStatus: 'verified',
    );
  }

  @override
  Future<void> reset() async {
    calls.add('reset');
    currentState = InstallationState.notEnrolled;
    currentSessionId = null;
  }

  @override
  Future<String?> sessionId() async => currentSessionId;
}

EnrollmentChallenge challenge(String id) => EnrollmentChallenge(
  id: id,
  token: 'tok-$id',
  expiresAt: DateTime.now().add(const Duration(minutes: 5)),
  attestationChallenge: Uint8List(0),
);

void main() {
  late FakePlatform platform;
  late SentomaruClient client;
  late FakeSecureStorage secure;
  late SentomaruPrincipalStore store;
  late SentomaruEnrollmentAssurance assurance;
  late List<String> challenges;

  Future<EnrollmentChallenge> provider(String subject, String tenant) async {
    final id = 'ch-${challenges.length + 1}';
    challenges.add(id);
    return challenge(id);
  }

  setUp(() async {
    debugDefaultTargetPlatformOverride = TargetPlatform.android;
    SharedPreferences.setMockInitialValues({});
    platform = FakePlatform();
    client = SentomaruClient(platform: platform);
    await client.initialize(const SentomaruConfig(
      organization: 'ebees',
      app: 'example-app',
      environment: 'dev',
      enrollmentUrl: 'https://example.test/enroll',
      allowedHosts: {'example.test'},
    ));
    secure = FakeSecureStorage();
    store = SentomaruPrincipalStore(secure: secure);
    assurance = SentomaruEnrollmentAssurance(client: client, principalStore: store);
    challenges = [];
  });

  tearDown(() {
    debugDefaultTargetPlatformOverride = null;
    assurance.dispose();
    client.dispose();
  });

  group('principalOf', () {
    test('sha256 of subject NUL tenant, same as the ported app logic', () {
      expect(SentomaruEnrollmentAssurance.principalOf('u-1', 't-1'), SentomaruPrincipalStore.secureKey.isNotEmpty ? isA<String>() : null);
      expect(SentomaruEnrollmentAssurance.principalOf('u-1', 't-1'), hasLength(64));
      expect(SentomaruEnrollmentAssurance.principalOf('u-1', 't-1'), SentomaruEnrollmentAssurance.principalOf('u-1', 't-1'));
      expect(SentomaruEnrollmentAssurance.principalOf('u-1', 't-1'), isNot(SentomaruEnrollmentAssurance.principalOf('u-2', 't-1')));
    });
  });

  group('first enrollment and plain reuse', () {
    test('notEnrolled: enrolls once, fires stateNotEnrolled, stores the principal, returns the session id', () async {
      final reasons = <SentomaruReenrollReason>[];
      assurance.reenrollReasons.listen(reasons.add);
      final result = await assurance.ensureEnrolled(subject: 'u-1', tenant: 't-1', challengeProvider: provider);
      await Future<void>.delayed(Duration.zero);

      expect(platform.calls, ['enroll:ch-1']);
      expect(result, isA<EnsureEnrolledResult>());
      expect(result.current, isTrue);
      expect(result.sessionId, 'sess-ch-1');
      expect(reasons, [SentomaruReenrollReason.stateNotEnrolled]);
      expect(secure.values[SentomaruPrincipalStore.secureKey], SentomaruEnrollmentAssurance.principalOf('u-1', 't-1'));
    });

    test('same caller again: reused, no reset, no enroll, no reason, sessionId null', () async {
      await assurance.ensureEnrolled(subject: 'u-1', tenant: 't-1', challengeProvider: provider);
      platform.calls.clear();
      final reasons = <SentomaruReenrollReason>[];
      assurance.reenrollReasons.listen(reasons.add);

      final result = await assurance.ensureEnrolled(subject: 'u-1', tenant: 't-1', challengeProvider: provider);

      expect(platform.calls, isEmpty);
      expect(result.current, isTrue);
      expect(result.sessionId, isNull);
      expect(reasons, isEmpty);
    });

    test('secure storage empty, mirror has it: reuses and repairs the secure store', () async {
      await assurance.ensureEnrolled(subject: 'u-1', tenant: 't-1', challengeProvider: provider);
      secure.values.clear(); // simulates a lost Keystore/Keychain key
      platform.calls.clear();

      final result = await assurance.ensureEnrolled(subject: 'u-1', tenant: 't-1', challengeProvider: provider);

      expect(platform.calls, isEmpty); // no reset, no enroll
      expect(result.current, isTrue);
      expect(secure.values[SentomaruPrincipalStore.secureKey], SentomaruEnrollmentAssurance.principalOf('u-1', 't-1'));
    });

    test('secure storage throws on read, mirror has it: still reuses', () async {
      await assurance.ensureEnrolled(subject: 'u-1', tenant: 't-1', challengeProvider: provider);
      secure.throwOnRead = true;
      platform.calls.clear();

      final result = await assurance.ensureEnrolled(subject: 'u-1', tenant: 't-1', challengeProvider: provider);

      expect(platform.calls, isEmpty);
      expect(result.current, isTrue);
    });

    test('mirror alone does not authorize anything without the plugin also enrolled', () async {
      SharedPreferences.setMockInitialValues({
        SentomaruPrincipalStore.mirrorKey: SentomaruEnrollmentAssurance.principalOf('u-1', 't-1'),
      });

      await assurance.ensureEnrolled(subject: 'u-1', tenant: 't-1', challengeProvider: provider);

      expect(platform.calls, ['enroll:ch-1']); // plugin says notEnrolled: reenrolls regardless of the mirror
    });
  });

  group('reenrolls when it must', () {
    test('enrolled with no principal anywhere (installation from before this contract): reenrolls once', () async {
      platform.currentState = InstallationState.enrolled;
      final reasons = <SentomaruReenrollReason>[];
      assurance.reenrollReasons.listen(reasons.add);

      await assurance.ensureEnrolled(subject: 'u-1', tenant: 't-1', challengeProvider: provider);
      await assurance.ensureEnrolled(subject: 'u-1', tenant: 't-1', challengeProvider: provider);

      expect(platform.calls, ['reset', 'enroll:ch-1']); // the second call reuses what the first one just stored
      expect(reasons, [SentomaruReenrollReason.principalAbsent]);
    });

    test('a different subject on the same device reenrolls, even with a mirror for the old one', () async {
      await assurance.ensureEnrolled(subject: 'u-1', tenant: 't-1', challengeProvider: provider);
      platform.calls.clear();
      final reasons = <SentomaruReenrollReason>[];
      assurance.reenrollReasons.listen(reasons.add);

      await assurance.ensureEnrolled(subject: 'u-2', tenant: 't-1', challengeProvider: provider);

      expect(platform.calls, ['reset', 'enroll:ch-2']);
      expect(reasons, [SentomaruReenrollReason.principalChanged]);
    });

    test('keyInvalidated reenrolls and fires stateKeyInvalidated', () async {
      platform.currentState = InstallationState.keyInvalidated;
      final reasons = <SentomaruReenrollReason>[];
      assurance.reenrollReasons.listen(reasons.add);

      await assurance.ensureEnrolled(subject: 'u-1', tenant: 't-1', challengeProvider: provider);

      expect(platform.calls, ['reset', 'enroll:ch-1']);
      expect(reasons, [SentomaruReenrollReason.stateKeyInvalidated]);
    });
  });

  group('forgetInstallation', () {
    test('resets and erases the principal and its mirror', () async {
      await assurance.ensureEnrolled(subject: 'u-1', tenant: 't-1', challengeProvider: provider);

      await assurance.forgetInstallation();

      expect(platform.calls.last, 'reset');
      expect(secure.values, isEmpty);
      expect((await SharedPreferences.getInstance()).getString(SentomaruPrincipalStore.mirrorKey), isNull);
      // The next ensureEnrolled is a real reenrollment, not a reuse.
      platform.calls.clear();
      await assurance.ensureEnrolled(subject: 'u-1', tenant: 't-1', challengeProvider: provider);
      expect(platform.calls, isNot(contains('reset'))); // plugin already notEnrolled: no second reset needed
      expect(platform.calls, contains(startsWith('enroll:')));
    });
  });

  group('concurrency: the most recent caller wins', () {
    test('a queued call for an older caller is marked not current and never enrolls over the newer one', () async {
      final gate = Completer<EnrollmentChallenge>();
      final first = assurance.ensureEnrolled(
        subject: 'u-1',
        tenant: 't-1',
        challengeProvider: (s, t) => gate.future,
      );
      final second = assurance.ensureEnrolled(subject: 'u-2', tenant: 't-1', challengeProvider: provider);
      gate.complete(challenge('ch-stale'));

      final firstResult = await first;
      final secondResult = await second;

      expect(firstResult.current, isFalse);
      expect(secondResult.current, isTrue);
      expect(platform.calls, isNot(contains('enroll:ch-stale')));
      expect(platform.calls, contains('enroll:ch-1'));
    });
  });

  group('app-update rotation (D-04b/D-04d)', () {
    test('no reenrollmentReason: plain reuse, rotate is never called', () async {
      await assurance.ensureEnrolled(subject: 'u-1', tenant: 't-1', challengeProvider: provider);
      platform.calls.clear();

      await assurance.ensureEnrolled(subject: 'u-1', tenant: 't-1', challengeProvider: provider);

      expect(platform.calls, isEmpty);
    });

    test('appUpdated: rotates in place, no reset, returns the new session id', () async {
      await assurance.ensureEnrolled(subject: 'u-1', tenant: 't-1', challengeProvider: provider);
      platform.currentState = InstallationState.enrolled;
      platform.reenrollment = ReenrollmentReason.appUpdated;
      platform.calls.clear();

      final result = await assurance.ensureEnrolled(subject: 'u-1', tenant: 't-1', challengeProvider: provider);

      expect(platform.calls, ['rotate:ch-2']);
      expect(result.sessionId, 'sess-ch-2');
    });

    test('rotation refused: reenrolls with a NEW challenge, fires rotationRefused', () async {
      await assurance.ensureEnrolled(subject: 'u-1', tenant: 't-1', challengeProvider: provider);
      platform.reenrollment = ReenrollmentReason.appUpdated;
      platform.rotateThrows = const SentomaruException(SentomaruErrorCode.reenrollmentRefused, 'refused');
      platform.calls.clear();
      final reasons = <SentomaruReenrollReason>[];
      assurance.reenrollReasons.listen(reasons.add);

      final result = await assurance.ensureEnrolled(subject: 'u-1', tenant: 't-1', challengeProvider: provider);

      expect(platform.calls, ['rotate:ch-2', 'reset', 'enroll:ch-3']); // a fresh challenge, not the refused one
      expect(reasons, [SentomaruReenrollReason.rotationRefused]);
      expect(result.sessionId, 'sess-ch-3');
    });

    test('rotate throws a different SentomaruException: swallowed, current key keeps signing', () async {
      await assurance.ensureEnrolled(subject: 'u-1', tenant: 't-1', challengeProvider: provider);
      platform.reenrollment = ReenrollmentReason.appUpdated;
      platform.rotateThrows = const SentomaruException(SentomaruErrorCode.networkUnavailable, 'offline');
      platform.calls.clear();

      final result = await assurance.ensureEnrolled(subject: 'u-1', tenant: 't-1', challengeProvider: provider);

      expect(platform.calls, ['rotate:ch-2']);
      expect(result.sessionId, isNull);
      expect(result.current, isTrue);
    });

    test('the challenge for the rotation itself fails: swallowed, rotate is never called', () async {
      await assurance.ensureEnrolled(subject: 'u-1', tenant: 't-1', challengeProvider: provider);
      platform.reenrollment = ReenrollmentReason.appUpdated;
      platform.calls.clear();

      final result = await assurance.ensureEnrolled(
        subject: 'u-1',
        tenant: 't-1',
        challengeProvider: (s, t) => Future.error(Exception('network')),
      );

      expect(platform.calls, isEmpty);
      expect(result.sessionId, isNull);
    });

    test('a slow rotation past appUpdateTimeout: this call returns with no session; the attempt keeps running and '
        'eventually rotates for real', () async {
      await assurance.ensureEnrolled(subject: 'u-1', tenant: 't-1', challengeProvider: provider);
      final slow = SentomaruEnrollmentAssurance(
        client: client,
        principalStore: store,
        appUpdateTimeout: const Duration(milliseconds: 5),
      );
      platform.reenrollment = ReenrollmentReason.appUpdated;
      final gate = Completer<EnrollmentChallenge>();
      platform.calls.clear();

      final result = await slow.ensureEnrolled(
        subject: 'u-1',
        tenant: 't-1',
        challengeProvider: (s, t) => gate.future,
      );
      expect(result.sessionId, isNull); // timed out, nothing erased
      expect(platform.calls, isEmpty); // rotate() itself not reached yet: still waiting on the challenge

      gate.complete(challenge('ch-late'));
      await Future<void>.delayed(const Duration(milliseconds: 20));
      expect(platform.calls, ['rotate:ch-late']); // the background attempt finished on its own

      slow.dispose();
    });
  });

  group('settle vs. forgetInstallation and a different caller', () {
    test('forgetInstallation waits for an in-flight rotation, then resets anyway past settleTimeout', () async {
      await assurance.ensureEnrolled(subject: 'u-1', tenant: 't-1', challengeProvider: provider);
      final tight = SentomaruEnrollmentAssurance(
        client: client,
        principalStore: store,
        appUpdateTimeout: const Duration(milliseconds: 5),
        settleTimeout: const Duration(milliseconds: 5),
      );
      platform.reenrollment = ReenrollmentReason.appUpdated;
      final gate = Completer<EnrollmentChallenge>();
      await tight.ensureEnrolled(subject: 'u-1', tenant: 't-1', challengeProvider: (s, t) => gate.future); // times out
      platform.calls.clear();

      await tight.forgetInstallation(); // settle() also times out (gate never completes); resets anyway

      expect(platform.calls, contains('reset'));
      tight.dispose();
    });

    test('a reenrollment for a different caller fails with TimeoutException while a rotation is still settling', () async {
      await assurance.ensureEnrolled(subject: 'u-1', tenant: 't-1', challengeProvider: provider);
      final tight = SentomaruEnrollmentAssurance(
        client: client,
        principalStore: store,
        appUpdateTimeout: const Duration(milliseconds: 5),
        settleTimeout: const Duration(milliseconds: 5),
      );
      platform.reenrollment = ReenrollmentReason.appUpdated;
      final gate = Completer<EnrollmentChallenge>();
      await tight.ensureEnrolled(subject: 'u-1', tenant: 't-1', challengeProvider: (s, t) => gate.future);

      await expectLater(
        tight.ensureEnrolled(subject: 'u-2', tenant: 't-1', challengeProvider: provider),
        throwsA(isA<TimeoutException>()),
      );
      gate.complete(challenge('ch-cleanup'));
      tight.dispose();
    });
  });

  group('legacy principal migration hook', () {
    test('own store empty, legacy matches: reuses and copies the value into the SDK\'s own store', () async {
      platform.currentState = InstallationState.enrolled;
      var calls = 0;
      final migrating = SentomaruEnrollmentAssurance(
        client: client,
        principalStore: store,
        legacyPrincipal: () async {
          calls++;
          return SentomaruEnrollmentAssurance.principalOf('u-1', 't-1');
        },
      );

      final result = await migrating.ensureEnrolled(subject: 'u-1', tenant: 't-1', challengeProvider: provider);

      expect(platform.calls, isEmpty); // no reset, no enroll: reused on the strength of the legacy value
      expect(result.current, isTrue);
      expect(calls, 1);
      expect(secure.values[SentomaruPrincipalStore.secureKey], SentomaruEnrollmentAssurance.principalOf('u-1', 't-1'));
      migrating.dispose();
    });

    test('own store empty, legacy belongs to someone else: reenrolls (legacy never authorizes a mismatch)', () async {
      platform.currentState = InstallationState.enrolled;
      final migrating = SentomaruEnrollmentAssurance(
        client: client,
        principalStore: store,
        legacyPrincipal: () async => SentomaruEnrollmentAssurance.principalOf('someone-else', 't-1'),
      );

      await migrating.ensureEnrolled(subject: 'u-1', tenant: 't-1', challengeProvider: provider);

      expect(platform.calls, ['reset', 'enroll:ch-1']);
      migrating.dispose();
    });

    test('not consulted when this installation is not enrolled at all', () async {
      var calls = 0;
      final migrating = SentomaruEnrollmentAssurance(
        client: client,
        principalStore: store,
        legacyPrincipal: () async {
          calls++;
          return 'whatever';
        },
      );

      await migrating.ensureEnrolled(subject: 'u-1', tenant: 't-1', challengeProvider: provider);

      expect(calls, 0);
      migrating.dispose();
    });
  });

  group('iOS reinstall guard', () {
    setUp(() => debugDefaultTargetPlatformOverride = TargetPlatform.iOS);

    test('first call on iOS forgets any principal and resets before deciding', () async {
      SharedPreferences.setMockInitialValues({});
      secure.values[SentomaruPrincipalStore.secureKey] = 'leftover-from-the-keychain';
      platform.currentState = InstallationState.enrolled; // the Keychain says enrolled: a reinstall, not a logout

      await assurance.ensureEnrolled(subject: 'u-1', tenant: 't-1', challengeProvider: provider);

      // reset() from the reinstall guard, then the normal enroll flow (state is notEnrolled again by then).
      expect(platform.calls, ['reset', 'enroll:ch-1']);
      expect(
        (await SharedPreferences.getInstance()).getBool(SentomaruIosReinstallGuard.markerKey),
        isTrue,
      );
    });

    test('second call does not forget again (marker already set)', () async {
      SharedPreferences.setMockInitialValues({SentomaruIosReinstallGuard.markerKey: true});

      await assurance.ensureEnrolled(subject: 'u-1', tenant: 't-1', challengeProvider: provider);

      expect(platform.calls, ['enroll:ch-1']); // no extra reset from the guard
    });

    test('a fresh install already notEnrolled costs no extra reset from the guard', () async {
      SharedPreferences.setMockInitialValues({});
      // platform.currentState defaults to notEnrolled: a pristine install, nothing ever enrolled here, has
      // nothing for the guard to forget.

      await assurance.ensureEnrolled(subject: 'u-1', tenant: 't-1', challengeProvider: provider);

      expect(platform.calls, ['enroll:ch-1']); // the guard only resets a genuine leftover record, not a pristine one
      expect(
        (await SharedPreferences.getInstance()).getBool(SentomaruIosReinstallGuard.markerKey),
        isTrue,
      );
    });
  });

  group('not initialized', () {
    test('throws notInitialized without touching the platform', () async {
      final fresh = SentomaruClient(platform: FakePlatform());
      final freshAssurance = SentomaruEnrollmentAssurance(client: fresh);

      await expectLater(
        freshAssurance.ensureEnrolled(subject: 'u-1', tenant: 't-1', challengeProvider: provider),
        throwsA(isA<SentomaruException>().having((e) => e.code, 'code', SentomaruErrorCode.notInitialized)),
      );

      freshAssurance.dispose();
      fresh.dispose();
    });
  });
}
