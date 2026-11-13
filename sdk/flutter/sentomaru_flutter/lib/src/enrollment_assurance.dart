import 'dart:async';
import 'dart:convert';

import 'package:crypto/crypto.dart';

import 'exceptions.dart';
import 'ios_reinstall_guard.dart';
import 'models.dart';
import 'principal_store.dart';
import 'sentomaru_client.dart';

/// Asks the app's backend for a fresh, single-use enrollment challenge for [subject]/[tenant]. Called for the
/// first enrollment, for a key rotation (D-04b) and, when the server refuses that rotation, for the reenrollment
/// that follows — every time a new call, never cached or reused by [SentomaruEnrollmentAssurance] itself.
typedef SentomaruChallengeProvider = Future<EnrollmentChallenge> Function(String subject, String tenant);

/// Why [SentomaruEnrollmentAssurance] just enrolled or reenrolled this installation — no subject, tenant or other
/// personal data, safe for a log line or a metric. Ported 1:1 from the reasons
/// the reset reasons an app-side principal store already named.
enum SentomaruReenrollReason {
  /// [InstallationState.notEnrolled]: nothing to reuse.
  stateNotEnrolled,

  /// [InstallationState.enrollmentRequired]: the plugin itself discarded the session (renewal exhausted or revoked).
  stateEnrollmentRequired,

  /// [InstallationState.keyInvalidated]: the platform invalidated the key (Android: biometric enrollment changed;
  /// iOS: Secure Enclave access revoked).
  stateKeyInvalidated,

  /// Enrolled, but no principal was found for this installation (its own storage, mirror and legacy hook all
  /// empty): an installation from before this contract existed, or a storage wipe.
  principalAbsent,

  /// Enrolled with a principal on file, but it belongs to another subject or tenant.
  principalChanged,

  /// [SentomaruClient.rotate] was refused ([SentomaruErrorCode.reenrollmentRefused]): the server will not re-enroll
  /// this installation with the current key, so a new installation was created instead.
  rotationRefused,
}

/// Outcome of [SentomaruEnrollmentAssurance.ensureEnrolled].
class EnsureEnrolledResult {
  const EnsureEnrolledResult({required this.current, this.sessionId});

  /// False when a later call (for a different subject/tenant) superseded this one before it finished: a stale
  /// caller must not bind a session, or otherwise act as if its own call had won.
  final bool current;

  /// The session id this call obtained, when it enrolled, reenrolled or rotated the installation. `null` when the
  /// existing installation and session were simply reused — call [SentomaruClient.sessionId] for the one already
  /// active; this class never keeps a copy of its own (the plugin already does, natively).
  final String? sessionId;
}

/// High-level, portable "ensure this device is correctly enrolled" contract: decides on its own whether to reuse
/// the current installation, rotate it after an app update (D-04b/D-04d, same installation on the server) or
/// reenroll from scratch, so no app has to reimplement this logic. Ported from `sentomaru_service.dart` and
/// `sentomaru_app_update.dart` of a first consumer app (11/11/2026 decision: that logic moves into the SDKs; that app is
/// reverted to plain calls once this ships), generalized away from Dio and from any particular backend — the app
/// supplies a [SentomaruChallengeProvider] instead.
///
/// One instance per [SentomaruClient] (construct once, reuse — it carries its own queue and storage). Concurrent
/// calls are serialized and the most recent subject/tenant wins over one still queued for an older caller (a login
/// followed immediately by a tenant switch never enrolls the old tenant over the new one). [forgetInstallation]
/// joins the same queue.
class SentomaruEnrollmentAssurance {
  SentomaruEnrollmentAssurance({
    required this.client,
    SentomaruPrincipalStore? principalStore,
    this.appUpdateTimeout = const Duration(seconds: 15),
    this.settleTimeout = const Duration(seconds: 30),
    this.legacyPrincipal,
  }) : _principalStore = principalStore ?? SentomaruPrincipalStore();

  final SentomaruClient client;

  /// Ceiling for the app-update rotation check (D-04b: `reenrollmentReason` + a fresh challenge + `rotate`). Past
  /// it [ensureEnrolled] returns as if nothing needed rotating — the current key keeps signing — while the attempt
  /// keeps running; a later [forgetInstallation] or a reenrollment for another caller still waits for it
  /// ([settleTimeout]) instead of racing a `reset()` against it.
  final Duration appUpdateTimeout;

  /// Ceiling to wait for a rotation that outlived [appUpdateTimeout] before this class will touch `reset()` for a
  /// different reason. [forgetInstallation] resets anyway past this ceiling (the installation is being revoked;
  /// the recovery path must not get stuck); a reenrollment for a different subject/tenant instead fails with
  /// [TimeoutException], and a later call tries again.
  final Duration settleTimeout;

  final SentomaruPrincipalStore _principalStore;

  /// Consulted at most once per installation, only when this class's own storage (secure store + mirror) has
  /// nothing AND the plugin itself says `enrolled`: an app migrating from its own, app-level principal tracking
  /// (as a first consumer app did before this class existed) supplies its OLD stored value here, so upgrading the SDK
  /// does not force a one-time reenrollment of every existing installation. A match is copied into this class's
  /// own storage right away; a non-match (or `null`, the default) is never consulted again for this installation —
  /// a fresh integration has nothing to migrate from and can simply omit this.
  final Future<String?> Function()? legacyPrincipal;

  Future<void> _enrolling = Future.value();
  Future<void> _rotationInFlight = Future.value();
  String? _latestPrincipal;
  final _reasons = StreamController<SentomaruReenrollReason>.broadcast();

  /// Fires every time a call decided to enroll or reenroll rather than reuse the installation — never for a plain
  /// reuse, and never with subject, tenant or any other personal data (see [SentomaruReenrollReason]).
  Stream<SentomaruReenrollReason> get reenrollReasons => _reasons.stream;

  /// sha256 of `subject\u0000tenant`: the same hash [ensureEnrolled] compares against this installation's stored
  /// principal. Exposed so a caller can compare without calling [ensureEnrolled] itself.
  static String principalOf(String subject, String tenant) => sha256.convert(utf8.encode('$subject\u0000$tenant')).toString();

  /// Ensures [subject]/[tenant] is enrolled on this device: reuses the installation when it already is for the
  /// same caller (rotating its key in place after an app update, D-04b/D-04d), or reenrolls from scratch
  /// (`reset` + `enroll`) otherwise. [challengeProvider] is asked for a fresh, single-use challenge every time one
  /// is actually needed — never cached, never reused.
  ///
  /// Requires [SentomaruClient.initialize] already done ([SentomaruClient.isInitialized]): this class has no
  /// backend-agnostic way to build a `SentomaruConfig` itself, so initializing stays the app's own first step, same
  /// as before this contract existed. Throws [SentomaruException] [SentomaruErrorCode.notInitialized] otherwise.
  Future<EnsureEnrolledResult> ensureEnrolled({
    required String subject,
    required String tenant,
    required SentomaruChallengeProvider challengeProvider,
  }) {
    if (!client.isInitialized) {
      return Future.error(
        const SentomaruException(SentomaruErrorCode.notInitialized, 'SentomaruClient not initialized'),
      );
    }
    final principal = principalOf(subject, tenant);
    _latestPrincipal = principal;
    final run = _enrolling.catchError((_) {}).then((_) {
      // The most recent wins: a call queued behind an older one for a different caller never enrolls that one
      // over the caller that arrived after it.
      if (_latestPrincipal != principal) return Future.value(const EnsureEnrolledResult(current: false));
      return _ensureEnrolled(
        principal: principal,
        subject: subject,
        tenant: tenant,
        challengeProvider: challengeProvider,
      ).then((sessionId) => EnsureEnrolledResult(current: _latestPrincipal == principal, sessionId: sessionId));
    });
    _enrolling = run.then<void>((_) {}, onError: (Object _) {});
    return run;
  }

  Future<String?> _ensureEnrolled({
    required String principal,
    required String subject,
    required String tenant,
    required SentomaruChallengeProvider challengeProvider,
  }) async {
    await SentomaruIosReinstallGuard.forgetIfReinstalled(client: client, principalStore: _principalStore);

    final state = await client.state();
    final stored = await _storedPrincipal(state);
    if (state == InstallationState.enrolled && stored == principal) {
      return _rotateIfUpdated(subject: subject, tenant: tenant, challengeProvider: challengeProvider);
    }

    _reasons.add(_reasonFor(state, stored));
    // A rotation that outlived appUpdateTimeout may still be running in the background: never reset while it is.
    // Propagates TimeoutException unguarded (unlike forgetInstallation): this call fails, nothing erased, and a
    // later ensureEnrolled call tries again.
    if (state != InstallationState.notEnrolled) await _settle();
    // Challenge before reset: a network failure or a 5xx here must not erase an installation that still works.
    final challenge = await challengeProvider(subject, tenant);
    if (state != InstallationState.notEnrolled) await client.reset();
    final grant = await client.enroll(challenge);
    await _principalStore.write(principal);
    return grant.sessionId;
  }

  /// `null` when nothing needed rotating and [SentomaruClient.sessionId] already has what the caller needs; the
  /// id this call itself obtained otherwise (a D-04b rotation, or the reenrollment a refused rotation falls back
  /// to).
  Future<String?> _rotateIfUpdated({
    required String subject,
    required String tenant,
    required SentomaruChallengeProvider challengeProvider,
  }) async {
    final reason = await client.reenrollmentReason();
    if (reason == null) return null;
    final ({EnrollmentGrant? grant, bool refused}) outcome;
    final attempt = _attemptRotate(subject: subject, tenant: tenant, challengeProvider: challengeProvider);
    _rotationInFlight = attempt.then<void>((_) {}, onError: (Object _) {});
    try {
      outcome = await attempt.timeout(appUpdateTimeout);
    } on TimeoutException {
      // The native side keeps running whatever it was doing; nothing here was erased, and nothing here needs to
      // remember the result — SentomaruClient.sessionId() will already reflect it once it finishes.
      return null;
    } catch (_) {
      // Any other failure of the update check itself: the current key keeps signing, this call does not fail for it.
      return null;
    }
    if (!outcome.refused) return outcome.grant?.sessionId;
    // Refused: a fresh challenge before reset (same invariant as the normal reenrollment path), and from here on
    // NOT swallowed — the installation is already being replaced, a failure now must reach the caller.
    _reasons.add(SentomaruReenrollReason.rotationRefused);
    final challenge = await _challengeOrNull(subject, tenant, challengeProvider);
    if (challenge == null) return null;
    await client.reset();
    final grant = await client.enroll(challenge);
    await _principalStore.write(principalOf(subject, tenant));
    return grant.sessionId;
  }

  Future<({EnrollmentGrant? grant, bool refused})> _attemptRotate({
    required String subject,
    required String tenant,
    required SentomaruChallengeProvider challengeProvider,
  }) async {
    final challenge = await challengeProvider(subject, tenant);
    try {
      return (grant: await client.rotate(challenge), refused: false);
    } on SentomaruException catch (e) {
      if (e.code != SentomaruErrorCode.reenrollmentRefused) rethrow;
      return (grant: null, refused: true);
    }
  }

  Future<EnrollmentChallenge?> _challengeOrNull(
    String subject,
    String tenant,
    SentomaruChallengeProvider provider,
  ) async {
    try {
      return await provider(subject, tenant);
    } catch (_) {
      return null; // the current key keeps signing; this call simply has nothing new to replace it with
    }
  }

  /// Forgets this installation (revoked server-side, or the app's own sign-out-everywhere): the next
  /// [ensureEnrolled] enrolls from scratch, with a fresh attestation. Joins the same queue as [ensureEnrolled]:
  /// never races a reset against one still finishing, and never erases an installation a newer call just made.
  /// Waits for a rotation in flight up to [settleTimeout], then resets anyway past it — the installation is being
  /// revoked, the key no longer matters, and this recovery path must not get stuck.
  Future<void> forgetInstallation() {
    final run = _enrolling.catchError((_) {}).then((_) async {
      try {
        await _settle();
      } on TimeoutException {
        // Revoked either way; proceed.
      }
      await client.reset();
      await _principalStore.delete();
    });
    _enrolling = run.then<void>((_) {}, onError: (Object _) {});
    return run;
  }

  Future<void> _settle() => _rotationInFlight.timeout(
    settleTimeout,
    onTimeout: () => throw TimeoutException('Sentomaru: rotação após atualização ainda em andamento', settleTimeout),
  );

  Future<String?> _storedPrincipal(InstallationState state) async {
    final own = await _principalStore.read();
    if (own != null || legacyPrincipal == null) return own;
    if (state != InstallationState.enrolled) return null; // nothing to migrate into if this call reenrolls anyway
    final legacy = await legacyPrincipal!();
    if (legacy == null || legacy.isEmpty) return null;
    await _principalStore.write(legacy); // consulted at most once for this installation, match or not
    return legacy;
  }

  static SentomaruReenrollReason _reasonFor(InstallationState state, String? stored) {
    switch (state) {
      case InstallationState.notEnrolled:
        return SentomaruReenrollReason.stateNotEnrolled;
      case InstallationState.enrollmentRequired:
        return SentomaruReenrollReason.stateEnrollmentRequired;
      case InstallationState.keyInvalidated:
        return SentomaruReenrollReason.stateKeyInvalidated;
      case InstallationState.enrolled:
        return stored == null ? SentomaruReenrollReason.principalAbsent : SentomaruReenrollReason.principalChanged;
    }
  }

  /// Closes [reenrollReasons]. Call when this class's owner is disposed (same lifetime as its [client]).
  void dispose() => _reasons.close();
}
