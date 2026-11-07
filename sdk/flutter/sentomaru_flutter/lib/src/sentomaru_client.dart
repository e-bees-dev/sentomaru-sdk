import 'dart:async';
import 'dart:typed_data';

import 'exceptions.dart';
import 'models.dart';
import 'reattestation.dart';
import 'sentomaru_flutter_platform_interface.dart';
import 'server_response_sink.dart';
import 'signal_events.dart';
import 'signals_snapshot.dart';

/// Client coordinating Sentomaru key lifecycle, enrollment, and RFC 9421 signing.
///
/// Wraps native platform channel calls into asynchronous Dart Futures and reactive Streams.
/// Strictly non-interactive; never triggers biometric prompts (Decision E4).
class SentomaruClient {
  final SentomaruFlutterPlatform _platform;
  SentomaruConfig? _config;
  final _stateController = StreamController<InstallationState>.broadcast();
  late final _eventController = _createEventController();
  bool _eventsCreated = false;
  StreamSubscription<Object?>? _platformEvents;
  int _eventSequence = 0;

  /// The client starts uninitialized; only [initialize] (after the native side accepted the config) sets it.
  SentomaruClient({SentomaruFlutterPlatform? platform}) : _platform = platform ?? SentomaruFlutterPlatform.instance {
    serverResponseSinks[this] = _observeServerResponse;
  }

  /// Returns the current configuration, or throws if not initialized.
  SentomaruConfig get config {
    if (_config == null) {
      throw const SentomaruException(
        SentomaruErrorCode.notInitialized,
        'SentomaruClient not initialized. Call initialize(config) first.',
      );
    }
    return _config!;
  }

  /// Whether `initialize()` completed successfully in this isolate. False during boot, in a background isolate or
  /// engine whose Dart client was not initialized, and after a hot restart; the Dio interceptor then refuses
  /// declared operations with [SentomaruErrorCode.notInitialized].
  bool get isInitialized => _config != null;

  /// Broadcast stream of installation state transitions (FLT-1).
  Stream<InstallationState> get stateChanges => _stateController.stream;

  /// Initializes the client with the provided [config].
  /// The client counts as initialized only after the native side accepted the configuration.
  Future<void> initialize(SentomaruConfig config) async {
    config.validate();
    await _platform.initialize(config);
    _config = config;
    final currentState = await state();
    _stateController.add(currentState);
  }

  /// Queries current installation lifecycle state.
  Future<InstallationState> state() async {
    return _platform.state();
  }

  /// D-04b: why this [InstallationState.enrolled] installation should enroll again with a fresh attestation, or `null`.
  ///
  /// [ReenrollmentReason.appUpdated] when the app's `versionCode` differs from the one the current key was attested
  /// with (update or downgrade). [state] stays `enrolled` and [sign] keeps working: the plugin cannot fetch a challenge
  /// by itself. Get a NEW challenge from your backend every time and call [rotate] (keeps signing with the current key
  /// meanwhile) or [reset] + [enroll]; with a new challenge, either stores the running version. The challenge of an
  /// interrupted rotation only recovers its old grant (the version stays old and this keeps asking). Call it once per
  /// cold start, not around every request. An installation enrolled before plugin 0.10.0 (no stored
  /// version) answers `null` until its next enrollment or rotation. Since 0.11.0 (D-04d) [rotate] keeps the same
  /// installation on the server (new `installationId`, same code); [reset] + [enroll] creates a new one.
  Future<ReenrollmentReason?> reenrollmentReason() async {
    return _platform.reenrollmentReason();
  }

  /// Performs initial key generation and enrollment.
  Future<EnrollmentGrant> enroll(
    EnrollmentChallenge challenge, {
    bool strongBox = false,
    bool requiresHardware = false,
  }) async {
    final grant = await _platform.enroll(
      challenge,
      strongBox: strongBox,
      requiresHardware: requiresHardware,
    );
    _stateController.add(InstallationState.enrolled);
    return grant;
  }

  /// Performs key rotation with coexistence window (Decision E-rot).
  ///
  /// D-04d: the rotation is proven with the current key, so the server keeps the same installation (code, name, tags,
  /// suspension). Throws [SentomaruErrorCode.reenrollmentRefused] when the server refuses that proof (quarantined,
  /// already replaced, another subject/tenant): call [reset] and then [enroll], which creates a NEW installation.
  Future<EnrollmentGrant> rotate(
    EnrollmentChallenge challenge, {
    bool strongBox = false,
    bool requiresHardware = false,
  }) async {
    final grant = await _platform.rotate(
      challenge,
      strongBox: strongBox,
      requiresHardware: requiresHardware,
    );
    _stateController.add(InstallationState.enrolled);
    return grant;
  }

  /// Signs an outgoing HTTP request with frozen bytes (Decision E1/E2). [optionalHeaders] are the optional covered
  /// components (J-01f2): `x-sentomaru-signals` (H3) and `x-sentomaru-operation-id` (J-01f); they are signed too.
  Future<SignedMessageHeaders> sign({
    required String method,
    required String targetUri,
    required String operation,
    required Uint8List bodyBytes,
    Map<String, String> optionalHeaders = const {},
  }) async {
    return _platform.sign(
      method: method,
      targetUri: targetUri,
      operation: operation,
      bodyBytes: bodyBytes,
      optionalHeaders: optionalHeaders,
    );
  }

  /// Resets local installation keys and credentials.
  Future<void> reset() async {
    await _platform.reset();
    _stateController.add(InstallationState.notEnrolled);
  }

  /// Collects local environmental signals without extra permissions (Decision E5): the six capabilities of catalog
  /// 1.0.0. D-10e (0.19.0): on iOS too, from the Swift SDK (`debug_attached` by `P_TRACED`, `emulator_detected` on the
  /// simulator, `root_indicated` from jailbreak indicators on a device and `UNKNOWN` on the simulator,
  /// `app_signing_digest` `UNSUPPORTED`, `installer_source` `UNKNOWN`, `os_version`); before, an empty list.
  Future<List<SignalObservation>> collectSignals() async {
    return _platform.collectSignals();
  }

  /// D-05e: collects and returns the snapshot in the wire format ([SignalsSnapshot.toJson] is the value of the
  /// `x-sentomaru-signals` header): catalog version, `collectedAt`, `durationMs`, server-only ids dropped.
  ///
  /// Without [rasp], the same six capabilities as [collectSignals]. With [rasp], also the D-05 ones
  /// (`debugger_attached`, `app_debuggable`, `dev_settings_enabled`, `root_artifacts`, `emulator_indicated`,
  /// `hook_framework_java`), collected off the main thread with a per-collection deadline (a detector past it is
  /// `UNKNOWN` `timeout`). `root_artifacts` checks the root-manager packages only when the app declares
  /// `br.com.ebees.sentomaru:signals-rasp` in its own Android build; without it the capability is never
  /// `NOT_DETECTED` (`UNKNOWN`, `partial=root_package`). On iOS the D-05 ids come back `UNSUPPORTED`, next to the six
  /// iOS observations (D-10e).
  ///
  /// D-12e (0.13.0): with [appIntegrity], also `app_signer_mismatch`, `installer_class` and `code_integrity` (catalog
  /// 1.5.0), checked against the app's [AppIntegritySignals.expectedSignerDigests]. Without [rasp] the
  /// collection keeps no deadline (the six never become `UNKNOWN` `timeout` because of this option); with [rasp] the
  /// deadline is 135 ms for all, and any detector, the old ones included, may come back `UNKNOWN` `timeout`. `code_integrity` is always `UNKNOWN` from the app (`not_compared` with the aggregate, or `timeout` on
  /// the first collection of a process while the code is hashed in the background); the server compares it. On iOS the
  /// three come back `UNSUPPORTED`. Without [appIntegrity] nothing changes.
  ///
  /// D-27 (iOS): [screen] adds `screen_capture` (`UNSUPPORTED`) and `screen_shared` (secondary display, recording or
  /// mirroring), read from `UIScreen` on the main thread (held at most 135 ms). Consultive. Ignored on Android.
  Future<SignalsSnapshot> collectSignalsSnapshot({bool rasp = false, AppIntegritySignals? appIntegrity, bool screen = false}) async {
    return _platform.collectSignalsSnapshot(rasp: rasp, appIntegrity: appIntegrity, screen: screen);
  }

  /// Returns the active session ID, if enrolled.
  Future<String?> sessionId() async {
    return _platform.sessionId();
  }

  /// J-04r: renews the grant now, signed by the installation key (no new attestation); returns the new session id.
  /// Needs [SentomaruConfig.renewalUrl]. The Dio interceptor calls it once on `session-expired`; renewal before a grant
  /// expires happens natively inside [sign].
  Future<String> renewSession() async {
    return _platform.renewSession();
  }

  /// D-12e: whether [reattestIfDue] would ask now: no completed reattestation nor server "not now" within its wait.
  /// Never blocks (answered on the platform thread from a volatile field). On iOS always `false`, configured or not.
  /// On Android only, without [SentomaruConfig.reattestation] it throws `invalidRequest`.
  Future<bool> reattestationDue() async {
    return _platform.reattestationDue();
  }

  /// D-12e (0.13.0): reattestation under a single-use server challenge (`contracts/api/reattestation-v1.md`), opt-in
  /// with [SentomaruConfig.reattestation]. When due, asks the consumer's route for a challenge, generates a NEW
  /// attested key in the Keystore for it (deleted right after, it never signs) and sends its chain, both steps signed
  /// with the current installation key; otherwise [ReattestationNotNow] `notDue` without sending anything. Runs on a
  /// native worker thread, never the main thread, and never makes `sign` wait.
  ///
  /// Nothing calls it by itself: call it at most once in a while, e.g. right after a successful [renewSession]. The
  /// outcome is advisory and the evaluation does not read it yet. [ReattestationNotNow] = try after `retryAfter`, never
  /// in a loop; [ReattestationRefused] `session-expired` = renew first; `reattestation-disabled` = the scope has it off
  /// (24 h before asking again). Local failures throw [SentomaruException] (`notEnrolled`, `strongBoxUnavailable`,
  /// `cancelled`; a Keystore failure is `unknown` with message `KeyUnavailable`). On iOS: [ReattestationUnsupported].
  Future<ReattestationOutcome> reattestIfDue({bool strongBox = false}) async {
    return _platform.reattestIfDue(strongBox: strongBox);
  }

  /// D-06h (0.15.0): the same reattestation as [reattestIfDue], now, ignoring the local wait: for a
  /// `server_response` `challenge-required` of kind `reattest` (`SentomaruSignalEvent.isReattestChallenge`), where the
  /// server already decided. The app calls it once and repeats the operation ONCE with a new nonce; the server reads the
  /// reattestation on that evaluation. With [ReattestationCompleted] the app repeats once, whatever the states (the
  /// server, not the app, judges them), and does not reattest again for that operation even if challenged again; with
  /// [ReattestationNotNow] (429 of the interval or of the daily cap) it shows "try later" without repeating. Nothing calls
  /// it by itself and the plugin never repeats an operation. Same thread, errors and outcomes as [reattestIfDue]; on iOS
  /// [ReattestationUnsupported].
  Future<ReattestationOutcome> reattest({bool strongBox = false}) async {
    return _platform.reattest(strongBox: strongBox);
  }

  /// D-15c: whether [signalEvents] can carry `signal` events here: `true` on Android, `false` on iOS (no D-05/D-12c
  /// detector there, so no `signal` event; `server_response` events still come from the Dio interceptor).
  bool get signalEventsSupported => _platform.signalEventsSupported;

  /// D-15c (0.14.0): informative events, opt-in. Nothing is built while nobody listens: the native side keeps no
  /// events, and [collectSignals] and [collectSignalsSnapshot] return the same as before either way.
  ///
  /// * `signal` (Android only): the D-05/D-12c capabilities of each [collectSignalsSnapshot] made while the stream is
  ///   listened to, on the first observation of a capability and on each change of its state. No collection of its
  ///   own: no thread, timer or service. A new subscription starts from scratch (first observations again).
  /// * `server_response` (every platform): the closed code a consumer answered (401/403) to a request the
  ///   `SentomaruDioInterceptor` signed: the real result of the server's policy as the consumer passed it on.
  ///
  /// These events are not a security verdict and do not replace the server's decision. Recommended use (integration
  /// guide): a `signal` event at most warns and logs in the app; `challenge-required` with `step_up` asks the user to
  /// authenticate again; with `reattest` (D-06h) the app calls [reattest] and repeats the operation once;
  /// `installation-suspended` shows the suspension screen keeping drafts; `installation-revoked`
  /// enrolls again. Leaving the app on a `signal` event alone is discouraged (measured false positive), though the
  /// choice is the app's. `SentomaruRiskEvent`/`onRiskEvent` are unchanged.
  Stream<SentomaruSignalEvent> get signalEvents => _eventController.stream;

  StreamController<SentomaruSignalEvent> _createEventController() {
    _eventsCreated = true;
    return StreamController<SentomaruSignalEvent>.broadcast(
      onListen: _listenPlatformEvents,
      onCancel: _cancelPlatformEvents,
    );
  }

  /// D-15c: the receiver `SentomaruDioInterceptor` calls (through `server_response_sink.dart`, not exported) with the
  /// status and body of the final answer to a request it SIGNED; a closed code becomes a `server_response` event,
  /// anything else is ignored. Does nothing while nobody listens to [signalEvents]. Never throws.
  void _observeServerResponse(int? httpStatus, Object? data) {
    if (!_eventsCreated || _eventController.isClosed || !_eventController.hasListener) return;
    try {
      final event = SentomaruSignalEvent.fromServerResponse(httpStatus, data, _eventSequence + 1);
      if (event == null) return;
      _eventSequence++;
      _eventController.add(event);
    } catch (_) {
      // Informative only: a body that cannot be read costs its event, never the response.
    }
  }

  void _listenPlatformEvents() {
    try {
      _platformEvents = _platform.signalEvents().listen((raw) {
        if (_eventController.isClosed) return;
        final event = SentomaruSignalEvent.fromPlatform(raw, _eventSequence + 1);
        if (event == null) return; // outside the closed vocabulary: dropped, never passed on partly
        _eventSequence++;
        _eventController.add(event);
      }, onError: (Object _) {});
    } catch (_) {
      _platformEvents = null; // a platform without the channel: server_response events only
    }
  }

  Future<void> _cancelPlatformEvents() async {
    final sub = _platformEvents;
    _platformEvents = null;
    await sub?.cancel();
  }

  /// Disposes internal resources and streams.
  void dispose() {
    _stateController.close();
    serverResponseSinks[this] = null;
    unawaited(_cancelPlatformEvents());
    if (_eventsCreated) _eventController.close();
  }
}
