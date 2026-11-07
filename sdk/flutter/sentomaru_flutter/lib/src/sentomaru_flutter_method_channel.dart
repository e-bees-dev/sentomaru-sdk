import 'package:flutter/foundation.dart';
import 'package:flutter/services.dart';

import 'exceptions.dart';
import 'models.dart';
import 'reattestation.dart';
import 'sentomaru_flutter_platform_interface.dart';
import 'signals_snapshot.dart';

/// An implementation of [SentomaruFlutterPlatform] that uses method channels.
class MethodChannelSentomaruFlutter extends SentomaruFlutterPlatform {
  /// The method channel used to interact with the native platform.
  @visibleForTesting
  final methodChannel = const MethodChannel('sentomaru_flutter');

  /// D-15c: the native signal events (Android `SignalEventsBridge`).
  @visibleForTesting
  final eventChannel = const EventChannel('sentomaru_flutter/signal_events');

  static bool get _android => !kIsWeb && defaultTargetPlatform == TargetPlatform.android;

  /// D-15c: Android only; iOS has no D-05/D-12c detector (D-10e collects only the six), so never a `signal` event there.
  @override
  bool get signalEventsSupported => _android;

  /// D-15c. Android: the EventChannel (the native side keeps the events only while subscribed). Elsewhere: empty,
  /// without touching the channel. An error of the channel ends nothing: it is dropped (events are informative).
  @override
  Stream<Object?> signalEvents() {
    if (!_android) return const Stream.empty();
    return _nativeEvents ??= eventChannel.receiveBroadcastStream().handleError((Object _) {});
  }

  /// Review R I-2: ONE broadcast stream of the channel for every client of the engine. The native side keeps a single
  /// handler per channel, so a second `receiveBroadcastStream()` would cancel the first subscription natively (and its
  /// cancel would end the other's); the shared stream listens natively on the first listener and cancels on the last.
  static Stream<Object?>? _nativeEvents;

  @visibleForTesting
  static void resetSignalEventsForTesting() => _nativeEvents = null;

  @override
  Future<String?> scaffoldInfo() async {
    return _invoke('scaffoldInfo');
  }

  @override
  Future<void> initialize(SentomaruConfig config) async {
    await _invoke('initialize', config.toMap());
  }

  @override
  Future<InstallationState> state() async {
    final result = await _invoke<String>('state');
    return InstallationState.fromString(result);
  }

  @override
  Future<ReenrollmentReason?> reenrollmentReason() async {
    return ReenrollmentReason.fromPlatform(await _invoke<String>('reenrollmentReason'));
  }

  @override
  Future<EnrollmentGrant> enroll(
    EnrollmentChallenge challenge, {
    bool strongBox = false,
    bool requiresHardware = false,
  }) async {
    final result = await _invoke<Map>('enroll', {
      'challenge': challenge.toMap(),
      'strongBox': strongBox,
      'requiresHardware': requiresHardware,
    });
    if (result == null) {
      throw SentomaruException(
        SentomaruErrorCode.channelError,
        'Null response from native enroll',
      );
    }
    return EnrollmentGrant.fromMap(result);
  }

  @override
  Future<EnrollmentGrant> rotate(
    EnrollmentChallenge challenge, {
    bool strongBox = false,
    bool requiresHardware = false,
  }) async {
    final result = await _invoke<Map>('rotate', {
      'challenge': challenge.toMap(),
      'strongBox': strongBox,
      'requiresHardware': requiresHardware,
    });
    if (result == null) {
      throw SentomaruException(
        SentomaruErrorCode.channelError,
        'Null response from native rotate',
      );
    }
    return EnrollmentGrant.fromMap(result);
  }

  @override
  Future<SignedMessageHeaders> sign({
    required String method,
    required String targetUri,
    required String operation,
    required Uint8List bodyBytes,
    Map<String, String> optionalHeaders = const {},
  }) async {
    final result = await _invoke<Map>('sign', {
      'method': method,
      'targetUri': targetUri,
      'operation': operation,
      'body': bodyBytes,
      'optional': optionalHeaders,
    });
    if (result == null) {
      throw SentomaruException(
        SentomaruErrorCode.channelError,
        'Null response from native sign',
      );
    }
    final headers = <String, String>{};
    result.forEach((key, value) {
      headers[key.toString()] = value.toString();
    });
    return SignedMessageHeaders(headers);
  }

  @override
  Future<void> reset() async {
    await _invoke('reset');
  }

  @override
  Future<List<SignalObservation>> collectSignals() async {
    final result = await _invoke<List>('collectSignals');
    if (result == null) return [];
    try {
      return _observations(result);
    } on FormatException catch (e) {
      throw SentomaruException.channelError('Malformed native signals: ${e.message}');
    }
  }

  /// D-05e. Android: the native collector, on the plugin's background executor (`rasp` adds the D-05 detectors with
  /// `SignalsCollector.RASP_DEADLINE_MS`). D-10e, iOS: the Swift SDK's collector, same call and reply: the six of
  /// [collectSignals] observed on iOS, and the D-05 ids ([rasp]) as UNSUPPORTED (no iOS check exists). Any other platform
  /// has no native signals: [rasp] gives the D-05 ids as UNSUPPORTED, and the six are left out (never invented).
  ///
  /// D-12e: [appIntegrity] adds `expectedSignerDigests` to the call (absent otherwise, so the call without it is the
  /// same as before) and, natively, `appIntegrityDetectors` (with [rasp], 35 ms more deadline; without it, still no deadline). On iOS its three ids come back
  /// UNSUPPORTED. The digests are checked first on every platform.
  @override
  Future<SignalsSnapshot> collectSignalsSnapshot({bool rasp = false, AppIntegritySignals? appIntegrity, bool screen = false}) async {
    appIntegrity?.validate();
    if (kIsWeb || (defaultTargetPlatform != TargetPlatform.android && defaultTargetPlatform != TargetPlatform.iOS)) {
      return unsupportedSignalsSnapshot(rasp: rasp, appIntegrity: appIntegrity != null);
    }
    final result = await _invoke<Map>('collectSignalsSnapshot', {
      'rasp': rasp,
      if (appIntegrity != null) 'expectedSignerDigests': appIntegrity.expectedSignerDigests,
      if (screen) 'screen': true,
    });
    if (result == null) {
      throw SentomaruException(SentomaruErrorCode.channelError, 'Null response from native collectSignalsSnapshot');
    }
    try {
      final rawCollectedAt = result['collectedAt'];
      final collectedAt = rawCollectedAt is String ? DateTime.tryParse(rawCollectedAt) : null;
      if (collectedAt == null) throw const FormatException('Signals snapshot without a valid collectedAt');
      final durationMs = result['durationMs'];
      if (durationMs is! int) throw const FormatException('Signals snapshot without durationMs');
      final observations = result['observations'];
      if (observations is! List) throw const FormatException('Signals snapshot without observations');
      return SignalsSnapshot(collectedAt: collectedAt, durationMs: durationMs, observations: _observations(observations));
    } on FormatException catch (e) {
      throw SentomaruException.channelError('Malformed native signals: ${e.message}');
    } on TypeError {
      throw SentomaruException.channelError('Malformed native signals snapshot');
    }
  }

  /// The snapshot of a platform without native signals (neither Android nor, since the D-10e, iOS): the D-05 ids
  /// UNSUPPORTED when [rasp], the D-12c ones when [appIntegrity], else empty.
  @visibleForTesting
  static SignalsSnapshot unsupportedSignalsSnapshot({required bool rasp, bool appIntegrity = false, DateTime? now}) {
    final at = (now ?? DateTime.now()).toUtc();
    return SignalsSnapshot(collectedAt: at, durationMs: 0, observations: [
      for (final id in [
        if (rasp) ...SentomaruSignalsCatalog.raspCapabilityIds,
        if (appIntegrity) ...SentomaruSignalsCatalog.appIntegrityCapabilityIds,
      ])
          SignalObservation(
            capabilityId: id,
            version: SentomaruSignalsCatalog.byId(id)!.version,
            state: SignalState.unsupported,
            source: 'client_observed',
            observedAt: at,
          ),
    ]);
  }

  static List<SignalObservation> _observations(List raw) {
    final observations = raw.map((item) => SignalObservation.fromMap(item as Map)).toList();
    final ids = observations.map((o) => o.capabilityId.toLowerCase()).toList();
    if (ids.toSet().length != ids.length) {
      throw const FormatException('Duplicate capabilityId in signals snapshot');
    }
    return observations;
  }

  @override
  Future<String?> sessionId() async {
    return _invoke<String>('sessionId');
  }

  @override
  Future<String> renewSession() async {
    final session = await _invoke<String>('renewSession');
    if (session == null) {
      throw SentomaruException(SentomaruErrorCode.channelError, 'Null response from native renewSession');
    }
    return session;
  }

  /// D-12e: off Android there is no reattestation to wait for, so never due.
  @override
  Future<bool> reattestationDue() async {
    if (kIsWeb || defaultTargetPlatform != TargetPlatform.android) return false;
    final due = await _invoke<bool>('reattestationDue');
    if (due == null) throw SentomaruException.channelError('Null response from native reattestationDue');
    return due;
  }

  /// D-12e. Android: the native `reattestIfDue` on the plugin's reattestation thread (never the main thread nor the
  /// one `sign` uses). iOS and others: [ReattestationUnsupported] without a channel call.
  @override
  Future<ReattestationOutcome> reattestIfDue({bool strongBox = false}) async {
    if (kIsWeb || defaultTargetPlatform != TargetPlatform.android) return const ReattestationUnsupported();
    return ReattestationOutcome.fromPlatform(await _invoke<Map>('reattestIfDue', {'strongBox': strongBox}));
  }

  /// D-06h (0.15.0). Android: the native `reattest` (ignores the local wait) on the same thread as [reattestIfDue], same
  /// outcome. iOS and others: [ReattestationUnsupported] without a channel call.
  @override
  Future<ReattestationOutcome> reattest({bool strongBox = false}) async {
    if (kIsWeb || defaultTargetPlatform != TargetPlatform.android) return const ReattestationUnsupported();
    return ReattestationOutcome.fromPlatform(await _invoke<Map>('reattest', {'strongBox': strongBox}));
  }

  @override
  Future<T?> invokeOffline<T>(String method, Map<String, Object?>? arguments) {
    return methodChannel.invokeMethod<T>(method, arguments);
  }

  /// D-25: the transaction key calls go to the channel as they are; the caller maps the platform error.
  @override
  Future<T?> invokeTransaction<T>(String method, Map<String, Object?>? arguments) {
    return methodChannel.invokeMethod<T>(method, arguments);
  }

  Future<T?> _invoke<T>(String method, [dynamic arguments]) async {
    try {
      return await methodChannel.invokeMethod<T>(method, arguments);
    } on PlatformException catch (e) {
      throw SentomaruException.fromPlatformException(e);
    } on SentomaruException {
      rethrow;
    } catch (e) {
      throw SentomaruException.channelError(
        'Unexpected method channel error on $method: $e',
      );
    }
  }
}
