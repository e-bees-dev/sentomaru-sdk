import 'dart:typed_data';
import 'package:plugin_platform_interface/plugin_platform_interface.dart';

import 'models.dart';
import 'reattestation.dart';
import 'sentomaru_flutter_method_channel.dart';
import 'signals_snapshot.dart';

abstract class SentomaruFlutterPlatform extends PlatformInterface {
  /// Constructs a SentomaruFlutterPlatform.
  SentomaruFlutterPlatform() : super(token: _token);

  static final Object _token = Object();

  static SentomaruFlutterPlatform _instance = MethodChannelSentomaruFlutter();

  /// The default instance of [SentomaruFlutterPlatform] to use.
  static SentomaruFlutterPlatform get instance => _instance;

  /// Platform-specific implementations should set this with their own
  /// platform-specific class that extends [SentomaruFlutterPlatform] when
  /// they register themselves.
  static set instance(SentomaruFlutterPlatform instance) {
    PlatformInterface.verifyToken(instance, _token);
    _instance = instance;
  }

  Future<String?> scaffoldInfo() {
    throw UnimplementedError('scaffoldInfo() has not been implemented.');
  }

  Future<void> initialize(SentomaruConfig config) {
    throw UnimplementedError('initialize() has not been implemented.');
  }

  Future<InstallationState> state() {
    throw UnimplementedError('state() has not been implemented.');
  }

  /// D-04b: why the enrolled installation should enroll again (fresh attestation), or `null`.
  Future<ReenrollmentReason?> reenrollmentReason() {
    throw UnimplementedError('reenrollmentReason() has not been implemented.');
  }

  Future<EnrollmentGrant> enroll(
    EnrollmentChallenge challenge, {
    bool strongBox = false,
    bool requiresHardware = false,
  }) {
    throw UnimplementedError('enroll() has not been implemented.');
  }

  Future<EnrollmentGrant> rotate(
    EnrollmentChallenge challenge, {
    bool strongBox = false,
    bool requiresHardware = false,
  }) {
    throw UnimplementedError('rotate() has not been implemented.');
  }

  Future<SignedMessageHeaders> sign({
    required String method,
    required String targetUri,
    required String operation,
    required Uint8List bodyBytes,
    Map<String, String> optionalHeaders = const {},
  }) {
    throw UnimplementedError('sign() has not been implemented.');
  }

  Future<void> reset() {
    throw UnimplementedError('reset() has not been implemented.');
  }

  Future<List<SignalObservation>> collectSignals() {
    throw UnimplementedError('collectSignals() has not been implemented.');
  }

  /// D-05e: the signals snapshot in the wire format; [rasp] adds the D-05 capabilities (catalog 1.3.0). D-12e:
  /// [appIntegrity] adds the three of the catalog 1.5.0.
  Future<SignalsSnapshot> collectSignalsSnapshot({bool rasp = false, AppIntegritySignals? appIntegrity, bool screen = false}) {
    throw UnimplementedError('collectSignalsSnapshot() has not been implemented.');
  }

  /// D-25 (iOS): one call of the transaction key (`txKeyCreate`, `txSign`, `txIsEnrolled`, `txDiscard`).
  Future<T?> invokeTransaction<T>(String method, Map<String, Object?>? arguments) {
    throw UnimplementedError('invokeTransaction() has not been implemented.');
  }

  /// D-26 (iOS): one call of the offline proof chain (`offlineSeal`, `offlineReconcileBody`).
  Future<T?> invokeOffline<T>(String method, Map<String, Object?>? arguments) {
    throw UnimplementedError('invokeOffline() has not been implemented.');
  }

  Future<String?> sessionId() {
    throw UnimplementedError('sessionId() has not been implemented.');
  }

  /// J-04r: renews the grant now (signed by the installation key) and returns the new session id.
  Future<String> renewSession() {
    throw UnimplementedError('renewSession() has not been implemented.');
  }

  /// D-12e: whether [reattestIfDue] would ask now (never blocks).
  Future<bool> reattestationDue() {
    throw UnimplementedError('reattestationDue() has not been implemented.');
  }

  /// D-12e: the native `SentomaruReattestation.reattestIfDue`, on a worker thread.
  Future<ReattestationOutcome> reattestIfDue({bool strongBox = false}) {
    throw UnimplementedError('reattestIfDue() has not been implemented.');
  }

  /// D-06h (0.15.0): the native `SentomaruReattestation.reattest`, which ignores the local wait, on the same worker
  /// thread as [reattestIfDue].
  Future<ReattestationOutcome> reattest({bool strongBox = false}) {
    throw UnimplementedError('reattest() has not been implemented.');
  }

  /// D-15c: whether this platform emits signal events ([signalEvents] with `kind` `signal`): Android only.
  bool get signalEventsSupported => false;

  /// D-15c: the raw signal events of the native SDK, one map per event (see `SentomaruSignalEvent.fromPlatform`).
  /// Subscribed only while the app listens to `SentomaruClient.signalEvents`. A platform without native signal events
  /// (iOS) gives an empty stream; this default does too, so an implementation that predates 0.14.0 keeps working.
  Stream<Object?> signalEvents() => const Stream.empty();
}
