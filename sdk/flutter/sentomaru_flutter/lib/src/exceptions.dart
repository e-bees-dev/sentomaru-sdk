import 'package:flutter/services.dart';

/// Categorized error codes per Decision E7.
///
/// Ensures failure states are recoverable, categorized, and typed.
/// Raw unhandled platform exceptions must never leak to consumers.
enum SentomaruErrorCode {
  /// The Dart [SentomaruClient] of this isolate was never initialized (boot, background isolate, hot restart).
  notInitialized,

  /// Required configuration (organization/app/environment/allowlist/enrollment URL) is missing or invalid.
  configurationError,
  notEnrolled,
  enrollmentRequired,
  keyInvalidated,
  strongBoxUnavailable,
  challengeExpired,
  networkUnavailable,
  serverRejected,
  noActivity,
  cancelled,
  hostNotAllowed,
  bodyTooLarge,
  invalidRequest,
  channelError,
  unknown,

  /// `renewSession` was not attempted: the backoff of the previous failed renewal is still running (5 s, 15 s, then
  /// 60 s after consecutive suspensions, `ServerRejected:SUSPENDED`; 60 s otherwise). The grant is unchanged; try
  /// again later. Last on purpose: the ordinals of the older values do not change.
  renewalBackoff,

  /// D-04d (contract v1.6): `401 predecessor-invalid` on [SentomaruClient.rotate]: the server refused to re-enroll this
  /// installation with the current key (quarantined, already replaced, another subject/tenant, or a proof that does
  /// not verify). Rotating again cannot succeed: call `reset()` and then `enroll()`, which creates a NEW installation
  /// (new code, no name or tags, no suspension carried over). Appended last: older ordinals do not change.
  reenrollmentRefused,

  /// C-03a (0.16.0, Dart only): a connection to a host of the `network-pinning` section was refused before any byte of
  /// the request was written. [SentomaruException.details] is the reason: `pin_mismatch` (the leaf key is not pinned),
  /// `proxy` (a pinned host through a proxy cannot be checked) or `cleartext` (http to a pinned host). TLS failures
  /// the platform detects first keep their own `HandshakeException`. Appended last: older ordinals do not change.
  pinningRefused,

  /// D-10b (0.18.0, iOS): a platform capability the installation needs is missing on this device or build, and the
  /// plugin never enrolls without it. [SentomaruException.details] is the native code: `Unsupported:APP_ATTEST` (no App
  /// Attest: simulator, unsupported device, or an app without the App Attest capability) or `Unsupported:SECURE_ENCLAVE`
  /// (no Secure Enclave). Nothing was created or sent. Never thrown on Android. Appended last: older ordinals do not change.
  unsupported;

  static SentomaruErrorCode fromString(String? code) {
    if (code == null) return SentomaruErrorCode.unknown;
    final trimmed = code.trim();
    // Kotlin codes carry a reason suffix (`InvalidRequest:PARAMS`, `ServerRejected:INVALID`).
    if (trimmed.startsWith('InvalidRequest:')) return SentomaruErrorCode.invalidRequest;
    if (trimmed.startsWith('ServerRejected:')) return SentomaruErrorCode.serverRejected;
    if (trimmed.startsWith('Unsupported:')) return SentomaruErrorCode.unsupported;
    switch (trimmed) {
      case 'NotInitialized':
        return SentomaruErrorCode.notInitialized;
      case 'ConfigurationError':
        return SentomaruErrorCode.configurationError;
      case 'NotEnrolled':
        return SentomaruErrorCode.notEnrolled;
      case 'EnrollmentRequired':
        return SentomaruErrorCode.enrollmentRequired;
      case 'KeyInvalidated':
        return SentomaruErrorCode.keyInvalidated;
      case 'StrongBoxUnavailable':
        return SentomaruErrorCode.strongBoxUnavailable;
      case 'ChallengeExpired':
        return SentomaruErrorCode.challengeExpired;
      case 'NetworkUnavailable':
        return SentomaruErrorCode.networkUnavailable;
      case 'ServerRejected':
        return SentomaruErrorCode.serverRejected;
      case 'NoActivity':
        return SentomaruErrorCode.noActivity;
      case 'Cancelled':
        return SentomaruErrorCode.cancelled;
      case 'HostNotAllowed':
        return SentomaruErrorCode.hostNotAllowed;
      case 'BodyTooLarge':
        return SentomaruErrorCode.bodyTooLarge;
      case 'InvalidRequest':
        return SentomaruErrorCode.invalidRequest;
      case 'RenewalBackoff':
        return SentomaruErrorCode.renewalBackoff;
      case 'ReenrollmentRefused':
        return SentomaruErrorCode.reenrollmentRefused;
      case 'ChannelError':
        return SentomaruErrorCode.channelError;
      default:
        return SentomaruErrorCode.unknown;
    }
  }
}

/// Typed exception for all Sentomaru SDK operations (Decision E7).
class SentomaruException implements Exception {
  final SentomaruErrorCode code;
  final String message;
  final dynamic details;

  const SentomaruException(this.code, this.message, [this.details]);

  factory SentomaruException.fromPlatformException(PlatformException e) {
    final code = SentomaruErrorCode.fromString(e.code);
    // For ServerRejected the reason (e.g. `ServerRejected:INVALID`) is kept in [details] when the platform sent none;
    // the same for the capability of Unsupported (`Unsupported:APP_ATTEST`, D-10b).
    final keepCode = code == SentomaruErrorCode.serverRejected || code == SentomaruErrorCode.unsupported;
    return SentomaruException(
      code,
      e.message ?? 'Platform error: ${e.code}',
      e.details ?? (keepCode ? e.code : null),
    );
  }

  factory SentomaruException.channelError(String message, [dynamic details]) {
    return SentomaruException(
      SentomaruErrorCode.channelError,
      message,
      details,
    );
  }

  @override
  String toString() {
    if (details != null) {
      return 'SentomaruException($code: $message, details: $details)';
    }
    return 'SentomaruException($code: $message)';
  }
}
