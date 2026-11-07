import 'exceptions.dart';

/// D-12e: why [ReattestationNotNow] (the native `ReattestationWait`). Try again after the wait, never in a loop.
enum ReattestationWait {
  /// `429 rate-limited`: the scope's minimum interval or the server's cap of challenges per day.
  rateLimited,

  /// `503 verifier-unavailable` again after the one retry (or a retry that would not fit the challenge).
  verifierUnavailable,

  /// The consumer's route could not be reached, answered another 5xx, or `409 replay` could not be retried.
  unavailable,

  /// Local: the last reattestation, or a server "not now", is more recent than the interval. Nothing was sent.
  notDue,

  /// A reason this plugin version does not know (a newer native SDK). Treat it as "not now".
  unknown;

  static ReattestationWait fromPlatform(Object? value) => switch (value) {
        'RATE_LIMITED' => ReattestationWait.rateLimited,
        'VERIFIER_UNAVAILABLE' => ReattestationWait.verifierUnavailable,
        'UNAVAILABLE' => ReattestationWait.unavailable,
        'NOT_DUE' => ReattestationWait.notDue,
        _ => ReattestationWait.unknown,
      };
}

/// D-12e: what the server recorded for a reattestation (the Sentomaru re-attestation API contract, the 200 answer). States
/// and reasons are the server's closed codes; advisory, never an authorization, and the evaluation does not read it
/// yet (D-12b). [replayed] = the same body was answered before.
class ReattestationResult {
  final String installationId;
  final String challengeId;
  final DateTime reattestedAt;
  final String hardwareStatus;
  final String attestationStatus;
  final String? attestationReason;
  final String buildMatchState;
  final String? buildMatchReason;
  final String appIdentityState;
  final String? appIdentityReason;
  final bool replayed;

  const ReattestationResult({
    required this.installationId,
    required this.challengeId,
    required this.reattestedAt,
    required this.hardwareStatus,
    required this.attestationStatus,
    this.attestationReason,
    required this.buildMatchState,
    this.buildMatchReason,
    required this.appIdentityState,
    this.appIdentityReason,
    required this.replayed,
  });

  /// Strict: a missing or mistyped member is a [FormatException] (the caller turns it into `channelError`).
  factory ReattestationResult.fromMap(Map<dynamic, dynamic> map) {
    String required(String key) {
      final value = map[key];
      if (value is! String || value.isEmpty) throw FormatException('Reattestation result without $key');
      return value;
    }

    String? optional(String key) {
      final value = map[key];
      if (value == null) return null;
      if (value is! String || value.isEmpty) throw FormatException('Reattestation result with a bad $key');
      return value;
    }

    final at = DateTime.tryParse(required('reattestedAt'));
    if (at == null) throw const FormatException('Reattestation result without a valid reattestedAt');
    final replayed = map['replayed'];
    if (replayed is! bool) throw const FormatException('Reattestation result without replayed');
    return ReattestationResult(
      installationId: required('installationId'),
      challengeId: required('challengeId'),
      reattestedAt: at.toUtc(),
      hardwareStatus: required('hardwareStatus'),
      attestationStatus: required('attestationStatus'),
      attestationReason: optional('attestationReason'),
      buildMatchState: required('buildMatchState'),
      buildMatchReason: optional('buildMatchReason'),
      appIdentityState: required('appIdentityState'),
      appIdentityReason: optional('appIdentityReason'),
      replayed: replayed,
    );
  }
}

/// D-12e: the outcome of [SentomaruClient.reattestIfDue]. Local failures (not enrolled, Keystore, StrongBox,
/// cancelled) are thrown as [SentomaruException], as in `enroll`.
sealed class ReattestationOutcome {
  const ReattestationOutcome();

  /// Parses the native reply; anything malformed is `channelError`, never a made-up outcome.
  static ReattestationOutcome fromPlatform(Object? reply) {
    try {
      if (reply is! Map) throw const FormatException('Reattestation reply is not a map');
      switch (reply['outcome']) {
        case 'completed':
          final result = reply['result'];
          if (result is! Map) throw const FormatException('Completed reattestation without result');
          return ReattestationCompleted(ReattestationResult.fromMap(result));
        case 'notNow':
          final ms = reply['retryAfterMs'];
          if (ms is! int || ms < 0) throw const FormatException('Reattestation "not now" without retryAfterMs');
          return ReattestationNotNow(ReattestationWait.fromPlatform(reply['reason']), Duration(milliseconds: ms));
        case 'refused':
          final code = reply['code'];
          final status = reply['status'];
          if (code is! String || code.isEmpty || status is! int) {
            throw const FormatException('Refused reattestation without code or status');
          }
          return ReattestationRefused(code, status);
        default:
          throw const FormatException('Unknown reattestation outcome');
      }
    } on FormatException catch (e) {
      throw SentomaruException.channelError('Malformed native reattestation: ${e.message}');
    }
  }
}

/// The server recorded a result ([result]); [SentomaruClient.reattestationDue] stays false for the interval (1 h when
/// the result says `revocation_unchecked`).
class ReattestationCompleted extends ReattestationOutcome {
  final ReattestationResult result;
  const ReattestationCompleted(this.result);
}

/// "Not now": nothing to fix, try again after [retryAfter] (between 60 s and 24 h, or what is left of the interval
/// for [ReattestationWait.notDue]).
class ReattestationNotNow extends ReattestationOutcome {
  final ReattestationWait reason;
  final Duration retryAfter;
  const ReattestationNotNow(this.reason, this.retryAfter);
}

/// The server refused and trying again now would not change it: [code] is the server's JSON `code`
/// (`reattestation-disabled`, `reattestation-unsupported`, `session-expired` (renew first), `installation-suspended`,
/// `challenge-invalid`, `replay` twice, …) or `unexpected-answer`; [status] is the HTTP status, 0 when refused
/// locally (a challenge already expired on the device clock).
class ReattestationRefused extends ReattestationOutcome {
  final String code;
  final int status;
  const ReattestationRefused(this.code, this.status);
}

/// iOS (and any platform without the native Android SDK): there is no Key Attestation reattestation; nothing was
/// sent. The server answers App Attest installations `403 reattestation-unsupported` as well.
class ReattestationUnsupported extends ReattestationOutcome {
  const ReattestationUnsupported();
}
