import 'dart:convert';
import 'dart:typed_data';

import 'exceptions.dart';

/// Configuration for Sentomaru client and transport.
class SentomaruConfig {
  /// Organization slug (e.g. 'ebees').
  final String organization;

  /// Application slug (e.g. 'example-app').
  final String app;

  /// Environment slug (e.g. 'dev', 'hml', 'prod').
  final String environment;

  /// Public enrollment URL of the consumer backend.
  final String enrollmentUrl;

  /// Allowlist of hosts authorized for RFC 9421 signed requests (Decision E6).
  final Set<String> allowedHosts;

  /// Coexistence window for retired keys during rotation (Decision E-rot).
  /// Defaults to 7 days.
  final Duration rotationGracePeriod;

  /// C-04b: Google Cloud project number linked to the app (or to the Sentomaru SDK) for Play Integrity. When set, the
  /// SDK adds an advisory Play Integrity token to the enrollment; any failure enrolls without it. Null = off.
  final int? playIntegrityCloudProjectNumber;

  /// J-04r (0.9.0): the consumer's public renewal route. With it the native SDK renews the grant (10 minutes on the
  /// server) before it expires, signed by the installation key, without a new attestation, and the Dio interceptor
  /// renews and resends once on `session-expired`. Null keeps the pre-0.9 behaviour.
  final String? renewalUrl;

  /// D-12e (0.13.0): the consumer's reattestation routes, opt-in. Null (the default) = no reattestation:
  /// [SentomaruClient.reattestIfDue] answers `invalidRequest`. Nothing reattests by itself.
  final SentomaruReattestationConfig? reattestation;

  /// D-F1 (ativação de módulos em cliente novo, Fase F): what the app, not the SDK, declares about its own
  /// integration — does it actually enforce the policy's recommendation, does it treat the installation response
  /// (suspend/revoke)? Sent as `sdkModes` at enrollment, purely informational (A-13): the SDK never reads either
  /// back. `false` by default is deliberate: an app that forgets to set this is a true "not enforcing", the same
  /// gap the Prontidão (Fase A) exists to catch.
  final bool declaredEnforce;
  final bool declaredInstallationResponse;

  const SentomaruConfig({
    required this.organization,
    required this.app,
    required this.environment,
    required this.enrollmentUrl,
    required this.allowedHosts,
    this.rotationGracePeriod = const Duration(days: 7),
    this.playIntegrityCloudProjectNumber,
    this.renewalUrl,
    this.reattestation,
    this.declaredEnforce = false,
    this.declaredInstallationResponse = false,
  });

  /// Scope identity string or hash representation.
  String get identity => '$organization:$app:$environment';

  Map<String, dynamic> toMap() => {
        'organization': organization,
        'app': app,
        'environment': environment,
        'enrollmentUrl': enrollmentUrl,
        'allowedHosts': allowedHosts.toList(),
        'rotationGracePeriodDays': rotationGracePeriod.inDays,
        if (playIntegrityCloudProjectNumber != null) 'playIntegrityCloudProjectNumber': playIntegrityCloudProjectNumber,
        if (renewalUrl != null) 'renewalUrl': renewalUrl,
        if (reattestation != null) ...{
          'reattestationChallengeUrl': reattestation!.challengeUrl,
          'reattestationSubmitUrl': reattestation!.submitUrl,
          'reattestationMinIntervalSeconds': reattestation!.minInterval.inSeconds,
        },
        'declaredEnforce': declaredEnforce,
        'declaredInstallationResponse': declaredInstallationResponse,
      };

  /// Throws [SentomaruException] with [SentomaruErrorCode.configurationError] when a required field is missing or
  /// blank. There is no default scope: a build without organization/app/environment must not run as some other app.
  void validate() {
    final missing = <String>[
      if (organization.trim().isEmpty) 'organization',
      if (app.trim().isEmpty) 'app',
      if (environment.trim().isEmpty) 'environment',
      if (enrollmentUrl.trim().isEmpty) 'enrollmentUrl',
      if (allowedHosts.isEmpty) 'allowedHosts',
      if (playIntegrityCloudProjectNumber != null && playIntegrityCloudProjectNumber! <= 0) 'playIntegrityCloudProjectNumber',
      if (renewalUrl != null && !_allowedHttps(renewalUrl!)) 'renewalUrl',
      if (reattestation != null && !_allowedHttps(reattestation!.challengeUrl)) 'reattestation.challengeUrl',
      if (reattestation != null && !_allowedHttps(reattestation!.submitUrl)) 'reattestation.submitUrl',
      if (reattestation != null && !reattestation!._validInterval) 'reattestation.minInterval',
    ];
    if (missing.isNotEmpty) {
      throw SentomaruException(
        SentomaruErrorCode.configurationError,
        'Missing Sentomaru configuration: ${missing.join(', ')}',
      );
    }
  }

  bool _allowedHttps(String url) {
    final uri = Uri.tryParse(url);
    return uri != null && uri.scheme == 'https' && allowedHosts.contains(uri.host) && uri.userInfo.isEmpty;
  }

  factory SentomaruConfig.fromMap(Map<String, dynamic> map) {
    String required(String key) {
      final value = map[key];
      if (value is! String || value.trim().isEmpty) {
        throw SentomaruException(SentomaruErrorCode.configurationError, 'Missing Sentomaru configuration: $key');
      }
      return value;
    }

    final hosts = map['allowedHosts'];
    if (hosts is! List || hosts.isEmpty) {
      throw const SentomaruException(SentomaruErrorCode.configurationError, 'Missing Sentomaru configuration: allowedHosts');
    }
    return SentomaruConfig(
      organization: required('organization'),
      app: required('app'),
      environment: required('environment'),
      enrollmentUrl: required('enrollmentUrl'),
      allowedHosts: Set<String>.from(hosts),
      rotationGracePeriod: Duration(
        days: (map['rotationGracePeriodDays'] as num?)?.toInt() ?? 7,
      ),
      playIntegrityCloudProjectNumber: (map['playIntegrityCloudProjectNumber'] as num?)?.toInt(),
      renewalUrl: map['renewalUrl'] as String?,
      reattestation: map['reattestationChallengeUrl'] == null && map['reattestationSubmitUrl'] == null
          ? null
          : SentomaruReattestationConfig(
              challengeUrl: required('reattestationChallengeUrl'),
              submitUrl: required('reattestationSubmitUrl'),
              minInterval: Duration(
                seconds: (map['reattestationMinIntervalSeconds'] as num?)?.toInt() ??
                    SentomaruReattestationConfig.defaultMinInterval.inSeconds,
              ),
            ),
      declaredEnforce: map['declaredEnforce'] as bool? ?? false,
      declaredInstallationResponse: map['declaredInstallationResponse'] as bool? ?? false,
    );
  }
}

/// D-12e (0.13.0): the consumer's public reattestation routes, which forward to `POST …/reattestations/challenges` and
/// `POST …/reattestations` (the Sentomaru re-attestation API contract). Both https, on a host of
/// [SentomaruConfig.allowedHosts]. [minInterval] is how long [SentomaruClient.reattestationDue] stays false after a
/// completed reattestation (in memory only; a new process may ask again and the server answers 429); a positive
/// whole number of seconds, 24 h by default (the server's default for the scope).
class SentomaruReattestationConfig {
  static const defaultMinInterval = Duration(hours: 24);

  final String challengeUrl;
  final String submitUrl;
  final Duration minInterval;

  const SentomaruReattestationConfig({
    required this.challengeUrl,
    required this.submitUrl,
    this.minInterval = defaultMinInterval,
  });

  bool get _validInterval => minInterval.inSeconds > 0 && minInterval.inMicroseconds % Duration.microsecondsPerSecond == 0;
}

/// Installation lifecycle state.
enum InstallationState {
  notEnrolled,
  enrollmentRequired,
  keyInvalidated,
  enrolled;

  static InstallationState fromString(String? value) {
    switch (value) {
      case 'NotEnrolled':
        return InstallationState.notEnrolled;
      case 'EnrollmentRequired':
        return InstallationState.enrollmentRequired;
      case 'KeyInvalidated':
        return InstallationState.keyInvalidated;
      case 'Enrolled':
        return InstallationState.enrolled;
      default:
        return InstallationState.notEnrolled;
    }
  }

  String toPlatformString() {
    switch (this) {
      case InstallationState.notEnrolled:
        return 'NotEnrolled';
      case InstallationState.enrollmentRequired:
        return 'EnrollmentRequired';
      case InstallationState.keyInvalidated:
        return 'KeyInvalidated';
      case InstallationState.enrolled:
        return 'Enrolled';
    }
  }
}

/// D-04b: why an [InstallationState.enrolled] installation should enroll again with a fresh attestation
/// ([SentomaruClient.reenrollmentReason]). A separate answer, not a new [InstallationState]: the installation keeps
/// signing until the app enrolls again.
enum ReenrollmentReason {
  /// The app's `versionCode` differs from the one the current key was attested with (an update or a downgrade). The
  /// server keeps the build evidence of the enrollment (D-04a) until the app enrolls again.
  appUpdated,

  /// A reason this plugin version does not know (a newer native SDK). Treat it as "enroll again".
  unknown;

  /// `null` (nothing to do) stays `null`; native names map to values, anything else to [unknown].
  static ReenrollmentReason? fromPlatform(String? value) {
    if (value == null) return null;
    return value == 'APP_UPDATED' ? ReenrollmentReason.appUpdated : ReenrollmentReason.unknown;
  }
}

/// Challenge issued by consumer backend to initiate or renew enrollment.
class EnrollmentChallenge {
  final String id;
  final String token;
  final DateTime expiresAt;
  final Uint8List attestationChallenge;

  const EnrollmentChallenge({
    required this.id,
    required this.token,
    required this.expiresAt,
    required this.attestationChallenge,
  });

  Map<String, dynamic> toMap() => {
        'id': id,
        'token': token,
        'expiresAtEpochMs': expiresAt.millisecondsSinceEpoch,
        'attestationChallengeB64': base64Encode(attestationChallenge),
      };
}

/// Grant returned by consumer backend after successful enrollment.
class EnrollmentGrant {
  final String installationId;
  final String keyId;
  final String sessionId;
  final String hardwareStatus;
  final String attestationStatus;

  const EnrollmentGrant({
    required this.installationId,
    required this.keyId,
    required this.sessionId,
    required this.hardwareStatus,
    required this.attestationStatus,
  });

  bool get isHardware => hardwareStatus == 'hardware';

  factory EnrollmentGrant.fromMap(Map<dynamic, dynamic> map) {
    return EnrollmentGrant(
      installationId: map['installationId'] as String? ?? '',
      keyId: map['keyId'] as String? ?? '',
      sessionId: map['sessionId'] as String? ?? '',
      hardwareStatus: map['hardwareStatus'] as String? ?? 'unknown',
      attestationStatus: map['attestationStatus'] as String? ?? 'notEvaluated',
    );
  }

  Map<String, dynamic> toMap() => {
        'installationId': installationId,
        'keyId': keyId,
        'sessionId': sessionId,
        'hardwareStatus': hardwareStatus,
        'attestationStatus': attestationStatus,
      };
}

/// Signed RFC 9421 HTTP headers produced by the native SDK (lowercase names: `content-digest`, the profile
/// headers, `signature-input`, `signature`). There is no operation id or client epoch: neither is part of the
/// signed profile (SDK-NET-4 not implemented).
class SignedMessageHeaders {
  final Map<String, String> headers;

  const SignedMessageHeaders(this.headers);

  String? get signature => _get('signature');
  String? get signatureInput => _get('signature-input');
  String? get contentDigest => _get('content-digest');
  String? get sessionId => _get('x-sentomaru-session');

  String? _get(String name) {
    for (final entry in headers.entries) {
      if (entry.key.toLowerCase() == name) return entry.value;
    }
    return null;
  }

  Map<String, String> toMap() => Map.unmodifiable(headers);
}

/// Signal detection state (Decision E5).
enum SignalState {
  detected,
  notDetected,
  unknown,
  unsupported,
  error,
  stale;

  static SignalState fromString(String? value) {
    switch (value?.toLowerCase()) {
      case 'detected':
        return SignalState.detected;
      case 'not_detected':
        return SignalState.notDetected;
      case 'unknown':
        return SignalState.unknown;
      case 'unsupported':
        return SignalState.unsupported;
      case 'error':
        return SignalState.error;
      case 'stale':
        return SignalState.stale;
      default:
        return SignalState.unknown;
    }
  }

  /// D-05e: the state as the server reads it in the snapshot (`signals-observation-schema-v1.json`): `NOT_DETECTED`.
  String get wireName => switch (this) {
        SignalState.detected => 'DETECTED',
        SignalState.notDetected => 'NOT_DETECTED',
        SignalState.unknown => 'UNKNOWN',
        SignalState.unsupported => 'UNSUPPORTED',
        SignalState.error => 'ERROR',
        SignalState.stale => 'STALE',
      };
}

/// Local signal observation (Decision E5, SDK-SIG-1..6).
class SignalObservation {
  final String capabilityId;
  final String version;
  final SignalState state;
  final String source;
  final DateTime observedAt;
  final Map<String, dynamic> data;

  const SignalObservation({
    required this.capabilityId,
    required this.version,
    required this.state,
    required this.source,
    required this.observedAt,
    this.data = const {},
  });

  /// Parses a native observation. Required fields are never defaulted: a missing or unparseable `observedAt`
  /// must not become "now" (that would turn an unknown-age observation into a fresh one).
  factory SignalObservation.fromMap(Map<dynamic, dynamic> map) {
    String required(String key) {
      final value = map[key];
      if (value is! String || value.isEmpty) {
        throw FormatException('Signal observation without $key');
      }
      return value;
    }

    final rawObservedAt = map['observedAt'];
    final DateTime? observedAt = rawObservedAt is int
        ? DateTime.fromMillisecondsSinceEpoch(rawObservedAt, isUtc: true)
        : (rawObservedAt is String ? DateTime.tryParse(rawObservedAt) : null);
    if (observedAt == null) {
      throw const FormatException('Signal observation without a valid observedAt');
    }
    return SignalObservation(
      capabilityId: required('capabilityId'),
      version: required('version'),
      state: SignalState.fromString(map['state'] as String?),
      source: required('source'),
      observedAt: observedAt,
      data: map['data'] != null ? Map<String, dynamic>.from(map['data'] as Map) : {},
    );
  }
}

/// Evento de Risco (`RiskEvent`) lido do corpo de uma resposta desafiada ou bloqueada (chave `riskEvent`).
///
/// CONSULTIVO: o servidor Sentomaru não emite este objeto hoje; ele só existe se o backend consumidor o incluir.
/// [riskIndex] e [riskBand] são opcionais e nunca têm valor padrão: ausência significa "não informado", não
/// "sem risco". Não há veredito booleano de segurança.
class SentomaruRiskEvent {
  final String code;
  final int? riskIndex;
  final String? riskBand;
  final String reason;
  final String? challengeNonce;

  const SentomaruRiskEvent({
    required this.code,
    this.riskIndex,
    this.riskBand,
    required this.reason,
    this.challengeNonce,
  });

  factory SentomaruRiskEvent.fromMap(Map<String, dynamic> map) {
    return SentomaruRiskEvent(
      code: map['code'] as String? ?? 'UNKNOWN',
      riskIndex: (map['riskIndex'] as num?)?.toInt(),
      riskBand: map['riskBand'] as String?,
      reason: map['reason'] as String? ?? '',
      challengeNonce: map['challengeNonce'] as String?,
    );
  }

  Map<String, dynamic> toMap() => {
        'code': code,
        if (riskIndex != null) 'riskIndex': riskIndex,
        if (riskBand != null) 'riskBand': riskBand,
        'reason': reason,
        if (challengeNonce != null) 'challengeNonce': challengeNonce,
      };
}
