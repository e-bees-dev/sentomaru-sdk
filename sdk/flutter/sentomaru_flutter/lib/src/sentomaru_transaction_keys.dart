import 'dart:convert';
import 'dart:io' show HttpDate;

import 'package:dio/dio.dart';
import 'package:flutter/foundation.dart';

import 'sentomaru_transaction.dart';

/// D-25: why a call of [SentomaruTransactionKeys] to the integrator's backend failed.
///
/// [statusCode] is the HTTP status the backend answered, or null when no answer came (network, or the
/// `SentomaruDioInterceptor` refused to send the request: then [cause] holds the original error). [code] is the stable
/// `code` of the answer body (`challenge-invalid`, `user-auth-not-proven`, `transaction-key-format`, `rate-limited`,
/// `sentomaru-unavailable`, ...; contract `transaction-keys-v1`, section 3), `unexpected-response` when the answer carried
/// none or was not the documented one, and `transport` when there was no answer. [reason] is the closed vocabulary of
/// `422 user-auth-not-proven` (`attestation_not_hardware`, `auth_type_mismatch`, `platform_mismatch`, ...). [retryAfter]
/// comes from the `Retry-After` header (on `429`, and on `503` when the backend sends it): the plugin never retries by
/// itself; the app waits at least that long before a new attempt.
class SentomaruTransactionKeyException implements Exception {
  const SentomaruTransactionKeyException({
    required this.statusCode,
    required this.code,
    this.reason,
    this.retryAfter,
    this.cause,
  });

  final int? statusCode;
  final String code;
  final String? reason;
  final Duration? retryAfter;
  final Object? cause;

  /// The upper bound of [retryAfter] (24 h, the largest value the server emits), as in the Android SDK.
  static const Duration maxRetryAfter = Duration(hours: 24);

  /// Parses a `Retry-After` value: delay in seconds or an HTTP-date (RFC 9110, section 10.2.3). The result is clamped
  /// to 1 s..24 h. Null when the header is absent, unparseable, negative, or a date that already passed.
  static Duration? parseRetryAfter(String? value, {DateTime? now}) {
    if (value == null) return null;
    final text = value.trim();
    if (text.isEmpty) return null;
    Duration? delay;
    final seconds = int.tryParse(text);
    if (seconds != null) {
      if (seconds < 0) return null;
      delay = Duration(seconds: seconds);
    } else {
      try {
        delay = HttpDate.parse(text).difference(now ?? DateTime.now());
      } on Object {
        return null;
      }
      if (delay.isNegative) return null;
    }
    if (delay < const Duration(seconds: 1)) return const Duration(seconds: 1);
    return delay > maxRetryAfter ? maxRetryAfter : delay;
  }

  @override
  String toString() => 'SentomaruTransactionKeyException($statusCode, $code'
      '${reason == null ? '' : ', reason: $reason'}${retryAfter == null ? '' : ', retryAfter: $retryAfter'})';
}

/// D-25: answer of `POST transaction-keys/status` as the backend forwards it.
class SentomaruTransactionKeyStatus {
  const SentomaruTransactionKeyStatus({
    required this.enrolled,
    this.txKeyId,
    this.userAuthentication,
    this.enrolledAt,
    required this.signatureVersions,
    required this.signatureVersionsDeclared,
  });

  final bool enrolled;
  final String? txKeyId;

  /// `biometric-strong`, `biometric-or-credential` or `advisory-ios`.
  final String? userAuthentication;

  /// ISO 8601 with offset, as the server sends it.
  final String? enrolledAt;

  /// The header formats the server accepts. When the server omitted the field ([signatureVersionsDeclared] false) it is a
  /// server older than the v2 format and this is `['v1']` (contract, section 2a).
  final List<String> signatureVersions;
  final bool signatureVersionsDeclared;

  /// Whether the server accepts the v2 header, the only format this plugin emits. When false, do not ask the person
  /// to sign: the server would refuse the header (`401 tx-signature-invalid`); the server must be updated first.
  bool get acceptsPluginSignatures => signatureVersions.contains('v2');

  factory SentomaruTransactionKeyStatus.fromJson(Map<String, Object?> json) {
    final versions = json['signatureVersions'];
    final declared = versions is List;
    return SentomaruTransactionKeyStatus(
      enrolled: json['enrolled'] == true,
      txKeyId: json['txKeyId'] as String?,
      userAuthentication: json['userAuthentication'] as String?,
      enrolledAt: json['enrolledAt'] as String?,
      signatureVersions: declared ? List.unmodifiable(versions.whereType<String>()) : const ['v1'],
      signatureVersionsDeclared: declared,
    );
  }
}

/// D-25: answer `201` of `POST transaction-keys` as the backend forwards it.
class SentomaruTransactionKeyEnrollment {
  const SentomaruTransactionKeyEnrollment({
    required this.txKeyId,
    required this.userAuthentication,
    required this.attestationStatus,
    required this.enrolledAt,
  });

  final String txKeyId;

  /// `biometric-strong`, `biometric-or-credential` or `advisory-ios`.
  final String userAuthentication;

  /// `verified` on Android; `unattested` on iOS (advisory evidence, never proof of presence).
  final String attestationStatus;

  /// ISO 8601 with offset, as the server sends it.
  final String enrolledAt;

  factory SentomaruTransactionKeyEnrollment.fromJson(Map<String, Object?> json) => SentomaruTransactionKeyEnrollment(
        txKeyId: json['txKeyId'] as String,
        userAuthentication: json['userAuthentication'] as String,
        attestationStatus: json['attestationStatus'] as String,
        enrolledAt: json['enrolledAt'] as String,
      );
}

/// D-25: enrolls, reads and revokes the transaction key through the INTEGRATOR's backend, which forwards each app-signed
/// request to Sentomaru (contract `transaction-keys-v1`, section 1; the ASP.NET Core adapter has base actions for it in
/// `SentomaruEnrollmentControllerBase`). The app never talks to Sentomaru directly.
///
/// [dio] must already have the Sentomaru interceptor (`dio.addSentomaru(client)`) and a `baseUrl` on an allowed host:
/// every call here is a `POST` whose operation (`tx_key_challenge`, `tx_key_enroll`, `tx_key_status`, `tx_key_revoke`)
/// goes in `extra['sentomaru_operation']`, so the interceptor signs it with the installation key. The paths are those
/// of the backend, not of Sentomaru.
///
/// Errors are [SentomaruTransactionKeyException] (HTTP) or [SentomaruTransactionException] (the native key: cancelled,
/// no biometric, ...). Nothing is retried by itself.
class SentomaruTransactionKeys {
  SentomaruTransactionKeys({
    required this.dio,
    this.signer = const SentomaruTransactionSigner(),
    this.challengePath = defaultChallengePath,
    this.enrollPath = defaultEnrollPath,
    this.statusPath = defaultStatusPath,
    this.revocationsPath = defaultRevocationsPath,
  });

  static const String defaultChallengePath = '/api/v1/integridade/transaction-keys/challenges';
  static const String defaultEnrollPath = '/api/v1/integridade/transaction-keys';
  static const String defaultStatusPath = '/api/v1/integridade/transaction-keys/status';
  static const String defaultRevocationsPath = '/api/v1/integridade/transaction-keys/revocations';

  final Dio dio;
  final SentomaruTransactionSigner signer;
  final String challengePath;
  final String enrollPath;
  final String statusPath;
  final String revocationsPath;

  /// The transaction key the server holds for this installation, and which header formats it accepts. Check
  /// [SentomaruTransactionKeyStatus.acceptsPluginSignatures] before asking the person to sign.
  Future<SentomaruTransactionKeyStatus> status() async {
    final response = await _post(statusPath, 'tx_key_status', expected: const {200});
    return SentomaruTransactionKeyStatus.fromJson(_json(response));
  }

  /// Challenge, new staged key, `POST transaction-keys`; the staged key replaces the one that signs only after the
  /// server answered `201`. Any failure after the key was staged drops it ([SentomaruTransactionSigner.abortKey]) and
  /// rethrows, so the app keeps the key it had.
  ///
  /// Android: the key is attested against the challenge and the native side builds the body; [biometricOnly] true
  /// declares `biometric-strong` (strong biometric on every use), false declares `biometric-or-credential` (the device
  /// credential is also accepted, from API 30). [strongBox] asks for StrongBox and fails with `unavailable` when the
  /// device has none. Sign later with the same [biometricOnly].
  ///
  /// iOS: the body is `{"challenge", "publicKey", "userAuthentication": "advisory-ios"}`, without `attestationChain`.
  /// The server records the key as advisory evidence (`attestationStatus: unattested`) that never satisfies a presence
  /// requirement. [biometricOnly] chooses whether the Secure Enclave key also accepts the passcode; [strongBox] is ignored.
  Future<SentomaruTransactionKeyEnrollment> enroll({bool biometricOnly = false, bool strongBox = false}) async {
    final challenge = await _challenge();
    final Uint8List body;
    if (defaultTargetPlatform == TargetPlatform.android) {
      body = await signer.createKey(biometricOnly: biometricOnly, challenge: challenge, strongBox: strongBox);
    } else {
      final spki = await signer.createKey(biometricOnly: biometricOnly);
      body = iosEnrollmentBody(challengeToken: challenge.token, publicKey: spki);
    }
    try {
      final response = await _post(enrollPath, 'tx_key_enroll', body: body, expected: const {201});
      final enrollment = SentomaruTransactionKeyEnrollment.fromJson(_json(response));
      await signer.commitKey();
      return enrollment;
    } catch (_) {
      try {
        await signer.abortKey();
      } on Object {
        // The original failure is what the app acts on; a failed abort leaves a staged key the next createKey replaces.
      }
      rethrow;
    }
  }

  /// `POST transaction-keys/revocations` (`204`, also when there was no key), then deletes the local key.
  Future<void> revoke() async {
    await _post(revocationsPath, 'tx_key_revoke', expected: const {200, 204});
    await signer.discard();
  }

  /// The iOS body of `POST transaction-keys` (contract, section "iOS"): strict JSON, standard Base64, no `attestationChain`.
  @visibleForTesting
  static Uint8List iosEnrollmentBody({required String challengeToken, required Uint8List publicKey}) =>
      Uint8List.fromList(utf8.encode(jsonEncode({
        'challenge': challengeToken,
        'publicKey': base64.encode(publicKey),
        'userAuthentication': 'advisory-ios',
      })));

  /// Asks the person to sign [body] for [operationId] and returns the entries to merge into `Options.extra` of the
  /// business request (`sentomaru_tx_signature`, `sentomaru_operation_id`); add `sentomaru_operation` yourself.
  ///
  /// - [body] must be exactly the bytes Dio sends. Send the request with `data: body` (these same pre-encoded bytes):
  ///   the interceptor sends a `Uint8List` as is, while a `Map` is re-encoded and any difference breaks the signature.
  /// - Keep the same [operationId] on every retry of one business operation, but call this again for each retry: a
  ///   signature is single-use (the server refuses a repeated nonce with `409 tx-nonce-replay`) and expires in 5 minutes
  ///   (`401 tx-signature-stale`).
  /// - [biometricOnly] (Android) must match the class of the enrolled key.
  Future<Map<String, Object>> signedExtra({
    required String operationId,
    required Uint8List body,
    String? reason,
    bool biometricOnly = false,
    String? cancelLabel,
  }) async {
    final value = await signer.sign(
      operationId: operationId,
      body: body,
      reason: reason,
      biometricOnly: biometricOnly,
      cancelLabel: cancelLabel,
    );
    return {'sentomaru_tx_signature': value, 'sentomaru_operation_id': operationId};
  }

  Future<SentomaruTransactionChallenge> _challenge() async {
    final json = _json(await _post(challengePath, 'tx_key_challenge', expected: const {200, 201}));
    try {
      return SentomaruTransactionChallenge(
        challengeId: json['challengeId'] as String,
        token: json['token'] as String,
        attestationChallenge: base64.decode(json['attestationChallenge'] as String),
        expiresAt: json['expiresAt'] as String,
      );
    } on Object catch (e) {
      throw SentomaruTransactionKeyException(statusCode: null, code: 'unexpected-response', cause: e);
    }
  }

  Future<Response<Object?>> _post(String path, String operation, {Uint8List? body, required Set<int> expected}) async {
    final Response<Object?> response;
    try {
      response = await dio.post<Object?>(
        path,
        data: body ?? Uint8List(0),
        options: Options(extra: {'sentomaru_operation': operation}),
      );
    } on DioException catch (e) {
      final answer = e.response;
      if (answer == null) {
        throw SentomaruTransactionKeyException(statusCode: null, code: 'transport', cause: e.error ?? e);
      }
      throw _fromResponse(answer, e);
    }
    final status = response.statusCode;
    if (status == null || !expected.contains(status)) throw _fromResponse(response, null);
    return response;
  }

  static SentomaruTransactionKeyException _fromResponse(Response<Object?> response, Object? cause) {
    Map<String, Object?>? json;
    try {
      json = _json(response);
    } on Object {
      json = null;
    }
    final code = json?['code'];
    // The server and the .NET adapter send the 422 reason in `attestationReason`; `reason` is accepted for other backends.
    final reason = json?['attestationReason'] ?? json?['reason'];
    return SentomaruTransactionKeyException(
      statusCode: response.statusCode,
      code: code is String && code.isNotEmpty ? code : 'unexpected-response',
      reason: reason is String ? reason : null,
      retryAfter: SentomaruTransactionKeyException.parseRetryAfter(response.headers.value('retry-after')),
      cause: cause,
    );
  }

  static Map<String, Object?> _json(Response<Object?> response) {
    final data = response.data;
    final Object? decoded = switch (data) {
      Map() => data,
      String() => jsonDecode(data),
      List<int>() => jsonDecode(utf8.decode(data)),
      _ => null,
    };
    if (decoded is Map) return decoded.cast<String, Object?>();
    throw SentomaruTransactionKeyException(statusCode: response.statusCode, code: 'unexpected-response');
  }
}
