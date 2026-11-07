import 'package:flutter/foundation.dart';
import 'package:flutter/services.dart';

import 'sentomaru_flutter_platform_interface.dart';

/// D-25: why a transaction signature could not be made. [cancelled] is recoverable: nothing was spent and a new attempt
/// may follow. [unsupported]: this platform has no transaction key in the plugin (iOS and Android only).
enum SentomaruTransactionError {
  notEnrolled,
  keyInvalidated,
  cancelled,
  lockedOut,
  noUserAuthentication,
  unavailable,
  signingFailed,
  unsupported,
  invalidRequest,
  notInitialized,
  channelError,
}

/// D-25 (Android): the server challenge of `POST challenges` (contract `transaction-keys-v1`), as the consumer route returns it.
/// The Android key is attested by the platform against [attestationChallenge]; iOS does not use it.
class SentomaruTransactionChallenge {
  const SentomaruTransactionChallenge({
    required this.challengeId,
    required this.token,
    required this.attestationChallenge,
    required this.expiresAt,
  });
  final String challengeId;
  final String token;
  final Uint8List attestationChallenge;

  /// ISO 8601 with offset, as the server sends it.
  final String expiresAt;

  Map<String, Object?> toMap() => {
        'challengeId': challengeId,
        'token': token,
        'attestationChallenge': attestationChallenge,
        'expiresAt': expiresAt,
      };
}

class SentomaruTransactionException implements Exception {
  const SentomaruTransactionException(this.error);
  final SentomaruTransactionError error;

  @override
  String toString() => 'SentomaruTransactionException($error)';
}

/// D-25 (iOS and Android): signs one operation at a time with a Secure Enclave key whose every use asks the person (biometrics or the
/// device passcode). The value goes in the `x-sentomaru-tx-signature` header, or in `options.extra['sentomaru_tx_signature']`
/// for the `SentomaruDioInterceptor`, together with the `x-sentomaru-operation-id` of the same request.
///
/// Secure Enclave userPresence protege a chave no aparelho, mas a Apple não atesta o controle de acesso; o servidor não
/// consegue provar presença. On the server an iOS key is advisory evidence only: it never satisfies a presence requirement.
/// On Android the key is a hardware-attested Keystore key whose every use shows `BiometricPrompt` (strong biometric by default),
/// and the server can prove presence. The prompt needs the host activity to be a `FlutterFragmentActivity`; with any other
/// activity, no enrolled biometric or no sensor the call fails with a typed error and never signs.
/// Needs `SentomaruClient.initialize` and an enrolled installation (the key lives under `<installation alias>.tx`).
class SentomaruTransactionSigner {
  const SentomaruTransactionSigner();

  static const _codes = <String, SentomaruTransactionError>{
    'Transaction:NOT_ENROLLED': SentomaruTransactionError.notEnrolled,
    'Transaction:KEY_INVALIDATED': SentomaruTransactionError.keyInvalidated,
    'Transaction:CANCELLED': SentomaruTransactionError.cancelled,
    'Transaction:LOCKED_OUT': SentomaruTransactionError.lockedOut,
    'Transaction:NO_USER_AUTHENTICATION': SentomaruTransactionError.noUserAuthentication,
    'Transaction:UNAVAILABLE': SentomaruTransactionError.unavailable,
    'Transaction:SIGNING_FAILED': SentomaruTransactionError.signingFailed,
    'NotInitialized': SentomaruTransactionError.notInitialized,
  };

  static const _voidMethods = {'txDiscard', 'txKeyCommit', 'txKeyAbort'};

  static bool get _supported =>
      !kIsWeb && (defaultTargetPlatform == TargetPlatform.iOS || defaultTargetPlatform == TargetPlatform.android);
  static bool get _android => defaultTargetPlatform == TargetPlatform.android;

  Future<T> _call<T>(String method, [Map<String, Object?>? arguments]) async {
    if (!_supported) throw const SentomaruTransactionException(SentomaruTransactionError.unsupported);
    try {
      final result = await SentomaruFlutterPlatform.instance.invokeTransaction<T>(method, arguments);
      if (result == null && !_voidMethods.contains(method)) {
        throw const SentomaruTransactionException(SentomaruTransactionError.channelError);
      }
      return result as T;
    } on PlatformException catch (e) {
      final known = _codes[e.code];
      if (known != null) throw SentomaruTransactionException(known);
      if (e.code.startsWith('InvalidRequest')) throw const SentomaruTransactionException(SentomaruTransactionError.invalidRequest);
      throw const SentomaruTransactionException(SentomaruTransactionError.channelError);
    }
  }

  /// Whether the transaction key exists.
  Future<bool> isEnrolled() => _call<bool>('txIsEnrolled');

  /// Creates a NEW key under a provisional label; the key that signs is not touched, so a failed enrollment leaves the app with
  /// the key it had. Call [commitKey] after the server answered `201`, or [abortKey] if it did not. [biometricOnly] (default)
  /// refuses the passcode fallback.
  ///
  /// iOS returns the public key (SPKI DER). Android needs [challenge] (the key is attested against it) and returns the
  /// body of `POST transaction-keys` (public key, attestation chain and the declared class), ready to send with the
  /// signed request. [strongBox] asks for StrongBox on Android and fails with `unavailable` if the device has none.
  Future<Uint8List> createKey({bool biometricOnly = true, SentomaruTransactionChallenge? challenge, bool strongBox = false}) =>
      _call<Uint8List>('txKeyCreate', {
        'biometricOnly': biometricOnly,
        if (_android && challenge != null) 'challenge': challenge.toMap(),
        if (_android && strongBox) 'strongBox': true,
      });

  /// The server accepted the key from [createKey]: it replaces the old one. [SentomaruTransactionError.notEnrolled] if no key is staged.
  Future<void> commitKey() => _call<void>('txKeyCommit');

  /// The server did not accept the key from [createKey]: drops it and keeps the signing key.
  Future<void> abortKey() => _call<void>('txKeyAbort');

  /// Asks the person and returns the value of `x-sentomaru-tx-signature` for [operationId] and the exact request [body].
  /// The value is the v2 format (`sentomaru-tx-v2`, signed clock: the server accepts it only within 5 minutes of its own
  /// time), so the device clock must be right; a clock before 2001 is `Transaction:SIGNING_FAILED`. The plugin has no v1 option.
  /// Android only: [biometricOnly] must match the class of the enrolled key (a key made with `biometricOnly: false` allows
  /// the device credential from API 30), and [cancelLabel] is the text of the prompt's negative button.
  Future<String> sign({
    required String operationId,
    required Uint8List body,
    String? reason,
    bool biometricOnly = true,
    String? cancelLabel,
  }) =>
      _call<String>('txSign', {
        'operationId': operationId,
        'body': body,
        'reason': ?reason,
        if (_android) 'biometricOnly': biometricOnly,
        if (_android) 'cancelLabel': ?cancelLabel,
      });

  /// Deletes the key (after revoking it on the server).
  Future<void> discard() => _call<void>('txDiscard');
}
