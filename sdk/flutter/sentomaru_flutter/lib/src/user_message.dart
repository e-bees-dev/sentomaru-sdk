/// `sdk-user-message-v1` (contracts/sdk/user-message-v1.md): the default text an app shows its end user when an operation is
/// blocked. One stable key, three languages, no interpolation: the text never carries a code, a reason or a detection detail.
/// The error codes of this SDK are unchanged; this only adds the presentable message. The host can override the text per language.
library;

/// The closed set of situations a blocking code maps to (all show the same text today).
enum SentomaruBlockSituation { attestationFailed, verificationDenied, challenge, defer, unavailable, enrollmentPending }

class SentomaruUserMessage {
  const SentomaruUserMessage._();

  /// Stable key of the default text.
  static const String key = 'critical_operations_blocked';

  /// Default text by resolved language (`pt-BR`, `en`, `es`).
  static const Map<String, String> defaults = {
    'pt-BR': 'Algumas operações críticas estão bloqueadas até a aprovação. Tente novamente mais tarde ou fale com o suporte.',
    'en': 'Some critical operations are blocked until approval. Please try again later or contact support.',
    'es': 'Algunas operaciones críticas están bloqueadas hasta su aprobación. Inténtelo de nuevo más tarde o póngase en contacto con el soporte.',
  };

  /// `pt*` is `pt-BR`, `es*` is `es`, anything else, blank or null is `en`. `_` reads as `-`; case is ignored.
  static String resolveLocale(String? tag) {
    final primary = (tag ?? '').trim().replaceAll('_', '-').toLowerCase().split('-').first;
    switch (primary) {
      case 'pt':
        return 'pt-BR';
      case 'es':
        return 'es';
      default:
        return 'en';
    }
  }

  /// The text for [locale]. A non-blank host text in [overrides] under the resolved language replaces the default;
  /// a blank one, or one for another language, is ignored.
  static String resolve({String? locale, Map<String, String>? overrides}) {
    final resolved = resolveLocale(locale);
    final own = overrides?[resolved]?.trim();
    return (own != null && own.isNotEmpty) ? own : defaults[resolved]!;
  }

  /// The situation a stable error code (`ServerRejected:REVOKED`, `NetworkUnavailable`, ...) presents; null = not a block, the app decides.
  static SentomaruBlockSituation? situationFor(String? code) {
    switch (code) {
      case 'KeyInvalidated':
      case 'KeyUnavailable':
      case 'StorageUnavailable':
      case 'StrongBoxUnavailable':
      case 'Unsupported:APP_ATTEST':
      case 'Unsupported:SECURE_ENCLAVE':
      case 'ServerRejected:INVALID':
        return SentomaruBlockSituation.attestationFailed;
      case 'ServerRejected:REVOKED':
      case 'ServerRejected:SUSPENDED':
      case 'ServerRejected:CONFLICT':
      case 'ServerRejected:EXPIRED':
      case 'ReenrollmentRefused':
        return SentomaruBlockSituation.verificationDenied;
      case 'NetworkUnavailable':
      case 'ServerRejected:UNAVAILABLE':
      case 'ServerRejected:RATE_LIMITED':
      case 'RenewalBackoff':
      case 'PinningRefused':
        return SentomaruBlockSituation.unavailable;
      case 'NotEnrolled':
      case 'EnrollmentRequired':
      case 'ChallengeExpired':
        return SentomaruBlockSituation.enrollmentPending;
      default:
        return null;
    }
  }

  /// The text for a blocking [code], or null when the code is not a block.
  static String? forCode(String? code, {String? locale, Map<String, String>? overrides}) =>
      situationFor(code) == null ? null : resolve(locale: locale, overrides: overrides);
}
