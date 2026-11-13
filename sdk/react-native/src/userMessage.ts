// sdk-user-message-v1 (contracts/sdk/user-message-v1.md): the default text an end user reads when an operation is blocked, the language resolution, the host
// override and the map from the stable bridge `code` to a situation. Fixed text: no code, reason or detection detail. It changes no code and no behaviour.

export const BLOCKED_MESSAGE_KEY = 'critical_operations_blocked';

export type MessageLocale = 'pt-BR' | 'en' | 'es';

export const DEFAULT_MESSAGES: Readonly<Record<MessageLocale, string>> = Object.freeze({
  'pt-BR': 'Algumas operações críticas estão bloqueadas até a aprovação. Tente novamente mais tarde ou fale com o suporte.',
  en: 'Some critical operations are blocked until approval. Please try again later or contact support.',
  es: 'Algunas operaciones críticas están bloqueadas hasta su aprobación. Inténtelo de nuevo más tarde o póngase en contacto con el soporte.',
});

export const SITUATIONS = ['attestation_failed', 'verification_denied', 'challenge', 'defer', 'unavailable', 'enrollment_pending'] as const;
export type Situation = (typeof SITUATIONS)[number];

/** Host wording per resolved language; a blank text is ignored. */
export type MessageOverrides = Partial<Record<MessageLocale, string>>;

/** `pt*` is `pt-BR`, `es*` is `es`, anything else (or empty/absent) is `en`. */
export function resolveLocale(tag?: string | null): MessageLocale {
  const primary = (tag ?? '').trim().replace(/_/g, '-').toLowerCase().split('-')[0];
  return primary === 'pt' ? 'pt-BR' : primary === 'es' ? 'es' : 'en';
}

/** The text for a blocked `situation`; `overrides` replaces the default of its language when not blank. */
export function userMessage(situation: Situation, locale?: string | null, overrides?: MessageOverrides): string | null {
  if (!(SITUATIONS as readonly string[]).includes(situation)) return null;
  const resolved = resolveLocale(locale);
  const own = overrides?.[resolved];
  return typeof own === 'string' && own.trim() !== '' ? own.trim() : DEFAULT_MESSAGES[resolved];
}

const BY_CODE: Readonly<Record<string, Situation>> = Object.freeze({
  KeyInvalidated: 'attestation_failed', KeyUnavailable: 'attestation_failed', StorageUnavailable: 'attestation_failed', StrongBoxUnavailable: 'attestation_failed',
  'Unsupported:APP_ATTEST': 'attestation_failed', 'Unsupported:SECURE_ENCLAVE': 'attestation_failed', 'ServerRejected:INVALID': 'attestation_failed',
  'ServerRejected:REVOKED': 'verification_denied', 'ServerRejected:SUSPENDED': 'verification_denied', 'ServerRejected:CONFLICT': 'verification_denied',
  'ServerRejected:EXPIRED': 'verification_denied', ReenrollmentRefused: 'verification_denied',
  NetworkUnavailable: 'unavailable', 'ServerRejected:UNAVAILABLE': 'unavailable', 'ServerRejected:RATE_LIMITED': 'unavailable', RenewalBackoff: 'unavailable', PinningRefused: 'unavailable',
  NotEnrolled: 'enrollment_pending', EnrollmentRequired: 'enrollment_pending', ChallengeExpired: 'enrollment_pending',
});

/** The situation a stable SDK `code` presents, or null when it is not a block (cancelled, not initialized, bad configuration or request, unknown): the app decides. */
export function situationForCode(code: string | null | undefined): Situation | null {
  return (code && BY_CODE[code]) || null;
}

/** The text for a stable SDK `code`, or null when the code is not a block. */
export function userMessageForCode(code: string | null | undefined, locale?: string | null, overrides?: MessageOverrides): string | null {
  const situation = situationForCode(code);
  return situation ? userMessage(situation, locale, overrides) : null;
}
