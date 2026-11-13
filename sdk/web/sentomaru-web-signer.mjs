// WS-W W-05, browser side (contracts/web/web-request-signature-v1.md). Signs one HTTP request with a NON-EXTRACTABLE WebCrypto P-256 key, in the strict
// profile of RFC 9421 the server verifies (WebRequestSignatureVerifier). It uses only the platform's `crypto.subtle`; no primitive of ours.
//
// Limit, stated and not "solved": the key cannot be exported, but any script running in this page's origin can call `sign` with it. A signature proves the key
// signed THIS request with the server's nonce, not that the page's own code asked for it. Nothing here is persisted: the caller decides where the CryptoKeyPair
// lives (IndexedDB can store a non-extractable key; this module does not touch any storage, cookie or identifier).

const COMPONENTS = '("@method" "@authority" "@path" "@query" "content-digest")';
const TOKEN = /^[A-Za-z0-9_.:-]{1,128}$/;

const toBase64 = bytes => btoa(String.fromCharCode(...bytes));

/** A new session key pair. `extractable: false` makes `exportKey` fail for the private key; the public key is exported by `exportPublicKey`. */
export async function generateSessionKey(subtle = globalThis.crypto.subtle) {
  return subtle.generateKey({ name: 'ECDSA', namedCurve: 'P-256' }, false, ['sign', 'verify']);
}

/** SubjectPublicKeyInfo (DER) of the public key, as base64: what the server stores at registration. */
export async function exportPublicKey(keyPair, subtle = globalThis.crypto.subtle) {
  return toBase64(new Uint8Array(await subtle.exportKey('spki', keyPair.publicKey)));
}

/**
 * Returns the three header values to send: `Content-Digest`, `Signature-Input` and `Signature`.
 * `url` is the absolute URL the browser will request; `nonce` is the one the server issued for this signature; `created` is seconds since the epoch.
 */
export async function signRequest({ keyPair, keyId, nonce, method, url, body = new Uint8Array(0), created = Math.floor(Date.now() / 1000), subtle = globalThis.crypto.subtle }) {
  if (!TOKEN.test(keyId) || !TOKEN.test(nonce)) throw new TypeError('keyId and nonce must match [A-Za-z0-9_.:-]{1,128}');
  if (!Number.isSafeInteger(created) || created < 0) throw new TypeError('created must be a non-negative integer');
  const bytes = typeof body === 'string' ? new TextEncoder().encode(body) : body;
  const parsed = new URL(url);
  const digest = `sha-256=:${toBase64(new Uint8Array(await subtle.digest('SHA-256', bytes)))}:`;
  const parameters = `${COMPONENTS};created=${created};keyid="${keyId}";nonce="${nonce}";alg="ecdsa-p256-sha256"`;
  const base = [
    `"@method": ${method.toUpperCase()}`,
    `"@authority": ${parsed.host}`,
    `"@path": ${parsed.pathname}`,
    `"@query": ?${parsed.search.startsWith('?') ? parsed.search.slice(1) : ''}`,
    `"content-digest": ${digest}`,
    `"@signature-params": ${parameters}`,
  ].join('\n');
  const signature = new Uint8Array(await subtle.sign({ name: 'ECDSA', hash: 'SHA-256' }, keyPair.privateKey, new TextEncoder().encode(base)));
  return { 'Content-Digest': digest, 'Signature-Input': `sen=${parameters}`, Signature: `sen=:${toBase64(signature)}:` };
}

// sdk-user-message-v1 (contracts/sdk/user-message-v1.md): the default text an end user reads when an operation is blocked. Fixed text, no code, reason or detection
// detail; the host may override it per language. It changes no signing behaviour.
export const BLOCKED_MESSAGE_KEY = 'critical_operations_blocked';
export const DEFAULT_MESSAGES = Object.freeze({
  'pt-BR': 'Algumas operações críticas estão bloqueadas até a aprovação. Tente novamente mais tarde ou fale com o suporte.',
  en: 'Some critical operations are blocked until approval. Please try again later or contact support.',
  es: 'Algunas operaciones críticas están bloqueadas hasta su aprobación. Inténtelo de nuevo más tarde o póngase en contacto con el soporte.',
});
export const SITUATIONS = Object.freeze(['attestation_failed', 'verification_denied', 'challenge', 'defer', 'unavailable', 'enrollment_pending']);

/** `pt*` is `pt-BR`, `es*` is `es`, anything else (or empty/absent) is `en`. */
export function resolveLocale(tag) {
  const primary = String(tag ?? '').trim().replace(/_/g, '-').toLowerCase().split('-')[0];
  return primary === 'pt' ? 'pt-BR' : primary === 'es' ? 'es' : 'en';
}

/**
 * The text for a blocked `situation` (one of SITUATIONS; any other value gives null). `locale` defaults to the browser language; `overrides` maps a resolved
 * language to the host's own text, used when it is not blank.
 */
export function userMessage(situation, { locale = globalThis.navigator?.language, overrides } = {}) {
  if (!SITUATIONS.includes(situation)) return null;
  const resolved = resolveLocale(locale);
  const own = overrides?.[resolved];
  return typeof own === 'string' && own.trim() !== '' ? own.trim() : DEFAULT_MESSAGES[resolved];
}
