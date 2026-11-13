import assert from 'node:assert/strict';
import { test } from 'node:test';
import { readFileSync } from 'node:fs';
import { exportPublicKey, generateSessionKey, signRequest, userMessage, resolveLocale, DEFAULT_MESSAGES, SITUATIONS, BLOCKED_MESSAGE_KEY } from './sentomaru-web-signer.mjs';

// Node's `crypto.subtle` is the same WebCrypto interface the browser has.
const subtle = globalThis.crypto.subtle;
const unsigned = value => value.slice(value.indexOf('=') + 1);

test('the private key cannot be exported', async () => {
  const pair = await generateSessionKey();
  await assert.rejects(() => subtle.exportKey('pkcs8', pair.privateKey));
  assert.equal(pair.privateKey.extractable, false);
  assert.ok((await exportPublicKey(pair)).length > 80);
});

test('the headers have the exact shape of the profile and the signature verifies over the RFC 9421 base', async () => {
  const pair = await generateSessionKey();
  const headers = await signRequest({ keyPair: pair, keyId: 'k1', nonce: 'n0nce-1', method: 'post', url: 'https://shop.example.test/v1/pay?a=1', body: '{"amount":10}', created: 1_800_000_000 });
  assert.equal(headers['Signature-Input'], 'sen=("@method" "@authority" "@path" "@query" "content-digest");created=1800000000;keyid="k1";nonce="n0nce-1";alg="ecdsa-p256-sha256"');
  assert.match(headers['Content-Digest'], /^sha-256=:[A-Za-z0-9+/]{43}=:$/);
  assert.match(headers.Signature, /^sen=:[A-Za-z0-9+/]{86}==:$/);
  const base = `"@method": POST\n"@authority": shop.example.test\n"@path": /v1/pay\n"@query": ?a=1\n"content-digest": ${headers['Content-Digest']}\n"@signature-params": ${unsigned(headers['Signature-Input'])}`;
  const raw = Uint8Array.from(atob(unsigned(headers.Signature).slice(1, -1)), c => c.charCodeAt(0));
  assert.equal(raw.length, 64);
  assert.equal(await subtle.verify({ name: 'ECDSA', hash: 'SHA-256' }, pair.publicKey, raw, new TextEncoder().encode(base)), true);
});

test('no query signs an empty query, and the digest is the one of the independent vectors', async () => {
  const pair = await generateSessionKey();
  const headers = await signRequest({ keyPair: pair, keyId: 'k1', nonce: 'n', method: 'GET', url: 'https://a.example.test/p', created: 1 });
  assert.equal(headers['Content-Digest'], 'sha-256=:47DEQpj8HBSa+/TImW+5JCeuQeRkm5NMpJWZG3hSuFU=:'); // SHA-256 of the empty body
});

test('a keyId or nonce outside the profile is refused before signing', async () => {
  const pair = await generateSessionKey();
  await assert.rejects(() => signRequest({ keyPair: pair, keyId: 'a"b', nonce: 'n', method: 'GET', url: 'https://a.example.test/' }), TypeError);
  await assert.rejects(() => signRequest({ keyPair: pair, keyId: 'k', nonce: '', method: 'GET', url: 'https://a.example.test/' }), TypeError);
  await assert.rejects(() => signRequest({ keyPair: pair, keyId: 'k', nonce: 'n', method: 'GET', url: 'https://a.example.test/', created: -1 }), TypeError);
});

// sdk-user-message-v1: the shared vector locks the default text, the language resolution and the override.
const vectors = JSON.parse(readFileSync(new URL('../../contracts/sdk/user-message-vectors-v1.json', import.meta.url), 'utf8'));

test('the default texts, key and situations are the shared ones', () => {
  assert.equal(BLOCKED_MESSAGE_KEY, vectors.key);
  assert.deepEqual({ ...DEFAULT_MESSAGES }, vectors.texts);
  assert.deepEqual([...SITUATIONS], vectors.situations);
  for (const text of Object.values(DEFAULT_MESSAGES)) for (const word of vectors.forbiddenInText) assert.ok(!text.toLowerCase().includes(word.toLowerCase()), `${word} in ${text}`);
});

test('language resolution follows the vector', () => {
  for (const { tag, locale } of vectors.localeResolution) assert.equal(resolveLocale(tag), locale, String(tag));
});

test('the host override and the fallback follow the vector, for every situation', () => {
  for (const c of vectors.overrides) for (const situation of vectors.situations) assert.equal(userMessage(situation, { locale: c.locale, overrides: c.overrides ?? undefined }), c.expected, c.name);
  assert.equal(userMessage('cancelled', { locale: 'en' }), null);
  assert.equal(userMessage('defer', { locale: 'pt-BR' }), vectors.texts['pt-BR']);
});
