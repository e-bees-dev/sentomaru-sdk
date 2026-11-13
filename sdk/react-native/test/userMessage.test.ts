// sdk-user-message-v1: the shared vector locks the default text, the language resolution, the override and the code map.
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import test from 'node:test';
import { DEFAULT_MESSAGES, SITUATIONS, BLOCKED_MESSAGE_KEY, resolveLocale, userMessage, situationForCode, userMessageForCode, type Situation } from '../src/userMessage.ts';
import { SentomaruError } from '../src/types.ts';

const vectors = JSON.parse(readFileSync(new URL('../../../contracts/sdk/user-message-vectors-v1.json', import.meta.url), 'utf8'));

test('the default texts, key and situations are the shared ones and carry no internal detail', () => {
  assert.equal(BLOCKED_MESSAGE_KEY, vectors.key);
  assert.deepEqual({ ...DEFAULT_MESSAGES }, vectors.texts);
  assert.deepEqual([...SITUATIONS], vectors.situations);
  for (const text of Object.values(DEFAULT_MESSAGES)) for (const word of vectors.forbiddenInText) assert.ok(!text.toLowerCase().includes(word.toLowerCase()), `${word} in ${text}`);
});

test('language resolution follows the vector', () => {
  for (const { tag, locale } of vectors.localeResolution) assert.equal(resolveLocale(tag), locale, String(tag));
});

test('the host override and the fallback follow the vector', () => {
  for (const c of vectors.overrides) for (const s of vectors.situations) assert.equal(userMessage(s as Situation, c.locale, c.overrides ?? undefined), c.expected, c.name);
  assert.equal(userMessage('cancelled' as Situation, 'en'), null);
});

test('every stable code maps to the situation of the vector and a non-block code gives null', () => {
  for (const [code, situation] of Object.entries(vectors.mobileCodes.map as Record<string, string | null>)) {
    assert.equal(situationForCode(code), situation, code);
    assert.equal(userMessageForCode(code, 'es'), situation ? vectors.texts.es : null, code);
  }
  assert.equal(situationForCode(undefined), null);
});

test('SentomaruError keeps its code and message and only adds the end-user text', () => {
  const e = new SentomaruError('ServerRejected:SUSPENDED', 'detail for logs');
  assert.equal(e.code, 'ServerRejected:SUSPENDED');
  assert.equal(e.message, 'detail for logs');
  assert.equal(e.userMessage('pt-BR'), vectors.texts['pt-BR']);
  assert.equal(e.userMessage('en', { en: 'Mine.' }), 'Mine.');
  assert.ok(!e.userMessage('en')!.includes('SUSPENDED'));
  assert.equal(new SentomaruError('Cancelled').userMessage('en'), null);
});
