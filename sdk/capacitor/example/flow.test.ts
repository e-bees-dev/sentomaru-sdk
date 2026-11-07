// the flow of main.ts through the REAL facade (createSentomaru) with a fake native. It proves the example's calls match
// hybrid-bridge-v1 and that a native failure is shown by its stable code; it does not prove the plugin, the device or the server.
import assert from 'node:assert/strict';
import test from 'node:test';
import { createSentomaru } from '../src/bridge.ts';
import { SentomaruError } from '../src/types.ts';
import { runFlow } from './flow.ts';

const replies: Record<string, unknown> = {
  state: 'Enrolled',
  enroll: { installationId: 'inst-1', keyId: 'k', sessionId: 's', hardwareStatus: 'Hardware', attestationStatus: 'Verified' },
  sign: { 'x-sentomaru-installation': 'inst-1', signature: 'sig' },
  collectSignalsSnapshot: { collectedAt: '2026-11-06T00:00:00Z', durationMs: 12, observations: [{}, {}] },
};

test('the flow calls the five methods in order, with Base64 body, and prints what came back', async () => {
  const calls: { method: string; args: Record<string, unknown> }[] = [];
  const sdk = createSentomaru({ call: async (method, args) => { calls.push({ method, args }); return replies[method] ?? null; } });
  const log: string[] = [];
  await runFlow(sdk, (l) => log.push(l));
  assert.deepEqual(calls.map((c) => c.method), ['initialize', 'state', 'enroll', 'sign', 'collectSignalsSnapshot']);
  assert.equal(calls[3].args.body, Buffer.from('{"amount":1}').toString('base64'));
  assert.deepEqual(log, ['state: Enrolled', 'enrolled: inst-1', 'signed headers: x-sentomaru-installation, signature', 'signals: 2 observations in 12 ms']);
});

test('a native failure is shown by its stable code and stops the flow', async () => {
  const sdk = createSentomaru({ call: async (method) => { if (method === 'enroll') throw { code: 'ChallengeRejected', message: 'x' }; return replies[method] ?? null; } });
  const log: string[] = [];
  await runFlow(sdk, (l) => log.push(l));
  assert.deepEqual(log, ['state: Enrolled', 'error ChallengeRejected']);
  assert.ok(new SentomaruError('X') instanceof Error);
});
