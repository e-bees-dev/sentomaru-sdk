// the flow of www/js/flow.js through the REAL Cordova facade with a fake native. It proves the example's calls match
// hybrid-bridge-v1 and that a native failure is shown by its stable code; it does not prove the plugin, the device or the server.
'use strict';
const assert = require('node:assert/strict');
const test = require('node:test');
const { createSentomaru } = require('../../www/bridge.js');
const { runFlow } = require('../www/js/flow.js');

const replies = {
  state: 'Enrolled',
  enroll: { installationId: 'inst-1', keyId: 'k', sessionId: 's', hardwareStatus: 'Hardware', attestationStatus: 'Verified' },
  sign: { 'x-sentomaru-installation': 'inst-1', signature: 'sig' },
  collectSignalsSnapshot: { collectedAt: '2026-11-06T00:00:00Z', durationMs: 12, observations: [{}, {}] },
};

test('the flow calls the five methods in order, with Base64 body, and prints what came back', async () => {
  const calls = [];
  const sdk = createSentomaru({ call: async (method, args) => { calls.push({ method, args }); return replies[method] ?? null; } });
  const log = [];
  await runFlow(sdk, (l) => log.push(l));
  assert.deepEqual(calls.map((c) => c.method), ['initialize', 'state', 'enroll', 'sign', 'collectSignalsSnapshot']);
  assert.equal(calls[3].args.body, Buffer.from('{"amount":1}').toString('base64'));
  assert.deepEqual(log, ['state: Enrolled', 'enrolled: inst-1', 'signed headers: x-sentomaru-installation, signature', 'signals: 2 observations in 12 ms']);
});

test('a native failure is shown by its stable code and stops the flow', async () => {
  const sdk = createSentomaru({ call: async (method) => { if (method === 'enroll') throw { code: 'ChallengeRejected', message: 'x' }; return replies[method] ?? null; } });
  const log = [];
  await runFlow(sdk, (l) => log.push(l));
  assert.deepEqual(log, ['state: Enrolled', 'error ChallengeRejected']);
});
