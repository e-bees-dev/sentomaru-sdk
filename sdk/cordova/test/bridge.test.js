// the Cordova facade against contracts/sdk/hybrid-bridge-v1.json and against the Capacitor facade (same native calls, same results).
'use strict';
const assert = require('node:assert/strict');
const { readFileSync } = require('node:fs');
const path = require('node:path');
const test = require('node:test');
const { createSentomaru, fromExec, SentomaruError } = require('../www/bridge.js');

const contract = JSON.parse(readFileSync(path.join(__dirname, '../../../contracts/sdk/hybrid-bridge-v1.json'), 'utf8'));

function fake(reply = null) {
  const calls = [];
  return { calls, sdk: createSentomaru({ call: async (method, args) => { calls.push({ method, args }); return reply; } }) };
}

const sample = {
  organization: 'org', app: 'app', environment: 'hml', enrollmentUrl: 'https://api.example.test/enroll', allowedHosts: ['api.example.test'],
  rotationGracePeriodDays: 3, playIntegrityCloudProjectNumber: 1, renewalUrl: 'https://api.example.test/renew',
  reattestationChallengeUrl: 'https://api.example.test/c', reattestationSubmitUrl: 'https://api.example.test/s',
  reattestationMinIntervalSeconds: 60, challenge: 'ch', strongBox: true, requiresHardware: false, method: 'POST',
  targetUri: 'https://api.example.test/x', operation: 'op', body: new Uint8Array([1, 2, 3]), optional: { a: 'b' }, rasp: true,
  expectedSignerDigests: ['a'.repeat(64)], allowPlainFallback: false, plainStringsKey: 'k', key: 'asset',
};

function invoke(sdk, name, args) {
  const a = Object.fromEntries(args.map((n) => [n, sample[n]]));
  switch (name) {
    case 'reattestIfDue': case 'reattest': return sdk[name](a.strongBox);
    case 'sealedLoad': case 'sealedString': return sdk[name](a.key);
    default: return sdk[name](a);
  }
}

test('the facade has exactly the methods of the contract', () => {
  assert.deepEqual(Object.keys(fake().sdk).sort(), contract.methods.map((m) => m.name).sort());
});

test('each method calls the native entry with its own name and exactly the contract arguments', async () => {
  for (const m of contract.methods) {
    const { calls, sdk } = fake(m.name === 'sealedLoad' ? 'AQID' : null);
    await invoke(sdk, m.name, m.args);
    assert.equal(calls.length, 1, m.name);
    assert.equal(calls[0].method, m.name);
    assert.deepEqual(Object.keys(calls[0].args).sort(), [...m.args].sort(), m.name);
  }
});

test('same native calls and results as the Capacitor facade, for every method', async () => {
  const { createSentomaru: capacitor } = await import('../../capacitor/src/bridge.ts');
  for (const m of contract.methods) {
    const record = async (make) => {
      const calls = [];
      const sdk = make({ call: async (method, args) => { calls.push({ method, args }); return m.name === 'sealedLoad' ? 'AP8Q' : 'r'; } });
      const result = await invoke(sdk, m.name, m.args);
      return { calls: JSON.parse(JSON.stringify(calls)), result: result instanceof Uint8Array ? [...result] : result };
    };
    assert.deepEqual(await record(createSentomaru), await record(capacitor), m.name);
  }
});

test('body goes as Base64 and sealedLoad comes back as bytes', async () => {
  const { calls, sdk } = fake();
  await sdk.sign({ method: 'GET', targetUri: 'https://api.example.test/x', operation: 'op', body: new Uint8Array([0, 255, 16]) });
  assert.equal(calls[0].args.body, 'AP8Q');
  assert.deepEqual([...(await createSentomaru({ call: async () => 'AP8Q' }).sealedLoad('k'))], [0, 255, 16]);
});

test('a rejection keeps the stable code; anything else is a ChannelError', async () => {
  const failing = (e) => createSentomaru({ call: async () => { throw e; } });
  await assert.rejects(failing({ code: 'NotInitialized', message: 'x' }).state(), (e) => e instanceof SentomaruError && e.code === 'NotInitialized');
  await assert.rejects(failing(new Error('boom')).state(), (e) => e instanceof SentomaruError && e.code === 'ChannelError');
});

test('the facade adds no default: an omitted option goes as undefined', async () => {
  const { calls, sdk } = fake();
  await sdk.enroll({ challenge: 'c' });
  assert.equal(calls[0].args.strongBox, undefined);
  assert.equal(calls[0].args.requiresHardware, undefined);
});

test('the Cordova exec entry sends [method, args] to Sentomaru/call and unwraps {value}', async () => {
  const seen = [];
  const exec = (ok, fail, service, action, args) => { seen.push({ service, action, args }); ok({ value: 'state-x' }); };
  assert.equal(await createSentomaru(fromExec(exec)).state(), 'state-x');
  assert.deepEqual(seen, [{ service: 'Sentomaru', action: 'call', args: ['state', {}] }]);
  assert.equal(await createSentomaru(fromExec((ok) => ok({}))).reenrollmentReason(), null);
  assert.equal(await createSentomaru(fromExec((ok) => ok(undefined))).reenrollmentReason(), null);
});

test('a Cordova failure {code, message} becomes SentomaruError with that code', async () => {
  const sdk = createSentomaru(fromExec((ok, fail) => fail({ code: 'NotInitialized', message: 'no' })));
  await assert.rejects(sdk.state(), (e) => e instanceof SentomaruError && e.code === 'NotInitialized' && e.message === 'no');
  const text = createSentomaru(fromExec((ok, fail) => fail('plain text')));
  await assert.rejects(text.state(), (e) => e instanceof SentomaruError && e.code === 'ChannelError');
});

test('plugin.xml registers the Android class that exists in the source tree', () => {
  const xml = readFileSync(path.join(__dirname, '../plugin.xml'), 'utf8');
  assert.match(xml, /value="br\.com\.ebees\.sentomaru\.cordova\.SentomaruPlugin"/);
  for (const f of ['SentomaruPlugin.kt', 'BridgeValues.kt']) {
    assert.ok(xml.includes(`kotlin/br/com/ebees/sentomaru/cordova/${f}`), f);
    readFileSync(path.join(__dirname, '../android/src/main/kotlin/br/com/ebees/sentomaru/cordova', f));
  }
});
