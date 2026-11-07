// parity of the facade with contracts/sdk/hybrid-bridge-v1.json, and the few conversions it makes.
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import test from 'node:test';
import { createSentomaru } from '../src/bridge.ts';
import { SentomaruError, type NativeSentomaru } from '../src/types.ts';

const contract = JSON.parse(readFileSync(new URL('../../../contracts/sdk/hybrid-bridge-v1.json', import.meta.url), 'utf8'));

type Call = { method: string; args: Record<string, unknown> };
function fake(reply: unknown = null) {
  const calls: Call[] = [];
  const native: NativeSentomaru = { call: async (method, args) => { calls.push({ method, args }); return reply; } };
  return { calls, sdk: createSentomaru(native) };
}

// A value for every argument name, so each facade function can be driven from the contract alone.
const sample: Record<string, unknown> = {
  organization: 'org', app: 'app', environment: 'hml', enrollmentUrl: 'https://api.example.test/enroll', allowedHosts: ['api.example.test'],
  rotationGracePeriodDays: 3, playIntegrityCloudProjectNumber: 1, renewalUrl: 'https://api.example.test/renew',
  reattestationChallengeUrl: 'https://api.example.test/c', reattestationSubmitUrl: 'https://api.example.test/s',
  reattestationMinIntervalSeconds: 60, challenge: 'ch', strongBox: true, requiresHardware: false, method: 'POST',
  targetUri: 'https://api.example.test/x', operation: 'op', body: new Uint8Array([1, 2, 3]), optional: { a: 'b' }, rasp: true,
  expectedSignerDigests: ['a'.repeat(64)], allowPlainFallback: false, plainStringsKey: 'k', key: 'asset',
};

function invoke(sdk: ReturnType<typeof createSentomaru>, name: string, args: string[]) {
  const a = Object.fromEntries(args.map((n) => [n, sample[n]]));
  switch (name) {
    case 'initialize': return sdk.initialize(a as never);
    case 'enroll': return sdk.enroll(a as never);
    case 'rotate': return sdk.rotate(a as never);
    case 'sign': return sdk.sign(a as never);
    case 'collectSignalsSnapshot': return sdk.collectSignalsSnapshot(a as never);
    case 'reattestIfDue': return sdk.reattestIfDue(a.strongBox as boolean);
    case 'reattest': return sdk.reattest(a.strongBox as boolean);
    case 'sealedConfigure': return sdk.sealedConfigure(a as never);
    case 'sealedLoad': return sdk.sealedLoad(a.key as string);
    case 'sealedString': return sdk.sealedString(a.key as string);
    default: return (sdk as unknown as Record<string, () => Promise<unknown>>)[name]!();
  }
}

test('the facade has exactly the methods of the contract', () => {
  const { sdk } = fake();
  assert.deepEqual(Object.keys(sdk).sort(), contract.methods.map((m: { name: string }) => m.name).sort());
});

test('each method calls the native entry with its own name and exactly the contract arguments', async () => {
  for (const m of contract.methods as { name: string; args: string[] }[]) {
    const { calls, sdk } = fake(m.name === 'sealedLoad' ? 'AQID' : null);
    await invoke(sdk, m.name, m.args);
    assert.equal(calls.length, 1, m.name);
    assert.equal(calls[0]!.method, m.name);
    assert.deepEqual(Object.keys(calls[0]!.args).sort(), [...m.args].sort(), m.name);
  }
});

test('body goes as Base64 and sealedLoad comes back as bytes', async () => {
  const { calls, sdk } = fake();
  await sdk.sign({ method: 'GET', targetUri: 'https://api.example.test/x', operation: 'op', body: new Uint8Array([0, 255, 16]) });
  assert.equal(calls[0]!.args.body, 'AP8Q');
  const loaded = createSentomaru({ call: async () => 'AP8Q' });
  assert.deepEqual([...(await loaded.sealedLoad('k'))], [0, 255, 16]);
});

test('a rejection keeps the stable code; anything else is a ChannelError', async () => {
  const failing = (e: unknown) => createSentomaru({ call: async () => { throw e; } });
  await assert.rejects(failing({ code: 'NotInitialized', message: 'x' }).state(), (e: unknown) => e instanceof SentomaruError && e.code === 'NotInitialized');
  await assert.rejects(failing(new Error('boom')).state(), (e: unknown) => e instanceof SentomaruError && e.code === 'ChannelError');
});

test('the facade adds no default: an omitted option goes as undefined', async () => {
  const { calls, sdk } = fake();
  await sdk.enroll({ challenge: 'c' });
  assert.equal(calls[0]!.args.strongBox, undefined);
  assert.equal(calls[0]!.args.requiresHardware, undefined);
});
