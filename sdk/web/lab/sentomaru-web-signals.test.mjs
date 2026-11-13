import assert from 'node:assert/strict';
import { test } from 'node:test';
import { readFileSync } from 'node:fs';
import { collectSignals, AUTOMATION_GLOBALS, SCHEMA, COLLECTOR_VERSION } from './sentomaru-web-signals.mjs';

const vectors = JSON.parse(readFileSync(new URL('../../../contracts/web/web-bot-signals-vectors-v1.json', import.meta.url), 'utf8'));
const NAVIGATOR_READS = new Set(['webdriver', 'userAgent', 'platform', 'languages', 'maxTouchPoints']);
const SCOPE_READS = new Set(['navigator', 'outerWidth', 'outerHeight']);

/** A simulated global scope from a vector's `env`. Records every property read and presence check; any write, definition or deletion fails the test. */
function simulate(env, log = { reads: [], has: [] }) {
  const value = (name, v) => { if (v === '__throws__') throw new Error('unreadable'); return v; };
  const strict = { set() { throw new Error('write attempted'); }, defineProperty() { throw new Error('define attempted'); }, deleteProperty() { throw new Error('delete attempted'); } };
  const navigator = env.navigator === '__absent__' ? undefined : new Proxy({}, {
    ...strict,
    get: (_t, name) => { log.reads.push(`navigator.${String(name)}`); return value(name, env[name]); },
  });
  const scope = new Proxy({}, {
    ...strict,
    get: (_t, name) => {
      log.reads.push(String(name));
      if (name === 'navigator') return navigator;
      return value(name, env[name]);
    },
    has: (_t, name) => {
      log.has.push(String(name));
      if (env.globals === '__throws__') throw new Error('unreadable');
      return env.globals.includes(name);
    },
  });
  return scope;
}

test('the collector is off unless enabled is exactly true, and then it reads nothing at all', () => {
  const trap = new Proxy({}, { get() { throw new Error('read while off'); }, has() { throw new Error('check while off'); } });
  for (const options of [undefined, {}, { enabled: false }, { enabled: 'true' }, { enabled: 1 }, { scope: trap }, { enabled: false, scope: trap }, { enabled: 'yes', scope: trap }]) {
    assert.equal(collectSignals(options), null);
  }
});

test('every collector vector returns exactly the expected object', () => {
  for (const { name, env, expected } of vectors.collector) {
    assert.deepEqual(collectSignals({ enabled: true, scope: simulate(env) }), expected, name);
  }
});

test('the result has exactly the members of sentomaru-web-signals/1, in order, and every value is a boolean or null', () => {
  const result = collectSignals({ enabled: true, scope: simulate(vectors.collector[0].env) });
  assert.deepEqual(Object.keys(result), ['schema', 'collector', 'signals']);
  assert.equal(result.schema, SCHEMA);
  assert.equal(result.collector, COLLECTOR_VERSION);
  assert.match(result.collector, /^\d+\.\d+\.\d+$/);
  assert.deepEqual(Object.keys(result.signals), ['s1', 's2', 's3', 's4']);
  for (const value of Object.values(result.signals)) assert.ok(value === null || typeof value === 'boolean');
  assert.ok(JSON.stringify(result).length < 200);
});

test('a condition that cannot be read is null and never false', () => {
  const unreadable = '__throws__';
  const allThrow = { userAgent: unreadable, platform: unreadable, languages: unreadable, maxTouchPoints: unreadable, webdriver: unreadable, outerWidth: unreadable, outerHeight: unreadable, globals: unreadable };
  assert.deepEqual(collectSignals({ enabled: true, scope: simulate(allThrow) }).signals, { s1: null, s2: null, s3: null, s4: null });
  // A null scope, and a scope that is not an object (an omitted scope means the page's own global object).
  for (const scope of [null, 5, 'x']) {
    const { signals } = collectSignals({ enabled: true, scope });
    assert.deepEqual(signals, { s1: null, s2: null, s3: null, s4: null }, String(scope));
  }
  // One unreadable value never turns another signal's null into false: S4 needs the agent string.
  const noAgent = collectSignals({ enabled: true, scope: simulate({ ...vectors.collector[0].env, userAgent: unreadable }) }).signals;
  assert.equal(noAgent.s4, null);
});

test('a hostile global scope cannot make the collector throw', () => {
  const hostile = new Proxy({}, { get() { throw new Error('boom'); }, has() { throw new Error('boom'); } });
  assert.deepEqual(collectSignals({ enabled: true, scope: hostile }).signals, { s1: null, s2: null, s3: null, s4: null });
});

test('it reads only the listed properties, checks only the listed global names, and writes nothing', () => {
  for (const { name, env } of vectors.collector) {
    const log = { reads: [], has: [] };
    collectSignals({ enabled: true, scope: simulate(env, log) });
    for (const read of log.reads) {
      const allowed = read.startsWith('navigator.') ? NAVIGATOR_READS.has(read.slice('navigator.'.length)) : SCOPE_READS.has(read);
      assert.ok(allowed, `${name}: read of ${read}`);
    }
    for (const checked of log.has) assert.ok(AUTOMATION_GLOBALS.includes(checked), `${name}: presence check of ${checked}`);
  }
});

// What the file text must never contain: storage, network, timers, dynamic code, element creation, console, and the identification surfaces W-19 leaves out on purpose.
const FORBIDDEN = [
  'localStorage', 'sessionStorage', 'indexedDB', 'document', 'cookie', 'fetch', 'XMLHttpRequest', 'sendBeacon', 'WebSocket', 'EventSource', 'postMessage',
  'eval', 'Function', 'debugger', 'console', 'import(', 'importScripts', 'setTimeout', 'setInterval', 'requestAnimationFrame', 'performance', 'Date',
  'canvas', 'getContext', 'AudioContext', 'OfflineAudioContext', 'createElement', 'getBattery', 'geolocation', 'mediaDevices', 'getVoices', 'fonts', 'plugins',
  'mimeTypes', 'screen', 'WebGL', 'RTCPeerConnection', 'Notification', 'permissions', 'hardwareConcurrency', 'deviceMemory', 'serviceWorker', 'Worker',
];

const pattern = token => new RegExp(token.endsWith('(') ? token.replace('(', '\\(') : `\\b${token}\\b`);

test('the file text references none of the forbidden APIs (storage, network, timers, dynamic code, fingerprint surfaces)', () => {
  const source = readFileSync(new URL('./sentomaru-web-signals.mjs', import.meta.url), 'utf8');
  // Comments say what the file does not do, so they are not code: strip them before scanning.
  const code = source.replace(/\/\*[\s\S]*?\*\//g, '').replace(/^\s*\/\/.*$/gm, '').replace(/([^:\\])\/\/.*$/gm, '$1');
  const found = FORBIDDEN.filter(token => pattern(token).test(code));
  assert.deepEqual(found, []);
  // Only the one import-free module shape: no import or export-from of another file.
  assert.equal(/^\s*import\s/m.test(code), false);
  assert.equal(/export\s+\*?\s*from/.test(code), false);
});

test('the scan itself catches a forbidden token (the test is not vacuous)', () => {
  const sample = "const a = localStorage.getItem('x'); fetch('/y'); eval('1'); debugger;";
  const found = FORBIDDEN.filter(token => pattern(token).test(sample));
  assert.deepEqual(found.sort(), ['debugger', 'eval', 'fetch', 'localStorage']);
});

test('the file is not part of the npm package and has no integrity entry (laboratory only)', () => {
  const pack = JSON.parse(readFileSync(new URL('../package.json', import.meta.url), 'utf8'));
  assert.equal(pack.files.some(f => f.includes('signals') || f.includes('lab')), false);
  assert.equal(JSON.stringify(pack.exports).includes('signals'), false);
  assert.equal(readFileSync(new URL('../SRI.json', import.meta.url), 'utf8').includes('signals'), false);
});
