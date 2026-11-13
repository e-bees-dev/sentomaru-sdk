import test from 'node:test';
import assert from 'node:assert/strict';
import { execFileSync } from 'node:child_process';
import { readFileSync } from 'node:fs';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { integrity, matches } from './sri.mjs';

const root = join(dirname(fileURLToPath(import.meta.url)), '..');

test('integrity matches published known answers', () => {
  // SHA-256, SHA-384 and SHA-512 of the empty input and of "abc" (FIPS 180-4 examples), base64.
  assert.equal(integrity(new Uint8Array(0), 'sha256'), 'sha256-47DEQpj8HBSa+/TImW+5JCeuQeRkm5NMpJWZG3hSuFU=');
  assert.equal(integrity(Buffer.from('abc'), 'sha256'), 'sha256-ungWv48Bz+pBQUDeXa4iI7ADYaOWF3qctBD/YfIAFa0=');
  assert.equal(integrity(Buffer.from('abc'), 'sha384'), 'sha384-ywB1P0WjXou1oD1pmsZQBycsMqsO3tFjGotgWkP/W+2AhgcroefMI1i67KE0yCWn');
  assert.equal(integrity(Buffer.from('abc'), 'sha512').slice(0, 14), 'sha512-3a81oZN');
});

test('an unknown algorithm is refused and a list of hashes matches when any one fits', () => {
  assert.throws(() => integrity(Buffer.from('x'), 'md5'), TypeError);
  const bytes = Buffer.from('abc');
  assert.ok(matches(bytes, `sha256-AAAA ${integrity(bytes, 'sha384')}`));
  assert.ok(!matches(bytes, 'sha384-AAAA md5-AAAA'));
  assert.ok(!matches(bytes, ''));
});

test('the build is byte for byte, deterministic, and its SRI is the one documented for this version', () => {
  const run = () => execFileSync('node', [join(root, 'scripts', 'build.mjs'), '--check'], { encoding: 'utf8' });
  const first = run();
  assert.match(first, /SRI documented for this version matches the build\./);
  assert.equal(run(), first);
  assert.deepEqual(readFileSync(join(root, 'dist', 'sentomaru-web-signer.mjs')), readFileSync(join(root, 'sentomaru-web-signer.mjs')));
});

test('every documented version has a well formed sha384 value and the current version is documented', () => {
  const registry = JSON.parse(readFileSync(join(root, 'SRI.json'), 'utf8'));
  const version = JSON.parse(readFileSync(join(root, 'package.json'), 'utf8')).version;
  assert.ok(registry.versions[version], 'the current version has an SRI entry');
  for (const files of Object.values(registry.versions))
    for (const value of Object.values(files)) assert.match(value, /^sha384-[A-Za-z0-9+/]{64}$/);
});
