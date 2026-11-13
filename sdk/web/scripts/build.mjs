// Builds dist/ and checks the documented SRI of this version (decision D-W4: the package is distributed on npm with the SRI documented per version).
//
//   node scripts/build.mjs           copies the source to dist/ byte for byte (nothing is minified or transformed: what the consumer audits is what runs) and prints the SRI
//   node scripts/build.mjs --check   also fails when SRI.json has no entry for this version or its hash differs from the built file
//
// A new release changes `version` in package.json and adds that version to SRI.json in the same commit; an entry of a past version is never edited. Publishing is a manual,
// owner-authorised step and is NOT done here.
import { readFileSync, writeFileSync, mkdirSync } from 'node:fs';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { integrity } from './sri.mjs';

const root = join(dirname(fileURLToPath(import.meta.url)), '..');
const FILE = 'sentomaru-web-signer.mjs';
const check = process.argv.includes('--check');

const version = JSON.parse(readFileSync(join(root, 'package.json'), 'utf8')).version;
const bytes = readFileSync(join(root, FILE));
mkdirSync(join(root, 'dist'), { recursive: true });
writeFileSync(join(root, 'dist', FILE), bytes);
const built = readFileSync(join(root, 'dist', FILE));
const value = integrity(built, 'sha384');
console.log(`${FILE} ${version} ${value}`);

if (check) {
  const registry = JSON.parse(readFileSync(join(root, 'SRI.json'), 'utf8'));
  const documented = registry.versions?.[version]?.[FILE];
  if (!documented) { console.error(`SRI.json has no entry for ${FILE} in version ${version}: add it (and bump the version if the file changed).`); process.exit(1); }
  if (documented !== value) { console.error(`SRI.json says ${documented} for ${version}, the build gives ${value}: the file changed without a new version.`); process.exit(1); }
  console.log('SRI documented for this version matches the build.');
}
