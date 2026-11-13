// Subresource Integrity values for the files this package ships (W3C SRI: `sha384-<base64>`; SHA-256 and SHA-512 are also valid algorithms). Plain functions so the build and the test share them.
import { createHash } from 'node:crypto';

export const ALGORITHMS = ['sha256', 'sha384', 'sha512'];

/** `sha384-<base64 digest>` of the bytes, the value of an `integrity` attribute. */
export function integrity(bytes, algorithm = 'sha384') {
  if (!ALGORITHMS.includes(algorithm)) throw new TypeError('SRI algorithm must be sha256, sha384 or sha512');
  return `${algorithm}-${createHash(algorithm).update(bytes).digest('base64')}`;
}

/** True when `value` (an integrity attribute with one or more space separated hashes) lists a hash of `bytes`. */
export function matches(bytes, value) {
  return String(value).split(/\s+/).filter(Boolean).some(token => {
    const dash = token.indexOf('-');
    return dash > 0 && ALGORITHMS.includes(token.slice(0, dash)) && integrity(bytes, token.slice(0, dash)) === token;
  });
}
