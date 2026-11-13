# @ebees/sentomaru-web

Browser side of the Sentomaru web channel: signs one HTTP request with a **non-extractable** WebCrypto P-256 key, in the strict profile of RFC 9421 that the server verifies
(`contracts/web/web-request-signature-v1.md`). It uses only the platform's `crypto.subtle`, no cookie, storage or identifier. The signal it enables is **advisory**:
code running in the page's own origin can also ask for a signature (stated limit, not solved).

```js
import { generateSessionKey, exportPublicKey, signRequest } from '@ebees/sentomaru-web';

const keyPair = await generateSessionKey();            // non-extractable; the caller decides where it lives (IndexedDB can store it)
const publicKey = await exportPublicKey(keyPair);       // SubjectPublicKeyInfo, base64: what the backend registers for the session
const headers = await signRequest({ keyPair, keyId, nonce, method: 'POST', url, body });   // Content-Digest, Signature-Input, Signature
```

## Distribution (decision D-W4, 12/11/2026)

Distributed as an **npm package** with the **SRI documented per version** in [`SRI.json`](SRI.json). The package ships one file, `dist/sentomaru-web-signer.mjs`, which is the
source copied byte for byte (no minifier, no transform), so what you audit is what runs. To pin it in a page that loads the file from your own origin:

```html
<script type="module" src="/vendor/sentomaru-web-signer.mjs" integrity="sha384-…"></script>
```

Take the value for your version from `SRI.json` (or compute it: `openssl dgst -sha384 -binary sentomaru-web-signer.mjs | openssl base64 -A`, prefixed with `sha384-`). An SRI
entry of a released version is never edited; a changed file is a new version. `npm run check:sri` fails when the file and the documented value disagree.

## Not done here

Nothing is published: releasing is a manual step the owner authorises. `publishConfig.provenance` asks npm for a provenance statement when that release is made from CI. The
package has not been used in a real browser; its tests run in Node, whose WebCrypto is the browser's interface.

## Message for the end user (0.2.0)

When your backend blocks an operation, show the user a fixed text that says some critical operations are blocked until approval, without code, reason or detection detail (`contracts/sdk/user-message-v1.md`). Languages: `pt-BR`, `en`, `es` (resolved from the tag; anything else is `en`). Override per language if you want your own wording; a blank override is ignored.

```js
import { userMessage } from '@ebees/sentomaru-web';
userMessage('verification_denied', { locale: navigator.language });                        // default text
userMessage('verification_denied', { locale: 'es', overrides: { es: 'Su texto.' } });        // your text
```

Situations: `attestation_failed`, `verification_denied`, `challenge`, `defer`, `unavailable`, `enrollment_pending` (another value gives `null`). The signer itself shows nothing to the user and its behaviour is unchanged.
