# Capacitor example

A web page (`index.html`, `main.ts`) whose button runs `flow.ts` on the real `Sentomaru` plugin object: initialize, state, enroll, sign, signals snapshot. Values are placeholders; the challenge comes from your server.

What runs here (no device): `npm install`, `npm run typecheck`, `npm test` (the flow through the real facade with a fake native, 2 tests), `npm run build` (Vite bundles the web assets into `dist/`).

What does NOT run here: `npx cap add android`, `npx cap sync`, the Gradle build of the app with `sdk/capacitor/android` and `sdk/hybrid-core` in it, an install on a device, a call to a server.
