# Sentomaru for React Native

Typed JavaScript layer over the Android SDK. It adds no method, default or retry: each function maps to one method of
`contracts/sdk/hybrid-bridge-v1.json` and goes through the single native entry `call(method, args)` of the module in
`android/`. Fachada: `src/bridge.ts`; TurboModule spec: `src/NativeSentomaru.ts`; errors: `SentomaruError.code` carries the
contract's stable code.

- `body` (sign) and the result of `sealedLoad` cross the bridge as Base64; the facade converts, you pass `Uint8Array`.
- Tests: `npm test` (Node 22+, parity with the contract, fake native). Types: `npm run typecheck` (needs `typescript`).
- `example/App.tsx` is a sketch. It was not built or run.
- Not published to a public registry. iOS is not covered by this package.

