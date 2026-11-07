# Sentomaru for Cordova

Plain-JavaScript layer (a Cordova js-module is not compiled) over the Android SDK, same molde as the React Native and Capacitor
ones. It adds no method, default or retry: each function maps to one method of `contracts/sdk/hybrid-bridge-v1.json` and goes
through the single native action `call` with `[method, args]` of the plugin in `android/`, which answers `{value}`.
Errors: `SentomaruError.code` carries the contract's stable code (native failure is `{code, message}`). `body` (sign) and the result
of `sealedLoad` cross as Base64. The native class shares `sdk/hybrid-core` with the other híbridos.

- Tests: `npm test` (Node 22+; contract parity, fake `exec`, and a test that this facade and `sdk/capacitor/src/bridge.ts` make the
  same native calls and return the same results for every contract method).
- Not published, not installed in any Cordova app, Kotlin compiled and `BridgeValuesTest` (5) green, but never run inside a Cordova app.
- Example app: `example/` (the flow is tested against the facade with a fake native; no Cordova CLI run, no Android build).
