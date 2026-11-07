# Sentomaru for Capacitor

Typed JavaScript layer over the Android SDK, same molde as the React Native one (`sdk/react-native`). It adds no method,
default or retry: each function maps to one method of `contracts/sdk/hybrid-bridge-v1.json` and goes through the single
native entry `call({method, args})` of the plugin in `android/`, which resolves `{value}` (Capacitor resolves objects only).
Errors: `SentomaruError.code` carries the contract's stable code. `body` (sign) and the result of `sealedLoad` cross as Base64.

- Tests: `npm test` (Node 22+, contract parity, fake plugin; also checks `src/bridge.ts` equals the React Native one).
  Android: `android/` builds standalone like the RN module (see its `build.gradle.kts`); JVM tests cover the conversions.
- Not published to a public registry. Example app: `example/` (web side runs and bundles; the Android app was not built). No device run, no iOS.
