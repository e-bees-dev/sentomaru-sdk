// public entry. `Sentomaru` is the facade over the native module; tests use `createSentomaru` with a fake native.
import { NativeModules } from 'react-native';
import { createSentomaru } from './bridge.ts';
import type { NativeSentomaru } from './types.ts';

const native = NativeModules.Sentomaru as NativeSentomaru | undefined;

/** Fails closed at first use, not at import: an app that never calls the SDK is not broken by a missing native module. */
export const Sentomaru = createSentomaru({
  call: (method, args) => {
    if (!native) return Promise.reject({ code: 'NotInitialized', message: 'Sentomaru native module is not linked' });
    return native.call(method, args);
  },
});

export { createSentomaru } from './bridge.ts';
export * from './types.ts';
export * from './userMessage.ts';
