// public entry. `Sentomaru` is the facade over the native Capacitor plugin; tests use `createSentomaru` with a fake.
import { registerPlugin } from '@capacitor/core';
import { createSentomaru } from './bridge.ts';
import { type CapacitorSentomaruPlugin, fromPlugin } from './native.ts';

/** Fails closed at first use: on the web (no native plugin) Capacitor rejects with "not implemented" and the facade says ChannelError. */
export const Sentomaru = createSentomaru(fromPlugin(registerPlugin<CapacitorSentomaruPlugin>('Sentomaru')));

export { createSentomaru } from './bridge.ts';
export * from './types.ts';
