// the facade for Cordova, the same as sdk/capacitor/src/bridge.ts and sdk/react-native/src/bridge.ts written as plain CommonJS
// (a Cordova js-module is not compiled). One function per method of contracts/sdk/hybrid-bridge-v1.json; each only shapes its
// arguments with the contract's names, passes them to the single native `call` and maps a rejection to SentomaruError. No default,
// no retry, no decision of its own. The only conversions are the ones JavaScript forces: `body` and `sealedLoad` bytes travel as Base64.
// test/bridge.test.js drives this file and the TypeScript one from the contract and requires the same native calls and the same results.
'use strict';

class SentomaruError extends Error {
  constructor(code, message) {
    super(message ?? code);
    this.name = 'SentomaruError';
    this.code = code;
  }
}

const toBase64 = (bytes) => {
  let binary = '';
  for (const b of bytes) binary += String.fromCharCode(b);
  return btoa(binary);
};
const fromBase64 = (text) => Uint8Array.from(atob(text), (c) => c.charCodeAt(0));

function createSentomaru(native) {
  async function call(method, args = {}) {
    try {
      return await native.call(method, args);
    } catch (e) {
      throw new SentomaruError(typeof e?.code === 'string' ? e.code : 'ChannelError', typeof e?.message === 'string' ? e.message : undefined);
    }
  }
  return {
    initialize: (o) => call('initialize', {
      organization: o.organization, app: o.app, environment: o.environment, enrollmentUrl: o.enrollmentUrl,
      allowedHosts: o.allowedHosts, rotationGracePeriodDays: o.rotationGracePeriodDays,
      playIntegrityCloudProjectNumber: o.playIntegrityCloudProjectNumber, renewalUrl: o.renewalUrl,
      reattestationChallengeUrl: o.reattestationChallengeUrl, reattestationSubmitUrl: o.reattestationSubmitUrl,
      reattestationMinIntervalSeconds: o.reattestationMinIntervalSeconds,
    }),
    state: () => call('state'),
    reenrollmentReason: () => call('reenrollmentReason'),
    enroll: (o) => call('enroll', { challenge: o.challenge, strongBox: o.strongBox, requiresHardware: o.requiresHardware }),
    rotate: (o) => call('rotate', { challenge: o.challenge, strongBox: o.strongBox, requiresHardware: o.requiresHardware }),
    sign: (r) => call('sign', {
      method: r.method, targetUri: r.targetUri, operation: r.operation,
      body: r.body === undefined ? undefined : toBase64(r.body), optional: r.optional,
    }),
    reset: () => call('reset'),
    collectSignals: () => call('collectSignals'),
    collectSignalsSnapshot: (o = {}) => call('collectSignalsSnapshot', { rasp: o.rasp, expectedSignerDigests: o.expectedSignerDigests }),
    sessionId: () => call('sessionId'),
    renewSession: () => call('renewSession'),
    reattestationDue: () => call('reattestationDue'),
    reattestIfDue: (strongBox) => call('reattestIfDue', { strongBox }),
    reattest: (strongBox) => call('reattest', { strongBox }),
    sealedConfigure: (o = {}) => call('sealedConfigure', { allowPlainFallback: o.allowPlainFallback, plainStringsKey: o.plainStringsKey }),
    sealedLoad: async (key) => fromBase64(await call('sealedLoad', { key })),
    sealedString: (key) => call('sealedString', { key }),
  };
}

/** The Cordova entry: `exec(success, failure, service, action, args)`. The native action `call` takes [method, args] and answers {value}. */
function fromExec(exec) {
  return {
    call: (method, args) => new Promise((resolve, reject) => {
      exec((reply) => resolve(reply?.value ?? null), (error) => reject(error), 'Sentomaru', 'call', [method, args]);
    }),
  };
}

module.exports = { createSentomaru, fromExec, SentomaruError };
