// the typed facade. One function per method of hybrid-bridge-v1; each only shapes its arguments with the contract's
// names, passes them to the single native `call` and maps a rejection to SentomaruError. No default, no retry, no
// decision of its own (the contract: "a hybrid layer adds no method, no default and no retry"). The only conversions are
// the ones JavaScript forces: `body` and `sealedLoad` bytes travel as Base64.
import {
  type EnrollOptions, type Grant, type InitializeOptions, type NativeSentomaru, type ReattestationOutcome,
  type SealedOptions, type SignalObservation, type SignalsSnapshot, type SignedHeaders, type SignRequest,
  type SnapshotOptions, SentomaruError,
} from './types.ts';

const toBase64 = (bytes: Uint8Array): string => {
  let binary = '';
  for (const b of bytes) binary += String.fromCharCode(b);
  return btoa(binary);
};
const fromBase64 = (text: string): Uint8Array => Uint8Array.from(atob(text), (c) => c.charCodeAt(0));

export function createSentomaru(native: NativeSentomaru) {
  async function call<T>(method: string, args: Record<string, unknown> = {}): Promise<T> {
    try {
      return (await native.call(method, args)) as T;
    } catch (e) {
      const err = e as { code?: unknown; message?: unknown };
      throw new SentomaruError(typeof err.code === 'string' ? err.code : 'ChannelError', typeof err.message === 'string' ? err.message : undefined);
    }
  }
  return {
    initialize: (o: InitializeOptions) => call<void>('initialize', {
      organization: o.organization, app: o.app, environment: o.environment, enrollmentUrl: o.enrollmentUrl,
      allowedHosts: o.allowedHosts, rotationGracePeriodDays: o.rotationGracePeriodDays,
      playIntegrityCloudProjectNumber: o.playIntegrityCloudProjectNumber, renewalUrl: o.renewalUrl,
      reattestationChallengeUrl: o.reattestationChallengeUrl, reattestationSubmitUrl: o.reattestationSubmitUrl,
      reattestationMinIntervalSeconds: o.reattestationMinIntervalSeconds,
    }),
    state: () => call<string>('state'),
    reenrollmentReason: () => call<string | null>('reenrollmentReason'),
    enroll: (o: EnrollOptions) => call<Grant>('enroll', { challenge: o.challenge, strongBox: o.strongBox, requiresHardware: o.requiresHardware }),
    rotate: (o: EnrollOptions) => call<Grant>('rotate', { challenge: o.challenge, strongBox: o.strongBox, requiresHardware: o.requiresHardware }),
    sign: (r: SignRequest) => call<SignedHeaders>('sign', {
      method: r.method, targetUri: r.targetUri, operation: r.operation,
      body: r.body === undefined ? undefined : toBase64(r.body), optional: r.optional,
    }),
    reset: () => call<void>('reset'),
    collectSignals: () => call<SignalObservation[]>('collectSignals'),
    collectSignalsSnapshot: (o: SnapshotOptions = {}) => call<SignalsSnapshot>('collectSignalsSnapshot', {
      rasp: o.rasp, expectedSignerDigests: o.expectedSignerDigests,
    }),
    sessionId: () => call<string | null>('sessionId'),
    renewSession: () => call<string>('renewSession'),
    reattestationDue: () => call<boolean>('reattestationDue'),
    reattestIfDue: (strongBox?: boolean) => call<ReattestationOutcome>('reattestIfDue', { strongBox }),
    reattest: (strongBox?: boolean) => call<ReattestationOutcome>('reattest', { strongBox }),
    sealedConfigure: (o: SealedOptions = {}) => call<void>('sealedConfigure', {
      allowPlainFallback: o.allowPlainFallback, plainStringsKey: o.plainStringsKey,
    }),
    sealedLoad: async (key: string) => fromBase64(await call<string>('sealedLoad', { key })),
    sealedString: (key: string) => call<string>('sealedString', { key }),
  };
}

export type Sentomaru = ReturnType<typeof createSentomaru>;
export { SentomaruError };
