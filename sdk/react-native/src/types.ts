import { userMessageForCode, type MessageOverrides } from './userMessage.ts';

// types of the React Native layer. Names and arguments are those of contracts/sdk/hybrid-bridge-v1.json;
// nothing here is logic. Shapes of replies are the ones the shared Kotlin bridge (sdk/hybrid-core) returns.

export interface InitializeOptions {
  organization: string;
  app: string;
  environment: string;
  enrollmentUrl: string;
  allowedHosts: string[];
  rotationGracePeriodDays?: number;
  playIntegrityCloudProjectNumber?: number;
  renewalUrl?: string;
  reattestationChallengeUrl?: string;
  reattestationSubmitUrl?: string;
  reattestationMinIntervalSeconds?: number;
}

/**
 * The challenge the app's backend issued, exactly the shape the shared Kotlin/Swift bridge decodes
 * (`SentomaruBridge.parseChallenge`, `HybridBridge.enrollmentArguments`): a bare string here was never valid (D-W-port
 * fix - `EnrollOptions.challenge` used to be typed `string`, which a real native call would have refused as
 * malformed; nothing in this package exercised it against the real bridge before now).
 */
export interface EnrollmentChallenge {
  id: string;
  token: string;
  expiresAtEpochMs: number;
  attestationChallengeB64: string;
}

export interface EnrollOptions {
  challenge: EnrollmentChallenge;
  strongBox?: boolean;
  requiresHardware?: boolean;
}

export interface Grant {
  installationId: string;
  keyId: string;
  sessionId: string;
  hardwareStatus: string;
  attestationStatus: string;
}

export interface SignRequest {
  method: string;
  targetUri: string;
  operation: string;
  /** Request body bytes; crosses the bridge as Base64 (JavaScript has no byte array on it). */
  body?: Uint8Array;
  /** Extra signed headers; every key and value must be a string. */
  optional?: Record<string, string>;
}

/** The headers the app puts on its request. */
export type SignedHeaders = Record<string, string>;

export interface SignalObservation {
  capabilityId: string;
  version: string;
  state: string;
  source: string;
  observedAt: string;
  data?: Record<string, string>;
}

export interface SignalsSnapshot {
  collectedAt: string;
  durationMs: number;
  observations: SignalObservation[];
}

export interface SnapshotOptions {
  rasp?: boolean;
  expectedSignerDigests?: string[];
}

export type ReattestationOutcome =
  | { outcome: 'completed'; result: Record<string, unknown> }
  | { outcome: 'notNow'; reason: string; retryAfterMs: number }
  | { outcome: 'refused'; code: string; status: number };

export interface SealedOptions {
  allowPlainFallback?: boolean;
  plainStringsKey?: string;
}

/** An error of the SDK or of the bridge, with the stable `code` of hybrid-bridge-v1 (rejected promise `code`). */
export class SentomaruError extends Error {
  readonly code: string;
  constructor(code: string, message?: string) {
    super(message ?? code);
    this.name = 'SentomaruError';
    this.code = code;
  }

  /** sdk-user-message-v1: the end-user text for this code (null when the code is not a block); the code and `message` are unchanged. */
  userMessage(locale?: string | null, overrides?: MessageOverrides): string | null {
    return userMessageForCode(this.code, locale, overrides);
  }
}

/** The one native entry point (Kotlin `SentomaruModule.call`). */
export interface NativeSentomaru {
  call(method: string, args: Record<string, unknown>): Promise<unknown>;
}
