// High-level, portable "ensure this device is correctly enrolled" contract (D-W-port, 11/11/2026): decides on its
// own whether to reuse the current installation, rotate it after an app update (D-04b, Android only - see below)
// or reenroll from scratch, so no app has to reimplement this logic. Ported from `sentomaru_service.dart`/
// `sentomaru_app_update.dart` of a first consumer app through the Android (`EnrollmentAssurance`) and Flutter
// (`SentomaruEnrollmentAssurance`) ports, adapted to this package's own layering: it is built entirely on top of
// `createSentomaru`'s existing facade (`state`, `reenrollmentReason`, `enroll`, `rotate`, `reset`, `sessionId`) -
// the bridge itself (`bridge.ts`, `sdk/hybrid-core`, `sdk/ios-hybrid-core`) is untouched, same as this package's own
// rule that "a hybrid layer adds no method, no default and no retry": the decision lives here, one level up.
//
// No platform check needed: this package's README says iOS is not covered yet (`ios-bridge/` exists but is not
// wired into codegen), but `reenrollmentReason` already answers `null` on the shared iOS bridge itself
// (`ios-hybrid-core`'s own doc comment: "no iOS equivalent: an App Attest attestation names no app version") and
// on an installation from before D-04b, so the rotation branch below will simply never trigger there or then,
// once iOS is wired up, with no change needed here.
import type { Sentomaru } from './bridge.ts';
import type { EnrollmentChallenge } from './types.ts';

/** Asks the app's backend for a fresh, single-use enrollment challenge for `subject`/`tenant`. Called for the
 * first enrollment, for a key rotation (D-04b, Android) and, when the server refuses that rotation, for the
 * reenrollment that follows - every time a new call, never cached or reused by `EnrollmentAssurance` itself. */
export type ChallengeProvider = (subject: string, tenant: string) => Promise<EnrollmentChallenge>;

/** Why `EnrollmentAssurance` just enrolled or reenrolled this installation - no subject, tenant or other personal
 * data, safe for a log line or a metric. Same reasons as the Android (`ReenrollReason`) and Flutter
 * (`SentomaruReenrollReason`) ports. */
export type ReenrollReason =
  | 'stateNotEnrolled'
  | 'stateEnrollmentRequired'
  | 'stateKeyInvalidated'
  | 'principalAbsent'
  | 'principalChanged'
  | 'rotationRefused';

/** Outcome of `EnrollmentAssurance.ensureEnrolled`. */
export interface EnsureEnrolledResult {
  /** False when a later call (for a different subject/tenant) superseded this one before it finished: a stale
   * caller must not bind a session, or otherwise act as if its own call had won. */
  current: boolean;
  /** The session id this call obtained, when it enrolled, reenrolled or rotated the installation. `null` when the
   * existing installation and session were simply reused - call `sentomaru.sessionId()` for the one already
   * active; this module never keeps a copy of its own. */
  sessionId: string | null;
}

/** Read/write/delete of one named string value, async (`AsyncStorage`, `react-native-keychain`, or anything else
 * the app already uses). `EnrollmentAssurance` does not ship a concrete implementation - unlike Flutter's
 * `flutter_secure_storage` there is no single dominant secure-storage package for React Native, so the app brings
 * its own (see the package README for a reference wiring with `react-native-keychain` and
 * `@react-native-async-storage/async-storage`). A failing call is caught by `EnrollmentAssurance` itself - an
 * implementation does not need its own try/catch. */
export interface PrincipalStore {
  read(key: string): Promise<string | null>;
  write(key: string, value: string): Promise<void>;
  delete(key: string): Promise<void>;
}

export const PRINCIPAL_SECURE_KEY = 'sentomaru_enrollment_principal';
export const PRINCIPAL_MIRROR_KEY = 'sentomaru_enrollment_principal_mirror';
const REINSTALL_MARKER_KEY = 'sentomaru_enrollment_reinstall_marker';

async function safeRead(store: PrincipalStore, key: string): Promise<string | null> {
  try {
    return await store.read(key);
  } catch {
    return null;
  }
}
async function safeWrite(store: PrincipalStore, key: string, value: string): Promise<void> {
  try {
    await store.write(key, value);
  } catch {
    /* the other copy still allows a reuse later */
  }
}
async function safeDelete(store: PrincipalStore, key: string): Promise<void> {
  try {
    await store.delete(key);
  } catch {
    /* nothing left to read either way */
  }
}

/**
 * Where `EnrollmentAssurance` keeps the principal (sha256 of `subject\0tenant`) of whoever this installation is
 * enrolled for, so a later call can tell "reuse" from "someone else now" without the app storing anything of its
 * own. Composes two injected `PrincipalStore`s: `secure` can lose its key or fail to decrypt (the exact bug this
 * class guards against - evidence in production: 3 live installations of one user in 2.5 h), so `mirror` is read
 * when it comes back empty. The mirror never authorizes anything by itself: `EnrollmentAssurance` only trusts it
 * together with the SDK itself saying `Enrolled`.
 */
class PrincipalStorage {
  private readonly secure: PrincipalStore;
  private readonly mirror: PrincipalStore;

  constructor(secure: PrincipalStore, mirror: PrincipalStore) {
    this.secure = secure;
    this.mirror = mirror;
  }

  async read(): Promise<string | null> {
    const own = await safeRead(this.secure, PRINCIPAL_SECURE_KEY);
    if (own) return own;
    const backup = await safeRead(this.mirror, PRINCIPAL_MIRROR_KEY);
    if (!backup) return null;
    await safeWrite(this.secure, PRINCIPAL_SECURE_KEY, backup); // the mirror still answers on the next read if this fails
    return backup;
  }

  /** Writes the mirror first: a failure of the secure store alone must not lose the principal. */
  async write(principal: string): Promise<void> {
    await safeWrite(this.mirror, PRINCIPAL_MIRROR_KEY, principal);
    await safeWrite(this.secure, PRINCIPAL_SECURE_KEY, principal); // the mirror alone still allows a reuse later
  }

  async delete(): Promise<void> {
    await safeDelete(this.mirror, PRINCIPAL_MIRROR_KEY);
    await safeDelete(this.secure, PRINCIPAL_SECURE_KEY);
  }
}

function reasonFor(state: string, stored: string | null): ReenrollReason {
  switch (state) {
    case 'NotEnrolled':
      return 'stateNotEnrolled';
    case 'EnrollmentRequired':
      return 'stateEnrollmentRequired';
    case 'KeyInvalidated':
      return 'stateKeyInvalidated';
    default:
      return stored === null ? 'principalAbsent' : 'principalChanged';
  }
}

export interface EnrollmentAssuranceOptions {
  /** Consulted at most once per installation, only when this module's own storage (`secure` + `mirror`) has
   * nothing AND the SDK itself says `Enrolled`: an app migrating from its own, app-level principal tracking
   * supplies its OLD stored value here, so adopting this class does not force a one-time reenrollment of every
   * existing installation. A match is copied into this module's own storage right away; a non-match (or
   * `undefined`/`null`, the default) is never consulted again for this installation. */
  legacyPrincipal?: () => Promise<string | null | undefined>;
}

export class EnrollmentAssurance {
  private readonly principal: PrincipalStorage;
  private readonly legacyPrincipal?: () => Promise<string | null | undefined>;
  private latestPrincipal: string | null = null;
  private queue: Promise<unknown> = Promise.resolve();

  /** Fires every time a call decided to enroll or reenroll rather than reuse the installation - never for a plain
   * reuse, and never with subject, tenant or any other personal data (see `ReenrollReason`). */
  onReenrollReason?: (reason: ReenrollReason) => void;

  private readonly sentomaru: Sentomaru;
  private readonly mirrorStore: PrincipalStore;

  constructor(sentomaru: Sentomaru, secureStore: PrincipalStore, mirrorStore: PrincipalStore, options: EnrollmentAssuranceOptions = {}) {
    this.sentomaru = sentomaru;
    this.mirrorStore = mirrorStore;
    this.principal = new PrincipalStorage(secureStore, mirrorStore);
    this.legacyPrincipal = options.legacyPrincipal;
  }

  /** sha256 (hex) of `subject\0tenant`: the same hash `ensureEnrolled` compares against this installation's
   * stored principal. Exposed so a caller can compare without calling `ensureEnrolled` itself. Pure JS (no
   * `crypto.subtle`, not guaranteed on Hermes without a polyfill, same reasoning as this package's own
   * hand-written Base64 in `bridge.ts`). */
  static principalOf(subject: string, tenant: string): string {
    return sha256Hex(`${subject}\0${tenant}`);
  }

  /**
   * Ensures `subject`/`tenant` is enrolled on this device: reuses the installation when it already is for the
   * same caller (rotating its key in place after an app update on Android, D-04b), or reenrolls from scratch
   * (`reset` + `enroll`) otherwise. `challengeProvider` is asked for a fresh, single-use challenge every time one
   * is actually needed - never cached, never reused.
   */
  async ensureEnrolled(subject: string, tenant: string, challengeProvider: ChallengeProvider): Promise<EnsureEnrolledResult> {
    const principal = EnrollmentAssurance.principalOf(subject, tenant);
    this.latestPrincipal = principal;
    const run: Promise<EnsureEnrolledResult> = this.queue.catch(() => undefined).then(async () => {
      // The most recent wins: a call queued behind an older one for a different caller never enrolls that one
      // over the caller that arrived after it.
      if (this.latestPrincipal !== principal) return { current: false, sessionId: null };
      const sessionId = await this.ensureEnrolledLocked(principal, subject, tenant, challengeProvider);
      return { current: this.latestPrincipal === principal, sessionId };
    });
    this.queue = run.catch(() => undefined);
    return run;
  }

  private async ensureEnrolledLocked(
    principal: string,
    subject: string,
    tenant: string,
    challengeProvider: ChallengeProvider,
  ): Promise<string | null> {
    const state = await this.forgetIfReinstalled();
    const stored = await this.storedPrincipal(state);
    if (state === 'Enrolled' && stored === principal) {
      return this.rotateIfUpdated(subject, tenant, challengeProvider);
    }
    this.onReenrollReason?.(reasonFor(state, stored));
    // Challenge before reset: a network failure or a 5xx here must not erase an installation that still works.
    const challenge = await challengeProvider(subject, tenant);
    if (state !== 'NotEnrolled') await this.sentomaru.reset();
    const grant = await this.sentomaru.enroll({ challenge });
    await this.principal.write(principal);
    return grant.sessionId;
  }

  /** `null` when nothing needed rotating (or on iOS/an installation from before D-04b, where `reenrollmentReason`
   * never answers) and `sentomaru.sessionId()` already has what the caller needs; the id this call itself
   * obtained otherwise (a D-04b rotation, or the reenrollment a refused rotation falls back to). */
  private async rotateIfUpdated(subject: string, tenant: string, challengeProvider: ChallengeProvider): Promise<string | null> {
    const reason = await this.sentomaru.reenrollmentReason();
    if (reason === null) return null;
    let challenge: EnrollmentChallenge;
    try {
      challenge = await challengeProvider(subject, tenant);
    } catch {
      return null; // the current key keeps signing; this call simply has nothing new
    }
    let grant;
    try {
      grant = await this.sentomaru.rotate({ challenge });
    } catch (e) {
      if (!isReenrollmentRefused(e)) return null; // any other failure of the update check: the current key keeps signing
      // Refused: a fresh challenge before reset (same invariant as the normal reenrollment path), and from here on
      // NOT swallowed - the installation is already being replaced, a failure now must reach the caller.
      this.onReenrollReason?.('rotationRefused');
      const retryChallenge = await challengeProvider(subject, tenant);
      await this.sentomaru.reset();
      const retryGrant = await this.sentomaru.enroll({ challenge: retryChallenge });
      await this.principal.write(EnrollmentAssurance.principalOf(subject, tenant));
      return retryGrant.sessionId;
    }
    return grant.sessionId;
  }

  /**
   * Forgets this installation (revoked server-side, or the app's own sign-out-everywhere): the next
   * `ensureEnrolled` enrolls from scratch, with a fresh attestation. Joins the same queue as `ensureEnrolled`:
   * never races a reset against one still finishing, and never erases an installation a newer call just made.
   */
  async forgetInstallation(): Promise<void> {
    const run = this.queue.catch(() => undefined).then(async () => {
      await this.sentomaru.reset();
      await this.principal.delete();
    });
    this.queue = run.catch(() => undefined);
    return run;
  }

  /**
   * Reinstalling an iOS app does not erase the Keychain (`sentomaru_flutter`'s `SentomaruIosReinstallGuard`, the
   * Android/Swift ports' own equivalent): a marker in the mirror store answers "first run since (re)install" the
   * same way a Keychain item would survive while `AsyncStorage`-backed state does not. Safe to run on Android too
   * (the marker is never set there either until this runs once): checking `state()` first - not resetting
   * unconditionally - means a fresh Android install (already `NotEnrolled`) costs nothing beyond the one state
   * read every other path already makes; only a genuine leftover record (state other than `NotEnrolled`, the
   * iOS-reinstall case) pays for a `reset()`. Returns the state read here so `ensureEnrolledLocked` does not read
   * it twice. Idempotent and cheap once the marker is set (one store read, one state read); safe to call at the
   * start of every `ensureEnrolled`.
   */
  private async forgetIfReinstalled(): Promise<string> {
    const marker = await safeRead(this.mirrorStore, REINSTALL_MARKER_KEY);
    const state = await this.sentomaru.state();
    if (marker === '1') return state;
    await safeWrite(this.mirrorStore, REINSTALL_MARKER_KEY, '1');
    if (state === 'NotEnrolled') return state;
    await this.principal.delete();
    await this.sentomaru.reset();
    return 'NotEnrolled';
  }

  private async storedPrincipal(state: string): Promise<string | null> {
    const own = await this.principal.read();
    if (own !== null || !this.legacyPrincipal) return own;
    if (state !== 'Enrolled') return null; // nothing to migrate into if this call reenrolls anyway
    const legacy = await this.legacyPrincipal();
    if (!legacy) return null;
    await this.principal.write(legacy); // consulted at most once for this installation, match or not
    return legacy;
  }
}

function isReenrollmentRefused(e: unknown): boolean {
  const code = (e as { code?: unknown } | null)?.code;
  return code === 'ReenrollmentRefused';
}

// Pure, dependency-free SHA-256 (FIPS 180-4), verified against the NIST test vectors (empty string, "abc" and
// 1,000,000 repetitions of "a") before use here. `crypto.subtle` is not guaranteed available on Hermes without a
// polyfill, and this package otherwise has zero runtime dependencies (see `bridge.ts`'s own hand-written Base64).
const SHA256_K = [
  0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5, 0xd807aa98,
  0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174, 0xe49b69c1, 0xefbe4786,
  0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da, 0x983e5152, 0xa831c66d, 0xb00327c8,
  0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967, 0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13,
  0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85, 0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819,
  0xd6990624, 0xf40e3585, 0x106aa070, 0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a,
  0x5b9cca4f, 0x682e6ff3, 0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7,
  0xc67178f2,
] as const;

function rotr(x: number, n: number): number {
  return ((x >>> n) | (x << (32 - n))) >>> 0;
}

function sha256Bytes(bytes: Uint8Array): Uint8Array {
  let h0 = 0x6a09e667, h1 = 0xbb67ae85, h2 = 0x3c6ef372, h3 = 0xa54ff53a;
  let h4 = 0x510e527f, h5 = 0x9b05688c, h6 = 0x1f83d9ab, h7 = 0x5be0cd19;

  const bitLenHigh = Math.floor(bytes.length / 0x20000000);
  const bitLenLow = (bytes.length << 3) >>> 0;
  const padLen = Math.ceil((bytes.length + 1 + 8) / 64) * 64;
  const padded = new Uint8Array(padLen);
  padded.set(bytes);
  padded[bytes.length] = 0x80;
  const dv = new DataView(padded.buffer);
  dv.setUint32(padLen - 8, bitLenHigh, false);
  dv.setUint32(padLen - 4, bitLenLow, false);

  const w = new Uint32Array(64);
  for (let offset = 0; offset < padded.length; offset += 64) {
    for (let i = 0; i < 16; i++) w[i] = dv.getUint32(offset + i * 4, false);
    for (let i = 16; i < 64; i++) {
      const wi15 = w[i - 15]!;
      const wi2 = w[i - 2]!;
      const s0 = rotr(wi15, 7) ^ rotr(wi15, 18) ^ (wi15 >>> 3);
      const s1 = rotr(wi2, 17) ^ rotr(wi2, 19) ^ (wi2 >>> 10);
      w[i] = (w[i - 16]! + s0 + w[i - 7]! + s1) >>> 0;
    }
    let a = h0, b = h1, c = h2, d = h3, e = h4, f = h5, g = h6, hh = h7;
    for (let i = 0; i < 64; i++) {
      const S1 = rotr(e, 6) ^ rotr(e, 11) ^ rotr(e, 25);
      const ch = (e & f) ^ (~e & g);
      const temp1 = (hh + S1 + ch + SHA256_K[i]! + w[i]!) >>> 0;
      const S0 = rotr(a, 2) ^ rotr(a, 13) ^ rotr(a, 22);
      const maj = (a & b) ^ (a & c) ^ (b & c);
      const temp2 = (S0 + maj) >>> 0;
      hh = g; g = f; f = e; e = (d + temp1) >>> 0;
      d = c; c = b; b = a; a = (temp1 + temp2) >>> 0;
    }
    h0 = (h0 + a) >>> 0; h1 = (h1 + b) >>> 0; h2 = (h2 + c) >>> 0; h3 = (h3 + d) >>> 0;
    h4 = (h4 + e) >>> 0; h5 = (h5 + f) >>> 0; h6 = (h6 + g) >>> 0; h7 = (h7 + hh) >>> 0;
  }

  const out = new Uint8Array(32);
  const outView = new DataView(out.buffer);
  [h0, h1, h2, h3, h4, h5, h6, h7].forEach((v, i) => outView.setUint32(i * 4, v, false));
  return out;
}

function sha256Hex(text: string): string {
  const digest = sha256Bytes(new TextEncoder().encode(text));
  return Array.from(digest)
    .map((b) => b.toString(16).padStart(2, '0'))
    .join('');
}
