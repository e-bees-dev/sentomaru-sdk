// D-W-port: EnrollmentAssurance against a fake Sentomaru facade (never the real native module) and in-memory
// PrincipalStores. Model: bridge.test.ts (fakes, no real bridge).
import assert from 'node:assert/strict';
import test from 'node:test';
import {
  EnrollmentAssurance, PRINCIPAL_MIRROR_KEY, PRINCIPAL_SECURE_KEY, type PrincipalStore, type ReenrollReason,
} from '../src/enrollmentAssurance.ts';
import { SentomaruError, type EnrollmentChallenge, type Grant } from '../src/types.ts';
import type { Sentomaru } from '../src/bridge.ts';

let challengeSeq = 0;
function challenge(): EnrollmentChallenge {
  challengeSeq += 1;
  return { id: `ch-${challengeSeq}`, token: 'dG9rZW4', expiresAtEpochMs: Date.now() + 120_000, attestationChallengeB64: 'YXR0ZXN0' };
}

function grantFor(keyId: string): Grant {
  return { installationId: 'inst-1', keyId, sessionId: `sess-${keyId}`, hardwareStatus: 'hardware', attestationStatus: 'verified' };
}

function memoryStore(): PrincipalStore & { values: Map<string, string>; throwOnRead: boolean } {
  const store = {
    values: new Map<string, string>(),
    throwOnRead: false,
    async read(key: string) {
      if (store.throwOnRead) throw new Error('decrypt');
      return store.values.get(key) ?? null;
    },
    async write(key: string, value: string) {
      store.values.set(key, value);
    },
    async delete(key: string) {
      store.values.delete(key);
    },
  };
  return store;
}

function fakeSentomaru() {
  const calls: string[] = [];
  let state: 'NotEnrolled' | 'EnrollmentRequired' | 'Enrolled' | 'KeyInvalidated' = 'NotEnrolled';
  let reenrollmentReason: string | null = null;
  let rotateThrowsCode: string | null = null;
  const sentomaru = {
    state: async () => state,
    reenrollmentReason: async () => reenrollmentReason,
    enroll: async (o: { challenge: EnrollmentChallenge }) => {
      calls.push(`enroll:${o.challenge.id}`);
      state = 'Enrolled';
      return grantFor(o.challenge.id);
    },
    rotate: async (o: { challenge: EnrollmentChallenge }) => {
      calls.push(`rotate:${o.challenge.id}`);
      if (rotateThrowsCode) throw new SentomaruError(rotateThrowsCode);
      return grantFor(o.challenge.id);
    },
    reset: async () => {
      calls.push('reset');
      state = 'NotEnrolled';
    },
    sessionId: async () => null,
  } as unknown as Sentomaru;
  return {
    sentomaru,
    calls,
    setState: (s: typeof state) => { state = s; },
    setReenrollmentReason: (r: string | null) => { reenrollmentReason = r; },
    throwOnRotate: (code: string | null) => { rotateThrowsCode = code; },
  };
}

const REINSTALL_MARKER_KEY = 'sentomaru_enrollment_reinstall_marker';

/** `freshInstall: true` leaves the reinstall marker unset, for the guard's own dedicated tests below; every other
 * test pre-sets it so it is not incidentally exercising that guard too. */
function build(options: { freshInstall?: boolean } = {}) {
  const fake = fakeSentomaru();
  const secure = memoryStore();
  const mirror = memoryStore();
  if (!options.freshInstall) mirror.values.set(REINSTALL_MARKER_KEY, '1');
  const assurance = new EnrollmentAssurance(fake.sentomaru, secure, mirror);
  return { ...fake, secure, mirror, assurance };
}

test('principalOf is stable and subject-sensitive', () => {
  assert.equal(EnrollmentAssurance.principalOf('u-1', 't-1').length, 64);
  assert.equal(EnrollmentAssurance.principalOf('u-1', 't-1'), EnrollmentAssurance.principalOf('u-1', 't-1'));
  assert.notEqual(EnrollmentAssurance.principalOf('u-1', 't-1'), EnrollmentAssurance.principalOf('u-2', 't-1'));
});

test('notEnrolled enrolls once, fires stateNotEnrolled, stores the principal', async () => {
  challengeSeq = 0;
  const { assurance, calls, secure } = build();
  const reasons: ReenrollReason[] = [];
  assurance.onReenrollReason = (r) => reasons.push(r);

  const result = await assurance.ensureEnrolled('u-1', 't-1', async () => challenge());

  assert.deepEqual(calls, ['enroll:ch-1']);
  assert.equal(result.current, true);
  assert.ok(result.sessionId);
  assert.deepEqual(reasons, ['stateNotEnrolled']);
  assert.equal(secure.values.get(PRINCIPAL_SECURE_KEY), EnrollmentAssurance.principalOf('u-1', 't-1'));
});

test('same caller again: reused, no enroll, no reason, sessionId null', async () => {
  challengeSeq = 0;
  const { assurance, calls } = build();
  await assurance.ensureEnrolled('u-1', 't-1', async () => challenge());
  calls.length = 0;
  const reasons: ReenrollReason[] = [];
  assurance.onReenrollReason = (r) => reasons.push(r);

  const result = await assurance.ensureEnrolled('u-1', 't-1', async () => challenge());

  assert.deepEqual(calls, []);
  assert.equal(result.current, true);
  assert.equal(result.sessionId, null);
  assert.deepEqual(reasons, []);
});

test('secure store empty, mirror has it: reuses and repairs the secure store', async () => {
  challengeSeq = 0;
  const { assurance, calls, secure } = build();
  await assurance.ensureEnrolled('u-1', 't-1', async () => challenge());
  secure.values.clear(); // simulates a lost secure-storage key
  calls.length = 0;

  const result = await assurance.ensureEnrolled('u-1', 't-1', async () => challenge());

  assert.deepEqual(calls, []); // no reset, no enroll
  assert.equal(result.current, true);
  assert.equal(secure.values.get(PRINCIPAL_SECURE_KEY), EnrollmentAssurance.principalOf('u-1', 't-1'));
});

test('secure store throws on read, mirror has it: still reuses', async () => {
  challengeSeq = 0;
  const { assurance, calls, secure } = build();
  await assurance.ensureEnrolled('u-1', 't-1', async () => challenge());
  secure.throwOnRead = true;
  calls.length = 0;

  const result = await assurance.ensureEnrolled('u-1', 't-1', async () => challenge());

  assert.deepEqual(calls, []);
  assert.equal(result.current, true);
});

test('mirror alone does not authorize without the plugin also enrolled', async () => {
  challengeSeq = 0;
  const { assurance, calls, mirror } = build();
  mirror.values.set(PRINCIPAL_MIRROR_KEY, EnrollmentAssurance.principalOf('u-1', 't-1'));

  await assurance.ensureEnrolled('u-1', 't-1', async () => challenge());

  assert.deepEqual(calls, ['enroll:ch-1']); // state is NotEnrolled: reenrolls regardless of the mirror
});

test('enrolled with no principal anywhere reenrolls once, fires principalAbsent', async () => {
  challengeSeq = 0;
  const { assurance, calls, setState } = build();
  setState('Enrolled');
  const reasons: ReenrollReason[] = [];
  assurance.onReenrollReason = (r) => reasons.push(r);

  await assurance.ensureEnrolled('u-1', 't-1', async () => challenge());

  assert.deepEqual(calls, ['reset', 'enroll:ch-1']);
  assert.deepEqual(reasons, ['principalAbsent']);
});

test('a different subject reenrolls, fires principalChanged', async () => {
  challengeSeq = 0;
  const { assurance, calls } = build();
  await assurance.ensureEnrolled('u-1', 't-1', async () => challenge());
  calls.length = 0;
  const reasons: ReenrollReason[] = [];
  assurance.onReenrollReason = (r) => reasons.push(r);

  await assurance.ensureEnrolled('u-2', 't-1', async () => challenge());

  assert.deepEqual(calls, ['reset', 'enroll:ch-2']);
  assert.deepEqual(reasons, ['principalChanged']);
});

test('forgetInstallation erases the principal and its mirror, and resets', async () => {
  challengeSeq = 0;
  const { assurance, calls, secure, mirror } = build();
  await assurance.ensureEnrolled('u-1', 't-1', async () => challenge());

  await assurance.forgetInstallation();

  assert.equal(calls.at(-1), 'reset');
  assert.equal(secure.values.size, 0);
  assert.equal(mirror.values.get(PRINCIPAL_MIRROR_KEY), undefined);
});

test('the most recent caller wins: the older call never even asks for a challenge', async () => {
  challengeSeq = 0;
  const { assurance, calls } = build();
  const first = assurance.ensureEnrolled('u-1', 't-1', async () => {
    throw new Error('should not be called: superseded before its own body ran');
  });
  const second = assurance.ensureEnrolled('u-2', 't-1', async () => challenge());

  const [firstResult, secondResult] = await Promise.all([first, second]);

  assert.equal(firstResult.current, false);
  assert.equal(firstResult.sessionId, null);
  assert.equal(secondResult.current, true);
  assert.deepEqual(calls, ['enroll:ch-1']);
});

test('app-update rotation: no reenrollmentReason is a plain reuse, rotate never called', async () => {
  challengeSeq = 0;
  const { assurance, calls } = build();
  await assurance.ensureEnrolled('u-1', 't-1', async () => challenge());
  calls.length = 0;

  await assurance.ensureEnrolled('u-1', 't-1', async () => {
    throw new Error('should not be called');
  });

  assert.deepEqual(calls, []);
});

test('app-update rotation: appUpdated rotates in place, no reset', async () => {
  challengeSeq = 0;
  const { assurance, calls, setReenrollmentReason } = build();
  await assurance.ensureEnrolled('u-1', 't-1', async () => challenge());
  setReenrollmentReason('APP_UPDATED');
  calls.length = 0;

  const result = await assurance.ensureEnrolled('u-1', 't-1', async () => challenge());

  assert.deepEqual(calls, ['rotate:ch-2']);
  assert.equal(result.sessionId, 'sess-ch-2');
});

test('app-update rotation refused: reenrolls with a NEW challenge, fires rotationRefused', async () => {
  challengeSeq = 0;
  const { assurance, calls, setReenrollmentReason, throwOnRotate } = build();
  await assurance.ensureEnrolled('u-1', 't-1', async () => challenge());
  setReenrollmentReason('APP_UPDATED');
  throwOnRotate('ReenrollmentRefused');
  calls.length = 0;
  const reasons: ReenrollReason[] = [];
  assurance.onReenrollReason = (r) => reasons.push(r);

  const result = await assurance.ensureEnrolled('u-1', 't-1', async () => challenge());

  assert.deepEqual(calls, ['rotate:ch-2', 'reset', 'enroll:ch-3']); // the refused challenge is never resent
  assert.deepEqual(reasons, ['rotationRefused']);
  assert.equal(result.sessionId, 'sess-ch-3');
});

test('app-update rotation: rotate throws a different error, swallowed', async () => {
  challengeSeq = 0;
  const { assurance, calls, setReenrollmentReason, throwOnRotate } = build();
  await assurance.ensureEnrolled('u-1', 't-1', async () => challenge());
  setReenrollmentReason('APP_UPDATED');
  throwOnRotate('NetworkUnavailable');
  calls.length = 0;

  const result = await assurance.ensureEnrolled('u-1', 't-1', async () => challenge());

  assert.deepEqual(calls, ['rotate:ch-2']);
  assert.equal(result.sessionId, null);
  assert.equal(result.current, true);
});

test('app-update rotation: the challenge for the rotation itself fails, rotate never called', async () => {
  challengeSeq = 0;
  const { assurance, calls, setReenrollmentReason } = build();
  await assurance.ensureEnrolled('u-1', 't-1', async () => challenge());
  setReenrollmentReason('APP_UPDATED');
  calls.length = 0;

  const result = await assurance.ensureEnrolled('u-1', 't-1', async () => {
    throw new Error('network');
  });

  assert.deepEqual(calls, []);
  assert.equal(result.sessionId, null);
});

test('legacy principal match: reuses and copies the value into the SDK\'s own store', async () => {
  challengeSeq = 0;
  const { calls, secure, mirror, setState, sentomaru } = build();
  setState('Enrolled');
  let legacyCalls = 0;
  const migrating = new EnrollmentAssurance(sentomaru, secure, mirror, {
    legacyPrincipal: async () => {
      legacyCalls += 1;
      return EnrollmentAssurance.principalOf('u-1', 't-1');
    },
  });

  const result = await migrating.ensureEnrolled('u-1', 't-1', async () => {
    throw new Error('should not be called');
  });

  assert.deepEqual(calls, []); // no reset, no enroll: reused on the strength of the legacy value
  assert.equal(result.current, true);
  assert.equal(legacyCalls, 1);
  assert.equal(secure.values.get(PRINCIPAL_SECURE_KEY), EnrollmentAssurance.principalOf('u-1', 't-1'));
});

test('legacy principal belongs to someone else: reenrolls', async () => {
  challengeSeq = 0;
  const { calls, secure, mirror, setState, sentomaru } = build();
  setState('Enrolled');
  const migrating = new EnrollmentAssurance(sentomaru, secure, mirror, {
    legacyPrincipal: async () => EnrollmentAssurance.principalOf('someone-else', 't-1'),
  });

  await migrating.ensureEnrolled('u-1', 't-1', async () => challenge());

  assert.deepEqual(calls, ['reset', 'enroll:ch-1']);
});

test('legacy principal not consulted when not enrolled', async () => {
  challengeSeq = 0;
  const { secure, mirror, sentomaru } = build();
  let legacyCalls = 0;
  const migrating = new EnrollmentAssurance(sentomaru, secure, mirror, {
    legacyPrincipal: async () => {
      legacyCalls += 1;
      return 'whatever';
    },
  });

  await migrating.ensureEnrolled('u-1', 't-1', async () => challenge());

  assert.equal(legacyCalls, 0);
});

test('first call forgets any leftover principal and resets before deciding (iOS Keychain reinstall survival)', async () => {
  challengeSeq = 0;
  const { assurance, calls, secure, mirror, setState } = build({ freshInstall: true });
  setState('Enrolled'); // simulates a leftover Keychain record surviving a reinstall
  secure.values.set(PRINCIPAL_SECURE_KEY, 'leftover-principal');

  const result = await assurance.ensureEnrolled('u-1', 't-1', async () => challenge());

  assert.deepEqual(calls, ['reset', 'enroll:ch-1']);
  assert.equal(mirror.values.get(REINSTALL_MARKER_KEY), '1');
  assert.ok(result.sessionId);
});

test('a fresh install already NotEnrolled costs no extra reset from the guard', async () => {
  challengeSeq = 0;
  const { assurance, calls, mirror } = build({ freshInstall: true });

  await assurance.ensureEnrolled('u-1', 't-1', async () => challenge());

  assert.deepEqual(calls, ['enroll:ch-1']); // the guard only resets a genuine leftover record, not a pristine one
  assert.equal(mirror.values.get(REINSTALL_MARKER_KEY), '1');
});

test('second call does not forget again (marker already set)', async () => {
  challengeSeq = 0;
  const { assurance, calls } = build();

  await assurance.ensureEnrolled('u-1', 't-1', async () => challenge());

  assert.deepEqual(calls, ['enroll:ch-1']); // no extra reset from the guard
});
