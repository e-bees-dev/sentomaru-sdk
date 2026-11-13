package br.com.ebees.sentomaru.sdk

import br.com.ebees.sentomaru.core.SentomaruException
import java.security.KeyPair
import java.security.KeyPairGenerator
import java.security.Signature
import java.security.spec.ECGenParameterSpec
import java.time.Clock
import java.time.Instant
import java.time.ZoneOffset
import java.util.Base64
import java.util.concurrent.CountDownLatch
import java.util.concurrent.TimeUnit
import java.util.concurrent.TimeoutException
import org.junit.After
import org.junit.Assert.*
import org.junit.Before
import org.junit.Test

/** D-W-port: [EnrollmentAssurance] against a real [SentomaruClient] with in-memory fakes (model: ReenrollmentTest). */
class EnrollmentAssuranceTest {
    private val now = Instant.parse("2026-10-21T12:00:00Z")
    private val clock = Clock.fixed(now, ZoneOffset.UTC)
    private val session = "aaaaaaaa-bbbb-4ccc-8ddd-eeeeeeeeeeee"
    private val config = SentomaruConfig("org", "app", "hml", setOf("consumer.example"), "https://consumer.example/enroll")

    private class MemoryState : InstallationStore {
        var value: InstallationRecord? = null
        /** How many times [write] was called with `null`: exactly what `SentomaruClient.reset()` does, and
         * nothing else in this flow does. */
        var resets = 0
        override fun read() = value
        override fun write(record: InstallationRecord?) {
            if (record == null) resets++
            value = record
        }
    }

    private class JcaKeys : InstallationKeys {
        private val keys = mutableMapOf<String, KeyPair>()
        override fun exists(alias: String) = keys.containsKey(alias)
        override fun generate(alias: String, challenge: ByteArray, strongBox: Boolean): KeyMaterial {
            keys[alias] = KeyPairGenerator.getInstance("EC").apply { initialize(ECGenParameterSpec("secp256r1")) }.generateKeyPair()
            return material(alias)
        }
        override fun material(alias: String) = KeyMaterial(keys.getValue(alias).public.encoded, emptyList())
        override fun sign(alias: String, bytes: ByteArray) = Signature.getInstance("SHA256withECDSAinP1363Format")
            .run { initSign(keys.getValue(alias).private); update(bytes); sign() }
        override fun delete(alias: String) { keys.remove(alias) }
        override fun deleteOwned(prefix: String) { keys.keys.filter { it.startsWith(prefix) }.forEach { keys.remove(it) } }
    }

    private class MemoryKeyValueStore : SentomaruKeyValueStore {
        val values = mutableMapOf<String, String>()
        var throwOnRead = false
        var throwOnWrite = false
        override fun read(key: String): String? {
            if (throwOnRead) throw RuntimeException("decrypt")
            return values[key]
        }
        override fun write(key: String, value: String) {
            if (throwOnWrite) throw RuntimeException("encrypt")
            values[key] = value
        }
        override fun delete(key: String) { values.remove(key) }
    }

    private var idSeq = 0
    private fun uuid(): String {
        idSeq++
        return "00000000-0000-4000-8000-%012d".format(idSeq)
    }

    private fun challenge() = EnrollmentChallenge(uuid(), Base64.getEncoder().encodeToString(ByteArray(32) { 7 }),
        ByteArray(32) { 8 }, now.plusSeconds(120))
    private fun grant(id: String) = EnrollmentGrant(session, id, session, "hardware", "verified")

    private lateinit var keys: JcaKeys
    private lateinit var store: MemoryState
    private lateinit var client: SentomaruClient
    private lateinit var secure: MemoryKeyValueStore
    private lateinit var mirror: MemoryKeyValueStore
    private lateinit var principalStore: PrincipalStore
    private lateinit var assurance: EnrollmentAssurance
    private var enrollCalls = 0

    @Before
    fun setUp() {
        keys = JcaKeys()
        store = MemoryState()
        // appVersionCode=1 so the first enrollment stores a version; tests that construct a SentomaruClient with
        // appVersionCode=2 on the same store then see a genuine ReenrollmentReason.APP_UPDATED.
        client = SentomaruClient(config, keys, store, clock, appVersionCode = 1)
        secure = MemoryKeyValueStore()
        mirror = MemoryKeyValueStore()
        principalStore = PrincipalStore(secure, mirror)
        assurance = EnrollmentAssurance(client, principalStore)
        enrollCalls = 0
    }

    @After
    fun tearDown() {
        assurance.close()
    }

    /** A challenge provider paired with a grant sender whose keyId always matches the challenge just issued
     * (SentomaruClient.enroll/rotate refuse a mismatched keyId). */
    private fun paired(): Pair<ChallengeProvider, GrantSender> {
        var lastId = ""
        val provider: ChallengeProvider = { _, _ -> challenge().also { lastId = it.id } }
        val sender: GrantSender = { grant(lastId) }
        return provider to sender
    }

    private fun ensure(subject: String, tenant: String = "t-1"): EnsureEnrolledResult {
        var lastChallengeId = ""
        val challengeProvider: ChallengeProvider = { s, t -> challenge().also { lastChallengeId = it.id } }
        val grantSender: GrantSender = { enrollCalls++; grant(lastChallengeId) }
        return assurance.ensureEnrolled(subject, tenant, challengeProvider, grantSender)
    }

    @Test
    fun principalOfIsStableAndSubjectSensitive() {
        assertEquals(64, EnrollmentAssurance.principalOf("u-1", "t-1").length)
        assertEquals(EnrollmentAssurance.principalOf("u-1", "t-1"), EnrollmentAssurance.principalOf("u-1", "t-1"))
        assertNotEquals(EnrollmentAssurance.principalOf("u-1", "t-1"), EnrollmentAssurance.principalOf("u-2", "t-1"))
    }

    @Test
    fun notEnrolledEnrollsOnceAndStoresThePrincipal() {
        val reasons = mutableListOf<ReenrollReason>()
        assurance.onReenrollReason = { reasons.add(it) }

        val result = ensure("u-1")

        assertEquals(1, enrollCalls)
        assertTrue(result.current)
        assertNotNull(result.sessionId)
        assertEquals(listOf(ReenrollReason.STATE_NOT_ENROLLED), reasons)
        assertEquals(EnrollmentAssurance.principalOf("u-1", "t-1"), secure.values[PrincipalStore.KEY])
    }

    /** This SDK has no iOS-style reinstall guard (Android's own storage is wiped on uninstall - no bug to port
     * from there), but the Android/Flutter/iOS ports' shared reinstall guard was found resetting unconditionally
     * even on an already-`NotEnrolled` fresh install; proving the equivalent is true here too, not just assuming
     * it from "there is no guard to have the bug". */
    @Test
    fun aFreshInstallNeverCallsReset() {
        ensure("u-1")

        assertEquals(0, store.resets)
    }

    @Test
    fun sameCallerAgainIsReusedWithNoEnrollAndNoReason() {
        ensure("u-1")
        enrollCalls = 0
        val reasons = mutableListOf<ReenrollReason>()
        assurance.onReenrollReason = { reasons.add(it) }

        val result = ensure("u-1")

        assertEquals(0, enrollCalls)
        assertTrue(result.current)
        assertNull(result.sessionId)
        assertTrue(reasons.isEmpty())
    }

    @Test
    fun secureStoreEmptyMirrorHasIt_reusesAndRepairsTheSecureStore() {
        ensure("u-1")
        secure.values.clear() // simulates a lost EncryptedSharedPreferences key
        enrollCalls = 0

        val result = ensure("u-1")

        assertEquals(0, enrollCalls)
        assertTrue(result.current)
        assertEquals(EnrollmentAssurance.principalOf("u-1", "t-1"), secure.values[PrincipalStore.KEY])
    }

    @Test
    fun secureStoreThrowsOnRead_mirrorStillReuses() {
        ensure("u-1")
        secure.throwOnRead = true
        enrollCalls = 0

        val result = ensure("u-1")

        assertEquals(0, enrollCalls)
        assertTrue(result.current)
    }

    @Test
    fun mirrorAloneDoesNotAuthorizeWithoutThePluginAlsoEnrolled() {
        mirror.values[PrincipalStore.MIRROR_KEY] = EnrollmentAssurance.principalOf("u-1", "t-1")

        ensure("u-1")

        assertEquals(1, enrollCalls) // state is NotEnrolled: reenrolls regardless of the mirror
    }

    @Test
    fun enrolledWithNoPrincipalAnywhereReenrollsOnce() {
        ensure("u-1")
        // Simulate "installation from before this contract": the plugin is Enrolled but nothing is stored.
        secure.values.clear()
        mirror.values.clear()
        enrollCalls = 0
        val reasons = mutableListOf<ReenrollReason>()
        assurance.onReenrollReason = { reasons.add(it) }

        ensure("u-1")

        assertEquals(1, enrollCalls)
        assertEquals(listOf(ReenrollReason.PRINCIPAL_ABSENT), reasons)
    }

    @Test
    fun aDifferentSubjectReenrollsEvenWithAMirrorForTheOldOne() {
        ensure("u-1")
        enrollCalls = 0
        val reasons = mutableListOf<ReenrollReason>()
        assurance.onReenrollReason = { reasons.add(it) }

        ensure("u-2")

        assertEquals(1, enrollCalls)
        assertEquals(listOf(ReenrollReason.PRINCIPAL_CHANGED), reasons)
    }

    @Test
    fun forgetInstallationErasesPrincipalAndMirrorAndResets() {
        ensure("u-1")

        assurance.forgetInstallation()

        assertEquals(InstallationState.NotEnrolled, client.state())
        assertTrue(secure.values.isEmpty())
        assertTrue(mirror.values.isEmpty())
    }

    @Test
    fun theMostRecentCallerWinsEvenWhenTheOlderOneAlreadyRanToCompletion() {
        val gate = CountDownLatch(1)
        val started = CountDownLatch(1)
        var firstResult: EnsureEnrolledResult? = null
        val (pairedProvider, pairedSender) = paired()
        val firstThread = Thread {
            val slowProvider: ChallengeProvider = { s, t -> started.countDown(); gate.await(); pairedProvider(s, t) }
            firstResult = assurance.ensureEnrolled("u-1", "t-1", slowProvider, pairedSender)
        }
        firstThread.start()
        assertTrue(started.await(2, TimeUnit.SECONDS))
        // u-1's call is now blocked inside the lock, past its own staleness check (it already holds the lock);
        // this call for u-2 sets latestPrincipal before it can even try to acquire the lock.
        val secondThread = Thread { ensure("u-2") }
        secondThread.start()
        gate.countDown()
        firstThread.join(2000)
        secondThread.join(2000)

        // The older caller's own enrollment DID run (this SDK's blocking lock cannot preempt a thread already past
        // its own check, unlike the Flutter port's cooperative scheduling) but it must know not to trust it.
        assertFalse(firstResult!!.current)
        // The device ends up enrolled for the newer caller, not the older one, whichever ran last.
        assertEquals(EnrollmentAssurance.principalOf("u-2", "t-1"), secure.values[PrincipalStore.KEY])
    }

    @Test
    fun noReenrollmentReasonIsAPlainReuseAndRotateIsNeverCalled() {
        ensure("u-1")
        var touched = false

        val result = assurance.ensureEnrolled("u-1", "t-1", { _, _ -> touched = true; challenge() },
            { touched = true; grant("x") })

        assertFalse(touched) // reenrollmentReason() is null: rotateIfUpdated returns before asking for anything
        assertNull(result.sessionId)
    }

    @Test
    fun appUpdatedRotatesInPlaceWithNoReset() {
        ensure("u-1")
        val restarted = SentomaruClient(config, keys, store, clock, appVersionCode = 2)
        val restartedAssurance = EnrollmentAssurance(restarted, principalStore)
        val (provider, sender) = paired()
        var rotated = false

        val result = restartedAssurance.ensureEnrolled("u-1", "t-1", provider) { m -> rotated = true; sender(m) }

        assertTrue(rotated)
        assertNotNull(result.sessionId)
        assertEquals(InstallationState.Enrolled, restarted.state())
        restartedAssurance.close()
    }

    @Test
    fun rotationRefusedReenrollsWithANewChallenge() {
        ensure("u-1")
        val restarted = SentomaruClient(config, keys, store, clock, appVersionCode = 2)
        val restartedAssurance = EnrollmentAssurance(restarted, principalStore)
        val reasons = mutableListOf<ReenrollReason>()
        restartedAssurance.onReenrollReason = { reasons.add(it) }
        var calls = 0
        var lastId = ""
        val challengeProvider: ChallengeProvider = { _, _ -> calls++; challenge().also { lastId = it.id } }
        val grantSender: GrantSender = { _ ->
            if (calls == 1) throw SentomaruException(EnrollmentError.ReenrollmentRefused())
            grant(lastId)
        }

        val result = restartedAssurance.ensureEnrolled("u-1", "t-1", challengeProvider, grantSender)

        assertEquals(2, calls) // the refused challenge is never resent
        assertEquals(listOf(ReenrollReason.ROTATION_REFUSED), reasons)
        assertNotNull(result.sessionId)
        assertEquals(InstallationState.Enrolled, restarted.state())
        restartedAssurance.close()
    }

    @Test
    fun rotateThrowingADifferentErrorIsSwallowed() {
        ensure("u-1")
        val restarted = SentomaruClient(config, keys, store, clock, appVersionCode = 2)
        val restartedAssurance = EnrollmentAssurance(restarted, principalStore)

        val result = restartedAssurance.ensureEnrolled("u-1", "t-1",
            { _, _ -> challenge() },
            { throw SentomaruException(EnrollmentError.NetworkUnavailable()) })

        assertNull(result.sessionId)
        assertTrue(result.current)
        restartedAssurance.close()
    }

    @Test
    fun theChallengeForTheRotationItselfFailing_rotateIsNeverCalled() {
        ensure("u-1")
        val restarted = SentomaruClient(config, keys, store, clock, appVersionCode = 2)
        val restartedAssurance = EnrollmentAssurance(restarted, principalStore)
        var rotateAttempted = false

        val result = restartedAssurance.ensureEnrolled("u-1", "t-1",
            { _, _ -> throw RuntimeException("network") },
            { rotateAttempted = true; grant("x") })

        assertFalse(rotateAttempted)
        assertNull(result.sessionId)
        restartedAssurance.close()
    }

    @Test
    fun aSlowRotationPastTimeoutReturnsNoSessionButKeepsRunningInTheBackground() {
        ensure("u-1")
        val restarted = SentomaruClient(config, keys, store, clock, appVersionCode = 2)
        val slow = EnrollmentAssurance(restarted, principalStore, appUpdateTimeoutMs = 20)
        val gate = CountDownLatch(1)
        var lastId = ""
        var rotateCalled = false
        val challengeProvider: ChallengeProvider = { _, _ -> gate.await(); challenge().also { lastId = it.id } }
        val grantSender: GrantSender = { rotateCalled = true; grant(lastId) }

        val result = slow.ensureEnrolled("u-1", "t-1", challengeProvider, grantSender)

        assertNull(result.sessionId) // timed out, nothing erased
        assertFalse(rotateCalled) // still waiting on the challenge when this call gave up

        gate.countDown()
        // give the background thread a moment to finish on its own
        Thread.sleep(200)
        assertTrue(rotateCalled)
        slow.close()
    }

    @Test(expected = TimeoutException::class)
    fun aReenrollmentForADifferentCallerFailsWhileARotationIsStillSettling() {
        ensure("u-1")
        val restarted = SentomaruClient(config, keys, store, clock, appVersionCode = 2)
        val tight = EnrollmentAssurance(restarted, principalStore, appUpdateTimeoutMs = 10, settleTimeoutMs = 10)
        val gate = CountDownLatch(1)
        val (slowProvider, slowSender) = paired()
        tight.ensureEnrolled("u-1", "t-1", { s, t -> gate.await(); slowProvider(s, t) }, slowSender) // times out

        try {
            val (provider, sender) = paired()
            tight.ensureEnrolled("u-2", "t-1", provider, sender)
        } finally {
            gate.countDown()
            tight.close()
        }
    }

    @Test
    fun forgetInstallationWaitsForARotationThenResetsAnywayPastSettleTimeout() {
        ensure("u-1")
        val restarted = SentomaruClient(config, keys, store, clock, appVersionCode = 2)
        val tight = EnrollmentAssurance(restarted, principalStore, appUpdateTimeoutMs = 10, settleTimeoutMs = 10)
        val gate = CountDownLatch(1)
        val (slowProvider, slowSender) = paired()
        tight.ensureEnrolled("u-1", "t-1", { s, t -> gate.await(); slowProvider(s, t) }, slowSender)

        tight.forgetInstallation()

        assertEquals(InstallationState.NotEnrolled, restarted.state())
        gate.countDown()
        tight.close()
    }

    @Test
    fun legacyPrincipalMatch_reusesAndCopiesIntoOwnStore() {
        val restarted = SentomaruClient(config, keys, store, clock)
        // Enroll for real first so the plugin itself says Enrolled.
        val bootstrap = EnrollmentAssurance(restarted, PrincipalStore(MemoryKeyValueStore(), MemoryKeyValueStore()))
        val (bootstrapProvider, bootstrapSender) = paired()
        bootstrap.ensureEnrolled("u-1", "t-1", bootstrapProvider, bootstrapSender)
        bootstrap.close()
        var calls = 0
        val migrating = EnrollmentAssurance(restarted, principalStore, legacyPrincipal = {
            calls++
            EnrollmentAssurance.principalOf("u-1", "t-1")
        })
        var enrollAttempted = false

        val result = migrating.ensureEnrolled("u-1", "t-1", { _, _ -> challenge() }, { enrollAttempted = true; grant("x") })

        assertFalse(enrollAttempted)
        assertTrue(result.current)
        assertEquals(1, calls)
        assertEquals(EnrollmentAssurance.principalOf("u-1", "t-1"), secure.values[PrincipalStore.KEY])
        migrating.close()
    }

    @Test
    fun legacyPrincipalMismatchReenrolls() {
        val restarted = SentomaruClient(config, keys, store, clock)
        val bootstrap = EnrollmentAssurance(restarted, PrincipalStore(MemoryKeyValueStore(), MemoryKeyValueStore()))
        val (bootstrapProvider, bootstrapSender) = paired()
        bootstrap.ensureEnrolled("u-1", "t-1", bootstrapProvider, bootstrapSender)
        bootstrap.close()
        val migrating = EnrollmentAssurance(restarted, principalStore, legacyPrincipal = {
            EnrollmentAssurance.principalOf("someone-else", "t-1")
        })
        val (provider, sender) = paired()

        migrating.ensureEnrolled("u-1", "t-1", provider, sender)

        assertEquals(EnrollmentAssurance.principalOf("u-1", "t-1"), secure.values[PrincipalStore.KEY])
        migrating.close()
    }

    @Test
    fun legacyPrincipalNotConsultedWhenNotEnrolled() {
        var calls = 0
        val migrating = EnrollmentAssurance(client, principalStore, legacyPrincipal = { calls++; "whatever" })
        val (provider, sender) = paired()

        migrating.ensureEnrolled("u-1", "t-1", provider, sender)

        assertEquals(0, calls)
        migrating.close()
    }
}
