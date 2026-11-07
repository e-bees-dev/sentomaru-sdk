package br.com.ebees.sentomaru.sdk

import br.com.ebees.sentomaru.core.*
import java.io.IOException
import java.security.KeyPair
import java.security.KeyPairGenerator
import java.security.Signature
import java.security.spec.ECGenParameterSpec
import java.time.Clock
import java.time.Instant
import java.time.ZoneOffset
import java.util.Base64
import org.junit.Assert.*
import org.junit.Test

/** Isolated lifecycle tests; JCA keys are real, hardware trust/network are tested by device/API gates. */
class EnrollmentFlowTest {
    private val now = Instant.parse("2026-10-08T12:00:00Z")
    private val clock = Clock.fixed(now, ZoneOffset.UTC)
    private val id = "11111111-2222-4333-8444-555555555555"
    private val session = "aaaaaaaa-bbbb-4ccc-8ddd-eeeeeeeeeeee"
    private val config = SentomaruConfig("org", "app", "hml", setOf("consumer.example"),
        "https://consumer.example/enroll")
    private fun challenge(expiry: Instant = now.plusSeconds(120)) = EnrollmentChallenge(id,
        Base64.getEncoder().encodeToString(ByteArray(32) { 7 }), ByteArray(32) { 8 }, expiry)
    private fun grant() = EnrollmentGrant(session, id, session, "unknown", "notEvaluated")

    private class MemoryState : InstallationStore {
        var value: InstallationRecord? = null
        override fun read() = value
        override fun write(record: InstallationRecord?) { value = record }
    }
    private class JcaKeys : InstallationKeys {
        private val keys = mutableMapOf<String, KeyPair>()
        var generations = 0
        var unavailable = false
        override fun exists(alias: String) = keys.containsKey(alias)
        override fun generate(alias: String, challenge: ByteArray, strongBox: Boolean): KeyMaterial {
            if (unavailable) throw SentomaruException(EnrollmentError.StrongBoxUnavailable())
            generations++
            keys[alias] = KeyPairGenerator.getInstance("EC").apply {
                initialize(ECGenParameterSpec("secp256r1"))
            }.generateKeyPair()
            return material(alias)
        }
        override fun material(alias: String) = KeyMaterial(keys.getValue(alias).public.encoded, emptyList())
        override fun sign(alias: String, bytes: ByteArray) = Signature.getInstance("SHA256withECDSAinP1363Format")
            .run { initSign(keys.getValue(alias).private); update(bytes); sign() }
        override fun delete(alias: String) { keys.remove(alias) }
        override fun deleteOwned(prefix: String) { keys.keys.filter { it.startsWith(prefix) }.forEach { keys.remove(it) } }
        fun verify(alias: String, message: SignedMessage) = Signature.getInstance("SHA256withECDSAinP1363Format")
            .run {
                initVerify(keys.getValue(alias).public); update(message.signatureBase())
                verify(Base64.getDecoder().decode(message.header("signature")!!.removePrefix("sig1=:").removeSuffix(":")))
            }
    }
    private fun refused(code: String, action: () -> Unit) {
        val error = assertThrows(SentomaruException::class.java) { action() }
        assertEquals(code, error.error.code)
    }

    @Test fun expiredChallengeDoesNotCreateKey() {
        val keys = JcaKeys()
        val client = SentomaruClient(config, keys, MemoryState(), clock)
        refused("ChallengeExpired") { client.enroll(challenge(now)) { grant() } }
        assertEquals(0, keys.generations)
        assertEquals(InstallationState.NotEnrolled, client.state())
    }

    @Test fun lostResponseRetainsKeyBodyAndRecoversAcrossClientRecreation() {
        val keys = JcaKeys(); val store = MemoryState()
        val first = SentomaruClient(config, keys, store, clock)
        var body: ByteArray? = null
        refused("NetworkUnavailable") {
            first.enroll(challenge()) {
                body = it.body()
                assertEquals("https://consumer.example/enroll", it.targetUri)
                assertEquals(id, it.header("x-sentomaru-session"))
                assertTrue(keys.verify(store.value!!.alias, it))
                throw IOException("secret transport diagnostic")
            }
        }
        val recreated = SentomaruClient(config, keys, store, clock)
        recreated.enroll(challenge()) {
            assertArrayEquals(body, it.body())
            assertTrue(keys.verify(store.value!!.alias, it))
            grant()
        }
        assertEquals(1, keys.generations)
        assertEquals(InstallationState.Enrolled, recreated.state())
        recreated.enroll(challenge()) { throw AssertionError("cached enrollment must not be resent") }
    }

    @Test fun missingAliasCannotSignOrAutomaticallyReenroll() {
        val keys = JcaKeys(); val store = MemoryState()
        val client = SentomaruClient(config, keys, store, clock)
        client.enroll(challenge()) { grant() }
        keys.delete(store.value!!.alias)
        assertEquals(InstallationState.KeyInvalidated, client.state())
        refused("KeyInvalidated") { client.enroll(challenge()) { grant() } }
        assertEquals(1, keys.generations)
        client.reset()
        assertEquals(InstallationState.NotEnrolled, client.state())
    }

    @Test fun operationUsesPersistedGrantAndRefusesForeignScope() {
        val keys = JcaKeys(); val store = MemoryState()
        val client = SentomaruClient(config, keys, store, clock)
        val headers = linkedMapOf("content-type" to "application/json", "x-sentomaru-profile" to "sentomaru-p0",
            "x-sentomaru-org" to "org", "x-sentomaru-app" to "app", "x-sentomaru-environment" to "hml",
            "x-sentomaru-session" to session, "x-sentomaru-operation" to "submit")
        val request = FrozenRequest("POST", "https://consumer.example/submit", headers, "{}".toByteArray())
        refused("NotEnrolled") { client.signRequest(request) }
        client.enroll(challenge()) { grant() }
        assertTrue(keys.verify(store.value!!.alias, client.signRequest(request)))
        headers["x-sentomaru-app"] = "other"
        refused("InvalidRequest:HEADER_VALUE") { client.signRequest(FrozenRequest(request.method, request.targetUri, headers, request.body())) }
        refused("HostNotAllowed") { client.signRequest(FrozenRequest(request.method, "https://other.example/", request.headers, request.body())) }
    }

    @Test fun strongBoxFailureAndForeignGrantNeverBecomeEnrollment() {
        val keys = JcaKeys(); val store = MemoryState()
        val client = SentomaruClient(config, keys, store, clock)
        keys.unavailable = true
        refused("StrongBoxUnavailable") { client.enroll(challenge(), strongBox = true) { grant() } }
        assertEquals(InstallationState.NotEnrolled, client.state())
        keys.unavailable = false
        refused("InvalidRequest:PARAMS") {
            client.enroll(challenge()) { EnrollmentGrant(session, session, session, "hardware", "verified") }
        }
        assertEquals(InstallationState.EnrollmentRequired, client.state())
    }

    @Test fun retryCannotChangeHardwareRequirementOfFrozenEnrollment() {
        val client = SentomaruClient(config, JcaKeys(), MemoryState(), clock)
        refused("NetworkUnavailable") { client.enroll(challenge()) { throw IOException() } }
        refused("EnrollmentRequired") { client.enroll(challenge(), requiresHardware = true) { grant() } }
    }

    @Test fun acceptsActualServerVerifiedAndAdvisoryStatuses() {
        for ((hardware, attestation) in listOf("hardware" to "verified", "software" to "verified", "unknown" to "untrusted")) {
            val client = SentomaruClient(config, JcaKeys(), MemoryState(), clock)
            val result = client.enroll(challenge()) { EnrollmentGrant(session, id, session, hardware, attestation) }
            assertEquals(hardware, result.hardwareStatus)
            assertEquals(attestation, result.attestationStatus)
        }
    }

    @Test fun cancellationDuringSigningNeverSendsEnrollment() {
        val real = JcaKeys()
        val keys = object : InstallationKeys by real {
            override fun sign(alias: String, bytes: ByteArray): ByteArray = real.sign(alias, bytes).also {
                Thread.currentThread().interrupt()
            }
        }
        val client = SentomaruClient(config, keys, MemoryState(), clock)
        var sent = false
        try {
            refused("Cancelled") { client.enroll(challenge()) { sent = true; grant() } }
            assertFalse("cancelled signature must never reach transport", sent)
            assertEquals(InstallationState.EnrollmentRequired, client.state())
        } finally { Thread.interrupted() }
    }

    @Test fun resetDuringTransportCannotResurrectOldGrant() {
        val client = SentomaruClient(config, JcaKeys(), MemoryState(), clock)
        refused("Cancelled") { client.enroll(challenge()) { client.reset(); grant() } }
        assertEquals(InstallationState.NotEnrolled, client.state())
    }

    @Test fun rotateBeforeEnrollmentFails() {
        val client = SentomaruClient(config, JcaKeys(), MemoryState(), clock)
        refused("NotEnrolled") { client.rotate(challenge()) { grant() } }
    }

    @Test fun rotateWhenKeyInvalidatedFails() {
        val keys = JcaKeys(); val store = MemoryState()
        val client = SentomaruClient(config, keys, store, clock)
        client.enroll(challenge()) { grant() }
        keys.delete(store.value!!.alias)
        refused("KeyInvalidated") { client.rotate(challenge()) { grant() } }
    }

    @Test fun rotateWithExpiredChallengeFailsWithoutGeneratingKey() {
        val keys = JcaKeys(); val store = MemoryState()
        val client = SentomaruClient(config, keys, store, clock)
        client.enroll(challenge()) { grant() }
        val gens = keys.generations
        refused("ChallengeExpired") { client.rotate(challenge(now)) { grant() } }
        assertEquals(gens, keys.generations)
    }

    @Test fun rotateNetworkFailurePreservesExistingActiveKey() {
        val keys = JcaKeys(); val store = MemoryState()
        val client = SentomaruClient(config, keys, store, clock)
        client.enroll(challenge()) { grant() }
        val activeAlias = store.value!!.alias
        val rotateId = "22222222-3333-4444-8555-666666666666"
        val rotateChallenge = EnrollmentChallenge(rotateId, Base64.getEncoder().encodeToString(ByteArray(32) { 9 }),
            ByteArray(32) { 10 }, now.plusSeconds(120))
        refused("NetworkUnavailable") {
            client.rotate(rotateChallenge) { throw IOException() }
        }
        assertEquals(InstallationState.Enrolled, client.state())
        val req = FrozenRequest("POST", "https://consumer.example/submit",
            config.headers(session, "submit"), "{}".toByteArray())
        assertTrue(keys.verify(activeAlias, client.signRequest(req)))
        val gensBefore = keys.generations
        client.rotate(rotateChallenge) {
            EnrollmentGrant(session, rotateId, session, "hardware", "verified")
        }
        assertEquals(gensBefore, keys.generations)
        assertNotEquals(activeAlias, store.value!!.alias)
        assertEquals(1, client.retiredKeys().size)
        assertEquals(oldestRetired(client), activeAlias)
    }

    @Test fun rotateSwitchesActiveKeyAndRetiresOldKeyWith7DayWindow() {
        val keys = JcaKeys(); val store = MemoryState()
        val client = SentomaruClient(config, keys, store, clock)
        client.enroll(challenge()) { grant() }
        val oldAlias = store.value!!.alias
        val rotateId = "33333333-4444-4555-8666-777777777777"
        val rotateChallenge = EnrollmentChallenge(rotateId, Base64.getEncoder().encodeToString(ByteArray(32) { 11 }),
            ByteArray(32) { 12 }, now.plusSeconds(120))
        val newGrant = EnrollmentGrant(session, rotateId, session, "hardware", "verified")
        client.rotate(rotateChallenge) { newGrant }
        val newAlias = store.value!!.alias
        assertNotEquals(oldAlias, newAlias)
        assertTrue(newAlias.contains(".v2."))
        assertTrue(keys.exists(oldAlias))
        assertTrue(keys.exists(newAlias))
        assertEquals(1, client.retiredKeys().size)
        assertEquals(oldAlias, client.retiredKeys().first().alias)
        assertEquals(now.plus(java.time.Duration.ofDays(7)), client.retiredKeys().first().expiresAt)
        val req = FrozenRequest("POST", "https://consumer.example/submit",
            config.headers(session, "submit"), "{}".toByteArray())
        assertTrue(keys.verify(newAlias, client.signRequest(req)))
    }

    @Test fun expiredRetiredKeyIsPrunedAfterGracePeriod() {
        var currentInstant = now
        val testClock = object : Clock() {
            override fun getZone() = ZoneOffset.UTC
            override fun withZone(zone: java.time.ZoneId?) = this
            override fun instant() = currentInstant
        }
        val keys = JcaKeys(); val store = MemoryState()
        val client = SentomaruClient(config, keys, store, testClock)
        client.enroll(challenge()) { grant() }
        val oldAlias = store.value!!.alias
        val rotateId = "44444444-5555-4666-8777-888888888888"
        val rotateChallenge = EnrollmentChallenge(rotateId, Base64.getEncoder().encodeToString(ByteArray(32) { 13 }),
            ByteArray(32) { 14 }, now.plusSeconds(120))
        client.rotate(rotateChallenge) { EnrollmentGrant(session, rotateId, session, "hardware", "verified") }
        assertTrue(keys.exists(oldAlias))
        assertEquals(1, client.retiredKeys().size)
        currentInstant = now.plus(java.time.Duration.ofDays(8))
        assertEquals(InstallationState.Enrolled, client.state())
        assertFalse("expired retired key must be pruned from Keystore", keys.exists(oldAlias))
        assertTrue(client.retiredKeys().isEmpty())
    }

    @Test fun resetDeletesActiveAndRetiredKeys() {
        val keys = JcaKeys(); val store = MemoryState()
        val client = SentomaruClient(config, keys, store, clock)
        client.enroll(challenge()) { grant() }
        val oldAlias = store.value!!.alias
        val rotateId = "55555555-6666-4777-8888-999999999999"
        val rotateChallenge = EnrollmentChallenge(rotateId, Base64.getEncoder().encodeToString(ByteArray(32) { 15 }),
            ByteArray(32) { 16 }, now.plusSeconds(120))
        client.rotate(rotateChallenge) { EnrollmentGrant(session, rotateId, session, "hardware", "verified") }
        val newAlias = store.value!!.alias
        assertTrue(keys.exists(oldAlias))
        assertTrue(keys.exists(newAlias))
        client.reset()
        assertFalse(keys.exists(oldAlias))
        assertFalse(keys.exists(newAlias))
        assertEquals(InstallationState.NotEnrolled, client.state())
    }

    private fun oldestRetired(client: SentomaruClient) = client.retiredKeys().first().alias
}
