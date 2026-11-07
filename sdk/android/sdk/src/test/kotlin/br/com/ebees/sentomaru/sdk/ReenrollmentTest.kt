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

/**
 * D-04b: the installation remembers the `versionCode` its key was attested with and asks for a new enrollment (fresh
 * attestation) when the running app has another one. Each client below is "the app after a restart" with a given version.
 */
class ReenrollmentTest {
    private val now = Instant.parse("2026-10-21T12:00:00Z")
    private val clock = Clock.fixed(now, ZoneOffset.UTC)
    private val firstId = "11111111-2222-4333-8444-555555555555"
    private val secondId = "22222222-3333-4444-8555-666666666666"
    private val session = "aaaaaaaa-bbbb-4ccc-8ddd-eeeeeeeeeeee"
    private val config = SentomaruConfig("org", "app", "hml", setOf("consumer.example"),
        "https://consumer.example/enroll", renewalUrl = "https://consumer.example/sessions")
    private fun challenge(id: String = firstId, fill: Byte = 7) = EnrollmentChallenge(id,
        Base64.getEncoder().encodeToString(ByteArray(32) { fill }), ByteArray(32) { 8 }, now.plusSeconds(120))
    private fun grant(id: String = firstId) = EnrollmentGrant(session, id, session, "hardware", "verified")

    private class MemoryState : InstallationStore {
        var value: InstallationRecord? = null
        override fun read() = value
        override fun write(record: InstallationRecord?) { value = record }
    }
    private class JcaKeys : InstallationKeys {
        private val keys = mutableMapOf<String, KeyPair>()
        var generations = 0
        override fun exists(alias: String) = keys.containsKey(alias)
        override fun generate(alias: String, challenge: ByteArray, strongBox: Boolean): KeyMaterial {
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
    }

    private val keys = JcaKeys()
    private val store = MemoryState()
    private fun app(versionCode: Long?) = SentomaruClient(config, keys, store, clock, appVersionCode = versionCode)
    private fun signs(client: SentomaruClient) =
        client.sign("POST", "https://consumer.example/submit", "submit", "{}".toByteArray())

    @Test fun notEnrolledNeverAsks() {
        assertNull(app(42).reenrollmentReason())
    }

    @Test fun sameVersionDoesNotAskForReenrollment() {
        app(42).enroll(challenge()) { grant() }
        assertEquals(42L, store.value!!.versionCode)
        val restarted = app(42)
        assertNull(restarted.reenrollmentReason())
        assertEquals(InstallationState.Enrolled, restarted.state())
    }

    @Test fun updatedAppAsksForReenrollmentButKeepsSigning() {
        app(42).enroll(challenge()) { grant() }
        val updated = app(43)
        assertEquals(ReenrollmentReason.APP_UPDATED, updated.reenrollmentReason())
        assertEquals(InstallationState.Enrolled, updated.state()) // not a new state: apps that only check state still sign
        signs(updated)
        assertEquals(1, keys.generations) // the SDK never re-enrolls behind the app's back
    }

    @Test fun downgradeAlsoCountsAsDifferent() {
        app(43).enroll(challenge()) { grant() }
        assertEquals(ReenrollmentReason.APP_UPDATED, app(42).reenrollmentReason())
    }

    @Test fun rotationWithFreshAttestationStoresTheNewVersion() {
        app(42).enroll(challenge()) { grant() }
        val updated = app(43)
        val oldAlias = store.value!!.alias
        updated.rotate(challenge(secondId, 9)) { grant(secondId) }
        assertEquals(2, keys.generations) // a new key, so a new Key Attestation naming the running versionCode
        assertNotEquals(oldAlias, store.value!!.alias)
        assertEquals(43L, store.value!!.versionCode)
        assertNull(updated.reenrollmentReason())
        assertNull(app(43).reenrollmentReason())
    }

    /**
     * Single-use challenges as the server enforces them (p0-attestation-profile): the first body of a challenge wins;
     * an identical replay gets the original grant back, another body for the same challenge gets 409
     * `enrollment-conflict` (here a ServerRejected, as the transports map a refusal).
     */
    private class SingleUseServer {
        private val seen = mutableMapOf<String, ByteArray>()
        var conflicts = 0
        var lose = false // the next answer is lost after the server stored it
        fun send(message: SignedMessage): EnrollmentGrant {
            val id = message.header("x-sentomaru-session")!!
            val body = message.body()
            val first = seen.getOrPut(id) { body }
            if (!first.contentEquals(body)) {
                conflicts++
                throw SentomaruException(EnrollmentError.ServerRejected(EnrollmentError.Rejection.INVALID))
            }
            if (lose) { lose = false; throw IOException("answer lost") }
            return EnrollmentGrant("cccccccc-bbbb-4ccc-8ddd-eeeeeeeeeeee", id, "dddddddd-bbbb-4ccc-8ddd-eeeeeeeeeeee",
                "hardware", "verified")
        }
    }

    private val server = SingleUseServer()

    /** The old app (42) starts a rotation, the server stores it and the answer is lost; then the app is updated to 43. */
    private fun rotationLostByTheOldVersion() {
        app(42).enroll(challenge()) { server.send(it) }
        server.lose = true
        assertThrows(SentomaruException::class.java) { app(42).rotate(challenge(secondId, 9)) { server.send(it) } }
    }

    @Test fun sameChallengeAfterTheUpdateReplaysAndRecoversTheGrant() { // (a)
        rotationLostByTheOldVersion()
        val updated = app(43)
        assertEquals(ReenrollmentReason.APP_UPDATED, updated.reenrollmentReason())
        val grant = updated.rotate(challenge(secondId, 9)) { server.send(it) } // identical replay
        assertEquals(secondId, grant.keyId)
        assertEquals(0, server.conflicts)
        assertEquals(2, keys.generations) // enroll + the old rotation key; no new key for the replay
        assertEquals(42L, store.value!!.versionCode)
        assertEquals(ReenrollmentReason.APP_UPDATED, updated.reenrollmentReason()) // still asks: needs a NEW challenge
    }

    @Test fun newChallengeAfterTheUpdateGetsAFreshKeyAndStopsAsking() { // (b) and (c)
        rotationLostByTheOldVersion()
        val updated = app(43)
        val thirdId = "33333333-4444-4555-8666-777777777777"
        // D-04d: the lost rotation was sent, so the new challenge first resends it and adopts its grant (version 42) ...
        assertEquals(secondId, updated.rotate(challenge(thirdId, 11)) { server.send(it) }.keyId)
        assertEquals(ReenrollmentReason.APP_UPDATED, updated.reenrollmentReason())
        // ... and the next new challenge gets the fresh key.
        updated.rotate(challenge("55555555-6666-4777-8888-999999999999", 15)) { server.send(it) }
        assertEquals(0, server.conflicts)
        assertEquals(3, keys.generations) // a fresh key, attested by 43
        assertEquals(43L, store.value!!.versionCode)
        assertNull(updated.reenrollmentReason()) // (c) no loop: the next cold start does not ask again
        assertNull(app(43).reenrollmentReason())
    }

    @Test fun recoveredReplayThenANewChallengeEndsTheRequest() { // (a) then (b): no loop
        rotationLostByTheOldVersion()
        val updated = app(43)
        updated.rotate(challenge(secondId, 9)) { server.send(it) }
        assertEquals(ReenrollmentReason.APP_UPDATED, updated.reenrollmentReason())
        updated.rotate(challenge("44444444-5555-4666-8777-888888888888", 13)) { server.send(it) }
        assertEquals(0, server.conflicts)
        assertEquals(43L, store.value!!.versionCode)
        assertNull(updated.reenrollmentReason())
    }

    @Test fun nonPositiveRunningVersionIsUnknown() {
        app(42).enroll(challenge()) { grant() }
        assertNull(app(0).reenrollmentReason())
        assertNull(app(-5).reenrollmentReason())
        app(42).reset()
        app(0).enroll(challenge(secondId, 9)) { grant(secondId) }
        assertNull(store.value!!.versionCode) // never stored as a version
    }

    @Test fun pendingRotationOfTheSameVersionIsStillRetriedWithTheSameBody() {
        app(42).enroll(challenge()) { grant() }
        var frozen: ByteArray? = null
        assertThrows(SentomaruException::class.java) {
            app(42).rotate(challenge(secondId, 9)) { frozen = it.body(); throw IOException() }
        }
        app(42).rotate(challenge(secondId, 9)) { assertArrayEquals(frozen, it.body()); grant(secondId) }
        assertEquals(2, keys.generations)
        assertEquals(42L, store.value!!.versionCode)
    }

    @Test fun oldRecordWithOwnershipButNoBodyAttestsTheRunningVersionWhenTheKeyIsNew() {
        // A record from before D-04b written right before key generation (process death): alias, challenge, no body.
        store.value = InstallationRecord(config.identity, "sentomaru.v1.${config.identity}.v1.old", challenge(), false)
        app(43).enroll(challenge()) { grant() }
        assertEquals(1, keys.generations)
        assertEquals(43L, store.value!!.versionCode)
    }

    @Test fun oldRecordWithOwnershipAndAnExistingKeyStaysUnknown() {
        val alias = "sentomaru.v1.${config.identity}.v1.old"
        keys.generate(alias, ByteArray(32), false) // the old SDK generated the key, the body was never written
        store.value = InstallationRecord(config.identity, alias, challenge(), false)
        val updated = app(43)
        updated.enroll(challenge()) { grant() }
        assertNull(store.value!!.versionCode) // its attestation is of an unknown version: never forces re-enrollment
        assertNull(updated.reenrollmentReason())
    }

    @Test fun resetAndEnrollAlsoClearTheRequest() {
        app(42).enroll(challenge()) { grant() }
        val updated = app(43)
        updated.reset()
        assertNull(updated.reenrollmentReason())
        updated.enroll(challenge(secondId, 9)) { grant(secondId) }
        assertEquals(43L, store.value!!.versionCode)
        assertNull(updated.reenrollmentReason())
    }

    @Test fun recordWithoutStoredVersionIsUnknownAndNeverForcesReenrollment() {
        app(null).enroll(challenge()) { grant() } // a record written before D-04b has no versionCode
        assertNull(store.value!!.versionCode)
        val updated = app(43)
        assertNull(updated.reenrollmentReason())
        updated.rotate(challenge(secondId, 9)) { grant(secondId) } // the next enrollment stores it
        assertEquals(43L, store.value!!.versionCode)
        assertEquals(ReenrollmentReason.APP_UPDATED, app(44).reenrollmentReason())
    }

    @Test fun unknownRunningVersionNeverAsks() {
        app(42).enroll(challenge()) { grant() }
        assertNull(app(null).reenrollmentReason())
    }

    @Test fun enrollmentBodyFrozenByTheOldVersionKeepsItsVersion() {
        assertThrows(SentomaruException::class.java) { app(42).enroll(challenge()) { throw IOException() } }
        val updated = app(43)
        updated.enroll(challenge()) { grant() } // same frozen bytes, attestation of version 42
        assertEquals(42L, store.value!!.versionCode)
        assertEquals(ReenrollmentReason.APP_UPDATED, updated.reenrollmentReason())
    }

    @Test fun renewalAndStaleGrantKeepTheStoredVersion() {
        app(42).enroll(challenge()) { grant() }
        val client = app(42)
        client.markGrantStale()
        assertEquals(42L, store.value!!.versionCode)
        client.renew { RenewedGrant(session, firstId, "bbbbbbbb-bbbb-4ccc-8ddd-eeeeeeeeeeee", 600) }
        assertEquals(42L, store.value!!.versionCode)
        assertNull(client.reenrollmentReason())
    }

    @Test fun storedVersionCodeIsReadTolerantly() {
        assertNull(StoredVersionCode.parse(null)) // old JSON without the member (opt gives null)
        assertNull(StoredVersionCode.parse(Any())) // JSON null (JSONObject.NULL) or any other object
        assertNull(StoredVersionCode.parse("42"))
        assertNull(StoredVersionCode.parse(-1))
        assertNull(StoredVersionCode.parse(0L))
        assertNull(StoredVersionCode.parse(42.0))
        assertNull(StoredVersionCode.parse(1.5))
        assertEquals(42L, StoredVersionCode.parse(42))
        assertEquals(5_000_000_000L, StoredVersionCode.parse(5_000_000_000L))
        assertEquals(42L, StoredVersionCode.serialize(42L))
        assertNull(StoredVersionCode.serialize(null))
        assertNull(StoredVersionCode.serialize(-3L))
    }

    @Test fun lostGrantIsEnrollmentRequiredNotAReenrollmentReason() {
        app(42).enroll(challenge()) { grant() }
        val updated = app(43)
        assertThrows(SentomaruException::class.java) {
            updated.renew { throw SentomaruException(EnrollmentError.EnrollmentRequired()) }
        }
        assertEquals(InstallationState.EnrollmentRequired, updated.state())
        assertNull(updated.reenrollmentReason()) // the state already says "enroll again"
    }
}
