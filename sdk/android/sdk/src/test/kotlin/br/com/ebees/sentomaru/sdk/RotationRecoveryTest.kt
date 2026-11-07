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
import java.util.UUID
import org.junit.Assert.*
import org.junit.Test

/**
 * D-04d review item 2: a rotation whose body was sent and committed, with the answer lost, is recovered by resending
 * that frozen body even when the app asks again with a NEW challenge (the old installation is superseded and could
 * never prove a second rotation). The fake server follows the contract: single-use challenges, identical replay → the
 * original grant even after expiry, an expired unused challenge → `challenge-invalid`, a predecessor that is not the
 * live installation → `401 predecessor-invalid` (the transport throws [EnrollmentError.ReenrollmentRefused]).
 */
class RotationRecoveryTest {
    private val now = Instant.parse("2026-10-21T12:00:00Z")
    private val clock = Clock.fixed(now, ZoneOffset.UTC)
    private val config = SentomaruConfig("org", "app", "hml", setOf("consumer.example"), "https://consumer.example/enroll")
    private fun challenge(fill: Byte) = EnrollmentChallenge(UUID.nameUUIDFromBytes(byteArrayOf(fill)).toString(),
        Base64.getEncoder().encodeToString(ByteArray(32) { fill }), ByteArray(32) { 8 }, now.plusSeconds(120))

    private class MemoryState : InstallationStore {
        var value: InstallationRecord? = null
        override fun read() = value
        override fun write(record: InstallationRecord?) { value = record }
    }
    private class JcaKeys : InstallationKeys {
        val keys = mutableMapOf<String, KeyPair>()
        var generations = 0
        override fun exists(alias: String) = keys.containsKey(alias)
        override fun generate(alias: String, challenge: ByteArray, strongBox: Boolean): KeyMaterial {
            generations++
            keys[alias] = KeyPairGenerator.getInstance("EC").apply { initialize(ECGenParameterSpec("secp256r1")) }.generateKeyPair()
            return material(alias)
        }
        override fun material(alias: String) = KeyMaterial(keys.getValue(alias).public.encoded, emptyList())
        override fun sign(alias: String, bytes: ByteArray) = Signature.getInstance("SHA256withECDSAinP1363Format")
            .run { initSign(keys.getValue(alias).private); update(bytes); sign() }
        override fun delete(alias: String) { keys.remove(alias) }
        override fun deleteOwned(prefix: String) { keys.keys.filter { it.startsWith(prefix) }.forEach { keys.remove(it) } }
    }

    private class Server {
        private class Committed(val body: ByteArray, val grant: EnrollmentGrant)
        private val committed = mutableMapOf<String, Committed>()
        val expired = mutableSetOf<String>()
        var live: String? = null
        var down = false // the request never reaches the server
        var lose = false // the next answer is lost after the server committed
        var generic: Int? = null // a proxy answers this generic 4xx, without a Sentomaru code (transport: INVALID)
        val seen = mutableListOf<String>()
        private val predecessor = Regex("\"predecessor\":\\{\"installationId\":\"([0-9a-f-]{36})\"")

        fun send(message: SignedMessage): EnrollmentGrant {
            if (down) throw IOException("unreachable")
            generic?.let { reject(EnrollmentError.Rejection.INVALID) }
            val id = message.header("x-sentomaru-session")!!
            seen += id
            val body = message.body()
            committed[id]?.let {
                if (!it.body.contentEquals(body)) reject(EnrollmentError.Rejection.CONFLICT) // 409 enrollment-conflict
                return it.grant // identical replay, even after the challenge expired
            }
            if (id in expired) reject(EnrollmentError.Rejection.EXPIRED) // 401 challenge-invalid
            val named = predecessor.find(String(body, Charsets.UTF_8))?.groupValues?.get(1)
            if (named != null && named != live) throw SentomaruException(EnrollmentError.ReenrollmentRefused())
            val grant = EnrollmentGrant(UUID.randomUUID().toString(), id, UUID.randomUUID().toString(), "hardware", "verified")
            committed[id] = Committed(body, grant)
            live = grant.installationId
            if (lose) { lose = false; throw IOException("answer lost") }
            return grant
        }

        /** Another body committed [challengeId] (the stored one never will be). */
        fun commitOther(challengeId: String) {
            committed[challengeId] = Committed("other".toByteArray(), EnrollmentGrant(UUID.randomUUID().toString(),
                challengeId, UUID.randomUUID().toString(), "hardware", "verified"))
        }

        private fun reject(reason: EnrollmentError.Rejection): Nothing =
            throw SentomaruException(EnrollmentError.ServerRejected(reason))
    }

    private val keys = JcaKeys()
    private val store = MemoryState()
    private val server = Server()
    private fun app() = SentomaruClient(config, keys, store, clock)
    private fun code(block: () -> Unit) = assertThrows(SentomaruException::class.java) { block() }.error.code

    private val c1 = challenge(1)
    private val c2 = challenge(2)
    private val c3 = challenge(3)
    private val c4 = challenge(4)

    private fun enrolled(): EnrollmentGrant = app().enroll(c1) { server.send(it) }

    /** Rotation with [c2] committed by the server, answer lost; then [c2] expires. */
    private fun committedWithTheAnswerLost() {
        enrolled()
        server.lose = true
        assertEquals("NetworkUnavailable", code { app().rotate(c2) { server.send(it) } })
        assertTrue(store.value!!.pendingRotation!!.sent)
        server.expired += c2.id
    }

    @Test fun lostAnswerExpiredChallengeAndANewChallengeRecoverTheOriginalGrant() {
        committedWithTheAnswerLost()
        val committedId = server.live
        val grant = app().rotate(c3) { server.send(it) }
        assertEquals(c2.id, grant.keyId) // the original grant of the committed body
        assertEquals(committedId, grant.installationId)
        assertEquals(listOf(c1.id, c2.id, c2.id), server.seen) // c3 is never used: no second rotation
        assertEquals(2, keys.generations)
        assertNull(store.value!!.pendingRotation)
        assertEquals(c2.id, store.value!!.challenge.id)
        // The adopted key signs and the next rotation is proven by it.
        assertEquals(c4.id, app().rotate(c4) { server.send(it) }.keyId)
    }

    @Test fun aNetworkErrorOnTheResendKeepsThePendingRotation() {
        committedWithTheAnswerLost()
        val alias = store.value!!.pendingRotation!!.alias
        server.down = true
        assertEquals("NetworkUnavailable", code { app().rotate(c3) { server.send(it) } })
        assertEquals(alias, store.value!!.pendingRotation!!.alias)
        assertTrue(keys.exists(alias))
        server.down = false
        assertEquals(c2.id, app().rotate(c4) { server.send(it) }.keyId)
    }

    @Test fun aSentBodyTheServerNeverAcceptedIsDroppedAndTheNewChallengeRotates() {
        enrolled()
        server.down = true
        assertEquals("NetworkUnavailable", code { app().rotate(c2) { server.send(it) } })
        val stale = store.value!!.pendingRotation!!
        assertTrue(stale.sent)
        server.down = false
        server.expired += c2.id
        val grant = app().rotate(c3) { server.send(it) }
        assertEquals(c3.id, grant.keyId)
        assertEquals(listOf(c1.id, c2.id, c3.id), server.seen) // refused as expired, then the new rotation
        assertFalse(keys.exists(stale.alias))
        assertEquals(3, keys.generations)
    }

    @Test fun withoutAPreviousSendTheD04bRuleHolds() {
        enrolled()
        server.down = true
        assertEquals("NetworkUnavailable", code { app().rotate(c2) { server.send(it) } })
        server.down = false
        // As written by an SDK before D-04d (no `sent` member): the stale rotation is dropped without a resend.
        val record = store.value!!
        val old = record.pendingRotation!!
        store.value = InstallationRecord(record.scopeIdentity, record.alias, record.challenge, record.strongBox,
            record.body(), record.grant, record.requiresHardware, record.generation, record.retiredKeys,
            PendingRotation(old.alias, old.challenge, old.strongBox, old.body(), old.requiresHardware, old.versionCode),
            record.versionCode)
        assertEquals(c3.id, app().rotate(c3) { server.send(it) }.keyId)
        assertEquals(listOf(c1.id, c3.id), server.seen)
        assertFalse(keys.exists(old.alias))
    }

    @Test fun anOlderSdkRecordThatLostACommittedRotationGetsTheTypedRefusal() {
        committedWithTheAnswerLost()
        val record = store.value!!
        val old = record.pendingRotation!!
        store.value = InstallationRecord(record.scopeIdentity, record.alias, record.challenge, record.strongBox,
            record.body(), record.grant, record.requiresHardware, record.generation, record.retiredKeys,
            PendingRotation(old.alias, old.challenge, old.strongBox, old.body(), old.requiresHardware, old.versionCode),
            record.versionCode)
        // The previous installation is superseded: a fresh proof with its key is refused; only reset() + enroll() remain.
        assertEquals("ReenrollmentRefused", code { app().rotate(c3) { server.send(it) } })
    }

    @Test fun aQuarantinedInstallationIsReenrollmentRefusedAndTheResendDropsThePending() {
        enrolled()
        server.live = null // quarantined by the operator
        assertEquals("ReenrollmentRefused", code { app().rotate(c2) { server.send(it) } })
        val pending = store.value!!.pendingRotation!!
        assertTrue(pending.sent)
        assertEquals("ReenrollmentRefused", code { app().rotate(c3) { server.send(it) } })
        assertNull(store.value!!.pendingRotation)
        assertFalse(keys.exists(pending.alias))
        assertEquals(InstallationState.Enrolled, app().state()) // the SDK keeps its record; the app decides to reset
    }

    @Test fun aGenericClientErrorOnTheResendKeepsThePendingRotation() {
        committedWithTheAnswerLost()
        val pending = store.value!!.pendingRotation!!
        for (status in listOf(403, 404, 408, 400)) { // proxy refusal, wrong route, timeout, unreadable body
            server.generic = status
            assertEquals("ServerRejected:INVALID", code { app().rotate(c3) { server.send(it) } })
            assertEquals(pending.alias, store.value!!.pendingRotation!!.alias) // nothing proves it was not accepted
            assertTrue(keys.exists(pending.alias))
        }
        server.generic = null
        assertEquals(c2.id, app().rotate(c4) { server.send(it) }.keyId) // still recovers the committed grant
        assertEquals(2, keys.generations)
    }

    @Test fun aConflictProvesTheBodyWasNotAcceptedAndDropsIt() {
        enrolled()
        server.down = true
        assertEquals("NetworkUnavailable", code { app().rotate(c2) { server.send(it) } })
        server.down = false
        // Another body took c2 meanwhile (e.g. a restored backup of the same app): 409 enrollment-conflict.
        val stale = store.value!!.pendingRotation!!
        server.commitOther(c2.id)
        assertEquals(c3.id, app().rotate(c3) { server.send(it) }.keyId)
        assertFalse(keys.exists(stale.alias))
    }

    @Test fun resetDeletesThePendingRotationKey() {
        committedWithTheAnswerLost()
        val pending = store.value!!.pendingRotation!!
        assertTrue(keys.exists(pending.alias))
        app().reset()
        assertFalse(keys.exists(pending.alias))
        assertTrue(keys.keys.isEmpty())
        assertNull(store.value)
    }
}
