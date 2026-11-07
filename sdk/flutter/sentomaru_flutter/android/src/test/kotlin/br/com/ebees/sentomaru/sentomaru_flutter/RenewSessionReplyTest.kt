package br.com.ebees.sentomaru.sentomaru_flutter

import br.com.ebees.sentomaru.core.SentomaruException
import br.com.ebees.sentomaru.sdk.*
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNull
import org.junit.Assert.assertThrows
import org.junit.Test
import java.security.KeyPair
import java.security.KeyPairGenerator
import java.security.Signature
import java.security.spec.ECGenParameterSpec
import java.time.Clock
import java.time.Instant
import java.time.ZoneOffset
import java.util.Base64

/**
 * 0.9.2 (review of #184): what `handleRenewSession` replies, from a real [SentomaruClient] snapshot. The silent
 * renewal of `sign` (`renewIfDue`) fails with a suspension; the explicit `renewSession` then gets `RenewalBackoff`
 * with `ServerRejected:SUSPENDED` in details. Only the `result.error` call itself (main looper) is not exercised here.
 */
class RenewSessionReplyTest {
    private val now = Instant.parse("2026-10-09T10:00:00Z")
    private val session = "aaaaaaaa-bbbb-4ccc-8ddd-eeeeeeeeeeee"
    private val keyId = "11111111-2222-4333-8444-555555555555"

    private class MovingClock(var instant: Instant) : Clock() {
        override fun getZone() = ZoneOffset.UTC
        override fun withZone(zone: java.time.ZoneId?) = this
        override fun instant() = instant
    }

    private class MemoryStore : InstallationStore {
        var record: InstallationRecord? = null
        override fun read() = record
        override fun write(record: InstallationRecord?) { this.record = record }
    }

    private class JcaKeys : InstallationKeys {
        val keys = mutableMapOf<String, KeyPair>()
        override fun exists(alias: String) = keys.containsKey(alias)
        override fun generate(alias: String, challenge: ByteArray, strongBox: Boolean): KeyMaterial {
            keys[alias] = KeyPairGenerator.getInstance("EC").apply { initialize(ECGenParameterSpec("secp256r1")) }
                .generateKeyPair()
            return material(alias)
        }
        override fun material(alias: String) = KeyMaterial(keys.getValue(alias).public.encoded, emptyList())
        override fun sign(alias: String, bytes: ByteArray): ByteArray =
            Signature.getInstance("SHA256withECDSAinP1363Format").run {
                initSign(keys.getValue(alias).private); update(bytes); sign()
            }
        override fun delete(alias: String) { keys.remove(alias) }
        override fun deleteOwned(prefix: String) { keys.keys.filter { it.startsWith(prefix) }.forEach { keys.remove(it) } }
    }

    private val clock = MovingClock(now)

    private fun client(renewal: Boolean = true): SentomaruClient {
        val cfg = SentomaruConfig("org", "app", "hml", setOf("api.example.test"), "https://api.example.test/enroll",
            renewalUrl = if (renewal) "https://api.example.test/sessions" else null)
        return SentomaruClient(cfg, JcaKeys(), MemoryStore(), clock).also {
            it.enroll(EnrollmentChallenge(keyId, Base64.getEncoder().encodeToString(ByteArray(32) { 1 }),
                ByteArray(32) { 2 }, now.plusSeconds(300))) { EnrollmentGrant(session, keyId, session, "hardware", "verified") }
        }
    }

    private fun reply(c: SentomaruClient) = SentomaruFlutterPlugin.renewalRefusalReply(c.renewalGate())

    @Test fun afterASilentSuspendedRenewalTheRefusalCarriesTheSuspension() {
        val c = client()
        clock.instant = now.plusSeconds(700) // grant due
        assertThrows(SentomaruException::class.java) {
            c.renewIfDue { throw SentomaruException(EnrollmentError.ServerRejected(EnrollmentError.Rejection.SUSPENDED)) }
        }
        val refusal = reply(c)!!
        assertEquals("RenewalBackoff", refusal.code)
        assertEquals("ServerRejected:SUSPENDED", refusal.details)
    }

    @Test fun aTransientFailureCarriesItsOwnCode() {
        val c = client()
        clock.instant = now.plusSeconds(700)
        assertThrows(SentomaruException::class.java) { c.renewIfDue { throw java.io.IOException("down") } }
        val refusal = reply(c)!!
        assertEquals("RenewalBackoff", refusal.code)
        assertEquals("NetworkUnavailable", refusal.details)
    }

    @Test fun outsideTheBackoffThereIsNoRefusal() {
        val c = client()
        clock.instant = now.plusSeconds(700)
        assertThrows(SentomaruException::class.java) {
            c.renewIfDue { throw SentomaruException(EnrollmentError.ServerRejected(EnrollmentError.Rejection.SUSPENDED)) }
        }
        clock.instant = clock.instant.plus(SentomaruClient.SUSPENDED_RENEWAL_BACKOFF)
        assertNull(reply(c))
    }

    @Test fun withoutARenewalUrlTheRefusalIsParamsWithoutDetails() {
        val refusal = reply(client(renewal = false))!!
        assertEquals("InvalidRequest:PARAMS", refusal.code)
        assertNull(refusal.details)
    }
}
