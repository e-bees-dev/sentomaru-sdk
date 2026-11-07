package br.com.ebees.sentomaru.sentomaru_flutter

import br.com.ebees.sentomaru.sdk.*
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNull
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
 * D-04b: what `reenrollmentReason` sends over the channel, from a real [SentomaruClient] that enrolled with one
 * `versionCode` and runs with another. Dart maps `APP_UPDATED` to `ReenrollmentReason.appUpdated` and null to null.
 */
class ReenrollmentReplyTest {
    private val now = Instant.parse("2026-10-21T10:00:00Z")
    private val clock = Clock.fixed(now, ZoneOffset.UTC)
    private val session = "aaaaaaaa-bbbb-4ccc-8ddd-eeeeeeeeeeee"
    private val keyId = "11111111-2222-4333-8444-555555555555"
    private val cfg = SentomaruConfig("org", "app", "hml", setOf("api.example.test"), "https://api.example.test/enroll")

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

    private val keys = JcaKeys()
    private val store = MemoryStore()

    private fun enrolledWith(versionCode: Long?) = SentomaruClient(cfg, keys, store, clock, appVersionCode = versionCode)
        .enroll(EnrollmentChallenge(keyId, Base64.getEncoder().encodeToString(ByteArray(32) { 1 }), ByteArray(32) { 2 },
            now.plusSeconds(300))) { EnrollmentGrant(session, keyId, session, "hardware", "verified") }

    private fun reply(running: Long?) =
        SentomaruFlutterPlugin.reenrollmentReply(SentomaruClient(cfg, keys, store, clock, appVersionCode = running))

    @Test fun updatedAppRepliesAppUpdated() {
        enrolledWith(7)
        assertEquals("APP_UPDATED", reply(8))
        assertEquals("APP_UPDATED", reply(6)) // a downgrade too
    }

    @Test fun sameVersionUnknownVersionOrNoRecordReplyNull() {
        assertNull(reply(8)) // not enrolled
        enrolledWith(7)
        assertNull(reply(7))
        assertNull(reply(null))
    }

    @Test fun installationEnrolledBeforeD04bRepliesNull() {
        enrolledWith(null)
        assertNull(reply(8))
    }
}
