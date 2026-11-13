package br.com.ebees.sentomaru.sdk

import br.com.ebees.sentomaru.core.SentomaruException
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

/** D-04d: rotate() carries the proof made with the current key; enroll() never does. */
class ReenrollmentProofTest {
    private val now = Instant.parse("2026-10-21T12:00:00Z")
    private val clock = Clock.fixed(now, ZoneOffset.UTC)
    private val installation = "11111111-2222-4333-8444-555555555555"
    private val firstId = "aaaaaaaa-bbbb-4ccc-8ddd-eeeeeeeeeeee"
    private val rotateId = "66666666-7777-4888-9999-aaaaaaaaaaaa"
    private val config = SentomaruConfig("org", "app", "prd", setOf("consumer.example"), "https://consumer.example/enroll")

    private fun challenge(id: String, fill: Byte) = EnrollmentChallenge(id,
        Base64.getEncoder().encodeToString(ByteArray(32) { fill }), ByteArray(32) { (fill + 1).toByte() }, now.plusSeconds(120))

    private class MemoryState : InstallationStore {
        var value: InstallationRecord? = null
        override fun read() = value
        override fun write(record: InstallationRecord?) { value = record }
    }

    private class JcaKeys : InstallationKeys {
        val keys = mutableMapOf<String, KeyPair>()
        var failSign = false
        override fun exists(alias: String) = keys.containsKey(alias)
        override fun generate(alias: String, challenge: ByteArray, strongBox: Boolean): KeyMaterial {
            keys[alias] = KeyPairGenerator.getInstance("EC").apply { initialize(ECGenParameterSpec("secp256r1")) }.generateKeyPair()
            return material(alias)
        }
        override fun material(alias: String) = KeyMaterial(keys.getValue(alias).public.encoded, emptyList())
        override fun sign(alias: String, bytes: ByteArray): ByteArray {
            if (failSign) throw SentomaruException(EnrollmentError.KeyInvalidated())
            return Signature.getInstance("SHA256withECDSAinP1363Format").run { initSign(keys.getValue(alias).private); update(bytes); sign() }
        }
        override fun delete(alias: String) { keys.remove(alias) }
        override fun deleteOwned(prefix: String) { keys.keys.filter { it.startsWith(prefix) }.forEach { keys.remove(it) } }
        fun verify(alias: String, bytes: ByteArray, signature: ByteArray) = Signature.getInstance("SHA256withECDSAinP1363Format")
            .run { initVerify(keys.getValue(alias).public); update(bytes); verify(signature) }
    }

    private val member = Regex(",\"predecessor\":\\{\"installationId\":\"([0-9a-f-]{36})\",\"signature\":\"([A-Za-z0-9+/=]{88})\"}(,\"sdkModes\":\\{[^}]*})?(,\"integrityToken\":\"[^\"]+\")?}$")

    /** Same literal as the server test ReenrollmentTests.Message_is_the_documented_canonical_form. */
    @Test fun messageIsTheDocumentedCanonicalForm() {
        val message = ReenrollmentProof.message(config, "11111111-2222-3333-4444-555555555555",
            "66666666-7777-8888-9999-AAAAAAAAAAAA", byteArrayOf(1, 2, 3))
        assertEquals("sentomaru-reenroll-v1\norg\napp\nprd\n11111111-2222-3333-4444-555555555555\n" +
            "66666666-7777-8888-9999-aaaaaaaaaaaa\n039058c6f2c0cb492c533b0a4d14ef77cc0f78abccced5287d84a1a2011cfb81",
            String(message, Charsets.UTF_8))
    }

    @Test fun rotationBodyCarriesTheProofOfTheCurrentKeyAndEnrollmentNone() {
        val keys = JcaKeys(); val store = MemoryState()
        val client = SentomaruClient(config, keys, store, clock)
        var enrolled = ""
        client.enroll(challenge(firstId, 3)) {
            enrolled = String(it.body())
            EnrollmentGrant(installation, firstId, firstId, "hardware", "verified")
        }
        assertFalse(enrolled.contains("predecessor"))
        val oldAlias = store.value!!.alias

        var sent = ""
        client.rotate(challenge(rotateId, 5)) {
            sent = String(it.body())
            EnrollmentGrant("22222222-3333-4444-8555-666666666666", rotateId, rotateId, "hardware", "verified")
        }
        val (named, signature) = member.find(sent)!!.destructured
        assertEquals(installation, named)
        val newSpki = keys.material(store.value!!.alias).publicKey()
        assertTrue(keys.verify(oldAlias, ReenrollmentProof.message(config, installation, rotateId, newSpki),
            Base64.getDecoder().decode(signature)))
        assertTrue(sent.startsWith("{\"challenge\":\"")) // the rest of the schema is unchanged
    }

    @Test fun retryResendsTheFrozenProof() {
        val keys = JcaKeys(); val store = MemoryState()
        val client = SentomaruClient(config, keys, store, clock)
        client.enroll(challenge(firstId, 3)) { EnrollmentGrant(installation, firstId, firstId, "hardware", "verified") }
        val bodies = mutableListOf<String>()
        val error = assertThrows(SentomaruException::class.java) {
            client.rotate(challenge(rotateId, 5)) { bodies += String(it.body()); throw IOException() }
        }
        assertEquals("NetworkUnavailable", error.error.code)
        client.rotate(challenge(rotateId, 5)) {
            bodies += String(it.body())
            EnrollmentGrant("22222222-3333-4444-8555-666666666666", rotateId, rotateId, "hardware", "verified")
        }
        assertEquals(2, bodies.size)
        assertEquals(bodies[0], bodies[1]) // identical replay on the server
    }

    @Test fun failedProofDeletesTheNewKeyAndKeepsTheCurrentOne() {
        val keys = JcaKeys(); val store = MemoryState()
        val client = SentomaruClient(config, keys, store, clock)
        client.enroll(challenge(firstId, 3)) { EnrollmentGrant(installation, firstId, firstId, "hardware", "verified") }
        val oldAlias = store.value!!.alias
        keys.failSign = true
        val error = assertThrows(SentomaruException::class.java) {
            client.rotate(challenge(rotateId, 5)) { throw AssertionError("must not send") }
        }
        assertEquals("KeyInvalidated", error.error.code)
        assertEquals(setOf(oldAlias), keys.keys.keys)
        assertNull(store.value!!.pendingRotation)
        assertEquals(oldAlias, store.value!!.alias)
    }
}
