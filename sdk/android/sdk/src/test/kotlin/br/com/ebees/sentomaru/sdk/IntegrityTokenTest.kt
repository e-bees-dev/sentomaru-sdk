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

/** C-04b: the advisory Play Integrity token in the enrollment body (the Sentomaru Play Integrity API contract). */
class IntegrityTokenTest {
    private val now = Instant.parse("2026-10-15T12:00:00Z")
    private val clock = Clock.fixed(now, ZoneOffset.UTC)
    private val id = "11111111-2222-4333-8444-555555555555"
    private val packageName = "com.example.app"
    private val config = SentomaruConfig("org", "app", "hml", setOf("consumer.example"), "https://consumer.example/enroll",
        playIntegrityCloudProjectNumber = 123456789L)
    private fun challenge(seconds: Long = 120, challengeId: String = id, fill: Byte = 8) = EnrollmentChallenge(challengeId,
        Base64.getEncoder().encodeToString(ByteArray(32) { fill }), ByteArray(32) { fill }, now.plusSeconds(seconds))
    private fun grant() = EnrollmentGrant(id, id, id, "unknown", "notEvaluated")

    private class Memory : InstallationStore {
        var value: InstallationRecord? = null
        override fun read() = value
        override fun write(record: InstallationRecord?) { value = record }
    }
    private class Keys : InstallationKeys {
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
    private class Source(private val answer: (String) -> String?) : IntegrityTokenSource {
        val hashes = mutableListOf<String>()
        override fun token(requestHash: String): String? { hashes += requestHash; return answer(requestHash) }
    }

    private fun bodyOf(source: IntegrityTokenSource?, pkg: String? = packageName): String {
        var body = ""
        SentomaruClient(config, Keys(), Memory(), clock, source, pkg).enroll(challenge()) { body = String(it.body()); grant() }
        return body
    }

    @Test fun requestHashMatchesTheServerBinding() {
        // Same vector as IntegrityVerdict.ExpectedNonce / the vendor's integrity vectors check nonce().
        // Hex of the base64url value (a 43-char base64url literal has the shape the secret scan refuses).
        val hash = IntegrityRequestHash.of(challenge(), packageName)
        assertEquals(43, hash.length)
        assertEquals("8fc0560a732022c9ab31de5c846659d014568e9fad6e1847557ee258a3d2493a",
            Base64.getUrlDecoder().decode(hash).joinToString("") { "%02x".format(it) })
    }

    @Test fun tokenIsAppendedToTheSignedBodyBoundToTheChallenge() {
        val source = Source { "opaque-token.part-2_x.Part3" }
        val body = bodyOf(source)
        assertTrue(body.endsWith(",\"integrityToken\":\"opaque-token.part-2_x.Part3\"}"))
        assertEquals(listOf(IntegrityRequestHash.of(challenge(), packageName)), source.hashes)
    }

    @Test fun anyFailureEnrollsWithoutTheToken() {
        for (source in listOf(Source { null }, Source { throw IllegalStateException("no Play services") },
            Source { "bad token with spaces" }, Source { "x\"},\"requiresHardware\":true" }, Source { "" },
            Source { "a".repeat(16385) })) {
            val body = bodyOf(source)
            assertFalse(body, body.contains("integrityToken"))
            assertTrue(body.startsWith("{\"challenge\":"))
        }
    }

    @Test fun withoutSourceOrPackageNoTokenIsAsked() {
        assertFalse(bodyOf(null).contains("integrityToken"))
        val source = Source { "tok" }
        assertFalse(bodyOf(source, pkg = null).contains("integrityToken"))
        assertTrue(source.hashes.isEmpty())
    }

    @Test fun retryResendsTheSameFrozenTokenWithoutAskingAgain() {
        val store = Memory(); val keys = Keys()
        val source = Source { "tok-1" }
        val client = SentomaruClient(config, keys, store, clock, source, packageName)
        var first: ByteArray? = null
        val error = assertThrows(SentomaruException::class.java) {
            client.enroll(challenge()) { first = it.body(); throw IOException("lost") }
        }
        assertEquals("NetworkUnavailable", error.error.code)
        client.enroll(challenge()) { assertArrayEquals(first, it.body()); grant() }
        assertEquals(1, source.hashes.size)
    }

    @Test fun cancellationDuringTheTokenCallCancelsTheEnrollment() {
        val source = Source { Thread.currentThread().interrupt(); null }
        val client = SentomaruClient(config, Keys(), Memory(), clock, source, packageName)
        try {
            val error = assertThrows(SentomaruException::class.java) { client.enroll(challenge()) { grant() } }
            assertEquals("Cancelled", error.error.code)
        } finally {
            Thread.interrupted()
        }
    }

    @Test fun cloudProjectNumberIsValidatedAndNotPartOfTheIdentity() {
        assertThrows(IllegalArgumentException::class.java) {
            SentomaruConfig("org", "app", "hml", setOf("consumer.example"), "https://consumer.example/enroll",
                playIntegrityCloudProjectNumber = 0L)
        }
        val without = SentomaruConfig("org", "app", "hml", setOf("consumer.example"), "https://consumer.example/enroll")
        assertEquals(without.identity, config.identity) // turning Play Integrity on keeps existing installations
    }

    // ---- review fixes (F1–F5)

    @Test fun rotationCarriesItsOwnTokenOrNone() {
        val store = Memory(); val keys = Keys()
        var answer: String? = "tok-enroll"
        val source = Source { answer }
        val client = SentomaruClient(config, keys, store, clock, source, packageName)
        client.enroll(challenge()) { grant() }
        val next = challenge(challengeId = "22222222-2222-4333-8444-555555555555", fill = 9)
        answer = "tok-rotate"
        var body = ""
        client.rotate(next) { body = String(it.body()); EnrollmentGrant(next.id, next.id, next.id, "unknown", "notEvaluated") }
        assertTrue(body.endsWith(",\"integrityToken\":\"tok-rotate\"}"))
        assertEquals(IntegrityRequestHash.of(next, packageName), source.hashes.last())
        val third = challenge(challengeId = "33333333-2222-4333-8444-555555555555", fill = 10)
        answer = null
        client.rotate(third) { body = String(it.body()); EnrollmentGrant(third.id, third.id, third.id, "unknown", "notEvaluated") }
        assertFalse(body.contains("integrityToken"))
    }

    @Test fun encodeDropsAnUnsafeTokenEvenWhenCalledDirectly() {
        val material = Keys().generate("a", ByteArray(32), false)
        for (bad in listOf("a\"b", "a b", "a\\b", "", "a".repeat(16385), "ação")) {
            val body = String(EnrollmentBody.encode(Base64.getEncoder().encodeToString(ByteArray(32)), material, false, config, bad))
            assertFalse(bad, body.contains("integrityToken"))
        }
    }

    @Test fun interruptedExceptionFromACustomSourceCancels() {
        val client = SentomaruClient(config, Keys(), Memory(), clock,
            IntegrityTokenSource { throw InterruptedException("cancel") }, packageName)
        try {
            val error = assertThrows(SentomaruException::class.java) { client.enroll(challenge()) { grant() } }
            assertEquals("Cancelled", error.error.code)
        } finally {
            Thread.interrupted()
        }
    }

    @Test fun challengeCloseToExpiryIsSentWithoutAskingGoogle() {
        val source = Source { "tok" }
        var body = ""
        SentomaruClient(config, Keys(), Memory(), clock, source, packageName)
            .enroll(challenge(seconds = 15)) { body = String(it.body()); grant() }
        assertFalse(body.contains("integrityToken"))
        assertTrue(source.hashes.isEmpty())
    }

    @Test fun theClientIsNotLockedWhileGoogleAnswers() {
        val entered = java.util.concurrent.CountDownLatch(1)
        val release = java.util.concurrent.CountDownLatch(1)
        val client = SentomaruClient(config, Keys(), Memory(), clock, IntegrityTokenSource {
            entered.countDown(); release.await(); "tok"
        }, packageName)
        val worker = Thread { client.enroll(challenge()) { grant() } }
        worker.start()
        assertTrue(entered.await(5, java.util.concurrent.TimeUnit.SECONDS))
        val probe = java.util.concurrent.Executors.newSingleThreadExecutor()
        try {
            // state() takes the client lock: it must not wait for the Google call.
            assertEquals(InstallationState.NotEnrolled, probe.submit<InstallationState> { client.state() }
                .get(2, java.util.concurrent.TimeUnit.SECONDS))
        } finally {
            release.countDown(); worker.join(5000); probe.shutdownNow()
        }
        assertEquals(InstallationState.Enrolled, client.state())
    }

    @Test fun cachedRequesterReusesRepreparesOnceAndKeepsTheProviderOnTransientFailures() {
        var prepares = 0
        val script = ArrayDeque<String>()
        val requester = CachedIntegrityRequester(
            prepare = { prepares++; "provider-$prepares" },
            request = { provider, hash ->
                when (val next = script.removeFirstOrNull()) {
                    "invalid" -> throw IllegalStateException("invalid")
                    "transient" -> throw java.util.concurrent.TimeoutException()
                    else -> "$provider:$hash:${next ?: "ok"}"
                }
            },
            providerInvalid = { it is IllegalStateException })
        assertEquals("provider-1:h:ok", requester.token("h"))
        assertEquals("provider-1:h:ok", requester.token("h")) // reused
        script.addAll(listOf("transient"))
        assertNull(requester.token("h"))
        assertEquals("provider-1:h:ok", requester.token("h")) // a transient failure keeps the provider
        script.addAll(listOf("invalid"))
        assertEquals("provider-2:h:ok", requester.token("h")) // expired provider: prepared again, retried once
        script.addAll(listOf("invalid", "invalid"))
        assertNull(requester.token("h")) // only one retry
        assertEquals(3, prepares) // initial + one per expired provider
    }

    @Test fun cachedRequesterAnswersNullOnPrepareFailureAndPreservesInterruption() {
        val failing = CachedIntegrityRequester<String>({ throw java.io.IOException("no Play services") }, { _, _ -> "x" }, { false })
        assertNull(failing.token("h"))
        val interrupted = CachedIntegrityRequester<String>({ "p" }, { _, _ -> throw InterruptedException() }, { false })
        try {
            assertNull(interrupted.token("h"))
            assertTrue(Thread.currentThread().isInterrupted)
        } finally {
            Thread.interrupted()
        }
    }
}
