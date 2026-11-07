package br.com.ebees.sentomaru.sdk

import br.com.ebees.sentomaru.core.*
import java.io.IOException
import java.security.KeyPair
import java.security.KeyPairGenerator
import java.security.Signature
import java.security.spec.ECGenParameterSpec
import java.time.Clock
import java.time.Duration
import java.time.Instant
import java.time.ZoneId
import java.time.ZoneOffset
import java.util.Base64
import org.junit.Assert.*
import org.junit.Test

/**
 * D-12c: [SentomaruReattestation] by doubles of the consumer's route: every answer of the Sentomaru re-attestation API contract,
 * at most one retry (503 verifier-unavailable, 409 replay) honouring Retry-After, 429 as "not now", the frozen body,
 * the ephemeral key deleted, and never more than two sends of one step per call.
 */
class ReattestationTest {
    private val start = Instant.parse("2026-10-23T12:00:00Z")
    private val id = "11111111-2222-4333-8444-555555555555"
    private val session = "aaaaaaaa-bbbb-4ccc-8ddd-eeeeeeeeeeee"
    private val installation = "99999999-8888-4777-8666-555555555555"
    private val challengeId = "cccccccc-dddd-4eee-8fff-000000000000"
    private val attestationBytes = ByteArray(32) { 9 }
    private val config = SentomaruConfig("org", "app", "hml", setOf("consumer.example"),
        "https://consumer.example/enroll", renewalUrl = "https://consumer.example/renew")
    private val challengeUrl = "https://consumer.example/reattest/challenge"
    private val submitUrl = "https://consumer.example/reattest"

    private class MutableClock(var now: Instant) : Clock() {
        override fun getZone(): ZoneId = ZoneOffset.UTC
        override fun withZone(zone: ZoneId?): Clock = this
        override fun instant(): Instant = now
    }

    private class MemoryState : InstallationStore {
        var value: InstallationRecord? = null
        override fun read() = value
        override fun write(record: InstallationRecord?) { value = record }
    }

    /** JCA keys; a generated key carries a two-certificate fake chain (the server verifies it, not the SDK). */
    private class Keys : InstallationKeys {
        val pairs = mutableMapOf<String, KeyPair>()
        val challenges = mutableListOf<ByteArray>()
        val deleted = mutableListOf<String>()
        var failGenerate: SentomaruException? = null
        var emptyChain = false
        var deleteFailsAfterGenerate = false
        var generated = false
        var onGenerate: () -> Unit = {}
        override fun exists(alias: String) = pairs.containsKey(alias)
        override fun generate(alias: String, challenge: ByteArray, strongBox: Boolean): KeyMaterial {
            generated = true
            onGenerate()
            failGenerate?.let { throw it }
            challenges += challenge
            pairs[alias] = KeyPairGenerator.getInstance("EC").apply { initialize(ECGenParameterSpec("secp256r1")) }.generateKeyPair()
            return material(alias)
        }
        override fun material(alias: String) = KeyMaterial(pairs.getValue(alias).public.encoded,
            if (emptyChain) emptyList() else listOf(byteArrayOf(1, 2, 3), byteArrayOf(4, 5)))
        override fun sign(alias: String, bytes: ByteArray) = Signature.getInstance("SHA256withECDSAinP1363Format")
            .run { initSign(pairs.getValue(alias).private); update(bytes); sign() }
        override fun delete(alias: String) {
            if (deleteFailsAfterGenerate && generated && alias.endsWith(".reattest")) throw IllegalStateException("keystore busy")
            deleted += alias; pairs.remove(alias)
        }
        override fun deleteOwned(prefix: String) { pairs.keys.filter { it.startsWith(prefix) }.forEach { pairs.remove(it) } }
        fun verify(alias: String, message: SignedMessage) = Signature.getInstance("SHA256withECDSAinP1363Format").run {
            initVerify(pairs.getValue(alias).public); update(message.signatureBase())
            verify(Base64.getDecoder().decode(message.header("signature")!!.removePrefix("sig1=:").removeSuffix(":")))
        }
    }

    private inner class Fixture(enrolled: Boolean = true) {
        val clock = MutableClock(start)
        val keys = Keys()
        val store = MemoryState()
        val client = SentomaruClient(config, keys, store, clock)
        val sleeps = mutableListOf<Duration>()
        val sent = mutableListOf<SignedMessage>()
        var main = false
        val reattestation = SentomaruReattestation(client, challengeUrl, submitUrl, clock = clock,
            sleeper = { sleeps += it; clock.now = clock.now.plus(it) }, onMainThread = { main })

        init {
            if (enrolled) client.enroll(EnrollmentChallenge(id, Base64.getEncoder().encodeToString(ByteArray(32) { 7 }),
                ByteArray(32) { 8 }, start.plusSeconds(120))) {
                EnrollmentGrant(installation, id, session, "hardware", "verified")
            }
            keys.challenges.clear()
            keys.generated = false
        }

        val installationAlias get() = store.value!!.alias

        /** Answers in order; the step of each message is checked against its operation. */
        fun send(vararg answers: (SignedMessage) -> ReattestationAnswer): (SignedMessage) -> ReattestationAnswer {
            val queue = ArrayDeque(answers.toList())
            return { message ->
                sent += message
                assertTrue("signed by the installation key", keys.verify(installationAlias, message))
                assertEquals(session, message.header("x-sentomaru-session"))
                queue.removeFirstOrNull()?.invoke(message) ?: throw AssertionError("unexpected send ${message.header("x-sentomaru-operation")}")
            }
        }

        fun submits() = sent.filter { it.header("x-sentomaru-operation") == "reattest" }
        fun challenges() = sent.filter { it.header("x-sentomaru-operation") == "reattest_challenge" }
    }

    private fun challengeBody(expires: Instant = start.plusSeconds(120)) =
        """{"challengeId":"$challengeId","attestationChallenge":"${Base64.getEncoder().encodeToString(attestationBytes)}","expiresAt":"${expires.atOffset(ZoneOffset.UTC)}"}"""

    private fun resultBody(replayed: Boolean = false, reason: String? = null, installationId: String = installation,
        challenge: String = challengeId) =
        """{"installationId":"$installationId","challengeId":"$challenge","reattestedAt":"2026-10-23T12:00:01.123456+00:00",""" +
            """"hardwareStatus":"hardware","attestationStatus":"verified","attestationReason":${reason?.let { "\"$it\"" } ?: "null"},""" +
            """"buildMatchState":"not_detected","buildMatchReason":null,"appIdentityState":"not_detected","appIdentityReason":null,"replayed":$replayed}"""

    private val issued: (SignedMessage) -> ReattestationAnswer = { ReattestationAnswer(201, challengeBody()) }
    private fun ok(replayed: Boolean = false, reason: String? = null): (SignedMessage) -> ReattestationAnswer =
        { ReattestationAnswer(200, resultBody(replayed, reason)) }
    private fun error(status: Int, code: String, retryAfter: Long? = null): (SignedMessage) -> ReattestationAnswer =
        { ReattestationAnswer(status, """{"code":"$code"}""", retryAfter) }

    private fun refused(code: String, action: () -> Unit) {
        val error = assertThrows(SentomaruException::class.java) { action() }
        assertEquals(code, error.error.code)
    }

    @Test fun bothStepsSignedWithTheInstallationKeyAndTheEphemeralKeyIsDeleted() {
        val f = Fixture()
        val outcome = f.reattestation.reattest(send = f.send(issued, ok()))
        val result = (outcome as ReattestationCompleted).result
        assertEquals(installation, result.installationId)
        assertEquals("hardware", result.hardwareStatus)
        assertNull(result.attestationReason)
        assertFalse(result.replayed)
        assertEquals(Instant.parse("2026-10-23T12:00:01.123456Z"), result.reattestedAt)
        val (challenge, submit) = f.sent
        assertEquals(challengeUrl, challenge.targetUri)
        assertEquals("reattest_challenge", challenge.header("x-sentomaru-operation"))
        assertEquals("{}", String(challenge.body()))
        assertEquals(submitUrl, submit.targetUri)
        assertEquals("reattest", submit.header("x-sentomaru-operation"))
        assertArrayEquals(attestationBytes, f.keys.challenges.single())
        val alias = "sentomaru.v1.${config.identity}.reattest"
        assertFalse("the ephemeral key never stays", f.keys.exists(alias))
        assertTrue(f.keys.deleted.count { it == alias } >= 2) // before (leftover) and after generating
        val body = String(submit.body())
        assertTrue(body.startsWith("{\"challengeId\":\"$challengeId\",\"publicKey\":\""))
        assertTrue(body.endsWith(",\"attestationChain\":[\"AQID\",\"BAU=\"]}"))
        assertFalse("a new key, not the installation's",
            body.contains(Base64.getEncoder().encodeToString(f.keys.pairs.getValue(f.installationAlias).public.encoded)))
        assertEquals(InstallationState.Enrolled, f.client.state())
    }

    @Test fun completedWaitsTheIntervalLocallyWithoutSending() {
        val f = Fixture()
        f.reattestation.reattestIfDue(send = f.send(issued, ok()))
        assertFalse(f.reattestation.due())
        val notNow = f.reattestation.reattestIfDue { fail("must not send"); throw IllegalStateException() }
        assertEquals(ReattestationWait.NOT_DUE, (notNow as ReattestationNotNow).reason)
        assertEquals(Duration.ofHours(24), notNow.retryAfter)
        f.clock.now = start.plus(Duration.ofHours(24))
        assertTrue(f.reattestation.due())
        val later: (SignedMessage) -> ReattestationAnswer = { ReattestationAnswer(201, challengeBody(f.clock.now.plusSeconds(120))) }
        assertTrue(f.reattestation.reattestIfDue(send = f.send(later, ok())) is ReattestationCompleted)
    }

    @Test fun rateLimitedIsNotNowWithRetryAfterAndNoRetry() {
        for (step in listOf("challenge", "submit")) {
            val f = Fixture()
            val send = if (step == "challenge") f.send(error(429, "rate-limited", 3600)) else f.send(issued, error(429, "rate-limited", 120))
            val outcome = f.reattestation.reattestIfDue(send = send) as ReattestationNotNow
            assertEquals(ReattestationWait.RATE_LIMITED, outcome.reason)
            assertEquals(Duration.ofSeconds(if (step == "challenge") 3600 else 120), outcome.retryAfter)
            assertEquals(step, if (step == "challenge") 1 else 2, f.sent.size)
            assertTrue(f.sleeps.isEmpty())
            assertFalse(f.reattestation.due())
            assertTrue(f.reattestation.reattestIfDue { fail("must not send"); throw IllegalStateException() } is ReattestationNotNow)
            f.clock.now = f.clock.now.plus(outcome.retryAfter)
            assertTrue(f.reattestation.due())
        }
        val f = Fixture()
        val noHeader = f.reattestation.reattest(send = f.send(error(429, "rate-limited"))) as ReattestationNotNow
        assertEquals(SentomaruReattestation.RATE_LIMITED_WAIT, noHeader.retryAfter)
    }

    @Test fun verifierUnavailableIsRetriedOnceWithTheSameBodyAndANewSignature() {
        val f = Fixture()
        val outcome = f.reattestation.reattest(send = f.send(issued, error(503, "verifier-unavailable", 5), ok()))
        assertTrue(outcome is ReattestationCompleted)
        val (first, second) = f.submits()
        assertArrayEquals(first.body(), second.body())
        assertNotEquals(first.header("signature-input"), second.header("signature-input")) // new nonce
        assertEquals(listOf(Duration.ofSeconds(5)), f.sleeps) // Retry-After, above the minimum backoff
        assertEquals(1, f.keys.challenges.size)
    }

    @Test fun verifierUnavailableTwiceIsNotNowAfterOneRetryOnly() {
        val f = Fixture()
        val outcome = f.reattestation.reattest(send = f.send(issued, error(503, "verifier-unavailable"),
            error(503, "verifier-unavailable"))) as ReattestationNotNow
        assertEquals(ReattestationWait.VERIFIER_UNAVAILABLE, outcome.reason)
        assertEquals(SentomaruReattestation.VERIFIER_WAIT, outcome.retryAfter)
        assertEquals(2, f.submits().size)
        assertEquals(listOf(SentomaruReattestation.MIN_RETRY_BACKOFF), f.sleeps) // no Retry-After: the minimum
        assertFalse(f.reattestation.due())
    }

    @Test fun verifierUnavailableWithALongRetryAfterOrNearExpiryIsNotRetried() {
        val long = Fixture()
        val first = long.reattestation.reattest(send = long.send(issued, error(503, "verifier-unavailable", 600))) as ReattestationNotNow
        assertEquals(Duration.ofSeconds(600), first.retryAfter)
        assertEquals(1, long.submits().size)
        assertTrue(long.sleeps.isEmpty())

        val late = Fixture()
        val nearExpiry: (SignedMessage) -> ReattestationAnswer = { ReattestationAnswer(201, challengeBody(start.plusSeconds(11))) }
        val second = late.reattestation.reattest(send = late.send(nearExpiry, error(503, "verifier-unavailable"))) as ReattestationNotNow
        assertEquals(ReattestationWait.VERIFIER_UNAVAILABLE, second.reason)
        assertEquals(1, late.submits().size)
        assertTrue(late.sleeps.isEmpty())
    }

    @Test fun aLaterCallWithTheSameChallengeSendsTheSameBodyWithoutANewKey() {
        val f = Fixture()
        val challenge = (f.reattestation.requestChallenge(f.send(issued)) as ReattestationChallengeIssued).challenge
        f.reattestation.reattest(challenge, send = f.send(error(503, "verifier-unavailable"), error(503, "verifier-unavailable")))
        f.clock.now = start.plusSeconds(30)
        assertTrue(f.reattestation.reattest(challenge, send = f.send(ok(replayed = true))) is ReattestationCompleted)
        assertEquals(1, f.keys.challenges.size)
        assertEquals(1, f.submits().map { String(it.body()) }.distinct().size)
    }

    @Test fun replayIsRetriedOnceThenRefused() {
        val f = Fixture()
        val outcome = f.reattestation.reattest(send = f.send(issued, error(409, "replay"), ok(replayed = true)))
        assertTrue((outcome as ReattestationCompleted).result.replayed)
        assertEquals(2, f.submits().size)

        val twice = Fixture()
        val refused = twice.reattestation.reattest(send = twice.send(issued, error(409, "replay"), error(409, "replay")))
        assertEquals("replay", (refused as ReattestationRefused).code)
        assertEquals(2, twice.submits().size)

        val challengeReplay = Fixture()
        assertTrue(challengeReplay.reattestation.reattest(send = challengeReplay.send(error(409, "replay"),
            { ReattestationAnswer(200, challengeBody()) }, ok())) is ReattestationCompleted)
        assertEquals(2, challengeReplay.challenges().size)
    }

    @Test fun refusalsAreNotRetried() {
        val cases = listOf(
            Triple(403, "reattestation-disabled", "challenge"), Triple(403, "reattestation-unsupported", "challenge"),
            Triple(403, "session-unavailable", "submit"), Triple(403, "installation-suspended", "submit"),
            Triple(403, "operation-context", "submit"), Triple(401, "challenge-invalid", "submit"),
            Triple(409, "reattestation-conflict", "submit"), Triple(400, "reattestation-format", "submit"),
            Triple(401, "proof-invalid", "challenge"),
        )
        for ((status, code, step) in cases) {
            val f = Fixture()
            val send = if (step == "challenge") f.send(error(status, code)) else f.send(issued, error(status, code))
            val outcome = f.reattestation.reattest(send = send) as ReattestationRefused
            assertEquals(code, outcome.code)
            assertEquals(status, outcome.status)
            assertEquals(code, if (step == "challenge") 1 else 2, f.sent.size)
            assertTrue(f.sleeps.isEmpty())
            // Review R I2: a lasting refusal waits 24 h; the others do not start the interval.
            val lasting = code in setOf("reattestation-disabled", "reattestation-unsupported", "installation-suspended")
            assertEquals(code, !lasting, f.reattestation.due())
            if (lasting) {
                assertTrue(f.reattestation.reattestIfDue { throw AssertionError("must not send") } is ReattestationNotNow)
                f.clock.now = f.clock.now.plus(SentomaruReattestation.LASTING_REFUSAL_WAIT)
                assertTrue(f.reattestation.due())
            }
        }
    }

    @Test fun sessionExpiredMarksTheGrantStaleForARenewal() {
        val f = Fixture()
        f.client.renewIfDue { RenewedGrant(installation, id, session, 600) } // fresh grant: renewal not due
        assertFalse(f.client.needsRenewal())
        val outcome = f.reattestation.reattest(send = f.send(error(403, "session-expired"))) as ReattestationRefused
        assertEquals("session-expired", outcome.code)
        assertTrue(f.client.needsRenewal())
    }

    @Test fun networkAndOtherServerFailuresAreNotNowWithoutRetry() {
        val network = Fixture()
        val first = network.reattestation.reattest(send = network.send({ throw IOException("down") })) as ReattestationNotNow
        assertEquals(ReattestationWait.UNAVAILABLE, first.reason)
        assertEquals(1, network.sent.size)
        for (status in listOf(500, 502, 504)) {
            val f = Fixture()
            val outcome = f.reattestation.reattest(send = f.send(issued, { ReattestationAnswer(status, "<html>") })) as ReattestationNotNow
            assertEquals(ReattestationWait.UNAVAILABLE, outcome.reason)
            assertEquals(2, f.sent.size)
        }
        val plain503 = Fixture() // a 503 without the API's code (a proxy): not the verifier, no retry
        assertTrue(plain503.reattestation.reattest(send = plain503.send(issued, { ReattestationAnswer(503, "busy") })) is ReattestationNotNow)
        assertEquals(1, plain503.submits().size)
    }

    @Test fun unreadableOrForeignAnswersAreRefusedNeverCompleted() {
        val bodies = listOf("", "{}", "not json", resultBody(installationId = "00000000-0000-4000-8000-000000000001"),
            resultBody(challenge = "00000000-0000-4000-8000-000000000002"), resultBody().replace("\"replayed\":false", "\"replayed\":0"),
            resultBody() + resultBody(), resultBody().replace("\"hardware\"", "null"))
        for (body in bodies) {
            val f = Fixture()
            val outcome = f.reattestation.reattest(send = f.send(issued, { ReattestationAnswer(200, body) }))
            assertEquals(body, "unexpected-answer", (outcome as ReattestationRefused).code)
            assertTrue(f.reattestation.due())
        }
        for (body in listOf("{}", challengeBody().replace(challengeId, "not-a-uuid"),
            challengeBody().replace(Base64.getEncoder().encodeToString(attestationBytes), "AAAA"))) {
            val f = Fixture()
            assertEquals("unexpected-answer", (f.reattestation.reattest(send = f.send({ ReattestationAnswer(201, body) })) as ReattestationRefused).code)
            assertEquals(1, f.sent.size)
            assertTrue(f.keys.challenges.isEmpty())
        }
    }

    @Test fun revocationUncheckedAsksAgainSoonerThanTheInterval() {
        val f = Fixture()
        f.reattestation.reattest(send = f.send(issued, ok(reason = "revocation_unchecked")))
        f.clock.now = start.plus(SentomaruReattestation.REVOCATION_RETRY)
        assertTrue(f.reattestation.due())
    }

    @Test fun localFailuresSendNothing() {
        val main = Fixture().apply { this.main = true }
        assertThrows(IllegalStateException::class.java) { main.reattestation.reattest { fail("sent"); throw IllegalStateException() } }
        assertTrue(main.sent.isEmpty())

        val expired = Fixture()
        val challenge = ReattestationChallenge(challengeId, attestationBytes, start.minus(SentomaruReattestation.CLOCK_SKEW))
        assertEquals("challenge-invalid", (expired.reattestation.reattest(challenge) { fail("sent"); throw IllegalStateException() }
            as ReattestationRefused).code)
        assertTrue(expired.keys.challenges.isEmpty())

        val keyFailure = Fixture().apply { keys.failGenerate = SentomaruException(EnrollmentError.KeyUnavailable()) }
        refused("KeyUnavailable") { keyFailure.reattestation.reattest(send = keyFailure.send(issued)) }
        assertTrue(keyFailure.submits().isEmpty())

        val noChain = Fixture().apply { keys.emptyChain = true }
        refused("KeyUnavailable") { noChain.reattestation.reattest(send = noChain.send(issued)) }
        assertTrue(noChain.submits().isEmpty())
        assertFalse(noChain.keys.exists("sentomaru.v1.${config.identity}.reattest"))

        val notEnrolled = Fixture(enrolled = false)
        refused("NotEnrolled") { notEnrolled.reattestation.reattest { fail("sent"); throw IllegalStateException() } }
    }

    @Test fun routesMustBeAllowedHttps() {
        val f = Fixture()
        refused("HostNotAllowed") { SentomaruReattestation(f.client, "https://other.example/c", submitUrl) }
        refused("HostNotAllowed") { SentomaruReattestation(f.client, challengeUrl, "http://consumer.example/r") }
        assertThrows(IllegalArgumentException::class.java) { SentomaruReattestation(f.client, challengeUrl, submitUrl, Duration.ZERO) }
    }

    @Test fun neverMoreThanTwoSendsOfOneStepPerCall() {
        val answers = listOf(error(503, "verifier-unavailable"), error(409, "replay"), error(429, "rate-limited"),
            error(503, "verifier-unavailable", 1), ok(), error(500, "x"), error(403, "session-unavailable"))
        for (a in answers) for (b in answers) for (c in answers) {
            val f = Fixture()
            var step = 0
            val outcome = f.reattestation.reattest { message ->
                f.sent += message
                if (message.header("x-sentomaru-operation") == "reattest_challenge") return@reattest issued(message)
                listOf(a, b, c)[step++].invoke(message)
            }
            assertTrue(f.submits().size <= 2)
            assertTrue(f.sleeps.size <= 1)
            assertTrue(outcome is ReattestationCompleted || outcome is ReattestationNotNow || outcome is ReattestationRefused)
        }
    }

    @Test fun dueNeverWaitsForARunningReattestation() {
        val f = Fixture()
        val inside = java.util.concurrent.CountDownLatch(1)
        val release = java.util.concurrent.CountDownLatch(1)
        val worker = Thread {
            f.reattestation.reattest { message ->
                if (message.header("x-sentomaru-operation") == "reattest_challenge") {
                    inside.countDown()
                    release.await(10, java.util.concurrent.TimeUnit.SECONDS)
                }
                ReattestationAnswer(429, "{\"code\":\"rate-limited\"}", 600)
            }
        }
        worker.start()
        assertTrue(inside.await(5, java.util.concurrent.TimeUnit.SECONDS))
        var answered: Boolean? = null
        val reader = Thread { answered = f.reattestation.due() }
        reader.start()
        reader.join(1000)
        assertFalse("due() blocked on the running flow", reader.isAlive)
        assertEquals(true, answered)
        release.countDown()
        worker.join(5000)
        assertFalse(f.reattestation.due()) // the 429 of the flow is visible without a lock
    }

    @Test fun notNowWaitsAreBounded() {
        val zero = Fixture()
        assertEquals(Duration.ofSeconds(60), (zero.reattestation.reattest(send = zero.send(error(429, "rate-limited", 0))) as ReattestationNotNow).retryAfter)
        val huge = Fixture()
        assertEquals(Duration.ofHours(24), (huge.reattestation.reattest(send = huge.send(error(429, "rate-limited", 864_000))) as ReattestationNotNow).retryAfter)
        val verifier = Fixture()
        val wait = (verifier.reattestation.reattest(send = verifier.send(issued, error(503, "verifier-unavailable", 7200))) as ReattestationNotNow).retryAfter
        assertEquals(Duration.ofHours(2), wait)
    }

    @Test fun oversizedAnswersAreNeverParsed() {
        val f = Fixture()
        val padded = resultBody().dropLast(1) + ",\"pad\":\"" + "x".repeat(SentomaruReattestation.MAX_ANSWER_CHARS) + "\"}"
        assertEquals("unexpected-answer", (f.reattestation.reattest(send = f.send(issued, { ReattestationAnswer(200, padded) })) as ReattestationRefused).code)
        val g = Fixture()
        val bigChallenge = challengeBody().dropLast(1) + ",\"pad\":\"" + "x".repeat(SentomaruReattestation.MAX_ANSWER_CHARS) + "\"}"
        assertEquals("unexpected-answer", (g.reattestation.reattest(send = g.send({ ReattestationAnswer(201, bigChallenge) })) as ReattestationRefused).code)
        assertTrue(g.keys.challenges.isEmpty())
    }

    @Test fun aFailedDeleteNeverMasksTheCauseNorFailsTheReattestation() {
        val failing = Fixture().apply {
            keys.failGenerate = SentomaruException(EnrollmentError.KeyUnavailable())
            keys.deleteFailsAfterGenerate = true
        }
        val error = assertThrows(SentomaruException::class.java) { failing.reattestation.reattest(send = failing.send(issued)) }
        assertEquals("KeyUnavailable", error.error.code)
        assertEquals("keystore busy", error.suppressed.single().message)

        val orphan = Fixture().apply { keys.deleteFailsAfterGenerate = true }
        assertTrue(orphan.reattestation.reattest(send = orphan.send(issued, ok())) is ReattestationCompleted)
    }

    @Test fun expiryIsCheckedAgainAfterTheKeyWithClockSkewTolerance() {
        val slow = Fixture()
        slow.keys.onGenerate = { slow.clock.now = start.plusSeconds(120).plus(SentomaruReattestation.CLOCK_SKEW) }
        val outcome = slow.reattestation.reattest(send = slow.send(issued)) as ReattestationRefused
        assertEquals("challenge-invalid", outcome.code)
        assertTrue(slow.submits().isEmpty())

        val skewed = Fixture() // the device clock is 30 s past expiresAt: still sent, the server decides
        skewed.clock.now = start.plusSeconds(150)
        val challenge = ReattestationChallenge(challengeId, attestationBytes, start.plusSeconds(120))
        assertTrue(skewed.reattestation.reattest(challenge, send = skewed.send(ok())) is ReattestationCompleted)
    }
}
