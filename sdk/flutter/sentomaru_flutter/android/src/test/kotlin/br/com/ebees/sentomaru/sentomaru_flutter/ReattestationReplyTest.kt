package br.com.ebees.sentomaru.sentomaru_flutter

import br.com.ebees.sentomaru.hybrid.PluginConfig
import br.com.ebees.sentomaru.core.SentomaruException
import br.com.ebees.sentomaru.core.SignedMessage
import br.com.ebees.sentomaru.sdk.*
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNull
import org.junit.Assert.assertThrows
import org.junit.Assert.assertTrue
import org.junit.Test
import java.io.IOException
import java.security.KeyPair
import java.security.KeyPairGenerator
import java.security.Signature
import java.security.spec.ECGenParameterSpec
import java.time.Clock
import java.time.Duration
import java.time.Instant
import java.time.ZoneOffset
import java.util.Base64

/**
 * D-12e: what `reattestIfDue` sends to Dart for every outcome, from a real [SentomaruClient] and a real
 * [SentomaruReattestation] with doubles of the Keystore and of the consumer's routes; and the reattestation part of
 * the configuration. The worker thread itself (`reattestExecutor`) and `result.success` (main looper) are not run here.
 */
class ReattestationReplyTest {
    private val now = Instant.parse("2026-10-23T10:00:00Z")
    private val installation = "aaaaaaaa-bbbb-4ccc-8ddd-eeeeeeeeeeee"
    private val keyId = "11111111-2222-4333-8444-555555555555"
    private val challengeId = "5f0c7a9e-3b2d-4e1f-8a6c-9d7e2b1f0a34"
    private val host = "api.example.test"
    private val challengeUrl = "https://$host/reattest/challenge"
    private val submitUrl = "https://$host/reattest"

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

    /** JCA keys; the reattestation key has a one-certificate chain (the server verifies it, not this test). */
    private class JcaKeys : InstallationKeys {
        val keys = mutableMapOf<String, KeyPair>()
        var failGenerate = false
        override fun exists(alias: String) = keys.containsKey(alias)
        override fun generate(alias: String, challenge: ByteArray, strongBox: Boolean): KeyMaterial {
            if (failGenerate && alias.endsWith(".reattest")) throw SentomaruException(EnrollmentError.KeyUnavailable())
            if (strongBox) throw SentomaruException(EnrollmentError.StrongBoxUnavailable())
            keys[alias] = KeyPairGenerator.getInstance("EC").apply { initialize(ECGenParameterSpec("secp256r1")) }
                .generateKeyPair()
            return material(alias)
        }
        override fun material(alias: String) = KeyMaterial(keys.getValue(alias).public.encoded, listOf(ByteArray(16) { 7 }))
        override fun sign(alias: String, bytes: ByteArray): ByteArray =
            Signature.getInstance("SHA256withECDSAinP1363Format").run {
                initSign(keys.getValue(alias).private); update(bytes); sign()
            }
        override fun delete(alias: String) { keys.remove(alias) }
        override fun deleteOwned(prefix: String) { keys.keys.filter { it.startsWith(prefix) }.forEach { keys.remove(it) } }
    }

    private val clock = MovingClock(now)
    private val keys = JcaKeys()

    private fun client(): SentomaruClient {
        val cfg = SentomaruConfig("ebees", "sample", "hml", setOf(host), "https://$host/enroll")
        return SentomaruClient(cfg, keys, MemoryStore(), clock).also {
            it.enroll(EnrollmentChallenge(keyId, Base64.getEncoder().encodeToString(ByteArray(32) { 1 }),
                ByteArray(32) { 2 }, now.plusSeconds(300))) { EnrollmentGrant(installation, keyId, installation, "hardware", "verified") }
        }
    }

    private fun reattestation(c: SentomaruClient = client()) =
        SentomaruReattestation(c, challengeUrl, submitUrl, Duration.ofHours(24), clock, sleeper = { clock.instant = clock.instant.plus(it) },
            onMainThread = { false })

    private val challenge = """{"challengeId":"$challengeId","attestationChallenge":"${Base64.getEncoder().encodeToString(ByteArray(32) { 3 })}",""" +
        """"expiresAt":"2026-10-23T10:02:00Z"}"""
    private val result = """{"installationId":"$installation","challengeId":"$challengeId","reattestedAt":"2026-10-23T10:00:01Z",""" +
        """"hardwareStatus":"hardware","attestationStatus":"verified","attestationReason":null,"buildMatchState":"NOT_DETECTED",""" +
        """"buildMatchReason":"build_registered","appIdentityState":"NOT_DETECTED","appIdentityReason":null,"replayed":false}"""

    /** A double of the consumer's routes: one answer per send, in order; records the operations sent. */
    private class Routes(vararg answers: () -> ReattestationAnswer) {
        val queue = ArrayDeque(answers.toList())
        val sent = mutableListOf<String>()
        fun send(signed: SignedMessage): ReattestationAnswer {
            sent += signed.header("x-sentomaru-operation") ?: "?"
            return queue.removeFirst()()
        }
    }

    private fun reply(r: SentomaruReattestation, routes: Routes, strongBox: Boolean = false) =
        SentomaruFlutterPlugin.reattestationReply(r.reattestIfDue(strongBox) { routes.send(it) })

    @Test fun completedCarriesTheServerResultAndStopsBeingDue() {
        val r = reattestation()
        val routes = Routes({ ReattestationAnswer(201, challenge) }, { ReattestationAnswer(200, result) })
        assertTrue(r.due())
        val reply = reply(r, routes)
        assertEquals(listOf("reattest_challenge", "reattest"), routes.sent)
        assertEquals("completed", reply["outcome"])
        @Suppress("UNCHECKED_CAST") val res = reply["result"] as Map<String, Any?>
        assertEquals(installation, res["installationId"])
        assertEquals(challengeId, res["challengeId"])
        assertEquals("2026-10-23T10:00:01Z", res["reattestedAt"])
        assertEquals("NOT_DETECTED", res["buildMatchState"])
        assertEquals("build_registered", res["buildMatchReason"])
        assertNull(res["attestationReason"])
        assertTrue(res.containsKey("appIdentityReason"))
        assertEquals(false, res["replayed"])
        assertFalse(keys.keys.keys.any { it.endsWith(".reattest") }) // the reattestation key never stays
        // due() false for the interval: nothing is sent, the reply says NOT_DUE with what is left.
        assertFalse(r.due())
        val again = reply(r, Routes())
        assertEquals(mapOf("outcome" to "notNow", "reason" to "NOT_DUE", "retryAfterMs" to Duration.ofHours(24).toMillis()), again)
    }

    /** D-06h (0.15.0): the plugin's `reattest` path (the native `reattest`) ignores the local wait that `reattestIfDue`
     * keeps after a completed reattestation, and its reply has the same shape. */
    @Test fun reattestIgnoresTheLocalWaitAndRepliesTheSameWay() {
        val r = reattestation()
        reply(r, Routes({ ReattestationAnswer(201, challenge) }, { ReattestationAnswer(200, result) }))
        assertFalse(r.due())
        assertEquals("notNow", reply(r, Routes())["outcome"]) // reattestIfDue: NOT_DUE, nothing sent
        val routes = Routes({ ReattestationAnswer(201, challenge) }, { ReattestationAnswer(200, result) })
        val now = SentomaruFlutterPlugin.reattestationReply(r.reattest(false) { routes.send(it) })
        assertEquals(listOf("reattest_challenge", "reattest"), routes.sent)
        assertEquals("completed", now["outcome"])
        // A 429 of the server stays "not now", never retried in a loop.
        val limited = Routes({ ReattestationAnswer(429, """{"code":"rate-limited"}""", 3600) })
        assertEquals(mapOf("outcome" to "notNow", "reason" to "RATE_LIMITED", "retryAfterMs" to 3_600_000L),
            SentomaruFlutterPlugin.reattestationReply(r.reattest(false) { limited.send(it) }))
        assertEquals(1, limited.sent.size)
    }

    @Test fun rateLimitedIsNotNowWithItsRetryAfterAndNoRetry() {
        val routes = Routes({ ReattestationAnswer(429, """{"code":"rate-limited"}""", 7200) })
        val r = reattestation()
        assertEquals(mapOf("outcome" to "notNow", "reason" to "RATE_LIMITED", "retryAfterMs" to 7_200_000L), reply(r, routes))
        assertEquals(1, routes.sent.size)
        assertFalse(r.due())
    }

    @Test fun networkFailureIsNotNowUnavailable() {
        val reply = reply(reattestation(), Routes({ throw IOException("down") }))
        assertEquals("notNow", reply["outcome"])
        assertEquals("UNAVAILABLE", reply["reason"])
        assertEquals(60_000L, reply["retryAfterMs"])
    }

    @Test fun verifierUnavailableIsRetriedOnceThenNotNow() {
        val busy = { ReattestationAnswer(503, """{"code":"verifier-unavailable"}""", 2) }
        val routes = Routes({ ReattestationAnswer(201, challenge) }, busy, busy)
        val reply = reply(reattestation(), routes)
        assertEquals(listOf("reattest_challenge", "reattest", "reattest"), routes.sent)
        assertEquals("notNow", reply["outcome"])
        assertEquals("VERIFIER_UNAVAILABLE", reply["reason"])
    }

    @Test fun refusalsKeepTheServerCodeAndStatus() {
        for ((answer, code) in listOf(
            ReattestationAnswer(403, """{"code":"reattestation-disabled"}""") to "reattestation-disabled",
            ReattestationAnswer(403, """{"code":"reattestation-unsupported"}""") to "reattestation-unsupported",
            ReattestationAnswer(403, """{"code":"session-expired"}""") to "session-expired",
            ReattestationAnswer(403, """{"code":"installation-suspended"}""") to "installation-suspended",
            ReattestationAnswer(400, "not json") to "unexpected-answer",
            ReattestationAnswer(201, """{"challengeId":"nope"}""") to "unexpected-answer",
        )) {
            val reply = reply(reattestation(), Routes({ answer }))
            assertEquals(mapOf("outcome" to "refused", "code" to code, "status" to answer.status), reply)
        }
    }

    @Test fun anAnswerForAnotherInstallationIsRefusedNotCompleted() {
        val foreign = result.replace(installation, "bbbbbbbb-bbbb-4ccc-8ddd-eeeeeeeeeeee")
        val reply = reply(reattestation(), Routes({ ReattestationAnswer(201, challenge) }, { ReattestationAnswer(200, foreign) }))
        assertEquals(mapOf("outcome" to "refused", "code" to "unexpected-answer", "status" to 200), reply)
    }

    @Test fun anExpiredChallengeIsRefusedLocallyWithStatusZero() {
        val expired = challenge.replace("2026-10-23T10:02:00Z", "2026-10-23T09:00:00Z")
        val routes = Routes({ ReattestationAnswer(201, expired) })
        assertEquals(mapOf("outcome" to "refused", "code" to "challenge-invalid", "status" to 0), reply(reattestation(), routes))
        assertEquals(listOf("reattest_challenge"), routes.sent)
    }

    @Test fun localFailuresAreThrownWithTheirCode() {
        val r = reattestation()
        val strongBox = assertThrows(SentomaruException::class.java) {
            reply(r, Routes({ ReattestationAnswer(201, challenge) }), strongBox = true)
        }
        assertEquals("StrongBoxUnavailable", strongBox.error.code)
        keys.failGenerate = true
        val key = assertThrows(SentomaruException::class.java) { reply(r, Routes({ ReattestationAnswer(201, challenge) })) }
        assertEquals("KeyUnavailable", key.error.code)
        assertTrue(r.due()) // a local failure starts no wait
        val c = client()
        val r2 = reattestation(c)
        c.reset()
        assertEquals("NotEnrolled", assertThrows(SentomaruException::class.java) { reply(r2, Routes()) }.error.code)
    }

    // Review R of the D-12e: the worker always answers the result, whatever the flow throws.
    @Test fun everyThrowableBecomesAnErrorReplyNeverAnEscape() {
        val cases = listOf<Pair<Throwable, String>>(
            SentomaruException(EnrollmentError.NotEnrolled()) to "NotEnrolled",
            SentomaruException(EnrollmentError.KeyUnavailable()) to "KeyUnavailable",
            InterruptedException() to "Cancelled",
            IllegalStateException("main thread") to "ChannelError",
            RuntimeException("boom") to "ChannelError",
            OutOfMemoryError("oom") to "ChannelError",
            AssertionError("x") to "ChannelError",
            NoClassDefFoundError("old") to "ChannelError",
        )
        for ((thrown, code) in cases) {
            val reply = SentomaruFlutterPlugin.reattestationReplyOrError { throw thrown }
            assertNull(reply.value)
            assertEquals(thrown.toString(), code, reply.error)
        }
        Thread.interrupted() // clear the flag the InterruptedException case restored
        val ok = SentomaruFlutterPlugin.reattestationReplyOrError { ReattestationRefused("replay", 409) }
        assertNull(ok.error)
        assertEquals(mapOf("outcome" to "refused", "code" to "replay", "status" to 409), ok.value)
    }

    @Test fun configurationAbsentIsNullAndPartialOrBadIsInvalid() {
        assertNull(PluginConfig.parseReattestation(null, null, null))
        val ok = PluginConfig.parseReattestation(challengeUrl, submitUrl, 3600)!!
        assertEquals(3600L, ok.minIntervalSeconds)
        assertNull(PluginConfig.parseReattestation(challengeUrl, submitUrl, null)!!.minIntervalSeconds)
        for (args in listOf<Triple<Any?, Any?, Any?>>(
            Triple(challengeUrl, null, null), Triple(null, submitUrl, null), Triple(null, null, 3600),
            Triple(challengeUrl, submitUrl, 0), Triple(challengeUrl, submitUrl, -1), Triple(challengeUrl, submitUrl, "3600"),
            Triple(challengeUrl, submitUrl, 1.5), Triple(" ", submitUrl, null), Triple(challengeUrl, 7, null),
        )) assertThrows(args.toString(), PluginConfig.Invalid::class.java) {
            PluginConfig.parseReattestation(args.first, args.second, args.third)
        }
    }

    @Test fun aRouteTheSdkRefusesIsInvalidAndTheDefaultIntervalIsTheSdkOne() {
        val c = client()
        val built = PluginConfig.reattestation(c, PluginConfig.Reattestation(challengeUrl, submitUrl, null))
        assertEquals(SentomaruReattestation.DEFAULT_MIN_INTERVAL, built.minInterval)
        assertEquals(Duration.ofSeconds(3600), PluginConfig.reattestation(c, PluginConfig.Reattestation(challengeUrl, submitUrl, 3600)).minInterval)
        for (bad in listOf("http://$host/c", "https://other.example/c", "https://u@$host/c", "not a url"))
            assertThrows(bad, PluginConfig.Invalid::class.java) {
                PluginConfig.reattestation(c, PluginConfig.Reattestation(bad, submitUrl, null))
            }
    }
}
