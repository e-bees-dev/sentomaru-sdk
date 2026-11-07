package br.com.ebees.sentomaru.sdk

import android.os.Looper
import br.com.ebees.sentomaru.core.SignedMessage
import br.com.ebees.sentomaru.sdk.transport.SentomaruWire
import java.io.IOException
import java.time.Clock
import java.time.Duration
import java.time.Instant
import java.util.Base64

/**
 * D-12c: reattestation under a single-use server challenge (the Sentomaru re-attestation API contract, D-12b), opt-in. Nothing
 * creates it for the app and nothing calls it by itself: the app builds one per [SentomaruClient] and calls
 * [reattestIfDue] on a worker thread, e.g. right after a successful renewal (the trigger the spec proposes: at
 * renewal, at most once per [minInterval]). The server keeps it off unless the operator turns it on for the scope
 * (403 `reattestation-disabled`).
 *
 * Steps, both signed with the CURRENT installation key over the current grant, sent by the consumer's routes
 * ([challengeUrl], [submitUrl]) that forward to the private API: (1) `reattest_challenge` with body `{}` gets
 * `{challengeId, attestationChallenge, expiresAt}`; (2) a NEW key is generated in the Keystore with that challenge as
 * attestation challenge, its chain is read and the key is deleted (it never signs), and `reattest` sends
 * `{challengeId, publicKey, attestationChain}`. The body is kept for the challenge: a retry sends the same bytes (a
 * different body for a consumed challenge is `409 reattestation-conflict`).
 *
 * Answers: `429` is "not now" ([ReattestationNotNow], `Retry-After` respected, no retry). `503 verifier-unavailable`
 * (the challenge was not consumed) and `409 replay` (that exact message reached the server already) get **at most one**
 * retry, signed anew (new nonce), after `Retry-After` or [MIN_RETRY_BACKOFF], whichever is longer, and only if it
 * fits [MAX_RETRY_WAIT] and the challenge's life; then "not now" (a second `replay` is refused). Every retry costs the
 * installation budget the evaluations and renewals use, so there is never a loop. `403 session-expired` marks the
 * grant stale ([SentomaruClient.markGrantStale]): renew, then try again. Any other refusal is [ReattestationRefused].
 *
 * The result is advisory: it tells what the server recorded, never an authorization, and the evaluation does not read
 * it yet (D-12b). The interval is kept in memory: a new process may ask again, and the server answers 429.
 */
class SentomaruReattestation @JvmOverloads constructor(
    private val client: SentomaruClient,
    val challengeUrl: String,
    val submitUrl: String,
    val minInterval: Duration = DEFAULT_MIN_INTERVAL,
    private val clock: Clock = Clock.systemUTC(),
    private val sleeper: (Duration) -> Unit = { Thread.sleep(it.toMillis()) },
    private val onMainThread: () -> Boolean = { Looper.getMainLooper()?.isCurrentThread == true },
) {
    /** Read without a lock by [due] (review R I1): written only inside the flow lock. */
    @Volatile private var notBefore: Instant? = null
    private var frozen: Pair<String, ByteArray>? = null
    /** Held for the whole flow (Keystore, network, the retry wait); [due] never takes it. */
    private val flow = Any()

    init {
        client.config.checkHost(challengeUrl)
        client.config.checkHost(submitUrl)
        require(!minInterval.isNegative && !minInterval.isZero) { "Invalid reattestation interval" }
    }

    /**
     * Whether [reattestIfDue] would ask now: no completed reattestation nor server "not now" within its wait. Never
     * blocks (review R I1): it reads a volatile field and takes no lock, so it is safe on the main thread while a
     * reattestation runs on a worker (Keystore, network, a retry wait of up to [MAX_RETRY_WAIT]).
     */
    fun due(): Boolean = notBefore?.let { !clock.instant().isBefore(it) } ?: true

    /** [reattest] when [due], else [ReattestationNotNow] `NOT_DUE` with what is left (nothing is signed nor sent). */
    fun reattestIfDue(strongBox: Boolean = false, send: (SignedMessage) -> ReattestationAnswer): ReattestationOutcome {
        notDue()?.let { return it }
        return synchronized(flow) { notDue() ?: reattest(strongBox, send) } // a flow that ended meanwhile may have set it
    }

    private fun notDue(): ReattestationNotNow? {
        val wait = notBefore?.let { Duration.between(clock.instant(), it) } ?: return null
        return if (!wait.isNegative && !wait.isZero) ReattestationNotNow(ReattestationWait.NOT_DUE, wait) else null
    }

    /** Both steps now (ignores [due]): a challenge, then [reattest] with it. */
    fun reattest(strongBox: Boolean = false, send: (SignedMessage) -> ReattestationAnswer): ReattestationOutcome =
        synchronized(flow) {
            when (val issued = requestChallenge(send)) {
                is ReattestationChallengeIssued -> reattest(issued.challenge, strongBox, send)
                is ReattestationNotNow -> issued
                is ReattestationRefused -> issued
            }
        }

    /** Step 1: asks the server for a challenge (operation `reattest_challenge`, body `{}`). */
    fun requestChallenge(send: (SignedMessage) -> ReattestationAnswer): ReattestationChallengeOutcome = synchronized(flow) {
        refuseMainThread()
        when (val answer = exchange(CHALLENGE_OPERATION, challengeUrl, EMPTY_BODY, null, send)) {
            is Exchange.Answered -> parseBounded(answer.answer.body, ReattestationChallenge::parse)?.let(::ReattestationChallengeIssued)
                ?: ReattestationRefused(UNEXPECTED, answer.answer.status)
            is Exchange.Done -> answer.outcome as ReattestationChallengeOutcome
        }
    }

    /**
     * Step 2 with [challenge] (the spec's `reattest(challenge)`): a new attested key for it, then the signed submission.
     * A challenge past its `expiresAt` by more than [CLOCK_SKEW] on the device clock is not sent ([ReattestationRefused]
     * `challenge-invalid`, status 0), checked before and after generating the key (review R minor 2: the device clock
     * may be off, so the server decides inside the tolerance). Local key failures throw as in [SentomaruClient.enroll]
     * (`KeyUnavailable`, `StrongBoxUnavailable`, `Cancelled`).
     */
    fun reattest(challenge: ReattestationChallenge, strongBox: Boolean = false,
        send: (SignedMessage) -> ReattestationAnswer): ReattestationOutcome = synchronized(flow) { submit(challenge, strongBox, send) }

    private fun expiredLocally(challenge: ReattestationChallenge) =
        !clock.instant().isBefore(challenge.expiresAt.plus(CLOCK_SKEW))

    private fun submit(challenge: ReattestationChallenge, strongBox: Boolean,
        send: (SignedMessage) -> ReattestationAnswer): ReattestationOutcome {
        refuseMainThread()
        if (expiredLocally(challenge)) return ReattestationRefused(CHALLENGE_INVALID, 0)
        val body = frozen?.takeIf { it.first == challenge.challengeId }?.second ?: freeze(challenge, strongBox)
        if (expiredLocally(challenge)) return ReattestationRefused(CHALLENGE_INVALID, 0) // a slow Keystore
        return when (val answer = exchange(SUBMIT_OPERATION, submitUrl, body, challenge.expiresAt, send)) {
            is Exchange.Done -> answer.outcome as ReattestationOutcome
            is Exchange.Answered -> {
                val result = parseBounded(answer.answer.body, ReattestationResult::parse)
                if (result == null || result.challengeId != challenge.challengeId ||
                    !result.installationId.equals(client.installationId(), ignoreCase = true))
                    return ReattestationRefused(UNEXPECTED, answer.answer.status)
                frozen = null
                // revocation_unchecked does not count for the server's interval: ask again sooner, still not in a loop.
                val next = if (result.attestationReason == REVOCATION_UNCHECKED) REVOCATION_RETRY else minInterval
                notBefore = clock.instant().plus(next)
                ReattestationCompleted(result)
            }
        }
    }

    private fun freeze(challenge: ReattestationChallenge, strongBox: Boolean): ByteArray {
        val keys = client.keys
        val alias = "sentomaru.v1.${client.config.identity}.reattest"
        // A key left behind (a process that died, or a delete that failed) is removed here, and by reset().
        keys.delete(alias)
        val material = try {
            keys.generate(alias, challenge.attestationChallenge(), strongBox)
        } catch (e: Throwable) {
            try { keys.delete(alias) } catch (cleanup: Throwable) { e.addSuppressed(cleanup) } // never masks the cause
            throw e
        }
        // The key never signs: deleting it is housekeeping. A failure leaves an orphan the next reattestation or reset()
        // removes, and does not cost this reattestation.
        try { keys.delete(alias) } catch (_: Exception) { }
        val chain = material.chain()
        if (chain.isEmpty() || chain.size > 5 || chain.any { it.isEmpty() || it.size > 4096 }) fail(EnrollmentError.KeyUnavailable())
        val encoder = Base64.getEncoder()
        val body = ("{\"challengeId\":\"${challenge.challengeId}\",\"publicKey\":\"${encoder.encodeToString(material.publicKey())}\"," +
            "\"attestationChain\":[" + chain.joinToString(",") { "\"${encoder.encodeToString(it)}\"" } + "]}").toByteArray(Charsets.UTF_8)
        frozen = challenge.challengeId to body
        return body
    }

    private sealed class Exchange {
        class Answered(val answer: ReattestationAnswer) : Exchange()
        class Done(val outcome: Any) : Exchange()
    }

    /** One signed exchange with at most one retry (503 verifier-unavailable or 409 replay); never a loop. */
    private fun exchange(operation: String, url: String, body: ByteArray, expiresAt: Instant?,
        send: (SignedMessage) -> ReattestationAnswer): Exchange {
        var retried = false
        while (true) {
            interrupted()
            val signed = client.sign("POST", url, operation, body.copyOf())
            val answer = try {
                send(signed)
            } catch (_: IOException) {
                return notNow(ReattestationWait.UNAVAILABLE, UNAVAILABLE_WAIT)
            } catch (_: InterruptedException) {
                Thread.currentThread().interrupt()
                fail(EnrollmentError.Cancelled())
            }
            val code = if (answer.status in 200..299) null else SentomaruWire.errorCode(answer.body.take(SentomaruWire.MAX_RENEWAL_BYTES))
            val retryAfter = answer.retryAfterSeconds?.let(Duration::ofSeconds)
            when {
                answer.status == 200 || (answer.status == 201 && operation == CHALLENGE_OPERATION) -> return Exchange.Answered(answer)
                answer.status == 429 -> return notNow(ReattestationWait.RATE_LIMITED, retryAfter ?: RATE_LIMITED_WAIT)
                answer.status == 503 && code == VERIFIER_UNAVAILABLE || answer.status == 409 && code == REPLAY -> {
                    val reason = if (code == REPLAY) ReattestationWait.UNAVAILABLE else ReattestationWait.VERIFIER_UNAVAILABLE
                    val wait = maxOf(retryAfter ?: Duration.ZERO, MIN_RETRY_BACKOFF)
                    val fits = wait <= MAX_RETRY_WAIT &&
                        (expiresAt == null || clock.instant().plus(wait).plus(CHALLENGE_MARGIN).isBefore(expiresAt))
                    if (retried || !fits) {
                        return if (code == REPLAY && retried) Exchange.Done(ReattestationRefused(REPLAY, answer.status))
                        else notNow(reason, maxOf(retryAfter ?: Duration.ZERO, VERIFIER_WAIT))
                    }
                    retried = true
                    try { sleeper(wait) } catch (_: InterruptedException) {
                        Thread.currentThread().interrupt()
                        fail(EnrollmentError.Cancelled())
                    }
                }
                answer.status >= 500 -> return notNow(ReattestationWait.UNAVAILABLE, maxOf(retryAfter ?: Duration.ZERO, UNAVAILABLE_WAIT))
                else -> {
                    if (answer.status == 403 && code == SentomaruWire.SESSION_EXPIRED) client.markGrantStale()
                    // Review R I2: a refusal that holds for the scope or the installation waits, so the app does not send
                    // a signed request on every renewal forever.
                    if (answer.status == 403 && code in LASTING_REFUSALS) notBefore = clock.instant().plus(LASTING_REFUSAL_WAIT)
                    return Exchange.Done(ReattestationRefused(code ?: UNEXPECTED, answer.status))
                }
            }
        }
    }

    /** Review R minor 3: every "not now" waits between [MIN_NOT_NOW] and [MAX_NOT_NOW] (a 0 or huge Retry-After too). */
    private fun notNow(reason: ReattestationWait, wait: Duration): Exchange {
        val bounded = wait.coerceIn(MIN_NOT_NOW, MAX_NOT_NOW)
        notBefore = clock.instant().plus(bounded)
        return Exchange.Done(ReattestationNotNow(reason, bounded))
    }

    /** Review R minor 5: an answer longer than [MAX_ANSWER_CHARS] is never parsed. */
    private fun <T> parseBounded(body: String, parse: (String) -> T?): T? = if (body.length > MAX_ANSWER_CHARS) null else parse(body)

    private fun refuseMainThread() = check(!onMainThread()) { "Reattestation must not run on the main thread" }

    private fun interrupted() { if (Thread.currentThread().isInterrupted) fail(EnrollmentError.Cancelled()) }

    companion object {
        /** Reserved operations of the two steps (server: ReattestationService). */
        const val CHALLENGE_OPERATION = "reattest_challenge"
        const val SUBMIT_OPERATION = "reattest"

        /** The server's default minimum interval (pendência 2 do dono, until the D-12d measures the cost). */
        val DEFAULT_MIN_INTERVAL: Duration = Duration.ofHours(24)
        /** Minimum wait before the single retry after 503 verifier-unavailable or 409 replay. */
        val MIN_RETRY_BACKOFF: Duration = Duration.ofSeconds(2)
        /** A retry that would wait longer is not made ("not now" instead). */
        val MAX_RETRY_WAIT: Duration = Duration.ofSeconds(30)
        /** The retry must reach the server this long before the challenge expires. */
        val CHALLENGE_MARGIN: Duration = Duration.ofSeconds(10)
        /** "Not now" without `Retry-After`: 429, verifier still unavailable, network or another 5xx. */
        val RATE_LIMITED_WAIT: Duration = Duration.ofHours(1)
        val VERIFIER_WAIT: Duration = Duration.ofMinutes(5)
        val UNAVAILABLE_WAIT: Duration = Duration.ofMinutes(1)
        /** After a result with `revocation_unchecked` (it does not count for the server's interval). */
        val REVOCATION_RETRY: Duration = Duration.ofHours(1)
        /** Bounds of every "not now" wait (a `Retry-After: 0` on a 429 waits 60 s). */
        val MIN_NOT_NOW: Duration = Duration.ofSeconds(60)
        val MAX_NOT_NOW: Duration = Duration.ofHours(24)
        /**
         * Refusals that hold for a while (scope switched off, iOS installation, suspended installation): the next ask
         * waits this long. None of them charges the installation budget on the server (D-12b: `disabled` is decided
         * before reading any state; `unsupported` rolls back the unit that charged; `suspended` is decided before the
         * budgets), but each one still is a signed request through the consumer.
         */
        val LASTING_REFUSAL_WAIT: Duration = Duration.ofHours(24)
        /** The device clock may be off: a challenge is refused locally only this long past its `expiresAt`. */
        val CLOCK_SKEW: Duration = Duration.ofSeconds(60)
        /** Longest 200/201 answer read (a real one is under 600 characters). */
        const val MAX_ANSWER_CHARS = 4096
        private val LASTING_REFUSALS = setOf("reattestation-disabled", "reattestation-unsupported", "installation-suspended")

        private const val VERIFIER_UNAVAILABLE = "verifier-unavailable"
        private const val REPLAY = "replay"
        private const val CHALLENGE_INVALID = "challenge-invalid"
        private const val REVOCATION_UNCHECKED = "revocation_unchecked"
        private const val UNEXPECTED = "unexpected-answer"
        private val EMPTY_BODY = "{}".toByteArray(Charsets.UTF_8)
    }
}
