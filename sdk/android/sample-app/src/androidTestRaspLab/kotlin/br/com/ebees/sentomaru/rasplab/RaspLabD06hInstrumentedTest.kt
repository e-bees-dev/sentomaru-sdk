package br.com.ebees.sentomaru.rasplab

import android.os.Bundle
import androidx.test.ext.junit.runners.AndroidJUnit4
import androidx.test.platform.app.InstrumentationRegistry
import br.com.ebees.sentomaru.core.SignedMessage
import br.com.ebees.sentomaru.sdk.EnrollmentChallenge
import br.com.ebees.sentomaru.sdk.EnrollmentGrant
import br.com.ebees.sentomaru.sdk.ReattestationAnswer
import br.com.ebees.sentomaru.sdk.ReattestationCompleted
import br.com.ebees.sentomaru.sdk.ReattestationNotNow
import br.com.ebees.sentomaru.sdk.ReattestationOutcome
import br.com.ebees.sentomaru.sdk.ReattestationRefused
import br.com.ebees.sentomaru.sdk.SentomaruClient
import br.com.ebees.sentomaru.sdk.SentomaruConfig
import br.com.ebees.sentomaru.sdk.SentomaruReattestation
import br.com.ebees.sentomaru.signals.SignalsCollector
import okhttp3.MediaType.Companion.toMediaType
import okhttp3.OkHttpClient
import okhttp3.Request
import okhttp3.RequestBody.Companion.toRequestBody
import org.json.JSONArray
import org.json.JSONObject
import org.junit.After
import org.junit.Assert.assertTrue
import org.junit.Before
import org.junit.Test
import org.junit.runner.RunWith
import java.io.IOException
import java.time.Instant
import java.util.Base64
import java.util.concurrent.TimeUnit

/**
 * D-06h-f: the cases of the HML proof of the `challenge` of kind `reattest`, run by the
 * RASP lab build only (`-Psentomaru.raspLab=true`, package `br.com.ebees.sentomaru.rasplab`), in the scope
 * `ebees/integrity-lab/hml` (D-12h; `rasp-lab` also accepted). Like `RaspLabCasesInstrumentedTest` (D-05g-a), the test
 * plays the consumer itself, with the `consumer` workload token given as the instrumentation argument
 * `consumerToken`; the token only goes in the Authorization header and is never written, reported nor logged. This is
 * a separate class so the D-05g/D-12h cases, already proven in the HML, do not change.
 *
 * One run = one fresh installation (the SDK state is reset before and after), and in order ([RaspLabD06hPlan]):
 * - `enroll`: attested enrollment (HTTP status, `hardwareStatus`, `attestationStatus`, `attestationReason`);
 * - `plain` (operation `d06h_plain`, no rule cites the condition) and `observe` (`d06h_observe`, the condition in
 *   stage observe), each one evaluation;
 * - `enforce` (`d06h_enforce`, the condition in stage enforce), then the app's routine for a `challenge` `reattest`
 *   ([RaspLabReattestChallenge], D-06h-c): one [SentomaruReattestation.reattest] reported as `reattest-for-challenge`,
 *   a status `reattest-step` with the next step, and with `REPEAT_ONCE` the operation repeated ONCE with a new nonce
 *   (`enforce-retry`), whose answer is final: never a second reattestation for the same operation;
 * - `observe-after`: the observed operation again;
 * - `reattest-again` (argument `secondReattest`, default true): one more reattestation of the same installation inside
 *   the scope's minimum interval, outside any routine; the server is expected to answer 429 (`not-now`
 *   `RATE_LIMITED`), and nothing is repeated after it;
 * - `measure` pairs (argument `measure`, 0..30, default 10): `measure-plain` then `measure-enforce`, alternated, for
 *   the `server_ms` with and without the read; never a reattestation, whatever they answer.
 *
 * Each case is one instrumentation status `d06hCase` with fields of limited format only: HTTP status, error code,
 * recommended and evaluated action, `policyStatus`, `policySource`, `shadowMode`, `policyId`, `policyVersion`,
 * `challengeKind`, `observedRules`, reason codes; for a reattestation the outcome type and the server's closed codes
 * (or the refusal code, or the wait reason). A value outside its format is dropped, never echoed. Never reported:
 * installation, session, key or challenge ids, the token, bodies, the serial, signal values; a failure is reported by
 * its exception type only, never its message. Every evaluation carries a snapshot of the default and RASP detectors
 * (signed, as the SDK sends it); the proof policy has no signal rule, so it does not decide anything here.
 */
@RunWith(AndroidJUnit4::class)
class RaspLabD06hInstrumentedTest {

    private val instrumentation = InstrumentationRegistry.getInstrumentation()
    private val context = instrumentation.targetContext
    private val arguments = InstrumentationRegistry.getArguments()
    private val org = arguments.getString("org", "ebees")
    private val app = arguments.getString("app", "integrity-lab")
    private val env = arguments.getString("env", "hml")
    private val apiArgument = arguments.getString("api", "")
    private val measureArgument: String? = arguments.getString("measure")
    private val secondReattestArgument = arguments.getString("secondReattest", "true")
    private val json = "application/json".toMediaType()

    private lateinit var api: String
    private lateinit var token: String
    private lateinit var client: SentomaruClient
    private lateinit var http: OkHttpClient
    private lateinit var collector: SignalsCollector
    private var seq = 0

    @Before
    fun setUp() {
        val match = API.matchEntire(apiArgument)
        assertTrue("api must be an https origin without path", match != null)
        api = apiArgument.trimEnd('/')
        token = arguments.getString("consumerToken", "")
        assertTrue("consumerToken argument required in the workload token format", WORKLOAD_TOKEN.matches(token))
        assertTrue("scope must be slugs", listOf(org, app, env).all { SLUG.matches(it) })
        assertTrue("only the lab apps are accepted: $LAB_APPS", app in LAB_APPS)
        collector = SignalsCollector(detectors = SignalsCollector.defaultDetectors() + SignalsCollector.raspDetectors(),
            deadlineMs = SignalsCollector.RASP_DEADLINE_MS)
        // Real TLS, no redirect (it would carry the token elsewhere), no silent retry (a retried POST could spend a
        // single-use challenge or nonce twice and hide what the case measured).
        http = OkHttpClient.Builder().followRedirects(false).followSslRedirects(false).retryOnConnectionFailure(false)
            .callTimeout(30, TimeUnit.SECONDS).build()
        client = SentomaruClient.initialize(context, SentomaruConfig(org, app, env, setOf(match!!.groupValues[1]),
            "$api/v1/$org/$app/$env/installations"))
        client.reset()
    }

    @After
    fun tearDown() {
        // Local only: the installation on the server is removed by the roteiro cleanup (A-18).
        if (::client.isInitialized) client.reset()
    }

    private class Answer(val status: Int, val body: String, val retryAfterSeconds: Long? = null)

    private fun post(path: String, payload: JSONObject): Answer {
        val request = Request.Builder().url("$api$path").header("Authorization", "Bearer $token")
            // ByteArray body: String.toRequestBody appends "; charset=utf-8", and the API requires exactly application/json.
            .post(payload.toString().toByteArray(Charsets.UTF_8).toRequestBody(json)).build()
        http.newCall(request).execute().use {
            val retryAfter = it.header("Retry-After")?.takeIf { v -> RETRY_AFTER.matches(v) }?.toLong()
            return Answer(it.code, it.body?.string().orEmpty(), retryAfter)
        }
    }

    private fun envelopeRequest(signed: SignedMessage, extra: Map<String, String> = emptyMap()): JSONObject {
        val headers = JSONObject()
        (signed.headers + extra.toList()).forEach { (k, v) -> headers.put(k.lowercase(), JSONArray().put(v)) }
        return JSONObject().put("method", signed.method).put("uri", signed.targetUri).put("headers", headers)
            .put("body", Base64.getEncoder().encodeToString(signed.body()))
    }

    private fun caller() = JSONObject().put("subject", SUBJECT).put("tenant", TENANT)

    private fun send(out: JSONObject) = instrumentation.sendStatus(STATUS_CODE, Bundle().apply { putString(KEY, out.toString()) })

    /** One evaluation result, fields of limited format only. A value outside its format is dropped, never echoed. */
    private fun report(id: String, answer: Answer?, error: String? = null): JSONObject? {
        val out = JSONObject().put("id", id)
        if (answer != null) out.put("status", answer.status)
        val parsed = try { if (answer == null || answer.body.isEmpty()) null else JSONObject(answer.body) } catch (_: Exception) { null }
        if (parsed != null) {
            for (key in listOf("code", "recommendedAction", "evaluatedAction", "policyStatus", "policySource",
                "hardwareStatus", "attestationStatus", "attestationReason", "policyId", "challengeKind")) {
                val value = if (parsed.isNull(key)) "" else parsed.optString(key, "")
                if (TOKEN.matches(value)) out.put(key, value)
            }
            parsed.optJSONArray("reasonCodes")?.let { codes ->
                val kept = JSONArray()
                for (i in 0 until codes.length()) codes.optString(i).takeIf { REASON.matches(it) }?.let { kept.put(it) }
                out.put("reasonCodes", kept)
            }
            RaspLabPolicyFields.policyVersion(parsed.opt("policyVersion"))?.let { out.put("policyVersion", it) }
            parsed.optJSONArray("observedRules")?.let { rules ->
                out.put("observedRules", JSONArray(RaspLabPolicyFields.observedRules((0 until rules.length()).map { rules.opt(it) })))
            }
            if (parsed.has("shadowMode")) out.put("shadowMode", if (parsed.isNull("shadowMode")) JSONObject.NULL
                else parsed.optBoolean("shadowMode"))
        }
        if (error != null) out.put("error", error)
        send(out)
        return parsed
    }

    private fun enroll(): Boolean {
        var answered: Answer? = null
        return try {
            val challengeAnswer = post("/v1/$org/$app/$env/challenges", caller())
            if (challengeAnswer.status != 201) {
                report("enroll", challengeAnswer, "challenge")
                return false
            }
            val c = JSONObject(challengeAnswer.body)
            val challenge = EnrollmentChallenge(c.optString("challengeId", c.optString("id")),
                c.optString("challenge", c.optString("token")), Base64.getDecoder().decode(c.getString("attestationChallenge")),
                Instant.parse(c.getString("expiresAt")))
            val sentAt = Instant.now()
            client.enroll(challenge) { signed ->
                val answer = post("/v1/$org/$app/$env/installations", JSONObject().put("request", envelopeRequest(signed)))
                answered = answer
                if (answer.status !in 200..299) throw IOException("enrollment")
                val g = JSONObject(answer.body)
                val ttl = g.optLong("ttlSeconds", GRANT_TTL_SECONDS).takeIf { it in 1..86_400 } ?: GRANT_TTL_SECONDS
                EnrollmentGrant(g.getString("installationId"), g.getString("keyId"), g.getString("sessionId"),
                    g.getString("hardwareStatus"), g.getString("attestationStatus"), sentAt, ttl)
            }
            report("enroll", answered)
            true
        } catch (e: Exception) {
            report("enroll", answered, if (answered == null) "sdk:" + e.javaClass.simpleName.take(40) else null)
            false
        }
    }

    /**
     * One signed operation of the plan, evaluated; the parsed answer (null when it failed or was not JSON) and whether
     * it answered 200. The operation name is the signed operation header AND the evaluation's `operation`.
     */
    private fun evaluate(step: RaspLabD06hPlan.Evaluation): Pair<JSONObject?, Boolean> = try {
        val snapshot = collector.snapshot(context)
        val value = snapshot.toJson()
        if (value.length > SIGNALS_MAX_LENGTH || value.any { it.code !in 0x20..0x7E }) {
            report(step.id, null, "snapshot-too-large") to false
        } else {
            val i = seq++
            val signed = client.sign("POST", "$api/v1/$org/$app/$env/operations/${step.operation}?seq=$i", step.operation,
                "{\"synthetic\":true,\"case\":\"d06h\",\"seq\":$i}".toByteArray(), mapOf(SIGNALS_HEADER to value))
            val answer = post("/v1/$org/$app/$env/evaluations", JSONObject().put("operation", step.operation)
                .put("request", envelopeRequest(signed)).put("context", caller()))
            report(step.id, answer) to (answer.status == 200)
        }
    } catch (e: Exception) {
        report(step.id, null, "sdk:" + e.javaClass.simpleName.take(40)) to false
    }

    /** One reattestation, reported under [id]; null (reported by its exception type) when the SDK threw. */
    private fun reattestOnce(id: String): ReattestationOutcome? {
        val base = "$api/v1/$org/$app/$env/reattestations"
        val outcome: ReattestationOutcome = try {
            SentomaruReattestation(client, "$base/challenges", base).reattest { signed ->
                val path = signed.targetUri.removePrefix(api)
                check(signed.targetUri.startsWith("$api/") && (path == "/v1/$org/$app/$env/reattestations" ||
                    path == "/v1/$org/$app/$env/reattestations/challenges"))
                val answer = post(path, JSONObject().put("request", envelopeRequest(signed)).put("context", caller()))
                ReattestationAnswer(answer.status, answer.body, answer.retryAfterSeconds)
            }
        } catch (e: Exception) {
            send(JSONObject().put("id", id).put("error", "sdk:" + e.javaClass.simpleName.take(40)))
            return null
        }
        val out = JSONObject().put("id", id)
        fun put(key: String, value: String?) { if (value != null && TOKEN.matches(value)) out.put(key, value) }
        when (outcome) {
            is ReattestationCompleted -> {
                val r = outcome.result
                out.put("outcome", "completed").put("replayed", r.replayed)
                put("hardwareStatus", r.hardwareStatus); put("attestationStatus", r.attestationStatus)
                put("attestationReason", r.attestationReason); put("buildMatchState", r.buildMatchState)
                put("buildMatchReason", r.buildMatchReason); put("appIdentityState", r.appIdentityState)
                put("appIdentityReason", r.appIdentityReason)
            }
            is ReattestationRefused -> { out.put("outcome", "refused").put("status", outcome.status); put("code", outcome.code) }
            is ReattestationNotNow -> { out.put("outcome", "not-now"); put("wait", outcome.reason.name) }
        }
        send(out)
        return outcome
    }

    private fun field(json: JSONObject?, key: String) = json?.takeUnless { it.isNull(key) }?.optString(key, "")

    @Test
    fun test_D06H_reattest_challenge() {
        val measure = RaspLabD06hPlan.measure(measureArgument)
        assertTrue("measure must be an integer in 0..${RaspLabD06hPlan.MAX_MEASURE}", measure != null)
        assertTrue("secondReattest must be true or false",
            secondReattestArgument == "true" || secondReattestArgument == "false")
        assertTrue("enrollment failed (see the d06hCase status)", enroll())
        var ok = true
        for (step in RaspLabD06hPlan.BEFORE) ok = evaluate(step).second && ok

        // The app's routine (D-06h-c): one reattestation only for challenge + reattest, then one repetition.
        val (first, answered) = evaluate(RaspLabD06hPlan.ENFORCED)
        ok = answered && ok
        var step = if (answered) RaspLabReattestChallenge.afterAnswer(field(first, "recommendedAction"),
            field(first, "challengeKind")) else RaspLabReattestChallenge.Step.FINAL
        // Review R M-9: both variants of the proof expect challenge + reattest here and a completed reattestation
        // (passed or failed is the server's state, read on the repetition); anything else fails the run. The rest of the
        // gabarito is checked on the d06hCase lines (roteiro).
        ok = (step == RaspLabReattestChallenge.Step.REATTEST) && ok
        if (step == RaspLabReattestChallenge.Step.REATTEST) {
            val outcome = reattestOnce("reattest-for-challenge")
            ok = outcome is ReattestationCompleted && ok
            step = when (outcome) {
                is ReattestationCompleted -> RaspLabReattestChallenge.afterReattest(RaspLabReattestChallenge.Outcome.COMPLETED)
                is ReattestationNotNow -> RaspLabReattestChallenge.afterReattest(RaspLabReattestChallenge.Outcome.NOT_NOW)
                is ReattestationRefused -> RaspLabReattestChallenge.afterReattest(RaspLabReattestChallenge.Outcome.REFUSED)
                null -> RaspLabReattestChallenge.Step.FINAL
            }
        }
        send(JSONObject().put("id", "reattest-step").put("step", step.name))
        // Once, with a new nonce; its answer is final, whatever it says (no second reattestation for this operation).
        if (step == RaspLabReattestChallenge.Step.REPEAT_ONCE) ok = evaluate(RaspLabD06hPlan.RETRY).second && ok

        ok = evaluate(RaspLabD06hPlan.AFTER).second && ok
        // Inside the scope's interval: a not-now (429) is the expected result, never followed by anything.
        if (secondReattestArgument == "true") ok = (reattestOnce("reattest-again") != null) && ok
        for (pair in RaspLabD06hPlan.measurement(measure!!)) ok = evaluate(pair).second && ok
        assertTrue("an evaluation did not answer 200 or a reattestation threw (see the d06hCase statuses)", ok)
    }

    companion object {
        const val KEY = "d06hCase"
        /** Not a code AndroidJUnitRunner uses (1, 0, -1..-4); the same as the D-05g and J-04s2 tests. */
        const val STATUS_CODE = 7
        const val SIGNALS_HEADER = "x-sentomaru-signals"
        const val SUBJECT = "d06h-lab"
        const val TENANT = "integrity-lab"
        /** Fallback only: the API's default grant lifetime (600 s), used when the answer carries no `ttlSeconds`. */
        const val GRANT_TTL_SECONDS = 600L
        /** The SDK transport's limit for the header (`SignalsHeader.MAX_LENGTH`, internal to the SDK module). */
        const val SIGNALS_MAX_LENGTH = 4096
        private val LAB_APPS = setOf("integrity-lab", "rasp-lab")
        private val WORKLOAD_TOKEN = Regex("[A-Za-z0-9_-]{43}")
        private val API = Regex("https://([a-z0-9.-]+)(?::\\d{2,5})?/?")
        private val SLUG = Regex("[a-z0-9][a-z0-9-]{0,62}")
        private val TOKEN = Regex("[a-zA-Z][a-zA-Z0-9_-]{0,47}")
        private val REASON = Regex("[A-Z0-9_]{3,64}")
        private val RETRY_AFTER = Regex("[0-9]{1,7}")
    }
}
