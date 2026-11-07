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
import br.com.ebees.sentomaru.sdk.ReattestationWait
import br.com.ebees.sentomaru.sdk.SentomaruClient
import br.com.ebees.sentomaru.sdk.SentomaruConfig
import br.com.ebees.sentomaru.sdk.SentomaruReattestation
import br.com.ebees.sentomaru.signals.SignalState
import br.com.ebees.sentomaru.signals.SignalsCollector
import br.com.ebees.sentomaru.signals.SignalsSnapshot
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
 * D-05g-a: the cases of the D-05g HML proof, run by the RASP lab build only
 * (`-Psentomaru.raspLab=true`, package `br.com.ebees.sentomaru.rasplab`). The test plays the consumer itself: it asks
 * for a challenge, enrolls through the envelope route and sends each signed operation as an evaluation envelope, all to
 * the API URL given as the instrumentation argument `api`, with the `consumer` workload token given as `consumerToken`.
 * Neither is ever written in the code, reported or logged; the token only goes in the Authorization header. Only the
 * lab apps `rasp-lab` (D-05g) and `integrity-lab` (if the D-12h uses this build) are accepted as scope app.
 *
 * Cases (one instrumentation status `d05gCase` each, fields of limited format only: HTTP status, error code,
 * recommended and evaluated action, reason codes, `policyStatus`, `shadowMode`, `policySource`, enrollment statuses,
 * and for an operation the state of each capability of the snapshot sent). D-06g-a adds,
 * from the evaluation answer (D-06a, contract v1.9): `policyId` and `challengeKind` (the same format as the other
 * codes; absent when the server omits it), `policyVersion` (semver) and `observedRules` (rule ids of the 0054 format,
 * [RaspLabPolicyFields]). A value outside its format is dropped, never echoed. Never reported: installation, session,
 * key or challenge ids, the token, bodies, the serial, any `detail` value of a signal outside the closed `reasons` set
 * (below); a failure is reported by its exception type only, never its message.
 * - `enroll`: attested enrollment in the lab scope.
 * - `collected`: an operation with the real snapshot of this device, `defaultDetectors() + raspDetectors()` with
 *   `RASP_DEADLINE_MS` (and with `signals=rasp+integrity`, also `appIntegrityDetectors`, D-12c), covered by the
 *   signature (`x-sentomaru-signals` in Signature-Input).
 * - `unsigned-snapshot`: the same kind of snapshot, but the request is signed WITHOUT the `x-sentomaru-signals`
 *   component and the header is added after the signature, as the bad cases of the J-04s2 change a signed message. The
 *   server must read every NOT_DETECTED of it as UNKNOWN and count it with `signed = false`. This is a test-only
 *   construction: the published SDK has no option to leave the snapshot out of the signature.
 * - `reattest` (D-12h, only with the argument `reattest=true`): one [SentomaruReattestation.reattest] of the enrolled
 *   installation through the reattestation routes (D-12b), reported with the outcome type and the server's closed codes
 *   only (`hardwareStatus`, `attestationStatus`, `attestationReason`, `buildMatchState`, `buildMatchReason`,
 *   `appIdentityState`, `appIdentityReason`, or the refusal `code`). The scope must have the reattestation on; off, the
 *   case reports `refused` `reattestation-disabled` and does not fail the test.
 * - `reattest-challenge` (D-06h, only with the argument `reattestChallenge=true`): the app's routine for a `challenge`
 *   of kind `reattest` ([RaspLabReattestChallenge]). One operation with a fresh snapshot; when the answer is `challenge`
 *   `reattest`, one [SentomaruReattestation.reattest] (reported as `reattest-for-challenge`, same fields as `reattest`),
 *   then a status `reattest-step` with the next step (`REPEAT_ONCE`, `TRY_LATER`, `SHOW_REFUSAL`, or `FINAL` when no
 *   reattestation was asked), and with `REPEAT_ONCE` the operation repeated once with a new nonce (`reattest-retry`).
 *   The repeated answer is final: never a second reattestation for the same operation. Not combined with `reattest=true`
 *   (refused: the second reattestation of the run would meet the server's interval).
 *
 * D-12h also passes `operationDelayMs` (0..15000, default 0): the wait before each
 * `collected` operation after the first, so the server's background read of the build registry (D-12c-2,
 * `reference_pending` on the first evaluation) has answered before the next one.
 *
 * D-05g (emulator window of 23/10): with `RASP_DEADLINE_MS` a cold emulator sent the D-05 signals as UNKNOWN. The
 * collector runs the detectors in order on this thread, and past the deadline it reports UNKNOWN `timeout=overrun` (the
 * detector that crossed it, its result discarded) or `timeout=skipped` (every one after it). Two optional arguments, both
 * test-only constructions (the published SDK and its `RASP_DEADLINE_MS` do not change):
 * - `deadlineMs` (100..2000, default `RASP_DEADLINE_MS`, plus `APP_INTEGRITY_BUDGET_MS` with `signals=rasp+integrity`):
 *   the collector deadline of this run; every snapshot report carries the `deadlineMs` used and the `durationMs`.
 * - `warmup` (0..3, default 0): collections made and discarded before the first case, each reported as a `warmup` status
 *   (states and reasons only, nothing sent to the API), so a cold first collection does not stand for the device.
 * For each capability UNKNOWN or ERROR, the snapshot report carries `reasons`: codes of a closed set taken from the
 * signal `detail` by [RaspLabReasons] (`timeout:overrun`, `timeout:skipped`, `partial:<check>`, `reason:<code>`,
 * `cause:<code>`, `result:<code>`, `error`, `no_detail`); a value outside the set is reported as `other`, never echoed.
 *
 * The expected answer of each case lives in the roteiro, never here.
 */
@RunWith(AndroidJUnit4::class)
class RaspLabCasesInstrumentedTest {

    private val instrumentation = InstrumentationRegistry.getInstrumentation()
    private val context = instrumentation.targetContext
    private val arguments = InstrumentationRegistry.getArguments()
    private val org = arguments.getString("org", "ebees")
    private val app = arguments.getString("app", "rasp-lab")
    private val env = arguments.getString("env", "hml")
    private val apiArgument = arguments.getString("api", "")
    private val operationsArgument = arguments.getString("operations", "1")
    private val signalsArgument = arguments.getString("signals", "rasp")
    private val expectedSignerArgument = arguments.getString("expectedSigner", TEST_CERT_SHA256)
    private val operationDelayArgument = arguments.getString("operationDelayMs", "0")
    private val reattestArgument = arguments.getString("reattest", "false")
    private val reattestChallengeArgument = arguments.getString("reattestChallenge", "false")
    private val deadlineArgument: String? = arguments.getString("deadlineMs")
    private val warmupArgument = arguments.getString("warmup", "0")
    private val json = "application/json".toMediaType()

    private lateinit var api: String
    private lateinit var host: String
    private lateinit var token: String
    private lateinit var client: SentomaruClient
    private lateinit var http: OkHttpClient
    private lateinit var collector: SignalsCollector
    private var deadlineMs = 0L

    /** The app's public routes the signature covers (the consumer role is this test; the API never contacts them). */
    private val operationUrl get() = "$api/v1/$org/$app/$env/operations/submit"

    @Before
    fun setUp() {
        val match = API.matchEntire(apiArgument)
        assertTrue("api must be an https origin without path", match != null)
        api = apiArgument.trimEnd('/')
        host = match!!.groupValues[1]
        token = arguments.getString("consumerToken", "")
        // The API's workload token format (WorkloadAuth: 43 base64url characters); anything else is refused unread.
        assertTrue("consumerToken argument required in the workload token format", WORKLOAD_TOKEN.matches(token))
        assertTrue("scope must be slugs", listOf(org, app, env).all { SLUG.matches(it) })
        assertTrue("only the lab apps are accepted: $LAB_APPS", app in LAB_APPS)
        val detectors = when (signalsArgument) {
            "rasp" -> SignalsCollector.defaultDetectors() + SignalsCollector.raspDetectors()
            "rasp+integrity" -> SignalsCollector.defaultDetectors() + SignalsCollector.raspDetectors() +
                SignalsCollector.appIntegrityDetectors(listOf(expectedSignerArgument))
            else -> throw AssertionError("signals must be rasp or rasp+integrity")
        }
        val defaultDeadline = SignalsCollector.RASP_DEADLINE_MS +
            if (signalsArgument == "rasp+integrity") SignalsCollector.APP_INTEGRITY_BUDGET_MS else 0L
        val deadline = if (deadlineArgument == null) defaultDeadline else deadlineArgument.toLongOrNull()
        assertTrue("deadlineMs must be an integer in $DEADLINE_RANGE", deadline != null && deadline in DEADLINE_RANGE)
        deadlineMs = deadline!!
        collector = SignalsCollector(detectors = detectors, deadlineMs = deadlineMs)
        // Real TLS to the API (no trust override), no redirect (it would carry the token elsewhere) and no silent retry
        // (a retried POST could spend a single-use challenge or nonce twice and hide what the case measured).
        http = OkHttpClient.Builder().followRedirects(false).followSslRedirects(false).retryOnConnectionFailure(false)
            .callTimeout(30, TimeUnit.SECONDS).build()
        client = SentomaruClient.initialize(context, SentomaruConfig(org, app, env, setOf(host),
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

    /** The app's signed request as the consumer received it, in the envelope shape (`MessageDto`). */
    private fun envelopeRequest(signed: SignedMessage, extra: Map<String, String> = emptyMap()): JSONObject {
        val headers = JSONObject()
        (signed.headers + extra.toList()).forEach { (k, v) -> headers.put(k.lowercase(), JSONArray().put(v)) }
        return JSONObject().put("method", signed.method).put("uri", signed.targetUri).put("headers", headers)
            .put("body", Base64.getEncoder().encodeToString(signed.body()))
    }

    private fun caller() = JSONObject().put("subject", SUBJECT).put("tenant", TENANT)

    /** One case result, fields of limited format only. A value outside its format is dropped, never echoed. */
    private fun report(case: String, answer: Answer?, error: String? = null, snapshot: SignalsSnapshot? = null) {
        val out = JSONObject().put("id", case)
        if (answer != null) out.put("status", answer.status)
        val parsed = try { if (answer == null || answer.body.isEmpty()) null else JSONObject(answer.body) } catch (_: Exception) { null }
        if (parsed != null) {
            for (key in listOf("code", "recommendedAction", "evaluatedAction", "policyStatus", "proofStatus",
                "policySource", "hardwareStatus", "attestationStatus", "attestationReason", "policyId", "challengeKind")) {
                val value = if (parsed.isNull(key)) "" else parsed.optString(key, "")
                if (TOKEN.matches(value)) out.put(key, value)
            }
            parsed.optJSONArray("reasonCodes")?.let { codes ->
                val kept = JSONArray()
                for (i in 0 until codes.length()) codes.optString(i).takeIf { REASON.matches(it) }?.let { kept.put(it) }
                out.put("reasonCodes", kept)
            }
            // D-06g-a: the version that decided and the matched rules in `stage: observe`, each in its own format.
            RaspLabPolicyFields.policyVersion(parsed.opt("policyVersion"))?.let { out.put("policyVersion", it) }
            parsed.optJSONArray("observedRules")?.let { rules ->
                val values = (0 until rules.length()).map { rules.opt(it) }
                out.put("observedRules", JSONArray(RaspLabPolicyFields.observedRules(values)))
            }
            // The evaluation response has no `enforcementMode`: `shadowMode` and `policyStatus` tell the mode.
            if (parsed.has("shadowMode")) out.put("shadowMode", if (parsed.isNull("shadowMode")) JSONObject.NULL
                else parsed.optBoolean("shadowMode"))
        }
        if (snapshot != null) putSnapshot(out, snapshot)
        if (error != null) out.put("error", error)
        instrumentation.sendStatus(STATUS_CODE, Bundle().apply { putString(KEY, out.toString()) })
    }

    /** States, the closed-set reasons of each UNKNOWN or ERROR, the deadline used and the collection duration. */
    private fun putSnapshot(out: JSONObject, snapshot: SignalsSnapshot) {
        val states = JSONObject()
        val reasons = JSONObject()
        snapshot.observations.forEach {
            if (!CAPABILITY.matches(it.capabilityId)) return@forEach
            states.put(it.capabilityId, it.state.name)
            if (it.state == SignalState.UNKNOWN || it.state == SignalState.ERROR) {
                reasons.put(it.capabilityId, JSONArray(RaspLabReasons.of(it.state, it.detail)))
            }
        }
        out.put("catalogVersion", snapshot.catalogVersion).put("states", states).put("reasons", reasons)
            .put("deadlineMs", deadlineMs).put("durationMs", snapshot.durationMs.coerceIn(0L, 600_000L))
    }

    private fun enroll(): Boolean {
        var answered: Answer? = null
        return try {
            val challengeAnswer = post("/v1/$org/$app/$env/challenges", caller())
            if (challengeAnswer.status != 201) {
                report("enroll", challengeAnswer, "challenge")
                return false
            }
            // Parsed inside the try: a body that is not the expected JSON is reported by type, never in a stack trace.
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
                // The grant lifetime the server answered, when it answers one; else the API default (see the constant).
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
     * D-12h: one reattestation of the enrolled installation. The test is the consumer here too: each signed step goes
     * to the API route it names (only the two reattestation routes of this scope), in the envelope with the caller.
     */
    private fun reattest(): Boolean {
        val outcome = reattestOnce("reattest") ?: return false
        return outcome !is ReattestationNotNow || outcome.reason != ReattestationWait.UNAVAILABLE
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
            reportReattest(id, null, "sdk:" + e.javaClass.simpleName.take(40))
            return null
        }
        reportReattest(id, outcome, null)
        return outcome
    }

    /**
     * D-06h-c: the `reattest-challenge` case. The app's routine ([RaspLabReattestChallenge]): one reattestation only when
     * the server answered `challenge` `reattest`, then the operation repeated once after a completed one. True when
     * every evaluation answered 200 and the reattestation did not throw (a not-now or a refusal is a result, not a
     * failure of the case).
     */
    private fun reattestChallenge(): Boolean {
        var first: Answer? = null
        if (!case("reattest-challenge") {
                val snapshot = collector.snapshot(context)
                evaluate(client.sign("POST", "$operationUrl?seq=reattest-challenge", OPERATION, body(-2),
                    mapOf(SIGNALS_HEADER to header(snapshot)))).also { first = it } to snapshot
            }) return false
        val parsed = try { JSONObject(first!!.body) } catch (_: Exception) { null }
        fun field(json: JSONObject?, key: String) = json?.takeUnless { it.isNull(key) }?.optString(key, "")
        var step = RaspLabReattestChallenge.afterAnswer(field(parsed, "recommendedAction"), field(parsed, "challengeKind"))
        if (step == RaspLabReattestChallenge.Step.REATTEST) {
            val outcome = reattestOnce("reattest-for-challenge") ?: return false
            step = RaspLabReattestChallenge.afterReattest(when (outcome) {
                is ReattestationCompleted -> RaspLabReattestChallenge.Outcome.COMPLETED
                is ReattestationNotNow -> RaspLabReattestChallenge.Outcome.NOT_NOW
                is ReattestationRefused -> RaspLabReattestChallenge.Outcome.REFUSED
            })
        }
        instrumentation.sendStatus(STATUS_CODE, Bundle().apply {
            putString(KEY, JSONObject().put("id", "reattest-step").put("step", step.name).toString())
        })
        if (step != RaspLabReattestChallenge.Step.REPEAT_ONCE) return true
        // Once, with a new nonce (a new signature); its answer is final, whatever it says.
        return case("reattest-retry") {
            val snapshot = collector.snapshot(context)
            evaluate(client.sign("POST", "$operationUrl?seq=reattest-retry", OPERATION, body(-3),
                mapOf(SIGNALS_HEADER to header(snapshot)))) to snapshot
        }
    }

    private fun reportReattest(id: String, outcome: ReattestationOutcome?, error: String?) {
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
            null -> Unit
        }
        if (error != null) out.put("error", error)
        instrumentation.sendStatus(STATUS_CODE, Bundle().apply { putString(KEY, out.toString()) })
    }

    private fun evaluate(signed: SignedMessage, extra: Map<String, String> = emptyMap()): Answer =
        post("/v1/$org/$app/$env/evaluations", JSONObject().put("operation", OPERATION)
            .put("request", envelopeRequest(signed, extra)).put("context", caller()))

    /**
     * The snapshot as the header value, under the same rule the SDK transport applies (printable ASCII, at most
     * [SIGNALS_MAX_LENGTH], the server's limit): with the D-12c detectors (15 capabilities) a snapshot can pass 4096,
     * and the case then fails as `snapshot-too-large` without sending anything, never truncated.
     */
    private fun header(snapshot: SignalsSnapshot): String = snapshot.toJson().also { value ->
        if (value.length > SIGNALS_MAX_LENGTH || value.any { it.code !in 0x20..0x7E }) throw SnapshotTooLarge()
    }

    private class SnapshotTooLarge : IllegalStateException()

    private fun body(i: Int) = "{\"synthetic\":true,\"case\":\"d05g\",\"seq\":$i}".toByteArray()

    /** Test-only construction: collections discarded before the first case, reported without anything sent. */
    private fun warmUp(count: Int) = repeat(count) {
        val out = JSONObject().put("id", "warmup").put("seq", it)
        try {
            putSnapshot(out, collector.snapshot(context))
        } catch (e: Exception) {
            out.put("error", "sdk:" + e.javaClass.simpleName.take(40))
        }
        instrumentation.sendStatus(STATUS_CODE, Bundle().apply { putString(KEY, out.toString()) })
    }

    /** Runs one case; true only when the evaluation answered 200. A failure is reported by its type, never its message. */
    private fun case(id: String, block: () -> Pair<Answer, SignalsSnapshot>): Boolean = try {
        val (answer, snapshot) = block()
        report(id, answer, snapshot = snapshot)
        answer.status == 200
    } catch (_: SnapshotTooLarge) {
        report(id, null, "snapshot-too-large")
        false
    } catch (e: Exception) {
        report(id, null, "sdk:" + e.javaClass.simpleName.take(40))
        false
    }

    @Test
    fun test_D05G_lab_cases() {
        val operations = operationsArgument.toIntOrNull()
        assertTrue("operations must be an integer in 1..20", operations != null && operations in 1..20)
        val delay = operationDelayArgument.toLongOrNull()
        assertTrue("operationDelayMs must be an integer in 0..15000", delay != null && delay in 0..15_000)
        assertTrue("reattest must be true or false", reattestArgument == "true" || reattestArgument == "false")
        assertTrue("reattestChallenge must be true or false",
            reattestChallengeArgument == "true" || reattestChallengeArgument == "false")
        // Review R M-4 of the D-06h-c: one reattestation per run; with both, the second would meet the server's interval.
        assertTrue("reattest and reattestChallenge are separate runs", !(reattestArgument == "true" && reattestChallengeArgument == "true"))
        val warmup = warmupArgument.toIntOrNull()
        assertTrue("warmup must be an integer in 0..3", warmup != null && warmup in 0..3)
        assertTrue("enrollment failed (see the d05gCase status)", enroll())
        warmUp(warmup!!)
        var ok = true
        repeat(operations!!) { i ->
            if (i > 0 && delay!! > 0) Thread.sleep(delay)
            ok = case("collected") {
                val snapshot = collector.snapshot(context)
                evaluate(client.sign("POST", "$operationUrl?seq=$i", OPERATION, body(i),
                    mapOf(SIGNALS_HEADER to header(snapshot)))) to snapshot
            } && ok
        }
        ok = case("unsigned-snapshot") {
            val snapshot = collector.snapshot(context)
            val value = header(snapshot)
            val signed = client.sign("POST", "$operationUrl?seq=unsigned", OPERATION, body(-1))
            check(signed.headers.none { it.first.equals(SIGNALS_HEADER, ignoreCase = true) })
            evaluate(signed, mapOf(SIGNALS_HEADER to value)) to snapshot
        } && ok
        if (reattestArgument == "true") ok = reattest() && ok
        if (reattestChallengeArgument == "true") ok = reattestChallenge() && ok
        assertTrue("an evaluation did not answer 200 (see the d05gCase statuses)", ok)
    }

    companion object {
        const val KEY = "d05gCase"
        /** Not a code AndroidJUnitRunner uses (1, 0, -1..-4); the same as the J-04s2. */
        const val STATUS_CODE = 7
        const val OPERATION = "submit"
        const val SIGNALS_HEADER = "x-sentomaru-signals"
        const val SUBJECT = "d05g-lab"
        const val TENANT = "rasp-lab"
        /**
         * Fallback only: the API's default grant lifetime (SENTOMARU_GRANT_TTL_SECONDS, not set in the HML, so 600),
         * used when the enrollment answer carries no `ttlSeconds`. A shorter real lifetime is renewed reactively by
         * the SDK; this test runs a few operations within seconds of the enrollment.
         */
        const val GRANT_TTL_SECONDS = 600L
        /**
         * Public SHA-256 digest of the test keystore certificate (alias `exemplos`, the same as the J-04s release
         * `RELEASE_CERT_SHA256`); the default expected signer of `app_signer_mismatch` with `signals=rasp+integrity`.
         */
        const val TEST_CERT_SHA256 = "77b30c9f816fc928eaf9c70e3c29bfbd5084317d0482bb48aab3f1ef4f72fc91"
        /** The SDK transport's limit for the header (`SignalsHeader.MAX_LENGTH`, internal to the SDK module). */
        const val SIGNALS_MAX_LENGTH = 4096
        private val LAB_APPS = setOf("rasp-lab", "integrity-lab")
        private val WORKLOAD_TOKEN = Regex("[A-Za-z0-9_-]{43}")
        private val API = Regex("https://([a-z0-9.-]+)(?::\\d{2,5})?/?")
        private val SLUG = Regex("[a-z0-9][a-z0-9-]{0,62}")
        private val TOKEN = Regex("[a-zA-Z][a-zA-Z0-9_-]{0,47}")
        private val REASON = Regex("[A-Z0-9_]{3,64}")
        private val CAPABILITY = Regex("[a-z][a-z0-9_]{0,63}")
        private val RETRY_AFTER = Regex("[0-9]{1,7}")
        private val DEADLINE_RANGE = 100L..2_000L
    }
}
