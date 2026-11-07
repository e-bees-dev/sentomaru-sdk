package br.com.ebees.sentomaru.rasplab

import android.os.Bundle
import androidx.test.ext.junit.runners.AndroidJUnit4
import androidx.test.platform.app.InstrumentationRegistry
import br.com.ebees.sentomaru.core.SentomaruException
import br.com.ebees.sentomaru.sdk.EnrollmentChallenge
import br.com.ebees.sentomaru.sdk.EnrollmentGrant
import br.com.ebees.sentomaru.sdk.SentomaruClient
import br.com.ebees.sentomaru.sdk.SentomaruConfig
import br.com.ebees.sentomaru.sdk.transport.SentomaruRoutes
import br.com.ebees.sentomaru.sdk.transport.addSentomaru
import br.com.ebees.sentomaru.signals.SentomaruServerResponseEvent
import br.com.ebees.sentomaru.signals.SentomaruSignalEvent
import br.com.ebees.sentomaru.signals.SentomaruSignalEvents
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
import java.security.MessageDigest
import java.security.cert.CertificateException
import java.security.cert.X509Certificate
import java.time.Instant
import java.util.Base64
import java.util.concurrent.CopyOnWriteArrayList
import java.util.concurrent.Executor
import java.util.concurrent.TimeUnit
import javax.net.ssl.HostnameVerifier
import javax.net.ssl.SSLContext
import javax.net.ssl.TrustManager
import javax.net.ssl.X509TrustManager

/**
 * P-1 (device round J-2/J-6): the step-up of the policy ladder
 * (`policy-rasp-ladder-example.json`) seen from the app, against the lab host `integrations/samples/aspnetcore-rasp-lab-host`.
 * RASP lab build only (`-Psentomaru.raspLab=true`, package `br.com.ebees.sentomaru.rasplab`).
 *
 * Unlike [RaspLabCasesInstrumentedTest] (the test plays the consumer and holds the workload token), here the consumer is
 * the lab host: the test never holds a token. It uses the SDK transport the way an app does: `addSentomaru(client,
 * routes, events)`, the enrollment routes of the host and one protected route (`POST /pedidos/{id}/concluir`).
 *
 * Arguments (instrumentation): `host` (https origin of the lab host, required), `hostCertSha256` (SHA-256 hex of the
 * host's self-signed certificate, printed by the host at start; required: it is the only certificate the test trusts,
 * for that host only, never the system store), `org`/`app`/`env` (defaults `ebees`/`rasp-lab`/`hml`), `signals`
 * (`rasp` default or `rasp+integrity`), `expectedSigner` (as in the other lab test), `deadlineMs`, `warmup`.
 *
 * Cases (one status `d06iCase` each, fields of limited format only: HTTP status, closed `code`, `challengeKind`, the
 * `server_response` event type; never a token, id, serial, body or exception message):
 * - `enroll`: enrollment through the host (challenge issued by the host for the lab login, signed enrollment forwarded).
 * - `step-up-old-login`: the protected route with a login 30 minutes old (`X-Lab-Auth-Age-Seconds: 1800`). With the
 *   ladder active and the device with a root artifact the expected answer is `401 challenge-required` `step_up`; the
 *   server-response event of the SDK is reported next to it (`events`).
 * - `step-up-recent-login`: the same with a login 30 seconds old, the "after the step-up" request: the handler of the
 *   host accepts it, the expected answer is `200`.
 * - `step-up-old-login-again` (R-2): the old login right after the 200 is challenged again; `step-up-recent-login` also
 *   reports `stepUpProceeded` (the adapter's `StepUpProceededItem`, shown by the sample controller as a header).
 * - `observe-route-old-login` (R-2): an observe-only route, no operation id, so the handler is not asked: `200`.
 * - `candidate-1/2/3` (D-06i-e): allow, then a request with the snapshot (an observe rule matches), then allow, on one
 *   installation: the candidate criterion of the observation panel.
 * - `signal-first-collection` / `signal-second-collection` (R-3, D-15): number of `signal` events and the state per
 *   capability id; the second collection, with nothing changed, emits none.
 * The expected answer of each case lives in the roteiro, never here: without the ladder (or on a clean device) the old
 * login also gets `200`, and the case reports it as it is.
 */
@RunWith(AndroidJUnit4::class)
class RaspLabStepUpInstrumentedTest {

    private val instrumentation = InstrumentationRegistry.getInstrumentation()
    private val context = instrumentation.targetContext
    private val arguments = InstrumentationRegistry.getArguments()
    private val org = arguments.getString("org", "ebees")
    private val app = arguments.getString("app", "rasp-lab")
    private val env = arguments.getString("env", "hml")
    private val hostArgument = arguments.getString("host", "")
    private val certArgument = arguments.getString("hostCertSha256", "")
    private val signalsArgument = arguments.getString("signals", "rasp")
    private val expectedSignerArgument = arguments.getString("expectedSigner", RaspLabCasesInstrumentedTest.TEST_CERT_SHA256)
    private val deadlineArgument: String? = arguments.getString("deadlineMs")
    private val warmupArgument = arguments.getString("warmup", "0")
    private val json = "application/json".toMediaType()

    private lateinit var base: String
    private lateinit var hostName: String
    private lateinit var client: SentomaruClient
    private lateinit var http: OkHttpClient
    /** Challenge and enrollment: the signing interceptor refuses any request to an allowed host before an installation exists. */
    private lateinit var plain: OkHttpClient
    private lateinit var collector: SignalsCollector
    private val responses = CopyOnWriteArrayList<SentomaruServerResponseEvent>()
    private val signalEvents = CopyOnWriteArrayList<SentomaruSignalEvent>()

    @Before
    fun setUp() {
        val match = HOST.matchEntire(hostArgument)
        assertTrue("host must be an https origin without path", match != null)
        base = hostArgument.trimEnd('/')
        hostName = match!!.groupValues[1]
        assertTrue("hostCertSha256 argument required (64 hex)", CERT_SHA256.matches(certArgument))
        assertTrue("scope must be slugs", listOf(org, app, env).all { SLUG.matches(it) })
        assertTrue("only the lab apps are accepted: $LAB_APPS", app in LAB_APPS)
        val warmup = warmupArgument.toIntOrNull()
        assertTrue("warmup must be 0..3", warmup != null && warmup in 0..3)
        val detectors = when (signalsArgument) {
            "rasp" -> SignalsCollector.defaultDetectors() + SignalsCollector.raspDetectors()
            "rasp+integrity" -> SignalsCollector.defaultDetectors() + SignalsCollector.raspDetectors() +
                SignalsCollector.appIntegrityDetectors(listOf(expectedSignerArgument))
            else -> throw AssertionError("signals must be rasp or rasp+integrity")
        }
        val defaultDeadline = SignalsCollector.RASP_DEADLINE_MS +
            if (signalsArgument == "rasp+integrity") SignalsCollector.APP_INTEGRITY_BUDGET_MS else 0L
        val deadline = if (deadlineArgument == null) defaultDeadline else deadlineArgument.toLongOrNull()
        assertTrue("deadlineMs must be an integer in 100..2000", deadline != null && deadline in 100L..2000L)
        val events = SentomaruSignalEvents()
        events.addServerResponseListener(Executor { it.run() }) { responses.add(it) }
        events.addListener(Executor { it.run() }) { signalEvents.add(it) }
        collector = SignalsCollector(detectors = detectors, deadlineMs = deadline!!).also { it.events = events }
        repeat(warmup!!) { collector.snapshot(context) }

        client = SentomaruClient.initialize(context, SentomaruConfig(org, app, env, setOf(hostName),
            "$base/integrity/v1/$org/$app/$env/installations"))
        client.reset()
        val routes = SentomaruRoutes.of(listOf(hostName),
            listOf(SentomaruRoutes.Route("/pedidos/*/concluir", OPERATION)))
        val trust = PinnedLeaf(certArgument)
        val tls = SSLContext.getInstance("TLS").apply { init(null, arrayOf<TrustManager>(trust), null) }
        // The only certificate trusted is the host's own, by digest; no redirect and no silent retry (a retried POST
        // could spend a single-use challenge or nonce twice and hide what the case measured).
        plain = OkHttpClient.Builder().sslSocketFactory(tls.socketFactory, trust)
            .hostnameVerifier(HostnameVerifier { name, _ -> name == hostName })
            .retryOnConnectionFailure(false).callTimeout(30, TimeUnit.SECONDS).build()
        http = plain.newBuilder().addSentomaru(client, routes, events).build()
    }

    @After
    fun tearDown() {
        // Local only: the installation on the server is removed by the roteiro cleanup.
        if (::client.isInitialized) client.reset()
    }

    @Test
    fun stepUpLadder() {
        // R-3 (D-15): the first collection of the run (the warm-up ones of setUp included) emits one signal event per
        // capability; the next, with nothing changed, emits none. Counted before the enrollment, on this test's own collector.
        collector.snapshot(context)
        reportSignals("signal-first-collection")
        signalEvents.clear()
        collector.snapshot(context)
        reportSignals("signal-second-collection")
        if (!enroll()) return
        for ((case, age) in listOf("step-up-old-login" to OLD_LOGIN_SECONDS, "step-up-recent-login" to RECENT_LOGIN_SECONDS,
            // R-2: the old login again right after the 200 is challenged again (the adapter keeps no step-up state).
            "step-up-old-login-again" to OLD_LOGIN_SECONDS)) {
            responses.clear()
            operation(case, age)
        }
        // R-2: an observe-only route (no protected operation, so no operation id): the handler is not asked, 200 even
        // with the old login.
        responses.clear()
        operation("observe-route-old-login", OLD_LOGIN_SECONDS, path = "$base/pedidos/lab-observe", get = true)
        // D-06i-e: allow -> challenge (an observe rule matched) -> allow on one installation, the J-04 candidate criterion.
        // The first and third requests carry no snapshot (no signal, so the default allow); the second carries it.
        for ((case, withSignals) in listOf("candidate-1-no-signals" to false, "candidate-2-with-signals" to true, "candidate-3-no-signals" to false)) {
            responses.clear()
            operation(case, RECENT_LOGIN_SECONDS, path = "$base/pedidos/lab-candidate", get = true, withSignals = withSignals)
        }
    }

    /** One status per collection: how many signal events and, per capability id, the state of the event (closed vocabulary). */
    private fun reportSignals(case: String) {
        val out = JSONObject().put("id", case).put("signalEvents", signalEvents.size)
        out.put("states", JSONArray(signalEvents.map { e -> JSONObject().put("capabilityId", e.capabilityId.takeIf { c -> TOKEN.matches(c) })
            .put("state", e.state.name) }))
        instrumentation.sendStatus(STATUS_CODE, Bundle().apply { putString(KEY, out.toString()) })
    }

    /** The host's challenge route (for the lab login), then the signed enrollment forwarded to the installations route. */
    private fun enroll(): Boolean {
        var status: Int? = null
        var refusal: String? = null
        return try {
            val challenge = plain.newCall(post("$base/integrity/challenges", "{}".toByteArray(), RECENT_LOGIN_SECONDS)).execute().use {
                status = it.code
                if (it.code != 201) { report("enroll", it.code, "challenge"); return false }
                JSONObject(it.body?.string().orEmpty())
            }
            val enrollmentChallenge = EnrollmentChallenge(challenge.optString("challengeId", challenge.optString("id")),
                challenge.optString("challenge", challenge.optString("token")),
                Base64.getDecoder().decode(challenge.getString("attestationChallenge")),
                Instant.parse(challenge.getString("expiresAt")))
            val sentAt = Instant.now()
            client.enroll(enrollmentChallenge) { signed ->
                val request = Request.Builder().url(signed.targetUri).post(signed.body().toRequestBody(json))
                signed.headers.forEach { (k, v) -> request.header(k, v) }
                plain.newCall(request.build()).execute().use {
                    status = it.code
                    if (it.code !in 200..299) {
                        // The closed `code` of the API error, so a refusal is not reported only as a network failure.
                        refusal = try { JSONObject(it.body?.string().orEmpty()).optString("code") } catch (_: Exception) { null }
                        throw IOException("enrollment")
                    }
                    val g = JSONObject(it.body?.string().orEmpty())
                    val ttl = g.optLong("ttlSeconds", GRANT_TTL_SECONDS).takeIf { v -> v in 1..86_400 } ?: GRANT_TTL_SECONDS
                    EnrollmentGrant(g.getString("installationId"), g.getString("keyId"), g.getString("sessionId"),
                        g.getString("hardwareStatus"), g.getString("attestationStatus"), sentAt, ttl)
                }
            }
            report("enroll", status)
            true
        } catch (e: Exception) {
            // The exception type is a fixed-format name, never a message: it says where enrollment stopped even after a 201.
            report("enroll", status, code = refusal, error = "sdk:" + e.javaClass.simpleName.take(40) +
                (e as? SentomaruException)?.let { ":" + it.error.code.replace(Regex("[^A-Za-z0-9:_-]"), "").take(40) }.orEmpty())
            false
        }
    }

    /** One protected call with a fresh snapshot (signed by the transport) and the lab login of [ageSeconds]. */
    private fun operation(case: String, ageSeconds: Int, path: String = "$base/pedidos/lab-$case/concluir", get: Boolean = false, withSignals: Boolean = true) {
        try {
            val snapshot = collector.snapshot(context)
            val signals = snapshot.toJson()
            check(signals.length <= SIGNALS_MAX_LENGTH && signals.all { it.code in 0x20..0x7E }) { "snapshot-too-large" }
            val request = (if (get) Request.Builder().url(path).header(AGE_HEADER, ageSeconds.toString()).get().build()
                else post(path, "{}".toByteArray(), ageSeconds)).newBuilder().apply { if (withSignals) header(SIGNALS_HEADER, signals) }.build()
            http.newCall(request).execute().use {
                val parsed = try { JSONObject(it.body?.string().orEmpty()) } catch (_: Exception) { null }
                report(case, it.code, code = parsed?.takeUnless { p -> p.isNull("code") }?.optString("code"),
                    kind = parsed?.takeUnless { p -> p.isNull("challengeKind") }?.optString("challengeKind"),
                    proceeded = it.header(PROCEEDED_HEADER) == "true")
            }
        } catch (e: Exception) {
            // check() failures carry the fixed code above; anything else is reported by its exception type only.
            report(case, null, if (e is IllegalStateException) "snapshot-too-large" else "sdk:" + e.javaClass.simpleName.take(40))
        }
    }

    private fun post(url: String, body: ByteArray, ageSeconds: Int): Request = Request.Builder().url(url)
        .header(AGE_HEADER, ageSeconds.toString())
        // ByteArray body: String.toRequestBody appends "; charset=utf-8", and the API requires exactly application/json.
        .post(body.toRequestBody(json)).build()

    /** One case result, fields of limited format only. A value outside its format is dropped, never echoed. */
    private fun report(case: String, status: Int?, error: String? = null, code: String? = null, kind: String? = null, proceeded: Boolean? = null) {
        val out = JSONObject().put("id", case)
        if (status != null) out.put("status", status)
        if (code != null && TOKEN.matches(code)) out.put("code", code)
        if (kind != null && TOKEN.matches(kind)) out.put("challengeKind", kind)
        if (proceeded != null) out.put("stepUpProceeded", proceeded)
        if (case.startsWith("step-up") || case.startsWith("observe-route") || case.startsWith("candidate")) {
            out.put("events", JSONArray(responses.map { e ->
                JSONObject().put("type", "server_response").put("code", e.code.takeIf { c -> TOKEN.matches(c) })
                    .put("challengeKind", e.challengeKind?.takeIf { c -> TOKEN.matches(c) }).put("httpStatus", e.httpStatus)
            }))
        }
        if (error != null) out.put("error", error)
        instrumentation.sendStatus(STATUS_CODE, Bundle().apply { putString(KEY, out.toString()) })
    }

    /** Trusts exactly the leaf whose SHA-256 is [expected]; the system store is not consulted. */
    private class PinnedLeaf(private val expected: String) : X509TrustManager {
        override fun checkClientTrusted(chain: Array<X509Certificate>, authType: String) = throw CertificateException("client")
        override fun checkServerTrusted(chain: Array<X509Certificate>, authType: String) {
            val leaf = chain.firstOrNull() ?: throw CertificateException("empty")
            val digest = MessageDigest.getInstance("SHA-256").digest(leaf.encoded).joinToString("") { "%02x".format(it) }
            if (!MessageDigest.isEqual(digest.toByteArray(), expected.lowercase().toByteArray())) throw CertificateException("pin")
            leaf.checkValidity()
        }
        override fun getAcceptedIssuers(): Array<X509Certificate> = emptyArray()
    }

    companion object {
        const val KEY = "d06iCase"
        /** Same status code as the other lab tests (not one AndroidJUnitRunner uses). */
        const val STATUS_CODE = 7
        const val OPERATION = "concluir_pedido"
        const val SIGNALS_HEADER = "x-sentomaru-signals"
        const val AGE_HEADER = "X-Lab-Auth-Age-Seconds"
        /** Set by the sample controller when the adapter marked HttpContext.Items[StepUpProceededItem]. */
        const val PROCEEDED_HEADER = "X-Lab-StepUp-Proceeded"
        const val OLD_LOGIN_SECONDS = 1800
        const val RECENT_LOGIN_SECONDS = 30
        const val SIGNALS_MAX_LENGTH = 4096
        const val GRANT_TTL_SECONDS = 600L
        private val LAB_APPS = setOf("rasp-lab", "integrity-lab")
        private val HOST = Regex("https://([a-z0-9.-]+)(?::\\d{2,5})?/?")
        private val CERT_SHA256 = Regex("[0-9a-fA-F]{64}")
        private val SLUG = Regex("[a-z0-9][a-z0-9-]{0,62}")
        private val TOKEN = Regex("[a-zA-Z][a-zA-Z0-9_-]{0,47}")
    }
}
