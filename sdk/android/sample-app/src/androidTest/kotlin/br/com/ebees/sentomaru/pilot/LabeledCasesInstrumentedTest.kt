package br.com.ebees.sentomaru.pilot

import android.os.Bundle
import androidx.test.ext.junit.runners.AndroidJUnit4
import androidx.test.platform.app.InstrumentationRegistry
import br.com.ebees.sentomaru.core.SignedMessage
import br.com.ebees.sentomaru.sdk.EnrollmentChallenge
import br.com.ebees.sentomaru.sdk.EnrollmentGrant
import br.com.ebees.sentomaru.sdk.RenewedGrant
import br.com.ebees.sentomaru.sdk.SentomaruClient
import br.com.ebees.sentomaru.sdk.SentomaruConfig
import br.com.ebees.sentomaru.sdk.transport.SentomaruOperation
import br.com.ebees.sentomaru.sdk.transport.addSentomaru
import br.com.ebees.sentomaru.signals.SignalObservation
import br.com.ebees.sentomaru.signals.SignalState
import br.com.ebees.sentomaru.signals.SignalsCollector
import br.com.ebees.sentomaru.signals.SignalsSnapshot
import okhttp3.MediaType.Companion.toMediaType
import okhttp3.OkHttpClient
import okhttp3.Request
import okhttp3.RequestBody.Companion.toRequestBody
import okhttp3.Response
import org.json.JSONArray
import org.json.JSONObject
import org.junit.After
import org.junit.Assert.assertTrue
import org.junit.Before
import org.junit.Test
import org.junit.runner.RunWith
import java.io.IOException
import java.security.SecureRandom
import java.security.cert.X509Certificate
import java.time.Instant
import java.util.Base64
import javax.net.ssl.SSLContext
import javax.net.ssl.TrustManager
import javax.net.ssl.X509TrustManager

/**
 * J-04s2: labeled synthetic cases on the device (or the emulator), against the strict synthetic consumer on this machine
 * over `adb reverse`. The app only EXECUTES the cases and reports what the server answered, case by case, as an
 * instrumentation status (`j04sCase`, closed fields only: HTTP status, error code, recommended action, reason codes,
 * hardware/attestation status). The expected answer of every case (the gabarito) lives in the runner
 * (the vendor's run j04s synthetic check, `expected_cases`), never here, so an app change cannot move it.
 *
 * Never reported: installation, session, key or challenge ids, tokens, bodies, the serial.
 */
@RunWith(AndroidJUnit4::class)
class LabeledCasesInstrumentedTest {

    private val instrumentation = InstrumentationRegistry.getInstrumentation()
    private val context = instrumentation.targetContext
    private val arguments = InstrumentationRegistry.getArguments()
    private val org = arguments.getString("org", "org-a")
    private val app = arguments.getString("app", "app-a")
    private val env = arguments.getString("env", "hml")
    private val operationsArgument = arguments.getString("operations", "5")
    private val expiredWaitArgument = arguments.getString("expiredWaitS", "0")
    private val host = "127.0.0.1"
    private val base = "https://$host:8443"
    private val operationUrl = "$base/v1/$org/$app/$env/operations/submit"
    private val json = "application/json".toMediaType()

    private lateinit var client: SentomaruClient
    private lateinit var plain: OkHttpClient

    @Before
    fun setUp() {
        // The consumer listens on loopback with a throwaway self-signed certificate; the API leg is real TLS.
        val trustAll = object : X509TrustManager {
            override fun checkClientTrusted(chain: Array<out X509Certificate>?, authType: String?) {}
            override fun checkServerTrusted(chain: Array<out X509Certificate>?, authType: String?) {}
            override fun getAcceptedIssuers(): Array<X509Certificate> = arrayOf()
        }
        val ssl = SSLContext.getInstance("TLS").apply { init(null, arrayOf<TrustManager>(trustAll), SecureRandom()) }
        plain = OkHttpClient.Builder().sslSocketFactory(ssl.socketFactory, trustAll).hostnameVerifier { _, _ -> true }
            .followRedirects(false).followSslRedirects(false).build()
        client = SentomaruClient.initialize(context, SentomaruConfig(org, app, env, setOf(host),
            "$base/v1/$org/$app/$env/installations", renewalUrl = "$base/v1/$org/$app/$env/sessions"))
        client.reset()
    }

    @After
    fun tearDown() {
        client.reset()
    }

    /** One case result, closed fields only. A value that is not a short closed token is dropped, never echoed. */
    private fun report(case: String, response: Response?, body: String?, error: String? = null) {
        val out = JSONObject().put("id", case)
        if (response != null) out.put("status", response.code)
        val parsed = try { if (body.isNullOrEmpty()) null else JSONObject(body) } catch (_: Exception) { null }
        if (parsed != null) {
            for (key in listOf("code", "recommendedAction", "evaluatedAction", "policyStatus", "proofStatus",
                "hardwareStatus", "attestationStatus", "attestationReason")) {
                val value = if (parsed.isNull(key)) "" else parsed.optString(key, "")
                if (TOKEN.matches(value)) out.put(key, value)
            }
            parsed.optJSONArray("reasonCodes")?.let { codes ->
                val kept = JSONArray()
                for (i in 0 until codes.length()) codes.optString(i).takeIf { REASON.matches(it) }?.let { kept.put(it) }
                out.put("reasonCodes", kept)
            }
            if (parsed.has("ttlSeconds")) out.put("ttlSeconds", parsed.optInt("ttlSeconds"))
        }
        if (error != null) out.put("error", error)
        instrumentation.sendStatus(STATUS_CODE, Bundle().apply { putString(KEY, out.toString()) })
    }

    private fun execute(request: Request): Pair<Response, String> {
        val response = plain.newCall(request).execute()
        return response to response.use { it.body?.string().orEmpty() }
    }

    private fun send(signed: SignedMessage, body: ByteArray = signed.body(), url: String = signed.targetUri,
        override: Map<String, String> = emptyMap()): Pair<Response, String> {
        val request = Request.Builder().url(url).post(body.toRequestBody(json))
        signed.headers.forEach { (k, v) -> request.header(k, override[k] ?: v) }
        return execute(request.build())
    }

    private fun enroll(): Boolean {
        val (challengeResponse, challengeBody) = execute(Request.Builder().url("$base/api/consumer/challenge")
            .post("{}".toRequestBody(json)).build())
        if (!challengeResponse.isSuccessful) {
            report("enroll", challengeResponse, challengeBody, "challenge")
            return false
        }
        val c = JSONObject(challengeBody)
        val challenge = EnrollmentChallenge(c.getString("id"), c.getString("token"),
            Base64.getDecoder().decode(c.getString("attestationChallenge")), Instant.parse(c.getString("expiresAt")))
        var answered: Pair<Response, String>? = null
        val sentAt = Instant.now()
        return try {
            client.enroll(challenge) { signed ->
                val result = send(signed)
                answered = result
                if (!result.first.isSuccessful) throw IOException("enrollment")
                val g = JSONObject(result.second)
                EnrollmentGrant(g.getString("installationId"), g.getString("keyId"), g.getString("sessionId"),
                    g.getString("hardwareStatus"), g.getString("attestationStatus"), sentAt, GRANT_TTL_SECONDS)
            }
            report("enroll", answered!!.first, answered!!.second)
            true
        } catch (e: Exception) {
            answered?.let { report("enroll", it.first, it.second) } ?: report("enroll", null, null, "sdk")
            false
        }
    }

    /** The real signals of this device (frozen default detectors), as a field app would send them. */
    private fun collected(): SignalsSnapshot = SignalsCollector().snapshot(context)

    /** A declared snapshot: the given capabilities DETECTED, the other frozen ones NOT_DETECTED (signed by the app). */
    private fun declared(vararg detected: String): SignalsSnapshot {
        val now = Instant.now().toString()
        val ids = listOf("debug_attached", "emulator_detected", "root_indicated")
        return SignalsSnapshot(SignalsCollector.CATALOG_VERSION, now, 1L, ids.map { id ->
            SignalObservation(id, "1.0.0", if (id in detected) SignalState.DETECTED else SignalState.NOT_DETECTED,
                "client_observed", now, emptyMap())
        })
    }

    private fun sign(snapshot: SignalsSnapshot?, operation: String = "submit", url: String = operationUrl,
        body: ByteArray = "{\"synthetic\":true}".toByteArray()): SignedMessage =
        client.sign("POST", url, operation, body,
            if (snapshot == null) emptyMap() else mapOf("x-sentomaru-signals" to snapshot.toJson()))

    private fun guarded(case: String, block: () -> Unit) {
        try { block() } catch (e: Exception) { report(case, null, null, "sdk:" + e.javaClass.simpleName.take(40)) }
    }

    @Test
    fun test_J04S2_labeled_cases() {
        val operations = operationsArgument.toIntOrNull()
        assertTrue("operations must be an integer in 1..50, got '$operationsArgument'", operations != null && operations in 1..50)
        val expiredWait = expiredWaitArgument.toLongOrNull() ?: -1L
        assertTrue("expiredWaitS must be 0..1800", expiredWait in 0..1800)
        if (!enroll()) return // the runner marks every other case as not run

        // GOOD: N operations through the route table path (OkHttp interceptor), with the real signals of this device.
        val http = plain.newBuilder().addSentomaru(client).build()
        repeat(operations!!) { i ->
            guarded("op") {
                val request = Request.Builder().url("$operationUrl?seq=$i")
                    .tag(SentomaruOperation::class.java, SentomaruOperation("submit", collected()))
                    .post("{\"synthetic\":true,\"seq\":$i}".toRequestBody(json)).build()
                val (response, body) = execute(http, request)
                report("op", response, body)
            }
        }

        // GOOD: signed renewal (no new attestation), then one operation on the renewed session.
        guarded("renewal") {
            var answered: Pair<Response, String>? = null
            try {
                client.renew { signed ->
                    val result = send(signed)
                    answered = result
                    if (!result.first.isSuccessful) throw IOException("renewal")
                    val r = JSONObject(result.second)
                    RenewedGrant(r.getString("installationId"), r.getString("keyId"), r.getString("sessionId"),
                        r.getLong("ttlSeconds"))
                }
            } catch (_: Exception) { }
            answered?.let { report("renewal", it.first, it.second) } ?: report("renewal", null, null, "sdk")
        }
        guarded("op-after-renewal") {
            val (response, body) = send(sign(collected()))
            report("op-after-renewal", response, body)
        }

        // BAD: the exact same signed message twice (same nonce and signature): the second is a replay.
        guarded("replay") {
            val signed = sign(collected())
            val (first, firstBody) = send(signed)
            report("replay-original", first, firstBody)
            val (second, secondBody) = send(signed)
            report("replay", second, secondBody)
        }

        // BAD: the body changed after the signature (content digest no longer matches).
        guarded("tampered-body") {
            val (response, body) = send(sign(collected()), body = "{\"synthetic\":false}".toByteArray())
            report("tampered-body", response, body)
        }

        // BAD: one character of the signature value changed (still valid base64, never the original).
        guarded("tampered-signature") {
            val signed = sign(collected())
            val (name, original) = signed.headers.first { it.first.equals("signature", ignoreCase = true) }
            val at = original.indexOf(":") + 5
            val flipped = original.substring(0, at) + (if (original[at] == 'A') 'B' else 'A') + original.substring(at + 1)
            val (response, body) = send(signed, override = mapOf(name to flipped))
            report("tampered-signature", response, body)
        }

        // BAD: the app signed operation `approve`; the consumer (strict) evaluates `submit`: operation-context.
        guarded("operation-context") {
            val (response, body) = send(sign(collected(), operation = "approve", url = "$base/v1/$org/$app/$env/operations/approve"))
            report("operation-context", response, body)
        }

        // DECLARED: debugger / root DETECTED in the signed snapshot; the scope policy decides (built-in default here).
        guarded("declared-debugger") {
            val (response, body) = send(sign(declared("debug_attached")))
            report("declared-debugger", response, body)
        }
        guarded("declared-root") {
            val (response, body) = send(sign(declared("root_indicated")))
            report("declared-root", response, body)
        }

        // BAD (only with expiredWaitS, the emulator track): after the grant lifetime, an operation signed with the old
        // grant, sent without the SDK's renewal path, is refused with session-expired.
        if (expiredWait > 0) {
            guarded("session-expired") {
                Thread.sleep(expiredWait * 1000L)
                val (response, body) = send(sign(collected()))
                report("session-expired", response, body)
            }
        }
    }

    private fun execute(http: OkHttpClient, request: Request): Pair<Response, String> {
        val response = http.newCall(request).execute()
        return response to response.use { it.body?.string().orEmpty() }
    }

    companion object {
        const val KEY = "j04sCase"
        /** The API's default grant lifetime (SENTOMARU_GRANT_TTL_SECONDS, 600 in the HML); a shorter one is renewed reactively. */
        const val GRANT_TTL_SECONDS = 600L
        /** Not a code AndroidJUnitRunner uses (1, 0, -1..-4): the runner strips these blocks before parsing tests. */
        const val STATUS_CODE = 7
        private val TOKEN = Regex("[a-zA-Z][a-zA-Z0-9_-]{0,47}")
        private val REASON = Regex("[A-Z0-9_]{3,64}")
    }
}
