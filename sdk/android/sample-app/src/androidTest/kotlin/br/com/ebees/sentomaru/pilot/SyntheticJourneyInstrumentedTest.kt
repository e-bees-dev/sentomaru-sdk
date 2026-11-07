package br.com.ebees.sentomaru.pilot

import androidx.test.ext.junit.runners.AndroidJUnit4
import androidx.test.platform.app.InstrumentationRegistry
import br.com.ebees.sentomaru.sdk.EnrollmentChallenge
import br.com.ebees.sentomaru.sdk.EnrollmentGrant
import br.com.ebees.sentomaru.sdk.SentomaruClient
import br.com.ebees.sentomaru.sdk.SentomaruConfig
import br.com.ebees.sentomaru.sdk.transport.SentomaruRoutes
import br.com.ebees.sentomaru.sdk.transport.addSentomaru
import okhttp3.MediaType.Companion.toMediaType
import okhttp3.OkHttpClient
import okhttp3.Request
import okhttp3.RequestBody.Companion.toRequestBody
import org.json.JSONObject
import org.junit.After
import org.junit.Assert.assertEquals
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
 * J-04s synthetic pilot journey: one enrollment and N signed operations through the route table, as a field app would
 * do, against the synthetic consumer on this machine (over `adb reverse`), which forwards to the API of the scope given
 * by the runner (`verification/pilot/run_j04s_synthetic.py`). Synthetic traffic: it measures the path and the server,
 * never a false positive of a real user. Own package, so the C-06 suite (package br.com.ebees.sentomaru.sample) and
 * the G-03c class are unchanged.
 */
@RunWith(AndroidJUnit4::class)
class SyntheticJourneyInstrumentedTest {

    private val context = InstrumentationRegistry.getInstrumentation().targetContext
    private val arguments = InstrumentationRegistry.getArguments()
    private val org = arguments.getString("org", "org-a")
    private val app = arguments.getString("app", "app-a")
    private val env = arguments.getString("env", "hml")
    private val operationsArgument = arguments.getString("operations", "5")
    private val host = "127.0.0.1"
    private val consumerBase = "https://$host:8443"
    private val routes = SentomaruRoutes.of(listOf(host), listOf(SentomaruRoutes.Route("/v1/$org/$app/$env/operations/*", "submit")))

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
        client = SentomaruClient.initialize(context, SentomaruConfig(org, app, env, setOf(host), "$consumerBase/v1/$org/$app/$env/installations"))
        client.reset()
    }

    @After
    fun tearDown() {
        client.reset()
    }

    private fun enroll() {
        val challengeResponse = plain.newCall(Request.Builder().url("$consumerBase/api/consumer/challenge")
            .post("{}".toRequestBody("application/json".toMediaType())).build()).execute()
        val challengeBody = challengeResponse.body?.string().orEmpty()
        assertTrue("challenge: HTTP ${challengeResponse.code}", challengeResponse.isSuccessful)
        val c = JSONObject(challengeBody)
        val challenge = EnrollmentChallenge(c.getString("id"), c.getString("token"),
            Base64.getDecoder().decode(c.getString("attestationChallenge")), Instant.parse(c.getString("expiresAt")))
        client.enroll(challenge) { signed ->
            val request = Request.Builder().url(signed.targetUri).post(signed.body().toRequestBody("application/json".toMediaType()))
            signed.headers.forEach { (k, v) -> request.header(k, v) }
            val response = plain.newCall(request.build()).execute()
            val body = response.body?.string().orEmpty()
            if (!response.isSuccessful) throw IOException("enrollment: HTTP ${response.code}")
            val g = JSONObject(body)
            EnrollmentGrant(g.getString("installationId"), g.getString("keyId"), g.getString("sessionId"),
                g.getString("hardwareStatus"), g.getString("attestationStatus"))
        }
    }

    @Test
    fun test_J04S_1_enrollment_and_signed_operations_are_accepted() {
        // The runner already limits this; a value outside 1..50 here fails the run instead of being silently clamped.
        val operations = operationsArgument.toIntOrNull()
        assertTrue("operations must be an integer in 1..50, got '$operationsArgument'", operations != null && operations in 1..50)
        enroll()
        val http = plain.newBuilder().addSentomaru(client, routes).build()
        repeat(operations!!) { i ->
            val request = Request.Builder().url("$consumerBase/v1/$org/$app/$env/operations/submit?seq=$i")
                .post("{\"synthetic\":true,\"seq\":$i}".toRequestBody("application/json".toMediaType())).build()
            val response = http.newCall(request).execute()
            val body = response.body?.string().orEmpty()
            assertTrue("operation $i refused: HTTP ${response.code}", response.isSuccessful)
            assertEquals("operation $i", "valid", JSONObject(body).getString("proofStatus"))
        }
    }
}
