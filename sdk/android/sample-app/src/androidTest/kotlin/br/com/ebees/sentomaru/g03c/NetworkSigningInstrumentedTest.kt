package br.com.ebees.sentomaru.g03c

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
import org.junit.Assert.assertNull
import org.junit.Assert.assertThrows
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
 * G-03c on a real device: the app turns on signing in one line with the profile's route table, and the server accepts
 * the request on the route without any per-request tag; the same route without the line (no signature) is refused by
 * the server (a proof of the server, not of the SDK); a route table whose host is outside the allowlist is refused at
 * installation, so nothing is ever sent for it. Runs through `sdk/run_sdk.py --suite
 * g03c` (local two-replica cluster and synthetic consumer over `adb reverse`), in its own package so the C-06 suite
 * (package br.com.ebees.sentomaru.sample) is unchanged.
 */
@RunWith(AndroidJUnit4::class)
class NetworkSigningInstrumentedTest {

    private val context = InstrumentationRegistry.getInstrumentation().targetContext
    private val org = "org-a"
    private val app = "app-a"
    private val env = "hml"
    private val host = "127.0.0.1"
    private val consumerBase = "https://$host:8443"
    private val routeUrl = "$consumerBase/v1/$org/$app/$env/operations/submit?channel=field"
    private val routes = SentomaruRoutes.of(listOf(host), listOf(SentomaruRoutes.Route("/v1/$org/$app/$env/operations/*", "submit")))

    private lateinit var client: SentomaruClient
    private lateinit var plain: OkHttpClient

    @Before
    fun setUp() {
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
            .post(JSONObject().put("subject", "user-a").put("tenant", "tenant-a").toString()
                .toRequestBody("application/json".toMediaType())).build()).execute()
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

    private fun routeRequest() = Request.Builder().url(routeUrl)
        .post("{\"telemetry\":1}".toRequestBody("application/json".toMediaType())).build()

    @Test
    fun test_G03C_1_route_signed_by_the_table_is_accepted_by_the_server() {
        enroll()
        val http = plain.newBuilder().addSentomaru(client, routes).build()
        val response = http.newCall(routeRequest()).execute()
        val body = response.body?.string().orEmpty()
        assertTrue("route request refused: HTTP ${response.code} $body", response.isSuccessful)
        assertEquals("valid", JSONObject(body).getString("proofStatus"))
    }

    @Test
    fun test_G03C_2_server_proof_route_without_the_line_is_refused() {
        enroll()
        // Server-side proof: the app forgot the install line, the protected route goes out without a proof and the
        // server (not the SDK) refuses it.
        val response = plain.newCall(routeRequest().newBuilder().header("X-Consumer-Operation", "submit").build()).execute()
        val body = response.body?.string().orEmpty()
        assertEquals("unsigned route was not refused: $body", 401, response.code)
        assertNull(response.request.header("signature"))
    }

    @Test
    fun test_G03C_3_route_outside_the_allowlist_is_refused_at_installation() {
        // Another identity (environment "lab"): initialize refuses the same identity with different hosts.
        val offList = SentomaruClient.initialize(context, SentomaruConfig(org, app, "lab", setOf("other.example"),
            "https://other.example/v1/$org/$app/lab/installations"))
        val error = assertThrows(IllegalArgumentException::class.java) { plain.newBuilder().addSentomaru(offList, routes) }
        assertEquals("network-signing.hosts not within allowedHosts", error.message)
    }
}
