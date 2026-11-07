package br.com.ebees.sentomaru.j04r

import androidx.test.ext.junit.runners.AndroidJUnit4
import androidx.test.platform.app.InstrumentationRegistry
import br.com.ebees.sentomaru.sdk.EnrollmentChallenge
import br.com.ebees.sentomaru.sdk.EnrollmentGrant
import br.com.ebees.sentomaru.sdk.SentomaruClient
import br.com.ebees.sentomaru.sdk.SentomaruConfig
import br.com.ebees.sentomaru.sdk.transport.SentomaruOperation
import br.com.ebees.sentomaru.sdk.transport.addSentomaru
import okhttp3.MediaType.Companion.toMediaType
import okhttp3.OkHttpClient
import okhttp3.Request
import okhttp3.RequestBody.Companion.toRequestBody
import org.json.JSONObject
import org.junit.After
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNotEquals
import org.junit.Assert.assertTrue
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
 * J-04r on a real device against the local two-replica cluster whose grants live [GRANT_TTL_SECONDS] (the runner starts
 * it with SENTOMARU_GRANT_TTL_SECONDS), through the synthetic consumer over `adb reverse`:
 *  1. after the grant expired, an operation is refused with `session-expired`, the SDK renews (signed, no attestation)
 *     and resends once, and the server accepts it with the NEW session;
 *  2. after a renewal the SDK knows the lifetime: not due at once (margin min(120 s, ttl/5) = 6 s), due inside the
 *     margin, and then it renews BEFORE the next operation (no refusal first);
 *  3. a server proof: without a renewal URL, the expired grant's operation stays refused (`session-expired`).
 * Own package (br.com.ebees.sentomaru.j04r) so the C-06 and G-03c suites are unchanged.
 */
@RunWith(AndroidJUnit4::class)
class GrantRenewalInstrumentedTest {

    private val context = InstrumentationRegistry.getInstrumentation().targetContext
    private val org = "org-a"
    private val app = "app-a"
    private val env = "hml"
    private val trustAll = object : X509TrustManager {
        override fun checkClientTrusted(chain: Array<out X509Certificate>?, authType: String?) {}
        override fun checkServerTrusted(chain: Array<out X509Certificate>?, authType: String?) {}
        override fun getAcceptedIssuers(): Array<X509Certificate> = arrayOf()
    }
    private val plain: OkHttpClient = SSLContext.getInstance("TLS").apply {
        init(null, arrayOf<TrustManager>(trustAll), SecureRandom())
    }.let { ssl ->
        OkHttpClient.Builder().sslSocketFactory(ssl.socketFactory, trustAll).hostnameVerifier { _, _ -> true }
            .followRedirects(false).followSslRedirects(false).build()
    }
    private val clients = mutableListOf<SentomaruClient>()

    /** Distinct hosts give distinct SDK identities, so the renewing and the non-renewing clients never share state. */
    private fun client(host: String, renewal: Boolean): SentomaruClient {
        val base = "https://$host:8443"
        return SentomaruClient.initialize(context, SentomaruConfig(org, app, env, setOf(host),
            "$base/v1/$org/$app/$env/installations",
            renewalUrl = if (renewal) "$base/v1/$org/$app/$env/sessions" else null)).also {
            it.reset()
            clients += it
        }
    }

    @After
    fun tearDown() = clients.forEach { it.reset() }

    private fun enroll(sdk: SentomaruClient, host: String) {
        val base = "https://$host:8443"
        val challengeResponse = plain.newCall(Request.Builder().url("$base/api/consumer/challenge")
            .post(JSONObject().put("subject", "user-a").put("tenant", "tenant-a").toString()
                .toRequestBody("application/json".toMediaType())).build()).execute()
        val c = JSONObject(challengeResponse.body?.string().orEmpty())
        assertTrue("challenge: HTTP ${challengeResponse.code}", challengeResponse.isSuccessful)
        val challenge = EnrollmentChallenge(c.getString("id"), c.getString("token"),
            Base64.getDecoder().decode(c.getString("attestationChallenge")), Instant.parse(c.getString("expiresAt")))
        sdk.enroll(challenge) { signed ->
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

    private fun operation(http: OkHttpClient, host: String) = http.newCall(Request.Builder()
        .url("https://$host:8443/v1/$org/$app/$env/operations/submit")
        .tag(SentomaruOperation::class.java, SentomaruOperation("submit"))
        .post("{\"value\":1}".toRequestBody("application/json".toMediaType())).build()).execute()

    private fun waitForExpiry() = Thread.sleep((GRANT_TTL_SECONDS + 2) * 1000L)

    @Test
    fun test_J04R_1_expired_grant_is_renewed_on_session_expired_and_the_resend_is_accepted() {
        val host = "localhost"
        val sdk = client(host, renewal = true)
        enroll(sdk, host)
        val enrolledSession = sdk.sessionId()
        waitForExpiry()
        val response = operation(plain.newBuilder().addSentomaru(sdk).build(), host)
        val body = response.body?.string().orEmpty()
        assertTrue("resend refused: HTTP ${response.code} $body", response.isSuccessful)
        val accepted = JSONObject(body)
        assertEquals("valid", accepted.getString("proofStatus"))
        assertNotEquals(enrolledSession, accepted.getString("sessionId"))
        assertEquals(sdk.sessionId(), accepted.getString("sessionId"))
    }

    @Test
    fun test_J04R_2_a_renewed_grant_is_renewed_before_the_next_operation() {
        val host = "localhost"
        val sdk = client(host, renewal = true)
        enroll(sdk, host)
        waitForExpiry()
        val http = plain.newBuilder().addSentomaru(sdk).build()
        assertTrue(operation(http, host).isSuccessful) // reactive renewal (test 1)
        val renewedSession = sdk.sessionId()
        // The renewal answered the lifetime (30 s): the margin is min(120 s, 30/5) = 6 s, so the grant is NOT due right
        // after the renewal, and IS due 25 s later (inside the margin): the next signature renews first, no refusal.
        assertFalse("due right after the renewal", sdk.needsRenewal())
        Thread.sleep((GRANT_TTL_SECONDS - 5) * 1000L)
        assertTrue("not due inside the margin", sdk.needsRenewal())
        val response = operation(http, host)
        val body = response.body?.string().orEmpty()
        assertTrue("proactive renewal failed: HTTP ${response.code} $body", response.isSuccessful)
        assertNotEquals(renewedSession, JSONObject(body).getString("sessionId"))
    }

    @Test
    fun test_J04R_3_server_proof_without_renewal_the_expired_grant_stays_refused() {
        val host = "127.0.0.1"
        val sdk = client(host, renewal = false)
        enroll(sdk, host)
        waitForExpiry()
        val response = operation(plain.newBuilder().addSentomaru(sdk).build(), host)
        val body = response.body?.string().orEmpty()
        assertEquals("expired grant not refused: $body", 403, response.code)
        assertEquals("session-expired", JSONObject(body).getString("code"))
    }

    companion object {
        /** Must match SENTOMARU_GRANT_TTL_SECONDS of the runner (run_sdk.py --suite j04r). */
        const val GRANT_TTL_SECONDS = 30
    }
}
