package br.com.ebees.sentomaru.sample

import android.content.pm.PackageManager
import androidx.test.ext.junit.runners.AndroidJUnit4
import androidx.test.platform.app.InstrumentationRegistry
import br.com.ebees.sentomaru.core.*
import br.com.ebees.sentomaru.sdk.*
import br.com.ebees.sentomaru.sdk.transport.addSentomaru
import okhttp3.*
import okhttp3.MediaType.Companion.toMediaType
import okhttp3.RequestBody.Companion.toRequestBody
import org.json.JSONObject
import org.junit.After
import org.junit.Assert.*
import org.junit.Before
import org.junit.Test
import org.junit.runner.RunWith
import java.io.IOException
import java.security.SecureRandom
import java.security.cert.X509Certificate
import java.time.Instant
import java.util.Base64
import javax.net.ssl.*

@RunWith(AndroidJUnit4::class)
class E2EInstrumentedTest {

    private val context = InstrumentationRegistry.getInstrumentation().targetContext
    private val org = "org-a"
    private val app = "app-a"
    private val env = "hml"
    private val host = "127.0.0.1"
    private val port = 8443
    private val consumerBase = "https://$host:$port"
    private val enrollmentUrl = "$consumerBase/v1/$org/$app/$env/installations"
    private val operationUrl = "$consumerBase/v1/$org/$app/$env/operations/submit?channel=field"

    private lateinit var config: SentomaruConfig
    private lateinit var client: SentomaruClient
    private lateinit var baseHttpClient: OkHttpClient
    private lateinit var signedHttpClient: OkHttpClient

    @Before
    fun setUp() {
        config = SentomaruConfig(
            organization = org,
            app = app,
            environment = env,
            allowedHosts = setOf(host),
            enrollmentUrl = enrollmentUrl
        )

        val trustAll = object : X509TrustManager {
            override fun checkClientTrusted(chain: Array<out X509Certificate>?, authType: String?) {}
            override fun checkServerTrusted(chain: Array<out X509Certificate>?, authType: String?) {}
            override fun getAcceptedIssuers(): Array<X509Certificate> = arrayOf()
        }

        val sslContext = SSLContext.getInstance("TLS").apply {
            init(null, arrayOf<TrustManager>(trustAll), SecureRandom())
        }

        baseHttpClient = OkHttpClient.Builder()
            .sslSocketFactory(sslContext.socketFactory, trustAll)
            .hostnameVerifier { _, _ -> true }
            .followRedirects(false)
            .followSslRedirects(false)
            .build()

        client = SentomaruClient.initialize(context, config)
        client.reset()

        signedHttpClient = baseHttpClient.newBuilder()
            .addSentomaru(client)
            .build()
    }

    @After
    fun tearDown() {
        client.reset()
    }

    private fun fetchChallenge(subject: String = "user-a", tenant: String = "tenant-a"): EnrollmentChallenge {
        val payload = JSONObject().apply {
            put("subject", subject)
            put("tenant", tenant)
        }
        val request = Request.Builder()
            .url("$consumerBase/api/consumer/challenge")
            .post(payload.toString().toRequestBody("application/json".toMediaType()))
            .build()

        val response = baseHttpClient.newCall(request).execute()
        val body = response.body?.string() ?: ""
        assertTrue("Challenge fetch failed: HTTP ${response.code} $body", response.isSuccessful)

        val json = JSONObject(body)
        return EnrollmentChallenge(
            id = json.getString("id"),
            token = json.getString("token"),
            attestationChallenge = Base64.getDecoder().decode(json.getString("attestationChallenge")),
            expiresAt = Instant.parse(json.getString("expiresAt"))
        )
    }

    private fun sendEnrollment(signed: SignedMessage): EnrollmentGrant {
        val reqBuilder = Request.Builder()
            .url(signed.targetUri)
            .post(signed.body().toRequestBody("application/json".toMediaType()))

        for ((key, value) in signed.headers) {
            reqBuilder.header(key, value)
        }

        val response = baseHttpClient.newCall(reqBuilder.build()).execute()
        val body = response.body?.string() ?: ""
        if (!response.isSuccessful) {
            throw IOException("Enrollment failed: HTTP ${response.code} $body")
        }

        val json = JSONObject(body)
        return EnrollmentGrant(
            installationId = json.getString("installationId"),
            keyId = json.getString("keyId"),
            sessionId = json.getString("sessionId"),
            hardwareStatus = json.getString("hardwareStatus"),
            attestationStatus = json.getString("attestationStatus")
        )
    }

    private fun enroll(): EnrollmentGrant {
        val challenge = fetchChallenge()
        return client.enroll(challenge) { sendEnrollment(it) }
    }

    // --- SDK-ENR Scenarios ---

    @Test
    fun test_SDK_ENR_1_end_to_end_enrollment_with_hardware_attestation() {
        val challenge = fetchChallenge()
        val grant = client.enroll(challenge) { sendEnrollment(it) }

        assertNotNull(grant.installationId)
        assertEquals(challenge.id, grant.keyId)
        assertNotNull(grant.sessionId)
        assertEquals("hardware", grant.hardwareStatus)
        assertEquals("verified", grant.attestationStatus)
        assertEquals(InstallationState.Enrolled, client.state())
        assertEquals(grant.sessionId, client.sessionId())
    }

    @Test
    fun test_SDK_ENR_2_idempotent_enrollment_replay() {
        val challenge = fetchChallenge()
        val grant1 = client.enroll(challenge) { sendEnrollment(it) }
        val grant2 = client.enroll(challenge) { sendEnrollment(it) }

        assertEquals(grant1.installationId, grant2.installationId)
        assertEquals(grant1.sessionId, grant2.sessionId)
        assertEquals(grant1.keyId, grant2.keyId)
        assertEquals(InstallationState.Enrolled, client.state())
    }

    @Test
    fun test_SDK_ENR_3_expired_challenge_rejected() {
        val expired = EnrollmentChallenge(
            id = "00000000-0000-0000-0000-000000000001",
            token = Base64.getEncoder().encodeToString(ByteArray(32) { 1 }),
            attestationChallenge = ByteArray(32) { 2 },
            expiresAt = Instant.now().minusSeconds(30)
        )

        val ex = assertThrows(SentomaruException::class.java) {
            client.enroll(expired) { sendEnrollment(it) }
        }
        assertEquals("ChallengeExpired", ex.error.code)
        assertEquals(InstallationState.NotEnrolled, client.state())
    }

    @Test
    fun test_SDK_ENR_4_local_reset_and_re_enrollment() {
        enroll()
        assertEquals(InstallationState.Enrolled, client.state())

        client.reset()
        assertEquals(InstallationState.NotEnrolled, client.state())
        assertNull(client.sessionId())

        val grant = enroll()
        assertEquals(InstallationState.Enrolled, client.state())
        assertEquals("hardware", grant.hardwareStatus)
        assertEquals("verified", grant.attestationStatus)
    }

    @Test
    fun test_SDK_ENR_5_strongbox_unavailable_typed() {
        val hasStrongBox = context.packageManager.hasSystemFeature(PackageManager.FEATURE_STRONGBOX_KEYSTORE)
        if (hasStrongBox) return

        val challenge = fetchChallenge()
        val ex = assertThrows(SentomaruException::class.java) {
            client.enroll(challenge, strongBox = true) { sendEnrollment(it) }
        }
        assertEquals("StrongBoxUnavailable", ex.error.code)
        assertEquals(InstallationState.NotEnrolled, client.state())
    }

    // --- SDK-SIGN Scenarios ---

    @Test
    fun test_SDK_SIGN_1_signed_operation_accepted() {
        enroll()

        val body = "{\"telemetry\":123}".toRequestBody("application/json".toMediaType())
        val request = Request.Builder()
            .url(operationUrl)
            .header("x-sentomaru-operation", "submit")
            .post(body)
            .build()

        val response = signedHttpClient.newCall(request).execute()
        val responseBody = response.body?.string() ?: ""
        assertTrue("Operation rejected: HTTP ${response.code} $responseBody", response.isSuccessful)

        val json = JSONObject(responseBody)
        assertEquals("valid", json.getString("proofStatus"))
    }

    @Test
    fun test_SDK_SIGN_2_exact_replay_rejected_with_409() {
        enroll()

        val rawBody = "{\"telemetry\":456}".toByteArray(Charsets.UTF_8)
        val signed = client.sign("POST", operationUrl, "submit", rawBody)

        val req1 = Request.Builder()
            .url(signed.targetUri)
            .header("X-Consumer-Target-Replica", "0")
            .post(rawBody.toRequestBody("application/json".toMediaType()))
        for ((k, v) in signed.headers) req1.header(k, v)

        val resp1 = baseHttpClient.newCall(req1.build()).execute()
        assertTrue("First submission failed: HTTP ${resp1.code}", resp1.isSuccessful)

        // Exact replay against replica 1 with identical signature and nonce
        val req2 = Request.Builder()
            .url(signed.targetUri)
            .header("X-Consumer-Target-Replica", "1")
            .post(rawBody.toRequestBody("application/json".toMediaType()))
        for ((k, v) in signed.headers) req2.header(k, v)

        val resp2 = baseHttpClient.newCall(req2.build()).execute()
        assertEquals("Replay was not rejected with 409", 409, resp2.code)
        val body2 = resp2.body?.string() ?: ""
        assertTrue("Expected replay rejection code in $body2", body2.contains("replay"))
    }

    @Test
    fun test_SDK_SIGN_3_retry_with_fresh_nonce_accepted() {
        enroll()

        val rawBody = "{\"telemetry\":789}".toByteArray(Charsets.UTF_8)
        val signed1 = client.sign("POST", operationUrl, "submit", rawBody)

        val req1 = Request.Builder()
            .url(signed1.targetUri)
            .post(rawBody.toRequestBody("application/json".toMediaType()))
        for ((k, v) in signed1.headers) req1.header(k, v)
        val resp1 = baseHttpClient.newCall(req1.build()).execute()
        assertTrue(resp1.isSuccessful)

        // Retry same operation with fresh nonce and signature
        val signed2 = client.sign("POST", operationUrl, "submit", rawBody)
        val req2 = Request.Builder()
            .url(signed2.targetUri)
            .post(rawBody.toRequestBody("application/json".toMediaType()))
        for ((k, v) in signed2.headers) req2.header(k, v)
        val resp2 = baseHttpClient.newCall(req2.build()).execute()
        assertTrue("Retry with fresh nonce failed: HTTP ${resp2.code}", resp2.isSuccessful)
    }

    @Test
    fun test_SDK_SIGN_4_tampered_body_rejected_with_401() {
        enroll()

        val originalBody = "{\"value\":1}".toByteArray(Charsets.UTF_8)
        val tamperedBody = "{\"value\":2}".toByteArray(Charsets.UTF_8)

        val signed = client.sign("POST", operationUrl, "submit", originalBody)

        val request = Request.Builder()
            .url(signed.targetUri)
            .post(tamperedBody.toRequestBody("application/json".toMediaType()))
        for ((k, v) in signed.headers) request.header(k, v)

        val response = baseHttpClient.newCall(request.build()).execute()
        assertEquals("Tampered body was not rejected with 401", 401, response.code)
    }

    @Test
    fun test_SDK_SIGN_5_wrong_operation_context_rejected_with_403() {
        enroll()

        val body = "{\"value\":1}".toByteArray(Charsets.UTF_8)
        val signed = client.sign("POST", operationUrl, "submit", body)

        // Signed for 'submit', but consumer evaluates with 'transfer'
        val request = Request.Builder()
            .url(signed.targetUri)
            .header("X-Consumer-Operation", "transfer")
            .post(body.toRequestBody("application/json".toMediaType()))
        for ((k, v) in signed.headers) request.header(k, v)

        val response = baseHttpClient.newCall(request.build()).execute()
        assertEquals("Wrong operation was not rejected with 403", 403, response.code)
    }

    @Test
    fun test_SDK_SIGN_6_tampered_query_param_rejected_with_401() {
        enroll()

        val body = "{\"value\":1}".toByteArray(Charsets.UTF_8)
        val signed = client.sign("POST", operationUrl, "submit", body)

        // Alter query parameter from ?channel=field to ?channel=office
        val tamperedUrl = "$consumerBase/v1/$org/$app/$env/operations/submit?channel=office"
        val request = Request.Builder()
            .url(tamperedUrl)
            .post(body.toRequestBody("application/json".toMediaType()))
        for ((k, v) in signed.headers) request.header(k, v)

        val response = baseHttpClient.newCall(request.build()).execute()
        assertEquals("Tampered query was not rejected with 401", 401, response.code)
    }

    @Test
    fun test_SDK_SIGN_7_tampered_content_type_rejected() {
        enroll()

        val body = "{\"value\":1}".toByteArray(Charsets.UTF_8)
        val signed = client.sign("POST", operationUrl, "submit", body)

        val request = Request.Builder()
            .url(signed.targetUri)
            .post(body.toRequestBody("text/plain".toMediaType()))
        for ((k, v) in signed.headers) {
            if (k.lowercase() != "content-type") request.header(k, v)
        }
        request.header("content-type", "text/plain")

        val response = baseHttpClient.newCall(request.build()).execute()
        assertTrue("Tampered content-type should be rejected", response.code in setOf(400, 401))
    }

    @Test
    fun test_SDK_SIGN_8_cross_replica_operations_accepted() {
        enroll()

        val body1 = "{\"step\":1}".toRequestBody("application/json".toMediaType())
        val req1 = Request.Builder()
            .url(operationUrl)
            .header("x-sentomaru-operation", "submit")
            .header("X-Consumer-Target-Replica", "0")
            .post(body1)
            .build()
        val resp1 = signedHttpClient.newCall(req1).execute()
        assertTrue("Replica 0 failed: HTTP ${resp1.code}", resp1.isSuccessful)

        val body2 = "{\"step\":2}".toRequestBody("application/json".toMediaType())
        val req2 = Request.Builder()
            .url(operationUrl)
            .header("x-sentomaru-operation", "submit")
            .header("X-Consumer-Target-Replica", "1")
            .post(body2)
            .build()
        val resp2 = signedHttpClient.newCall(req2).execute()
        assertTrue("Replica 1 failed: HTTP ${resp2.code}", resp2.isSuccessful)
    }
}
