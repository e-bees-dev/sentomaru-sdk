package br.com.ebees.sentomaru.perf

import android.content.Context
import br.com.ebees.sentomaru.sdk.EnrollmentChallenge
import br.com.ebees.sentomaru.sdk.EnrollmentGrant
import br.com.ebees.sentomaru.sdk.SentomaruClient
import br.com.ebees.sentomaru.sdk.SentomaruConfig
import okhttp3.MediaType.Companion.toMediaType
import okhttp3.OkHttpClient
import okhttp3.Request
import okhttp3.RequestBody.Companion.toRequestBody
import org.json.JSONObject
import java.io.ByteArrayInputStream
import java.io.IOException
import java.security.KeyStore
import java.security.cert.CertificateFactory
import java.time.Instant
import java.util.Base64
import javax.net.ssl.SSLContext
import javax.net.ssl.TrustManagerFactory
import javax.net.ssl.X509TrustManager

/** The lab scope and the synthetic consumer reached through `adb reverse` (the vendor's consumer check). */
object PerfScope {
    const val HOST = "127.0.0.1"
    const val PORT = 8443
    const val BASE = "https://$HOST:$PORT"
    const val OPERATION_URL = "$BASE/v1/org-a/app-a/hml/operations/submit?channel=field"
    val config = SentomaruConfig(organization = "org-a", app = "app-a", environment = "hml",
        allowedHosts = setOf(HOST), enrollmentUrl = "$BASE/v1/org-a/app-a/hml/installations")

    fun client(context: Context): SentomaruClient = SentomaruClient.initialize(context, config)
}

/**
 * One journey step per method, blocking (worker thread only). TLS trusts only the consumer certificate the runner
 * generated for this run (base64 DER passed as an argument), never any other.
 */
class Journey(certificateDer: String) {
    private val json = "application/json".toMediaType()
    val http: OkHttpClient = pinned(Base64.getDecoder().decode(certificateDer))

    /** Network round trip alone: the consumer answers locally, no API call. */
    fun health() {
        http.newCall(Request.Builder().url("${PerfScope.BASE}/health").build()).execute().use {
            if (!it.isSuccessful) throw IOException("health ${it.code}")
        }
    }

    fun challenge(): EnrollmentChallenge {
        val payload = JSONObject().put("subject", "user-a").put("tenant", "tenant-a").toString()
        val request = Request.Builder().url("${PerfScope.BASE}/api/consumer/challenge").post(payload.toRequestBody(json)).build()
        http.newCall(request).execute().use { response ->
            val body = response.body?.string().orEmpty()
            if (!response.isSuccessful) throw IOException("challenge ${response.code}")
            val value = JSONObject(body)
            return EnrollmentChallenge(value.getString("id"), value.getString("token"),
                Base64.getDecoder().decode(value.getString("attestationChallenge")), Instant.parse(value.getString("expiresAt")))
        }
    }

    fun enroll(client: SentomaruClient, challenge: EnrollmentChallenge, onSend: (Long) -> Unit = {}): EnrollmentGrant =
        client.enroll(challenge) { signed ->
            val started = System.nanoTime()
            val request = Request.Builder().url(signed.targetUri).post(signed.body().toRequestBody(json))
            for ((key, value) in signed.headers) request.header(key, value)
            http.newCall(request.build()).execute().use { response ->
                val body = response.body?.string().orEmpty()
                onSend(System.nanoTime() - started)
                if (!response.isSuccessful) throw IOException("enrollment ${response.code}")
                val value = JSONObject(body)
                EnrollmentGrant(value.getString("installationId"), value.getString("keyId"), value.getString("sessionId"),
                    value.getString("hardwareStatus"), value.getString("attestationStatus"))
            }
        }

    /** Sends an operation already signed by the SDK; returns the API proof status ("valid" when accepted). */
    fun submit(targetUri: String, headers: List<Pair<String, String>>, body: ByteArray): String {
        val request = Request.Builder().url(targetUri).post(body.toRequestBody(json))
        for ((key, value) in headers) request.header(key, value)
        http.newCall(request.build()).execute().use { response ->
            val text = response.body?.string().orEmpty()
            if (!response.isSuccessful) return "http_${response.code}"
            return JSONObject(text).optString("proofStatus", "missing")
        }
    }

    private fun pinned(der: ByteArray): OkHttpClient {
        val certificate = CertificateFactory.getInstance("X.509").generateCertificate(ByteArrayInputStream(der))
        val store = KeyStore.getInstance(KeyStore.getDefaultType()).apply {
            load(null, null)
            setCertificateEntry("consumer", certificate)
        }
        val factory = TrustManagerFactory.getInstance(TrustManagerFactory.getDefaultAlgorithm()).apply { init(store) }
        val trust = factory.trustManagers.single() as X509TrustManager
        val context = SSLContext.getInstance("TLS").apply { init(null, arrayOf(trust), null) }
        return OkHttpClient.Builder().sslSocketFactory(context.socketFactory, trust)
            .followRedirects(false).followSslRedirects(false).build()
    }
}
