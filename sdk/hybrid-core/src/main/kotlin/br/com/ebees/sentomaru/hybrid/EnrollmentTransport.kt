package br.com.ebees.sentomaru.hybrid

import br.com.ebees.sentomaru.core.SentomaruError
import br.com.ebees.sentomaru.core.SentomaruException
import br.com.ebees.sentomaru.core.SignedMessage
import br.com.ebees.sentomaru.sdk.EnrollmentError
import br.com.ebees.sentomaru.sdk.EnrollmentGrant
import br.com.ebees.sentomaru.sdk.ReattestationAnswer
import br.com.ebees.sentomaru.sdk.RenewedGrant
import okhttp3.MediaType.Companion.toMediaType
import okhttp3.OkHttpClient
import okhttp3.Request
import okhttp3.RequestBody.Companion.toRequestBody
import org.json.JSONException
import org.json.JSONObject
import java.io.IOException
import java.net.URI
import java.util.concurrent.TimeUnit

/**
 * Sends the signed enrollment built by the native SDK (R4).
 *
 * - Only to an https host of the configured allowlist (checked again here, before any byte is sent).
 * - Redirects are never followed: a 3xx is a rejection, so the attestation chain never goes anywhere else.
 * - No silent retry (`retryOnConnectionFailure = false`): the same signed bytes are sent once.
 * - Transport failure -> [IOException] (the SDK maps it to `NetworkUnavailable`); an HTTP answer that is not a valid
 *   grant -> `ServerRejected(<reason>)`. Server bodies and exception messages are never echoed to Dart.
 * - `403 installation-suspended` (contract v1.5) -> `ServerRejected:SUSPENDED`, on enrollment and on renewal.
 * - `401 predecessor-invalid` (contract v1.6, D-04d) -> `ReenrollmentRefused`: the rotation cannot re-enroll this
 *   installation; the app calls reset() and enroll().
 * - D-12e: the two reattestation steps go out under the same rules ([reattest]); the SDK reads the answer.
 */
class EnrollmentTransport(
    private val allowedHosts: Set<String>,
    private val http: OkHttpClient = defaultClient(),
) {
    /**
     * J-04r: sends the signed renewal under the same rules as enrollment (allowlisted https host, no redirect, one send).
     * Anything but a 200 with a valid grant is a [SentomaruException]; the SDK keeps the current grant.
     */
    fun renew(signed: SignedMessage): RenewedGrant {
        val (code, body) = post(signed)
        val serverCode = if (code == 403) serverCodeOf(body) else ""
        // session-unavailable: the installation cannot renew any more (revoked, stale epoch, chain ceiling, hardware);
        // the SDK drops the grant so the app enrolls again.
        if (serverCode == SESSION_UNAVAILABLE) throw SentomaruException(EnrollmentError.EnrollmentRequired())
        // installation-suspended (contract v1.5): wait and retry later; the SDK keeps the grant (and backs off).
        if (serverCode == INSTALLATION_SUSPENDED) reject(EnrollmentError.Rejection.SUSPENDED)
        if (code != 200 || body == null) throw SentomaruException(SentomaruError.InvalidRequest(SentomaruError.Reason.PARAMS))
        return RenewedGrant.parse(body)
    }

    fun send(signed: SignedMessage): EnrollmentGrant {
        val (code, body) = post(signed)
        return mapResponse(code, body)
    }

    /**
     * D-12e: one reattestation step (`reattest_challenge` or `reattest`) under the enrollment rules (allowlisted https
     * host, no redirect, one send). The answer is passed through for `SentomaruReattestation` to read: status, body
     * and the `Retry-After` seconds (delta form only; an HTTP date or anything else is absent). A body above
     * [MAX_RESPONSE_BYTES] goes on as empty, so the SDK never parses part of an answer (`unexpected-answer` on a 200).
     * A transport failure, or a status outside 100..599, is an [IOException]: "not now" (`UNAVAILABLE`) in the SDK.
     */
    fun reattest(signed: SignedMessage): ReattestationAnswer {
        val answer = exchange(signed)
        if (answer.status !in 100..599) throw IOException("HTTP status out of range")
        return ReattestationAnswer(answer.status, answer.body ?: "", retryAfterSeconds(answer.retryAfter))
    }

    private fun post(signed: SignedMessage): Pair<Int, String?> = exchange(signed).let { it.status to it.body }

    private class Answer(val status: Int, val body: String?, val retryAfter: String?)

    private fun exchange(signed: SignedMessage): Answer {
        val uri = try { URI(signed.targetUri) } catch (_: Exception) {
            throw SentomaruException(SentomaruError.InvalidRequest(SentomaruError.Reason.TARGET_URI))
        }
        if (uri.scheme != "https" || uri.host !in allowedHosts || uri.rawUserInfo != null) {
            throw SentomaruException(SentomaruError.HostNotAllowed())
        }
        val builder = Request.Builder().url(signed.targetUri)
        var contentType = "application/json"
        for ((name, value) in signed.headers) {
            if (name.equals("content-type", ignoreCase = true)) contentType = value
            builder.header(name, value)
        }
        builder.post(signed.body().toRequestBody(contentType.toMediaType()))

        http.newCall(builder.build()).execute().use { response ->
            val body = response.body?.source()?.let { source ->
                source.request(MAX_RESPONSE_BYTES + 1)
                val buffered = source.buffer
                if (buffered.size > MAX_RESPONSE_BYTES) null else buffered.readUtf8()
            }
            return Answer(response.code, body, response.header("Retry-After"))
        }
    }

    companion object {
        const val MAX_RESPONSE_BYTES = 16L * 1024
        private const val SESSION_UNAVAILABLE = "session-unavailable"
        private const val INSTALLATION_SUSPENDED = "installation-suspended"
        private const val PREDECESSOR_INVALID = "predecessor-invalid"

        /** `Retry-After` in seconds (`0`..`9…`, at most 10 digits), else null; the SDK bounds every wait anyway. */
        fun retryAfterSeconds(header: String?): Long? =
            header?.trim()?.takeIf { it.length in 1..10 && it.all { c -> c in '0'..'9' } }?.toLong()

        /** Applies the enrollment policy on [base] (tests pass a builder that trusts their TLS server). */
        fun defaultClient(base: OkHttpClient.Builder = OkHttpClient.Builder()): OkHttpClient = base
            .followRedirects(false)
            .followSslRedirects(false)
            .retryOnConnectionFailure(false)
            .connectTimeout(15, TimeUnit.SECONDS)
            .readTimeout(15, TimeUnit.SECONDS)
            .build()

        /** Pure mapping from an HTTP answer to a grant or a typed rejection; [body] is null when oversized. */
        fun mapResponse(code: Int, body: String?): EnrollmentGrant {
            if (code in 200..299) {
                val json = try { JSONObject(body ?: "") } catch (_: JSONException) { reject(EnrollmentError.Rejection.INVALID) }
                return try {
                    EnrollmentGrant(
                        installationId = json.getString("installationId"),
                        keyId = json.getString("keyId"),
                        sessionId = json.getString("sessionId"),
                        hardwareStatus = json.getString("hardwareStatus"),
                        attestationStatus = json.getString("attestationStatus"),
                    )
                } catch (_: JSONException) {
                    reject(EnrollmentError.Rejection.INVALID)
                } catch (_: IllegalArgumentException) {
                    reject(EnrollmentError.Rejection.INVALID)
                }
            }
            val serverCode = serverCodeOf(body)
            if (code == 401 && serverCode == PREDECESSOR_INVALID) throw SentomaruException(EnrollmentError.ReenrollmentRefused())
            reject(rejectionFor(code, serverCode))
        }

        /** The JSON `code` member of a refusal; "" when the body is absent, oversized or not a JSON object. */
        private fun serverCodeOf(body: String?): String = body?.let {
            try { JSONObject(it).optString("code", "") } catch (_: JSONException) { "" }
        } ?: ""

        fun rejectionFor(status: Int, serverCode: String): EnrollmentError.Rejection = when {
            // Only the exact v1.5 answer: any other 403 stays INVALID/REVOKED, so nothing becomes a suspension by mistake.
            status == 403 && serverCode == INSTALLATION_SUSPENDED -> EnrollmentError.Rejection.SUSPENDED
            // D-04d: EXPIRED, REVOKED and CONFLICT say the server did NOT accept a body (the SDK then drops a resent
            // rotation), so only Sentomaru's own codes map to them; a bare 410 or a proxy's 4xx stays INVALID (kept).
            serverCode == "enrollment-revoked" || serverCode == "installation-revoked" -> EnrollmentError.Rejection.REVOKED
            serverCode == "challenge-invalid" || serverCode == "challenge-expired" -> EnrollmentError.Rejection.EXPIRED
            status == 409 && serverCode == "enrollment-conflict" -> EnrollmentError.Rejection.CONFLICT
            status == 429 || serverCode == "rate-limited" -> EnrollmentError.Rejection.RATE_LIMITED
            status >= 500 || serverCode.endsWith("-unavailable") -> EnrollmentError.Rejection.UNAVAILABLE
            else -> EnrollmentError.Rejection.INVALID // 3xx (redirect refused) and every other 4xx
        }

        private fun reject(reason: EnrollmentError.Rejection): Nothing =
            throw SentomaruException(EnrollmentError.ServerRejected(reason))
    }
}
