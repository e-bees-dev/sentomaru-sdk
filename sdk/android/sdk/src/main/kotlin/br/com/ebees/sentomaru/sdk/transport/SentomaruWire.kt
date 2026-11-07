package br.com.ebees.sentomaru.sdk.transport

import br.com.ebees.sentomaru.core.Profile
import br.com.ebees.sentomaru.core.SentomaruError
import br.com.ebees.sentomaru.core.SentomaruException
import br.com.ebees.sentomaru.sdk.EnrollmentError
import br.com.ebees.sentomaru.sdk.SentomaruClient
import okhttp3.HttpUrl.Companion.toHttpUrl

/**
 * Rules shared by the two Android signing transports, [SentomaruInterceptor] (OkHttp) and [SentomaruUrlConnection]
 * (HttpURLConnection), so both refuse, sign and map renewal answers the same way. The signature itself is always the
 * core's ([SentomaruClient.sign]); nothing here signs.
 */
internal object SentomaruWire {
    /** Same limit as the Dio interceptor. */
    const val MAX_REDIRECTS = 5
    const val MAX_RENEWAL_BYTES = 4096
    const val SESSION_EXPIRED = "session-expired"
    const val SESSION_UNAVAILABLE = "session-unavailable"
    const val INSTALLATION_SUSPENDED = "installation-suspended"
    /** Optional header a consumer may set on a refusal; the JSON `code` member works without it. */
    const val SESSION_ERROR_HEADER = "Sentomaru-Error"
    private val CODE = Regex("\"code\"\\s*:\\s*\"([a-z-]{1,64})\"")

    /** Sentomaru and signature headers: never forwarded to a host the SDK does not govern, nor on an unsigned hop. */
    val SENTOMARU_HEADERS: List<String> = Profile.CALLER_HEADERS.filter { it.startsWith("x-sentomaru-") } +
        listOf(Profile.CONTENT_DIGEST, Profile.SIGNATURE_INPUT, Profile.SIGNATURE, SignalsHeader.NAME, Profile.OPERATION_ID_HEADER,
            Profile.TX_SIGNATURE_HEADER)

    /** A route host the client does not allow could only ever fail closed: refuse the installation instead. */
    fun requireRoutesWithin(client: SentomaruClient, routes: SentomaruRoutes?) =
        require(routes == null || client.config.allowedHosts.containsAll(routes.hosts)) { "network-signing.hosts not within allowedHosts" }

    /** The target URI must be the canonical form the server reconstructs (Task 1 review M7). */
    fun requireCanonical(urlString: String) {
        val reparsed = try { urlString.toHttpUrl().toString() } catch (_: Exception) {
            throw SentomaruException(SentomaruError.InvalidRequest(SentomaruError.Reason.TARGET_URI))
        }
        if (reparsed != urlString) throw SentomaruException(SentomaruError.InvalidRequest(SentomaruError.Reason.TARGET_URI))
    }

    /** Content-Type exactness before signing (SIGN-6 / decision E2): absent or exactly [Profile.CONTENT_TYPE]. */
    fun requireProfileContentType(headerValue: String?) {
        if (headerValue != null && headerValue != Profile.CONTENT_TYPE)
            throw SentomaruException(SentomaruError.InvalidRequest(SentomaruError.Reason.HEADER_VALUE))
    }

    /**
     * H3 + J-01f: the optional covered components (signals, then the caller's operation id), each with at most one
     * value; the signals come from the request header or else from the [SentomaruOperation].
     */
    fun optionalHeaders(signalsValues: List<String>, operationSignals: String?, operationIdValues: List<String>,
        txSignatureValues: List<String> = emptyList()): Map<String, String> {
        if (signalsValues.size > 1) throw SentomaruException(SentomaruError.InvalidRequest(SentomaruError.Reason.HEADER_VALUE))
        val signalsJson = (signalsValues.firstOrNull() ?: operationSignals)?.let(SignalsHeader::encode)
        if (operationIdValues.size > 1) throw SentomaruException(SentomaruError.InvalidRequest(SentomaruError.Reason.HEADER_VALUE))
        // D-25: the transaction signature, made by the app after the person authenticated; one value at most.
        if (txSignatureValues.size > 1) throw SentomaruException(SentomaruError.InvalidRequest(SentomaruError.Reason.HEADER_VALUE))
        return buildMap {
            signalsJson?.let { put(Profile.SIGNALS_HEADER, it) }
            operationIdValues.firstOrNull()?.let { put(Profile.OPERATION_ID_HEADER, it) }
            txSignatureValues.firstOrNull()?.let { put(Profile.TX_SIGNATURE_HEADER, it) }
        }
    }

    /** The JSON `code` member of an error body (first [MAX_RENEWAL_BYTES] bytes), or null. */
    fun errorCode(text: String): String? = CODE.find(text)?.groupValues?.get(1)

    fun isRedirect(code: Int): Boolean = code in setOf(300, 301, 302, 303, 307, 308)

    /**
     * J-04r renewal answers with a meaning of their own. `session-unavailable`: the installation cannot renew any more
     * (revoked, stale epoch, chain ceiling, hardware), the SDK drops the grant so the app enrolls again.
     * `installation-suspended` (contract v1.5): wait and retry later; the SDK keeps the grant and backs off
     * `SUSPENDED_RENEWAL_BACKOFF` (same mapping as the Flutter plugin's EnrollmentTransport.renew).
     */
    fun failOnRenewalRefusal(serverCode: String?) {
        if (serverCode == SESSION_UNAVAILABLE) throw SentomaruException(EnrollmentError.EnrollmentRequired())
        if (serverCode == INSTALLATION_SUSPENDED)
            throw SentomaruException(EnrollmentError.ServerRejected(EnrollmentError.Rejection.SUSPENDED))
    }
}
