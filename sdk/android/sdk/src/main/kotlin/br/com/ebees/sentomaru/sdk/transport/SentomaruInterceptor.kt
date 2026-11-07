package br.com.ebees.sentomaru.sdk.transport

import br.com.ebees.sentomaru.core.*
import br.com.ebees.sentomaru.sdk.RenewedGrant
import br.com.ebees.sentomaru.sdk.SentomaruClient
import br.com.ebees.sentomaru.signals.SentomaruSignalEvents
import br.com.ebees.sentomaru.signals.ServerResponseCodes
import okhttp3.*
import okhttp3.MediaType.Companion.toMediaType
import okhttp3.RequestBody.Companion.toRequestBody
import okio.Buffer

/**
 * OkHttp Application Interceptor that freezes request body bytes, verifies target URI consistency,
 * signs RFC 9421 headers via [SentomaruClient], and strictly enforces redirect security (E6).
 *
 * - Outside allowlist: an undeclared request passes unsigned with Sentomaru/signature headers stripped; a declared
 *   operation is refused with HostNotAllowed.
 * - Allowed hosts: requires HTTPS; signs protected operations.
 * - Redirects of a signed request: never followed off the allowlist (the 3xx is returned to the caller); never to
 *   http; 301/302/303 become an unsigned GET without body; 307/308 re-sign the frozen body for the new target.
 *   Authorization and Cookie are dropped whenever the host changes. At most [MAX_REDIRECTS] hops.
 *
 * Not constructible by consumers (I1): an application interceptor cannot stop OkHttp's own redirect follower, so
 * the only supported installation is [addSentomaru], which disables OkHttp redirects and adds
 * [SentomaruRedirectGuard] as a network interceptor (refuses any signed hop OkHttp might still follow).
 */
class SentomaruInterceptor private constructor(val client: SentomaruClient, val routes: SentomaruRoutes?,
    private val events: SentomaruSignalEvents? = null) : Interceptor {

    override fun intercept(chain: Interceptor.Chain): Response {
        val originalRequest = chain.request()
        val host = originalRequest.url.host
        // G-03c: a request with nothing declared takes its operation from the route table of addSentomaru(client, routes).
        val declaredOperation = originalRequest.header("x-sentomaru-operation")
            ?: originalRequest.tag(SentomaruOperation::class.java)?.name
            ?: routes?.operationFor(originalRequest.url)

        // Decision E6 / NET-1: host outside allowlist is not protected. A declared operation there is refused
        // (M1, same as an unusable client); an undeclared request passes with Sentomaru headers stripped.
        if (host !in client.config.allowedHosts) {
            if (declaredOperation != null) throw SentomaruException(SentomaruError.HostNotAllowed())
            return proceed(chain, stripSentomaruHeaders(originalRequest))
        }

        // Allowed host: enforce HTTPS (Decision E6 / NET-3)
        if (originalRequest.url.scheme != "https") {
            throw SentomaruException(SentomaruError.HostNotAllowed())
        }

        // Verify URL canonical representation before signing (Task 1 review M7)
        val urlString = originalRequest.url.toString()
        SentomaruWire.requireCanonical(urlString)

        // Identify operation name and optional signals
        val operationTag = originalRequest.tag(SentomaruOperation::class.java)
        val operation = declaredOperation

        // If no operation declared, allowed host request proceeds unsigned
        if (operation == null) {
            return proceed(chain, originalRequest)
        }

        // H3 + J-01f: optional headers are SIGNED (covered components), never added after the signature. J-01f2: the
        // caller's business operation id (the same on every retry of one operation), validated by the core.
        val optional = SentomaruWire.optionalHeaders(originalRequest.headers(SignalsHeader.NAME),
            operationTag?.resolvedSignalsJson(), originalRequest.headers(Profile.OPERATION_ID_HEADER),
            originalRequest.headers(Profile.TX_SIGNATURE_HEADER))

        // Enforce Content-Type exactness before signing (Task 1 review M7 / SIGN-6 / decision E2)
        SentomaruWire.requireProfileContentType(originalRequest.header("content-type"))
        val bodyMediaType = originalRequest.body?.contentType()
        if (bodyMediaType != null) {
            val bodyTypeStr = bodyMediaType.toString().lowercase()
            if (bodyTypeStr != Profile.CONTENT_TYPE && bodyTypeStr != "${Profile.CONTENT_TYPE}; charset=utf-8") {
                throw SentomaruException(SentomaruError.InvalidRequest(SentomaruError.Reason.HEADER_VALUE))
            }
        }

        // Freeze request body bytes (Decision E2 / SIGN-2 / SIGN-8)
        val frozenBody = readBodyBytes(originalRequest.body)
        if (frozenBody.size > Profile.MAX_BODY_BYTES) {
            throw SentomaruException(SentomaruError.BodyTooLarge(frozenBody.size))
        }

        // J-04r: renew the grant before it expires (signed by the installation key, no new attestation).
        if (client.needsRenewal()) tryRenew(chain, ifDue = true)

        // Sign the request
        val signed = client.sign(originalRequest.method, urlString, operation, frozenBody, optional)
        var currentRequest = buildSignedRequest(originalRequest, signed, frozenBody)
        // Whether the request on the wire for the current hop is the signed operation (method + frozen body).
        var currentHopSigned = true

        var response = proceed(chain, currentRequest)
        failIfFollowedByOkHttp(response)
        // J-04r: the consumer answered session-expired (nothing was done: the evaluation rolled back). Renew once and
        // resend once with a fresh signature; never a loop.
        if (sessionExpired(response) && client.canRenewNow()) {
            client.markGrantStale()
            if (tryRenew(chain)) {
                response.close()
                currentRequest = buildSignedRequest(originalRequest,
                    client.sign(originalRequest.method, urlString, operation, frozenBody, optional), frozenBody)
                response = proceed(chain, currentRequest)
                failIfFollowedByOkHttp(response)
            }
        }
        var redirects = 0

        // Handle redirects explicitly (SDK-NET-1, SDK-NET-2). OkHttp's own follow-up is disabled by addSentomaru.
        while (response.isRedirect && redirects < MAX_REDIRECTS) {
            val location = response.header("Location") ?: break
            val nextUrl = currentRequest.url.resolve(location) ?: break

            // Off-allowlist target: never follow. The 3xx goes back to the caller, so no method, body, signature,
            // Sentomaru header, Authorization or Cookie is ever sent to a host the SDK does not govern (SDK-NET-1).
            if (nextUrl.host !in client.config.allowedHosts) break

            // Allowed host: https only; a downgrade is refused before anything is sent (SDK-NET-3).
            if (nextUrl.scheme != "https") {
                response.close()
                throw SentomaruException(SentomaruError.HostNotAllowed())
            }

            redirects++
            val code = response.code
            response.close()
            val crossHost = nextUrl.host != currentRequest.url.host
            val base = currentRequest.newBuilder().url(nextUrl).apply {
                if (crossHost) {
                    removeHeader("Authorization")
                    removeHeader("Cookie")
                }
            }.build()

            currentRequest = if ((code == 307 || code == 308) && currentHopSigned) {
                // 307/308 keep method and body: re-sign the frozen body for the new @target-uri (SDK-NET-2).
                val nextSigned = client.sign(currentRequest.method, nextUrl.toString(), operation, frozenBody, optional)
                buildSignedRequest(base, nextSigned, frozenBody)
            } else if (code == 307 || code == 308) {
                // The current hop is already an unsigned GET/HEAD (after a 301/302/303): resend it unchanged.
                base
            } else {
                // 300/301/302/303: becomes GET (HEAD stays HEAD) without body; it is no longer the signed operation.
                currentHopSigned = false
                val method = if (currentRequest.method == "HEAD") "HEAD" else "GET"
                stripSentomaruHeaders(base.newBuilder()
                    .method(method, null)
                    .removeHeader("Content-Type")
                    .removeHeader("Content-Length")
                    .build())
            }
            response = proceed(chain, currentRequest)
            failIfFollowedByOkHttp(response)
        }

        // D-15b: only the answer to the signed operation itself (not an unsigned hop after a 301/302/303).
        if (currentHopSigned) reportServerResponse(response)
        return response
    }

    /**
     * D-07d: every exchange of this interceptor (pass-through, signed, redirect hop, renewal) goes through here. A
     * failure on a host of the app's pinning meta-data becomes a local `pin_failure` event when the app passed `events`
     * with a transport listener; the exception is rethrown unchanged in every case. The host is the one of the request
     * this interceptor sent: [addSentomaru] turns OkHttp's own redirects off, so no hop happens below it (an app that
     * turns them back on after `addSentomaru` may get an event named after the first host of the followed chain).
     */
    private fun proceed(chain: Interceptor.Chain, request: Request): Response = try {
        chain.proceed(request)
    } catch (e: java.io.IOException) {
        PinFailureReporter.of(client, events)?.observe(request.url.host, e)
        throw e
    }

    /**
     * D-15b: peeks the error body (never consumed) and hands it to the events; any failure here costs only the event.
     * The peek waits for up to 4097 bytes of a slow body (bounded by the client's read timeout), only on 401/403 and
     * only with a listener registered.
     */
    private fun reportServerResponse(response: Response) {
        val target = events ?: return
        if (response.code != 401 && response.code != 403 || !target.hasServerResponseListeners) return
        val body = try {
            response.peekBody(ServerResponseCodes.MAX_BODY_CHARS + 1L).string()
        } catch (_: Exception) {
            return // review R I-2: an IOException, a closed source or anything else costs only the event
        }
        target.observeServerResponse(response.code, body)
    }

    /** J-04r: one renewal through this chain; false (current grant kept) on any failure. */
    private fun tryRenew(chain: Interceptor.Chain, ifDue: Boolean = false): Boolean = try {
        if (ifDue) client.renewIfDue { signed -> sendRenewal(chain, signed) } else client.renew { signed -> sendRenewal(chain, signed) }
        true
    } catch (_: SentomaruException) {
        false
    }

    private fun sendRenewal(chain: Interceptor.Chain, signed: SignedMessage): RenewedGrant {
        val builder = Request.Builder().url(signed.targetUri)
        signed.headers.forEach { (name, value) -> builder.header(name, value) }
        val request = builder.post(signed.body().toRequestBody(Profile.CONTENT_TYPE.toMediaType())).build()
        proceed(chain, request).use { response ->
            // session-unavailable -> EnrollmentRequired; installation-suspended -> ServerRejected(SUSPENDED).
            if (response.code == 403)
                SentomaruWire.failOnRenewalRefusal(SentomaruWire.errorCode(response.peekBody(MAX_RENEWAL_BYTES.toLong()).string()))
            if (response.code != 200 || response.priorResponse != null)
                throw SentomaruException(SentomaruError.InvalidRequest(SentomaruError.Reason.PARAMS))
            val text = response.body?.let { body ->
                val source = body.source()
                if (!source.request(MAX_RENEWAL_BYTES + 1L) || source.buffer.size <= MAX_RENEWAL_BYTES) source.buffer.readUtf8()
                else throw SentomaruException(SentomaruError.InvalidRequest(SentomaruError.Reason.PARAMS))
            } ?: throw SentomaruException(SentomaruError.InvalidRequest(SentomaruError.Reason.PARAMS))
            return RenewedGrant.parse(text)
        }
    }

    /** `403` whose JSON `code` (or `Sentomaru-Error` header) is `session-expired`, read without consuming the body. */
    private fun sessionExpired(response: Response): Boolean {
        if (response.code != 403) return false
        if (response.header(SESSION_ERROR_HEADER) == SESSION_EXPIRED) return true
        val peek = try { response.peekBody(MAX_RENEWAL_BYTES.toLong()).string() } catch (_: java.io.IOException) { return false }
        return SentomaruWire.errorCode(peek) == SESSION_EXPIRED
    }

    /** Defense in depth: if OkHttp's follower ran anyway (redirects re-enabled), the result is refused. */
    private fun failIfFollowedByOkHttp(response: Response) {
        if (response.priorResponse != null) {
            response.close()
            throw SentomaruException(SentomaruError.HostNotAllowed())
        }
    }

    private fun readBodyBytes(body: RequestBody?): ByteArray {
        if (body == null) return ByteArray(0)
        val buffer = Buffer()
        body.writeTo(buffer)
        return buffer.readByteArray()
    }

    private fun buildSignedRequest(base: Request, signed: SignedMessage, frozenBody: ByteArray): Request {
        val builder = base.newBuilder()
        signed.headers.forEach { (name, value) ->
            builder.header(name, value)
        }
        if (base.body != null || base.method in setOf("POST", "PUT", "PATCH")) {
            builder.method(base.method, frozenBody.toRequestBody(Profile.CONTENT_TYPE.toMediaType()))
        }
        return builder.build()
    }

    private fun stripSentomaruHeaders(request: Request): Request {
        val builder = request.newBuilder()
        // Only Sentomaru and signature headers; the caller's content-type is not ours to remove.
        SentomaruWire.SENTOMARU_HEADERS.forEach { builder.removeHeader(it) }
        return builder.build()
    }

    companion object {
        /** Same limit as the Dio interceptor (and [SentomaruUrlConnection]). */
        const val MAX_REDIRECTS = SentomaruWire.MAX_REDIRECTS

        internal fun create(client: SentomaruClient, routes: SentomaruRoutes? = null, events: SentomaruSignalEvents? = null) =
            SentomaruInterceptor(client, routes, events)

        private const val MAX_RENEWAL_BYTES = SentomaruWire.MAX_RENEWAL_BYTES
        private const val SESSION_EXPIRED = SentomaruWire.SESSION_EXPIRED
        /** Optional header a consumer may set on a refusal; the JSON `code` member works without it. */
        const val SESSION_ERROR_HEADER = SentomaruWire.SESSION_ERROR_HEADER
        /** Kept for the transport tests; the parser lives in [RenewedGrant.parse]. */
        internal fun parseRenewal(text: String): RenewedGrant = RenewedGrant.parse(text)
    }
}
