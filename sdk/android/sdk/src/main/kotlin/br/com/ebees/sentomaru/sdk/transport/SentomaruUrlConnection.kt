package br.com.ebees.sentomaru.sdk.transport

import br.com.ebees.sentomaru.core.Profile
import br.com.ebees.sentomaru.core.SentomaruError
import br.com.ebees.sentomaru.core.SentomaruException
import br.com.ebees.sentomaru.core.SignedMessage
import br.com.ebees.sentomaru.sdk.RenewedGrant
import br.com.ebees.sentomaru.sdk.SentomaruClient
import br.com.ebees.sentomaru.signals.SentomaruSignalEvents
import okhttp3.HttpUrl
import okhttp3.HttpUrl.Companion.toHttpUrlOrNull
import java.io.ByteArrayInputStream
import java.io.IOException
import java.io.InputStream
import java.io.SequenceInputStream
import java.net.HttpURLConnection
import java.net.URL
import javax.net.ssl.HttpsURLConnection
import java.util.TreeMap

/**
 * S2: RFC 9421 signing for `java.net.HttpURLConnection`, usable from Java. One call does the whole exchange and returns
 * the final connection, already answered: the caller reads `getResponseCode()` and `getInputStream()` /
 * `getErrorStream()` and closes them.
 *
 * ```java
 * HttpURLConnection conn = SentomaruUrlConnection.send(client, routes, "POST", url, bodyBytes, headers);
 * ```
 *
 * Same rules as [addSentomaru] (OkHttp), shared through [SentomaruWire]; the signature is the core's ([SentomaruClient.sign]):
 * - Operation: the `x-sentomaru-operation` header, else [SentomaruOperation] (`operation`), else `routes.operationFor`.
 * - Host outside `allowedHosts`: a request with no operation is sent unsigned, Sentomaru and signature headers removed;
 *   a declared operation is refused (`HostNotAllowed`). [routes] with a host outside `allowedHosts` is refused
 *   (`IllegalArgumentException`, like [addSentomaru]).
 * - Allowed host: https only (`HostNotAllowed`), canonical target URI (`InvalidRequest:TARGET_URI`: pass the URL as
 *   OkHttp's `HttpUrl` prints it, path at least `/`), content-type absent or exactly `application/json`; the body is copied
 *   (frozen) at the call, at most [Profile.MAX_BODY_BYTES] (`BodyTooLarge`); signals and `x-sentomaru-operation-id` are signed.
 * - J-04r: renews before signing when due; a `403 session-expired` (JSON `code` or `Sentomaru-Error` header) renews once and
 *   resends once. `session-unavailable` on the renewal → `EnrollmentRequired`; `installation-suspended` →
 *   `ServerRejected(SUSPENDED)` (grant kept, short backoff).
 * - Redirects are never followed by HttpURLConnection (`setInstanceFollowRedirects(false)`); the SDK follows at most
 *   [MAX_REDIRECTS] hops: off the allowlist the 3xx is returned; https→http is refused; 307/308 re-sign the frozen body for
 *   the new target; 301/302/303 become GET (HEAD stays HEAD) without body or signature; `Authorization` and `Cookie` are
 *   dropped when the host changes. A request with no operation gets its 3xx back, as with [addSentomaru].
 *
 * Not supported here: streaming and bodies of unknown length (the body is a `ByteArray`, at most 64 KiB when signed);
 * `Host`, `Content-Length` and `Transfer-Encoding` in [headers] (the connection frames the body: `InvalidRequest:HEADER_NAME`);
 * a non-empty body on GET/HEAD (`InvalidRequest:METHOD`: the JDK would turn the request into a POST; an empty one is sent
 * as no body); one header name given twice
 * with different case (`InvalidRequest:HEADER_VALUE`). The methods are the platform's: the JDK refuses PATCH.
 * A 403 whose body had to be read to look for `session-expired` is returned as a delegating connection with the same
 * status, headers and whole error body (not an `HttpsURLConnection`): never cast the result to `HttpsURLConnection`.
 * An [Opener] must return an `HttpsURLConnection` for an https URL (`HostNotAllowed` otherwise).
 *
 * D-07d, opt-in: with `events`, a TLS failure of any hop (or of the renewal) to a host of the app's pinning meta-data
 * (`sentomaru protect`, `network-pinning`) becomes a local `SentomaruTransportEvent` (`addTransportListener`); the
 * exception reaches the caller unchanged. Here `events` carries only transport events (the D-15b server response
 * events stay on OkHttp).
 */
object SentomaruUrlConnection {
    /** Same limit as [SentomaruInterceptor.MAX_REDIRECTS] and the Dio interceptor. */
    const val MAX_REDIRECTS = SentomaruWire.MAX_REDIRECTS

    /**
     * Opens each hop (and the renewal). The default is `url.openConnection()`; an app may set timeouts, a socket factory
     * or pinning here. The SDK then owns the connection: it refuses one whose URL is not the one asked for and sets
     * method, headers, body and `setInstanceFollowRedirects(false)` itself.
     */
    fun interface Opener {
        @Throws(IOException::class)
        fun open(url: URL): HttpURLConnection

        companion object {
            @JvmField val DEFAULT: Opener = Opener { it.openConnection() as HttpURLConnection }
        }
    }

    private val FRAMING = setOf("host", "content-length", "transfer-encoding")
    private val BODY_METHODS = setOf("POST", "PUT", "PATCH")

    @JvmStatic
    @JvmOverloads
    @Throws(IOException::class, SentomaruException::class)
    fun send(client: SentomaruClient, routes: SentomaruRoutes?, method: String, url: URL, body: ByteArray?,
        headers: Map<String, String>, operation: SentomaruOperation? = null, opener: Opener? = null): HttpURLConnection =
        send(client, routes, method, url, body, headers, operation, null, opener)

    /**
     * D-07d: as the other [send], with [events] for the local `pin_failure` event (`addTransportListener`). Its own
     * overload, with [opener] still last, so a Kotlin call that passes the opener as a trailing lambda keeps compiling.
     */
    @JvmStatic
    @Throws(IOException::class, SentomaruException::class)
    fun send(client: SentomaruClient, routes: SentomaruRoutes?, method: String, url: URL, body: ByteArray?,
        headers: Map<String, String>, operation: SentomaruOperation?, events: SentomaruSignalEvents?,
        opener: Opener?): HttpURLConnection {
        SentomaruWire.requireRoutesWithin(client, routes)
        val open = opener ?: Opener.DEFAULT
        val pins = PinFailureReporter.of(client, events)
        val caller = callerHeaders(headers)
        // GET/HEAD never send a body: a non-empty one is refused, an empty one is the same as none (with doOutput the
        // JDK would turn the request into a POST, unsigned or with a signed @method that is not the one sent).
        val bodyless = method == "GET" || method == "HEAD"
        if (bodyless && body != null && body.isNotEmpty())
            throw SentomaruException(SentomaruError.InvalidRequest(SentomaruError.Reason.METHOD))
        val payload = if (bodyless) null else body?.copyOf()
        val target = url.toString().toHttpUrlOrNull()
            ?: throw SentomaruException(SentomaruError.InvalidRequest(SentomaruError.Reason.TARGET_URI))
        // G-03c: a request with nothing declared takes its operation from the route table.
        val declared = caller["x-sentomaru-operation"] ?: operation?.name ?: routes?.operationFor(target)

        // Decision E6 / NET-1 (M1): outside the allowlist a declared operation is refused; an undeclared request passes
        // with Sentomaru headers stripped.
        if (target.host !in client.config.allowedHosts) {
            if (declared != null) throw SentomaruException(SentomaruError.HostNotAllowed())
            return exchange(open, Hop(method, target, stripped(caller), payload ?: emptyFor(method)), pins, url)
        }
        // Allowed host: https (NET-3) and the canonical target URI (M7) before anything else.
        if (target.scheme != "https") throw SentomaruException(SentomaruError.HostNotAllowed())
        val urlString = url.toString()
        SentomaruWire.requireCanonical(urlString)
        if (declared == null) return exchange(open, Hop(method, target, caller, payload ?: emptyFor(method)), pins, url)

        val optional = SentomaruWire.optionalHeaders(listOfNotNull(caller[SignalsHeader.NAME]), operation?.resolvedSignalsJson(),
            listOfNotNull(caller[Profile.OPERATION_ID_HEADER]), listOfNotNull(caller[Profile.TX_SIGNATURE_HEADER]))
        SentomaruWire.requireProfileContentType(caller["content-type"])
        // Decision E2 / SIGN-2 / SIGN-8: the bytes signed are the bytes sent.
        val frozen = payload ?: ByteArray(0)
        if (frozen.size > Profile.MAX_BODY_BYTES) throw SentomaruException(SentomaruError.BodyTooLarge(frozen.size))
        val sendsBody = payload != null || method in BODY_METHODS

        // J-04r: renew the grant before it expires (signed by the installation key, no new attestation).
        if (client.needsRenewal()) tryRenew(client, open, pins, ifDue = true)
        val sign = { hopUrl: HttpUrl -> client.sign(method, hopUrl.toString(), declared, frozen, optional) }
        var current = signedHop(method, target, caller, sign(target), frozen, sendsBody)
        var currentHopSigned = true
        var conn = exchange(open, current, pins)

        // J-04r: session-expired (nothing was done on the consumer): renew once and resend once, never a loop.
        if (conn.responseCode == 403 && client.canRenewNow()) {
            // The error body is read (at most MAX_RENEWAL_BYTES) only when the header does not already say it.
            var peek: Pair<ByteArray, InputStream?>? = null
            val expired = conn.getHeaderField(SentomaruWire.SESSION_ERROR_HEADER) == SentomaruWire.SESSION_EXPIRED || run {
                val stream = conn.errorStream
                val prefix = readAtMost(stream, SentomaruWire.MAX_RENEWAL_BYTES)
                peek = prefix to stream
                SentomaruWire.errorCode(prefix.decodeToString()) == SentomaruWire.SESSION_EXPIRED
            }
            var resent = false
            if (expired) {
                client.markGrantStale()
                if (tryRenew(client, open, pins)) {
                    discard(conn)
                    current = signedHop(method, target, caller, sign(target), frozen, sendsBody)
                    conn = exchange(open, current, pins)
                    resent = true
                }
            }
            if (!resent) peek?.let { (prefix, rest) -> conn = PeekedConnection(conn, prefix, rest) }
        }

        // SDK-NET-1/2: redirects under the SDK rules; HttpURLConnection never follows on its own.
        var redirects = 0
        while (SentomaruWire.isRedirect(conn.responseCode) && redirects < MAX_REDIRECTS) {
            val location = conn.getHeaderField("Location") ?: break
            val next = current.url.resolve(location) ?: break
            // Off-allowlist target: never followed; the 3xx goes back to the caller (nothing reaches that host).
            if (next.host !in client.config.allowedHosts) break
            if (next.scheme != "https") {
                discard(conn)
                throw SentomaruException(SentomaruError.HostNotAllowed())
            }
            redirects++
            val code = conn.responseCode
            discard(conn)
            val kept = TreeMap<String, String>(String.CASE_INSENSITIVE_ORDER).apply { putAll(current.headers) }
            if (next.host != current.url.host) {
                kept.remove("Authorization")
                kept.remove("Cookie")
            }
            current = if ((code == 307 || code == 308) && currentHopSigned) {
                // 307/308 keep method and body: re-sign the frozen body for the new @target-uri.
                signedHop(method, next, kept, sign(next), frozen, sendsBody)
            } else if (code == 307 || code == 308) {
                // Already an unsigned GET/HEAD (after a 301/302/303): resend it unchanged.
                Hop(current.method, next, kept, current.body)
            } else {
                // 300/301/302/303: GET (HEAD stays HEAD) without body; no longer the signed operation.
                currentHopSigned = false
                kept.remove("Content-Type")
                Hop(if (current.method == "HEAD") "HEAD" else "GET", next, stripped(kept), null)
            }
            conn = exchange(open, current, pins)
        }
        return conn
    }

    /** POST/PUT/PATCH always carry a body (empty when none was given), as OkHttp requires. */
    private fun emptyFor(method: String): ByteArray? = if (method in BODY_METHODS) ByteArray(0) else null

    private class Hop(val method: String, val url: HttpUrl, val headers: Map<String, String>, val body: ByteArray?)

    private fun callerHeaders(headers: Map<String, String>): TreeMap<String, String> {
        val out = TreeMap<String, String>(String.CASE_INSENSITIVE_ORDER)
        for ((name, value) in headers) {
            if (name.lowercase() in FRAMING) throw SentomaruException(SentomaruError.InvalidRequest(SentomaruError.Reason.HEADER_NAME))
            if (out.put(name, value) != null) throw SentomaruException(SentomaruError.InvalidRequest(SentomaruError.Reason.HEADER_VALUE))
        }
        return out
    }

    private fun stripped(headers: Map<String, String>): Map<String, String> =
        TreeMap<String, String>(String.CASE_INSENSITIVE_ORDER).apply {
            putAll(headers)
            SentomaruWire.SENTOMARU_HEADERS.forEach { remove(it) }
        }

    private fun signedHop(method: String, url: HttpUrl, base: Map<String, String>, signed: SignedMessage, frozen: ByteArray,
        sendsBody: Boolean): Hop {
        val headers = TreeMap<String, String>(String.CASE_INSENSITIVE_ORDER).apply { putAll(base) }
        signed.headers.forEach { (name, value) -> headers[name] = value }
        return Hop(method, url, headers, if (sendsBody) frozen else null)
    }

    /**
     * One request on the wire. [asked] is the caller's URL on a pass-through hop (sent as given), else the hop URL.
     * D-07d: an IOException on the way (open, connect and handshake, body, status line) goes to [pins] for a host of
     * the pinning meta-data, then is rethrown unchanged.
     */
    private fun exchange(open: Opener, hop: Hop, pins: PinFailureReporter?, asked: URL? = null): HttpURLConnection {
        val url = asked ?: URL(hop.url.toString())
        val conn = try {
            open.open(url)
        } catch (e: IOException) {
            pins?.observe(url.host, e)
            throw e
        }
        // The opener may not move the request elsewhere (defense in depth, as failIfFollowedByOkHttp), nor drop TLS.
        if (conn.url.toString() != url.toString() || (url.protocol == "https" && conn !is HttpsURLConnection)) {
            conn.disconnect()
            throw SentomaruException(SentomaruError.HostNotAllowed())
        }
        try {
            conn.instanceFollowRedirects = false
            conn.requestMethod = hop.method
            if (hop.headers.keys.any { it.startsWith("x-sentomaru-", ignoreCase = true) }) conn.useCaches = false
            hop.headers.forEach { (name, value) -> conn.setRequestProperty(name, value) }
            if (hop.body != null) {
                // Buffered, not streaming: the JDK answers a 401 to a streamed body with HttpRetryException.
                conn.doOutput = true
                conn.outputStream.use { it.write(hop.body) }
            }
            conn.responseCode
        } catch (e: IOException) {
            conn.disconnect()
            pins?.observe(url.host, e)
            throw e
        }
        if (conn.url.toString() != url.toString()) {
            conn.disconnect()
            throw SentomaruException(SentomaruError.HostNotAllowed())
        }
        return conn
    }

    /** Releases an intermediate answer (3xx, or the refusal that is resent). */
    private fun discard(conn: HttpURLConnection) {
        try {
            (if (conn.responseCode >= 400) conn.errorStream else conn.inputStream)?.close()
        } catch (_: IOException) {
            conn.disconnect()
        }
    }

    private fun readAtMost(stream: InputStream?, limit: Int): ByteArray {
        if (stream == null) return ByteArray(0)
        val out = java.io.ByteArrayOutputStream()
        val buffer = ByteArray(1024)
        while (out.size() < limit) {
            val n = stream.read(buffer, 0, minOf(buffer.size, limit - out.size()))
            if (n < 0) break
            out.write(buffer, 0, n)
        }
        return out.toByteArray()
    }

    /** J-04r: one renewal over HttpURLConnection; false (current grant kept) on any failure. */
    private fun tryRenew(client: SentomaruClient, open: Opener, pins: PinFailureReporter?, ifDue: Boolean = false): Boolean = try {
        if (ifDue) client.renewIfDue { sendRenewal(client, open, pins, it) } else client.renew { sendRenewal(client, open, pins, it) }
        true
    } catch (_: SentomaruException) {
        false
    }

    private fun sendRenewal(client: SentomaruClient, open: Opener, pins: PinFailureReporter?, signed: SignedMessage): RenewedGrant {
        val target = signed.targetUri.toHttpUrlOrNull()
        if (target == null || target.scheme != "https" || target.host !in client.config.allowedHosts)
            throw SentomaruException(SentomaruError.HostNotAllowed())
        val headers = TreeMap<String, String>(String.CASE_INSENSITIVE_ORDER)
        signed.headers.forEach { (name, value) -> headers[name] = value }
        val conn = exchange(open, Hop("POST", target, headers, signed.body()), pins)
        try {
            val code = conn.responseCode
            if (code == 403) SentomaruWire.failOnRenewalRefusal(
                SentomaruWire.errorCode(readAtMost(conn.errorStream, SentomaruWire.MAX_RENEWAL_BYTES).decodeToString()))
            if (code != 200) throw SentomaruException(SentomaruError.InvalidRequest(SentomaruError.Reason.PARAMS))
            val bytes = conn.inputStream.use { readAtMost(it, SentomaruWire.MAX_RENEWAL_BYTES + 1) }
            if (bytes.size > SentomaruWire.MAX_RENEWAL_BYTES) throw SentomaruException(SentomaruError.InvalidRequest(SentomaruError.Reason.PARAMS))
            return RenewedGrant.parse(bytes.decodeToString())
        } finally {
            discard(conn)
        }
    }

    /**
     * A 403 whose error body was read to look for `session-expired`: the same answer, with the bytes read put back in
     * front of the rest of the error stream ([rest] null: the body was only [prefix]).
     */
    private class PeekedConnection(private val delegate: HttpURLConnection, prefix: ByteArray, rest: InputStream?) :
        HttpURLConnection(delegate.url) {
        private val error: InputStream =
            if (rest == null) ByteArrayInputStream(prefix) else SequenceInputStream(ByteArrayInputStream(prefix), rest)

        init { connected = true }
        override fun connect() = Unit
        override fun disconnect() = delegate.disconnect()
        override fun usingProxy() = delegate.usingProxy()
        override fun getResponseCode() = delegate.responseCode
        override fun getResponseMessage(): String? = delegate.responseMessage
        override fun getHeaderField(name: String?): String? = delegate.getHeaderField(name)
        override fun getHeaderField(n: Int): String? = delegate.getHeaderField(n)
        override fun getHeaderFieldKey(n: Int): String? = delegate.getHeaderFieldKey(n)
        override fun getHeaderFields(): Map<String?, List<String>> = delegate.headerFields
        override fun getInputStream(): InputStream = delegate.inputStream
        override fun getErrorStream(): InputStream = error
        override fun getRequestMethod(): String = delegate.requestMethod
        override fun getInstanceFollowRedirects() = delegate.instanceFollowRedirects
        override fun getConnectTimeout() = delegate.connectTimeout
        override fun getReadTimeout() = delegate.readTimeout
    }
}
