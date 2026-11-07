package br.com.ebees.sentomaru.sdk.transport

import br.com.ebees.sentomaru.core.*
import br.com.ebees.sentomaru.sdk.*
import br.com.ebees.sentomaru.signals.*
import okhttp3.MediaType.Companion.toMediaType
import okhttp3.OkHttpClient
import okhttp3.Request
import okhttp3.RequestBody.Companion.toRequestBody
import okhttp3.mockwebserver.MockResponse
import okhttp3.mockwebserver.MockWebServer
import okhttp3.mockwebserver.RecordedRequest
import org.junit.After
import org.junit.Assert.*
import org.junit.Before
import org.junit.Test
import java.net.HttpURLConnection
import java.net.URL
import java.time.Clock
import java.time.Instant
import java.time.ZoneOffset
import java.util.Base64
import javax.net.ssl.HttpsURLConnection

/**
 * S2: the RFC 9421 signing transport for HttpURLConnection ([SentomaruUrlConnection.send]), against the same TLS
 * MockWebServer as [OkHttpTransportTest] and with the same rules. Cross-host hops use `127.0.0.1` (allowed, loopback)
 * so no DNS override is needed; an off-allowlist target is never contacted, so its name never resolves.
 */
class UrlConnectionTransportTest {
    private val ALT_ALLOWED_HOST = "127.0.0.1"
    private val EXTERNAL_HOST = "external.untrusted.test"
    private val now = Instant.parse("2026-10-09T10:00:00Z")
    private val clock = Clock.fixed(now, ZoneOffset.UTC)
    private val session = "aaaaaaaa-bbbb-4ccc-8ddd-eeeeeeeeeeee"
    private val keyId = "11111111-2222-4333-8444-555555555555"

    private lateinit var server: MockWebServer
    private lateinit var allowedHost: String
    private lateinit var keys: TestJcaKeys
    private lateinit var store: TestStore
    private lateinit var client: SentomaruClient

    /** Test TLS only (self-signed `localhost`); a production app keeps the platform defaults. */
    private val opener = SentomaruUrlConnection.Opener { url ->
        (url.openConnection() as HttpURLConnection).also {
            if (it is HttpsURLConnection) {
                it.sslSocketFactory = TestTls.sslContext.socketFactory
                it.hostnameVerifier = javax.net.ssl.HostnameVerifier { _, _ -> true }
            }
            it.connectTimeout = 5_000
            it.readTimeout = 5_000
        }
    }

    @Before fun setUp() {
        server = MockWebServer()
        server.useHttps(TestTls.sslContext.socketFactory, false)
        server.start()
        allowedHost = server.hostName
        assertNotEquals("the cross-host tests need the server reachable by a second allowed name", ALT_ALLOWED_HOST, allowedHost)
        keys = TestJcaKeys()
        store = TestStore()
        client = enrolled(SentomaruConfig("org", "app", "hml", setOf(allowedHost, ALT_ALLOWED_HOST),
            "https://$allowedHost:${server.port}/enroll"), keys, store, clock)
    }

    @After fun tearDown() {
        server.shutdown()
    }

    private fun enrolled(cfg: SentomaruConfig, k: InstallationKeys, s: InstallationStore, c: Clock): SentomaruClient =
        SentomaruClient(cfg, k, s, c).also {
            it.enroll(EnrollmentChallenge(keyId, Base64.getEncoder().encodeToString(ByteArray(32) { 1 }), ByteArray(32) { 2 },
                c.instant().plusSeconds(300))) { EnrollmentGrant(session, keyId, session, "hardware", "verified") }
        }

    private fun url(path: String, host: String = allowedHost, port: Int = server.port, scheme: String = "https") =
        URL("$scheme://$host:$port$path")

    private fun send(method: String, url: URL, body: ByteArray?, headers: Map<String, String> = emptyMap(),
        operation: SentomaruOperation? = null, routes: SentomaruRoutes? = null, sdk: SentomaruClient = client): HttpURLConnection =
        SentomaruUrlConnection.send(sdk, routes, method, url, body, headers, operation, opener)

    private val credentials = mapOf("x-sentomaru-operation" to "submit", "Authorization" to "Bearer user-token",
        "Cookie" to "session=user-cookie")

    private fun signedPost(path: String, body: String = "{\"id\":1}", sdk: SentomaruClient = client) =
        send("POST", url(path), body.toByteArray(), credentials, sdk = sdk)

    private fun HttpURLConnection.errorText(): String = (errorStream ?: inputStream).use { it.readBytes().decodeToString() }

    private fun params(sigInput: String) = SignatureParams(
        sigInput.substringAfter("created=").substringBefore(";").toLong(),
        sigInput.substringAfter("expires=").substringBefore(";").toLong(),
        sigInput.substringAfter("nonce=\"").substringBefore("\""),
        sigInput.substringAfter("keyid=\"").substringBefore("\""))

    private fun verifies(recorded: RecordedRequest, method: String, target: String, k: TestJcaKeys = keys, s: TestStore = store): Boolean {
        val base = SignatureBase.build(method, target, Profile.CALLER_HEADERS.associateWith { recorded.getHeader(it)!! },
            recorded.getHeader("content-digest")!!, params(recorded.getHeader("signature-input")!!))
        return k.verify(s.record!!.alias, base, recorded.getHeader("signature")!!)
    }

    private fun assertNoSentomaruOrSignatureHeaders(recorded: RecordedRequest) {
        for (name in Profile.CALLER_HEADERS.filter { it.startsWith("x-sentomaru-") } +
            listOf("content-digest", "signature", "signature-input", "x-sentomaru-signals", "x-sentomaru-operation-id")) {
            assertNull("$name must not be forwarded", recorded.getHeader(name))
        }
    }

    // ---- profile headers, signature, operation sources

    @Test fun signedRequestHasTheProfileHeadersAVerifiedSignatureAndTheOkHttpFormat() {
        server.enqueue(MockResponse().setResponseCode(200).setBody("{\"status\":\"ok\"}"))
        server.enqueue(MockResponse().setResponseCode(200))
        val target = "https://$allowedHost:${server.port}/api/v1/inspections"
        val body = "{\"field\":\"value\"}"

        val conn = send("POST", URL(target), body.toByteArray(),
            mapOf("x-sentomaru-operation" to "submit", "content-type" to "application/json"))
        assertEquals(200, conn.responseCode)
        assertEquals("{\"status\":\"ok\"}", conn.inputStream.use { it.readBytes().decodeToString() })

        val recorded = server.takeRequest()
        assertEquals("POST", recorded.method)
        assertEquals("/api/v1/inspections", recorded.path)
        assertEquals(body, recorded.body.readUtf8())
        assertEquals("sentomaru-p0", recorded.getHeader("x-sentomaru-profile"))
        assertEquals("org", recorded.getHeader("x-sentomaru-org"))
        assertEquals("app", recorded.getHeader("x-sentomaru-app"))
        assertEquals("hml", recorded.getHeader("x-sentomaru-environment"))
        assertEquals(session, recorded.getHeader("x-sentomaru-session"))
        assertEquals("submit", recorded.getHeader("x-sentomaru-operation"))
        assertEquals("application/json", recorded.getHeader("content-type"))
        assertEquals(1, recorded.headers.values("content-type").size)
        assertTrue("signature verifies with the installation key", verifies(recorded, "POST", target))

        // The same request through addSentomaru (OkHttp): same signed components, same digest, same header set.
        val okHttp = OkHttpClient.Builder().sslSocketFactory(TestTls.sslContext.socketFactory, TestTls.trustManager)
            .hostnameVerifier { _, _ -> true }.addSentomaru(client).build()
        okHttp.newCall(Request.Builder().url(target).header("x-sentomaru-operation", "submit")
            .post(body.toRequestBody("application/json".toMediaType())).build()).execute().close()
        val viaOkHttp = server.takeRequest()
        assertEquals(viaOkHttp.getHeader("signature-input")!!.substringBefore(";created="),
            recorded.getHeader("signature-input")!!.substringBefore(";created="))
        assertEquals(viaOkHttp.getHeader("content-digest"), recorded.getHeader("content-digest"))
        for (name in Profile.CALLER_HEADERS) assertEquals(name, viaOkHttp.getHeader(name), recorded.getHeader(name))
        val sentomaruNames = { r: RecordedRequest -> r.headers.names().filter { it.startsWith("x-sentomaru-") || it in
            setOf("content-digest", "signature", "signature-input") }.toSet() }
        assertEquals(sentomaruNames(viaOkHttp), sentomaruNames(recorded))
    }

    @Test fun anExplicitOperationParameterDeclaresTheOperationAndSignsItsSignals() {
        server.enqueue(MockResponse().setResponseCode(200))
        val snapshot = SignalsSnapshot(catalogVersion = "1.0.0", collectedAt = "2026-10-09T10:00:00Z", durationMs = 25,
            observations = listOf(SignalObservation(capabilityId = "root_indicated", version = "1.0.0",
                state = SignalState.NOT_DETECTED, observedAt = "2026-10-09T10:00:00Z")))
        val conn = send("POST", url("/api/tagged"), "{}".toByteArray(), operation = SentomaruOperation("upload", signals = snapshot))
        assertEquals(200, conn.responseCode)
        val recorded = server.takeRequest()
        assertEquals("upload", recorded.getHeader("x-sentomaru-operation"))
        assertTrue(recorded.getHeader("x-sentomaru-signals")!!.contains("\"root_indicated\""))
        assertTrue(recorded.getHeader("signature-input")!!.contains("\"x-sentomaru-operation\" \"x-sentomaru-signals\")"))
    }

    @Test fun theHeaderWinsOverTheParameter() {
        server.enqueue(MockResponse().setResponseCode(200))
        send("POST", url("/api/x"), "{}".toByteArray(), mapOf("X-Sentomaru-Operation" to "submit"),
            operation = SentomaruOperation("upload")).responseCode
        assertEquals("submit", server.takeRequest().getHeader("x-sentomaru-operation"))
    }

    @Test fun operationIdIsSignedAndAFreshNonceIsUsedOnEachSend() {
        server.enqueue(MockResponse().setResponseCode(503))
        server.enqueue(MockResponse().setResponseCode(200))
        val headers = mapOf("x-sentomaru-operation" to "charge", "x-sentomaru-operation-id" to "op-0123456789abcdef")
        assertEquals(503, send("POST", url("/api/charge"), "{}".toByteArray(), headers).responseCode)
        assertEquals(200, send("POST", url("/api/charge"), "{}".toByteArray(), headers).responseCode)
        val first = server.takeRequest()
        val second = server.takeRequest()
        for (r in listOf(first, second)) {
            assertEquals("op-0123456789abcdef", r.getHeader("x-sentomaru-operation-id"))
            assertTrue(r.getHeader("signature-input")!!.contains("\"x-sentomaru-operation\" \"x-sentomaru-operation-id\")"))
        }
        assertNotEquals(params(first.getHeader("signature-input")!!).nonce, params(second.getHeader("signature-input")!!).nonce)
    }

    @Test fun requestWithoutOperationOnAnAllowedHostProceedsUnsigned() {
        server.enqueue(MockResponse().setResponseCode(200))
        assertEquals(200, send("GET", url("/public/health"), null).responseCode)
        val recorded = server.takeRequest()
        assertEquals("GET", recorded.method)
        assertNoSentomaruOrSignatureHeaders(recorded)
    }

    // ---- G-03c route table

    private fun routes(vararg hosts: String = arrayOf(allowedHost)) = SentomaruRoutes.of(hosts.toList(),
        listOf(SentomaruRoutes.Route("/v1/demandas/*/concluir", "concluir_demanda")))

    @Test fun aRequestOnAProfileRouteIsSignedWithoutDeclaringIt() {
        server.enqueue(MockResponse().setResponseCode(200))
        val target = "https://$allowedHost:${server.port}/V1/demandas/42/concluir/"
        assertEquals(200, send("POST", URL(target), "{\"ok\":true}".toByteArray(), routes = routes()).responseCode)
        val recorded = server.takeRequest()
        assertEquals("concluir_demanda", recorded.getHeader("x-sentomaru-operation"))
        assertTrue(verifies(recorded, "POST", target))
    }

    @Test fun aDeclaredOperationWinsAndAnUncoveredPathPassesUnsigned() {
        server.enqueue(MockResponse().setResponseCode(200))
        server.enqueue(MockResponse().setResponseCode(200))
        send("POST", url("/v1/demandas/42/concluir"), "{}".toByteArray(), mapOf("x-sentomaru-operation" to "submit"),
            routes = routes()).responseCode
        assertEquals("submit", server.takeRequest().getHeader("x-sentomaru-operation"))
        send("GET", url("/v1/demandas/42/concluir/extra"), null, routes = routes()).responseCode
        assertNoSentomaruOrSignatureHeaders(server.takeRequest())
    }

    @Test fun aRouteOnAHostOutsideTheAllowlistIsRefusedLikeAddSentomaru() {
        val offList = SentomaruClient(SentomaruConfig("org", "app", "hml", setOf("other.example"), "https://other.example/enroll"),
            keys, TestStore(), clock)
        val error = assertThrows(IllegalArgumentException::class.java) {
            send("GET", url("/v1/x"), null, routes = routes(), sdk = offList)
        }
        assertEquals("network-signing.hosts not within allowedHosts", error.message)
        assertEquals(0, server.requestCount)
    }

    @Test fun aPercentEncodedRoutePathIsCoveredAndRefusedAsNonCanonicalNeverSentUnsigned() {
        val error = assertThrows(SentomaruException::class.java) {
            send("POST", url("/v1/%64emandas/42/concluir"), "{}".toByteArray(), routes = routes())
        }
        assertEquals("InvalidRequest:TARGET_URI", error.error.code)
        assertEquals(0, server.requestCount)
    }

    // ---- allowlist, https, content-type, body

    private fun offListClient() = SentomaruClient(SentomaruConfig("org", "app", "hml", setOf("other.example"),
        "https://other.example/enroll"), keys, TestStore(), clock)

    @Test fun hostOutsideAllowlistPassesAnUndeclaredRequestUnsignedWithSentomaruHeadersStripped() {
        server.enqueue(MockResponse().setResponseCode(200))
        val conn = send("POST", url("/third-party"), "a,b".toByteArray(),
            mapOf("content-type" to "text/csv", "signature" to "sig1=:leaked:", "X-Sentomaru-Session" to "leaked",
                "content-digest" to "sha-256=:x:", "x-sentomaru-signals" to "{}"), sdk = offListClient())
        assertEquals(200, conn.responseCode)
        val recorded = server.takeRequest()
        assertNoSentomaruOrSignatureHeaders(recorded)
        assertEquals("the caller's content-type is not ours to remove", "text/csv", recorded.getHeader("content-type"))
        assertEquals("a,b", recorded.body.readUtf8())
    }

    @Test fun declaredOperationToHostOutsideAllowlistIsRefusedNotSentUnsigned() {
        for (declare in listOf<(HttpURLConnection?) -> Unit>(
            { send("POST", url("/external"), "{}".toByteArray(), mapOf("x-sentomaru-operation" to "submit"), sdk = offListClient()) },
            { send("POST", url("/external"), "{}".toByteArray(), operation = SentomaruOperation("submit"), sdk = offListClient()) })) {
            val error = assertThrows(SentomaruException::class.java) { declare(null) }
            assertEquals("HostNotAllowed", error.error.code)
        }
        assertEquals(0, server.requestCount)
    }

    @Test fun insecureHttpOnAllowedHostIsRefused() {
        val error = assertThrows(SentomaruException::class.java) {
            send("POST", url("/insecure", scheme = "http"), "{}".toByteArray(), mapOf("x-sentomaru-operation" to "submit"))
        }
        assertEquals("HostNotAllowed", error.error.code)
        assertEquals(0, server.requestCount)
    }

    @Test fun invalidContentTypeIsRefused() {
        for (type in listOf("application/json; charset=utf-8", "text/plain", "Application/JSON")) {
            val error = assertThrows(SentomaruException::class.java) {
                send("POST", url("/api/test"), "{}".toByteArray(), mapOf("x-sentomaru-operation" to "submit", "Content-Type" to type))
            }
            assertEquals(type, "InvalidRequest:HEADER_VALUE", error.error.code)
        }
        assertEquals(0, server.requestCount)
    }

    @Test fun bodyExceeding64KiBIsRefusedAndTheLimitItselfIsSigned() {
        val error = assertThrows(SentomaruException::class.java) {
            send("POST", url("/api/large"), ByteArray(Profile.MAX_BODY_BYTES + 1) { 42 }, mapOf("x-sentomaru-operation" to "submit"))
        }
        assertEquals("BodyTooLarge", error.error.code)
        assertEquals(0, server.requestCount)
        server.enqueue(MockResponse().setResponseCode(200))
        assertEquals(200, send("POST", url("/api/large"), ByteArray(Profile.MAX_BODY_BYTES) { 42 },
            mapOf("x-sentomaru-operation" to "submit")).responseCode)
        assertEquals(Profile.MAX_BODY_BYTES.toLong(), server.takeRequest().bodySize)
    }

    @Test fun framingHeadersAndABodyOnGetAreRefused() {
        for (name in listOf("Host", "content-length", "Transfer-Encoding")) {
            val error = assertThrows(SentomaruException::class.java) {
                send("POST", url("/api/x"), "{}".toByteArray(), mapOf("x-sentomaru-operation" to "submit", name to "1"))
            }
            assertEquals(name, "InvalidRequest:HEADER_NAME", error.error.code)
        }
        for (dup in listOf(mapOf("x-sentomaru-operation" to "a", "X-Sentomaru-Operation" to "b"),
                mapOf("x-sentomaru-operation" to "a", "x-sentomaru-signals" to "{}", "X-SENTOMARU-SIGNALS" to "{}"))) {
            val error = assertThrows(SentomaruException::class.java) { send("POST", url("/api/x"), "{}".toByteArray(), dup) }
            assertEquals("InvalidRequest:HEADER_VALUE", error.error.code)
        }
        val error = assertThrows(SentomaruException::class.java) {
            send("GET", url("/api/x"), "{}".toByteArray(), mapOf("x-sentomaru-operation" to "submit"))
        }
        assertEquals("InvalidRequest:METHOD", error.error.code)
        assertEquals(0, server.requestCount)
    }

    @Test fun aSignedGetCarriesNoBodyAndSignsTheEmptyDigest() {
        server.enqueue(MockResponse().setResponseCode(200))
        val target = "https://$allowedHost:${server.port}/api/read?x=1"
        assertEquals(200, send("GET", URL(target), null, mapOf("x-sentomaru-operation" to "read")).responseCode)
        val recorded = server.takeRequest()
        assertEquals("GET", recorded.method)
        assertEquals(0L, recorded.bodySize)
        assertTrue(verifies(recorded, "GET", target))
    }

    @Test fun anEmptyBodyOnGetOrHeadIsNoBodyAndKeepsTheMethod() {
        // With doOutput the JDK sends a GET as POST: an empty array must not reach the wire as a body.
        for (method in listOf("GET", "HEAD")) {
            for (headers in listOf(mapOf("x-sentomaru-operation" to "read"), emptyMap())) {
                server.enqueue(MockResponse().setResponseCode(200))
                val target = "https://$allowedHost:${server.port}/api/read"
                assertEquals(200, send(method, URL(target), ByteArray(0), headers).responseCode)
                val recorded = server.takeRequest()
                assertEquals("$method $headers", method, recorded.method)
                assertEquals(0L, recorded.bodySize)
                if (headers.isNotEmpty()) assertTrue(verifies(recorded, method, target))
            }
        }
    }

    @Test fun anOpenerThatDropsTlsOnAnHttpsUrlIsRefused() {
        val plain = object : HttpURLConnection(URL("https://$allowedHost:${server.port}/api/x")) {
            override fun connect() = Unit
            override fun disconnect() = Unit
            override fun usingProxy() = false
        }
        val error = assertThrows(SentomaruException::class.java) {
            SentomaruUrlConnection.send(client, null, "POST", URL("https://$allowedHost:${server.port}/api/x"), "{}".toByteArray(),
                mapOf("x-sentomaru-operation" to "submit"), null) { plain }
        }
        assertEquals("HostNotAllowed", error.error.code)
        assertEquals(0, server.requestCount)
    }

    @Test fun aRefusalReachesTheCallerWithItsBody() {
        // JDK HttpURLConnection in streaming mode turns a 401 into HttpRetryException; the SDK buffers instead.
        for (code in listOf(400, 401, 403, 409, 413)) {
            server.enqueue(MockResponse().setResponseCode(code).setBody("{\"code\":\"proof-invalid\"}"))
            val conn = signedPost("/api/refused")
            assertEquals(code, conn.responseCode)
            assertEquals("{\"code\":\"proof-invalid\"}", conn.errorText())
        }
    }

    @Test fun unenrolledClientFailsWithTypedError() {
        client.reset()
        val error = assertThrows(SentomaruException::class.java) { signedPost("/api/fail") }
        assertEquals("NotEnrolled", error.error.code)
        assertEquals(0, server.requestCount)
    }

    // ---- redirects (R2 / SDK-NET-1..3)

    @Test fun redirect307OnAllowedHostReSignsForTheNewTargetUri() {
        val target = "https://$allowedHost:${server.port}/api/v1/destination"
        for (code in listOf(307, 308)) {
            server.enqueue(MockResponse().setResponseCode(code).addHeader("Location", target))
            server.enqueue(MockResponse().setResponseCode(200).setBody("{\"redirected\":true}"))
            val conn = send("POST", url("/api/v1/source"), "{\"id\":1}".toByteArray(), mapOf("x-sentomaru-operation" to "move"))
            assertEquals(200, conn.responseCode)
            assertEquals(target, conn.url.toString())
            val first = server.takeRequest()
            val second = server.takeRequest()
            assertEquals("/api/v1/destination", second.path)
            assertEquals("POST", second.method)
            assertEquals("{\"id\":1}", second.body.readUtf8())
            assertNotEquals(first.getHeader("signature"), second.getHeader("signature"))
            assertTrue("$code: the second hop is signed for its own @target-uri", verifies(second, "POST", target))
        }
    }

    @Test fun redirectOutsideAllowlistIsNotFollowedSoNothingLeaks() {
        for (code in listOf(301, 302, 303, 307, 308)) {
            server.enqueue(MockResponse().setResponseCode(code).addHeader("Location", "https://$EXTERNAL_HOST:1/landing"))
            val conn = signedPost("/redirect-out")
            assertEquals("off-allowlist $code is returned to the caller, not followed", code, conn.responseCode)
            assertEquals("https://$EXTERNAL_HOST:1/landing", conn.getHeaderField("Location"))
            server.takeRequest()
        }
        assertEquals(5, server.requestCount)
    }

    @Test fun redirectDowngradeToHttpOnAllowedHostIsRefusedBeforeSending() {
        for (code in listOf(302, 307)) {
            server.enqueue(MockResponse().setResponseCode(code).addHeader("Location", "http://$allowedHost:${server.port}/plain"))
            val error = assertThrows(SentomaruException::class.java) { signedPost("/downgrade") }
            assertEquals("HostNotAllowed", error.error.code)
            server.takeRequest()
        }
        assertEquals(2, server.requestCount)
    }

    @Test fun redirect303OnAllowedHostBecomesAnUnsignedGetWithoutBody() {
        for (code in listOf(301, 302, 303)) {
            server.enqueue(MockResponse().setResponseCode(code).addHeader("Location", "/api/v1/result-$code"))
            server.enqueue(MockResponse().setResponseCode(200))
            assertEquals(200, signedPost("/api/v1/submit-$code").responseCode)
            val first = server.takeRequest()
            assertEquals("POST", first.method)
            assertNotNull(first.getHeader("signature"))
            val second = server.takeRequest()
            assertEquals("/api/v1/result-$code", second.path)
            assertEquals("$code converts to GET", "GET", second.method)
            assertEquals("body dropped on $code", 0L, second.bodySize)
            assertNull(second.getHeader("content-type"))
            assertNoSentomaruOrSignatureHeaders(second)
            assertEquals("same-host hop keeps caller credentials", "Bearer user-token", second.getHeader("Authorization"))
        }
    }

    @Test fun crossHostRedirectWithinAllowlistDropsAuthorizationAndCookie() {
        for (code in listOf(301, 302, 307, 308)) {
            val alt = MockWebServer()
            alt.useHttps(TestTls.sslContext.socketFactory, false)
            alt.start()
            try {
                val target = "https://$ALT_ALLOWED_HOST:${alt.port}/n?x=1"
                server.enqueue(MockResponse().setResponseCode(code).addHeader("Location", target))
                alt.enqueue(MockResponse().setResponseCode(200))
                assertEquals(200, signedPost("/x$code", "{\"id\":7}").responseCode)
                server.takeRequest()
                val second = alt.takeRequest()
                assertNull("$code: Authorization dropped cross-host", second.getHeader("Authorization"))
                assertNull("$code: Cookie dropped cross-host", second.getHeader("Cookie"))
                if (code >= 307) {
                    assertEquals("POST", second.method)
                    assertEquals("{\"id\":7}", second.body.readUtf8())
                    assertTrue(verifies(second, "POST", target))
                } else {
                    assertEquals("GET", second.method)
                    assertNoSentomaruOrSignatureHeaders(second)
                }
            } finally {
                alt.shutdown()
            }
        }
    }

    @Test fun redirectChainTracksStatePerHopAndNeverResurrectsPost() {
        server.enqueue(MockResponse().setResponseCode(303).addHeader("Location", "/b/hop"))
        server.enqueue(MockResponse().setResponseCode(307).addHeader("Location", "c"))
        server.enqueue(MockResponse().setResponseCode(200))
        assertEquals(200, signedPost("/a/start").responseCode)
        assertEquals("POST", server.takeRequest().method)
        assertEquals("GET", server.takeRequest().method)
        val third = server.takeRequest()
        assertEquals("Location resolves against the current hop", "/b/c", third.path)
        assertEquals("307 after a 303 keeps GET", "GET", third.method)
        assertEquals(0L, third.bodySize)
        assertNoSentomaruOrSignatureHeaders(third)
    }

    @Test fun hopLimitIsFiveLikeOkHttpAndDio() {
        repeat(SentomaruUrlConnection.MAX_REDIRECTS + 1) {
            server.enqueue(MockResponse().setResponseCode(302).addHeader("Location", "/loop$it"))
        }
        assertEquals("after 5 follows the last 3xx is returned", 302, signedPost("/loop").responseCode)
        assertEquals(5, SentomaruUrlConnection.MAX_REDIRECTS)
        assertEquals(SentomaruInterceptor.MAX_REDIRECTS, SentomaruUrlConnection.MAX_REDIRECTS)
        assertEquals(6, server.requestCount)
    }

    @Test fun anOpenerThatRedirectsTheConnectionElsewhereIsRefused() {
        val other = SentomaruUrlConnection.Opener { (URL("https://$EXTERNAL_HOST:1/x").openConnection() as HttpURLConnection) }
        val error = assertThrows(SentomaruException::class.java) {
            SentomaruUrlConnection.send(client, null, "POST", url("/a"), "{}".toByteArray(),
                mapOf("x-sentomaru-operation" to "submit"), null, other)
        }
        assertEquals("HostNotAllowed", error.error.code)
    }

    // ---- J-04r renewal

    private class MovingClock(var instant: Instant) : Clock() {
        override fun getZone() = ZoneOffset.UTC
        override fun withZone(zone: java.time.ZoneId?) = this
        override fun instant() = instant
    }

    private val renewedSession = "bbbbbbbb-cccc-4ddd-8eee-ffffffffffff"
    private lateinit var moving: MovingClock
    private lateinit var renewingStore: TestStore
    private lateinit var renewingKeys: TestJcaKeys

    private fun renewingClient(): SentomaruClient {
        moving = MovingClock(now)
        renewingStore = TestStore()
        renewingKeys = TestJcaKeys()
        return enrolled(SentomaruConfig("org", "app", "hml", setOf(allowedHost), "https://$allowedHost:${server.port}/enroll",
            renewalUrl = "https://$allowedHost:${server.port}/sessions"), renewingKeys, renewingStore, moving)
    }

    private fun renewal(ttl: Int = 600) = MockResponse().setResponseCode(200)
        .setBody("{\"installationId\":\"$session\",\"keyId\":\"$keyId\",\"sessionId\":\"$renewedSession\"," +
            "\"expiresAt\":\"2026-10-09T10:20:00+00:00\",\"ttlSeconds\":$ttl}")

    @Test fun aGrantNearItsLifetimeIsRenewedWithASignedRequestBeforeTheOperation() {
        val sdk = renewingClient()
        moving.instant = now.plusSeconds(EnrollmentGrant.DEFAULT_TTL_SECONDS - 119)
        assertTrue(sdk.needsRenewal())
        server.enqueue(renewal())
        server.enqueue(MockResponse().setResponseCode(200))
        assertEquals(200, signedPost("/api/demandas", sdk = sdk).responseCode)

        val renew = server.takeRequest()
        assertEquals("POST" to "/sessions", renew.method to renew.path)
        assertEquals(session to "session_renew", renew.getHeader("x-sentomaru-session") to renew.getHeader("x-sentomaru-operation"))
        assertEquals("{}", renew.body.readUtf8())
        assertTrue(verifies(renew, "POST", "https://$allowedHost:${server.port}/sessions", renewingKeys, renewingStore))
        assertEquals(renewedSession, server.takeRequest().getHeader("x-sentomaru-session"))
        assertFalse(sdk.needsRenewal())
    }

    @Test fun aFailedRenewalKeepsTheGrantAndStillSendsTheOperation() {
        val sdk = renewingClient()
        moving.instant = now.plusSeconds(700)
        server.enqueue(MockResponse().setResponseCode(503).setBody("{\"code\":\"store-unavailable\"}"))
        server.enqueue(MockResponse().setResponseCode(200))
        assertEquals(200, signedPost("/api/demandas", sdk = sdk).responseCode)
        server.takeRequest()
        assertEquals(session, server.takeRequest().getHeader("x-sentomaru-session"))
        assertFalse(sdk.needsRenewal()) // 60 s backoff
    }

    @Test fun aRenewalAnswerLargerThanTheLimitIsRefusedAndTheGrantKept() {
        val sdk = renewingClient()
        moving.instant = now.plusSeconds(700)
        server.enqueue(MockResponse().setResponseCode(200).setBody("{\"pad\":\"" + "x".repeat(5000) + "\"}"))
        server.enqueue(MockResponse().setResponseCode(200))
        assertEquals(200, signedPost("/api/demandas", sdk = sdk).responseCode)
        server.takeRequest()
        assertEquals(session, server.takeRequest().getHeader("x-sentomaru-session"))
        assertEquals("InvalidRequest:PARAMS", sdk.lastRenewalFailure())
    }

    @Test fun sessionExpiredRenewsOnceAndResendsOnceNeverLooping() {
        val sdk = renewingClient()
        server.enqueue(MockResponse().setResponseCode(403).setBody("{\"code\":\"session-expired\"}"))
        server.enqueue(renewal())
        server.enqueue(MockResponse().setResponseCode(403).setBody("{\"code\":\"session-expired\"}"))
        val conn = signedPost("/api/demandas", sdk = sdk)
        assertEquals("the second refusal goes back to the caller", 403, conn.responseCode)
        assertEquals("{\"code\":\"session-expired\"}", conn.errorText())
        val first = server.takeRequest()
        assertEquals(session, first.getHeader("x-sentomaru-session"))
        assertEquals("/sessions", server.takeRequest().path)
        val resent = server.takeRequest()
        assertEquals(renewedSession, resent.getHeader("x-sentomaru-session"))
        // The resend is a new signature (fresh nonce), never a replay of the refused one.
        assertNotEquals(params(first.getHeader("signature-input")!!).nonce, params(resent.getHeader("signature-input")!!).nonce)
        assertNotEquals(first.getHeader("signature"), resent.getHeader("signature"))
        assertEquals(3, server.requestCount)
    }

    @Test fun sessionExpiredByHeaderRenewsAndTheResentRequestSucceeds() {
        val sdk = renewingClient()
        server.enqueue(MockResponse().setResponseCode(403).addHeader("Sentomaru-Error", "session-expired"))
        server.enqueue(renewal())
        server.enqueue(MockResponse().setResponseCode(200).setBody("done"))
        val conn = signedPost("/api/demandas", sdk = sdk)
        assertEquals(200, conn.responseCode)
        assertEquals("done", conn.inputStream.use { it.readBytes().decodeToString() })
        assertEquals(3, server.requestCount)
    }

    @Test fun anotherForbiddenKeepsItsWholeBodyForTheCaller() {
        val sdk = renewingClient()
        val big = "{\"code\":\"operation-context\",\"pad\":\"" + "y".repeat(10_000) + "\"}"
        server.enqueue(MockResponse().setResponseCode(403).setBody(big).addHeader("X-Extra", "1"))
        val conn = signedPost("/api/demandas", sdk = sdk)
        assertEquals(403, conn.responseCode)
        assertEquals("1", conn.getHeaderField("X-Extra"))
        assertEquals(big, conn.errorText())
        assertEquals(1, server.requestCount)
    }

    @Test fun sessionExpiredInsideTheBackoffDoesNotRenewAgain() {
        val sdk = renewingClient()
        moving.instant = now.plusSeconds(700)
        server.enqueue(MockResponse().setResponseCode(503).setBody("{\"code\":\"store-unavailable\"}"))
        server.enqueue(MockResponse().setResponseCode(403).setBody("{\"code\":\"session-expired\"}"))
        assertEquals(403, signedPost("/api/demandas", sdk = sdk).responseCode)
        assertEquals(2, server.requestCount)
    }

    @Test fun installationSuspendedOnTheRenewalIsSuspendedNotEnrollmentRequired() {
        val sdk = renewingClient()
        moving.instant = now.plusSeconds(700)
        val failedAt = moving.instant
        server.enqueue(MockResponse().setResponseCode(403).setBody("{\"code\":\"installation-suspended\"}"))
        server.enqueue(MockResponse().setResponseCode(200))
        assertEquals(200, signedPost("/api/demandas", sdk = sdk).responseCode)
        assertEquals("/sessions", server.takeRequest().path)
        assertEquals(session, server.takeRequest().getHeader("x-sentomaru-session"))
        assertEquals(InstallationState.Enrolled, sdk.state())
        assertEquals("ServerRejected:SUSPENDED", sdk.lastRenewalFailure())
        moving.instant = failedAt.plusSeconds(4)
        assertFalse(sdk.canRenewNow())
        moving.instant = failedAt.plus(SentomaruClient.SUSPENDED_RENEWAL_BACKOFF)
        assertTrue(sdk.canRenewNow())
    }

    @Test fun sessionUnavailableOnRenewalMeansEnrollAgain() {
        val sdk = renewingClient()
        moving.instant = now.plusSeconds(700)
        server.enqueue(MockResponse().setResponseCode(403).setBody("{\"code\":\"session-unavailable\"}"))
        val error = assertThrows(SentomaruException::class.java) { signedPost("/api/demandas", sdk = sdk) }
        assertEquals("EnrollmentRequired", error.error.code)
        assertEquals(InstallationState.EnrollmentRequired, sdk.state())
        assertEquals("the operation never left unsigned", 1, server.requestCount)
    }
}
