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
import org.junit.After
import org.junit.Assert.*
import org.junit.Before
import org.junit.Test
import java.io.IOException
import java.security.KeyPair
import java.security.KeyPairGenerator
import java.security.KeyStore
import java.security.SecureRandom
import java.security.Signature
import java.security.spec.ECGenParameterSpec
import java.time.Clock
import java.time.Instant
import java.time.ZoneOffset
import java.util.Base64
import java.util.concurrent.Executors
import java.util.concurrent.TimeUnit
import javax.net.ssl.KeyManagerFactory
import javax.net.ssl.SSLContext
import javax.net.ssl.TrustManagerFactory
import javax.net.ssl.X509TrustManager

class OkHttpTransportTest {
    companion object {
        // One test TLS identity for both transports (TransportTestSupport.kt).
        private val sslContext = TestTls.sslContext
        private val trustManager = TestTls.trustManager
    }

    private val ALT_ALLOWED_HOST = "alt.allowed.test"
    private val EXTERNAL_HOST = "external.untrusted.test"
    private val now = Instant.parse("2026-10-09T10:00:00Z")
    private val clock = Clock.fixed(now, ZoneOffset.UTC)
    private val session = "aaaaaaaa-bbbb-4ccc-8ddd-eeeeeeeeeeee"
    private val keyId = "11111111-2222-4333-8444-555555555555"

    private lateinit var server: MockWebServer
    private lateinit var allowedHost: String
    private lateinit var config: SentomaruConfig
    private lateinit var keys: TestJcaKeys
    private lateinit var store: TestStore
    private lateinit var client: SentomaruClient
    private lateinit var okHttpClient: OkHttpClient

    @Before fun setUp() {
        server = MockWebServer()
        server.useHttps(sslContext.socketFactory, false)
        server.start()
        allowedHost = server.hostName

        config = SentomaruConfig(
            organization = "org",
            app = "app",
            environment = "hml",
            allowedHosts = setOf(allowedHost, "localhost", "127.0.0.1", ALT_ALLOWED_HOST),
            enrollmentUrl = "https://$allowedHost:${server.port}/enroll"
        )
        keys = TestJcaKeys()
        store = TestStore()
        client = SentomaruClient(config, keys, store, clock)

        // Enroll client so signing is active
        val challenge = EnrollmentChallenge(
            keyId,
            Base64.getEncoder().encodeToString(ByteArray(32) { 1 }),
            ByteArray(32) { 2 },
            now.plusSeconds(300)
        )
        client.enroll(challenge) {
            EnrollmentGrant(session, keyId, session, "hardware", "verified")
        }

        okHttpClient = OkHttpClient.Builder()
            .sslSocketFactory(sslContext.socketFactory, trustManager)
            .hostnameVerifier { _, _ -> true }
            .addSentomaru(client)
            .build()
    }

    @After fun tearDown() {
        server.shutdown()
    }

    @Test fun signedRequestProducesExactProfileHeadersAndVerifiedSignature() {
        server.enqueue(MockResponse().setResponseCode(200).setBody("{\"status\":\"ok\"}"))

        val url = "https://$allowedHost:${server.port}/api/v1/inspections"
        val bodyContent = "{\"field\":\"value\"}"
        val request = Request.Builder()
            .url(url)
            .header("x-sentomaru-operation", "submit")
            .header("content-type", "application/json")
            .post(bodyContent.toRequestBody("application/json".toMediaType()))
            .build()

        val response = okHttpClient.newCall(request).execute()
        assertEquals(200, response.code)

        val recorded = server.takeRequest()
        assertEquals("POST", recorded.method)
        assertEquals("/api/v1/inspections", recorded.path)
        assertEquals(bodyContent, recorded.body.readUtf8())
        assertEquals("sentomaru-p0", recorded.getHeader("x-sentomaru-profile"))
        assertEquals("org", recorded.getHeader("x-sentomaru-org"))
        assertEquals("app", recorded.getHeader("x-sentomaru-app"))
        assertEquals("hml", recorded.getHeader("x-sentomaru-environment"))
        assertEquals(session, recorded.getHeader("x-sentomaru-session"))
        assertEquals("submit", recorded.getHeader("x-sentomaru-operation"))
        assertEquals("application/json", recorded.getHeader("content-type"))
        assertNotNull(recorded.getHeader("content-digest"))
        assertNotNull(recorded.getHeader("signature-input"))
        assertNotNull(recorded.getHeader("signature"))

        // Reconstruct and verify signature base
        val sigInput = recorded.getHeader("signature-input")!!
        val signature = recorded.getHeader("signature")!!
        val callerHeaders = Profile.CALLER_HEADERS.associateWith { recorded.getHeader(it)!! }
        val digest = recorded.getHeader("content-digest")!!
        val created = sigInput.substringAfter("created=").substringBefore(";").toLong()
        val expires = sigInput.substringAfter("expires=").substringBefore(";").toLong()
        val nonce = sigInput.substringAfter("nonce=\"").substringBefore("\"")
        val kid = sigInput.substringAfter("keyid=\"").substringBefore("\"")
        val sigParams = SignatureParams(created, expires, nonce, kid)
        val base = SignatureBase.build("POST", url, callerHeaders, digest, sigParams)
        assertTrue("Signature must verify with active installation key",
            keys.verify(store.record!!.alias, base, signature))
    }

    @Test fun requestTagCanDeclareOperation() {
        server.enqueue(MockResponse().setResponseCode(200))
        val url = "https://$allowedHost:${server.port}/api/tagged"
        val request = Request.Builder()
            .url(url)
            .tag(SentomaruOperation::class.java, SentomaruOperation("upload"))
            .post("{}".toRequestBody("application/json".toMediaType()))
            .build()

        val response = okHttpClient.newCall(request).execute()
        assertEquals(200, response.code)

        val recorded = server.takeRequest()
        assertEquals("upload", recorded.getHeader("x-sentomaru-operation"))
        assertNotNull(recorded.getHeader("signature"))
    }

    @Test fun requestWithoutOperationProceedsUnsigned() {
        server.enqueue(MockResponse().setResponseCode(200))
        val url = "https://$allowedHost:${server.port}/public/health"
        val request = Request.Builder().url(url).get().build()

        val response = okHttpClient.newCall(request).execute()
        assertEquals(200, response.code)

        val recorded = server.takeRequest()
        assertNull(recorded.getHeader("x-sentomaru-operation"))
        assertNull(recorded.getHeader("signature"))
    }

    private fun clientFor(allowed: Set<String>): OkHttpClient = OkHttpClient.Builder()
        .sslSocketFactory(sslContext.socketFactory, trustManager)
        .hostnameVerifier { _, _ -> true }
        .addSentomaru(SentomaruClient(SentomaruConfig("org", "app", "hml", allowed, "https://${allowed.first()}/enroll"),
            keys, TestStore(), clock))
        .build()

    @Test fun hostOutsideAllowlistPassesUndeclaredRequestUnsignedAndStripsLeakedHeaders() {
        server.enqueue(MockResponse().setResponseCode(200))
        val request = Request.Builder()
            .url("https://$allowedHost:${server.port}/external") // allowedHost is not in other.example
            .header("signature", "sig1=:leaked:")
            .header("x-sentomaru-session", "leaked")
            .get()
            .build()

        clientFor(setOf("other.example")).newCall(request).execute().use { assertEquals(200, it.code) }

        val recorded = server.takeRequest()
        assertNull(recorded.getHeader("x-sentomaru-session"))
        assertNull(recorded.getHeader("signature"))
    }

    @Test fun declaredOperationToHostOutsideAllowlistIsRefusedNotSentUnsigned() {
        val request = Request.Builder()
            .url("https://$allowedHost:${server.port}/external")
            .header("x-sentomaru-operation", "submit")
            .post("{}".toRequestBody("application/json".toMediaType()))
            .build()
        val error = assertThrows(SentomaruException::class.java) {
            clientFor(setOf("other.example")).newCall(request).execute()
        }
        assertEquals("HostNotAllowed", error.error.code)
        assertEquals(0, server.requestCount)
    }

    @Test fun interceptorCannotBeInstalledRawOnlyViaAddSentomaru() {
        assertEquals("no public constructor: a raw addInterceptor(...) would leave OkHttp redirects on",
            0, SentomaruInterceptor::class.java.constructors.count { !it.isSynthetic })
    }

    @Test fun reEnabledOkHttpRedirectsAfterAddSentomaruNeverLeakOrSucceed() {
        val external = MockWebServer()
        external.useHttps(sslContext.socketFactory, false)
        external.start()
        try {
            val reEnabled = redirectClient(external).newBuilder().followRedirects(true).followSslRedirects(true).build()

            server.enqueue(MockResponse().setResponseCode(307).addHeader("Location", "https://$EXTERNAL_HOST:${external.port}/x"))
            assertEquals("HostNotAllowed", assertThrows(SentomaruException::class.java) {
                reEnabled.newCall(signedPost("/a")).execute()
            }.error.code)
            assertEquals(0, external.requestCount)

            server.enqueue(MockResponse().setResponseCode(307).addHeader("Location", "http://$allowedHost:${server.port}/plain"))
            assertEquals("HostNotAllowed", assertThrows(SentomaruException::class.java) {
                reEnabled.newCall(signedPost("/b")).execute()
            }.error.code)

            // Allowed https target followed by OkHttp itself (stale signature): refused, not returned as success.
            server.enqueue(MockResponse().setResponseCode(307).addHeader("Location", "/c"))
            server.enqueue(MockResponse().setResponseCode(200))
            assertEquals("HostNotAllowed", assertThrows(SentomaruException::class.java) {
                reEnabled.newCall(signedPost("/c0")).execute()
            }.error.code)
        } finally {
            external.shutdown()
        }
    }

    @Test fun insecureHttpOnAllowedHostIsRefused() {
        val request = Request.Builder()
            .url("http://$allowedHost:${server.port}/insecure")
            .header("x-sentomaru-operation", "submit")
            .post("{}".toRequestBody("application/json".toMediaType()))
            .build()

        val error = assertThrows(SentomaruException::class.java) {
            okHttpClient.newCall(request).execute()
        }
        assertEquals("HostNotAllowed", error.error.code)
    }

    @Test fun invalidContentTypeParametersAreRefused() {
        val url = "https://$allowedHost:${server.port}/api/test"
        val request = Request.Builder()
            .url(url)
            .header("x-sentomaru-operation", "submit")
            .header("content-type", "application/json; charset=utf-8")
            .post("{}".toRequestBody("application/json; charset=utf-8".toMediaType()))
            .build()

        val error = assertThrows(SentomaruException::class.java) {
            okHttpClient.newCall(request).execute()
        }
        assertEquals("InvalidRequest:HEADER_VALUE", error.error.code)
    }

    @Test fun bodyExceeding64KiBIsRefused() {
        val url = "https://$allowedHost:${server.port}/api/large"
        val largeBytes = ByteArray(65537) { 42 }
        val request = Request.Builder()
            .url(url)
            .header("x-sentomaru-operation", "submit")
            .post(largeBytes.toRequestBody("application/json".toMediaType()))
            .build()

        val error = assertThrows(SentomaruException::class.java) {
            okHttpClient.newCall(request).execute()
        }
        assertEquals("BodyTooLarge", error.error.code)
    }

    @Test fun redirect307OnAllowedHostReSignsForNewTargetUri() {
        val originalPath = "/api/v1/source"
        val targetPath = "/api/v1/destination"
        val targetUrl = "https://$allowedHost:${server.port}$targetPath"

        server.enqueue(MockResponse().setResponseCode(307).addHeader("Location", targetUrl))
        server.enqueue(MockResponse().setResponseCode(200).setBody("{\"redirected\":true}"))

        val request = Request.Builder()
            .url("https://$allowedHost:${server.port}$originalPath")
            .header("x-sentomaru-operation", "move")
            .post("{\"id\":1}".toRequestBody("application/json".toMediaType()))
            .build()

        val response = okHttpClient.newCall(request).execute()
        assertEquals(200, response.code)

        val first = server.takeRequest()
        assertEquals(originalPath, first.path)
        val sig1 = first.getHeader("signature")!!

        val second = server.takeRequest()
        assertEquals(targetPath, second.path)
        val sig2 = second.getHeader("signature")!!

        assertNotEquals("307 redirect must generate fresh signature for new target URI", sig1, sig2)
        assertEquals("{\"id\":1}", second.body.readUtf8())
    }

    /** OkHttp client whose DNS maps the synthetic hosts used by redirect tests onto [target]'s loopback address. */
    private fun redirectClient(target: MockWebServer): OkHttpClient = okHttpClient.newBuilder()
        .dns(object : okhttp3.Dns {
            override fun lookup(hostname: String): List<java.net.InetAddress> =
                if (hostname == EXTERNAL_HOST || hostname == ALT_ALLOWED_HOST) listOf(java.net.InetAddress.getByName(target.hostName))
                else okhttp3.Dns.SYSTEM.lookup(hostname)
        })
        .build()

    private fun signedPost(path: String, body: String = "{\"id\":1}"): Request = Request.Builder()
        .url("https://$allowedHost:${server.port}$path")
        .header("x-sentomaru-operation", "submit")
        .header("Authorization", "Bearer user-token")
        .header("Cookie", "session=user-cookie")
        .post(body.toRequestBody("application/json".toMediaType()))
        .build()

    private fun assertNoSentomaruOrSignatureHeaders(recorded: okhttp3.mockwebserver.RecordedRequest) {
        for (name in Profile.CALLER_HEADERS.filter { it.startsWith("x-sentomaru-") } +
            listOf("content-digest", "signature", "signature-input", "x-sentomaru-signals")) {
            assertNull("$name must not be forwarded", recorded.getHeader(name))
        }
    }

    @Test fun redirectOutsideAllowlistIsNotFollowedSoNothingLeaks() {
        for (code in listOf(301, 302, 303, 307, 308)) {
            val external = MockWebServer()
            external.useHttps(sslContext.socketFactory, false)
            external.start()
            try {
                server.enqueue(MockResponse().setResponseCode(code)
                    .addHeader("Location", "https://$EXTERNAL_HOST:${external.port}/landing"))
                external.enqueue(MockResponse().setResponseCode(200))

                redirectClient(external).newCall(signedPost("/redirect-out")).execute().use { response ->
                    assertEquals("off-allowlist $code is returned to the caller, not followed", code, response.code)
                }
                server.takeRequest()
                assertEquals("no request (method, body, signature, Authorization, Cookie) reaches the external host",
                    0, external.requestCount)
            } finally {
                external.shutdown()
            }
        }
    }

    @Test fun redirectDowngradeToHttpOnAllowedHostIsRefusedBeforeSending() {
        server.enqueue(MockResponse().setResponseCode(302).addHeader("Location", "http://$allowedHost:${server.port}/plain"))
        val error = assertThrows(SentomaruException::class.java) {
            okHttpClient.newCall(signedPost("/downgrade")).execute()
        }
        assertEquals("HostNotAllowed", error.error.code)
        assertEquals(1, server.requestCount)
    }

    @Test fun redirect303OnAllowedHostBecomesUnsignedGetWithoutBody() {
        for (code in listOf(301, 302, 303)) {
            server.enqueue(MockResponse().setResponseCode(code).addHeader("Location", "/api/v1/result-$code"))
            server.enqueue(MockResponse().setResponseCode(200))

            okHttpClient.newCall(signedPost("/api/v1/submit-$code")).execute().use { assertEquals(200, it.code) }

            val first = server.takeRequest()
            assertEquals("POST", first.method)
            assertNotNull(first.getHeader("signature"))

            val second = server.takeRequest()
            assertEquals("https", second.requestUrl!!.scheme)
            assertEquals("/api/v1/result-$code", second.path)
            assertEquals("$code converts to GET", "GET", second.method)
            assertEquals("body dropped on $code", 0L, second.bodySize)
            assertNull(second.getHeader("content-type"))
            assertNoSentomaruOrSignatureHeaders(second)
            assertEquals("same-host hop keeps caller credentials", "Bearer user-token", second.getHeader("Authorization"))
        }
    }

    @Test fun redirect307ToOtherAllowedHostReSignsAndDropsCallerCredentials() {
        val alt = MockWebServer()
        alt.useHttps(sslContext.socketFactory, false)
        alt.start()
        try {
            val target = "https://$ALT_ALLOWED_HOST:${alt.port}/api/v1/moved?x=1"
            server.enqueue(MockResponse().setResponseCode(307).addHeader("Location", target))
            alt.enqueue(MockResponse().setResponseCode(200))

            redirectClient(alt).newCall(signedPost("/api/v1/source", "{\"id\":7}")).execute().use { assertEquals(200, it.code) }

            val first = server.takeRequest()
            val second = alt.takeRequest()
            assertEquals("https", second.requestUrl!!.scheme)
            assertEquals("POST", second.method)
            assertEquals("{\"id\":7}", second.body.readUtf8())
            assertNotEquals(first.getHeader("signature"), second.getHeader("signature"))
            assertNull("Authorization never crosses hosts", second.getHeader("Authorization"))
            assertNull("Cookie never crosses hosts", second.getHeader("Cookie"))

            val sigInput = second.getHeader("signature-input")!!
            val params = SignatureParams(
                sigInput.substringAfter("created=").substringBefore(";").toLong(),
                sigInput.substringAfter("expires=").substringBefore(";").toLong(),
                sigInput.substringAfter("nonce=\"").substringBefore("\""),
                sigInput.substringAfter("keyid=\"").substringBefore("\""),
            )
            val base = SignatureBase.build("POST", target,
                Profile.CALLER_HEADERS.associateWith { second.getHeader(it)!! }, second.getHeader("content-digest")!!, params)
            assertTrue("second hop is signed for its own @target-uri",
                keys.verify(store.record!!.alias, base, second.getHeader("signature")!!))
        } finally {
            alt.shutdown()
        }
    }

    @Test fun redirectChainTracksStatePerHopAndNeverResurrectsPost() {
        server.enqueue(MockResponse().setResponseCode(303).addHeader("Location", "/b/hop"))
        server.enqueue(MockResponse().setResponseCode(307).addHeader("Location", "c"))
        server.enqueue(MockResponse().setResponseCode(200))

        okHttpClient.newCall(signedPost("/a/start")).execute().use { assertEquals(200, it.code) }

        assertEquals("POST", server.takeRequest().method)
        val second = server.takeRequest()
        assertEquals("GET", second.method)
        val third = server.takeRequest()
        assertEquals("Location resolves against the current hop, not the original URL", "/b/c", third.path)
        assertEquals("307 after a 303 keeps GET; the original POST is never re-sent", "GET", third.method)
        assertEquals(0L, third.bodySize)
        assertNoSentomaruOrSignatureHeaders(third)
    }

    @Test fun crossHostRedirectWithinAllowlistDropsAuthorizationAndCookie() {
        for (code in listOf(301, 302, 307, 308)) {
            val alt = MockWebServer()
            alt.useHttps(sslContext.socketFactory, false)
            alt.start()
            try {
                server.enqueue(MockResponse().setResponseCode(code).addHeader("Location", "https://$ALT_ALLOWED_HOST:${alt.port}/n"))
                alt.enqueue(MockResponse().setResponseCode(200))
                redirectClient(alt).newCall(signedPost("/x$code")).execute().use { assertEquals(200, it.code) }
                server.takeRequest()
                val second = alt.takeRequest()
                assertEquals("https", second.requestUrl!!.scheme)
                assertNull("$code: Authorization dropped cross-host", second.getHeader("Authorization"))
                assertNull("$code: Cookie dropped cross-host", second.getHeader("Cookie"))
                assertEquals(if (code >= 307) "POST" else "GET", second.method)
            } finally {
                alt.shutdown()
            }
        }
    }

    @Test fun redirect307DowngradeToHttpIsRefused() {
        server.enqueue(MockResponse().setResponseCode(307).addHeader("Location", "http://$allowedHost:${server.port}/plain"))
        assertEquals("HostNotAllowed", assertThrows(SentomaruException::class.java) {
            okHttpClient.newCall(signedPost("/d307")).execute()
        }.error.code)
        assertEquals(1, server.requestCount)
    }

    @Test fun hopLimitIsFiveLikeDio() {
        repeat(SentomaruInterceptor.MAX_REDIRECTS + 1) {
            server.enqueue(MockResponse().setResponseCode(302).addHeader("Location", "/loop$it"))
        }
        okHttpClient.newCall(signedPost("/loop")).execute().use {
            assertEquals("after 5 follows the last 3xx is returned", 302, it.code)
        }
        assertEquals(5, SentomaruInterceptor.MAX_REDIRECTS)
        assertEquals(6, server.requestCount)
    }

    @Test fun passThroughToOffAllowlistHostKeepsCallerContentType() {
        server.enqueue(MockResponse().setResponseCode(200))
        val externalConfig = SentomaruConfig("org", "app", "hml", setOf("other.example"), "https://other.example/enroll")
        val unmanagedClient = OkHttpClient.Builder()
            .sslSocketFactory(sslContext.socketFactory, trustManager)
            .hostnameVerifier { _, _ -> true }
            .addSentomaru(SentomaruClient(externalConfig, keys, TestStore(), clock))
            .build()
        val request = Request.Builder()
            .url("https://$allowedHost:${server.port}/third-party")
            .header("content-type", "text/csv")
            .header("x-sentomaru-session", "leak")
            .post("a,b".toByteArray().toRequestBody(null)) // header is the only content-type source
            .build()
        unmanagedClient.newCall(request).execute().use { assertEquals(200, it.code) }
        val recorded = server.takeRequest()
        assertEquals("text/csv", recorded.getHeader("content-type"))
        assertNull(recorded.getHeader("x-sentomaru-session"))
    }

    /**
     * A caller-level retry of the same request is re-signed with a fresh nonce (no 409 replay). Without an
     * `x-sentomaru-operation-id` from the caller this is NOT idempotent (see operationIdIsSigned… below, J-01f2).
     */
    @Test fun callerRetryOfSameRequestIsReSignedWithFreshNonce() {
        server.enqueue(MockResponse().setResponseCode(503))
        server.enqueue(MockResponse().setResponseCode(200))

        val url = "https://$allowedHost:${server.port}/api/idempotent"
        val request = Request.Builder()
            .url(url)
            .header("x-sentomaru-operation", "charge")
            .post("{}".toRequestBody("application/json".toMediaType()))
            .build()

        val resp1 = okHttpClient.newCall(request).execute()
        assertEquals(503, resp1.code)

        val resp2 = okHttpClient.newCall(request).execute()
        assertEquals(200, resp2.code)

        val req1 = server.takeRequest()
        val req2 = server.takeRequest()

        assertFalse("no operation id unless the caller sets one",
            req1.getHeader("signature-input")!!.contains("operation-id"))

        val nonce1 = req1.getHeader("signature-input")!!.substringAfter("nonce=\"").substringBefore("\"")
        val nonce2 = req2.getHeader("signature-input")!!.substringAfter("nonce=\"").substringBefore("\"")
        assertNotEquals("Retry must generate fresh nonce to prevent 409 replay rejection", nonce1, nonce2)
    }

    @Test fun concurrentRequestsMaintainIndependentSignatures() {
        val pool = Executors.newFixedThreadPool(4)
        val count = 8
        repeat(count) {
            server.enqueue(MockResponse().setResponseCode(200))
        }

        val nonces = java.util.concurrent.ConcurrentHashMap.newKeySet<String>()
        val futures = (0 until count).map { index ->
            pool.submit {
                val req = Request.Builder()
                    .url("https://$allowedHost:${server.port}/api/concurrent/$index")
                    .header("x-sentomaru-operation", "op-$index")
                    .post("{}".toRequestBody("application/json".toMediaType()))
                    .build()
                val resp = okHttpClient.newCall(req).execute()
                assertEquals(200, resp.code)
            }
        }
        futures.forEach { it.get(10, TimeUnit.SECONDS) }
        pool.shutdown()

        repeat(count) {
            val req = server.takeRequest()
            val nonce = req.getHeader("signature-input")!!.substringAfter("nonce=\"").substringBefore("\"")
            assertTrue("Nonce must be unique across concurrent requests", nonces.add(nonce))
        }
    }

    @Test fun unenrolledClientFailsWithTypedError() {
        client.reset()
        val request = Request.Builder()
            .url("https://$allowedHost:${server.port}/api/fail")
            .header("x-sentomaru-operation", "submit")
            .post("{}".toRequestBody("application/json".toMediaType()))
            .build()

        val error = assertThrows(SentomaruException::class.java) {
            okHttpClient.newCall(request).execute()
        }
        assertEquals("NotEnrolled", error.error.code)
    }

    @Test fun signalsAttachedViaSentomaruOperationTagArePropagatedInHeader() {
        server.enqueue(MockResponse().setResponseCode(200).setBody("{\"status\":\"ok\"}"))

        val snapshot = SignalsSnapshot(
            catalogVersion = "1.0.0",
            collectedAt = "2026-10-09T10:00:00Z",
            durationMs = 25,
            observations = listOf(
                SignalObservation(
                    capabilityId = "root_indicated",
                    version = "1.0.0",
                    state = SignalState.NOT_DETECTED,
                    observedAt = "2026-10-09T10:00:00Z"
                )
            )
        )

        val request = Request.Builder()
            .url("https://$allowedHost:${server.port}/api/signals")
            .tag(SentomaruOperation::class.java, SentomaruOperation("submit", signals = snapshot))
            .post("{}".toRequestBody("application/json".toMediaType()))
            .build()

        okHttpClient.newCall(request).execute().use { response ->
            assertTrue(response.isSuccessful)
        }

        val recorded = server.takeRequest()
        val signalsHeader = recorded.getHeader("x-sentomaru-signals")
        assertNotNull(signalsHeader)
        assertTrue(signalsHeader!!.contains("\"catalogVersion\":\"1.0.0\""))
        assertTrue(signalsHeader.contains("\"root_indicated\""))
        assertTrue(signalsHeader.contains("\"NOT_DETECTED\""))
        // H3 (J-01f2): the snapshot is a covered component, signed after the base list (never added after signing).
        assertTrue(recorded.getHeader("signature-input")!!.contains("\"x-sentomaru-operation\" \"x-sentomaru-signals\")"))
    }

    /** J-01f2 (SDK-NET-4, RETRY-01): the caller's operation id is signed; a retry re-signs it with a fresh nonce. */
    @Test fun operationIdIsSignedAndKeptAcrossRetriesWithFreshNonces() {
        server.enqueue(MockResponse().setResponseCode(503))
        server.enqueue(MockResponse().setResponseCode(200))
        val request = Request.Builder()
            .url("https://$allowedHost:${server.port}/api/charge")
            .header("x-sentomaru-operation", "charge")
            .header("x-sentomaru-operation-id", "op-0123456789abcdef")
            .post("{}".toRequestBody("application/json".toMediaType()))
            .build()
        assertEquals(503, okHttpClient.newCall(request).execute().code)
        assertEquals(200, okHttpClient.newCall(request).execute().code)
        val first = server.takeRequest()
        val second = server.takeRequest()
        for (recorded in listOf(first, second)) {
            assertEquals("op-0123456789abcdef", recorded.getHeader("x-sentomaru-operation-id"))
            assertTrue(recorded.getHeader("signature-input")!!.contains("\"x-sentomaru-operation\" \"x-sentomaru-operation-id\")"))
        }
        assertNotEquals(first.getHeader("signature-input")!!.substringAfter("nonce=\"").substringBefore("\""),
            second.getHeader("signature-input")!!.substringAfter("nonce=\"").substringBefore("\""))
    }

    @Test fun malformedOperationIdIsRefusedBeforeSending() {
        val request = Request.Builder()
            .url("https://$allowedHost:${server.port}/api/charge")
            .header("x-sentomaru-operation", "charge")
            .header("x-sentomaru-operation-id", "short")
            .post("{}".toRequestBody("application/json".toMediaType()))
            .build()
        try {
            okHttpClient.newCall(request).execute().close()
            fail("malformed operation id was sent")
        } catch (e: SentomaruException) {
            assertEquals("InvalidRequest:HEADER_VALUE", e.error.code)
        }
        assertEquals(0, server.requestCount)
    }

    // ---- G-03c: the route table of addSentomaru(client, routes) (profile network-signing section)

    private fun routedClient(routes: SentomaruRoutes): OkHttpClient = OkHttpClient.Builder()
        .sslSocketFactory(sslContext.socketFactory, trustManager)
        .hostnameVerifier { _, _ -> true }
        .addSentomaru(client, routes)
        .build()

    private fun routes(vararg hosts: String = arrayOf(allowedHost)) = SentomaruRoutes.of(hosts.toList(),
        listOf(SentomaruRoutes.Route("/v1/demandas/*/concluir", "concluir_demanda")))

    @Test fun aRequestOnAProfileRouteIsSignedWithoutBeingTagged() {
        server.enqueue(MockResponse().setResponseCode(200))
        val request = Request.Builder().url("https://$allowedHost:${server.port}/V1/demandas/42/concluir/")
            .post("{\"ok\":true}".toRequestBody("application/json".toMediaType())).build()
        assertEquals(200, routedClient(routes()).newCall(request).execute().code)
        val recorded = server.takeRequest()
        assertEquals("concluir_demanda", recorded.getHeader("x-sentomaru-operation"))
        assertNotNull(recorded.getHeader("signature"))
        assertNotNull(recorded.getHeader("content-digest"))
    }

    @Test fun aDeclaredOperationWinsAndAnUncoveredPathPassesUnsigned() {
        server.enqueue(MockResponse().setResponseCode(200))
        server.enqueue(MockResponse().setResponseCode(200))
        val http = routedClient(routes())
        http.newCall(Request.Builder().url("https://$allowedHost:${server.port}/v1/demandas/42/concluir")
            .header("x-sentomaru-operation", "submit")
            .post("{}".toRequestBody("application/json".toMediaType())).build()).execute().close()
        assertEquals("submit", server.takeRequest().getHeader("x-sentomaru-operation"))
        // One segment more than the route, and a `*` never matches an empty segment: not covered, sent unsigned.
        http.newCall(Request.Builder().url("https://$allowedHost:${server.port}/v1/demandas/42/concluir/extra").build()).execute().close()
        assertNoSentomaruOrSignatureHeaders(server.takeRequest())
    }

    @Test fun aRouteOnAHostOutsideTheAllowlistIsRefusedAtInstallation() {
        val offList = SentomaruClient(SentomaruConfig("org", "app", "hml", setOf("other.example"), "https://other.example/enroll"),
            keys, TestStore(), clock)
        val error = assertThrows(IllegalArgumentException::class.java) { OkHttpClient.Builder().addSentomaru(offList, routes()) }
        assertEquals("network-signing.hosts not within allowedHosts", error.message)
    }

    @Test fun aRouteHostWithATrailingDotIsCoveredAndFailsClosed() {
        // `localhost.` is the same host for DNS; the table covers it, the allowlist (exact names) refuses it: never unsigned.
        val dotted = Request.Builder().url("https://$allowedHost.:${server.port}/v1/demandas/1/concluir")
            .post("{}".toRequestBody("application/json".toMediaType())).build()
        val error = assertThrows(SentomaruException::class.java) { routedClient(routes()).newCall(dotted).execute() }
        assertEquals("HostNotAllowed", error.error.code)
        assertEquals(0, server.requestCount)
    }

    @Test fun aPercentEncodedRoutePathIsCoveredAndNeverSentUnsigned() {
        // `%64emandas` decodes to the route (the table compares decoded, as the server routes): the request is the
        // protected operation, and the core refuses its non-canonical target URI. Refused, never sent unsigned.
        val request = Request.Builder().url("https://$allowedHost:${server.port}/v1/%64emandas/42/concluir")
            .post("{}".toRequestBody("application/json".toMediaType())).build()
        val error = assertThrows(SentomaruException::class.java) { routedClient(routes()).newCall(request).execute() }
        assertEquals("InvalidRequest:TARGET_URI", error.error.code)
        assertEquals(0, server.requestCount)
    }

    // ---- J-04r: signed grant renewal ----

    private class MovingClock(var instant: Instant) : Clock() {
        override fun getZone() = ZoneOffset.UTC
        override fun withZone(zone: java.time.ZoneId?) = this
        override fun instant() = instant
    }

    private val renewedSession = "bbbbbbbb-cccc-4ddd-8eee-ffffffffffff"
    private lateinit var moving: MovingClock
    private lateinit var renewingStore: TestStore
    private lateinit var renewingKeys: TestJcaKeys

    private fun renewingClient(renewal: Boolean = true): Pair<SentomaruClient, OkHttpClient> {
        moving = MovingClock(now)
        renewingStore = TestStore()
        renewingKeys = TestJcaKeys()
        val cfg = SentomaruConfig("org", "app", "hml", setOf(allowedHost), "https://$allowedHost:${server.port}/enroll",
            renewalUrl = if (renewal) "https://$allowedHost:${server.port}/sessions" else null)
        val sdk = SentomaruClient(cfg, renewingKeys, renewingStore, moving)
        sdk.enroll(EnrollmentChallenge(keyId, Base64.getEncoder().encodeToString(ByteArray(32) { 1 }), ByteArray(32) { 2 },
            now.plusSeconds(300))) { EnrollmentGrant(session, keyId, session, "hardware", "verified") }
        val http = OkHttpClient.Builder().sslSocketFactory(sslContext.socketFactory, trustManager)
            .hostnameVerifier { _, _ -> true }.addSentomaru(sdk).build()
        return sdk to http
    }

    private fun renewal(sessionId: String = renewedSession, ttl: Int = 600) = MockResponse().setResponseCode(200)
        .setBody("{\"installationId\":\"$session\",\"keyId\":\"$keyId\",\"sessionId\":\"$sessionId\"," +
            "\"expiresAt\":\"2026-10-09T10:20:00+00:00\",\"ttlSeconds\":$ttl}")

    private fun business(http: OkHttpClient) = http.newCall(signedPost("/api/demandas")).execute()

    @Test fun aFreshGrantIsNotRenewedAndTheEnrollmentGrantIsStamped() {
        val (sdk, http) = renewingClient()
        server.enqueue(MockResponse().setResponseCode(200))
        assertEquals(200, business(http).code)
        assertEquals(1, server.requestCount)
        assertEquals(now, renewingStore.record!!.grant!!.issuedAt)
        assertFalse(sdk.needsRenewal())
    }

    @Test fun aGrantNearItsLifetimeIsRenewedWithASignedRequestBeforeTheOperation() {
        val (sdk, http) = renewingClient()
        moving.instant = now.plusSeconds(EnrollmentGrant.DEFAULT_TTL_SECONDS - 119) // inside the 120 s margin
        assertTrue(sdk.needsRenewal())
        server.enqueue(renewal())
        server.enqueue(MockResponse().setResponseCode(200))
        assertEquals(200, business(http).code)

        val renew = server.takeRequest()
        assertEquals(("POST" to "/sessions"), renew.method to renew.path)
        assertEquals((session to "session_renew"),
            renew.getHeader("x-sentomaru-session") to renew.getHeader("x-sentomaru-operation"))
        assertEquals("{}", renew.body.readUtf8())
        val sigInput = renew.getHeader("signature-input")!!
        val params = SignatureParams(sigInput.substringAfter("created=").substringBefore(";").toLong(),
            sigInput.substringAfter("expires=").substringBefore(";").toLong(),
            sigInput.substringAfter("nonce=\"").substringBefore("\""), sigInput.substringAfter("keyid=\"").substringBefore("\""))
        val base = SignatureBase.build("POST", "https://$allowedHost:${server.port}/sessions",
            Profile.CALLER_HEADERS.associateWith { renew.getHeader(it)!! }, renew.getHeader("content-digest")!!, params)
        assertTrue(renewingKeys.verify(renewingStore.record!!.alias, base, renew.getHeader("signature")!!))

        val operation = server.takeRequest()
        assertEquals(renewedSession, operation.getHeader("x-sentomaru-session"))
        assertEquals((moving.instant to 600L), renewingStore.record!!.grant!!.let { it.issuedAt to it.ttlSeconds })
        assertFalse(sdk.needsRenewal())
    }

    @Test fun aFailedRenewalKeepsTheGrantSendsTheOperationAndBacksOff() {
        val (sdk, http) = renewingClient()
        moving.instant = now.plusSeconds(700)
        server.enqueue(MockResponse().setResponseCode(503).setBody("{\"code\":\"store-unavailable\"}"))
        server.enqueue(MockResponse().setResponseCode(200))
        assertEquals(200, business(http).code)
        server.takeRequest()
        assertEquals(session, server.takeRequest().getHeader("x-sentomaru-session"))
        assertFalse(sdk.needsRenewal()) // 60 s backoff
        server.enqueue(MockResponse().setResponseCode(200))
        assertEquals(200, business(http).code)
        assertEquals(3, server.requestCount) // no renewal attempt inside the backoff
        moving.instant = moving.instant.plusSeconds(61)
        assertTrue(sdk.needsRenewal())
    }

    @Test fun sessionExpiredFromTheConsumerRenewsOnceAndResendsOnceNeverLooping() {
        val (_, http) = renewingClient()
        val expired = MockResponse().setResponseCode(403).setBody("{\"code\":\"session-expired\"}")
        server.enqueue(expired)
        server.enqueue(renewal())
        server.enqueue(MockResponse().setResponseCode(403).setBody("{\"code\":\"session-expired\"}"))
        val response = business(http)
        assertEquals(403, response.code) // the second refusal goes back to the caller
        assertEquals("{\"code\":\"session-expired\"}", response.body!!.string())
        assertEquals(session, server.takeRequest().getHeader("x-sentomaru-session"))
        assertEquals("/sessions", server.takeRequest().path)
        val resent = server.takeRequest()
        assertEquals(renewedSession, resent.getHeader("x-sentomaru-session"))
        assertEquals(3, server.requestCount)
    }

    @Test fun withoutARenewalUrlNothingChanges() {
        val (sdk, http) = renewingClient(renewal = false)
        moving.instant = now.plusSeconds(3600)
        assertFalse(sdk.needsRenewal())
        server.enqueue(MockResponse().setResponseCode(403).setBody("{\"code\":\"session-expired\"}"))
        assertEquals(403, business(http).code)
        assertEquals(1, server.requestCount)
    }

    @Test fun aRecordFromBeforeJ04rHasNoIssuedAtAndRenewsAtOnce() {
        val (sdk, _) = renewingClient()
        val record = renewingStore.record!!
        val old = record.grant!!
        renewingStore.record = InstallationRecord(record.scopeIdentity, record.alias, record.challenge, record.strongBox,
            record.body(), EnrollmentGrant(old.installationId, old.keyId, old.sessionId, old.hardwareStatus, old.attestationStatus),
            record.requiresHardware, record.generation, record.retiredKeys, record.pendingRotation)
        assertTrue(sdk.needsRenewal())
    }

    @Test fun aRenewalAnswerForAnotherKeyOrMalformedIsRefusedAndTheGrantKept() {
        val (sdk, _) = renewingClient()
        val other = "99999999-2222-4333-8444-555555555555"
        val error = assertThrows(SentomaruException::class.java) {
            sdk.renew { RenewedGrant(session, other, renewedSession, 600) }
        }
        assertEquals("InvalidRequest:PARAMS", error.error.code)
        assertEquals(session, renewingStore.record!!.grant!!.sessionId)
        for (bad in listOf("{}", "{\"installationId\":\"$session\",\"keyId\":\"$keyId\",\"sessionId\":\"$renewedSession\",\"ttlSeconds\":0}",
                "{\"installationId\":\"x\",\"keyId\":\"$keyId\",\"sessionId\":\"$renewedSession\",\"ttlSeconds\":600}"))
            assertThrows(SentomaruException::class.java) { SentomaruInterceptor.parseRenewal(bad) }
    }

    // Contract v1.5: a suspended installation waits (grant kept, short backoff, no re-enrollment) and the caller can
    // tell the suspension apart from a generic refusal by its code. Once the operator releases it, the user's retry
    // renews after SUSPENDED_RENEWAL_BACKOFF (5 s), not after the generic 60 s.
    @Test fun aSuspendedRenewalKeepsTheGrantBacksOffFiveSecondsThenRenews() {
        val (sdk, _) = renewingClient()
        moving.instant = now.plusSeconds(700)
        val failedAt = moving.instant
        val error = assertThrows(SentomaruException::class.java) {
            sdk.renew { throw SentomaruException(EnrollmentError.ServerRejected(EnrollmentError.Rejection.SUSPENDED)) }
        }
        assertEquals("ServerRejected:SUSPENDED", error.error.code)
        assertEquals(InstallationState.Enrolled, sdk.state())
        assertEquals(session, renewingStore.record!!.grant!!.sessionId)
        assertEquals(java.time.Duration.ofSeconds(5), SentomaruClient.SUSPENDED_RENEWAL_BACKOFF)
        moving.instant = failedAt.plusSeconds(4)
        assertFalse(sdk.canRenewNow()) // 5 s backoff
        assertTrue(sdk.renewalBackingOff())
        assertFalse(sdk.needsRenewal())
        moving.instant = failedAt.plus(SentomaruClient.SUSPENDED_RENEWAL_BACKOFF)
        assertTrue(sdk.canRenewNow())
        assertFalse(sdk.renewalBackingOff())
        val renewed = sdk.renew { RenewedGrant(session, keyId, renewedSession, 600) } // released: accepted
        assertEquals(renewedSession, renewed.sessionId)
        assertEquals(renewedSession, renewingStore.record!!.grant!!.sessionId)
        assertFalse(sdk.renewalBackingOff())
    }

    @Test fun aGenericRenewalFailureStillBacksOffSixtySeconds() {
        val (sdk, _) = renewingClient()
        moving.instant = now.plusSeconds(700)
        val failedAt = moving.instant
        assertThrows(SentomaruException::class.java) {
            sdk.renew { throw SentomaruException(EnrollmentError.ServerRejected(EnrollmentError.Rejection.UNAVAILABLE)) }
        }
        moving.instant = failedAt.plus(SentomaruClient.SUSPENDED_RENEWAL_BACKOFF)
        assertFalse(sdk.canRenewNow()) // not the short suspension backoff
        assertTrue(sdk.renewalBackingOff())
        moving.instant = failedAt.plusSeconds(59)
        assertFalse(sdk.canRenewNow())
        moving.instant = failedAt.plus(SentomaruClient.RENEWAL_BACKOFF)
        assertTrue(sdk.canRenewNow())
        assertFalse(sdk.renewalBackingOff())
    }

    // A suspension after a generic failure does not inherit the 60 s: the backoff follows the last failure.
    @Test fun theBackoffFollowsTheLastFailure() {
        val (sdk, _) = renewingClient()
        moving.instant = now.plusSeconds(700)
        assertThrows(SentomaruException::class.java) { sdk.renew { throw java.io.IOException("down") } }
        moving.instant = moving.instant.plus(SentomaruClient.RENEWAL_BACKOFF)
        assertThrows(SentomaruException::class.java) {
            sdk.renew { throw SentomaruException(EnrollmentError.ServerRejected(EnrollmentError.Rejection.SUSPENDED)) }
        }
        moving.instant = moving.instant.plus(SentomaruClient.SUSPENDED_RENEWAL_BACKOFF)
        assertTrue(sdk.canRenewNow())
    }

    private fun suspend(sdk: SentomaruClient) = assertThrows(SentomaruException::class.java) {
        sdk.renew { throw SentomaruException(EnrollmentError.ServerRejected(EnrollmentError.Rejection.SUSPENDED)) }
    }

    // Consecutive suspensions escalate 5 s -> 15 s -> 60 s (client-side bound on the renewal rate); success resets.
    @Test fun consecutiveSuspensionsEscalateAndASuccessResetsTheStep() {
        val (sdk, _) = renewingClient()
        moving.instant = now.plusSeconds(700)
        for (step in listOf(5L, 15L, 60L, 60L)) {
            val failedAt = moving.instant
            suspend(sdk)
            assertTrue(sdk.renewalBackingOff())
            moving.instant = failedAt.plusSeconds(step - 1)
            assertTrue("still waiting inside the $step s step", sdk.renewalBackingOff())
            assertFalse(sdk.canRenewNow())
            moving.instant = failedAt.plusSeconds(step)
            assertFalse(sdk.renewalBackingOff())
            assertTrue(sdk.canRenewNow()) // the retry is allowed
        }
        assertEquals(renewedSession, sdk.renew { RenewedGrant(session, keyId, renewedSession, 600) }.sessionId)
        val failedAt = moving.instant
        suspend(sdk)
        moving.instant = failedAt.plusSeconds(5)
        assertTrue(sdk.canRenewNow()) // back to the first step
    }

    // A non-SUSPENDED failure resets the step: the next suspension waits 5 s again.
    @Test fun aNonSuspendedFailureResetsTheSuspensionStep() {
        val (sdk, _) = renewingClient()
        moving.instant = now.plusSeconds(700)
        suspend(sdk)
        moving.instant = moving.instant.plusSeconds(5)
        suspend(sdk) // second step: 15 s
        moving.instant = moving.instant.plusSeconds(15)
        assertThrows(SentomaruException::class.java) { sdk.renew { throw java.io.IOException("down") } }
        moving.instant = moving.instant.plus(SentomaruClient.RENEWAL_BACKOFF)
        val failedAt = moving.instant
        suspend(sdk)
        moving.instant = failedAt.plusSeconds(5)
        assertTrue(sdk.canRenewNow())
    }

    // reset() clears the backoff (and the step); a new enrollment renews at once.
    @Test fun resetClearsTheBackoff() {
        val (sdk, _) = renewingClient()
        moving.instant = now.plusSeconds(700)
        suspend(sdk)
        moving.instant = moving.instant.plusSeconds(5)
        suspend(sdk)
        assertTrue(sdk.renewalBackingOff())
        sdk.reset()
        assertFalse(sdk.renewalBackingOff()) // not enrolled: never "wait"
        sdk.enroll(EnrollmentChallenge(keyId, Base64.getEncoder().encodeToString(ByteArray(32) { 1 }), ByteArray(32) { 2 },
            moving.instant.plusSeconds(300))) { EnrollmentGrant(session, keyId, session, "hardware", "verified") }
        assertFalse(sdk.renewalBackingOff())
        assertTrue(sdk.canRenewNow())
        val failedAt = moving.instant
        suspend(sdk)
        moving.instant = failedAt.plusSeconds(5)
        assertTrue(sdk.canRenewNow()) // first step again
    }

    // renewalBackingOff() is only "wait": without a renewal URL or when not enrolled it is false (PARAMS case).
    @Test fun renewalBackingOffIsFalseWhenARenewalIsNotPossibleAtAll() {
        val (noUrl, _) = renewingClient(renewal = false)
        moving.instant = now.plusSeconds(700)
        assertThrows(SentomaruException::class.java) { noUrl.renew { RenewedGrant(session, keyId, renewedSession, 600) } }
        assertFalse(noUrl.renewalBackingOff())
        assertFalse(noUrl.canRenewNow())

        val (sdk, _) = renewingClient()
        moving.instant = now.plusSeconds(700)
        suspend(sdk)
        assertTrue(sdk.renewalBackingOff())
        val record = renewingStore.record!! // grant gone: EnrollmentRequired, not enrolled
        renewingStore.record = InstallationRecord(record.scopeIdentity, record.alias, record.challenge, record.strongBox,
            record.body(), null, record.requiresHardware, record.generation, record.retiredKeys, record.pendingRotation)
        assertEquals(InstallationState.EnrollmentRequired, sdk.state())
        assertFalse(sdk.renewalBackingOff())
        assertFalse(sdk.canRenewNow())
    }

    // session-unavailable drops the grant and the backoff: once enrolled again, nothing is left to wait for.
    @Test fun theEnrollmentRequiredDropClearsTheBackoff() {
        val (sdk, _) = renewingClient()
        moving.instant = now.plusSeconds(700)
        suspend(sdk)
        assertThrows(SentomaruException::class.java) {
            sdk.renew { throw SentomaruException(EnrollmentError.EnrollmentRequired()) }
        }.let { assertEquals("EnrollmentRequired", it.error.code) }
        assertEquals(InstallationState.EnrollmentRequired, sdk.state())
        val record = renewingStore.record!! // simulate the new grant of a re-enrollment, same key
        renewingStore.record = InstallationRecord(record.scopeIdentity, record.alias, record.challenge, record.strongBox,
            record.body(), EnrollmentGrant(session, keyId, renewedSession, "hardware", "verified"), record.requiresHardware,
            record.generation, record.retiredKeys, record.pendingRotation)
        assertFalse(sdk.renewalBackingOff())
        assertTrue(sdk.canRenewNow())
    }

    // 0.9.2: the code of the failure that started the backoff is kept while it runs (the plugin sends it as the details
    // of RenewalBackoff), so a suspension seen by the silent renewIfDue is still told apart from a transient failure.
    @Test fun aSuspendedFailureIsTheLastRenewalFailureWhileBackingOff() {
        val (sdk, _) = renewingClient()
        moving.instant = now.plusSeconds(700)
        assertNull(sdk.lastRenewalFailure()) // never failed
        val failedAt = moving.instant
        suspend(sdk)
        assertEquals("ServerRejected:SUSPENDED", sdk.lastRenewalFailure())
        moving.instant = failedAt.plus(SentomaruClient.SUSPENDED_RENEWAL_BACKOFF)
        assertNull(sdk.lastRenewalFailure()) // only while backing off
    }

    @Test fun theLastRenewalFailureIsClearedBySuccess() {
        val (sdk, _) = renewingClient()
        moving.instant = now.plusSeconds(700)
        suspend(sdk)
        moving.instant = moving.instant.plus(SentomaruClient.SUSPENDED_RENEWAL_BACKOFF)
        sdk.renew { RenewedGrant(session, keyId, renewedSession, 600) }
        assertNull(sdk.lastRenewalFailure())
        assertThrows(SentomaruException::class.java) { sdk.renew { throw java.io.IOException("down") } }
        assertEquals("NetworkUnavailable", sdk.lastRenewalFailure()) // a new failure, not the old SUSPENDED
    }

    @Test fun theLastRenewalFailureIsClearedByReset() {
        val (sdk, _) = renewingClient()
        moving.instant = now.plusSeconds(700)
        suspend(sdk)
        sdk.reset()
        assertNull(sdk.lastRenewalFailure())
        sdk.enroll(EnrollmentChallenge(keyId, Base64.getEncoder().encodeToString(ByteArray(32) { 1 }), ByteArray(32) { 2 },
            moving.instant.plusSeconds(300))) { EnrollmentGrant(session, keyId, session, "hardware", "verified") }
        assertNull(sdk.lastRenewalFailure()) // enrolled again: nothing left from before the reset
    }

    @Test fun aGenericRenewalFailureKeepsItsOwnCode() {
        val (sdk, _) = renewingClient()
        moving.instant = now.plusSeconds(700)
        assertThrows(SentomaruException::class.java) {
            sdk.renew { throw SentomaruException(EnrollmentError.ServerRejected(EnrollmentError.Rejection.UNAVAILABLE)) }
        }
        assertEquals("ServerRejected:UNAVAILABLE", sdk.lastRenewalFailure())
        moving.instant = moving.instant.plus(SentomaruClient.RENEWAL_BACKOFF)
        suspend(sdk)
        assertEquals("ServerRejected:SUSPENDED", sdk.lastRenewalFailure()) // follows the last failure
    }

    // A grant for another key is recorded with the code the caller gets, InvalidRequest:PARAMS (no closer error exists).
    @Test fun aGrantMismatchIsRecordedAsParams() {
        val (sdk, _) = renewingClient()
        moving.instant = now.plusSeconds(700)
        val error = assertThrows(SentomaruException::class.java) {
            sdk.renew { RenewedGrant(session, "99999999-2222-4333-8444-555555555555", renewedSession, 600) }
        }
        assertEquals("InvalidRequest:PARAMS", error.error.code)
        assertTrue(sdk.renewalBackingOff())
        assertEquals("InvalidRequest:PARAMS", sdk.lastRenewalFailure())
    }

    // An exception from send that carries no SentomaruError still backs off, with no code to report.
    @Test fun aGenericExceptionFromTheTransportBacksOffWithoutACode() {
        val (sdk, _) = renewingClient()
        moving.instant = now.plusSeconds(700)
        suspend(sdk)
        moving.instant = moving.instant.plus(SentomaruClient.SUSPENDED_RENEWAL_BACKOFF)
        assertThrows(IllegalStateException::class.java) { sdk.renew { throw IllegalStateException("boom") } }
        assertTrue(sdk.renewalBackingOff())
        assertNull(sdk.lastRenewalFailure()) // not the SUSPENDED of the previous failure
    }

    // renewalGate() is one snapshot: the decision and the code agree, and match the separate accessors.
    @Test fun theRenewalGateIsOneConsistentSnapshot() {
        val (sdk, _) = renewingClient()
        moving.instant = now.plusSeconds(700)
        sdk.renewalGate().let { assertFalse(it.backingOff); assertTrue(it.canRenewNow); assertNull(it.lastFailure) }
        val failedAt = moving.instant
        suspend(sdk)
        sdk.renewalGate().let {
            assertTrue(it.backingOff); assertFalse(it.canRenewNow); assertEquals("ServerRejected:SUSPENDED", it.lastFailure)
        }
        moving.instant = failedAt.plus(SentomaruClient.SUSPENDED_RENEWAL_BACKOFF)
        sdk.renewalGate().let { assertFalse(it.backingOff); assertTrue(it.canRenewNow); assertNull(it.lastFailure) }
        val (noUrl, _) = renewingClient(renewal = false)
        noUrl.renewalGate().let { assertFalse(it.backingOff); assertFalse(it.canRenewNow); assertNull(it.lastFailure) }
    }

    // The silent renewal of sign (renewIfDue) records the code too; the explicit renewSession then reads it.
    @Test fun theSilentRenewIfDueFailureIsTheLastRenewalFailure() {
        val (sdk, _) = renewingClient()
        moving.instant = now.plusSeconds(700)
        assertTrue(sdk.needsRenewal())
        assertThrows(SentomaruException::class.java) {
            sdk.renewIfDue { throw SentomaruException(EnrollmentError.ServerRejected(EnrollmentError.Rejection.SUSPENDED)) }
        }
        assertTrue(sdk.renewalBackingOff())
        assertEquals("ServerRejected:SUSPENDED", sdk.lastRenewalFailure())
    }

    // The session-unavailable drop clears it with the backoff.
    @Test fun theEnrollmentRequiredDropClearsTheLastRenewalFailure() {
        val (sdk, _) = renewingClient()
        moving.instant = now.plusSeconds(700)
        suspend(sdk)
        assertThrows(SentomaruException::class.java) {
            sdk.renew { throw SentomaruException(EnrollmentError.EnrollmentRequired()) }
        }
        assertNull(sdk.lastRenewalFailure())
    }

    // The plugin answers a renewal refused for backoff with this code (Dart: SentomaruErrorCode.renewalBackoff).
    @Test fun theRenewalBackoffErrorHasItsOwnStableCode() {
        assertEquals("RenewalBackoff", EnrollmentError.RenewalBackoff().code)
        val (sdk, _) = renewingClient()
        assertFalse(sdk.renewalBackingOff()) // never failed: no backoff
    }

    // OkHttp path: the consumer's 403 installation-suspended on the renewal maps to ServerRejected(SUSPENDED), like
    // the plugin: the grant is kept (no EnrollmentRequired), the operation still goes out, and the backoff is 5 s.
    @Test fun installationSuspendedOnTheOkHttpRenewalIsSuspendedNotEnrollmentRequired() {
        val (sdk, http) = renewingClient()
        moving.instant = now.plusSeconds(700)
        val failedAt = moving.instant
        server.enqueue(MockResponse().setResponseCode(403).setBody("{\"code\":\"installation-suspended\"}"))
        server.enqueue(MockResponse().setResponseCode(200))
        assertEquals(200, business(http).code)
        assertEquals("/sessions", server.takeRequest().path)
        assertEquals(session, server.takeRequest().getHeader("x-sentomaru-session"))
        assertEquals(InstallationState.Enrolled, sdk.state())
        moving.instant = failedAt.plusSeconds(4)
        assertFalse(sdk.canRenewNow())
        moving.instant = failedAt.plus(SentomaruClient.SUSPENDED_RENEWAL_BACKOFF)
        assertTrue(sdk.canRenewNow()) // SUSPENDED, not the generic 60 s

        // Any other 403 on the renewal stays a generic failure (60 s).
        server.enqueue(MockResponse().setResponseCode(403).setBody("{\"code\":\"operation-context\"}"))
        server.enqueue(MockResponse().setResponseCode(200))
        val otherAt = moving.instant
        assertEquals(200, business(http).code)
        moving.instant = otherAt.plus(SentomaruClient.SUSPENDED_RENEWAL_BACKOFF)
        assertFalse(sdk.canRenewNow())
        assertEquals(InstallationState.Enrolled, sdk.state())
    }

    @Test fun theMarginIsAFifthOfAShortLifetime() {
        val (sdk, http) = renewingClient()
        moving.instant = now.plusSeconds(EnrollmentGrant.DEFAULT_TTL_SECONDS) // enrollment grant due: renew (ttl 30)
        server.enqueue(renewal(ttl = 30))
        server.enqueue(MockResponse().setResponseCode(200))
        assertEquals(200, business(http).code)
        val renewedAt = moving.instant
        moving.instant = renewedAt.plusSeconds(23) // margin = min(120, 30/5) = 6 s: not due before 24 s
        assertFalse(sdk.needsRenewal())
        moving.instant = renewedAt.plusSeconds(24)
        assertTrue(sdk.needsRenewal())
    }

    @Test fun sessionExpiredInsideTheBackoffDoesNotRenewAgain() {
        val (_, http) = renewingClient()
        moving.instant = now.plusSeconds(700)
        server.enqueue(MockResponse().setResponseCode(503).setBody("{\"code\":\"store-unavailable\"}")) // renewal fails
        server.enqueue(MockResponse().setResponseCode(403).setBody("{\"code\":\"session-expired\"}"))
        assertEquals(403, business(http).code)
        assertEquals(2, server.requestCount) // no second renewal for the refusal: backoff
    }

    @Test fun sessionUnavailableOnRenewalMeansEnrollAgain() {
        val (sdk, http) = renewingClient()
        moving.instant = now.plusSeconds(700)
        server.enqueue(MockResponse().setResponseCode(403).setBody("{\"code\":\"session-unavailable\"}"))
        val error = assertThrows(SentomaruException::class.java) { business(http) }
        assertEquals("EnrollmentRequired", error.error.code)
        assertEquals(InstallationState.EnrollmentRequired, sdk.state())
        assertFalse(sdk.needsRenewal())
        assertEquals(1, server.requestCount) // the operation never left unsigned
    }
}
