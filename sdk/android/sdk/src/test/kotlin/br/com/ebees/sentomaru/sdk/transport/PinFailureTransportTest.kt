package br.com.ebees.sentomaru.sdk.transport

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
import java.net.HttpURLConnection
import java.net.Socket
import java.net.URL
import java.security.SecureRandom
import java.security.cert.CertificateException
import java.security.cert.X509Certificate
import java.time.Clock
import java.time.Instant
import java.time.ZoneOffset
import java.util.Base64
import java.util.concurrent.Executor
import java.util.concurrent.TimeUnit
import javax.net.ssl.HttpsURLConnection
import javax.net.ssl.SSLContext
import javax.net.ssl.SSLEngine
import javax.net.ssl.SSLHandshakeException
import javax.net.ssl.SSLSocket
import javax.net.ssl.X509ExtendedTrustManager

/**
 * D-07d over a real TLS handshake (MockWebServer with the test `localhost` identity, JDK TLS): a handshake refused on a
 * pinned host becomes one `pin_failure` event and the same exception reaches the app, on OkHttp and on
 * HttpURLConnection. The platform's `network_security_config` is emulated on the client by [PlatformPinTrust] (the
 * test chain is trusted, then the pin check throws the platform's `CertificateException("Pin verification failed")`
 * for the hosts it pins, as `NetworkSecurityTrustManager.checkPins` does); the real platform is the D-07e device proof.
 * Without meta-data hosts, without `events`, without a transport listener or for a host not listed, nothing is emitted
 * and the failure is the same.
 */
class PinFailureTransportTest {
    private val now = Instant.parse("2026-10-09T10:00:00Z")
    private val session = "aaaaaaaa-bbbb-4ccc-8ddd-eeeeeeeeeeee"
    private val keyId = "11111111-2222-4333-8444-555555555555"
    private val loopback = "127.0.0.1"
    private lateinit var server: MockWebServer
    private lateinit var host: String
    private lateinit var client: SentomaruClient
    private val events = SentomaruSignalEvents()
    private val received = mutableListOf<SentomaruTransportEvent>()

    /** Trusts the test chain, then refuses [pinFails] hosts with the platform's pin message (client side only). */
    private class PlatformPinTrust(private val pinFails: Set<String>) : X509ExtendedTrustManager() {
        private val delegate = TestTls.trustManager
        private fun pin(peer: String?) { if (peer in pinFails) throw CertificateException(PinFailure.PLATFORM_PIN_MESSAGE) }
        override fun checkServerTrusted(chain: Array<out X509Certificate>, authType: String, socket: Socket) {
            delegate.checkServerTrusted(chain, authType)
            pin((socket as SSLSocket).handshakeSession?.peerHost)
        }
        override fun checkServerTrusted(chain: Array<out X509Certificate>, authType: String, engine: SSLEngine) {
            delegate.checkServerTrusted(chain, authType)
            pin(engine.peerHost)
        }
        override fun checkServerTrusted(chain: Array<out X509Certificate>, authType: String) = throw CertificateException("no peer")
        override fun checkClientTrusted(chain: Array<out X509Certificate>, authType: String, socket: Socket) = throw UnsupportedOperationException()
        override fun checkClientTrusted(chain: Array<out X509Certificate>, authType: String, engine: SSLEngine) = throw UnsupportedOperationException()
        override fun checkClientTrusted(chain: Array<out X509Certificate>, authType: String) = throw UnsupportedOperationException()
        override fun getAcceptedIssuers(): Array<X509Certificate> = delegate.acceptedIssuers
    }

    private fun context(trust: X509ExtendedTrustManager) = SSLContext.getInstance("TLS").apply { init(null, arrayOf(trust), SecureRandom()) }

    @Before fun setUp() {
        server = MockWebServer()
        server.useHttps(TestTls.sslContext.socketFactory, false)
        server.start()
        host = server.hostName
        assertNotEquals(loopback, host)
        client = enrolled(setOf(host, loopback))
        events.addTransportListener(Executor { it.run() }) { received += it }
    }

    @After fun tearDown() = server.shutdown()

    /** The meta-data value the CLI would write for [hosts] (MockWebServer's `localhost` passes the SDK's host rule). */
    private fun pinned(vararg hosts: String) = PinnedHosts.parse(hosts.joinToString(",")).also { assertFalse(it.isEmpty) }

    /** Signs on [loopback] (unpinned), renews on [host] (pinned): the grant is marked stale, so the next call renews first. */
    private fun renewingClient() = SentomaruClient(SentomaruConfig("org", "app", "hml", setOf(host, loopback),
        "https://$host:${server.port}/enroll", renewalUrl = "https://$host:${server.port}/renew"), TestJcaKeys(), TestStore(),
        Clock.fixed(now, ZoneOffset.UTC)).also {
        it.enroll(EnrollmentChallenge(keyId, Base64.getEncoder().encodeToString(ByteArray(32) { 1 }), ByteArray(32) { 2 }, now.plusSeconds(300))) {
            EnrollmentGrant(session, keyId, session, "hardware", "verified")
        }
        it.markGrantStale()
        assertTrue(it.needsRenewal())
        it.pinnedHostSet = pinned(host)
    }

    private fun enrolled(allowed: Set<String>, enrollHost: String = host) = SentomaruClient(SentomaruConfig("org", "app", "hml", allowed,
        "https://$enrollHost:${server.port}/enroll"), TestJcaKeys(), TestStore(), Clock.fixed(now, ZoneOffset.UTC)).also {
        it.enroll(EnrollmentChallenge(keyId, Base64.getEncoder().encodeToString(ByteArray(32) { 1 }), ByteArray(32) { 2 }, now.plusSeconds(300))) {
            EnrollmentGrant(session, keyId, session, "hardware", "verified")
        }
    }

    private fun okHttp(c: SentomaruClient = client, trust: X509ExtendedTrustManager = PlatformPinTrust(setOf(host)),
        withEvents: Boolean = true) = OkHttpClient.Builder()
        .sslSocketFactory(context(trust).socketFactory, trust).hostnameVerifier { _, _ -> true }
        .retryOnConnectionFailure(false).callTimeout(10, TimeUnit.SECONDS)
        .addSentomaru(c, null, if (withEvents) events else null).build()

    private fun signed(h: String = host, path: String = "/api/orders") = Request.Builder().url("https://$h:${server.port}$path")
        .header("x-sentomaru-operation", "pagar_pedido").post("{}".toRequestBody("application/json".toMediaType())).build()

    private fun plainGet(h: String = host) = Request.Builder().url("https://$h:${server.port}/public").get().build()

    private fun failure(block: () -> Unit): IOException = try {
        block()
        throw AssertionError("expected a TLS failure")
    } catch (e: IOException) {
        e
    }

    @Test fun aPinMismatchOnASignedOkHttpRequestIsOneEventAndTheSameFailure() {
        client.pinnedHostSet = pinned(host)
        val e = failure { okHttp().newCall(signed()).execute().close() }
        assertTrue(e is SSLHandshakeException)
        assertEquals("pin_mismatch", PinFailure.classify(e))
        assertEquals(listOf(SentomaruTransportEvent("pin_failure", "pin_mismatch", host, 1)), received)
        assertEquals("nothing of the request reached the peer", 0, server.requestCount)
    }

    /** The JDK default trust does not know the test CA: tls_untrusted. */
    @Test fun anUntrustedChainOnAPinnedHostIsTlsUntrusted() {
        client.pinnedHostSet = pinned(host)
        val jdkDefault = javax.net.ssl.TrustManagerFactory.getInstance(javax.net.ssl.TrustManagerFactory.getDefaultAlgorithm())
            .apply { init(null as java.security.KeyStore?) }.trustManagers.filterIsInstance<X509ExtendedTrustManager>().first()
        failure { okHttp(trust = jdkDefault).newCall(signed()).execute().close() }
        assertEquals(listOf(SentomaruTransportEvent("pin_failure", "tls_untrusted", host, 1)), received)
    }

    /**
     * A peer that reads the ClientHello and then closes the connection cleanly (FIN) before answering: tls_other. The cut is
     * made by a plain server socket, not by `SocketPolicy.DISCONNECT_AT_START`: that policy closes a socket that still has the
     * ClientHello unread, which the OS may turn into a reset (RST), and the JDK then reports a bare `SocketException` instead
     * of an `SSLHandshakeException` in about 1 run in 8 (300 runs: 260 SSLHandshakeException, 40 SocketException). A bare
     * reset is not a TLS failure to `PinFailure.classify`, so that run gave no event: the test was flaky, not the SDK.
     */
    @Test fun aCutHandshakeOnAPinnedHostIsTlsOther() {
        client.pinnedHostSet = pinned(host)
        val cutter = java.net.ServerSocket(0, 1, java.net.InetAddress.getByName(host))
        val worker = Thread {
            try {
                cutter.accept().use { peer ->
                    peer.soTimeout = 5_000
                    peer.getInputStream().read(ByteArray(1024)) // the ClientHello is consumed, so closing cannot reset
                    peer.shutdownOutput() // FIN: the client reads end-of-stream in the middle of the handshake
                    try { while (peer.getInputStream().read() >= 0) { /* drain until the client closes */ } } catch (_: IOException) { }
                }
            } catch (_: IOException) { }
        }.apply { isDaemon = true; start() }
        try {
            val request = Request.Builder().url("https://$host:${cutter.localPort}/public").get().build()
            val cut = failure { okHttp(trust = PlatformPinTrust(emptySet())).newCall(request).execute().close() }
            assertTrue(cut.toString(), cut is javax.net.ssl.SSLException)
            assertEquals(listOf(SentomaruTransportEvent("pin_failure", "tls_other", host, 1)), received)
        } finally {
            cutter.close()
            worker.join(5_000)
        }
    }

    /**
     * J-04r renewal before the operation goes to a pinned host that fails: one event, for the renewal's host; the failed
     * renewal keeps the grant (as before D-07d) and the operation itself goes out on the unpinned host and is answered.
     */
    @Test fun aRenewalToAPinnedHostOnOkHttpIsReportedOnce() {
        val renewing = renewingClient()
        server.enqueue(MockResponse().setBody("{}"))
        okHttp(c = renewing).newCall(signed(h = loopback)).execute().use { assertEquals(200, it.code) }
        assertEquals(listOf(SentomaruTransportEvent("pin_failure", "pin_mismatch", host, 1)), received)
        assertEquals("/api/orders", server.takeRequest().path)
        assertEquals(1, server.requestCount)
    }

    /** An unsigned request to a pinned host outside `allowedHosts` passes through the interceptor and is reported too. */
    @Test fun aPassThroughRequestToAPinnedHostOutsideTheAllowlistIsReported() {
        val other = enrolled(setOf("api.example"), enrollHost = "api.example")
        other.pinnedHostSet = pinned(host)
        failure { okHttp(c = other).newCall(plainGet()).execute().close() }
        assertEquals(listOf("pin_mismatch"), received.map { it.reason })
    }

    /** A re-signed 307 hop from an allowed, unpinned host to a pinned one is reported with the pinned host. */
    @Test fun aReSignedRedirectHopToAPinnedHostIsReportedWithThatHost() {
        client.pinnedHostSet = pinned(host)
        server.enqueue(MockResponse().setResponseCode(307).addHeader("Location", "https://$host:${server.port}/api/other"))
        failure { okHttp(trust = PlatformPinTrust(setOf(host))).newCall(signed(h = loopback)).execute().close() }
        assertEquals(listOf(SentomaruTransportEvent("pin_failure", "pin_mismatch", host, 1)), received)
        assertEquals(1, server.requestCount)
    }

    @Test fun withoutMetaDataEventsOrListenerOrForAnotherHostNothingIsEmittedAndTheFailureIsTheSame() {
        // No meta-data (the default of a client built directly, and of an app without the pinning control).
        val withoutMeta = failure { okHttp().newCall(signed()).execute().close() }
        // Pinned, but the app did not pass events.
        client.pinnedHostSet = pinned(host)
        val withoutEvents = failure { okHttp(withEvents = false).newCall(signed()).execute().close() }
        // Pinned, events passed, but the host that failed is not listed.
        client.pinnedHostSet = pinned("api.example")
        val otherHost = failure { okHttp().newCall(signed()).execute().close() }
        // Pinned and listed, but no transport listener.
        client.pinnedHostSet = pinned(host)
        val quiet = SentomaruSignalEvents()
        val noListener = failure {
            OkHttpClient.Builder().sslSocketFactory(context(PlatformPinTrust(setOf(host))).socketFactory, PlatformPinTrust(setOf(host)))
                .hostnameVerifier { _, _ -> true }.retryOnConnectionFailure(false).addSentomaru(client, null, quiet).build()
                .newCall(signed()).execute().close()
        }
        assertTrue(received.isEmpty())
        for (e in listOf(withoutMeta, withoutEvents, otherHost, noListener)) {
            assertTrue(e is SSLHandshakeException)
            assertEquals(PinFailure.PLATFORM_PIN_MESSAGE, generateSequence(e as Throwable) { it.cause }
                .filterIsInstance<CertificateException>().first().message)
        }
    }

    @Test fun aSuccessfulExchangeOnAPinnedHostIsNoEvent() {
        client.pinnedHostSet = pinned(host)
        server.enqueue(MockResponse().setBody("{}"))
        okHttp(trust = PlatformPinTrust(emptySet())).newCall(signed()).execute().use { assertEquals(200, it.code) }
        assertTrue(received.isEmpty())
    }

    private fun opener(trust: X509ExtendedTrustManager) = SentomaruUrlConnection.Opener { url ->
        (url.openConnection() as HttpURLConnection).also {
            if (it is HttpsURLConnection) {
                it.sslSocketFactory = context(trust).socketFactory
                it.hostnameVerifier = javax.net.ssl.HostnameVerifier { _, _ -> true }
            }
            it.connectTimeout = 5_000
            it.readTimeout = 5_000
        }
    }

    @Test fun aPinMismatchOnHttpUrlConnectionIsOneEventAndTheSameFailure() {
        client.pinnedHostSet = pinned(host)
        val e = failure {
            SentomaruUrlConnection.send(client, null, "POST", URL("https://$host:${server.port}/api/orders"), "{}".toByteArray(),
                mapOf("x-sentomaru-operation" to "pagar_pedido", "content-type" to "application/json"), null,
                events, opener(PlatformPinTrust(setOf(host))))
        }
        assertTrue(e is SSLHandshakeException)
        assertEquals(listOf(SentomaruTransportEvent("pin_failure", "pin_mismatch", host, 1)), received)
        assertEquals(0, server.requestCount)
    }

    private fun sendSigned(c: SentomaruClient, h: String) = SentomaruUrlConnection.send(c, null, "POST",
        URL("https://$h:${server.port}/api/orders"), "{}".toByteArray(),
        mapOf("x-sentomaru-operation" to "pagar_pedido", "content-type" to "application/json"), null, events,
        opener(PlatformPinTrust(setOf(host))))

    @Test fun aReSignedRedirectHopOnHttpUrlConnectionIsReportedWithThePinnedHost() {
        client.pinnedHostSet = pinned(host)
        server.enqueue(MockResponse().setResponseCode(307).addHeader("Location", "https://$host:${server.port}/api/other"))
        val e = failure { sendSigned(client, loopback) }
        assertTrue(e is SSLHandshakeException)
        assertEquals(listOf(SentomaruTransportEvent("pin_failure", "pin_mismatch", host, 1)), received)
        assertEquals(1, server.requestCount)
    }

    @Test fun aRenewalToAPinnedHostOnHttpUrlConnectionIsReportedOnce() {
        server.enqueue(MockResponse().setBody("{}"))
        val conn = sendSigned(renewingClient(), loopback)
        assertEquals(200, conn.responseCode)
        conn.inputStream.close()
        assertEquals(listOf(SentomaruTransportEvent("pin_failure", "pin_mismatch", host, 1)), received)
        assertEquals("/api/orders", server.takeRequest().path)
        assertEquals(1, server.requestCount)
    }

    @Test fun httpUrlConnectionWithoutEventsOrMetaDataEmitsNothing() {
        val send = { withEvents: Boolean ->
            failure {
                SentomaruUrlConnection.send(client, null, "GET", URL("https://$host:${server.port}/public"), null, emptyMap(), null,
                    if (withEvents) events else null, opener(PlatformPinTrust(setOf(host))))
            }
        }
        val withoutMeta = send(true)
        client.pinnedHostSet = pinned(host)
        val withoutEvents = send(false)
        assertTrue(received.isEmpty())
        assertTrue(withoutMeta is SSLHandshakeException && withoutEvents is SSLHandshakeException)
        send(true)
        assertEquals(listOf("pin_mismatch"), received.map { it.reason })
    }

    @Test fun theClientReportsItsPinnedHostsAndIsEmptyWhenBuiltDirectly() {
        assertTrue(client.pinnedHosts.isEmpty())
        client.pinnedHostSet = PinnedHosts.parse("a.example,b.example")
        assertEquals(setOf("a.example", "b.example"), client.pinnedHosts)
    }
}
