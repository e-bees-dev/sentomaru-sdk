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
import java.time.Clock
import java.time.Instant
import java.time.ZoneOffset
import java.util.Base64
import java.util.concurrent.Executor

/**
 * D-15b over OkHttp: the answer of the consumer to a SIGNED request becomes a server response event when it carries a
 * closed code; the app still reads the same body; unsigned requests, an unsigned hop after a 302 and an install without
 * events give none.
 */
class ServerResponseEventsTransportTest {
    private val now = Instant.parse("2026-10-09T10:00:00Z")
    private val session = "aaaaaaaa-bbbb-4ccc-8ddd-eeeeeeeeeeee"
    private val keyId = "11111111-2222-4333-8444-555555555555"
    private lateinit var server: MockWebServer
    private lateinit var client: SentomaruClient
    private val events = SentomaruSignalEvents()
    private val received = mutableListOf<SentomaruServerResponseEvent>()

    @Before fun setUp() {
        server = MockWebServer()
        server.useHttps(TestTls.sslContext.socketFactory, false)
        server.start()
        val config = SentomaruConfig(organization = "org", app = "app", environment = "hml", allowedHosts = setOf(server.hostName),
            enrollmentUrl = "https://${server.hostName}:${server.port}/enroll")
        client = SentomaruClient(config, TestJcaKeys(), TestStore(), Clock.fixed(now, ZoneOffset.UTC))
        client.enroll(EnrollmentChallenge(keyId, Base64.getEncoder().encodeToString(ByteArray(32) { 1 }), ByteArray(32) { 2 }, now.plusSeconds(300))) {
            EnrollmentGrant(session, keyId, session, "hardware", "verified")
        }
        events.addServerResponseListener(Executor { it.run() }) { received += it }
    }

    @After fun tearDown() = server.shutdown()

    private fun http(withEvents: Boolean = true) = OkHttpClient.Builder()
        .sslSocketFactory(TestTls.sslContext.socketFactory, TestTls.trustManager).hostnameVerifier { _, _ -> true }
        .addSentomaru(client, null, if (withEvents) events else null).build()

    private fun signed(path: String = "/api/orders") = Request.Builder().url("https://${server.hostName}:${server.port}$path")
        .header("x-sentomaru-operation", "pagar_pedido").post("{}".toRequestBody("application/json".toMediaType())).build()

    @Test fun aChallengeOnASignedRequestIsAnEventAndTheBodyStaysReadable() {
        val body = """{"code":"challenge-required","challengeKind":"step_up"}"""
        server.enqueue(MockResponse().setResponseCode(401).setBody(body))
        http().newCall(signed()).execute().use { assertEquals(body, it.body!!.string()) }
        assertEquals(listOf(SentomaruServerResponseEvent("challenge-required", "step_up", 401, 1)), received)
    }

    /** D-06h: the 4.6.0 adapter's 401 for a reattest challenge is one event with the kind; the SDK neither reattests
     * nor repeats the request by itself (one call reached the server). */
    @Test fun aReattestChallengeIsOneEventAndNothingIsRepeated() {
        val body = """{"code":"challenge-required","attestationReason":null,"challengeKind":"reattest"}"""
        server.enqueue(MockResponse().setResponseCode(401).setBody(body))
        http().newCall(signed()).execute().use { assertEquals(body, it.body!!.string()) }
        assertEquals(listOf(SentomaruServerResponseEvent("challenge-required", "reattest", 401, 1)), received)
        assertTrue(received.single().isReattestChallenge)
        assertEquals(1, server.requestCount)
    }

    @Test fun policyRefusalAndSuspensionAreEventsOtherBodiesAreNot() {
        server.enqueue(MockResponse().setResponseCode(403).setBody("""{"code":"RASP_ROOT_ARTIFACTS","attestationReason":null}"""))
        server.enqueue(MockResponse().setResponseCode(403).setBody("""{"code":"installation-suspended"}"""))
        server.enqueue(MockResponse().setResponseCode(403).setBody("""{"riskEvent":{"code":"installation-suspended","reason":"x"}}"""))
        server.enqueue(MockResponse().setResponseCode(200).setBody("""{"code":"challenge-required"}"""))
        repeat(4) { http().newCall(signed()).execute().close() }
        assertEquals(listOf("RASP_ROOT_ARTIFACTS", "installation-suspended"), received.map { it.code })
    }

    @Test fun unsignedRequestsUnsignedHopsAndInstallsWithoutEventsGiveNone() {
        server.enqueue(MockResponse().setResponseCode(403).setBody("""{"code":"installation-suspended"}"""))
        http().newCall(Request.Builder().url("https://${server.hostName}:${server.port}/public").get().build()).execute().close()
        server.enqueue(MockResponse().setResponseCode(302).addHeader("Location", "/elsewhere"))
        server.enqueue(MockResponse().setResponseCode(403).setBody("""{"code":"installation-suspended"}"""))
        http().newCall(signed()).execute().close()
        server.enqueue(MockResponse().setResponseCode(403).setBody("""{"code":"installation-suspended"}"""))
        http(withEvents = false).newCall(signed()).execute().close()
        assertTrue(received.isEmpty())
    }

    @Test fun aReSignedHopReportsAndAnOversizedBodyIsNoEventButStaysReadable() {
        server.enqueue(MockResponse().setResponseCode(307).addHeader("Location", "/api/other"))
        server.enqueue(MockResponse().setResponseCode(403).setBody("""{"code":"policy-denied"}"""))
        http().newCall(signed()).execute().close()
        assertEquals(listOf("policy-denied"), received.map { it.code })
        val big = """{"code":"installation-suspended","pad":"${"x".repeat(5000)}"}"""
        server.enqueue(MockResponse().setResponseCode(403).setBody(big))
        http().newCall(signed()).execute().use { assertEquals(big, it.body!!.string()) }
        assertEquals(1, received.size)
    }

    @Test fun withoutEventsTheBodyIsUntouched() {
        val body = """{"code":"challenge-required","challengeKind":"step_up"}"""
        server.enqueue(MockResponse().setResponseCode(401).setBody(body))
        http(withEvents = false).newCall(signed()).execute().use { assertEquals(body, it.body!!.string()) }
        assertTrue(received.isEmpty())
    }
}
