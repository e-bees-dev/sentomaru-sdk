package br.com.ebees.sentomaru.sentomaru_flutter

import br.com.ebees.sentomaru.core.FrozenRequest
import br.com.ebees.sentomaru.core.MessageSigner
import br.com.ebees.sentomaru.core.SentomaruException
import br.com.ebees.sentomaru.core.SignatureParams
import br.com.ebees.sentomaru.core.SignedMessage
import br.com.ebees.sentomaru.sdk.EnrollmentError
import okhttp3.OkHttpClient
import okhttp3.mockwebserver.MockResponse
import okhttp3.mockwebserver.MockWebServer
import okhttp3.tls.HandshakeCertificates
import okhttp3.tls.HeldCertificate
import org.junit.After
import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertThrows
import org.junit.Before
import org.junit.Test
import java.io.IOException
import java.net.InetAddress

/** Real OkHttp + MockWebServer over TLS; exercises the enrollment policy used by the Flutter plugin (R4). */
class EnrollmentTransportTest {
    private val id = "11111111-2222-4333-8444-555555555555"
    private val grantJson = """{"installationId":"$id","keyId":"$id","sessionId":"$id",""" +
        """"hardwareStatus":"hardware","attestationStatus":"verified"}"""

    private lateinit var server: MockWebServer
    private lateinit var other: MockWebServer
    private lateinit var http: OkHttpClient
    private lateinit var host: String

    @Before fun setUp() {
        val localhost = InetAddress.getByName("localhost").canonicalHostName
        val cert = HeldCertificate.Builder().addSubjectAlternativeName(localhost).build()
        val serverTls = HandshakeCertificates.Builder().heldCertificate(cert).build()
        val clientTls = HandshakeCertificates.Builder().addTrustedCertificate(cert.certificate).build()
        server = MockWebServer().apply { useHttps(serverTls.sslSocketFactory(), false); start() }
        other = MockWebServer().apply { useHttps(serverTls.sslSocketFactory(), false); start() }
        host = server.hostName
        http = EnrollmentTransport.defaultClient(
            OkHttpClient.Builder().sslSocketFactory(clientTls.sslSocketFactory(), clientTls.trustManager))
    }

    @After fun tearDown() {
        server.shutdown()
        other.shutdown()
    }

    private fun signed(url: String, body: ByteArray = """{"token":"t"}""".toByteArray()): SignedMessage {
        val headers = linkedMapOf(
            "content-type" to "application/json", "x-sentomaru-profile" to "sentomaru-p0",
            "x-sentomaru-org" to "ebees", "x-sentomaru-app" to "example-app", "x-sentomaru-environment" to "hml",
            "x-sentomaru-session" to id, "x-sentomaru-operation" to "enroll")
        return MessageSigner.sign(FrozenRequest("POST", url, headers, body), SignatureParams(1, 2, id, id)) { ByteArray(64) }
    }

    private fun transport() = EnrollmentTransport(setOf(host), http)
    private fun url(path: String = "/enroll") = "https://$host:${server.port}$path"

    private fun rejection(block: () -> Unit): String =
        assertThrows(SentomaruException::class.java) { block() }.error.code

    @Test fun validGrantIsReturnedAndSignedBytesAreSentUnchanged() {
        server.enqueue(MockResponse().setBody(grantJson))
        val message = signed(url())
        val grant = transport().send(message)
        assertEquals(id, grant.sessionId)
        assertEquals("hardware", grant.hardwareStatus)
        val recorded = server.takeRequest()
        assertEquals("POST", recorded.method)
        assertArrayEquals(message.body(), recorded.body.readByteArray())
        assertEquals(message.header("signature"), recorded.getHeader("signature"))
        assertEquals("application/json", recorded.getHeader("content-type"))
    }

    // D-12e: the reattestation steps under the same rules; the answer goes to the SDK as it came.
    @Test fun reattestPassesStatusBodyAndRetryAfterThrough() {
        server.enqueue(MockResponse().setResponseCode(429).setHeader("Retry-After", "120").setBody("""{"code":"rate-limited"}"""))
        server.enqueue(MockResponse().setResponseCode(200).setBody("""{"ok":true}"""))
        val first = transport().reattest(signed(url("/reattest")))
        assertEquals(429, first.status)
        assertEquals(120L, first.retryAfterSeconds)
        assertEquals("""{"code":"rate-limited"}""", first.body)
        val second = transport().reattest(signed(url("/reattest")))
        assertEquals(200, second.status)
        assertEquals(null, second.retryAfterSeconds)
        assertEquals("""{"ok":true}""", second.body)
        assertEquals("/reattest", server.takeRequest().path)
    }

    @Test fun reattestRetryAfterOnlyInSeconds() {
        assertEquals(0L, EnrollmentTransport.retryAfterSeconds("0"))
        assertEquals(3600L, EnrollmentTransport.retryAfterSeconds(" 3600 "))
        for (bad in listOf(null, "", "-1", "1.5", "Wed, 21 Oct 2026 07:28:00 GMT", "12345678901", "1e3"))
            assertEquals(bad, null, EnrollmentTransport.retryAfterSeconds(bad))
    }

    @Test fun reattestNeverFollowsARedirectNorReadsAnOversizedBody() {
        server.enqueue(MockResponse().setResponseCode(307).setHeader("Location", "https://$host:${other.port}/x"))
        assertEquals(307, transport().reattest(signed(url("/reattest"))).status)
        assertEquals(0, other.requestCount)
        server.enqueue(MockResponse().setBody("x".repeat(EnrollmentTransport.MAX_RESPONSE_BYTES.toInt() + 1)))
        assertEquals("", transport().reattest(signed(url("/reattest"))).body)
    }

    @Test fun reattestTransportFailureIsAnIOExceptionAndHostOutsideTheAllowlistIsRefused() {
        val dead = url("/reattest")
        server.shutdown()
        assertThrows(IOException::class.java) { transport().reattest(signed(dead)) }
        assertEquals("HostNotAllowed", rejection { EnrollmentTransport(setOf("other.example"), http).reattest(signed(dead)) })
    }

    @Test fun redirectsAreNeverFollowed() {
        for (code in listOf(301, 302, 303, 307, 308)) {
            server.enqueue(MockResponse().setResponseCode(code).addHeader("Location", "https://$host:${other.port}/x"))
            assertEquals("ServerRejected:INVALID", rejection { transport().send(signed(url())) })
            server.takeRequest()
        }
        assertEquals("the signed attestation never reaches the redirect target", 0, other.requestCount)
    }

    @Test fun serverAnswersMapToTypedRejectionsNotNetworkUnavailable() {
        val cases = listOf(
            MockResponse().setResponseCode(400).setBody("""{"code":"challenge-invalid"}""") to "ServerRejected:EXPIRED",
            MockResponse().setResponseCode(403).setBody("""{"code":"enrollment-revoked"}""") to "ServerRejected:REVOKED",
            MockResponse().setResponseCode(429) to "ServerRejected:RATE_LIMITED",
            MockResponse().setResponseCode(503).setBody("""{"code":"store-unavailable"}""") to "ServerRejected:UNAVAILABLE",
            MockResponse().setResponseCode(422).setBody("""{"code":"hardware-not-proven"}""") to "ServerRejected:INVALID",
            MockResponse().setResponseCode(401).setBody("not json") to "ServerRejected:INVALID",
            // v1.5: a suspended installation waits; it is neither a revocation nor a generic refusal.
            MockResponse().setResponseCode(403).setBody("""{"code":"installation-suspended"}""") to "ServerRejected:SUSPENDED",
            MockResponse().setResponseCode(409).setBody("""{"code":"enrollment-revoked"}""") to "ServerRejected:REVOKED",
            MockResponse().setResponseCode(403).setBody("""{"code":"installation-revoked"}""") to "ServerRejected:REVOKED",
            MockResponse().setResponseCode(403).setBody("""{"code":"enrollment-context"}""") to "ServerRejected:INVALID",
            MockResponse().setResponseCode(403) to "ServerRejected:INVALID",
            // v1.6 (D-04d): a refused re-enrollment is its own error (reset() + enroll()); only the exact 401 answer.
            MockResponse().setResponseCode(401).setBody("""{"code":"predecessor-invalid"}""") to "ReenrollmentRefused",
            MockResponse().setResponseCode(403).setBody("""{"code":"predecessor-invalid"}""") to "ServerRejected:INVALID",
            // D-04d: only Sentomaru's own codes prove a body was not accepted; anything generic stays INVALID (kept).
            MockResponse().setResponseCode(409).setBody("""{"code":"enrollment-conflict"}""") to "ServerRejected:CONFLICT",
            MockResponse().setResponseCode(410) to "ServerRejected:INVALID",
            MockResponse().setResponseCode(404) to "ServerRejected:INVALID",
            MockResponse().setResponseCode(408) to "ServerRejected:INVALID",
            MockResponse().setResponseCode(401).setBody("""{"code":"proof-invalid"}""") to "ServerRejected:INVALID",
            MockResponse().setResponseCode(403).setBody("""{"code":"session-revoked-by-proxy"}""") to "ServerRejected:INVALID",
        )
        for ((response, expected) in cases) {
            server.enqueue(response)
            assertEquals(expected, rejection { transport().send(signed(url())) })
        }
    }

    @Test fun malformedOrIncompleteGrantIsRejectedWithoutEchoingTheBody() {
        server.enqueue(MockResponse().setBody("<html>secret-echo</html>"))
        val error = assertThrows(SentomaruException::class.java) { transport().send(signed(url())) }
        assertEquals("ServerRejected:INVALID", error.error.code)
        assertFalse(error.message!!.contains("secret-echo"))

        server.enqueue(MockResponse().setBody("""{"installationId":"$id","keyId":"$id","sessionId":"$id"}"""))
        assertEquals("missing status fields are not defaulted", "ServerRejected:INVALID",
            rejection { transport().send(signed(url())) })
    }

    @Test fun hostOutsideAllowlistOrPlainHttpIsRefusedBeforeSending() {
        assertEquals("HostNotAllowed", rejection {
            EnrollmentTransport(setOf("api.example"), http).send(signed(url()))
        })
        // An http target cannot even be signed (the core refuses it), so no http enrollment can reach send().
        assertEquals("InvalidRequest:TARGET_URI", rejection { transport().send(signed("http://$host:${server.port}/enroll")) })
        assertEquals(0, server.requestCount)
    }

    @Test fun transportFailureIsIoExceptionSoTheSdkReportsNetworkUnavailable() {
        val port = server.port
        server.shutdown()
        assertThrows(IOException::class.java) { transport().send(signed("https://$host:$port/enroll")) }
    }

    // J-04r: the renewal goes through the same policy (allowlisted https, no redirect, one send).
    @Test fun renewalReturnsTheNewGrantAndRefusesEverythingElse() {
        val renewed = "bbbbbbbb-cccc-4ddd-8eee-ffffffffffff"
        server.enqueue(MockResponse().setBody("""{"installationId":"$id","keyId":"$id","sessionId":"$renewed","expiresAt":"x","ttlSeconds":600}"""))
        val grant = transport().renew(signed(url("/sessions"), "{}".toByteArray()))
        assertEquals((renewed to 600L), grant.sessionId to grant.ttlSeconds)
        assertEquals("/sessions", server.takeRequest().path)
        server.enqueue(MockResponse().setResponseCode(403).setBody("""{"code":"session-unavailable"}"""))
        assertEquals("EnrollmentRequired", rejection { transport().renew(signed(url("/sessions"), "{}".toByteArray())) })
        for (answer in listOf(MockResponse().setResponseCode(403).setBody("""{"code":"operation-context"}"""),
                MockResponse().setResponseCode(302).setHeader("Location", url("/x")),
                MockResponse().setBody("""{"installationId":"$id"}"""))) {
            server.enqueue(answer)
            assertEquals("InvalidRequest:PARAMS", rejection { transport().renew(signed(url("/sessions"), "{}".toByteArray())) })
        }
        assertEquals("HostNotAllowed", rejection { EnrollmentTransport(setOf("api.example"), http).renew(signed(url("/sessions"))) })
    }

    // Contract v1.5: 403 installation-suspended on a renewal is told apart (wait, never enroll again) and only that
    // exact answer is: every other 403, a body without that code or another status keeps InvalidRequest:PARAMS.
    @Test fun renewalOfASuspendedInstallationIsServerRejectedSuspendedAndNothingElseIs() {
        server.enqueue(MockResponse().setResponseCode(403).setBody("""{"code":"installation-suspended"}"""))
        assertEquals("ServerRejected:SUSPENDED", rejection { transport().renew(signed(url("/sessions"), "{}".toByteArray())) })
        server.enqueue(MockResponse().setResponseCode(403).setBody("""{"code":"session-unavailable"}"""))
        assertEquals("EnrollmentRequired", rejection { transport().renew(signed(url("/sessions"), "{}".toByteArray())) })
        for (answer in listOf(
                MockResponse().setResponseCode(403),
                MockResponse().setResponseCode(403).setBody("not json installation-suspended"),
                MockResponse().setResponseCode(403).setBody("""{"code":"installation-revoked"}"""),
                MockResponse().setResponseCode(403).setBody("""{"code":"operation-context"}"""),
                MockResponse().setResponseCode(403).setBody("""{"code":"installation-suspended-later"}"""),
                MockResponse().setResponseCode(403).setBody("""{"code":"Installation-Suspended"}"""),
                MockResponse().setResponseCode(403).setBody("""{"error":"installation-suspended"}"""),
                MockResponse().setResponseCode(409).setBody("""{"code":"installation-suspended"}"""),
                MockResponse().setResponseCode(503).setBody("""{"code":"installation-suspended"}"""))) {
            server.enqueue(answer)
            assertEquals("InvalidRequest:PARAMS", rejection { transport().renew(signed(url("/sessions"), "{}".toByteArray())) })
        }
    }

    @Test fun suspensionIsOnlyThe403WithThatExactCode() {
        assertEquals(EnrollmentError.Rejection.SUSPENDED, EnrollmentTransport.rejectionFor(403, "installation-suspended"))
        assertEquals(EnrollmentError.Rejection.INVALID, EnrollmentTransport.rejectionFor(409, "installation-suspended"))
        assertEquals(EnrollmentError.Rejection.UNAVAILABLE, EnrollmentTransport.rejectionFor(503, "installation-suspended"))
        assertEquals(EnrollmentError.Rejection.INVALID, EnrollmentTransport.rejectionFor(403, "installation-suspended-x"))
        assertEquals(EnrollmentError.Rejection.INVALID, EnrollmentTransport.rejectionFor(403, ""))
        assertEquals(EnrollmentError.Rejection.REVOKED, EnrollmentTransport.rejectionFor(403, "installation-revoked"))
    }
}
