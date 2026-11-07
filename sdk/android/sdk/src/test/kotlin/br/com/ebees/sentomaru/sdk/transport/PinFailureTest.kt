package br.com.ebees.sentomaru.sdk.transport

import org.junit.Assert.*
import org.junit.Test
import java.io.EOFException
import java.io.IOException
import java.net.ConnectException
import java.net.SocketTimeoutException
import java.security.cert.CertificateException
import java.security.cert.CertificateExpiredException
import javax.net.ssl.SSLException
import javax.net.ssl.SSLHandshakeException
import javax.net.ssl.SSLPeerUnverifiedException
import javax.net.ssl.SSLProtocolException

/**
 * D-07d: the classification of a TLS failure (only the cause chain, only the platform's pin message gives
 * `pin_mismatch`) and the meta-data reader (exactly the CLI's format, anything else is no host at all).
 */
class PinFailureTest {
    private fun handshake(cause: Throwable?) = SSLHandshakeException("handshake").apply { cause?.let(::initCause) }

    @Test
    fun thePlatformPinMessageAnywhereInTheChainIsAPinMismatch() {
        val pin = CertificateException(PinFailure.PLATFORM_PIN_MESSAGE)
        assertEquals("pin_mismatch", PinFailure.classify(handshake(pin)))
        assertEquals("pin_mismatch", PinFailure.classify(IOException("wrapped", handshake(pin))))
        assertEquals("pin_mismatch", PinFailure.classify(pin))
        // Same message on another type is not the platform's pin check.
        assertEquals("tls_other", PinFailure.classify(handshake(IllegalStateException(PinFailure.PLATFORM_PIN_MESSAGE))))
        assertEquals("tls_untrusted", PinFailure.classify(handshake(CertificateException("Pin verification failed."))))
        assertEquals("tls_untrusted", PinFailure.classify(handshake(CertificateException("pin verification failed"))))
    }

    @Test
    fun otherCertificateFailuresAreUntrustedOtherTlsFailuresAreOther() {
        assertEquals("tls_untrusted", PinFailure.classify(handshake(CertificateException("Trust anchor for certification path not found."))))
        assertEquals("tls_untrusted", PinFailure.classify(handshake(CertificateExpiredException("expired"))))
        assertEquals("tls_untrusted", PinFailure.classify(SSLPeerUnverifiedException("Hostname api.example not verified")))
        assertEquals("tls_untrusted", PinFailure.classify(SSLPeerUnverifiedException("Certificate pinning failure!")))
        assertEquals("tls_untrusted", PinFailure.classify(handshake(java.security.cert.CertPathValidatorException("Trust anchor for certification path not found."))))
        assertEquals("tls_other", PinFailure.classify(handshake(null)))
        assertEquals("tls_other", PinFailure.classify(SSLProtocolException("protocol")))
        assertEquals("tls_other", PinFailure.classify(SSLException("Unsupported or unrecognized SSL message")))
        assertEquals("tls_other", PinFailure.classify(handshake(EOFException())))
    }

    @Test
    fun aFailureWithoutTlsIsNotClassified() {
        for (e in listOf(IOException("x"), ConnectException("refused"), SocketTimeoutException(), EOFException(),
                IOException("wrapped", IllegalStateException())))
            assertNull(e.toString(), PinFailure.classify(e))
    }

    @Test
    fun aCyclicOrVeryLongChainEnds() {
        val a = IOException("a")
        val b = SSLException("b", a)
        a.initCause(b)
        assertEquals("tls_other", PinFailure.classify(a))
        var deep: Throwable = CertificateException(PinFailure.PLATFORM_PIN_MESSAGE)
        repeat(20) { deep = IOException("level", deep) }
        assertNull("beyond the bounded depth the chain is not read", PinFailure.classify(deep))
    }

    @Test
    fun theMetaDataInTheCliFormatIsRead() {
        assertEquals(setOf("lab-pin.sentomaru.com.br"), PinnedHosts.parse("lab-pin.sentomaru.com.br").hosts)
        assertEquals(listOf("b.example", "a.example", "x-1.y.example"), PinnedHosts.parse("b.example,a.example,x-1.y.example").hosts.toList())
        val sixteen = (1..16).joinToString(",") { "h$it.example" }
        assertEquals(16, PinnedHosts.parse(sixteen).hosts.size)
    }

    @Test
    fun anythingElseIsNoHostAtAll() {
        val seventeen = (1..17).joinToString(",") { "h$it.example" }
        for (bad in listOf(null, "", ",", "a.example,", ",a.example", "a.example, b.example", "a.example;b.example", "A.example",
                "10.0.0.1", "a.example,a.example", "a.example.", "*.example", "https://a.example", "a.example:443",
                seventeen, "-a.example", "a_b.example"))
            assertTrue(bad.toString(), PinnedHosts.parse(bad).isEmpty)
    }

    @Test
    fun aRequestHostMatchesOnlyThePinnedNameItself() {
        val pinned = PinnedHosts.parse("api.example,lab-pin.sentomaru.com.br")
        assertEquals("api.example", pinned.match("api.example"))
        assertEquals("api.example", pinned.match("API.Example"))
        assertEquals("api.example", pinned.match("api.example."))
        assertNull(pinned.match("sub.api.example"))
        assertNull(pinned.match("example"))
        assertNull(pinned.match("api.example.evil"))
        assertNull(PinnedHosts.NONE.match("api.example"))
    }
}
