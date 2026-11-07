package br.com.ebees.sentomaru.signer

import java.security.KeyPairGenerator
import java.security.Signature
import java.security.spec.ECGenParameterSpec
import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Assert.assertThrows
import org.junit.Assert.assertTrue
import org.junit.Test

/**
 * JVM tests for the DER <-> P1363 converter. Cross-checked against the JDK SunEC provider,
 * which (unlike Android) exposes SHA256withECDSAinP1363Format as an independent oracle.
 */
class EcdsaSignatureFormatTest {

    private fun hex(s: String): ByteArray =
        s.replace(" ", "").chunked(2).map { it.toInt(16).toByte() }.toByteArray()

    private fun filled(b: Int, n: Int) = ByteArray(n) { b.toByte() }

    // r = 0x80..(32 bytes, high bit set -> DER needs 0x00 pad), s = 0x01 (1 byte).
    private val rHigh = byteArrayOf(0x80.toByte()) + filled(0x11, 31)
    private val vectorHighRShortS = hex("30 26 02 21 00") + rHigh + hex("02 01 01")
    private val p1363HighRShortS = rHigh + (ByteArray(31) + byteArrayOf(1))

    // r = 31-byte value (leading zero byte stripped by DER), s = 32 bytes no high bit.
    private val r31 = filled(0x7f, 31)
    private val s32 = filled(0x22, 32)
    private val vectorShortR = hex("30 43 02 1f") + r31 + hex("02 20") + s32
    private val p1363ShortR = byteArrayOf(0) + r31 + s32

    @Test
    fun fixedVectorsConvertBothWays() {
        assertArrayEquals(p1363HighRShortS, EcdsaSignatureFormat.derToP1363(vectorHighRShortS))
        assertArrayEquals(vectorHighRShortS, EcdsaSignatureFormat.p1363ToDer(p1363HighRShortS))
        assertArrayEquals(p1363ShortR, EcdsaSignatureFormat.derToP1363(vectorShortR))
        assertArrayEquals(vectorShortR, EcdsaSignatureFormat.p1363ToDer(p1363ShortR))
    }

    @Test
    fun rejectsMalformedDer() {
        // name to (input, exact error message) — the message proves which check fired.
        val bad = listOf(
            "empty" to (ByteArray(0) to "not a DER SEQUENCE"),
            "trailing byte" to (vectorShortR + byteArrayOf(0) to "SEQUENCE length mismatch"),
            "trailing data inside SEQUENCE" to (hex("30 07 02 01 01 02 01 01 00") to "trailing data"),
            "wrong outer tag" to (hex("31") + vectorShortR.copyOfRange(1, vectorShortR.size) to "not a DER SEQUENCE"),
            "outer length mismatch" to (hex("30 44") + vectorShortR.copyOfRange(2, vectorShortR.size) to "SEQUENCE length mismatch"),
            "long-form length" to (hex("30 81 06 02 01 01 02 01 01") to "long-form length not allowed"),
            "non-minimal r" to (hex("30 07 02 02 00 01 02 01 01") to "non-minimal INTEGER"),
            "non-minimal s" to (hex("30 07 02 01 01 02 02 00 01") to "non-minimal INTEGER"),
            "negative r" to (hex("30 06 02 01 81 02 01 01") to "negative INTEGER"),
            "negative s" to (hex("30 06 02 01 01 02 01 81") to "negative INTEGER"),
            "zero r" to (hex("30 06 02 01 00 02 01 01") to "zero INTEGER"),
            "zero s" to (hex("30 06 02 01 01 02 01 00") to "zero INTEGER"),
            "zero-length INTEGER" to (hex("30 05 02 00 02 01 01") to "invalid INTEGER length"),
            "33-byte INTEGER with 0x00 prefix" to (hex("30 27 02 22 00") + filled(0x80, 33) + hex("02 01 01") to "INTEGER too long"),
            "33-byte INTEGER without 0x00 prefix" to (hex("30 26 02 21") + filled(0x01, 33) + hex("02 01 01") to "INTEGER too long"),
            "wrong integer tag" to (hex("30 06 04 01 01 02 01 01") to "expected INTEGER"),
            "missing s" to (hex("30 03 02 01 01") to "truncated INTEGER header"),
            "truncated INTEGER" to (hex("30 04 02 05 01 02") to "truncated INTEGER"),
        )
        for ((name, case) in bad) {
            val (der, fragment) = case
            val e = assertThrows(name, IllegalArgumentException::class.java) {
                EcdsaSignatureFormat.derToP1363(der)
            }
            assertEquals(name, fragment, e.message)
        }
    }

    @Test
    fun rejectsMalformedP1363() {
        assertThrows(IllegalArgumentException::class.java) { EcdsaSignatureFormat.p1363ToDer(ByteArray(63)) }
        assertThrows(IllegalArgumentException::class.java) { EcdsaSignatureFormat.p1363ToDer(ByteArray(65)) }
        assertThrows(IllegalArgumentException::class.java) { EcdsaSignatureFormat.p1363ToDer(ByteArray(64)) }
        assertThrows("only r zero", IllegalArgumentException::class.java) {
            EcdsaSignatureFormat.p1363ToDer(ByteArray(32) + filled(0x01, 32))
        }
        assertThrows("only s zero", IllegalArgumentException::class.java) {
            EcdsaSignatureFormat.p1363ToDer(filled(0x01, 32) + ByteArray(32))
        }
    }

    @Test
    fun derFromJdkConvertsToP1363VerifiableByJdk() {
        val kpg = KeyPairGenerator.getInstance("EC")
        kpg.initialize(ECGenParameterSpec("secp256r1"))
        val kp = kpg.generateKeyPair()
        val message = "sentomaru-p0 signature base".toByteArray()
        var sawShortComponent = false
        repeat(2000) {
            val der = Signature.getInstance("SHA256withECDSA").run {
                initSign(kp.private); update(message); sign()
            }
            val p1363 = EcdsaSignatureFormat.derToP1363(der)
            assertEquals(64, p1363.size)
            if (p1363[0] == 0.toByte() || p1363[32] == 0.toByte()) sawShortComponent = true
            val ok = Signature.getInstance("SHA256withECDSAinP1363Format").run {
                initVerify(kp.public); update(message); verify(p1363)
            }
            assertTrue("P1363 from DER must verify", ok)
            assertArrayEquals(der, EcdsaSignatureFormat.p1363ToDer(p1363))
        }
        // Probabilistic (miss chance ~(255/256)^4000 < 1e-6); documents that short components were exercised.
        assertTrue("expected at least one r/s with a leading zero byte", sawShortComponent)
    }

    @Test
    fun p1363FromJdkConvertsToDerVerifiableByJdk() {
        val kpg = KeyPairGenerator.getInstance("EC")
        kpg.initialize(ECGenParameterSpec("secp256r1"))
        val kp = kpg.generateKeyPair()
        val message = byteArrayOf(1, 2, 3)
        repeat(100) {
            val p1363 = Signature.getInstance("SHA256withECDSAinP1363Format").run {
                initSign(kp.private); update(message); sign()
            }
            val der = EcdsaSignatureFormat.p1363ToDer(p1363)
            val ok = Signature.getInstance("SHA256withECDSA").run {
                initVerify(kp.public); update(message); verify(der)
            }
            assertTrue(ok)
        }
    }
}
