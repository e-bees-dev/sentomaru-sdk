package br.com.ebees.sentomaru.reactnative

import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Assert.assertSame
import org.junit.Assert.assertTrue
import org.junit.Test

class BridgeValuesTest {
    @Test fun theBodyOfSignComesInAsBase64() {
        val out = BridgeValues.arguments(mapOf("body" to "AQID", "method" to "POST"))
        assertArrayEquals(byteArrayOf(1, 2, 3), out["body"] as ByteArray)
        assertEquals("POST", out["method"])
    }

    @Test fun onlyTheBodyIsDecoded() {
        assertEquals("AQID", BridgeValues.arguments(mapOf("key" to "AQID"))["key"])
    }

    @Test fun bytesGoOutAsBase64AndNestedValuesAreConverted() {
        assertEquals("AQID", BridgeValues.reply(byteArrayOf(1, 2, 3)))
        assertEquals(mapOf("a" to listOf("AQ==", 7)), BridgeValues.reply(mapOf("a" to listOf(byteArrayOf(1), 7))))
        val plain = "text"
        assertSame(plain, BridgeValues.reply(plain))
        assertEquals(null, BridgeValues.reply(null))
    }

    // Revisão A (G-02), RN-01: `ReadableMap.toHashMap()` entrega todo número do JavaScript como Double. O núcleo só aceita
    // Int/Long em playIntegrityCloudProjectNumber e reattestationMinIntervalSeconds, então um inteiro vindo do RN
    // seria sempre ConfigurationError.
    @Test fun integralNumbersFromJavaScriptReachTheCoreAsLong() {
        val out = BridgeValues.arguments(mapOf("playIntegrityCloudProjectNumber" to 123456789012.0,
            "reattestationMinIntervalSeconds" to 3600.0, "rotationGracePeriodDays" to 7.5,
            "challenge" to mapOf("expiresAtEpochMs" to 1.7e12), "allowedHosts" to listOf("a.example"), "strongBox" to true))
        assertEquals(123456789012L, out["playIntegrityCloudProjectNumber"])
        assertEquals(3600L, out["reattestationMinIntervalSeconds"])
        assertEquals(7.5, out["rotationGracePeriodDays"]) // not integral: stays a Double, the core refuses it
        assertEquals(1700000000000L, (out["challenge"] as Map<*, *>)["expiresAtEpochMs"])
        assertEquals(listOf("a.example"), out["allowedHosts"])
        assertEquals(true, out["strongBox"])
    }

    @Test fun aBodyThatIsNotCanonicalBase64IsRefused() {
        for (bad in listOf(" AQID", "AQID\n", "AQI", "AQID=", "-_8=", "AR==")) {
            val refused = try { BridgeValues.arguments(mapOf("body" to bad)); false } catch (e: IllegalArgumentException) { true }
            assertTrue(bad, refused)
        }
        assertArrayEquals(byteArrayOf(1, 2, 3), BridgeValues.arguments(mapOf("body" to "AQID"))["body"] as ByteArray)
    }
}
