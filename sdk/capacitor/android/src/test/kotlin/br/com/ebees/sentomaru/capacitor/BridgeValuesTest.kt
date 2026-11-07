package br.com.ebees.sentomaru.capacitor

import org.json.JSONArray
import org.json.JSONObject
import org.junit.Assert.*
import org.junit.Test

class BridgeValuesTest {
    @Test fun nullAndAbsentArgumentsAreEmpty() {
        assertEquals(emptyMap<String, Any?>(), BridgeValues.arguments(null))
        assertEquals(emptyMap<String, Any?>(), BridgeValues.arguments(JSONObject()))
    }

    @Test fun bodyArrivesAsBase64AndBecomesBytes() {
        val args = BridgeValues.arguments(JSONObject().put("body", "AP8Q").put("operation", "op"))
        assertArrayEquals(byteArrayOf(0, -1, 16), args["body"] as ByteArray)
        assertEquals("op", args["operation"])
    }

    @Test fun anotherStringNamedLikeDataIsLeftAlone() {
        assertEquals("AP8Q", BridgeValues.arguments(JSONObject().put("challenge", "AP8Q"))["challenge"])
    }

    @Test fun numbersBooleansNullsAndNestedValuesKeepTheirShape() {
        val raw = JSONObject().put("rotationGracePeriodDays", 3).put("playIntegrityCloudProjectNumber", 4_000_000_000L)
            .put("strongBox", true).put("fraction", 1.5).put("nothing", JSONObject.NULL)
            .put("allowedHosts", JSONArray().put("a.example.test").put("b.example.test"))
            .put("optional", JSONObject().put("k", "v").put("n", 2))
        val args = BridgeValues.arguments(raw)
        assertEquals(3, args["rotationGracePeriodDays"])
        assertEquals(4_000_000_000L, args["playIntegrityCloudProjectNumber"])
        assertEquals(true, args["strongBox"])
        assertEquals(1.5, args["fraction"])
        assertTrue(args.containsKey("nothing") && args["nothing"] == null)
        assertEquals(listOf("a.example.test", "b.example.test"), args["allowedHosts"])
        assertEquals(mapOf("k" to "v", "n" to 2), args["optional"])
    }

    @Test fun repliesBecomeJsonFriendlyValuesAndBytesBecomeBase64() {
        assertEquals("AP8Q", BridgeValues.reply(byteArrayOf(0, -1, 16)))
        assertEquals(JSONObject.NULL, BridgeValues.reply(null))
        assertEquals("s", BridgeValues.reply("s"))
        val map = BridgeValues.reply(mapOf("a" to 1, "b" to listOf("x", byteArrayOf(1)), "c" to setOf("y"))) as JSONObject
        assertEquals(1, map.getInt("a"))
        assertEquals("x", map.getJSONArray("b").getString(0))
        assertEquals("AQ==", map.getJSONArray("b").getString(1))
        assertEquals("y", map.getJSONArray("c").getString(0))
    }

    @Test fun aBodyThatIsNotCanonicalBase64IsRefused() {
        for (bad in listOf(" AQID", "AQID\n", "AQI", "AQID=", "-_8=", "AR==")) {
            val refused = try { BridgeValues.arguments(JSONObject().put("body", bad)); false } catch (e: IllegalArgumentException) { true }
            assertTrue(bad, refused)
        }
        assertArrayEquals(byteArrayOf(1, 2, 3), BridgeValues.arguments(JSONObject().put("body", "AQID"))["body"] as ByteArray)
    }
}
