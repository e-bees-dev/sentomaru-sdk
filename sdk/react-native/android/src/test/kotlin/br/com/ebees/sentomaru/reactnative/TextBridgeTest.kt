package br.com.ebees.sentomaru.reactnative

import br.com.ebees.sentomaru.hybrid.SentomaruTextBridge
import br.com.ebees.sentomaru.hybrid.TextBridgeJson
import org.json.JSONArray
import org.json.JSONObject
import org.junit.Assert.assertEquals
import org.junit.Assert.assertThrows
import org.junit.Assert.assertTrue
import org.junit.Test

/**
 * D-22c: the pure logic the generic text bridge (Unity, chiefly; `hybrid-core`'s `SentomaruTextBridge` and
 * `TextBridgeJson`) adds over the shared `SentomaruBridge`. Hosted here, not duplicated in Capacitor/Cordova, because
 * it is genuinely shared core logic (unlike the small per-layer `SealedReader` adapters) and `testDebugUnitTest` of
 * this module is the one `.github/workflows/ci.yml` already runs (`react-native/android/build.gradle.kts` via the
 * Flutter sample's gradlew).
 *
 * What is NOT tested here: a real `call()` round trip through `SentomaruBridge.onMethodCall` → `Handler.post`. The
 * Android unit-test stub jar makes `Looper.getMainLooper()` return null and `Handler.post` a no-op, so no reply is
 * ever delivered outside Robolectric or a device/instrumented test — the same limitation `sign`/`initialize` already
 * had in `SentomaruBridge`; nothing new here. The timeout test below exercises exactly that path on purpose: it
 * proves `call()` gives up and returns rather than hanging forever when no reply ever arrives.
 */
class TextBridgeTest {
    @Test fun argumentsParsesAJsonObjectAndDecodesTheCanonicalBody() {
        val args = TextBridgeJson.arguments("""{"body":"AP8Q","operation":"op","n":3,"flag":true,"nothing":null,"list":[1,2],"map":{"k":"v"}}""")
        assertTrue(args["body"] is ByteArray)
        assertEquals(listOf<Byte>(0, -1, 16), (args["body"] as ByteArray).toList())
        assertEquals("op", args["operation"])
        assertEquals(3, args["n"])
        assertEquals(true, args["flag"])
        assertTrue(args.containsKey("nothing") && args["nothing"] == null)
        assertEquals(listOf(1, 2), args["list"])
        assertEquals(mapOf("k" to "v"), args["map"])
    }

    @Test fun noArgumentsIsAnEmptyObjectText() {
        assertEquals(emptyMap<String, Any?>(), TextBridgeJson.arguments("{}"))
    }

    @Test fun aNonCanonicalBodyIsRefused() {
        assertThrows(IllegalArgumentException::class.java) { TextBridgeJson.arguments("""{"body":"AP8Q=="}""") } // extra padding
    }

    @Test fun anythingThatIsNotAJsonObjectIsRefused() {
        for (bad in listOf("not json", "[]", "\"x\"", "3", "null")) {
            assertThrows(bad, Exception::class.java) { TextBridgeJson.arguments(bad) }
        }
    }

    @Test fun successReplyPutsBytesAsBase64AndConvertsCollectionsElementByElement() {
        val text = TextBridgeJson.successReply(mapOf("header" to byteArrayOf(0, -1, 16), "n" to 3, "list" to listOf("a", "b"), "nothing" to null))
        val value = JSONObject(text).getJSONObject("value")
        assertEquals("AP8Q", value.getString("header"))
        assertEquals(3, value.getInt("n"))
        assertEquals(listOf("a", "b"), (value.getJSONArray("list")).let { (0 until it.length()).map(it::getString) })
        assertTrue(value.isNull("nothing"))
    }

    @Test fun successAndErrorRepliesNeverShareAKey() {
        val success = JSONObject(TextBridgeJson.successReply("x"))
        val error = JSONObject(TextBridgeJson.errorReply("ChannelError", "boom"))
        assertTrue(success.has("value") && !success.has("code"))
        assertTrue(error.has("code") && error.has("message") && !error.has("value"))
        assertEquals("ChannelError", error.getString("code"))
        assertEquals("boom", error.getString("message"))
    }

    @Test fun errorReplyFallsBackToTheCodeWhenThereIsNoMessage() {
        assertEquals("X", JSONObject(TextBridgeJson.errorReply("X", null)).getString("message"))
    }

    @Test fun aScalarByteArrayRoundTripsThroughArgumentsAndSuccessReply() {
        val bytes = byteArrayOf(1, 2, 3, 4, 5)
        val reply = TextBridgeJson.successReply(bytes)
        val encoded = JSONObject(reply).getString("value")
        val decoded = TextBridgeJson.arguments("""{"body":"$encoded"}""")["body"] as ByteArray
        assertEquals(bytes.toList(), decoded.toList())
    }

    // SentomaruTextBridge.call itself needs a real android.content.Context (the constructor calls
    // `context.applicationContext`, stubbed to null under the unit-test jar) and a real Looper to ever get a reply
    // (see the class doc above): neither is testable here. What IS verified, without either: `call()` run off a
    // background thread (never the main one) does not throw the main-thread guard and does not hang forever — it
    // gives up at the timeout and returns the documented shape, exactly what protects Unity's UI thread in the field
    // if the native side never answers.
    @Test fun aCallThatNeverGetsAReplyTimesOutRatherThanHangingForever() {
        var text: String? = null
        val thread = Thread {
            val bridge = SentomaruTextBridge(NullContext)
            text = bridge.call("state", "{}", timeoutMs = 50)
        }
        thread.start()
        thread.join(5_000)
        assertTrue("the call thread did not finish within the join timeout", !thread.isAlive)
        val reply = JSONObject(requireNotNull(text))
        assertEquals("ChannelError", reply.getString("code"))
        assertEquals("timeout", reply.getString("message"))
    }
}

/** A `Context` whose only method this test's path reaches, `getApplicationContext()`, answers itself: enough for
 * `SentomaruTextBridge`'s constructor and for `SentomaruBridge.context` to hold something non-null, without the real
 * Android framework (every other `Context` method would hit the "not mocked" stub). */
private object NullContext : android.content.ContextWrapper(null) {
    override fun getApplicationContext(): android.content.Context = this
}
