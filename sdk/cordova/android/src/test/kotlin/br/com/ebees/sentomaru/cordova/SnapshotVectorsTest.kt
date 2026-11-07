package br.com.ebees.sentomaru.cordova

import br.com.ebees.sentomaru.hybrid.SentomaruBridge
import br.com.ebees.sentomaru.signals.SignalObservation
import br.com.ebees.sentomaru.signals.SignalState
import br.com.ebees.sentomaru.signals.SignalsSnapshot
import org.json.JSONArray
import org.json.JSONObject
import org.junit.Assert.assertEquals
import org.junit.Test
import java.io.File

/**
 * the second link of the Kotlin to C# chain. What the shared bridge core (`SentomaruBridge.snapshotReply`, the one every
 * hybrid layer sends over its channel) makes of an observation is exactly the `reply` of contracts/sdk/hybrid-bridge-v1-vectors.json,
 * which the C# `SignalsReader` reads and the signals module test (HybridBridgeVectorsTest) produces its observations from.
 */
class SnapshotVectorsTest {
    private val vectors: JSONObject by lazy {
        val path = System.getProperty("sentomaru.hybridBridgeVectors") ?: error("sentomaru.hybridBridgeVectors not set")
        JSONObject(File(path).readText())
    }

    private fun observation(o: JSONObject) = SignalObservation(
        capabilityId = o.getString("capabilityId"), version = o.getString("version"),
        state = SignalState.valueOf(o.getString("state")), source = o.getString("source"), observedAt = o.getString("observedAt"),
        detail = o.getJSONObject("detail").let { d -> d.keys().asSequence().associateWith { d.getString(it) } },
    )

    private fun check(name: String, observations: JSONArray, expected: JSONObject) {
        val snapshot = SignalsSnapshot(
            catalogVersion = vectors.getString("catalogVersion"), collectedAt = vectors.getString("collectedAt"),
            durationMs = vectors.getLong("durationMs"),
            observations = (0 until observations.length()).map { observation(observations.getJSONObject(it)) },
        )
        assertEquals(name, plain(expected), plain(SentomaruBridge.snapshotReply(snapshot)))
    }

    /** Maps, lists and text with integers as Long, so a parsed JSON file and the bridge's own map compare by value. */
    private fun plain(value: Any?): Any? = when (value) {
        is JSONObject -> value.keys().asSequence().associateWith { plain(value.get(it)) }
        is JSONArray -> (0 until value.length()).map { plain(value.get(it)) }
        is Map<*, *> -> value.entries.associate { (k, v) -> k as String to plain(v) }
        is List<*> -> value.map { plain(it) }
        is Number -> value.toLong()
        else -> value
    }

    @Test
    fun theBridgeCoreSendsTheReplyOfEveryVector() {
        val screen = vectors.getJSONArray("screenCapture")
        val snapshots = vectors.getJSONArray("snapshots")
        assertEquals(true, screen.length() >= 8 && snapshots.length() >= 4)
        for (i in 0 until screen.length()) {
            val c = screen.getJSONObject(i)
            check(c.getString("name"), JSONArray().put(c.getJSONObject("observation")), c.getJSONObject("reply"))
        }
        for (i in 0 until snapshots.length()) {
            val s = snapshots.getJSONObject(i)
            check(s.getString("name"), s.getJSONArray("observations"), s.getJSONObject("reply"))
        }
    }

    @Test
    fun theBytesRuleOfTheVectorsHoldsOnTheKotlinSideBothWays() {
        val bytes = vectors.getJSONArray("bytes")
        for (i in 0 until bytes.length()) {
            val v = bytes.getJSONObject(i)
            val raw = v.getString("hex").chunked(2).filter { it.isNotEmpty() }.map { it.toInt(16).toByte() }.toByteArray()
            assertEquals(v.getString("base64"), BridgeValues.reply(raw))
            org.junit.Assert.assertArrayEquals(raw, BridgeValues.arguments(JSONObject().put("body", v.getString("base64")))["body"] as ByteArray)
        }
    }

    @Test
    fun everyNonCanonicalBase64OfTheVectorsIsRefusedOnTheWayIn() {
        val bad = vectors.getJSONArray("bytesRejected")
        assertEquals(true, bad.length() >= 10)
        for (i in 0 until bad.length()) {
            val v = bad.getJSONObject(i)
            val refused = try {
                BridgeValues.arguments(JSONObject().put("body", v.getString("base64")))
                false
            } catch (e: IllegalArgumentException) {
                true
            }
            assertEquals(v.getString("name"), true, refused)
        }
    }
}
