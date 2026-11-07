package br.com.ebees.sentomaru.signals

import android.content.Context
import br.com.ebees.sentomaru.signals.detectors.ScreenCaptureDetector
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test
import java.io.File
import java.time.Clock
import java.time.Instant
import java.time.ZoneOffset

/**
 * D-22c: the first link of the Kotlin to C# chain. The `screen_capture` detector, driven by the ops of
 * contracts/sdk/hybrid-bridge-v1-vectors.json, must produce exactly the observation the vector states; the same file is read by the
 * bridge core test (sdk/cordova, `snapshotReply`) and by the C# tests (`SignalsReader`), so a change on either side shows on all.
 */
class HybridBridgeVectorsTest {
    private val vectors: Map<String, Any?> by lazy {
        val path = System.getProperty("sentomaru.hybridBridgeVectors") ?: error("sentomaru.hybridBridgeVectors not set")
        @Suppress("UNCHECKED_CAST")
        StrictJson.parse(File(path).readText()) as Map<String, Any?>
    }
    private val context: Context = object : android.content.ContextWrapper(null) {}

    @Suppress("UNCHECKED_CAST")
    private fun list(value: Any?) = value as List<Map<String, Any?>>

    @Test
    fun theVectorsAreWrittenForThisCatalog() {
        assertEquals(SignalsCatalog.VERSION, vectors["catalogVersion"])
    }

    @Test
    fun theDetectorProducesEachScreenCaptureObservationOfTheVectors() {
        val cases = list(vectors["screenCapture"])
        assertTrue(cases.size >= 8)
        for (case in cases) {
            val name = case["name"] as String
            val clock = Clock.fixed(Instant.parse(vectors["collectedAt"] as String), ZoneOffset.UTC)
            val monitor = ScreenCaptureMonitor().apply { scopeAll = case["scope"] == "all" }
            for (op in case["ops"] as List<*>) when (op) {
                "arm" -> monitor.arm(true)
                "arm_other" -> monitor.arm(false)
                "capture" -> monitor.onCapture(true)
                "capture_other" -> monitor.onCapture(false)
                else -> error("$name: unknown op $op")
            }
            val env = ScreenSignalsTest.ScreenEnv(sdk = (case["sdk"] as Long).toInt())
            val got = ScreenCaptureDetector(monitor, clock, env).detect(context)
            val want = case["observation"] as Map<*, *>
            assertEquals(name, want["capabilityId"], got.capabilityId)
            assertEquals(name, want["version"], got.version)
            assertEquals(name, want["state"], got.state.name)
            assertEquals(name, want["source"], got.source)
            assertEquals(name, want["observedAt"], got.observedAt)
            assertEquals(name, want["detail"], got.detail)
        }
    }
}
