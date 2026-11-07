package br.com.ebees.sentomaru.perf

import android.os.StrictMode
import androidx.test.ext.junit.runners.AndroidJUnit4
import androidx.test.platform.app.InstrumentationRegistry
import br.com.ebees.sentomaru.signals.SignalState
import br.com.ebees.sentomaru.signals.SignalsCatalog
import br.com.ebees.sentomaru.signals.SignalsCollector
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test
import org.junit.runner.RunWith

/**
 * D-05b on a device (opt-in, with the D-05c run): the D-05 collection never does its disk reads on the main thread.
 * StrictMode with penaltyDeath on the main thread kills the process (failing the test) if a detector reads a file
 * there; the collector must refuse the main thread before any detector runs. Off the main thread all twelve
 * capabilities are collected within 3 KiB.
 */
@RunWith(AndroidJUnit4::class)
class SignalsStrictModeInstrumentedTest {
    private val instrumentation = InstrumentationRegistry.getInstrumentation()
    private val context = instrumentation.targetContext

    private fun rasp() = SignalsCollector(
        detectors = SignalsCollector.defaultDetectors() + SignalsCollector.raspDetectors(),
        deadlineMs = SignalsCollector.RASP_DEADLINE_MS,
    )

    @Test
    fun collectionOnTheMainThreadIsRefusedUnderStrictMode() {
        var refused: Throwable? = null
        instrumentation.runOnMainSync {
            val previous = StrictMode.getThreadPolicy()
            StrictMode.setThreadPolicy(StrictMode.ThreadPolicy.Builder().detectAll().penaltyDeath().build())
            try {
                rasp().snapshot(context)
            } catch (e: IllegalStateException) {
                refused = e
            } finally {
                StrictMode.setThreadPolicy(previous)
            }
        }
        assertTrue("collection on the main thread must be refused", refused != null)
    }

    @Test
    fun collectionOffTheMainThreadReturnsAllTwelve() {
        val snapshot = rasp().snapshot(context)
        assertEquals(SignalsCatalog.CAPABILITIES.map { it.capabilityId }, snapshot.observations.map { it.capabilityId })
        assertTrue(snapshot.observations.none { it.state == SignalState.ERROR })
        assertTrue(snapshot.toJson().toByteArray(Charsets.UTF_8).size <= 3072)
    }
}
