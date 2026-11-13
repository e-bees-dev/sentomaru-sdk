package br.com.ebees.sentomaru.g03

import android.graphics.PixelFormat
import android.hardware.display.DisplayManager
import android.media.ImageReader
import android.os.SystemClock
import android.view.Display
import androidx.test.ext.junit.runners.AndroidJUnit4
import br.com.ebees.sentomaru.signals.detectors.ScreenSharedDetector
import org.junit.Test
import org.junit.runner.RunWith

/**
 * G-03 P-5 (D-27 RAT-01): a `VirtualDisplay` created by the app itself, and what the public API shows of it. The ficha of D-27 keeps the
 * virtual display OUT of the `screen_shared` reasons until this measures which public flags it carries; this fixture only MEASURES, it
 * never asserts a verdict (what the device says is the result).
 *
 * Cases (run each with `-e class ...VirtualDisplayDeviceTest#<name>`):
 *  - `p5_flags`: creates a private, a public and a presentation virtual display in turn, lists `DisplayManager.getDisplays()` with the
 *    flags of each (id, `Display.FLAG_*` bit values only, never the display name) and the `screen_shared` reasons the detector gives.
 *  - `p5_cost`: 200 reads of `ScreenSharedDetector` with one virtual display alive; reports p50 and p95 in milliseconds (target of RAT-01: p95 <= 2 ms).
 */
@RunWith(AndroidJUnit4::class)
class VirtualDisplayDeviceTest {
    private val context = G03Support.context
    private val manager = context.getSystemService(DisplayManager::class.java)

    /** Runs [block] with a virtual display of [flags]; a refusal of the platform (no permission for a mirroring or public display) is a measured result, not a failure. */
    private fun withVirtualDisplay(name: String, flags: Int, block: () -> Unit) {
        val reader = ImageReader.newInstance(320, 240, PixelFormat.RGBA_8888, 2)
        try {
            val display = try {
                manager.createVirtualDisplay("g03-p5", 320, 240, 160, reader.surface, flags)
            } catch (e: SecurityException) {
                G03Support.report("P-5", "MEASURED", "case=$name flags=$flags refused=SecurityException")
                return
            }
            try { block() } finally { display?.release() }
        } finally { reader.close() }
    }

    private fun describeDisplays(): String = manager.displays.joinToString(";") {
        "id=${it.displayId} default=${it.displayId == Display.DEFAULT_DISPLAY} flags=${it.flags}"
    }

    private fun reasons(): String {
        val observation = ScreenSharedDetector().detect(context)
        return "state=${observation.state} detail=${observation.detail.values.joinToString(",")}"
    }

    @Test fun p5_flags() {
        G03Support.report("P-5", "MEASURED", "case=baseline displays=[${describeDisplays()}] ${reasons()}")
        val own = DisplayManager.VIRTUAL_DISPLAY_FLAG_OWN_CONTENT_ONLY
        val public = DisplayManager.VIRTUAL_DISPLAY_FLAG_PUBLIC
        val cases = linkedMapOf(
            "private-mirror" to 0,
            "private-own-content" to own,
            "public-own-content" to (public or own),
            "presentation-own-content" to (public or DisplayManager.VIRTUAL_DISPLAY_FLAG_PRESENTATION or own),
        )
        for ((name, flags) in cases) {
            withVirtualDisplay(name, flags) {
                G03Support.report("P-5", "MEASURED", "case=$name displays=[${describeDisplays()}] ${reasons()}")
            }
        }
    }

    @Test fun p5_cost() {
        withVirtualDisplay("private-own-content", DisplayManager.VIRTUAL_DISPLAY_FLAG_OWN_CONTENT_ONLY) {
            val detector = ScreenSharedDetector()
            repeat(20) { detector.detect(context) }
            val millis = DoubleArray(200) {
                val start = SystemClock.elapsedRealtimeNanos()
                detector.detect(context)
                (SystemClock.elapsedRealtimeNanos() - start) / 1_000_000.0
            }.sorted()
            G03Support.report("P-5", "MEASURED", "case=cost p50_ms=${"%.3f".format(millis[100])} p95_ms=${"%.3f".format(millis[190])} max_ms=${"%.3f".format(millis.last())}")
        }
    }
}
