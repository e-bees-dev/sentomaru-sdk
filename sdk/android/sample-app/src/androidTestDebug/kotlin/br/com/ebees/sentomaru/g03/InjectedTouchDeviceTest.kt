package br.com.ebees.sentomaru.g03

import android.os.SystemClock
import android.view.InputDevice
import android.view.MotionEvent
import androidx.test.ext.junit.runners.AndroidJUnit4
import androidx.test.platform.app.InstrumentationRegistry
import br.com.ebees.sentomaru.signals.ObscuredTouchMonitor
import br.com.ebees.sentomaru.signals.detectors.SyntheticInputDetector
import org.junit.After
import org.junit.Assert.*
import org.junit.Before
import org.junit.Test
import org.junit.runner.RunWith
import android.content.Intent
import java.util.concurrent.TimeUnit

/**
 * G-03 P-4 (D-27 `injected_touch`): a touch on a screen the app "marks" (here
 * [TouchProbeActivity], which forwards touches to a private [ObscuredTouchMonitor]) and the `synthetic_input` detector reading it.
 *
 * Cases (run each with `-e class ...InjectedTouchDeviceTest#<name>`):
 *  - `p4_flag` and `p4_virtualDevice`: no human; the test dispatches a DOWN carrying FLAG_IS_ACCESSIBILITY_EVENT (0x800, API 33), or a negative device id. Asserts the indicator is set.
 *  - `p4_finger`: a human finger touches the probe within 60 s. Asserts the indicator is NOT set (a real touch is not injected).
 *  - `p4_adb`: the host runs `adb shell input tap X Y` within 60 s. MEASURES, does not assert: whether `input tap` is flagged is exactly what the device must tell.
 */
@RunWith(AndroidJUnit4::class)
class InjectedTouchDeviceTest {
    private val instrumentation = InstrumentationRegistry.getInstrumentation()
    private val monitor = ObscuredTouchMonitor()
    private var activity: TouchProbeActivity? = null

    @Before fun setUp() {
        TouchProbeActivity.downs.set(0)
        TouchProbeActivity.monitor = monitor
        val intent = Intent(instrumentation.targetContext, TouchProbeActivity::class.java).addFlags(Intent.FLAG_ACTIVITY_NEW_TASK)
        activity = instrumentation.startActivitySync(intent) as TouchProbeActivity
        instrumentation.waitForIdleSync()
    }

    @After fun tearDown() { TouchProbeActivity.monitor = null; activity?.finish() }

    private fun injectedIndicator(): Boolean {
        val observation = SyntheticInputDetector(monitor = monitor).detect(G03Support.context)
        return observation.detail.values.any { "injected_touch" in it }
    }

    private fun downEvent(flags: Int, deviceId: Int): MotionEvent {
        val now = SystemClock.uptimeMillis()
        val props = arrayOf(MotionEvent.PointerProperties().apply { id = 0; toolType = MotionEvent.TOOL_TYPE_FINGER })
        val coords = arrayOf(MotionEvent.PointerCoords().apply { x = 10f; y = 10f; pressure = 1f; size = 1f })
        // Public overload with `flags`: 0x800 is FLAG_IS_ACCESSIBILITY_EVENT (API 33).
        return MotionEvent.obtain(now, now, MotionEvent.ACTION_DOWN, 1, props, coords, 0, 0, 1f, 1f, deviceId, 0,
            InputDevice.SOURCE_TOUCHSCREEN, flags)
    }

    /** The accessibility flag, as a service that performs gestures sets it. */
    @Test fun p4_flag() {
        val event = downEvent(flags = 0x800, deviceId = 0)
        instrumentation.runOnMainSync { activity!!.dispatchTouchEvent(event) }
        event.recycle()
        assertTrue("an accessibility-flagged touch sets injected_touch", injectedIndicator())
        G03Support.report("P-4", "PASS", "case=flag")
    }

    /** A virtual input device (negative id), as a remote-control tool registers. */
    @Test fun p4_virtualDevice() {
        val event = downEvent(flags = 0, deviceId = -1)
        instrumentation.runOnMainSync { activity!!.dispatchTouchEvent(event) }
        event.recycle()
        assertTrue("a touch from a virtual device sets injected_touch", injectedIndicator())
        G03Support.report("P-4", "PASS", "case=virtual-device")
    }

    @Test fun p4_finger() = waitForOneTouchThenRead(expectInjected = false)

    @Test fun p4_adb() = waitForOneTouchThenRead(expectInjected = null)

    private fun waitForOneTouchThenRead(expectInjected: Boolean?) {
        // The detector drains the flag, so it is read only after the probe counted a DOWN.
        val deadline = SystemClock.elapsedRealtime() + TimeUnit.SECONDS.toMillis(60)
        while (SystemClock.elapsedRealtime() < deadline && TouchProbeActivity.downs.get() == 0) Thread.sleep(200)
        assertTrue("no touch reached the probe within 60 s", TouchProbeActivity.downs.get() > 0)
        val injected = injectedIndicator()
        if (expectInjected == null) G03Support.report("P-4", "MEASURED", "case=adb injected_touch=$injected")
        else {
            assertEquals("a real finger must not set injected_touch", expectInjected, injected)
            G03Support.report("P-4", "PASS", "case=finger injected_touch=$injected")
        }
    }
}
