package br.com.ebees.sentomaru.signals

import android.view.MotionEvent
import java.util.concurrent.atomic.AtomicBoolean
import java.util.concurrent.atomic.AtomicInteger

/**
 * D-24b: counts the touches that reached the app through an obscured window (`FLAG_WINDOW_IS_OBSCURED`, or
 * `FLAG_WINDOW_IS_PARTIALLY_OBSCURED`), only on the screens the app marks. The app calls [onTouch] from the
 * `dispatchTouchEvent` of each marked screen (a payment or login screen, never the whole app); a screen it does not
 * mark is never counted, which is the approved scope of the ficha. Only ACTION_DOWN counts: one gesture is one touch.
 * Counts live in memory and are read (and cleared) by the `overlay` detector: one collection window is the time between
 * two snapshots. No event, coordinate, window title or package name is kept.
 *
 * D-27: the same call also notes, as one boolean, whether any touch of the window was injected (an accessibility event
 * flag, API 33, or a virtual input device id): read by `synthetic_input` as the indicator `injected_touch`. Which of the
 * two marks fired is not kept, so assistive-technology use is not separated from other injection.
 */
class ObscuredTouchMonitor {
    private val touches = AtomicInteger()
    private val obscured = AtomicInteger()
    private val injected = AtomicBoolean()

    /** Thin wrapper over [record]; never throws. */
    fun onTouch(event: MotionEvent) {
        try {
            record(event.actionMasked == MotionEvent.ACTION_DOWN, event.flags, event.deviceId)
        } catch (_: Exception) {
            // a broken event costs only this touch
        }
    }

    internal fun record(isDown: Boolean, flags: Int, deviceId: Int = 0) {
        if (!isDown) return
        increment(touches)
        if ((flags and OBSCURED_MASK) != 0) increment(obscured)
        if ((flags and ACCESSIBILITY_EVENT) != 0 || deviceId < 0) injected.set(true)
    }

    /** Counts saturate at [MAX_COUNT]: a flood of touches cannot overflow the counter or grow the reported detail. */
    private fun increment(counter: AtomicInteger) { counter.updateAndGet { if (it >= MAX_COUNT) MAX_COUNT else it + 1 } }

    /** Gives back a window the collector discarded (deadline overrun, failed read); adds to what arrived meanwhile. */
    internal fun restore(window: Window) {
        touches.updateAndGet { minOf(MAX_COUNT.toLong(), it.toLong() + window.touches).toInt() }
        obscured.updateAndGet { minOf(MAX_COUNT.toLong(), it.toLong() + window.obscured).toInt() }
    }

    internal fun restoreInjected() { injected.set(true) }

    /** Whether a touch of the window that ends now was injected, then clears it. */
    internal fun drainInjected(): Boolean = injected.getAndSet(false)

    /** The counts of the window that ends now, then clears them. */
    internal fun drain(): Window = Window(touches.getAndSet(0), obscured.getAndSet(0))

    internal data class Window(val touches: Int, val obscured: Int)

    companion object {
        /** Shared by the SDK collector and the app's marked screens. */
        val shared = ObscuredTouchMonitor()

        /** Ceiling of `touches` and `obscured` in one window. */
        const val MAX_COUNT = 9999

        // MotionEvent.FLAG_WINDOW_IS_OBSCURED (0x1) | FLAG_WINDOW_IS_PARTIALLY_OBSCURED (0x2, API 29)
        private const val OBSCURED_MASK = 0x1 or 0x2

        // MotionEvent.FLAG_IS_ACCESSIBILITY_EVENT (0x800, API 33); a negative device id is a virtual input device
        private const val ACCESSIBILITY_EVENT = 0x800
    }
}
