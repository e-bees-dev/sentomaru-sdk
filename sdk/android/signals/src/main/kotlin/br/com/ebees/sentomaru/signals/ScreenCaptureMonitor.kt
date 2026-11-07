package br.com.ebees.sentomaru.signals

import java.util.concurrent.atomic.AtomicBoolean
import java.util.concurrent.atomic.AtomicInteger

/**
 * D-20: what the [ScreenShield] saw on the screens the app marks. Counts screenshots taken while a marked screen was
 * in front (`Activity.ScreenCaptureCallback`, API 34), remembers whether any marked screen had the callback registered
 * in the window, and (API 35) the last state of the screen-recording callback. Everything lives in memory and is read
 * (and cleared) by the `screen_capture` detector: one collection window is the time between two snapshots. No image,
 * file, screen name or app name is kept.
 */
class ScreenCaptureMonitor {
    private val captures = AtomicInteger()
    private val armed = AtomicInteger()
    private val screensSeen = AtomicBoolean()
    private val otherCaptures = AtomicInteger()
    private val otherArmed = AtomicInteger()
    private val otherSeen = AtomicBoolean()

    /**
     * D-20 scope `all` (opt-in, set by [ScreenShield] when installed with [CaptureScope.ALL]): captures with a screen the
     * app did not mark in front are counted apart, as a number only (no screen name), and the detector reports them.
     */
    @Volatile
    internal var scopeAll: Boolean = false

    /** Last recording state reported by the platform (API 35); null = never reported. */
    @Volatile
    internal var recordingVisible: Boolean? = null

    internal fun onCapture(marked: Boolean = true) {
        (if (marked) captures else otherCaptures).updateAndGet { if (it >= MAX_COUNT) MAX_COUNT else it + 1 }
    }

    /** A screen registered the capture callback (a marked one, or an unmarked one in scope `all`). */
    internal fun arm(marked: Boolean = true) {
        if (marked) { armed.incrementAndGet(); screensSeen.set(true) } else { otherArmed.incrementAndGet(); otherSeen.set(true) }
    }

    /** A screen unregistered the capture callback (never below zero). */
    internal fun disarm(marked: Boolean = true) {
        (if (marked) armed else otherArmed).updateAndGet { if (it > 0) it - 1 else 0 }
    }

    /** The window that ends now: captures and whether a screen was registered at any time in it, then clears. */
    internal fun drain(): Window = Window(
        captures.getAndSet(0), screensSeen.getAndSet(armed.get() > 0),
        otherCaptures.getAndSet(0), otherSeen.getAndSet(otherArmed.get() > 0), scopeAll,
    )

    /** Gives back a window the collector discarded (deadline overrun, failed read): the captures return, the "was seen" mark too. */
    internal fun restore(window: Window) {
        captures.updateAndGet { minOf(MAX_COUNT.toLong(), it.toLong() + window.captures).toInt() }
        otherCaptures.updateAndGet { minOf(MAX_COUNT.toLong(), it.toLong() + window.otherCaptures).toInt() }
        if (window.screenSeen) screensSeen.set(true)
        if (window.otherSeen) otherSeen.set(true)
    }

    internal data class Window(
        val captures: Int,
        val screenSeen: Boolean,
        val otherCaptures: Int = 0,
        val otherSeen: Boolean = false,
        val scopeAll: Boolean = false,
    )

    companion object {
        /** Ceiling of the captures held between two reads. */
        const val MAX_COUNT = 9999

        /** Shared by the SDK collector and the app's [ScreenShield]. */
        val shared = ScreenCaptureMonitor()
    }
}
