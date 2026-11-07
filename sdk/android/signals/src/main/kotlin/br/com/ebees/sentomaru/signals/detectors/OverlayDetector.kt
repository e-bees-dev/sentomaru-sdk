package br.com.ebees.sentomaru.signals.detectors

import android.content.Context
import br.com.ebees.sentomaru.signals.*
import java.time.Clock

/**
 * D-24b: touches that reached a marked screen through an obscured window ([ObscuredTouchMonitor]). One collection
 * window = the time since the previous read. `result=obscured` (DETECTED, with `obscured` and `touches` counts),
 * `clear` (NOT_DETECTED: marked-screen touches arrived and none was obscured) or `no_touches` (UNKNOWN: no touch on a
 * marked screen in the window, so nothing was measured). The count of a window is cleared by the read and saturates at
 * [ObscuredTouchMonitor.MAX_COUNT]; if the collector discards the read (deadline overrun) the counts are given back.
 */
class OverlayDetector(
    private val monitor: ObscuredTouchMonitor = ObscuredTouchMonitor.shared,
    private val clock: Clock = Clock.systemUTC(),
) : SignalDetector {
    override val capabilityId = "overlay"
    override val version = "1.0.0"
    override val budgetMs = 1L
    @Volatile private var lastWindow: ObscuredTouchMonitor.Window? = null

    override fun discarded() { lastWindow?.let { monitor.restore(it) }; lastWindow = null }

    override fun detect(context: Context): SignalObservation {
        val observedAt = clock.instant().toString()
        return try {
            val window = monitor.drain()
            lastWindow = window
            when {
                window.obscured > 0 -> SignalObservation(capabilityId, version, SignalState.DETECTED, "client_observed",
                    observedAt, linkedMapOf("result" to "obscured", "obscured" to window.obscured.toString(),
                        "touches" to window.touches.toString()))
                window.touches > 0 -> SignalObservation(capabilityId, version, SignalState.NOT_DETECTED, "client_observed",
                    observedAt, linkedMapOf("result" to "clear", "obscured" to "0", "touches" to window.touches.toString()))
                else -> SignalObservation(capabilityId, version, SignalState.UNKNOWN, "client_observed", observedAt,
                    linkedMapOf("result" to "no_touches"))
            }
        } catch (e: Exception) {
            discarded()
            if (e is InterruptedException) Thread.currentThread().interrupt()
            SignalObservation(capabilityId, version, SignalState.ERROR, "client_observed", observedAt)
        }
    }
}
