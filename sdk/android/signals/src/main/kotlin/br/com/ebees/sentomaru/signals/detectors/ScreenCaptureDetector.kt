package br.com.ebees.sentomaru.signals.detectors

import android.content.Context
import br.com.ebees.sentomaru.signals.*
import java.time.Clock

/**
 * D-20 (consultive, declared): screenshots taken with a screen the app marked in front (`ScreenCaptureMonitor`, fed by
 * [ScreenShield], API 34). One collection window = the time since the previous read. `result=captured` (DETECTED, with
 * `captures` capped at 9), `none` (NOT_DETECTED: a marked screen was registered in the window and no capture came) or
 * `no_screens` (UNKNOWN: no marked screen was in front, so nothing was measured). Below API 34 the platform has no
 * callback: UNSUPPORTED. The count of a window is cleared by the read.
 */
class ScreenCaptureDetector(
    private val monitor: ScreenCaptureMonitor = ScreenCaptureMonitor.shared,
    private val clock: Clock = Clock.systemUTC(),
    private val env: PlatformEnvironment = AndroidPlatformEnvironment,
) : SignalDetector {
    override val capabilityId = "screen_capture"
    override val version = "1.1.0"
    override val budgetMs = 1L
    @Volatile private var lastWindow: ScreenCaptureMonitor.Window? = null

    override fun discarded() { lastWindow?.let { monitor.restore(it) }; lastWindow = null }

    override fun detect(context: Context): SignalObservation {
        val observedAt = clock.instant().toString()
        return try {
            val sdk = try {
                env.osVersion().first
            } catch (e: Exception) {
                if (e is InterruptedException) Thread.currentThread().interrupt()
                return SignalObservation(capabilityId, version, SignalState.UNKNOWN, "client_observed", observedAt,
                    linkedMapOf("result" to "no_screens"))
            }
            if (sdk < MIN_SDK) {
                return SignalObservation(capabilityId, version, SignalState.UNSUPPORTED, "client_observed", observedAt)
            }
            val window = monitor.drain()
            lastWindow = window
            // Scope `all` (opt-in): captures with an unmarked screen in front are a second number; scope `marked` (default)
            // keeps the 1.0.0 shape exactly.
            fun detail(result: String): LinkedHashMap<String, String> = linkedMapOf(
                "result" to result,
                "captures" to minOf(window.captures, MAX_REPORTED).toString(),
            ).also { if (window.scopeAll) it["captures_other"] = minOf(window.otherCaptures, MAX_REPORTED).toString() }
            when {
                window.captures > 0 || window.otherCaptures > 0 -> SignalObservation(capabilityId, version,
                    SignalState.DETECTED, "client_observed", observedAt, detail("captured"))
                window.screenSeen || window.otherSeen -> SignalObservation(capabilityId, version, SignalState.NOT_DETECTED,
                    "client_observed", observedAt, detail("none"))
                else -> SignalObservation(capabilityId, version, SignalState.UNKNOWN, "client_observed", observedAt,
                    linkedMapOf("result" to "no_screens"))
            }
        } catch (e: Exception) {
            discarded()
            if (e is InterruptedException) Thread.currentThread().interrupt()
            SignalObservation(capabilityId, version, SignalState.ERROR, "client_observed", observedAt)
        }
    }

    private companion object {
        const val MIN_SDK = 34
        const val MAX_REPORTED = 9
    }
}
