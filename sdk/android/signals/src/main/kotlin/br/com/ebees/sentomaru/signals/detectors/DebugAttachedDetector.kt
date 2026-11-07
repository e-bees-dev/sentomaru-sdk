package br.com.ebees.sentomaru.signals.detectors

import android.content.Context
import br.com.ebees.sentomaru.signals.*
import java.time.Clock

class DebugAttachedDetector(
    private val clock: Clock = Clock.systemUTC(),
    private val env: PlatformEnvironment = AndroidPlatformEnvironment,
) : SignalDetector {
    override val capabilityId = "debug_attached"
    override val version = "1.0.0"
    override val budgetMs = 5L

    override fun detect(context: Context): SignalObservation {
        val now = clock.instant().toString()
        return try {
            val connected = env.isDebuggerConnected()
            val debuggable = env.isAppDebuggable(context)
            val state = if (connected || debuggable) SignalState.DETECTED else SignalState.NOT_DETECTED
            SignalObservation(
                capabilityId = capabilityId,
                version = version,
                state = state,
                source = "client_observed",
                observedAt = now,
                detail = mapOf(
                    "debugger_connected" to connected.toString(),
                    "app_debuggable" to debuggable.toString(),
                ),
            )
        } catch (_: Exception) {
            SignalObservation(
                capabilityId = capabilityId,
                version = version,
                state = SignalState.ERROR,
                source = "client_observed",
                observedAt = now,
            )
        }
    }
}
