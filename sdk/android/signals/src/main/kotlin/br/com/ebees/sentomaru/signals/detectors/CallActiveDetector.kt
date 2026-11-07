package br.com.ebees.sentomaru.signals.detectors

import android.content.Context
import br.com.ebees.sentomaru.signals.*
import java.time.Clock

/**
 * F-08 (consultive, declared): the system audio mode says a call (`MODE_IN_CALL`, 2) or a communication session
 * (`MODE_IN_COMMUNICATION`, 3) is in progress. Reads `AudioManager.getMode()` only: no telephony permission, nothing
 * about the call. Result codes only: `cellular`, `communication` (DETECTED), `none` (NOT_DETECTED: normal 0, ringing 1,
 * call screening 4), `partial` (UNKNOWN: the read failed or the mode is one the SDK does not know). Evidence only.
 */
class CallActiveDetector(
    private val clock: Clock = Clock.systemUTC(),
    private val env: PlatformEnvironment = AndroidPlatformEnvironment,
) : SignalDetector {
    override val capabilityId = "call_active"
    override val version = "1.0.0"
    override val budgetMs = 1L

    override fun detect(context: Context): SignalObservation {
        val observedAt = clock.instant().toString()
        fun obs(state: SignalState, result: String) = SignalObservation(
            capabilityId, version, state, "client_observed", observedAt, linkedMapOf("result" to result),
        )
        return try {
            when (env.audioMode(context)) {
                2 -> obs(SignalState.DETECTED, "cellular")
                3 -> obs(SignalState.DETECTED, "communication")
                0, 1, 4 -> obs(SignalState.NOT_DETECTED, "none")
                else -> obs(SignalState.UNKNOWN, "partial")
            }
        } catch (e: Exception) {
            if (e is InterruptedException) Thread.currentThread().interrupt()
            if (e is SecurityException || e is IllegalStateException || e is UnsupportedOperationException || e is java.io.IOException)
                obs(SignalState.UNKNOWN, "partial")
            else SignalObservation(capabilityId, version, SignalState.ERROR, "client_observed", observedAt)
        }
    }
}
