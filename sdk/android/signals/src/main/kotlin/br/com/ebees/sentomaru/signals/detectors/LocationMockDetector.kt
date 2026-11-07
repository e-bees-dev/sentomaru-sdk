package br.com.ebees.sentomaru.signals.detectors

import android.content.Context
import br.com.ebees.sentomaru.signals.*
import java.time.Clock

/**
 * F-07 (consultive, declared): the newest last known location the app can already read carries the platform's
 * mock-provider flag. The SDK never asks for the location permission and never starts a location request. Result codes
 * only: `mock_flagged` (DETECTED), `clean` (NOT_DETECTED, for that one fix), `no_permission` and `no_fix` (UNKNOWN: nothing
 * measured), `partial` (UNKNOWN: the read failed or the fix did not say its origin). A failure never gives NOT_DETECTED.
 * No coordinate, provider, accuracy or time is read into the observation. Evidence only.
 */
class LocationMockDetector(
    private val clock: Clock = Clock.systemUTC(),
    private val env: PlatformEnvironment = AndroidPlatformEnvironment,
) : SignalDetector {
    override val capabilityId = "location_mock"
    override val version = "1.0.0"
    override val budgetMs = 5L

    override fun detect(context: Context): SignalObservation {
        val observedAt = clock.instant().toString()
        fun obs(state: SignalState, result: String? = null) = SignalObservation(
            capabilityId, version, state, "client_observed", observedAt, if (result == null) emptyMap() else linkedMapOf("result" to result),
        )
        return try {
            if (env.osVersion().first < MIN_SDK) return obs(SignalState.UNSUPPORTED)
            val facts = env.lastKnownLocation(context)
            when {
                !facts.permission -> obs(SignalState.UNKNOWN, "no_permission")
                facts.fixAgeMs == null || facts.fixAgeMs > MAX_FIX_AGE_MS -> obs(SignalState.UNKNOWN, "no_fix")
                facts.mock == null -> obs(SignalState.UNKNOWN, "partial")
                facts.mock -> obs(SignalState.DETECTED, "mock_flagged")
                else -> obs(SignalState.NOT_DETECTED, "clean")
            }
        } catch (e: Exception) {
            if (e is InterruptedException) Thread.currentThread().interrupt()
            if (e is SecurityException || e is IllegalStateException || e is UnsupportedOperationException || e is java.io.IOException)
                obs(SignalState.UNKNOWN, "partial")
            else SignalObservation(capabilityId, version, SignalState.ERROR, "client_observed", observedAt)
        }
    }

    private companion object {
        const val MIN_SDK = 28
        const val MAX_FIX_AGE_MS = 10 * 60_000L
    }
}
