package br.com.ebees.sentomaru.signals.detectors

import android.content.Context
import br.com.ebees.sentomaru.signals.*
import java.time.Clock

class OsVersionDetector(
    private val clock: Clock = Clock.systemUTC(),
    private val env: PlatformEnvironment = AndroidPlatformEnvironment,
) : SignalDetector {
    override val capabilityId = "os_version"
    override val version = "1.0.0"
    override val budgetMs = 5L

    override fun detect(context: Context): SignalObservation {
        val now = clock.instant().toString()
        return try {
            val (sdkInt, release) = env.osVersion()
            SignalObservation(
                capabilityId = capabilityId,
                version = version,
                state = SignalState.DETECTED,
                source = "client_observed",
                observedAt = now,
                detail = mapOf(
                    "sdk_int" to sdkInt.toString(),
                    "release" to release,
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
