package br.com.ebees.sentomaru.signals.detectors

import android.content.Context
import br.com.ebees.sentomaru.signals.*
import java.time.Clock

class InstallerSourceDetector(
    private val clock: Clock = Clock.systemUTC(),
    private val env: PlatformEnvironment = AndroidPlatformEnvironment,
) : SignalDetector {
    override val capabilityId = "installer_source"
    override val version = "1.0.0"
    override val budgetMs = 5L

    override fun detect(context: Context): SignalObservation {
        val now = clock.instant().toString()
        return try {
            val installer = env.getInstallerPackageName(context)
            if (installer != null && installer.isNotEmpty()) {
                SignalObservation(
                    capabilityId = capabilityId,
                    version = version,
                    state = SignalState.DETECTED,
                    source = "client_observed",
                    observedAt = now,
                    detail = mapOf(
                        "installer_package" to installer,
                    ),
                )
            } else {
                SignalObservation(
                    capabilityId = capabilityId,
                    version = version,
                    state = SignalState.NOT_DETECTED,
                    source = "client_observed",
                    observedAt = now,
                )
            }
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
