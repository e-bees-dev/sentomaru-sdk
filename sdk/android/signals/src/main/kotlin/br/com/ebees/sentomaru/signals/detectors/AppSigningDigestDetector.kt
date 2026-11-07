package br.com.ebees.sentomaru.signals.detectors

import android.content.Context
import br.com.ebees.sentomaru.signals.*
import java.time.Clock

class AppSigningDigestDetector(
    private val clock: Clock = Clock.systemUTC(),
    private val env: PlatformEnvironment = AndroidPlatformEnvironment,
) : SignalDetector {
    override val capabilityId = "app_signing_digest"
    override val version = "1.0.0"
    override val budgetMs = 15L

    override fun detect(context: Context): SignalObservation {
        val now = clock.instant().toString()
        return try {
            val digests = env.getAppSigningCertificateDigests(context)
            if (digests.isNotEmpty()) {
                SignalObservation(
                    capabilityId = capabilityId,
                    version = version,
                    state = SignalState.DETECTED,
                    source = "client_observed",
                    observedAt = now,
                    detail = mapOf(
                        "sha256" to digests.first(),
                    ),
                )
            } else {
                SignalObservation(
                    capabilityId = capabilityId,
                    version = version,
                    state = SignalState.UNKNOWN,
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
