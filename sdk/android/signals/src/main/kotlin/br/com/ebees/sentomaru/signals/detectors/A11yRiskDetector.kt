package br.com.ebees.sentomaru.signals.detectors

import android.content.Context
import br.com.ebees.sentomaru.signals.*
import java.time.Clock

/**
 * D-24a: enabled accessibility services against the list of risky packages of the scope (configuration of the app).
 * Reduces the services to an enum, never a name: `result=none` (no service enabled, NOT_DETECTED), `listed` (at
 * least one enabled service is on the list, DETECTED) or `unlisted_present` (services enabled, none on the list,
 * UNKNOWN: they are not judged, and a screen reader of a user with a disability is the common case). A legitimate
 * assistive service on the list is a false positive: evidence only, never a deny reason on its own.
 */
class A11yRiskDetector(
    private val riskyPackages: Collection<String>,
    private val clock: Clock = Clock.systemUTC(),
    private val env: PlatformEnvironment = AndroidPlatformEnvironment,
) : SignalDetector {
    override val capabilityId = "a11y_risk"
    override val version = "1.0.0"
    override val budgetMs = 5L

    private val risky = riskyPackages.toSet()

    override fun detect(context: Context): SignalObservation {
        val observedAt = clock.instant().toString()
        return try {
            val enabled = try {
                env.enabledAccessibilityServicePackages(context)
            } catch (e: Exception) {
                if (e is InterruptedException) Thread.currentThread().interrupt()
                null
            } catch (_: LinkageError) {
                null
            }
            when {
                enabled == null -> SignalObservation(capabilityId, version, SignalState.UNKNOWN, "client_observed", observedAt,
                    linkedMapOf("partial" to "services"))
                enabled.isEmpty() -> SignalObservation(capabilityId, version, SignalState.NOT_DETECTED, "client_observed",
                    observedAt, linkedMapOf("result" to "none"))
                enabled.any { it in risky } -> SignalObservation(capabilityId, version, SignalState.DETECTED, "client_observed",
                    observedAt, linkedMapOf("result" to "listed"))
                else -> SignalObservation(capabilityId, version, SignalState.UNKNOWN, "client_observed", observedAt,
                    linkedMapOf("result" to "unlisted_present"))
            }
        } catch (e: Exception) {
            if (e is InterruptedException) Thread.currentThread().interrupt()
            SignalObservation(capabilityId, version, SignalState.ERROR, "client_observed", observedAt)
        }
    }
}
