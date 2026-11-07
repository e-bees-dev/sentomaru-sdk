package br.com.ebees.sentomaru.signals.detectors

import android.content.Context
import br.com.ebees.sentomaru.signals.*
import java.time.Clock

/**
 * D-24c: the default input method against the list of known keyboards of the scope (configuration of the app), reduced
 * to an enum, never the package. `result=known` (NOT_DETECTED), `unknown` (DETECTED: a third-party keyboard is common
 * and legitimate, so a weak signal, evidence only), `no_reference` (UNKNOWN: the app passed no list) or `partial`
 * (UNKNOWN: the setting could not be read, or none is set).
 */
class ImeUntrustedDetector(
    knownPackages: Collection<String>,
    private val clock: Clock = Clock.systemUTC(),
    private val env: PlatformEnvironment = AndroidPlatformEnvironment,
) : SignalDetector {
    override val capabilityId = "ime_untrusted"
    override val version = "1.0.0"
    override val budgetMs = 3L

    private val known = knownPackages.toSet()

    override fun detect(context: Context): SignalObservation {
        val observedAt = clock.instant().toString()
        if (known.isEmpty()) {
            return SignalObservation(capabilityId, version, SignalState.UNKNOWN, "client_observed", observedAt,
                linkedMapOf("result" to "no_reference"))
        }
        return try {
            val ime = try {
                env.defaultInputMethodPackage(context)
            } catch (e: Exception) {
                if (e is InterruptedException) Thread.currentThread().interrupt()
                null
            } catch (_: LinkageError) {
                null
            }
            when {
                ime == null -> SignalObservation(capabilityId, version, SignalState.UNKNOWN, "client_observed", observedAt,
                    linkedMapOf("partial" to "input_method"))
                ime in known -> SignalObservation(capabilityId, version, SignalState.NOT_DETECTED, "client_observed",
                    observedAt, linkedMapOf("result" to "known"))
                else -> SignalObservation(capabilityId, version, SignalState.DETECTED, "client_observed", observedAt,
                    linkedMapOf("result" to "unknown"))
            }
        } catch (e: Exception) {
            if (e is InterruptedException) Thread.currentThread().interrupt()
            SignalObservation(capabilityId, version, SignalState.ERROR, "client_observed", observedAt)
        }
    }
}
