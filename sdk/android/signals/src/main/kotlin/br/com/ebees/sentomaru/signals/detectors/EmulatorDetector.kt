package br.com.ebees.sentomaru.signals.detectors

import android.content.Context
import br.com.ebees.sentomaru.signals.*
import java.time.Clock

class EmulatorDetector(
    private val clock: Clock = Clock.systemUTC(),
    private val env: PlatformEnvironment = AndroidPlatformEnvironment,
) : SignalDetector {
    override val capabilityId = "emulator_detected"
    override val version = "1.0.0"
    override val budgetMs = 5L

    override fun detect(context: Context): SignalObservation {
        val now = clock.instant().toString()
        return try {
            val props = env.buildProperties()
            val matched = mutableListOf<String>()

            val fingerprint = props["FINGERPRINT"] ?: ""
            if (fingerprint.startsWith("generic") || fingerprint.startsWith("unknown")) matched.add("fingerprint")

            val model = props["MODEL"] ?: ""
            if (model.contains("google_sdk", ignoreCase = true) ||
                model.contains("Emulator", ignoreCase = true) ||
                model.contains("Android SDK built for", ignoreCase = true)) matched.add("model")

            val hardware = props["HARDWARE"] ?: ""
            if (hardware.contains("goldfish", ignoreCase = true) ||
                hardware.contains("ranchu", ignoreCase = true)) matched.add("hardware")

            val product = props["PRODUCT"] ?: ""
            if (product.contains("sdk", ignoreCase = true) ||
                product.contains("google_sdk", ignoreCase = true) ||
                product.contains("sdk_x86", ignoreCase = true) ||
                product.contains("vbox86p", ignoreCase = true)) matched.add("product")

            val manufacturer = props["MANUFACTURER"] ?: ""
            if (manufacturer.contains("Genymotion", ignoreCase = true)) matched.add("manufacturer")

            val state = if (matched.isNotEmpty()) SignalState.DETECTED else SignalState.NOT_DETECTED
            SignalObservation(
                capabilityId = capabilityId,
                version = version,
                state = state,
                source = "client_observed",
                observedAt = now,
                detail = mapOf(
                    "matched_indicators" to if (matched.isEmpty()) "none" else matched.joinToString(","),
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
