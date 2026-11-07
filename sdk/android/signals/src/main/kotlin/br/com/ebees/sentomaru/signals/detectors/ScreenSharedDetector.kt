package br.com.ebees.sentomaru.signals.detectors

import android.content.Context
import br.com.ebees.sentomaru.signals.*
import java.time.Clock

/**
 * D-20 (consultive, declared): the screen may be shown or recorded outside the device. Indicators, all from public
 * APIs: `presentation_display` (a visible display flagged as a presentation display), `secondary_display` (any other
 * visible display that is not the default one) and `screen_recording` (API 35, the platform reports a recording that
 * shows the app's windows). A display or recording that cannot be read is `partial`: below API 35 `screen_recording` is
 * never measured, so a device with no display found is UNKNOWN there, never NOT_DETECTED. Only fixed codes go in detail,
 * never a display name, id or the package that created it. Evidence only.
 */
class ScreenSharedDetector(
    private val clock: Clock = Clock.systemUTC(),
    private val env: PlatformEnvironment = AndroidPlatformEnvironment,
) : SignalDetector {
    override val capabilityId = "screen_shared"
    override val version = "1.0.0"
    override val budgetMs = 3L

    // Not `Evidence.collect`: the D-05 matrix check (verification/check_rasp_matrix.py) reads every detector that uses it.
    override fun detect(context: Context): SignalObservation {
        val observedAt = clock.instant().toString()
        return try {
            val evidence = Evidence()
            evidence.probe("display") { env.visibleDisplays(context) }?.let { displays ->
                if (displays.any { it.presentation }) evidence.found("presentation_display")
                if (displays.any { !it.isDefault && !it.presentation }) evidence.found("secondary_display")
            }
            evidence.probe("screen_recording") { env.screenRecordingVisible() }?.let {
                if (it) evidence.found("screen_recording")
            }
            evidence.observation(capabilityId, version, observedAt)
        } catch (e: Exception) {
            if (e is InterruptedException) Thread.currentThread().interrupt()
            SignalObservation(capabilityId, version, SignalState.ERROR, "client_observed", observedAt)
        }
    }
}
