package br.com.ebees.sentomaru.signals.detectors

import android.content.Context
import br.com.ebees.sentomaru.signals.*
import java.time.Clock

/** D-05: FLAG_DEBUGGABLE of the running app (debug build, or a release repackaged with the flag on). */
class AppDebuggableDetector(
    private val clock: Clock = Clock.systemUTC(),
    private val env: PlatformEnvironment = AndroidPlatformEnvironment,
) : SignalDetector {
    override val capabilityId = "app_debuggable"
    override val version = "1.0.0"
    override val budgetMs = 2L

    override fun detect(context: Context): SignalObservation =
        Evidence.collect(capabilityId, version, clock.instant().toString()) { e ->
            e.check("flag_debuggable") { env.isAppDebuggable(context) }
        }
}
