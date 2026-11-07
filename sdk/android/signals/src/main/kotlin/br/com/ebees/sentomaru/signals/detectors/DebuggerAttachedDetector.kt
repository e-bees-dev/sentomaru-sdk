package br.com.ebees.sentomaru.signals.detectors

import android.content.Context
import br.com.ebees.sentomaru.signals.*
import java.time.Clock

/** D-05: JDWP debugger connected or awaited. Java debugger only; ptrace and native debuggers are D-19. */
class DebuggerAttachedDetector(
    private val clock: Clock = Clock.systemUTC(),
    private val env: PlatformEnvironment = AndroidPlatformEnvironment,
) : SignalDetector {
    override val capabilityId = "debugger_attached"
    override val version = "1.0.0"
    override val budgetMs = 5L

    override fun detect(context: Context): SignalObservation =
        Evidence.collect(capabilityId, version, clock.instant().toString()) { e ->
            e.check("jdwp_connected") { env.isDebuggerConnected() }
            e.check("jdwp_waiting") { env.isWaitingForDebugger() }
        }
}
