package br.com.ebees.sentomaru.signals.detectors

import android.content.Context
import br.com.ebees.sentomaru.signals.*
import java.time.Clock

/**
 * D-24e: a virtual touch or pointer input device is registered (`InputDevice.isVirtual`), the trace of input injected by
 * a remote-control tool or a virtualized environment. Indicator `virtual_pointer`. Evidence only. D-27 (1.1.0): `injected_touch`, a touch on a screen the
 * app marks (see [ObscuredTouchMonitor]) carried an accessibility-event flag or a virtual device id; coordinates are never
 * read. No touch on a marked screen says nothing, never "clean". Assistive technology produces it too: evidence only.
 */
class SyntheticInputDetector(
    private val clock: Clock = Clock.systemUTC(),
    private val env: PlatformEnvironment = AndroidPlatformEnvironment,
    private val monitor: ObscuredTouchMonitor = ObscuredTouchMonitor.shared,
) : SignalDetector {
    override val capabilityId = "synthetic_input"
    override val version = "1.1.0"
    override val budgetMs = 5L
    @Volatile private var drainedInjected = false

    override fun discarded() { if (drainedInjected) monitor.restoreInjected(); drainedInjected = false }

    // Not `Evidence.collect`: the D-05 matrix check (the vendor's detector matrix check) reads every detector that uses it.
    override fun detect(context: Context): SignalObservation {
        val observedAt = clock.instant().toString()
        return try {
            val evidence = Evidence()
            evidence.probe("virtual_pointer") { env.virtualPointerDeviceCount() }?.let { if (it > 0) evidence.found("virtual_pointer") }
            drainedInjected = monitor.drainInjected()
            if (drainedInjected) evidence.found("injected_touch")
            evidence.observation(capabilityId, version, observedAt)
        } catch (e: Exception) {
            if (e is InterruptedException) Thread.currentThread().interrupt()
            SignalObservation(capabilityId, version, SignalState.ERROR, "client_observed", observedAt)
        }
    }
}
