package br.com.ebees.sentomaru.signals.detectors

import android.content.Context
import br.com.ebees.sentomaru.signals.*
import java.time.Clock

/**
 * D-12c (D-13, declared): the installer as a fixed class, never a package name. A value signal: DETECTED with
 * `class` (installingPackageName) and `initiator` (initiatingPackageName), each `play`, `none` or `other`; UNKNOWN
 * with `class=unknown` when `InstallSourceInfo` is absent (Android 9 and 10) or the lookup failed. Never NOT_DETECTED.
 * The mapping is provisional until the D-12d measures adb and the system package installer on a device.
 */
class InstallerClassDetector(
    private val clock: Clock = Clock.systemUTC(),
    private val env: PlatformEnvironment = AndroidPlatformEnvironment,
) : SignalDetector {
    override val capabilityId = "installer_class"
    override val version = "1.0.0"
    override val budgetMs = 5L

    override fun detect(context: Context): SignalObservation {
        val observedAt = clock.instant().toString()
        return try {
            val source = try {
                env.installSource(context)
            } catch (e: Exception) {
                if (e is InterruptedException) Thread.currentThread().interrupt()
                null
            } catch (_: LinkageError) {
                null
            }
            if (source == null) {
                SignalObservation(capabilityId, version, SignalState.UNKNOWN, "client_observed", observedAt,
                    linkedMapOf("class" to "unknown", "initiator" to "unknown"))
            } else {
                SignalObservation(capabilityId, version, SignalState.DETECTED, "client_observed", observedAt,
                    linkedMapOf("class" to classOf(source.installingPackageName), "initiator" to classOf(source.initiatingPackageName)))
            }
        } catch (e: Exception) {
            if (e is InterruptedException) Thread.currentThread().interrupt()
            SignalObservation(capabilityId, version, SignalState.ERROR, "client_observed", observedAt)
        }
    }

    companion object {
        /** The Play Store package; the only one read as `play`. */
        const val PLAY_STORE = "com.android.vending"

        internal fun classOf(packageName: String?): String = when {
            packageName.isNullOrEmpty() -> "none"
            packageName == PLAY_STORE -> "play"
            else -> "other"
        }
    }
}
