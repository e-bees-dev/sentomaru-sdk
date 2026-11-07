package br.com.ebees.sentomaru.signals.detectors

import android.content.Context
import android.provider.Settings
import br.com.ebees.sentomaru.signals.*
import java.time.Clock

/** D-05: developer options or USB debugging on. A device setting, not an attack: context only. */
class DevSettingsEnabledDetector(
    private val clock: Clock = Clock.systemUTC(),
    private val env: PlatformEnvironment = AndroidPlatformEnvironment,
) : SignalDetector {
    override val capabilityId = "dev_settings_enabled"
    override val version = "1.0.0"
    override val budgetMs = 3L

    override fun detect(context: Context): SignalObservation =
        Evidence.collect(capabilityId, version, clock.instant().toString()) { e ->
            e.check("adb_enabled") { env.globalSettingOn(context, Settings.Global.ADB_ENABLED) }
            e.check("development_settings") {
                env.globalSettingOn(context, Settings.Global.DEVELOPMENT_SETTINGS_ENABLED)
            }
        }
}
