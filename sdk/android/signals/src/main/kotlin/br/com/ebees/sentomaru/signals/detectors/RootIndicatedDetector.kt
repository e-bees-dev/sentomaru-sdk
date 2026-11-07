package br.com.ebees.sentomaru.signals.detectors

import android.content.Context
import br.com.ebees.sentomaru.signals.*
import java.time.Clock

class RootIndicatedDetector(
    private val clock: Clock = Clock.systemUTC(),
    private val env: PlatformEnvironment = AndroidPlatformEnvironment,
) : SignalDetector {
    override val capabilityId = "root_indicated"
    override val version = "1.0.0"
    override val budgetMs = 10L

    companion object {
        val SU_PATHS = listOf(
            "/system/app/Superuser.apk",
            "/sbin/su",
            "/system/bin/su",
            "/system/xbin/su",
            "/data/local/xbin/su",
            "/data/local/bin/su",
            "/system/sd/xbin/su",
            "/system/bin/failsafe/su",
            "/data/local/su",
        )
    }

    override fun detect(context: Context): SignalObservation {
        val now = clock.instant().toString()
        return try {
            val props = env.buildProperties()
            val tags = props["TAGS"] ?: ""
            val testKeys = tags.contains("test-keys")

            var suFound = false
            for (path in SU_PATHS) {
                if (env.fileExists(path)) {
                    suFound = true
                    break
                }
            }

            val state = if (testKeys || suFound) SignalState.DETECTED else SignalState.NOT_DETECTED
            SignalObservation(
                capabilityId = capabilityId,
                version = version,
                state = state,
                source = "client_observed",
                observedAt = now,
                detail = mapOf(
                    "test_keys" to testKeys.toString(),
                    "su_found" to suFound.toString(),
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
