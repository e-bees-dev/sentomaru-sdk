package br.com.ebees.sentomaru.hybrid

import br.com.ebees.sentomaru.sdk.SentomaruClient
import br.com.ebees.sentomaru.sdk.SentomaruConfig
import br.com.ebees.sentomaru.sdk.SentomaruReattestation
import java.time.Duration

/**
 * Builds the native [SentomaruConfig] from channel arguments (R4). Nothing is defaulted: a missing or invalid
 * organization/app/environment/enrollmentUrl/allowedHosts is a typed `ConfigurationError`, never a silent fallback
 * to some scope. Only the rotation grace period has a documented default (7 days, decision E-rot).
 * C-04b: `playIntegrityCloudProjectNumber` is optional (absent = no Play Integrity token); when present it must be a
 * positive integer, otherwise `ConfigurationError`. J-04r: `renewalUrl` is optional too (https, allowlisted host).
 */
object PluginConfig {
    const val ERROR_CODE = "ConfigurationError"

    class Invalid : Exception(ERROR_CODE)

    fun parse(organization: Any?, app: Any?, environment: Any?, enrollmentUrl: Any?, allowedHosts: Any?,
        rotationGracePeriodDays: Any?, playIntegrityCloudProjectNumber: Any? = null, renewalUrl: Any? = null): SentomaruConfig {
        val hosts = (allowedHosts as? List<*>)?.map { it as? String ?: throw Invalid() }?.toSet()
        if (hosts.isNullOrEmpty()) throw Invalid()
        val graceDays = when (rotationGracePeriodDays) {
            null -> 7L
            is Number -> rotationGracePeriodDays.toLong()
            else -> throw Invalid()
        }
        val cloudProject = when (playIntegrityCloudProjectNumber) {
            null -> null
            is Int, is Long -> (playIntegrityCloudProjectNumber as Number).toLong().takeIf { it > 0 } ?: throw Invalid()
            else -> throw Invalid()
        }
        return try {
            SentomaruConfig(
                organization = text(organization),
                app = text(app),
                environment = text(environment),
                allowedHosts = hosts,
                enrollmentUrl = text(enrollmentUrl),
                rotationGracePeriod = Duration.ofDays(graceDays),
                playIntegrityCloudProjectNumber = cloudProject,
                renewalUrl = renewalUrl?.let(::text), // J-04r: absent = no renewal (pre-0.9 behaviour)
            )
        } catch (e: Invalid) {
            throw e
        } catch (_: Exception) {
            throw Invalid() // invalid slug, allowlist, URL or grace period (SentomaruConfig validation)
        }
    }

    /**
     * D-12e: the optional reattestation routes of the consumer (`contracts/api/reattestation-v1.md`). Both absent = no
     * reattestation (null, the pre-0.13 behaviour); one without the other, a non-positive or non-integer interval, or a
     * URL [SentomaruReattestation] refuses (not https, host outside the allowlist) = [Invalid]. Absent interval = the
     * SDK default (24 h).
     */
    class Reattestation(val challengeUrl: String, val submitUrl: String, val minIntervalSeconds: Long?)

    fun parseReattestation(challengeUrl: Any?, submitUrl: Any?, minIntervalSeconds: Any?): Reattestation? {
        if (challengeUrl == null && submitUrl == null && minIntervalSeconds == null) return null
        val interval = when (minIntervalSeconds) {
            null -> null
            is Int, is Long -> (minIntervalSeconds as Number).toLong().takeIf { it > 0 } ?: throw Invalid()
            else -> throw Invalid()
        }
        return Reattestation(text(challengeUrl), text(submitUrl), interval)
    }

    /** Builds the native [SentomaruReattestation] for [client]; a URL it refuses is [Invalid] (ConfigurationError). */
    fun reattestation(client: SentomaruClient, settings: Reattestation): SentomaruReattestation = try {
        val interval = settings.minIntervalSeconds?.let(Duration::ofSeconds) ?: SentomaruReattestation.DEFAULT_MIN_INTERVAL
        SentomaruReattestation(client, settings.challengeUrl, settings.submitUrl, interval)
    } catch (_: Exception) {
        throw Invalid()
    }

    private fun text(value: Any?): String = (value as? String)?.takeIf { it.isNotBlank() } ?: throw Invalid()
}
