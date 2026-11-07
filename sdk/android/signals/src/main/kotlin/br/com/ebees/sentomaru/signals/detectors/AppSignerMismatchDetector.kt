package br.com.ebees.sentomaru.signals.detectors

import android.content.Context
import br.com.ebees.sentomaru.signals.*
import java.time.Clock

/**
 * D-12c (D-13, declared): every signing-certificate digest the app reads against [expectedDigests], the SHA-256 of the
 * certificates the app is expected to be signed with (whole rotation lineage; with Play App Signing, Google's). Sends
 * only `result` (`match`, `mismatch`, `no_reference`, `unreadable`) and the counts `signers` and `unexpected`, never a
 * digest. A failed read is UNKNOWN, never NOT_DETECTED.
 *
 * [expectedDigests] accepts lowercase or uppercase hex, with or without `:` separators (keytool form); anything that is
 * not a SHA-256 throws `IllegalArgumentException` when the detector is built.
 */
class AppSignerMismatchDetector(
    expectedDigests: Collection<String>,
    private val clock: Clock = Clock.systemUTC(),
    private val env: PlatformEnvironment = AndroidPlatformEnvironment,
) : SignalDetector {
    override val capabilityId = "app_signer_mismatch"
    override val version = "1.0.0"
    override val budgetMs = 15L

    private val expected: Set<String> = expectedDigests.map { digest ->
        normalize(digest) ?: throw IllegalArgumentException("expected signer digest is not a SHA-256")
    }.toSet()

    override fun detect(context: Context): SignalObservation {
        val observedAt = clock.instant().toString()
        return try {
            if (expected.isEmpty()) return observation(SignalState.UNKNOWN, observedAt, mapOf("result" to "no_reference"))
            val read = try {
                env.signingCertificateDigests(context)
            } catch (e: Exception) {
                if (e is InterruptedException) Thread.currentThread().interrupt()
                null
            } catch (_: LinkageError) {
                null
            }
            val digests = read?.map { normalize(it) }
            if (digests.isNullOrEmpty() || digests.any { it == null })
                return observation(SignalState.UNKNOWN, observedAt, mapOf("result" to "unreadable"))
            val unexpected = digests.count { it !in expected }
            val state = if (unexpected > 0) SignalState.DETECTED else SignalState.NOT_DETECTED
            observation(state, observedAt, linkedMapOf(
                "result" to if (unexpected > 0) "mismatch" else "match",
                "signers" to digests.size.toString(),
                "unexpected" to unexpected.toString(),
            ))
        } catch (e: Exception) {
            if (e is InterruptedException) Thread.currentThread().interrupt()
            SignalObservation(capabilityId, version, SignalState.ERROR, "client_observed", observedAt)
        }
    }

    private fun observation(state: SignalState, observedAt: String, detail: Map<String, String>) =
        SignalObservation(capabilityId, version, state, "client_observed", observedAt, detail)

    companion object {
        private val SHA256 = Regex("[0-9a-f]{64}")

        internal fun normalize(digest: String): String? =
            digest.replace(":", "").lowercase().takeIf { SHA256.matches(it) }
    }
}
