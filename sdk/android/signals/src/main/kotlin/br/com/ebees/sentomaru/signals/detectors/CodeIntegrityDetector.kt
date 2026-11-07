package br.com.ebees.sentomaru.signals.detectors

import android.content.Context
import android.os.Looper
import br.com.ebees.sentomaru.signals.*
import java.time.Clock
import java.util.concurrent.ExecutionException
import java.util.concurrent.RejectedExecutionException
import java.util.concurrent.TimeUnit
import java.util.concurrent.TimeoutException

/**
 * D-12c (D-12, declared): the aggregate of `apk-code-sha256-v1` over the installed APKs, for the server to compare with
 * the registered `codeDigests`. The SDK never decides: the state is always UNKNOWN (catalog `supportedStates` has no
 * DETECTED nor NOT_DETECTED, so the API reads a forged clean state as UNKNOWN too), with `reason`:
 *
 * - `not_compared`, plus `algorithm`, `aggregate` (lowercase hex64) and `files` (count): computed;
 * - `timeout`: the hash did not finish within [waitMs]; it goes on in the background ([cache]) for the next collection;
 * - `partial`, plus `cause` (a fixed code of [ApkCodeDigests.Result.Refused], `apk_list`, `executor` or `hash_failed`):
 *   not computed;
 * - `main_thread`: called on the main thread, where it never hashes nor waits.
 *
 * ERROR only for an unexpected exception in the detector itself.
 */
class CodeIntegrityDetector @JvmOverloads constructor(
    private val clock: Clock = Clock.systemUTC(),
    private val env: PlatformEnvironment = AndroidPlatformEnvironment,
    private val cache: CodeDigestCache = CodeDigestCache.shared,
    private val waitMs: Long = DEFAULT_WAIT_MS,
    private val onMainThread: () -> Boolean = ::isAndroidMainThread,
) : SignalDetector {
    override val capabilityId = "code_integrity"
    override val version = "1.0.0"
    override val budgetMs = 15L

    init {
        require(waitMs >= 0) { "waitMs must not be negative" }
    }

    override fun detect(context: Context): SignalObservation {
        val observedAt = clock.instant().toString()
        return try {
            if (onMainThread()) return unknown(observedAt, "main_thread")
            val apks = try {
                env.installedApks(context).also { if (it.files.isEmpty()) throw IllegalStateException("no APK") }
            } catch (e: Exception) {
                if (e is InterruptedException) Thread.currentThread().interrupt()
                return unknown(observedAt, "partial", "apk_list")
            } catch (_: LinkageError) {
                return unknown(observedAt, "partial", "apk_list")
            }
            val future = try { cache.resultFor(apks) } catch (_: RejectedExecutionException) {
                return unknown(observedAt, "partial", "executor")
            }
            val result = try {
                future.get(waitMs, TimeUnit.MILLISECONDS)
            } catch (_: TimeoutException) {
                return unknown(observedAt, "timeout")
            } catch (_: InterruptedException) {
                Thread.currentThread().interrupt()
                return unknown(observedAt, "timeout")
            } catch (_: ExecutionException) {
                return unknown(observedAt, "partial", "hash_failed")
            }
            when (result) {
                is ApkCodeDigests.Result.Computed -> SignalObservation(capabilityId, version, SignalState.UNKNOWN,
                    "client_observed", observedAt, linkedMapOf("reason" to "not_compared",
                        "algorithm" to ApkCodeDigests.ALGORITHM, "aggregate" to result.aggregate,
                        "files" to result.files.size.toString()))
                is ApkCodeDigests.Result.Refused -> unknown(observedAt, "partial", result.cause)
            }
        } catch (e: Exception) {
            if (e is InterruptedException) Thread.currentThread().interrupt()
            SignalObservation(capabilityId, version, SignalState.ERROR, "client_observed", observedAt)
        }
    }

    private fun unknown(observedAt: String, reason: String, cause: String? = null): SignalObservation {
        val detail = linkedMapOf("reason" to reason)
        cause?.let { detail["cause"] = it }
        return SignalObservation(capabilityId, version, SignalState.UNKNOWN, "client_observed", observedAt, detail)
    }

    companion object {
        /** How long one collection waits for the hash: the warm budget proposed for D-12d. */
        const val DEFAULT_WAIT_MS = 15L

        private fun isAndroidMainThread(): Boolean = Looper.getMainLooper()?.isCurrentThread == true
    }
}
