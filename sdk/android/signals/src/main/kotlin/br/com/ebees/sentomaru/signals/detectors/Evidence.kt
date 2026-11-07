package br.com.ebees.sentomaru.signals.detectors

import br.com.ebees.sentomaru.signals.SignalObservation
import br.com.ebees.sentomaru.signals.SignalState

/**
 * Checks of one D-05 detector run. Each check has a fixed code: it lands in `indicators` when it found something and
 * in `partial` when it could not run. DETECTED when any check found an indicator; otherwise UNKNOWN when any check did
 * not run; NOT_DETECTED only when every check ran and found nothing. `detail` carries only these codes, never a path,
 * package name, device property or identifier.
 */
internal class Evidence {
    private val indicators = LinkedHashSet<String>()
    private val partial = LinkedHashSet<String>()

    /**
     * One platform call. A call that throws is a known measurement failure: the check did not run (null). A linkage
     * failure (a class or method missing on this device or in an old environment binary) counts the same way; an
     * interrupt is kept on the thread.
     */
    fun <T : Any> probe(code: String, call: () -> T): T? = try {
        call()
    } catch (e: Exception) {
        notRun(code, e)
        null
    } catch (e: LinkageError) {
        notRun(code, e)
        null
    }

    fun found(code: String) {
        indicators += code
    }

    /** A check that could not run (its input was not available, or the call failed). */
    fun notRun(code: String, cause: Throwable? = null) {
        if (cause is InterruptedException) Thread.currentThread().interrupt()
        partial += code
    }

    /** A check that answers for one value: indicator when true, `partial` when the call failed. */
    fun check(code: String, call: () -> Boolean) {
        if (probe(code, call) == true) found(code)
    }

    /**
     * A check answered from a read that was cut at its cap (only a prefix was seen): a hit in the prefix is a real indicator
     * (the file does contain it), a miss proves nothing about the rest, so the check did not run.
     */
    fun cut(code: String, presentInPrefix: Boolean) {
        if (presentInPrefix) found(code) else notRun(code)
    }

    /** A check over several items (paths, packages, classes): indicator when any item is present, even if another
     * item could not be measured; `partial` when none is present and some item could not be measured. */
    fun <T> anyOf(code: String, items: List<T>, present: (T) -> Boolean) {
        var unmeasured = false
        for (item in items) {
            val answer = try {
                present(item)
            } catch (e: Exception) {
                if (e is InterruptedException) Thread.currentThread().interrupt()
                unmeasured = true
                continue
            } catch (_: LinkageError) {
                unmeasured = true
                continue
            }
            if (answer) {
                found(code)
                return
            }
        }
        if (unmeasured) partial += code
    }

    fun observation(capabilityId: String, version: String, observedAt: String): SignalObservation {
        val state = when {
            indicators.isNotEmpty() -> SignalState.DETECTED
            partial.isNotEmpty() -> SignalState.UNKNOWN
            else -> SignalState.NOT_DETECTED
        }
        val detail = linkedMapOf<String, String>("indicators" to if (indicators.isEmpty()) "none" else indicators.joinToString(","))
        if (partial.isNotEmpty()) detail["partial"] = partial.joinToString(",")
        return SignalObservation(
            capabilityId = capabilityId,
            version = version,
            state = state,
            source = "client_observed",
            observedAt = observedAt,
            detail = detail,
        )
    }

    companion object {
        /** Runs the checks; an unexpected exception in the detector itself (not in a platform call) is ERROR. */
        fun collect(
            capabilityId: String,
            version: String,
            observedAt: String,
            checks: (Evidence) -> Unit,
        ): SignalObservation = try {
            Evidence().also(checks).observation(capabilityId, version, observedAt)
        } catch (e: Exception) {
            if (e is InterruptedException) Thread.currentThread().interrupt()
            SignalObservation(
                capabilityId = capabilityId,
                version = version,
                state = SignalState.ERROR,
                source = "client_observed",
                observedAt = observedAt,
            )
        }
    }
}
