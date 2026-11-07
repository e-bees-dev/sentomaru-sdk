package br.com.ebees.sentomaru.signals

import android.content.Context

/**
 * Contract for a versioned signal detector.
 */
interface SignalDetector {
    val capabilityId: String
    val version: String
    val budgetMs: Long
    fun detect(context: Context): SignalObservation

    /**
     * The collector calls this when it threw away what [detect] returned (the deadline passed, or the detector failed after
     * reading). A detector that consumes state on read (the touch counts of D-24b) puts it back, so a late or failed
     * read does not erase a finding. Default: nothing to give back.
     */
    fun discarded() {}
}
