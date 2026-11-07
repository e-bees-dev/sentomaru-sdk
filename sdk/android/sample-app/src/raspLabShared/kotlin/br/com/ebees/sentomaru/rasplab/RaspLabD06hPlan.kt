package br.com.ebees.sentomaru.rasplab

/**
 * D-06h-f: the operations and the order of the HML proof, played by
 * `RaspLabD06hInstrumentedTest`. The proof policy (the vendor's policy integrity lab d06h 1.0.0 notes) cites the
 * reattestation condition on [ENFORCE] (stage enforce) and on [OBSERVE] (stage observe); [PLAIN] cites none, so its
 * evaluations are the `server_ms` without the read. Test-only code of the raspLab build (source set
 * `src/raspLabShared`); the expected answers live in the roteiro, never here.
 */
object RaspLabD06hPlan {
    const val ENFORCE = "d06h_enforce"
    const val OBSERVE = "d06h_observe"
    const val PLAIN = "d06h_plain"

    /** Measurement pairs after the cases: 0..[MAX_MEASURE], default [DEFAULT_MEASURE]. */
    const val DEFAULT_MEASURE = 10
    const val MAX_MEASURE = 30

    /** One evaluation of the plan: the report id and the operation evaluated. */
    data class Evaluation(val id: String, val operation: String)

    /** The cases before the reattestation challenge: one plain, one observed (both with no reattestation yet). */
    val BEFORE = listOf(Evaluation("plain", PLAIN), Evaluation("observe", OBSERVE))

    /** The first evaluation of the enforced operation; its answer decides the app's routine (RaspLabReattestChallenge). */
    val ENFORCED = Evaluation("enforce", ENFORCE)

    /** The repetition after a completed reattestation, once, with a new nonce; its answer is final. */
    val RETRY = Evaluation("enforce-retry", ENFORCE)

    /** The observed operation again, after the reattestation. */
    val AFTER = Evaluation("observe-after", OBSERVE)

    /** The `measure` argument, or null when it is not an integer in 0..[MAX_MEASURE] (absent: [DEFAULT_MEASURE]). */
    fun measure(argument: String?): Int? =
        if (argument == null) DEFAULT_MEASURE else argument.toIntOrNull()?.takeIf { it in 0..MAX_MEASURE }

    /** [count] pairs, plain then enforced, alternated so both see the same server load; never a reattestation. */
    fun measurement(count: Int): List<Evaluation> {
        require(count in 0..MAX_MEASURE)
        return (0 until count).flatMap { listOf(Evaluation("measure-plain", PLAIN), Evaluation("measure-enforce", ENFORCE)) }
    }
}
