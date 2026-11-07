package br.com.ebees.sentomaru.rasplab

/**
 * D-06h-c: the app's routine for a `challenge` of kind `reattest` (integration guide, item 8 of the D-06h spec), as the
 * raspLab build plays it in the `reattest-challenge` case (`RaspLabCasesInstrumentedTest`). Test-only code of the raspLab
 * build (source set `src/raspLabShared`); the published SDK has no such flow and never reattests or repeats an operation
 * by itself.
 *
 * - Only a `challenge` whose `challengeKind` is exactly `reattest` asks for a reattestation; anything else is final.
 * - The app calls `SentomaruReattestation.reattest()` ONCE (it ignores the local wait: the server decided).
 * - With `ReattestationCompleted`, whatever the states it carries, the operation is repeated ONCE with a new nonce: the
 *   server, not the app, reads the reattestation on that evaluation. If it challenges again, the app does not reattest
 *   again for this operation (that would be a loop).
 * - With `ReattestationNotNow` (429 of the interval or of the daily cap, verifier or route unavailable), the app shows
 *   "try later" and does not repeat; with `ReattestationRefused`, it shows the refusal and does not repeat.
 */
object RaspLabReattestChallenge {
    const val KIND = "reattest"

    /** What the app does after the first answer and, when there was one, the outcome of its single reattestation. */
    enum class Step { FINAL, REATTEST, REPEAT_ONCE, TRY_LATER, SHOW_REFUSAL }

    // The repeated operation's answer is always final (no function: nothing to decide), even another `challenge`
    // `reattest`: there is no second reattestation for the same operation.

    /** The reattestation outcome as this routine needs it (the SDK's sealed outcome types, without their content). */
    enum class Outcome { COMPLETED, NOT_NOW, REFUSED }

    /** After the first evaluation answer: [Step.REATTEST] only for `challenge` + `reattest`, else [Step.FINAL]. */
    fun afterAnswer(recommendedAction: String?, challengeKind: String?): Step =
        if (recommendedAction == "challenge" && challengeKind == KIND) Step.REATTEST else Step.FINAL

    /** After the single reattestation of this operation. */
    fun afterReattest(outcome: Outcome): Step = when (outcome) {
        Outcome.COMPLETED -> Step.REPEAT_ONCE
        Outcome.NOT_NOW -> Step.TRY_LATER
        Outcome.REFUSED -> Step.SHOW_REFUSAL
    }
}
