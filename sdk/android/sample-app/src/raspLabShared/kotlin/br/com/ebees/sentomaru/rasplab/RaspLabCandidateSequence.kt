package br.com.ebees.sentomaru.rasplab

/**
 * D-06i-e: the order of operations that can fabricate a false-positive CANDIDATE of the observation (migration 0055,
 * `policy_observation_rules`): one installation with an accepted `allow` BEFORE and another AFTER an evaluation whose
 * evaluated action is `challenge` or `deny`. Test-only code of the raspLab build (source set `src/raspLabShared`); the
 * published SDK has no such flow.
 *
 * Without the option the run is, as always: `collected` x N, then `unsigned-snapshot`. The `unsigned-snapshot` is NOT an
 * allow: its header is added after the signature but still carries the DETECTED states, so a rule on a DETECTED
 * capability matches it like it matches a `collected` operation. With the argument `candidateSequence=true` the run
 * becomes `bare-before`, `collected` x N, `bare-after`, then `unsigned-snapshot`.
 *
 * A `bare` operation is signed like a `collected` one, but its snapshot comes from the default detectors only
 * (`SignalsCollector.defaultDetectors()`, no `raspDetectors()`), so it carries no state for the RASP capabilities
 * (`dev_settings_enabled`, `root_artifacts`, ...). A rule on one of those capabilities does not match it, and the
 * default rule of the policy decides: the roteiro expects `allow` there. Which rule the `collected` operation matches
 * is the policy's business, never this class's.
 *
 * Nothing here talks to the API; the expected answer of each case lives in the roteiro.
 */
object RaspLabCandidateSequence {
    /** The argument name of the instrumentation. */
    const val ARGUMENT = "candidateSequence"

    enum class Kind { BARE_BEFORE, COLLECTED, BARE_AFTER }

    /** The argument as a flag: absent or "false" is off, "true" is on, anything else is invalid (null). */
    fun parse(value: String?): Boolean? = when (value) {
        null, "false" -> false
        "true" -> true
        else -> null
    }

    /** The operations of the run, in order, for [collected] collected operations (the caller keeps it in 1..20). */
    fun plan(collected: Int, enabled: Boolean): List<Kind> {
        require(collected >= 1) { "at least one collected operation" }
        val middle = List(collected) { Kind.COLLECTED }
        return if (enabled) listOf(Kind.BARE_BEFORE) + middle + listOf(Kind.BARE_AFTER) else middle
    }

    /** The case id reported for an operation of the plan. */
    fun caseId(kind: Kind): String = when (kind) {
        Kind.BARE_BEFORE -> "bare-before"
        Kind.COLLECTED -> "collected"
        Kind.BARE_AFTER -> "bare-after"
    }
}
