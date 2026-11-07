package br.com.ebees.sentomaru.rasplab

/**
 * D-06g-a: the per-rule fields of the evaluation answer (D-06a, contract v1.9) in the lab report
 * (`RaspLabCasesInstrumentedTest`), each kept only in a format of its own; a value outside it is dropped, never echoed.
 * Test-only code of the raspLab build (source set `src/raspLabShared`, shared by `androidTestRaspLab` and the JVM
 * `testRaspLab`); the published SDK does not have it.
 */
object RaspLabPolicyFields {
    /** The rule id format of the policy schema and of the CHECK of migration 0054 (`^[a-z0-9_]{3,32}$`). */
    val RULE_ID = Regex("[a-z0-9_]{3,32}")

    /** The policy version format of the policy schema (semver, `^[0-9]+\.[0-9]+\.[0-9]+$`), bounded in length here. */
    val VERSION = Regex("[0-9]{1,9}\\.[0-9]{1,9}\\.[0-9]{1,9}")

    /** At most this many rule ids are reported: the validator's limit of rules in one policy (`MaxRules`). */
    const val MAX_RULES = 128

    /**
     * The `observedRules` of an answer as reported: the ids in the [RULE_ID] format, in the server's order, without
     * repeats, at most [MAX_RULES]. Anything else (null, other type, free text) is dropped.
     */
    fun observedRules(values: List<Any?>): List<String> =
        values.asSequence().filterIsInstance<String>().filter { RULE_ID.matches(it) }.distinct().take(MAX_RULES).toList()

    /** The `policyVersion` of an answer when it is in the [VERSION] format, else null (not reported). */
    fun policyVersion(value: Any?): String? = (value as? String)?.takeIf { VERSION.matches(it) }
}
