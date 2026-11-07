package br.com.ebees.sentomaru.rasplab

import br.com.ebees.sentomaru.signals.SignalState

/**
 * D-05g: the reasons of an UNKNOWN or ERROR observation in the lab report (`RaspLabCasesInstrumentedTest`), as
 * `key:code` of a closed set taken from the signal `detail`; a value outside the set is `other`, never echoed, and a
 * key outside the set (`indicators`, `algorithm`, `aggregate`, `files`, `sha256`...) is dropped. Test-only code of the
 * raspLab build (source set `src/raspLabShared`, shared by `androidTestRaspLab` and the JVM `testRaspLab`); the
 * published SDK does not have it.
 */
object RaspLabReasons {
    /**
     * Closed set of the `detail` codes a D-05 or D-12c detector (or the collector) gives an UNKNOWN or ERROR:
     * `timeout` from SignalsCollector, `partial` from the Evidence checks, `reason`/`cause` from code_integrity and
     * `result` from app_signer_mismatch. Kept in step with the detectors by hand; anything new is reported `other`.
     */
    val CODES: Map<String, Set<String>> = mapOf(
        "timeout" to setOf("overrun", "skipped"),
        "partial" to setOf("adb_enabled", "development_settings", "flag_debuggable", "jdwp_connected", "jdwp_waiting",
            "su_path", "manager_path", "root_package", "build_type", "test_keys", "mountinfo", "build_props",
            "qemu_device", "sensor_missing", "xposed_class", "hook_frame"),
        "reason" to setOf("main_thread", "partial", "timeout", "not_compared"),
        "cause" to setOf("apk_list", "executor", "hash_failed", "apk_unreadable", "entry_unreadable",
            "duplicate_entry", "too_many_files", "too_large", "no_code_files"),
        "result" to setOf("no_reference", "unreadable"),
    )

    /** The reasons of one UNKNOWN or ERROR observation, from its `detail`, as `key:code` of [CODES] only. */
    fun of(state: SignalState, detail: Map<String, String>): List<String> {
        val out = LinkedHashSet<String>()
        if (state == SignalState.ERROR) out += "error"
        for ((key, value) in detail) {
            val allowed = CODES[key] ?: continue
            value.split(',').forEach { code -> out += if (code in allowed) "$key:$code" else "other" }
        }
        if (out.isEmpty()) out += "no_detail"
        return out.toList()
    }
}
