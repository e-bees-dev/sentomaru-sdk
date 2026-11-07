package br.com.ebees.sentomaru.rasplab

import br.com.ebees.sentomaru.signals.SignalState
import org.junit.Assert.assertEquals
import org.junit.Test

class RaspLabReasonsTest {
    @Test
    fun `valid codes pass as key and code`() {
        assertEquals(listOf("timeout:overrun"), RaspLabReasons.of(SignalState.UNKNOWN, mapOf("timeout" to "overrun")))
        assertEquals(listOf("partial:mountinfo", "partial:build_props"),
            RaspLabReasons.of(SignalState.UNKNOWN, mapOf("indicators" to "none", "partial" to "mountinfo,build_props")))
        assertEquals(listOf("reason:partial", "cause:apk_list"),
            RaspLabReasons.of(SignalState.UNKNOWN, mapOf("reason" to "partial", "cause" to "apk_list")))
        assertEquals(listOf("result:no_reference"), RaspLabReasons.of(SignalState.UNKNOWN, mapOf("result" to "no_reference")))
    }

    @Test
    fun `a free value becomes other and is never echoed`() {
        val reasons = RaspLabReasons.of(SignalState.UNKNOWN,
            mapOf("timeout" to "/data/local/tmp/frida", "partial" to "mountinfo,com.topjohnwu.magisk", "cause" to "x y"))
        assertEquals(listOf("other", "partial:mountinfo"), reasons)
    }

    @Test
    fun `keys outside the set are dropped`() {
        val detail = mapOf("indicators" to "su_path", "algorithm" to "apk-code-sha256-v1", "aggregate" to "ab".repeat(32),
            "files" to "12", "sha256" to "cd".repeat(32))
        assertEquals(listOf("no_detail"), RaspLabReasons.of(SignalState.UNKNOWN, detail))
        assertEquals(listOf("error"), RaspLabReasons.of(SignalState.ERROR, detail))
        assertEquals(listOf("no_detail"), RaspLabReasons.of(SignalState.UNKNOWN, emptyMap()))
    }
}
