package br.com.ebees.sentomaru.signals

import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test

class SignalStateTest {
    @Test
    fun catalogStatesMatchDecisionE5() {
        assertEquals(
            listOf("DETECTED", "NOT_DETECTED", "UNKNOWN", "UNSUPPORTED", "ERROR", "STALE"),
            SignalState.values().map { it.name },
        )
        // Absence of detection must stay distinguishable from "clean".
        assertTrue(SignalState.NOT_DETECTED != SignalState.UNKNOWN)
    }
}
