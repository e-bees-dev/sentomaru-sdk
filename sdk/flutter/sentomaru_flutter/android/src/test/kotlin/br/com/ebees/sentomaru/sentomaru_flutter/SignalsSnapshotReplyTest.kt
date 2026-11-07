package br.com.ebees.sentomaru.sentomaru_flutter

import br.com.ebees.sentomaru.signals.SignalObservation
import br.com.ebees.sentomaru.signals.SignalState
import br.com.ebees.sentomaru.signals.SignalsCatalog
import br.com.ebees.sentomaru.signals.SignalsCollector
import br.com.ebees.sentomaru.signals.SignalsSnapshot
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNull
import org.junit.Test

/** D-05e: which collector `collectSignalsSnapshot` uses and what it sends over the channel. */
class SignalsSnapshotReplyTest {
    @Test
    fun withoutRaspIsTheFrozenCollector() {
        val collector = SentomaruFlutterPlugin.signalsCollector(rasp = false)
        assertEquals(SignalsCatalog.DEFAULT_CAPABILITY_IDS, collector.detectors.map { it.capabilityId })
        assertNull(collector.deadlineMs)
    }

    @Test
    fun withRaspAddsTheD05DetectorsWithTheDeadline() {
        val collector = SentomaruFlutterPlugin.signalsCollector(rasp = true)
        assertEquals(
            SignalsCatalog.DEFAULT_CAPABILITY_IDS + SignalsCatalog.RASP_CAPABILITY_IDS,
            collector.detectors.map { it.capabilityId },
        )
        assertEquals(SignalsCollector.RASP_DEADLINE_MS, collector.deadlineMs)
    }

    @Test
    fun replyCarriesCollectedAtDurationAndObservations() {
        val snapshot = SignalsSnapshot(
            catalogVersion = SignalsCatalog.VERSION,
            collectedAt = "2026-10-21T10:00:00Z",
            durationMs = 7,
            observations = listOf(
                SignalObservation(
                    capabilityId = "root_artifacts",
                    version = "1.0.0",
                    state = SignalState.UNKNOWN,
                    observedAt = "2026-10-21T10:00:00.004Z",
                    detail = mapOf("partial" to "root_package"),
                ),
            ),
        )
        val reply = SentomaruFlutterPlugin.snapshotReply(snapshot)
        assertEquals("2026-10-21T10:00:00Z", reply["collectedAt"])
        assertEquals(7L, reply["durationMs"])
        assertEquals(
            listOf(
                mapOf(
                    "capabilityId" to "root_artifacts",
                    "version" to "1.0.0",
                    "state" to "unknown",
                    "source" to "client_observed",
                    "observedAt" to "2026-10-21T10:00:00.004Z",
                    "data" to mapOf("partial" to "root_package"),
                ),
            ),
            reply["observations"],
        )
    }
}
