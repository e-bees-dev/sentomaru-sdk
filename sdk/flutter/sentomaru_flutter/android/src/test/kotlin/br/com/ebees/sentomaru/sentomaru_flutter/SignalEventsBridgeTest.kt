package br.com.ebees.sentomaru.sentomaru_flutter

import br.com.ebees.sentomaru.signals.SignalObservation
import br.com.ebees.sentomaru.signals.SignalState
import br.com.ebees.sentomaru.signals.SignalsCatalog
import br.com.ebees.sentomaru.signals.SignalsSnapshot
import io.flutter.plugin.common.EventChannel
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNotSame
import org.junit.Assert.assertNull
import org.junit.Assert.assertSame
import org.junit.Assert.assertTrue
import org.junit.Test

/**
 * D-15c: the EventChannel handler. Failure classes: events built while Dart does not listen, a cancelled sink still
 * receiving, a new subscription missing the first observations, and a reply map with anything beyond the closed fields.
 */
class SignalEventsBridgeTest {
    private class Sink : EventChannel.EventSink {
        val got = mutableListOf<Any?>()
        override fun success(event: Any?) { got += event }
        override fun error(errorCode: String?, errorMessage: String?, errorDetails: Any?) { got += "error:$errorCode" }
        override fun endOfStream() { got += "end" }
    }

    private fun snapshot(state: SignalState, detail: Map<String, String> = emptyMap()) = SignalsSnapshot(
        catalogVersion = SignalsCatalog.VERSION,
        collectedAt = "2026-10-23T10:00:00Z",
        durationMs = 3,
        observations = listOf(
            SignalObservation("root_artifacts", "1.0.0", state, observedAt = "2026-10-23T10:00:00Z", detail = detail),
            SignalObservation("installer_source", "1.0.0", SignalState.DETECTED, observedAt = "2026-10-23T10:00:00Z",
                detail = mapOf("installer" to "com.example.store")),
        ),
    )

    @Test
    fun nothingBeforeListenAndNothingAfterCancel() {
        val bridge = SignalEventsBridge { it.run() }
        assertNull(bridge.current())
        val sink = Sink()
        bridge.onListen(null, sink)
        val events = bridge.current()!!
        events.observe(snapshot(SignalState.DETECTED, mapOf("indicators" to "su_path,/system/xbin/su", "partial" to "root_package")))
        events.observeServerResponse(401, """{"code":"challenge-required","challengeKind":"step_up","user":"x"}""")
        assertEquals(
            listOf(
                mapOf(
                    "kind" to "signal",
                    "type" to "root_artifacts",
                    "capabilityId" to "root_artifacts",
                    "capabilityVersion" to "1.0.0",
                    "state" to "DETECTED",
                    "reasonCodes" to listOf("su_path", "partial"),
                    "catalogVersion" to SignalsCatalog.VERSION,
                    "sequence" to 1L,
                ),
                mapOf(
                    "kind" to "server_response",
                    "code" to "challenge-required",
                    "challengeKind" to "step_up",
                    "httpStatus" to 401,
                    "sequence" to 2L,
                ),
            ),
            sink.got,
        )
        val text = sink.got.toString()
        assertTrue(text, "/system" !in text && "com.example" !in text && "user" !in text)

        bridge.onCancel(null)
        assertNull(bridge.current())
        events.observe(snapshot(SignalState.NOT_DETECTED))
        events.observeServerResponse(403, """{"code":"installation-suspended"}""")
        assertEquals(2, sink.got.size)
    }

    @Test // D-06h: a reattest challenge crosses the channel with its kind, like step_up
    fun aReattestChallengeCrossesWithItsKind() {
        val bridge = SignalEventsBridge { it.run() }
        val sink = Sink()
        bridge.onListen(null, sink)
        bridge.current()!!.observeServerResponse(401, """{"code":"challenge-required","attestationReason":null,"challengeKind":"reattest"}""")
        assertEquals(listOf(mapOf("kind" to "server_response", "code" to "challenge-required", "challengeKind" to "reattest",
            "httpStatus" to 401, "sequence" to 1L)), sink.got)
    }

    @Test
    fun aNewSubscriptionStartsFromScratch() {
        val bridge = SignalEventsBridge { it.run() }
        val first = Sink()
        bridge.onListen(null, first)
        val a = bridge.current()!!
        a.observe(snapshot(SignalState.NOT_DETECTED))
        a.observe(snapshot(SignalState.NOT_DETECTED)) // same state: no second event
        assertEquals(1, first.got.size)
        bridge.onCancel(null)

        val second = Sink()
        bridge.onListen(null, second)
        val b = bridge.current()!!
        assertNotSame(a, b)
        b.observe(snapshot(SignalState.NOT_DETECTED))
        assertEquals(1, second.got.size) // the first observation again, sequence from 1
        assertEquals(1L, (second.got[0] as Map<*, *>)["sequence"])
        a.observe(snapshot(SignalState.DETECTED)) // the old instance reaches no sink
        assertEquals(1, first.got.size)
        assertEquals(1, second.got.size)
    }

    @Test // review R I-3: a task already posted to main that runs after cancel (or after a new listen) reaches no sink
    fun aPostedEventThatRunsAfterCancelOrRelistenIsDropped() {
        val main = ArrayDeque<Runnable>()
        val bridge = SignalEventsBridge { main.addLast(it) }
        val old = Sink()
        bridge.onListen(null, old)
        val a = bridge.current()!!
        a.observe(snapshot(SignalState.DETECTED, mapOf("indicators" to "su_path")))
        a.observeServerResponse(403, """{"code":"installation-suspended"}""")
        assertEquals(2, main.size) // posted, not run: the sink is only called on main
        assertTrue(old.got.isEmpty())
        bridge.onCancel(null)
        val fresh = Sink()
        bridge.onListen(null, fresh)
        while (main.isNotEmpty()) main.removeFirst().run()
        assertTrue(old.got.isEmpty())
        assertTrue(fresh.got.isEmpty())
        bridge.current()!!.observe(snapshot(SignalState.DETECTED))
        while (main.isNotEmpty()) main.removeFirst().run()
        assertEquals(1, fresh.got.size)
        assertTrue(old.got.isEmpty())
    }

    @Test // the plugin feeds a collector only while Dart listens (SentomaruFlutterPlugin.feedEvents)
    fun collectorsGetEventsOnlyWhileListening() {
        val bridge = SignalEventsBridge { it.run() }
        val idle = SentomaruFlutterPlugin.signalsCollector(rasp = true)
        SentomaruFlutterPlugin.feedEvents(idle, bridge)
        assertNull(idle.events)
        bridge.onListen(null, Sink())
        val listening = SentomaruFlutterPlugin.signalsCollector(rasp = true)
        SentomaruFlutterPlugin.feedEvents(listening, bridge)
        assertSame(bridge.current(), listening.events)
        assertNull(SentomaruFlutterPlugin.signalsCollector(rasp = false).events) // the frozen path never has events
    }

    @Test
    fun aNullSinkIsIgnored() {
        val bridge = SignalEventsBridge { it.run() }
        bridge.onListen(null, null)
        assertNull(bridge.current())
    }
}
