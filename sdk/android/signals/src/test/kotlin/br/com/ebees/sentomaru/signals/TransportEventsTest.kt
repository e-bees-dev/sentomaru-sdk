package br.com.ebees.sentomaru.signals

import org.junit.Assert.*
import org.junit.Test
import java.util.concurrent.Executor
import java.util.concurrent.RejectedExecutionException

/**
 * D-07d: transport events. Only `pin_failure` with one of the three closed reasons and a lower-case host name; anything
 * else is dropped before an event exists; one counter with the other two kinds; a listener that throws (or an executor
 * that refuses) costs only its own delivery; the signals catalog does not gain the vocabulary.
 */
class TransportEventsTest {
    private val direct = Executor { it.run() }

    private class Recorder : SentomaruTransportListener {
        val events = mutableListOf<SentomaruTransportEvent>()
        override fun onTransportEvent(event: SentomaruTransportEvent) { events += event }
    }

    @Test
    fun eachClosedReasonOnAHostNameIsOneEvent() {
        val events = SentomaruSignalEvents()
        val recorder = Recorder()
        events.addTransportListener(direct, recorder)
        for (reason in listOf("pin_mismatch", "tls_untrusted", "tls_other", "pin_mismatch")) events.observePinFailure("lab-pin.sentomaru.com.br", reason)
        assertEquals(listOf(
            SentomaruTransportEvent("pin_failure", "pin_mismatch", "lab-pin.sentomaru.com.br", 1),
            SentomaruTransportEvent("pin_failure", "tls_untrusted", "lab-pin.sentomaru.com.br", 2),
            SentomaruTransportEvent("pin_failure", "tls_other", "lab-pin.sentomaru.com.br", 3),
            SentomaruTransportEvent("pin_failure", "pin_mismatch", "lab-pin.sentomaru.com.br", 4),
        ), recorder.events)
        assertTrue(recorder.events.all { it.kind == SentomaruTransportEvent.Kind.TRANSPORT })
        assertEquals(setOf("pin_mismatch", "tls_untrusted", "tls_other"), TransportEventCodes.REASONS)
    }

    @Test
    fun anyOtherReasonOrHostIsDropped() {
        val events = SentomaruSignalEvents()
        val recorder = Recorder()
        events.addTransportListener(direct, recorder)
        for (reason in listOf("", "PIN_MISMATCH", "pin_failure", "tls_untrusted ", "Pin verification failed")) events.observePinFailure("api.example", reason)
        for (host in listOf("", "API.example", "api.example.", "https://api.example", "api.example/v1", "api.example:443",
                "10.0.0.1", "a b.example", "user@api.example", "a".repeat(250) + ".example")) {
            events.observePinFailure(host, "pin_mismatch")
        }
        assertTrue(recorder.events.isEmpty())
        events.observePinFailure("api.example", "tls_other")
        assertEquals(listOf(SentomaruTransportEvent("pin_failure", "tls_other", "api.example", 1)), recorder.events)
    }

    @Test
    fun theSequenceIsSharedWithServerResponseEvents() {
        val events = SentomaruSignalEvents()
        val transport = Recorder()
        val responses = mutableListOf<SentomaruServerResponseEvent>()
        events.addTransportListener(direct, transport)
        events.addServerResponseListener(direct) { responses += it }
        events.observeServerResponse(403, """{"code":"policy-denied"}""")
        events.observePinFailure("api.example", "pin_mismatch")
        events.observeServerResponse(403, """{"code":"installation-suspended"}""")
        assertEquals(listOf(1L, 3L), responses.map { it.sequence })
        assertEquals(listOf(2L), transport.events.map { it.sequence })
    }

    @Test
    fun aBrokenListenerOrExecutorCostsOnlyItsDeliveryAndRemovalWorks() {
        val events = SentomaruSignalEvents()
        val good = Recorder()
        val throwing = SentomaruTransportListener { throw IllegalStateException("listener") }
        events.addTransportListener(direct, throwing)
        events.addTransportListener(Executor { throw RejectedExecutionException() }, Recorder())
        events.addTransportListener(direct, good)
        assertTrue(events.hasTransportListeners)
        events.observePinFailure("api.example", "pin_mismatch")
        assertEquals(1, good.events.size)
        assertTrue(events.removeTransportListener(good))
        assertFalse(events.removeTransportListener(good))
        events.observePinFailure("api.example", "pin_mismatch")
        assertEquals(1, good.events.size)
    }

    @Test
    fun noListenerNoEventAndTheOtherListenersSeeNothing() {
        val events = SentomaruSignalEvents()
        assertFalse(events.hasTransportListeners)
        val signals = mutableListOf<SentomaruSignalEvent>()
        val responses = mutableListOf<SentomaruServerResponseEvent>()
        events.addListener(direct) { signals += it }
        events.addServerResponseListener(direct) { responses += it }
        events.observePinFailure("api.example", "pin_mismatch")
        assertFalse(events.hasTransportListeners)
        assertTrue(signals.isEmpty() && responses.isEmpty())
    }

    /** The vocabulary is the SDK's, not the catalog's (D-07d: the catalog does not change). */
    @Test
    fun theCatalogDoesNotKnowTheTransportVocabulary() {
        val words = setOf("pin_failure", "pin_mismatch", "tls_untrusted", "tls_other", "transport")
        assertTrue(SignalsCatalog.EVENT_TYPES.values.none { it in words })
        assertTrue(SignalsCatalog.EVENT_TYPES.keys.none { it in words })
        assertTrue(SignalsCatalog.EVENT_REASON_CODES.values.flatten().none { it in words })
        assertTrue(SignalsCatalog.CAPABILITIES.none { it.capabilityId in words })
    }
}
