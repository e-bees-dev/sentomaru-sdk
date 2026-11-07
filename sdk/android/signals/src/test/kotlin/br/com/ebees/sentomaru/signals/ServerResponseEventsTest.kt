package br.com.ebees.sentomaru.signals

import org.junit.Assert.*
import org.junit.Test
import java.util.concurrent.Executor
import java.util.concurrent.RejectedExecutionException

/**
 * D-15b: server response events. Only the closed codes (status-bound), only the top-level `code` and the
 * `challengeKind` next to `challenge-required`; other members, free text, a `riskEvent`, a nested or repeated `code`,
 * malformed or oversized bodies give no event; no field of the body other than the code (and kind) reaches the event;
 * one counter with the signal events; a listener that throws costs only its own delivery.
 */
class ServerResponseEventsTest {
    private val direct = Executor { it.run() }

    private class Recorder : SentomaruServerResponseListener {
        val events = mutableListOf<SentomaruServerResponseEvent>()
        override fun onServerResponseEvent(event: SentomaruServerResponseEvent) { events += event }
    }

    private fun read(status: Int, body: String?) = ServerResponseCodes.read(status, body)

    @Test
    fun closedCodesAreReadWithTheirStatus() {
        assertEquals("challenge-required" to "step_up", read(401, """{"code":"challenge-required","challengeKind":"step_up"}"""))
        assertEquals("challenge-required" to "fresh_signals", read(401, """{"challengeKind":"fresh_signals","code":"challenge-required"}"""))
        assertEquals("challenge-required" to null, read(401, """{"code":"challenge-required"}"""))
        assertEquals("challenge-required" to "reattest", read(401, """{"code":"challenge-required","challengeKind":"reattest"}""")) // D-06h, known
        assertEquals("challenge-required" to "future_kind", read(401, """{"code":"challenge-required","challengeKind":"future_kind"}""")) // raw token
        assertEquals("proof-required" to null, read(401, """{"code":"proof-required"}"""))
        for (code in listOf("installation-suspended", "installation-revoked", "session-unavailable", "policy-denied")) {
            assertEquals(code to null, read(403, """{"code":"$code","attestationReason":null}"""))
        }
        assertEquals("installation-suspended" to null, read(401, """{"code":"installation-suspended"}"""))
        assertEquals("installation-suspended" to null, read(403, """{"\u0063ode":"installation-suspended"}"""))
        assertEquals("RASP_ROOT_ARTIFACTS" to null, read(403, """ {"code" : "RASP_ROOT_ARTIFACTS", "attestationReason": null} """))
    }

    /** D-06h: the closed list of challenge kinds gains `reattest`; a malformed neighbour never passes, and the
     * convenience flag is true only for `challenge-required` with exactly `reattest`. */
    @Test
    fun reattestIsAKnownChallengeKind() {
        assertEquals(setOf("fresh_signals", "step_up", "reattest"), ServerResponseCodes.CHALLENGE_KINDS)
        for (bad in listOf("Reattest", "reattest ", "re-attest", "_reattest")) {
            assertEquals(bad, "challenge-required" to null, read(401, """{"code":"challenge-required","challengeKind":"$bad"}"""))
        }
        assertNull(read(403, """{"code":"challenge-required","challengeKind":"reattest"}"""))
        assertEquals("installation-suspended" to null, read(403, """{"code":"installation-suspended","challengeKind":"reattest"}"""))
        assertTrue(SentomaruServerResponseEvent("challenge-required", "reattest", 401, 1).isReattestChallenge)
        assertFalse(SentomaruServerResponseEvent("challenge-required", "step_up", 401, 1).isReattestChallenge)
        assertFalse(SentomaruServerResponseEvent("challenge-required", null, 401, 1).isReattestChallenge)
        assertFalse(SentomaruServerResponseEvent("policy-denied", null, 403, 1).isReattestChallenge)
    }

    @Test
    fun anythingOutsideTheClosedSetGivesNoEvent() {
        val none = listOf(
            200 to """{"code":"challenge-required"}""",
            500 to """{"code":"challenge-required"}""",
            403 to """{"code":"challenge-required"}""",                // challenge only on 401
            401 to """{"code":"RASP_ROOT_ARTIFACTS"}""",               // a policy refusal only on 403
            403 to """{"code":"forbidden"}""",
            403 to """{"code":"RASP root"}""",
            403 to """{"code":"AB"}""",
            403 to """{"code":"${"A".repeat(65)}"}""",
            403 to """{"riskEvent":{"code":"installation-suspended","reason":"texto livre do consumidor"}}""",
            403 to """{"message":"installation-suspended"}""",
            403 to """installation-suspended""",
            403 to """["installation-suspended"]""",
            403 to """{"code":"installation-suspended","code":"policy-denied"}""",
            403 to """{"code":"installation-suspended"} trailing""",
            403 to """{"code":"installation-suspended"""",
            403 to """{"code":403}""",
            403 to """{"code":"\u+069nstallation-suspended"}""",                 // review R M-4: \u needs 4 hex digits
            403 to "\uFEFF{\"code\":\"installation-suspended\"}",
            403 to "",
            403 to """{"code":"installation-suspended","pad":"${"x".repeat(ServerResponseCodes.MAX_BODY_CHARS)}"}""",
            403 to """{"code":"installation-suspended","deep":${"[".repeat(40)}${"]".repeat(40)}}""",
        )
        for ((status, body) in none) assertNull("$status $body", read(status, body))
        assertNull(read(403, null))
    }

    @Test
    fun aMalformedKindIsDroppedAndAKindIsReadOnlyWithAChallenge() {
        for (kind in listOf("STEP_UP", "step-up", "_x", "1x", "a".repeat(33), "step up")) {
            assertEquals(kind, "challenge-required" to null, read(401, """{"code":"challenge-required","challengeKind":"$kind"}"""))
        }
        assertEquals("proof-required" to null, read(401, """{"code":"proof-required","challengeKind":"step_up"}"""))
        assertEquals("challenge-required" to "a".repeat(32), read(401, """{"code":"challenge-required","challengeKind":"${"a".repeat(32)}"}"""))
    }

    @Test
    fun eventsCarryOnlyTheCodeAndShareTheCounterWithSignalEvents() {
        val events = SentomaruSignalEvents()
        val responses = Recorder().also { events.addServerResponseListener(direct, it) }
        val signals = mutableListOf<SentomaruSignalEvent>()
        events.addListener(direct) { signals += it }
        assertTrue(events.hasServerResponseListeners)
        events.observe(SignalsSnapshot(SignalsCatalog.VERSION, "2026-10-23T10:00:00Z", 1,
            listOf(SignalObservation(capabilityId = "root_artifacts", version = "1.0.0", state = SignalState.DETECTED,
                observedAt = "2026-10-23T10:00:00Z", detail = mapOf("indicators" to "su_path")))))
        val secret = "installation 11111111-2222-4333-8444-555555555555 br.com.terceiro /data/x"
        events.observeServerResponse(401, """{"code":"challenge-required","challengeKind":"step_up","detail":"$secret"}""")
        events.observeServerResponse(401, """{"code":"challenge-required","challengeKind":"step_up"}""")
        events.observeServerResponse(403, """{"riskEvent":{"code":"policy-denied"}}""")
        assertEquals(1, signals.size)
        assertEquals(listOf(SentomaruServerResponseEvent("challenge-required", "step_up", 401, 2),
            SentomaruServerResponseEvent("challenge-required", "step_up", 401, 3)), responses.events)
        assertEquals(SentomaruServerResponseEvent.Kind.SERVER_RESPONSE, responses.events[0].kind)
        assertFalse(responses.events.toString().contains("terceiro"))
        // The class has exactly these properties: nothing else of a body can be carried.
        assertEquals(setOf("code", "challengeKind", "httpStatus", "sequence", "kind"),
            SentomaruServerResponseEvent::class.java.declaredMethods.filter { it.name.startsWith("get") }
                .map { it.name.removePrefix("get").replaceFirstChar(Char::lowercase) }.toSet())
    }

    @Test
    fun aBrokenListenerOrExecutorNeverReachesTheCallerNorTheOthers() {
        val events = SentomaruSignalEvents()
        events.addServerResponseListener(direct) { throw IllegalStateException("app bug") }
        events.addServerResponseListener(Executor { throw RejectedExecutionException() }) { fail("never runs") }
        val good = Recorder().also { events.addServerResponseListener(direct, it) }
        events.observeServerResponse(403, """{"code":"installation-suspended"}""")
        assertEquals(1, good.events.size)
        assertTrue(events.removeServerResponseListener(good))
        assertFalse(events.removeServerResponseListener(good))
        events.observeServerResponse(403, """{"code":"installation-suspended"}""")
        assertEquals(1, good.events.size)
    }

    @Test
    fun withoutAServerResponseListenerNothingIsDelivered() {
        val events = SentomaruSignalEvents()
        val signals = mutableListOf<SentomaruSignalEvent>()
        events.addListener(direct) { signals += it }
        assertFalse(events.hasServerResponseListeners)
        events.observeServerResponse(403, """{"code":"installation-suspended"}""")
        assertTrue(signals.isEmpty())
    }
}
