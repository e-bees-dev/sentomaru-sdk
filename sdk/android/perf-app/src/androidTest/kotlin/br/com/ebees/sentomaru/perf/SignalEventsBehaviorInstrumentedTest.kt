package br.com.ebees.sentomaru.perf

import android.os.Build
import android.os.Bundle
import androidx.test.ext.junit.runners.AndroidJUnit4
import androidx.test.platform.app.InstrumentationRegistry
import br.com.ebees.sentomaru.signals.SentomaruServerResponseEvent
import br.com.ebees.sentomaru.signals.SentomaruSignalEvent
import br.com.ebees.sentomaru.signals.SentomaruSignalEvents
import br.com.ebees.sentomaru.signals.ServerResponseCodes
import br.com.ebees.sentomaru.signals.SignalState
import br.com.ebees.sentomaru.signals.SignalsCatalog
import br.com.ebees.sentomaru.signals.SignalsSnapshot
import okhttp3.MediaType.Companion.toMediaType
import okhttp3.Protocol
import okhttp3.Request
import okhttp3.Response
import okhttp3.ResponseBody.Companion.toResponseBody
import org.json.JSONObject
import org.junit.Test
import org.junit.runner.RunWith
import java.io.File
import java.util.concurrent.Executor

/**
 * D-15e: BEHAVIOUR of the signal events (D-15a `signal`, D-15b `server_response`) on a real device, with the real D-05
 * collection (the cost of the same events is D-15d, `SignalEventsCostInstrumentedTest`). Opt-in like its siblings: the
 * argument `d15e=run` starts it, absent it returns at once. No server, no network, no files: the consumer's answers are
 * built in memory, as in the cost test (`SignalEventsCostInstrumentedTest.answer`/`reportServerResponse`).
 *
 * The result `d15e` carries only booleans, counts and the closed vocabulary (a state name, an event type), never a
 * value read from the device. Each check is one boolean; the run fails when one is false.
 */
@RunWith(AndroidJUnit4::class)
class SignalEventsBehaviorInstrumentedTest {

    @Test
    fun signal_events_behaviour() {
        val instrumentation = InstrumentationRegistry.getInstrumentation()
        if (InstrumentationRegistry.getArguments().getString("d15e") != "run") return
        RaspCost.requireWorkerThread()
        val context = instrumentation.targetContext
        val checks = LinkedHashMap<String, Boolean>()
        val facts = JSONObject()
        try {
            val threadsBefore = threads()
            val direct = Executor { it.run() }
            val signals = ArrayList<SentomaruSignalEvent>()
            val secondSignals = ArrayList<SentomaruSignalEvent>()
            val responses = ArrayList<SentomaruServerResponseEvent>()
            val events = SentomaruSignalEvents().apply {
                // A listener that throws must cost only its own events (the next listener still gets them).
                addListener(direct) { throw IllegalStateException("listener failure") }
                addListener(direct) { signals += it }
                addListener(direct) { secondSignals += it }
                addServerResponseListener(direct) { responses += it }
            }
            val collector = RaspCost.collector().apply { this.events = events }

            // 1. First real collection: one event per observed capability of the event catalog, none for the rest.
            val first = collector.snapshot(context)
            val eligible = first.observations.filter {
                it.capabilityId in SignalsCatalog.EVENT_TYPES && it.state != SignalState.STALE
            }
            facts.put("firstObservations", first.observations.size).put("firstEvents", signals.size)
            checks["first_collection_gives_one_event_per_eligible_capability"] =
                eligible.isNotEmpty() && signals.size == eligible.size &&
                    signals.map { it.capabilityId }.toSet() == eligible.map { it.capabilityId }.toSet()
            checks["event_state_matches_the_observation"] = signals.all { event ->
                first.observations.first { it.capabilityId == event.capabilityId }.state == event.state
            }
            checks["sequence_is_1_to_n_in_order"] = signals.map { it.sequence } == (1L..signals.size).toList()
            checks["event_fields_come_from_the_catalog"] = signals.all { event ->
                val definition = SignalsCatalog.CAPABILITIES.first { it.capabilityId == event.capabilityId }
                event.kind == SentomaruSignalEvent.Kind.SIGNAL &&
                    event.type == SignalsCatalog.EVENT_TYPES[event.capabilityId] &&
                    event.capabilityVersion == definition.version &&
                    event.catalogVersion == SignalsCatalog.VERSION &&
                    event.reasonCodes.all { it in SignalsCatalog.EVENT_REASON_CODES[event.capabilityId].orEmpty() }
            }
            checks["failing_listener_does_not_stop_the_others"] =
                secondSignals.size == signals.size && signals.isNotEmpty()

            // 2. Privacy on a real device: nothing the device or the app is called appears in any event.
            val rendered = signals.joinToString("|") { it.toString() }
            val marks = listOf(Build.MODEL, Build.DEVICE, Build.PRODUCT, Build.BOARD, Build.FINGERPRINT, Build.ID,
                Build.HARDWARE, context.packageName, android.os.Process.myPid().toString())
                .filter { it.length >= 4 && it != "unknown" }
            checks["events_carry_no_device_or_app_identifier"] = marks.none { rendered.contains(it, ignoreCase = true) }

            // 3. Second collection: events only for a change (the state of each capability is remembered).
            val before = signals.size
            val second = collector.snapshot(context)
            val changed = second.observations.count { now ->
                now.capabilityId in SignalsCatalog.EVENT_TYPES && now.state != SignalState.STALE &&
                    first.observations.firstOrNull { it.capabilityId == now.capabilityId }?.state != now.state
            }
            facts.put("secondEvents", signals.size - before).put("changedBetweenCollections", changed)
            checks["second_collection_gives_events_only_for_changes"] = signals.size - before == changed
            checks["sequence_keeps_growing"] = signals.map { it.sequence } == (1L..signals.size).toList()

            // 4. Server responses (D-15b): closed codes only, every answer an event, the body stays readable.
            fun report(status: Int, body: String) = answer(status, body).use {
                reportServerResponse(events, it)
                it.body?.string()
            }
            val signalSequenceTop = signals.size.toLong()
            val unreadBody = report(401, CHALLENGE_STEP_UP)
            checks["challenge_step_up_is_an_event"] = responses.lastOrNull()?.let {
                it.code == "challenge-required" && it.challengeKind == "step_up" && it.httpStatus == 401
            } == true
            checks["the_app_still_reads_the_body_after_the_peek"] = unreadBody == CHALLENGE_STEP_UP
            report(401, CHALLENGE_REATTEST)
            checks["reattest_is_recognised"] = responses.lastOrNull()?.isReattestChallenge == true
            report(403, """{"code":"RASP_ROOT_ARTIFACTS"}""")
            checks["policy_reason_on_403_is_an_event"] =
                responses.lastOrNull()?.let { it.code == "RASP_ROOT_ARTIFACTS" && it.challengeKind == null } == true
            val count = responses.size
            report(401, CHALLENGE_STEP_UP)
            report(401, CHALLENGE_STEP_UP)
            checks["every_answer_is_an_event_not_only_changes"] = responses.size == count + 2
            val beforeIgnored = responses.size
            report(401, """{"code":"something-else"}""")          // outside the closed set
            report(403, """{"code":"challenge-required"}""")      // 401-only code on 403
            report(401, """{"error":{"code":"challenge-required"}}""") // nested code is never read
            report(401, "not json")
            report(200, CHALLENGE_STEP_UP)                        // not a refusal
            report(401, """{"code":"challenge-required","pad":"${"x".repeat(5000)}"}""") // over the body bound
            checks["unknown_nested_malformed_or_oversized_answers_give_no_event"] = responses.size == beforeIgnored
            checks["response_sequence_shares_the_signal_counter"] =
                responses.map { it.sequence }.let { seq -> seq.first() > signalSequenceTop && seq == seq.sorted() && seq.toSet().size == seq.size }

            // 5. No thread, timer or service was started by any of it.
            val threadsAfter = threads()
            facts.put("threadsBefore", threadsBefore).put("threadsAfter", threadsAfter)
            checks["no_thread_was_started"] = threadsAfter <= threadsBefore
            facts.put("signalEvents", signals.size).put("serverResponseEvents", responses.size)
        } finally {
            val result = JSONObject().put("facts", facts).put("checks", JSONObject(checks as Map<*, *>))
                .put("passed", checks.isNotEmpty() && checks.values.all { it })
            instrumentation.addResults(Bundle().apply { putString("d15e", result.toString()) })
        }
        check(checks.values.all { it }) { "d15e: " + checks.filterValues { !it }.keys.joinToString() }
    }

    private fun threads(): Int = File("/proc/self/task").list()?.size ?: -1

    private companion object {
        private val JSON = "application/problem+json".toMediaType()
        private val REQUEST = Request.Builder().url("https://consumer.invalid/api/operation").build()

        /** One consumer answer, built in memory (the app's HTTP stack has it anyway). */
        fun answer(code: Int, body: String): Response = Response.Builder().request(REQUEST).protocol(Protocol.HTTP_1_1)
            .code(code).message("").body(body.toResponseBody(JSON)).build()

        /**
         * A REPLICA of the transport's D-15b work (`SentomaruInterceptor.reportServerResponse`, private there), the same
         * one the cost test uses: this test proves the events class on a device, not the interceptor's wiring (the JVM
         * `ServerResponseEventsTransportTest` covers the interceptor itself).
         */
        fun reportServerResponse(events: SentomaruSignalEvents, response: Response) {
            if (response.code != 401 && response.code != 403 || !events.hasServerResponseListeners) return
            val body = try {
                response.peekBody(ServerResponseCodes.MAX_BODY_CHARS + 1L).string()
            } catch (_: Exception) {
                return
            }
            events.observeServerResponse(response.code, body)
        }

        const val CHALLENGE_STEP_UP = """{"type":"about:blank","status":401,"code":"challenge-required","challengeKind":"step_up"}"""
        const val CHALLENGE_REATTEST = """{"code":"challenge-required","challengeKind":"reattest"}"""
    }
}
