package br.com.ebees.sentomaru.perf

import android.os.Bundle
import android.os.Debug
import android.os.SystemClock
import androidx.test.ext.junit.runners.AndroidJUnit4
import androidx.test.platform.app.InstrumentationRegistry
import br.com.ebees.sentomaru.signals.SentomaruServerResponseListener
import br.com.ebees.sentomaru.signals.SentomaruSignalEventListener
import br.com.ebees.sentomaru.signals.SentomaruSignalEvents
import br.com.ebees.sentomaru.signals.ServerResponseCodes
import br.com.ebees.sentomaru.signals.SignalObservation
import br.com.ebees.sentomaru.signals.SignalState
import br.com.ebees.sentomaru.signals.SignalsCatalog
import br.com.ebees.sentomaru.signals.SignalsCollector
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
import java.util.concurrent.atomic.AtomicLong

/**
 * D-15d cost of the signal events (D-15a `signal`, D-15b `server_response`), driven by the vendor's run d15d cost check
 * (never in CI). The collection is the D-05c one (`RaspCost.collector()`); the listeners run on a direct executor, so
 * their delivery is inside the timed region (the worst case the API allows) and no thread is involved. Arguments:
 * - `d15d` = `warm` or `cold`; absent, the test returns at once (as `RaspCostInstrumentedTest`);
 * - warm: `runs` (default 300) after `warmup` (default 30) discarded rounds, in one process. Each round times, back to
 *   back and in a rotating order, one snapshot of three collectors built once: `none` (no events, the default),
 *   `events` (events set, no listener) and `listener` (events with a signal and a server response listener); the
 *   difference `listener - none` of the same round is the end-to-end added cost (noisy: it is the difference of two
 *   collections). Then the emission alone, the exact work `snapshot()` adds (`events?.observe(snapshot)`):
 *   `observeSteady` (the listener collector's own events fed the snapshot it just made: steady state, events only on a
 *   change), `observeFirst` (a fresh events with listener fed the same snapshot: every capability is a first
 *   observation, one event each), `observeAllTypes` (a fresh events with listener fed a snapshot of every event type
 *   of the catalog, DETECTED with every allowed reason code: the most events one collection can give); and the
 *   transport's D-15b work on one 401 (`serverResponse401`) and one 403 (`serverResponse403`): `peekBody` of 4097
 *   bytes plus `observeServerResponse` with a listener, as `SentomaruInterceptor.reportServerResponse` does (the
 *   in-memory OkHttp answer is built before the clock starts: the app's HTTP stack builds it with or without events);
 * - cold: `target` = `none`, `listener` or `emission`; one run, the first SDK call of a fresh process (the runner
 *   force-stops the app before each). `none`/`listener`: building the collector and its first snapshot are timed.
 *   `emission`: a collection without events first (not timed), then, each timed apart: building the events with their
 *   listeners (`buildEvents`, once per process when the app opts in), its first `observe` (`observeFirst`) and the
 *   first server response (`serverResponse401`); the class loading of what `observe` and the response code touch
 *   first is in the last two.
 * - `holdS`: after measuring, outside every timed region, the status `d15dHold=ready` and that many seconds alive, so
 *   the runner reads `dumpsys` while the app lives (as D-05c).
 * The JSON (samples, the events delivered inside each emission target over every round, the thread count of the
 * process before and after, informative) goes to the result `d15d`.
 */
@RunWith(AndroidJUnit4::class)
class SignalEventsCostInstrumentedTest {

    @Test
    fun signal_events_cost() {
        val instrumentation = InstrumentationRegistry.getInstrumentation()
        val arguments = InstrumentationRegistry.getArguments()
        val mode = arguments.getString("d15d") ?: return
        RaspCost.requireWorkerThread()
        val context = instrumentation.targetContext
        val result = JSONObject().put("mode", mode).put("threadsBefore", threads())
        val targets = LinkedHashMap<String, Tally>()
        val tally = { name: String -> targets.getOrPut(name) { Tally() } }
        val counter = Counter()
        // Events delivered inside each timed emission target, every round included (the runner checks the work).
        val eventCounts = HashMap<String, Long>()
        fun emit(name: String, into: Tally, block: () -> Unit) {
            val before = counter.total()
            timed(into, block)
            eventCounts.merge(name, counter.total() - before, Long::plus)
        }
        try {
            when (mode) {
                "cold" -> {
                    val target = requireNotNull(arguments.getString("target")) { "target argument required" }
                    when (target) {
                        NONE -> timedCollection(tally(NONE)) { RaspCost.collector().snapshot(context) }
                        LISTENER -> timedCollection(tally(LISTENER)) {
                            RaspCost.collector().apply { events = counter.events() }.snapshot(context)
                        }
                        EMISSION -> {
                            val snapshot = RaspCost.collector().snapshot(context)
                            // Building the events (class loading of SentomaruSignalEvents) is timed apart: it is
                            // paid once per process, when the app opts in, not per collection.
                            lateinit var events: SentomaruSignalEvents
                            timed(tally(BUILD_EVENTS)) { events = counter.events() }
                            emit(OBSERVE_FIRST, tally(OBSERVE_FIRST)) { events.observe(snapshot) }
                            answer(401, RESPONSE_401).use { r ->
                                emit(SERVER_401, tally(SERVER_401)) { reportServerResponse(events, r) }
                            }
                        }
                        else -> throw IllegalArgumentException("unknown target")
                    }
                }
                "warm" -> {
                    val runs = arguments.getString("runs")?.toInt() ?: 300
                    val warmup = arguments.getString("warmup")?.toInt() ?: 30
                    val listening = counter.events()
                    val collectors = linkedMapOf(
                        NONE to RaspCost.collector(),
                        EVENTS to RaspCost.collector().apply { events = SentomaruSignalEvents() },
                        LISTENER to RaspCost.collector().apply { events = listening },
                    )
                    val names = collectors.keys.toList() + listOf(OBSERVE_STEADY, OBSERVE_FIRST, OBSERVE_ALL, SERVER_401, SERVER_403)
                    names.forEach { tally(it) } // report order
                    val discard = Tally()
                    val added = ArrayList<Long>()
                    val allTypes = allTypesSnapshot()
                    repeat(warmup + runs) { round ->
                        val keep = round >= warmup
                        val pick = { name: String -> if (keep) tally(name) else discard }
                        val walls = HashMap<String, Long>()
                        var last: SignalsSnapshot? = null
                        for (i in collectors.keys.indices) {
                            val name = collectors.keys.elementAt((i + round) % collectors.size) // rotating order
                            walls[name] = timedCollection(pick(name)) {
                                collectors.getValue(name).snapshot(context).also { if (name == LISTENER) last = it }
                            }
                        }
                        if (keep) added += walls.getValue(LISTENER) - walls.getValue(NONE)
                        val snapshot = requireNotNull(last)
                        emit(OBSERVE_STEADY, pick(OBSERVE_STEADY)) { listening.observe(snapshot) }
                        val fresh = counter.events()
                        emit(OBSERVE_FIRST, pick(OBSERVE_FIRST)) { fresh.observe(snapshot) }
                        val freshAll = counter.events()
                        emit(OBSERVE_ALL, pick(OBSERVE_ALL)) { freshAll.observe(allTypes) }
                        answer(401, RESPONSE_401).use { r ->
                            emit(SERVER_401, pick(SERVER_401)) { reportServerResponse(listening, r) }
                        }
                        answer(403, RESPONSE_403).use { r ->
                            emit(SERVER_403, pick(SERVER_403)) { reportServerResponse(listening, r) }
                        }
                    }
                    result.put("runs", runs).put("warmup", warmup)
                        .put("addedListenerMinusNoneUs", org.json.JSONArray(added))
                }
                else -> throw IllegalArgumentException("d15d must be warm or cold")
            }
            result.put("signalEvents", counter.signals.get()).put("serverResponseEvents", counter.responses.get())
                .put("threadsAfter", threads()).put("eventCounts", JSONObject(eventCounts as Map<*, *>))
            hold(arguments, instrumentation)
        } finally {
            val json = JSONObject()
            targets.forEach { (name, t) -> json.put(name, t.toJson()) }
            instrumentation.addResults(Bundle().apply { putString("d15d", result.put("targets", json).toString()) })
        }
    }

    /** Signal and server response listeners on a direct executor: delivery runs inside the timed region. */
    private class Counter {
        val signals = AtomicLong()
        val responses = AtomicLong()
        private val direct = Executor { it.run() }
        private val signal = SentomaruSignalEventListener { signals.incrementAndGet() }
        private val response = SentomaruServerResponseListener { responses.incrementAndGet() }

        fun total() = signals.get() + responses.get()

        fun events() = SentomaruSignalEvents().apply {
            addListener(direct, signal)
            addServerResponseListener(direct, response)
        }
    }

    private fun hold(arguments: Bundle, instrumentation: android.app.Instrumentation) {
        val seconds = arguments.getString("holdS")?.toLong() ?: return
        instrumentation.sendStatus(HOLD_CODE, Bundle().apply { putString("d15dHold", "ready") })
        Thread.sleep(seconds * 1_000)
    }

    private companion object {
        const val NONE = "none"
        const val EVENTS = "events"
        const val LISTENER = "listener"
        const val EMISSION = "emission"
        const val BUILD_EVENTS = "buildEvents"
        const val OBSERVE_STEADY = "observeSteady"
        const val OBSERVE_FIRST = "observeFirst"
        const val OBSERVE_ALL = "observeAllTypes"
        const val SERVER_401 = "serverResponse401"
        const val SERVER_403 = "serverResponse403"
        const val HOLD_CODE = 3 // not one of AndroidJUnitRunner's status codes

        // What a consumer answers (adapter 4.5.0 problem body; a policy refusal with its reasonCode).
        const val RESPONSE_401 =
            """{"type":"about:blank","title":"Challenge required","status":401,"code":"challenge-required","challengeKind":"step_up"}"""
        const val RESPONSE_403 = """{"code":"RASP_ROOT_ARTIFACTS","attestationReason":null}"""
        private val JSON = "application/problem+json".toMediaType()
        private val REQUEST = Request.Builder().url("https://consumer.invalid/api/operation").build()

        /** One consumer answer, built outside the timed region (the app's HTTP stack has it anyway). */
        fun answer(code: Int, body: String): Response = Response.Builder().request(REQUEST).protocol(Protocol.HTTP_1_1)
            .code(code).message("").body(body.toResponseBody(JSON)).build()

        /**
         * A REPLICA of the transport's D-15b work on one answer (`SentomaruInterceptor.reportServerResponse`, private
         * there): the status and listener check, a peek of up to 4097 bytes (the body stays unread for the app) and the
         * event. the vendor's test run d15d cost check checks the interceptor still has these lines (review R I-1).
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

        /** Every event type of the catalog, DETECTED, with every allowed reason code in the detail keys it reads. */
        fun allTypesSnapshot(): SignalsSnapshot = SignalsSnapshot(
            catalogVersion = SignalsCollector.CATALOG_VERSION,
            collectedAt = "2026-10-24T00:00:00Z",
            durationMs = 0,
            observations = SignalsCatalog.EVENT_TYPES.keys.map { id ->
                val codes = SignalsCatalog.EVENT_REASON_CODES[id].orEmpty()
                SignalObservation(id, SignalsCatalog.CAPABILITIES.first { it.capabilityId == id }.version,
                    SignalState.DETECTED, observedAt = "2026-10-24T00:00:00Z",
                    detail = if (codes.isEmpty()) emptyMap() else mapOf("indicators" to codes.joinToString(",")))
            },
        )

        /** Threads of this process (`/proc/self/task`): the events must start none. */
        fun threads(): Int = File("/proc/self/task").list()?.size ?: -1

        inline fun timed(tally: Tally, block: () -> Unit): Long {
            val cpu0 = Debug.threadCpuTimeNanos()
            val wall0 = SystemClock.elapsedRealtimeNanos()
            block()
            val wall = SystemClock.elapsedRealtimeNanos() - wall0
            val cpu1 = Debug.threadCpuTimeNanos()
            tally.add(wall / 1_000, if (cpu0 < 0 || cpu1 < 0) -1 else (cpu1 - cpu0) / 1_000, emptyList())
            return wall / 1_000
        }

        inline fun timedCollection(tally: Tally, block: () -> SignalsSnapshot): Long {
            val cpu0 = Debug.threadCpuTimeNanos()
            val wall0 = SystemClock.elapsedRealtimeNanos()
            val observations = block().observations
            val wall = SystemClock.elapsedRealtimeNanos() - wall0
            val cpu1 = Debug.threadCpuTimeNanos()
            tally.add(wall / 1_000, if (cpu0 < 0 || cpu1 < 0) -1 else (cpu1 - cpu0) / 1_000, observations)
            return wall / 1_000
        }
    }
}
