package br.com.ebees.sentomaru.perf

import android.app.AlarmManager
import android.app.Instrumentation
import android.app.PendingIntent
import android.content.Intent
import android.os.Bundle
import android.os.SystemClock
import androidx.test.ext.junit.runners.AndroidJUnit4
import androidx.test.platform.app.InstrumentationRegistry
import org.json.JSONObject
import org.junit.Test
import org.junit.runner.RunWith

/**
 * D-05c cost of the signals detectors, driven by `verification/run_d05c_cost.py` (never in CI).
 * Arguments:
 * - `d05c` = `warm` or `cold`; absent, the test returns at once (guard clause, as `DeviceBridge` in app-lab), so a
 *   plain `connectedDebugAndroidTest` stays green without measuring anything;
 * - warm: `runs` (default 300) and `warmup` (default 30) rounds in this process; each round runs every target once,
 *   in catalog order, `collection` last; the warmup rounds are not kept. The detectors and the collector are built
 *   once and reused, as an app holding a collector would;
 * - cold: `target` = a capability id or `collection`; one run, the first SDK call of a fresh process (the runner
 *   force-stops the app and starts one instrumentation per run). For a capability the detector objects are built
 *   before the clock starts (their first `detect` is timed); for `collection` building the collector is timed too.
 * - canary: schedules one non-wakeup alarm an hour ahead, holds, then cancels it. The runner must see exactly that
 *   alarm in its snapshot, the proof that its dumps and parsers see what this app leaves scheduled;
 * - `holdS` (warm, cold, canary): after the measurement, outside every timed region, the test sends the status
 *   `d05cHold=ready` and keeps the process alive that many seconds, so the runner reads `dumpsys` while the app
 *   still lives (the end of an instrumentation may force-stop the app, which would cancel jobs and alarms).
 * Off the main thread (the instrumentation thread; checked). The JSON goes to the instrumentation result `d05c`.
 */
@RunWith(AndroidJUnit4::class)
class RaspCostInstrumentedTest {

    @Test
    fun rasp_cost() {
        val instrumentation = InstrumentationRegistry.getInstrumentation()
        val arguments = InstrumentationRegistry.getArguments()
        val mode = arguments.getString("d05c") ?: return
        RaspCost.requireWorkerThread()
        val context = instrumentation.targetContext
        val result = JSONObject().put("mode", mode).put("selinuxDomain", RaspCost.selinuxDomain())
        val targets = JSONObject()
        try {
            when (mode) {
                "cold" -> {
                    val target = requireNotNull(arguments.getString("target")) { "target argument required" }
                    val tally = Tally()
                    if (target == RaspCost.COLLECTION) {
                        RaspCost.timed(tally) { RaspCost.collector().snapshot(context).observations }
                    } else {
                        val detector = requireNotNull(RaspCost.detectors().firstOrNull { it.capabilityId == target }) {
                            "unknown target"
                        }
                        RaspCost.timed(tally) { RaspCost.detectOnce(detector, context) }
                    }
                    targets.put(target, tally.toJson())
                }
                "warm" -> {
                    val runs = arguments.getString("runs")?.toInt() ?: 300
                    val warmup = arguments.getString("warmup")?.toInt() ?: 30
                    val detectors = RaspCost.detectors()
                    val collector = RaspCost.collector()
                    val tallies = (detectors.map { it.capabilityId } + RaspCost.COLLECTION).associateWith { Tally() }
                    val discard = Tally()
                    repeat(warmup + runs) { round ->
                        for (detector in detectors) {
                            RaspCost.timed(if (round < warmup) discard else tallies.getValue(detector.capabilityId)) {
                                RaspCost.detectOnce(detector, context)
                            }
                        }
                        RaspCost.timed(if (round < warmup) discard else tallies.getValue(RaspCost.COLLECTION)) {
                            collector.snapshot(context).observations
                        }
                    }
                    result.put("runs", runs).put("warmup", warmup)
                    tallies.forEach { (id, tally) -> targets.put(id, tally.toJson()) }
                }
                "canary" -> {
                    val alarms = context.getSystemService(AlarmManager::class.java)
                    val canary = PendingIntent.getBroadcast(context, 0,
                        Intent(CANARY_ACTION).setPackage(context.packageName), PendingIntent.FLAG_IMMUTABLE)
                    alarms.set(AlarmManager.ELAPSED_REALTIME, SystemClock.elapsedRealtime() + 3_600_000, canary)
                    try {
                        hold(instrumentation, arguments)
                    } finally {
                        alarms.cancel(canary)
                    }
                }
                else -> throw IllegalArgumentException("d05c must be warm, cold or canary")
            }
            if (mode != "canary") hold(instrumentation, arguments)
        } finally {
            instrumentation.addResults(Bundle().apply { putString("d05c", result.put("targets", targets).toString()) })
        }
    }

    private fun hold(instrumentation: Instrumentation, arguments: Bundle) {
        val seconds = arguments.getString("holdS")?.toLong() ?: return
        instrumentation.sendStatus(HOLD_CODE, Bundle().apply { putString("d05cHold", "ready") })
        Thread.sleep(seconds * 1_000)
    }

    private companion object {
        const val CANARY_ACTION = "br.com.ebees.sentomaru.perf.D05C_CANARY"
        const val HOLD_CODE = 3 // not one of AndroidJUnitRunner's status codes (1, 0, -1, -2, -3, -4)
    }
}
