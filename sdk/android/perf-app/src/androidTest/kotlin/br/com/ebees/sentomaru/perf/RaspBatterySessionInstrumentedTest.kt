package br.com.ebees.sentomaru.perf

import android.os.Bundle
import android.os.SystemClock
import androidx.test.ext.junit.runners.AndroidJUnit4
import androidx.test.platform.app.InstrumentationRegistry
import org.json.JSONObject
import org.junit.Test
import org.junit.runner.RunWith

/**
 * D-05c battery session, driven by `the vendor's run d05c cost check --battery-session` (never in CI; reported, not
 * gated). Arguments:
 * - `d05cBattery` = `collect` (one full D-05 collection per tick, the ExampleApp signals cache period) or `control`
 *   (same process, same ticks, no collection); absent, the test returns at once;
 * - `durationS` (default 3600) and `intervalMs` (default 8000).
 * The ticks are scheduled on `elapsedRealtime` and slept with `Thread.sleep` on the instrumentation thread: no
 * wakelock, alarm, job or service, so a tick delayed by device sleep is counted in `lateTicks`, never forced.
 * The summary goes to the instrumentation result `d05cBattery`.
 */
@RunWith(AndroidJUnit4::class)
class RaspBatterySessionInstrumentedTest {

    @Test
    fun battery_session() {
        val instrumentation = InstrumentationRegistry.getInstrumentation()
        val arguments = InstrumentationRegistry.getArguments()
        val session = arguments.getString("d05cBattery") ?: return
        require(session == "collect" || session == "control") { "d05cBattery must be collect or control" }
        RaspCost.requireWorkerThread()
        val durationMs = (arguments.getString("durationS")?.toLong() ?: 3600L) * 1000
        val intervalMs = arguments.getString("intervalMs")?.toLong() ?: 8000L
        val context = instrumentation.targetContext
        val collector = RaspCost.collector()
        val tally = Tally()
        var ticks = 0
        var lateTicks = 0
        val start = SystemClock.elapsedRealtime()
        try {
            while (true) {
                val due = start + ticks * intervalMs
                val now = SystemClock.elapsedRealtime()
                if (due - start >= durationMs) break
                if (now > due + intervalMs) lateTicks++
                if (now < due) Thread.sleep(due - now)
                if (session == "collect") RaspCost.timed(tally) { collector.snapshot(context).observations }
                ticks++
            }
        } finally {
            val result = JSONObject().put("session", session).put("durationS", durationMs / 1000)
                .put("intervalMs", intervalMs).put("ticks", ticks).put("lateTicks", lateTicks)
                .put("elapsedMs", SystemClock.elapsedRealtime() - start)
                .put("selinuxDomain", RaspCost.selinuxDomain()).put("collection", tally.toJson())
            instrumentation.addResults(Bundle().apply { putString("d05cBattery", result.toString()) })
        }
    }
}
