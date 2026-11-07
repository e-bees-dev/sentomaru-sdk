package br.com.ebees.sentomaru.perf

import android.os.Bundle
import android.os.Debug
import androidx.test.ext.junit.runners.AndroidJUnit4
import androidx.test.platform.app.InstrumentationRegistry
import br.com.ebees.sentomaru.signals.SignalsCollector
import org.json.JSONObject
import org.junit.Test
import org.junit.runner.RunWith

/**
 * D-05d-2: the emulator layer of the RASP matrix (`verification/rasp/matrix-v1.json`), driven by
 * `verification/run_d05d_emulator.py` on an AVD (never on the SM-A055M, never in the PR CI).
 * Arguments:
 * - `d05d` = `collect` or `debugger`; absent, the test returns at once (guard clause, as `RaspCostInstrumentedTest`),
 *   so a plain `connectedDebugAndroidTest` stays green without measuring anything;
 * - collect: `rounds` (default 20) rounds of the six D-05 detectors (`raspDetectors()`), each one guarded like the
 *   collector (`RaspCost.detectOnce`: a throw is ERROR `thrown=1`, never clean). The deadline is the collector's
 *   concern (D-05c); here each detector gives its own verdict;
 * - debugger: a daemon thread of this process calls `Debug.waitForDebugger()` (a debuggable app may; the VM then
 *   reports `waitingForDebugger`), and once the flag is up `rounds` rounds are taken (phase `waiting`). Then the
 *   status `d05dDebugger=waiting` asks the runner to attach `jdb` over JDWP, the test waits up to `attachS` (default
 *   60) seconds for `Debug.isDebuggerConnected()`, waits for the waiting flag to drop (`waitForDebugger()` returns a
 *   moment after the attach) and takes `rounds` more rounds (phase `connected`) while it stays attached. `am set-debug-app -w` is not used: with it the VM waits in `bindApplication`, before any app code runs,
 *   so the app itself can never observe the waiting state;
 * - in every mode the JSON (states and details per capability, fixed codes only) goes to the instrumentation result
 *   `d05d`, with `debuggable` (the `FLAG_DEBUGGABLE` of this build) for the runner to check the build it installed.
 * Off the main thread (the instrumentation thread; checked).
 */
@RunWith(AndroidJUnit4::class)
class RaspMatrixInstrumentedTest {

    @Test
    fun rasp_matrix() {
        val instrumentation = InstrumentationRegistry.getInstrumentation()
        val arguments = InstrumentationRegistry.getArguments()
        val mode = arguments.getString("d05d") ?: return
        RaspCost.requireWorkerThread()
        val context = instrumentation.targetContext
        val rounds = arguments.getString("rounds")?.toInt() ?: 20
        require(rounds in 1..500) { "rounds must be 1..500" }
        val detectors = SignalsCollector.raspDetectors()
        val take = {
            val tally = Tally()
            repeat(rounds) { detectors.forEach { tally.countOnly(RaspCost.detectOnce(it, context)) } }
            tally.toJson(samples = false)
        }
        val debuggable = context.applicationInfo.flags and android.content.pm.ApplicationInfo.FLAG_DEBUGGABLE != 0
        val result = JSONObject().put("mode", mode).put("rounds", rounds).put("debuggable", debuggable)
            .put("selinuxDomain", RaspCost.selinuxDomain())
        val phases = JSONObject()
        try {
            when (mode) {
                "collect" -> phases.put("collect", take())
                "debugger" -> {
                    val attachS = arguments.getString("attachS")?.toLong() ?: 60
                    Thread({ Debug.waitForDebugger() }, "d05d-wait-for-debugger").apply { isDaemon = true }.start()
                    check(poll(10_000) { Debug.waitingForDebugger() }) { "waitingForDebugger never came up" }
                    phases.put("waiting", take())
                    instrumentation.sendStatus(STATUS_CODE, Bundle().apply { putString("d05dDebugger", "waiting") })
                    val connected = poll(attachS * 1_000) { Debug.isDebuggerConnected() }
                    result.put("debuggerConnected", connected)
                    // waitForDebugger() returns a moment after the attach: the connected phase starts once the waiting
                    // flag is down, so its rounds see the attached debugger alone
                    if (connected) {
                        result.put("waitEnded", poll(10_000) { !Debug.waitingForDebugger() })
                        phases.put("connected", take())
                    }
                }
                else -> throw IllegalArgumentException("d05d must be collect or debugger")
            }
        } finally {
            instrumentation.addResults(Bundle().apply { putString("d05d", result.put("phases", phases).toString()) })
        }
    }

    private fun poll(timeoutMs: Long, condition: () -> Boolean): Boolean {
        val deadline = System.nanoTime() + timeoutMs * 1_000_000
        while (System.nanoTime() < deadline) {
            if (condition()) return true
            Thread.sleep(100)
        }
        return condition()
    }

    private companion object {
        const val STATUS_CODE = 3 // not one of AndroidJUnitRunner's status codes (1, 0, -1, -2, -3, -4)
    }
}
