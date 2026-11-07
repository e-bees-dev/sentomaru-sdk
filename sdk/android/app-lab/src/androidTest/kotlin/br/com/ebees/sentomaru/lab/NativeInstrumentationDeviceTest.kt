package br.com.ebees.sentomaru.lab

import android.os.Bundle
import android.os.SystemClock
import androidx.test.ext.junit.runners.AndroidJUnit4
import androidx.test.platform.app.InstrumentationRegistry
import br.com.ebees.sentomaru.signals.detectors.NativeInstrumentationDetector
import org.junit.Test
import org.junit.runner.RunWith

/**
 * LAB ONLY. D-19 adversarial matrix: runs the
 * real `NativeInstrumentationDetector` N times in the process of this app and reports, per run, the state, the fixed
 * `indicators` / `partial` codes and the cost in microseconds. Nothing else is read or reported (no path, thread name, pid or address:
 * the detector never carries them).
 *
 * `am instrument -w -r -e class br.com.ebees.sentomaru.lab.NativeInstrumentationDeviceTest -e sentomaruLine <label> [-e sentomaruN 20]
 *  [-e sentomaruWaitMs 0] [-e sentomaruGapMs 200] [-e sentomaruLoadGadget on] <test package>/androidx.test.runner.AndroidJUnitRunner`
 *
 * `sentomaruWaitMs` holds the process still before the first run, so the host can attach the tool (frida, strace) to this very
 * process. `sentomaruLoadGadget on` loads `libfrida-gadget.so` from the APK (the variant the driver builds for the gadget line);
 * without the library the test reports `gadget=missing` and goes on (that line then measures nothing and the driver marks it).
 * Without `sentomaruLine` the test returns early (guard clause, no Assume), so `connectedDebugAndroidTest` stays green.
 */
@RunWith(AndroidJUnit4::class)
class NativeInstrumentationDeviceTest {
    @Test
    fun measure() {
        val args = InstrumentationRegistry.getArguments()
        val line = args.getString("sentomaruLine") ?: return // not a driver invocation
        require(LINE.matches(line)) { "line must match ${LINE.pattern}" }
        val n = (args.getString("sentomaruN") ?: "20").toInt()
        require(n in 1..200) { "N must be 1..200" }
        val waitMs = (args.getString("sentomaruWaitMs") ?: "0").toLong()
        val gapMs = (args.getString("sentomaruGapMs") ?: "200").toLong()
        require(waitMs in 0..120_000 && gapMs in 0..5_000) { "wait/gap out of range" }
        val out = Bundle().apply { putString("sentomaru.line", line); putString("sentomaru.n", n.toString()) }
        if (args.getString("sentomaruLoadGadget") == "on") {
            out.putString("sentomaru.gadget", try { System.loadLibrary("frida-gadget"); "loaded" } catch (_: UnsatisfiedLinkError) { "missing" })
        }
        val context = InstrumentationRegistry.getInstrumentation().targetContext
        val detector = NativeInstrumentationDetector()
        if (waitMs > 0) Thread.sleep(waitMs)
        for (i in 1..n) {
            val t0 = SystemClock.elapsedRealtimeNanos()
            val observation = detector.detect(context)
            val micros = (SystemClock.elapsedRealtimeNanos() - t0) / 1_000L
            val indicators = observation.detail["indicators"] ?: "-"
            val partial = observation.detail["partial"] ?: "-"
            out.putString("sentomaru.run." + i.toString().padStart(2, '0'), "${observation.state.name}|$indicators|$partial|$micros")
            if (gapMs > 0 && i < n) Thread.sleep(gapMs)
        }
        InstrumentationRegistry.getInstrumentation().sendStatus(STATUS_CODE, out)
    }

    private companion object {
        val LINE = Regex("[a-z0-9-]{1,32}")
        const val STATUS_CODE = 7
    }
}
