package br.com.ebees.sentomaru.signals

import android.content.Context
import br.com.ebees.sentomaru.signals.detectors.NativeInstrumentationDetector
import br.com.ebees.sentomaru.signals.detectors.NativeInstrumentationSource
import org.junit.Assert.*
import org.junit.Test
import java.io.IOException
import java.time.Clock
import java.time.Instant
import java.time.ZoneOffset

/**
 * D-19 (contract `contracts/sdk/native-instrumentation-v1.md`): the Java-side reading of /proc for ptrace, Frida's agent and
 * gadget, its threads and its default port. No NDK. The detector is not in the shipped catalog yet; these tests are its
 * whole proof, with a double of the four reads.
 */
class NativeInstrumentationDetectorTest {
    private val clock = Clock.fixed(Instant.parse("2026-11-05T10:00:00Z"), ZoneOffset.UTC)
    private val context: Context = object : android.content.ContextWrapper(null) {}

    private class Source(
        var status: List<String> = listOf("Name:\tapp", "State:\tS (sleeping)", "TracerPid:\t0", "Uid:\t10441"),
        var maps: List<String> = listOf("7f00000000-7f00001000 r-xp 00000000 fd:00 1234 /system/lib64/libc.so",
            "7f00002000-7f00003000 rw-p 00000000 00:00 0 [anon:libc_malloc]"),
        var threads: List<String> = listOf("main", "RenderThread", "OkHttp Dispatcher", "HeapTaskDaemon"),
        var port: Boolean = false,
        var failing: Set<String> = emptySet(),
    ) : NativeInstrumentationSource {
        private fun guard(call: String) { if (call in failing) throw IOException("denied") }
        override fun statusLines() = status.also { guard("status") }
        override fun mapsLines() = maps.also { guard("maps") }
        override fun threadNames() = threads.also { guard("threads") }
        override fun fridaPortOpen() = port.also { guard("port") }
    }

    private fun run(source: Source) = NativeInstrumentationDetector(clock, source).detect(context)
    private fun indicators(o: SignalObservation) = o.detail["indicators"]

    @Test fun aCleanProcessIsNotDetectedAndEveryCheckRan() {
        val o = run(Source())
        assertEquals("native_instrumentation", o.capabilityId)
        assertEquals(SignalState.NOT_DETECTED, o.state)
        assertEquals("none", indicators(o))
        assertNull(o.detail["partial"])
    }

    @Test fun aTracerPidThatIsNotZeroIsDetected() {
        val o = run(Source(status = listOf("Name:\tapp", "TracerPid:\t4242")))
        assertEquals(SignalState.DETECTED, o.state)
        assertEquals("tracer_attached", indicators(o))
    }

    @Test fun aMalformedOrMissingTracerPidIsUnknownNotClean() {
        for (status in listOf(listOf("Name:\tapp"), listOf("TracerPid:\tabc"), listOf("TracerPid:"), emptyList())) {
            val o = run(Source(status = status))
            assertEquals(status.toString(), SignalState.UNKNOWN, o.state)
            assertEquals("none", indicators(o))
            assertEquals("tracer_pid", o.detail["partial"])
        }
    }

    @Test fun fridaAgentAndGadgetInTheMapsAreDetected() {
        for (name in listOf("frida-agent-64.so", "frida-agent-32.so", "libfrida-gadget.so", "frida-gadget.so", "/data/local/tmp/re.frida.server/frida-agent-64.so")) {
            val o = run(Source(maps = listOf("7f00-7f10 r-xp 00000000 fd:00 99 /data/local/tmp/$name")))
            assertEquals(name, SignalState.DETECTED, o.state)
            assertEquals(name, "frida_map", indicators(o))
        }
    }

    @Test fun anUnrelatedLibraryWithFridaInItsNameIsNotAMatch() {
        // "friday" and a path component are not Frida's agent or gadget.
        val o = run(Source(maps = listOf("7f00-7f10 r-xp 0 fd:00 99 /data/app/libfridayplanner.so", "7f20-7f30 r--p 0 fd:00 98 /data/app/fridge.so")))
        assertEquals(SignalState.NOT_DETECTED, o.state)
    }

    @Test fun theGumJsLoopThreadIsDetectedAndGenericGlibThreadsAreNot() {
        assertEquals("frida_thread", indicators(run(Source(threads = listOf("main", "gum-js-loop")))))
        assertEquals("frida_thread", indicators(run(Source(threads = listOf("pool-frida")))))
        // gmain and gdbus are glib's names, used by many legitimate native libraries: not an indicator alone.
        assertEquals(SignalState.NOT_DETECTED, run(Source(threads = listOf("main", "gmain", "gdbus"))).state)
    }

    @Test fun anOpenFridaDefaultPortIsDetected() {
        val o = run(Source(port = true))
        assertEquals(SignalState.DETECTED, o.state)
        assertEquals("frida_port", indicators(o))
    }

    @Test fun severalIndicatorsAreListedInAFixedOrder() {
        val o = run(Source(status = listOf("TracerPid:\t7"), maps = listOf("7f-8f r-xp 0 fd:00 1 /x/frida-agent-64.so"), threads = listOf("gum-js-loop"), port = true))
        assertEquals("tracer_attached,frida_map,frida_thread,frida_port", indicators(o))
    }

    @Test fun xposedLsposedEdxposedAndSubstrateInTheMapsAreDetectedAsHookMap() {
        for (name in listOf("/system/framework/XposedBridge.jar", "/data/adb/modules/zygisk_lsposed/lib/liblspd.so", "/data/misc/lsposed/x.dex",
                "/data/adb/edxp/libedxposed.so", "/data/local/tmp/libsubstrate.so")) {
            val o = run(Source(maps = listOf("7f00-7f10 r-xp 00000000 fd:00 99 $name")))
            assertEquals(name, SignalState.DETECTED, o.state)
            assertEquals(name, "hook_map", indicators(o))
        }
    }

    @Test fun aLibraryThatOnlyLooksLikeAHookFrameworkIsNotAMatch() {
        val o = run(Source(maps = listOf("7f00-7f10 r-xp 0 fd:00 99 /data/app/libsubstitute.so", "7f20-7f30 r--p 0 fd:00 98 /data/app/libposed.so")))
        assertEquals(SignalState.NOT_DETECTED, o.state)
    }

    @Test fun fridaAndHookFrameworkTogetherListBothInTheFixedOrder() {
        val o = run(Source(maps = listOf("7f-8f r-xp 0 fd:00 1 /x/frida-agent-64.so", "7f-8f r-xp 0 fd:00 2 /x/liblspd.so")))
        assertEquals("frida_map,hook_map", indicators(o))
    }

    @Test fun aReadThatFailsMakesThatCheckPartialAndTheStateUnknownUnlessSomethingWasFound() {
        for ((call, code) in mapOf("status" to "tracer_pid", "maps" to "frida_map,hook_map", "threads" to "frida_thread", "port" to "frida_port")) {
            val o = run(Source(failing = setOf(call)))
            assertEquals(call, SignalState.UNKNOWN, o.state)
            assertEquals(call, code, o.detail["partial"])
        }
        // A found indicator wins over a check that could not run.
        val found = run(Source(status = listOf("TracerPid:\t9"), failing = setOf("maps")))
        assertEquals(SignalState.DETECTED, found.state)
        assertEquals("frida_map,hook_map", found.detail["partial"])
    }

    @Test fun theDetailCarriesFixedCodesOnlyNeverAPathAThreadNameOrAPid() {
        val o = run(Source(status = listOf("TracerPid:\t31337"), maps = listOf("7f-8f r-xp 0 fd:00 1 /data/local/tmp/secret-dir/frida-agent-64.so"), threads = listOf("gum-js-loop"), port = true))
        val text = o.detail.toString()
        for (leak in listOf("31337", "secret-dir", "/data", "gum-js-loop", "frida-agent")) assertFalse(leak, text.contains(leak))
        assertTrue(o.detail.values.all { v -> v.split(',').all { it in setOf("none", "tracer_attached", "frida_map", "hook_map", "frida_thread", "frida_port", "tracer_pid") } })
    }

    @Test fun anUnexpectedExceptionInTheDetectorItselfIsErrorNotACrash() {
        val bad = object : NativeInstrumentationSource {
            override fun statusLines(): List<String> = throw IllegalStateException("bug")
            override fun mapsLines() = emptyList<String>()
            override fun threadNames() = emptyList<String>()
            override fun fridaPortOpen() = false
        }
        // statusLines throwing IllegalStateException is a platform-call failure (partial), not an ERROR: the detector never throws.
        val o = NativeInstrumentationDetector(clock, bad).detect(context)
        assertNotEquals(SignalState.ERROR, o.state)
        assertEquals("tracer_pid", o.detail["partial"])
    }

    @Test fun theBudgetCoversTheLoopbackConnect() {
        assertTrue(NativeInstrumentationDetector(clock, Source()).budgetMs in 10L..50L)
    }
}
