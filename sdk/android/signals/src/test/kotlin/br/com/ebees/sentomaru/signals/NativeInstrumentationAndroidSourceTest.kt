package br.com.ebees.sentomaru.signals

import android.content.Context
import br.com.ebees.sentomaru.signals.detectors.AndroidNativeInstrumentationSource
import br.com.ebees.sentomaru.signals.detectors.NativeInstrumentationDetector
import org.junit.Assert.*
import org.junit.Rule
import org.junit.Test
import org.junit.rules.TemporaryFolder
import java.io.File
import java.io.IOException
import java.time.Clock
import java.time.Instant
import java.time.ZoneOffset

/** D19-1/D19-3 (revisão A): the real /proc reader, pointed at a fake /proc tree; a read cut at its cap is partial, never complete. */
class NativeInstrumentationAndroidSourceTest {
    @get:Rule val tmp = TemporaryFolder()
    private val clock = Clock.fixed(Instant.parse("2026-11-05T10:00:00Z"), ZoneOffset.UTC)
    private val context: Context = object : android.content.ContextWrapper(null) {}

    private fun proc(maps: List<String>, tasks: Map<String, String> = mapOf("1" to "main")): File {
        val root = tmp.newFolder()
        File(root, "status").writeText("Name:\tapp\nTracerPid:\t0\n")
        File(root, "maps").writeText(maps.joinToString("\n") + "\n")
        for ((tid, comm) in tasks) File(root, "task/$tid").apply { mkdirs() }.let { File(it, "comm").writeText("$comm\n") }
        return root
    }

    @Test fun readsTheThreeProcFiles() {
        val s = AndroidNativeInstrumentationSource(proc(listOf("a /system/lib64/libc.so"), mapOf("1" to "main", "2" to "gum-js-loop")))
        assertEquals(listOf("Name:\tapp", "TracerPid:\t0"), s.statusLines())
        assertEquals(listOf("a /system/lib64/libc.so"), s.mapsLines())
        assertEquals(setOf("main", "gum-js-loop"), s.threadNames().toSet())
    }

    @Test fun aMapsFileExactlyAtTheCapIsComplete() {
        val s = AndroidNativeInstrumentationSource(proc(List(3) { "m$it" }), maxLines = 3)
        assertEquals(3, s.mapsLines().size)
    }

    @Test fun aMapsFileOverTheCapFailsInsteadOfCountingAsComplete() {
        val s = AndroidNativeInstrumentationSource(proc(List(4) { "m$it" }), maxLines = 3)
        assertThrows(IOException::class.java) { s.mapsLines() }
    }

    @Test fun aTaskListOverTheCapFails() {
        val s = AndroidNativeInstrumentationSource(proc(listOf("m"), mapOf("1" to "a", "2" to "b", "3" to "c")), maxTasks = 2)
        assertThrows(IOException::class.java) { s.threadNames() }
    }

    @Test fun theFridaAgentAfterTheCutIsUnknownNotNotDetected() {
        val maps = List(5) { "7f$it r-xp 0 fd:00 1 /system/lib64/libc.so" } + "7fff r-xp 0 fd:00 1 /data/local/tmp/frida-agent-64.so"
        val d = NativeInstrumentationDetector(clock, AndroidNativeInstrumentationSource(proc(maps), maxLines = 3))
        val o = d.detect(context)
        assertNotEquals("not_detected", o.state.name.lowercase())
        assertEquals("UNKNOWN", o.state.name)
        assertTrue(o.detail.toString(), o.detail["partial"]!!.contains("frida_map"))
    }

    @Test fun aHitInsideTheCutPrefixIsDetectedAndOnlyTheOtherMapCheckIsPartial() {
        // D-19 bloco 15: maps over the cap keep their prefix; a Frida agent inside it is real, the hook check saw only a prefix.
        val maps = listOf("7f0 r-xp 0 fd:00 1 /data/local/tmp/frida-agent-64.so") + List(5) { "7f$it r-xp 0 fd:00 1 /system/lib64/libc.so" }
        val o = NativeInstrumentationDetector(clock, AndroidNativeInstrumentationSource(proc(maps), maxLines = 3)).detect(context)
        assertEquals("DETECTED", o.state.name)
        assertEquals("frida_map", o.detail["indicators"])
        assertEquals("hook_map", o.detail["partial"])
    }

    @Test fun aHookFrameworkInsideTheCutPrefixIsDetectedToo() {
        val maps = List(2) { "7f$it r-xp 0 fd:00 1 /system/lib64/libc.so" } + "7fa r-xp 0 fd:00 1 /data/app/x/lib/arm64/liblspd.so" + List(4) { "7e$it r-xp 0 0 0 /x" }
        val o = NativeInstrumentationDetector(clock, AndroidNativeInstrumentationSource(proc(maps), maxLines = 3)).detect(context)
        assertEquals("DETECTED", o.state.name)
        assertEquals("hook_map", o.detail["indicators"])
        assertEquals("frida_map", o.detail["partial"])
    }

    @Test fun aCleanPrefixOfACutReadIsStillUnknownForBothMapChecks() {
        val o = NativeInstrumentationDetector(clock, AndroidNativeInstrumentationSource(proc(List(6) { "7f$it r-xp 0 fd:00 1 /system/lib64/libc.so" }), maxLines = 3)).detect(context)
        assertEquals("UNKNOWN", o.state.name)
        assertEquals("frida_map,hook_map", o.detail["partial"])
    }

    @Test fun theRealCapDefaultKeepsTheTwentyThousandLinePrefix() {
        val maps = List(20_000) { "7f$it r-xp 0 fd:00 1 /system/lib64/libc.so" }.toMutableList()
        maps[19_999] = "7fff r-xp 0 fd:00 1 /data/local/tmp/frida-gadget.so"
        val over = maps + "7ffe r-xp 0 fd:00 1 /x"
        val o = NativeInstrumentationDetector(clock, AndroidNativeInstrumentationSource(proc(over))).detect(context)
        assertEquals("DETECTED", o.state.name)
        assertEquals("frida_map", o.detail["indicators"])
        val exact = NativeInstrumentationDetector(clock, AndroidNativeInstrumentationSource(proc(maps))).detect(context)
        assertEquals("DETECTED", exact.state.name)
        assertNull(exact.detail["partial"]?.takeIf { "frida_map" in it || "hook_map" in it })
    }

    @Test fun aMissingProcFileIsAFailureToo() {
        val root = proc(listOf("m")).also { File(it, "maps").delete() }
        assertThrows(IOException::class.java) { AndroidNativeInstrumentationSource(root).mapsLines() }
    }
}
