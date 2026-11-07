package br.com.ebees.sentomaru.signals.detectors

import android.content.Context
import br.com.ebees.sentomaru.signals.*
import java.io.File
import java.io.IOException
import java.net.ConnectException
import java.net.InetSocketAddress
import java.net.Socket
import java.time.Clock

/**
 * D-19 (contract `contracts/sdk/native-instrumentation-v1.md`): what the Java side can read of native instrumentation in its
 * own process, without the NDK: a ptrace tracer (`TracerPid` in `/proc/self/status`), Frida's agent or gadget among the mapped
 * files, Frida's own threads, and a listener on Frida's default port. Each read is one platform call, so a denied or missing
 * file is a check that did not run (UNKNOWN), never a clean answer.
 */
interface NativeInstrumentationSource {
    /** Lines of `/proc/self/status`. */
    fun statusLines(): List<String>
    /** Lines of `/proc/self/maps`. */
    fun mapsLines(): List<String>
    /** `comm` of every task of the process. */
    fun threadNames(): List<String>
    /** True when something accepts a TCP connection on 127.0.0.1:[NativeInstrumentationDetector.FRIDA_PORT]; false when it is refused. */
    fun fridaPortOpen(): Boolean
}

/**
 * A read that hit its line cap. [lines] is the prefix that was read (at most the cap): what is in it is real, what is past it
 * was not seen. The detector counts a hit in the prefix and treats a miss as a check that did not run, never as complete.
 */
class PartialRead(val lines: List<String>, message: String) : IOException(message)

class AndroidNativeInstrumentationSource(
    private val procRoot: File = File("/proc/self"),
    private val maxLines: Int = MAX_LINES,
    private val maxTasks: Int = MAX_TASKS,
) : NativeInstrumentationSource {
    /** A read cut at the cap did not see the whole file: it fails (partial -> UNKNOWN), it never counts as complete. */
    private fun lines(name: String, keepPrefix: Boolean = false): List<String> = File(procRoot, name).bufferedReader().useLines { seq ->
        val read = seq.take(maxLines + 1).toList()
        if (read.size > maxLines) {
            // `maps` of a process with many libraries can pass the cap: its prefix still holds real hits (D-19, bloco 15).
            if (keepPrefix) throw PartialRead(read.take(maxLines), "$name over $maxLines lines")
            throw IOException("$name over $maxLines lines")
        }
        read
    }

    override fun statusLines(): List<String> = lines("status")
    override fun mapsLines(): List<String> = lines("maps", keepPrefix = true)

    override fun threadNames(): List<String> {
        val tasks = File(procRoot, "task").listFiles() ?: throw IOException("no task list")
        if (tasks.size > maxTasks) throw IOException("task list over $maxTasks")
        return tasks.mapNotNull { runCatching { File(it, "comm").readText().trim() }.getOrNull() }
    }

    override fun fridaPortOpen(): Boolean = try {
        Socket().use { it.connect(InetSocketAddress("127.0.0.1", NativeInstrumentationDetector.FRIDA_PORT), CONNECT_TIMEOUT_MS); true }
    } catch (_: ConnectException) {
        false // refused: nothing listens, a complete answer
    }

    private companion object {
        const val MAX_LINES = 20_000
        const val MAX_TASKS = 1_024
        const val CONNECT_TIMEOUT_MS = 15
    }
}

class NativeInstrumentationDetector(
    private val clock: Clock = Clock.systemUTC(),
    private val source: NativeInstrumentationSource = AndroidNativeInstrumentationSource(),
) : SignalDetector {
    override val capabilityId = "native_instrumentation"
    override val version = "1.0.0"
    override val budgetMs = 25L

    companion object {
        const val FRIDA_PORT = 27042
        /** Substrings of a mapped file name; "frida-" alone would match unrelated libraries. */
        val FRIDA_MAP_MARKERS = listOf("frida-agent", "frida-gadget")
        /**
         * Xposed family and Substrate in the mapped files (D-19): the Xposed bridge jar, LSPosed's and EdXposed's own libraries,
         * Cydia Substrate. Matched on the file name, lower case; a hook framework can rename them (the contract says so).
         */
        val HOOK_MAP_MARKERS = listOf("xposedbridge", "liblspd", "lsposed", "edxposed", "libsubstrate")
        /** Frida's JS runtime and pool threads. glib's `gmain` and `gdbus` are not here: legitimate libraries use them. */
        val FRIDA_THREADS = setOf("gum-js-loop", "pool-frida")
    }

    override fun detect(context: Context): SignalObservation =
        Evidence.collect(capabilityId, version, clock.instant().toString()) { e ->
            val status = e.probe("tracer_pid") { source.statusLines() }
            if (status != null) {
                val pid = status.firstOrNull { it.startsWith("TracerPid:") }?.substringAfter(':')?.trim()?.toIntOrNull()
                when {
                    pid == null || pid < 0 -> e.notRun("tracer_pid")
                    pid > 0 -> e.found("tracer_attached")
                }
            }
            fun hits(lines: List<String>, markers: List<String>) = lines.any { line -> val l = line.lowercase(); markers.any { l.contains(it) } }
            // One read feeds both map checks. A read cut at its cap (PartialRead) keeps its prefix: a hit there stands, a miss is partial.
            val read: Any? = try {
                source.mapsLines()
            } catch (p: PartialRead) {
                p
            } catch (x: Exception) {
                e.notRun("frida_map", x); e.notRun("hook_map", x); null
            } catch (x: LinkageError) {
                e.notRun("frida_map", x); e.notRun("hook_map", x); null
            }
            if (read is PartialRead) {
                e.cut("frida_map", hits(read.lines, FRIDA_MAP_MARKERS))
                e.cut("hook_map", hits(read.lines, HOOK_MAP_MARKERS))
            } else if (read is List<*>) {
                @Suppress("UNCHECKED_CAST") val maps = read as List<String>
                if (hits(maps, FRIDA_MAP_MARKERS)) e.found("frida_map")
                if (hits(maps, HOOK_MAP_MARKERS)) e.found("hook_map")
            }
            val threads = e.probe("frida_thread") { source.threadNames() }
            if (threads != null && threads.any { it in FRIDA_THREADS }) e.found("frida_thread")
            e.check("frida_port") { source.fridaPortOpen() }
        }
}
