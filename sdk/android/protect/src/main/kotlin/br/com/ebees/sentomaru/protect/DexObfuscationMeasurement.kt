package br.com.ebees.sentomaru.protect

import com.android.tools.smali.dexlib2.formatter.DexFormatter
import com.android.tools.smali.dexlib2.iface.ClassDef
import com.android.tools.smali.dexlib2.iface.DexFile
import com.android.tools.smali.dexlib2.iface.Method
import java.io.File

/**
 * D-21a3 (the cost/break-rate slice only): the measurement instrument the `dex-obfuscation` report (D-16) needs,
 * built ahead of the transformation itself (D-21a1 opaque predicates, D-21a2 flattening are not built yet) so the
 * harness is ready the day one lands. Wires into nothing: not called from `protect`'s pipeline or from any CLI
 * command, no default `targetMethods`, opt-in only (the project's own risk mitigation for D-21: "medição
 * obrigatória" before anything claims a gain, never the gain itself).
 *
 * Measures a `before`/`after` DEX pair some transform already produced (today only `DexObfuscationMeasurementTest`'s
 * own hand-built opaque-predicate shape exercises it: there is no real transform yet). Per method:
 *  - cost: instruction-count and code-unit delta of each method in [targetMethods] (never device startup time or
 *    verification time: that needs the D-21p device step this project does not have — real `dex-obfuscation` builds
 *    would add a device run on top of this, not replace it);
 *  - break: dexlib2 refuses to read [before] or [after] back (`DexRoundTrip.NotWellFormed`), a target method is
 *    missing after the transform, or a class with no target method changed anyway (`DexRoundTrip.describe`): the
 *    transform's own exclusion list let something through. None of this proves ART accepts the file or that a
 *    target method's own result is unchanged for every input — only a device does (same gap D-21p already named).
 *    [dexdumpAccepts] adds the other static check the project's own acceptance bar names (`dexdump`), kept separate
 *    so [measure] itself stays a pure JVM function with no process to spawn.
 */
object DexObfuscationMeasurement {
    data class MethodCost(val method: String, val beforeInstructions: Int, val afterInstructions: Int,
                           val beforeCodeUnits: Int, val afterCodeUnits: Int) {
        val instructionDelta: Int get() = afterInstructions - beforeInstructions
        val codeUnitDelta: Int get() = afterCodeUnits - beforeCodeUnits
    }

    data class Report(val methodsChecked: Int, val broken: List<String>, val costs: List<MethodCost>,
                       val beforeTotalBytes: Int, val afterTotalBytes: Int) {
        /** 1.0, never a false 0.0, when [before]/[after] could not even be read (nothing was checked, so nothing
         * can be called a success either; revisor A, rodada 2, baixo C). Otherwise the share of [methodsChecked] -
         * the target methods actually present in `before`, never the caller's whole [targetMethods], which could
         * dilute a real break with methods this transform never touched - that ended up in [broken]. */
        val breakRate: Double get() = when {
            broken.any { it.startsWith("before: ") || it.startsWith("after: ") } -> 1.0
            methodsChecked == 0 -> 0.0
            else -> broken.size.toDouble() / methodsChecked
        }
        val sizeDeltaBytes: Int get() = afterTotalBytes - beforeTotalBytes
        val sizeDeltaPercent: Double get() = if (beforeTotalBytes == 0) 0.0 else sizeDeltaBytes * 100.0 / beforeTotalBytes
    }

    /**
     * [targetMethods] the fully qualified `DexFormatter` references (`Lpkg/Class;->name(params)return`) the
     * transform meant to touch. Every other class is checked only for "no side effect": any difference there is
     * counted broken, since it means the transform's exclusion list missed something (a class holding at least one
     * target method is skipped for that check — distinguishing an untouched sibling method from the transform's own
     * work would need a per-method diff this object does not have).
     */
    fun measure(before: ByteArray, after: ByteArray, targetMethods: Set<String>): Report {
        val beforeDex = runCatching { DexRoundTrip.read(before) }.getOrNull()
        val afterDex = runCatching { DexRoundTrip.read(after) }.getOrNull()
        val broken = mutableListOf<String>()
        if (beforeDex == null) broken += "before: not well formed"
        if (afterDex == null) broken += "after: not well formed"
        val costs = mutableListOf<MethodCost>()
        var methodsChecked = 0
        if (beforeDex != null && afterDex != null) {
            val beforeIndex = index(beforeDex)
            val afterIndex = index(afterDex)
            for (key in targetMethods) {
                val b = beforeIndex[key] ?: continue // not this transform's concern: it was never in `before`
                methodsChecked++
                val a = afterIndex[key]
                if (a == null) { broken += "$key: missing after transform"; continue }
                costs += MethodCost(key, instructionCount(b), instructionCount(a), codeUnitCount(b), codeUnitCount(a))
            }
            val untouchedClasses = targetMethods.map { it.substringBefore("->") }.toSet()
            val beforeText = DexRoundTrip.describe(beforeDex)
            val afterText = DexRoundTrip.describe(afterDex)
            for (type in beforeText.keys) {
                if (type in untouchedClasses) continue
                if (beforeText[type] != afterText[type]) broken += "$type: changed outside the target list"
            }
        }
        return Report(methodsChecked, broken, costs, before.size, after.size)
    }

    /** The other static acceptance check the project names ("dexdump/verificador do ART aceita"); a nonzero exit or
     * a timeout is refused, never thrown. No check at all (false) when [dexdump] is not an executable file: the
     * harness still runs without the Android SDK on the PATH, with a smaller, explicit guarantee.
     *
     * Revisor A, rodada 2 (médio B): `dexdump` writes its whole disassembly to stdout; redirecting it to a file
     * (instead of leaving it on the inherited pipe and never reading it) means a real, non-trivial DEX cannot fill
     * the pipe buffer and deadlock the child before [waitFor] gives up - a real DEX was timing out and coming back
     * `false` ("rejected") only because nothing drained the pipe, never because `dexdump` actually refused it. On a
     * timeout the process is also killed outright, instead of left running past the method's return. */
    fun dexdumpAccepts(dex: ByteArray, dexdump: File): Boolean {
        if (!dexdump.canExecute()) return false
        val temp = File.createTempFile("sentomaru-measure-", ".dex")
        val output = File.createTempFile("sentomaru-measure-", ".dexdump.out")
        return try {
            temp.writeBytes(dex)
            val process = ProcessBuilder(dexdump.absolutePath, temp.absolutePath)
                .redirectErrorStream(true).redirectOutput(output).start()
            val finished = process.waitFor(30, java.util.concurrent.TimeUnit.SECONDS)
            if (!finished) process.destroyForcibly()
            finished && process.exitValue() == 0
        } catch (e: java.io.IOException) {
            false
        } finally {
            temp.delete()
            output.delete()
        }
    }

    private fun index(dex: DexFile): Map<String, Method> =
        dex.classes.flatMap { methodsOf(it) }.associateBy { DexFormatter.INSTANCE.getReference(it) }

    private fun methodsOf(cls: ClassDef): List<Method> = (cls.directMethods + cls.virtualMethods).toList()

    private fun instructionCount(m: Method): Int = m.implementation?.instructions?.count() ?: 0
    private fun codeUnitCount(m: Method): Int = m.implementation?.instructions?.sumOf { it.codeUnits } ?: 0
}
