package br.com.ebees.sentomaru.protect

import com.android.tools.smali.dexlib2.AccessFlags
import com.android.tools.smali.dexlib2.Opcode
import com.android.tools.smali.dexlib2.Opcodes
import com.android.tools.smali.dexlib2.immutable.ImmutableClassDef
import com.android.tools.smali.dexlib2.immutable.ImmutableDexFile
import com.android.tools.smali.dexlib2.immutable.ImmutableMethod
import com.android.tools.smali.dexlib2.immutable.ImmutableMethodImplementation
import com.android.tools.smali.dexlib2.immutable.ImmutableMethodParameter
import com.android.tools.smali.dexlib2.immutable.instruction.ImmutableInstruction10t
import com.android.tools.smali.dexlib2.immutable.instruction.ImmutableInstruction11x
import com.android.tools.smali.dexlib2.immutable.instruction.ImmutableInstruction21c
import com.android.tools.smali.dexlib2.immutable.instruction.ImmutableInstruction21s
import com.android.tools.smali.dexlib2.immutable.instruction.ImmutableInstruction21t
import com.android.tools.smali.dexlib2.immutable.reference.ImmutableStringReference
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test
import java.io.File

/**
 * D-21a3 (lite): the cost/break-rate instrument, exercised with a hand-built opaque-predicate shape (no D-21a1 exists
 * to produce one yet). The "after" fixtures below insert exactly the branch D-21a1 is scoped to insert (`contracts`
 * table: "insere desvio condicional com resultado fixo... em métodos marcados"), built by hand with dexlib2's
 * `Immutable*` instruction types instead of by a transform, so the harness has something real to measure today.
 */
class DexObfuscationMeasurementTest {
    private val opcodes = Opcodes.getDefault()
    private val target = "Lpkg/Guarded;->guarded(I)Ljava/lang/String;"

    /** `const/16 v1, 7` / `goto +1` (a no-op forward jump, kept from the project's own DexRoundTrip fixture) /
     * `const-string v0, "hello"` / `return-object v0`. 2 registers, 4 instructions. */
    private fun plainMethod(): ImmutableMethod = ImmutableMethod(
        "Lpkg/Guarded;", "guarded", listOf(ImmutableMethodParameter("I", emptySet(), "n")), "Ljava/lang/String;",
        AccessFlags.PUBLIC.value, emptySet(), null,
        ImmutableMethodImplementation(
            2,
            listOf(
                ImmutableInstruction21s(Opcode.CONST_16, 1, 7),
                ImmutableInstruction10t(Opcode.GOTO, 1),
                ImmutableInstruction21c(Opcode.CONST_STRING, 0, ImmutableStringReference("hello")),
                ImmutableInstruction11x(Opcode.RETURN_OBJECT, 0),
            ),
            null, null,
        ),
    )

    /** The plain method with an opaque predicate guarding it: `const/16 v2, 1` / `if-nez v2, :real` (always taken,
     * never provably so without running it) / a dead branch that returns a different, unreachable string / `:real`
     * the original four instructions unchanged. 3 registers (one more, for the predicate), 8 instructions. */
    private fun guardedMethod(): ImmutableMethod = ImmutableMethod(
        "Lpkg/Guarded;", "guarded", listOf(ImmutableMethodParameter("I", emptySet(), "n")), "Ljava/lang/String;",
        AccessFlags.PUBLIC.value, emptySet(), null,
        ImmutableMethodImplementation(
            3,
            listOf(
                ImmutableInstruction21s(Opcode.CONST_16, 2, 1), // addr 0, cu 2
                ImmutableInstruction21t(Opcode.IF_NEZ, 2, 5), // addr 2, cu 2, target addr 7 (":real")
                ImmutableInstruction21c(Opcode.CONST_STRING, 0, ImmutableStringReference("dead")), // addr 4, cu 2
                ImmutableInstruction11x(Opcode.RETURN_OBJECT, 0), // addr 6, cu 1
                ImmutableInstruction21s(Opcode.CONST_16, 1, 7), // addr 7, cu 2 (":real")
                ImmutableInstruction10t(Opcode.GOTO, 1), // addr 9, cu 1
                ImmutableInstruction21c(Opcode.CONST_STRING, 0, ImmutableStringReference("hello")), // addr 10, cu 2
                ImmutableInstruction11x(Opcode.RETURN_OBJECT, 0), // addr 12, cu 1
            ),
            null, null,
        ),
    )

    private fun otherMethod(literal: Int = 1): ImmutableMethod = ImmutableMethod(
        "Lpkg/Other;", "untouched", emptyList<ImmutableMethodParameter>(), "I",
        AccessFlags.PUBLIC.value, emptySet(), null,
        ImmutableMethodImplementation(1, listOf(ImmutableInstruction21s(Opcode.CONST_16, 0, literal), ImmutableInstruction11x(Opcode.RETURN, 0)), null, null),
    )

    private fun classOf(method: ImmutableMethod): ImmutableClassDef = ImmutableClassDef(
        method.definingClass, AccessFlags.PUBLIC.value, "Ljava/lang/Object;", emptyList<String>(), null, emptySet(),
        emptyList(), listOf(method),
    )

    private fun dexOf(vararg methods: ImmutableMethod): ByteArray =
        DexRoundTrip.write(ImmutableDexFile(opcodes, methods.map { classOf(it) }))

    @Test
    fun theOpaquePredicateFixtureIsWellFormedAndDexlib2ReadsBothBranches() {
        val before = dexOf(plainMethod())
        val after = dexOf(guardedMethod())
        assertTrue(DexRoundTrip.headerIsConsistent(before))
        assertTrue(DexRoundTrip.headerIsConsistent(after))
        val report = DexObfuscationMeasurement.measure(before, after, setOf(target))
        assertEquals(emptyList<String>(), report.broken)
        assertEquals(0.0, report.breakRate, 0.0)
        assertEquals(1, report.costs.size)
        val cost = report.costs.single()
        assertEquals(4, cost.beforeInstructions)
        assertEquals(8, cost.afterInstructions)
        assertEquals(4, cost.instructionDelta) // the cost: the predicate and the dead branch, every time
        assertTrue("size grew", report.sizeDeltaBytes > 0)
        assertTrue("percent grew", report.sizeDeltaPercent > 0.0)
    }

    @Test
    fun aMethodTheTransformNeverSeesIsIgnored() {
        val report = DexObfuscationMeasurement.measure(dexOf(otherMethod()), dexOf(otherMethod()), setOf(target))
        assertEquals(0, report.costs.size)
        assertEquals(emptyList<String>(), report.broken) // nothing in `before` matched `target`: not this transform's concern
    }

    @Test
    fun aTargetMethodMissingAfterTheTransformIsBroken() {
        val before = dexOf(plainMethod())
        val after = dexOf(otherMethod()) // the transform lost the target method entirely
        val report = DexObfuscationMeasurement.measure(before, after, setOf(target))
        assertEquals(listOf("$target: missing after transform"), report.broken)
        assertEquals(1.0, report.breakRate, 0.0)
    }

    @Test
    fun aSideEffectOnAnUntargetedClassIsBroken() {
        val before = dexOf(plainMethod(), otherMethod(1))
        val after = dexOf(guardedMethod(), otherMethod(2)) // the exclusion list let `Lpkg/Other;` through
        val report = DexObfuscationMeasurement.measure(before, after, setOf(target))
        assertEquals(listOf("Lpkg/Other;: changed outside the target list"), report.broken)
        assertEquals(1.0, report.breakRate, 0.0) // one target method checked, one break recorded
    }

    @Test
    fun malformedInputIsBrokenNeverThrown() {
        val report = DexObfuscationMeasurement.measure(ByteArray(0), dexOf(plainMethod()), setOf(target))
        assertEquals(listOf("before: not well formed"), report.broken)
    }

    @Test
    fun aTargetMethodNeverInBeforeDoesNotDiluteTheBreakRateOfOneThatActuallyBroke() {
        // revisor A, rodada 2, baixo C: `targetMethods` also names a method this transform never saw; before the fix
        // it still counted toward the denominator and made a 100% break on the method that mattered look like 50%.
        val before = dexOf(plainMethod())
        val after = dexOf(otherMethod()) // the one target method present in `before` is gone after the transform
        val neverSeen = "Lpkg/NeverSeen;->x()V"
        val report = DexObfuscationMeasurement.measure(before, after, setOf(target, neverSeen))
        assertEquals(1, report.methodsChecked) // only `target`, not `neverSeen`
        assertEquals(1.0, report.breakRate, 0.0)
    }

    @Test
    fun breakRateIsOneWhenBeforeFailsToParseEvenWithNoTargetMethods() {
        // revisor A, rodada 2, baixo C: `methodsChecked == 0` must not read as "0% broken" when `before` itself
        // could not be read at all - there `broken` is non-empty and the old formula still said 0.0.
        val report = DexObfuscationMeasurement.measure(ByteArray(0), dexOf(plainMethod()), emptySet())
        assertEquals(0, report.methodsChecked)
        assertEquals(listOf("before: not well formed"), report.broken)
        assertEquals(1.0, report.breakRate, 0.0)
    }

    @Test
    fun dexdumpAcceptsIsFalseWithoutAnExecutableBinary() {
        assertTrue(DexObfuscationMeasurement.dexdumpAccepts(dexOf(plainMethod()), File("/nonexistent/dexdump")) == false)
    }

    @Test
    fun dexdumpAcceptsDrainsLargeOutputInsteadOfDeadlockingOnTheProcessPipe() {
        // revisor A, rodada 2, médio B: a fake `dexdump` that only prints more than one pipe buffer (commonly 64
        // KiB) and exits 0 used to time out and come back `false`, with nothing read from `process.inputStream`.
        val fake = File.createTempFile("sentomaru-fake-dexdump-", ".sh")
        try {
            fake.writeText("#!/bin/sh\nhead -c 2000000 /dev/zero | tr '\\0' 'x'\nexit 0\n")
            fake.setExecutable(true)
            val start = System.nanoTime()
            assertTrue(DexObfuscationMeasurement.dexdumpAccepts(dexOf(plainMethod()), fake))
            val elapsedSeconds = (System.nanoTime() - start) / 1_000_000_000.0
            assertTrue("took $elapsedSeconds s: looks like it waited for the 30 s timeout, not a drained pipe", elapsedSeconds < 10.0)
        } finally {
            fake.delete()
        }
    }

    /** Local only (`-Dsentomaru.dexdump=/path/to/dexdump`): the Android SDK's own static checker, the other half of
     * the project's acceptance bar ("dexdump/verificador do ART aceita"), against both fixtures. */
    @Test
    fun dexdumpAcceptsBothFixturesWhenTheBinaryIsAvailable() {
        val path = System.getProperty("sentomaru.dexdump").orEmpty()
        org.junit.Assume.assumeTrue("no -Dsentomaru.dexdump", path.isNotBlank())
        val dexdump = File(path)
        assertTrue(DexObfuscationMeasurement.dexdumpAccepts(dexOf(plainMethod()), dexdump))
        assertTrue(DexObfuscationMeasurement.dexdumpAccepts(dexOf(guardedMethod()), dexdump))
    }
}
