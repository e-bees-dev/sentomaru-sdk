package br.com.ebees.sentomaru.protect

import com.android.tools.smali.dexlib2.AccessFlags
import com.android.tools.smali.dexlib2.Opcode
import com.android.tools.smali.dexlib2.Opcodes
import com.android.tools.smali.dexlib2.immutable.ImmutableAnnotation
import com.android.tools.smali.dexlib2.immutable.ImmutableAnnotationElement
import com.android.tools.smali.dexlib2.immutable.ImmutableClassDef
import com.android.tools.smali.dexlib2.immutable.ImmutableDexFile
import com.android.tools.smali.dexlib2.immutable.ImmutableField
import com.android.tools.smali.dexlib2.immutable.ImmutableMethod
import com.android.tools.smali.dexlib2.immutable.ImmutableMethodImplementation
import com.android.tools.smali.dexlib2.immutable.ImmutableMethodParameter
import com.android.tools.smali.dexlib2.immutable.instruction.ImmutableInstruction10x
import com.android.tools.smali.dexlib2.immutable.instruction.ImmutableInstruction11x
import com.android.tools.smali.dexlib2.immutable.instruction.ImmutableInstruction21c
import com.android.tools.smali.dexlib2.immutable.instruction.ImmutableInstruction21s
import com.android.tools.smali.dexlib2.immutable.instruction.ImmutableInstruction35c
import com.android.tools.smali.dexlib2.immutable.instruction.ImmutableInstruction10t
import com.android.tools.smali.dexlib2.immutable.reference.ImmutableMethodReference
import com.android.tools.smali.dexlib2.immutable.reference.ImmutableStringReference
import com.android.tools.smali.dexlib2.immutable.value.ImmutableIntEncodedValue
import com.android.tools.smali.dexlib2.immutable.value.ImmutableStringEncodedValue
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNotEquals
import org.junit.Assert.assertThrows
import org.junit.Assert.assertTrue
import org.junit.Assume.assumeTrue
import org.junit.Test
import java.io.File
import java.util.zip.ZipFile

/**
 * D-21p: reading a DEX and writing it again changes the bytes (dexlib2 lays the file out itself) and nothing in the
 * meaning. Inputs: a synthetic DEX, the runtime DEX this CLI embeds (a real d8 output), and, when given, the APKs of
 * the example apps (`-Dsentomaru.dexRoundTripApks=a.apk:b.apk`; local, not in the CI).
 */
class DexRoundTripTest {
    private val opcodes = Opcodes.getDefault()

    /** A class with an annotation, a static field with a value, and a method with a branch, a call and a string. */
    private fun synthetic(): ByteArray {
        val obj = "Ljava/lang/Object;"
        val init = ImmutableMethodReference(obj, "<init>", emptyList<CharSequence>(), "V")
        val clinitLike = ImmutableMethod(
            "Lpkg/Sample;", "run", listOf(ImmutableMethodParameter("I", emptySet(), "n")), "Ljava/lang/String;",
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
        val constructor = ImmutableMethod(
            "Lpkg/Sample;", "<init>", emptyList<ImmutableMethodParameter>(), "V",
            AccessFlags.PUBLIC.value or AccessFlags.CONSTRUCTOR.value, emptySet(), null,
            ImmutableMethodImplementation(
                1,
                listOf(ImmutableInstruction35c(Opcode.INVOKE_DIRECT, 1, 0, 0, 0, 0, 0, init), ImmutableInstruction10x(Opcode.RETURN_VOID)),
                null, null,
            ),
        )
        val annotation = ImmutableAnnotation(
            1, "Lpkg/Tag;", listOf(ImmutableAnnotationElement("label", ImmutableStringEncodedValue("x"))),
        )
        val field = ImmutableField(
            "Lpkg/Sample;", "LIMIT", "I", AccessFlags.PUBLIC.value or AccessFlags.STATIC.value or AccessFlags.FINAL.value,
            ImmutableIntEncodedValue(42), emptySet(), null,
        )
        val cls = ImmutableClassDef(
            "Lpkg/Sample;", AccessFlags.PUBLIC.value, obj, emptyList<String>(), "Sample.java", setOf(annotation),
            listOf(field), listOf(constructor, clinitLike),
        )
        return DexRoundTrip.write(ImmutableDexFile(opcodes, listOf(cls)))
    }

    private fun assertSameProgram(input: ByteArray, label: String) {
        val before = DexRoundTrip.read(input)
        val output = DexRoundTrip.rewrite(input)
        assertTrue("$label: header checksum and signature of the rewritten file", DexRoundTrip.headerIsConsistent(output))
        val differences = DexRoundTrip.differences(before, DexRoundTrip.read(output))
        assertEquals("$label: ${differences.take(5)}", emptyList<String>(), differences)
        assertEquals("$label: same classes", before.classes.size, DexRoundTrip.read(output).classes.size)
        // A second pass changes nothing more: the layout is stable.
        assertTrue("$label: second pass is byte-identical", output.contentEquals(DexRoundTrip.rewrite(output)))
    }

    @Test
    fun syntheticDexKeepsItsMeaning() {
        val input = synthetic()
        assertTrue(DexRoundTrip.headerIsConsistent(input))
        assertSameProgram(input, "synthetic")
        val text = DexRoundTrip.describe(DexRoundTrip.read(input)).getValue("Lpkg/Sample;")
        assertTrue(text, "value=int:42" in text && "const-string a=0 ref=\"hello\"" in text && "@v1 Lpkg/Tag; label=string:x" in text)
    }

    @Test
    fun theEmbeddedRuntimeDexKeepsItsMeaning() {
        val bytes = DexRoundTripTest::class.java.getResourceAsStream("/br/com/ebees/sentomaru/protect/runtime/classes.dex")!!
            .use { it.readBytes() }
        assertSameProgram(bytes, "runtime classes.dex")
        assertTrue(DexRoundTrip.read(bytes).classes.isNotEmpty())
    }

    @Test
    fun anExplicitZeroInitialValueIsTheSameAsNone() {
        val flags = AccessFlags.PUBLIC.value or AccessFlags.STATIC.value
        fun dexWith(value: com.android.tools.smali.dexlib2.iface.value.EncodedValue?) = DexRoundTrip.write(ImmutableDexFile(opcodes, listOf(
            ImmutableClassDef("Lpkg/Z;", AccessFlags.PUBLIC.value, "Ljava/lang/Object;", emptyList<String>(), null, emptySet(),
                listOf(ImmutableField("Lpkg/Z;", "f", "I", flags, value, emptySet(), null)), emptyList<ImmutableMethod>()))))
        val explicit = DexRoundTrip.read(dexWith(ImmutableIntEncodedValue(0)))
        val none = DexRoundTrip.read(dexWith(null))
        assertEquals(emptyList<String>(), DexRoundTrip.differences(explicit, none))
        // A non-zero value is a difference.
        assertNotEquals(emptyList<String>(), DexRoundTrip.differences(DexRoundTrip.read(dexWith(ImmutableIntEncodedValue(1))), none))
    }

    @Test
    fun aChangeInMeaningIsSeen() {
        val a = DexRoundTrip.read(synthetic())
        val changed = synthetic().let { String(it, Charsets.ISO_8859_1).replace("hello", "jello").toByteArray(Charsets.ISO_8859_1) }
        // The string is in the data section; the checksum is wrong now, but dexlib2 reads it anyway: the text differs.
        val b = DexRoundTrip.read(changed)
        assertNotEquals(emptyList<String>(), DexRoundTrip.differences(a, b))
        assertFalse(DexRoundTrip.headerIsConsistent(changed))
    }

    @Test
    fun aDexThatIsNotWellFormedIsRefused() {
        assertThrows(DexRoundTrip.NotWellFormed::class.java) { DexRoundTrip.rewrite(ByteArray(0)) }
        assertThrows(DexRoundTrip.NotWellFormed::class.java) { DexRoundTrip.rewrite("not a dex file at all".toByteArray()) }
        assertThrows(DexRoundTrip.NotWellFormed::class.java) { DexRoundTrip.rewrite(synthetic().copyOf(80)) }
        assertFalse(DexRoundTrip.headerIsConsistent(ByteArray(10)))
    }

    @Test
    fun theExampleAppsKeepTheirMeaning() {
        val apks = System.getProperty("sentomaru.dexRoundTripApks").orEmpty().split(File.pathSeparator).filter { it.isNotBlank() }
        assumeTrue("no -Dsentomaru.dexRoundTripApks", apks.isNotEmpty())
        for (path in apks) ZipFile(path).use { zip ->
            val dexes = zip.entries().asSequence().filter { Regex("""classes\d*\.dex""").matches(it.name) }.toList()
            assertTrue("$path has no classes.dex", dexes.isNotEmpty())
            for (entry in dexes) {
                val bytes = zip.getInputStream(entry).use { it.readBytes() }
                assertSameProgram(bytes, "${File(path).name}!${entry.name}")
            }
        }
    }
}
