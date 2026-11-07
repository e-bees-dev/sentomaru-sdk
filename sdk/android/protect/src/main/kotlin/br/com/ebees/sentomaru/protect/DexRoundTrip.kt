package br.com.ebees.sentomaru.protect

import com.android.tools.smali.dexlib2.Opcodes
import com.android.tools.smali.dexlib2.dexbacked.DexBackedDexFile
import com.android.tools.smali.dexlib2.iface.Annotation
import com.android.tools.smali.dexlib2.iface.ClassDef
import com.android.tools.smali.dexlib2.iface.DexFile
import com.android.tools.smali.dexlib2.iface.MethodImplementation
import com.android.tools.smali.dexlib2.iface.debug.DebugItem
import com.android.tools.smali.dexlib2.iface.instruction.DualReferenceInstruction
import com.android.tools.smali.dexlib2.iface.instruction.FiveRegisterInstruction
import com.android.tools.smali.dexlib2.iface.instruction.Instruction
import com.android.tools.smali.dexlib2.iface.instruction.NarrowLiteralInstruction
import com.android.tools.smali.dexlib2.iface.instruction.OffsetInstruction
import com.android.tools.smali.dexlib2.iface.instruction.OneRegisterInstruction
import com.android.tools.smali.dexlib2.iface.instruction.ReferenceInstruction
import com.android.tools.smali.dexlib2.iface.instruction.RegisterRangeInstruction
import com.android.tools.smali.dexlib2.iface.instruction.ThreeRegisterInstruction
import com.android.tools.smali.dexlib2.iface.instruction.TwoRegisterInstruction
import com.android.tools.smali.dexlib2.iface.instruction.VerificationErrorInstruction
import com.android.tools.smali.dexlib2.iface.instruction.WideLiteralInstruction
import com.android.tools.smali.dexlib2.iface.instruction.formats.ArrayPayload
import com.android.tools.smali.dexlib2.iface.instruction.SwitchPayload
import com.android.tools.smali.dexlib2.iface.reference.Reference
import com.android.tools.smali.dexlib2.iface.value.AnnotationEncodedValue
import com.android.tools.smali.dexlib2.iface.value.ArrayEncodedValue
import com.android.tools.smali.dexlib2.iface.value.BooleanEncodedValue
import com.android.tools.smali.dexlib2.iface.value.ByteEncodedValue
import com.android.tools.smali.dexlib2.iface.value.CharEncodedValue
import com.android.tools.smali.dexlib2.iface.value.DoubleEncodedValue
import com.android.tools.smali.dexlib2.iface.value.EncodedValue
import com.android.tools.smali.dexlib2.iface.value.EnumEncodedValue
import com.android.tools.smali.dexlib2.iface.value.FieldEncodedValue
import com.android.tools.smali.dexlib2.iface.value.FloatEncodedValue
import com.android.tools.smali.dexlib2.iface.value.IntEncodedValue
import com.android.tools.smali.dexlib2.iface.value.LongEncodedValue
import com.android.tools.smali.dexlib2.iface.value.MethodEncodedValue
import com.android.tools.smali.dexlib2.iface.value.MethodHandleEncodedValue
import com.android.tools.smali.dexlib2.iface.value.MethodTypeEncodedValue
import com.android.tools.smali.dexlib2.iface.value.NullEncodedValue
import com.android.tools.smali.dexlib2.iface.value.ShortEncodedValue
import com.android.tools.smali.dexlib2.iface.value.StringEncodedValue
import com.android.tools.smali.dexlib2.iface.value.TypeEncodedValue
import com.android.tools.smali.dexlib2.formatter.DexFormatter
import com.android.tools.smali.dexlib2.writer.io.MemoryDataStore
import com.android.tools.smali.dexlib2.writer.pool.DexPool
import java.security.MessageDigest
import java.util.zip.Adler32

/**
 * D-21p: read a DEX, write it again with nothing changed, and show that the program is the same (the base of the
 * `dex-obfuscation` control, D-21a). The library is dexlib2 of the AOSP smali project (BSD-3-Clause). [rewrite] rebuilds the whole file in dexlib2's own layout (the bytes differ from the input:
 * ordering of the pools, the data section and the map are chosen by the writer), so equality is checked on meaning:
 * [describe] gives a canonical text of every class (flags, super type, interfaces, source file, annotations, fields with
 * their initial values, methods with their registers, instructions, try blocks and debug items) and the two texts must
 * be equal. Reading a name, a string or an instruction through dexlib2 is the same as through ART; what this does NOT
 * prove is that ART accepts the rewritten file (that needs a device or an emulator, the D-21p device step).
 */
internal object DexRoundTrip {
    /** Latest opcode table dexlib2 knows: a DEX the app compiled for any API is read with the opcodes it can use. */
    private val OPCODES: Opcodes = Opcodes.getDefault()

    /**
     * dexlib2's writer drops the explicit initial value of a static field when it is the zero of its type (false, 0,
     * null): ART gives such a field that value anyway, so [describe] reads both as "no initial value". Found by the round
     * trip of the example apps' own DEX (a library with `static boolean sInit = false`); raw float and double bits, so
     * `-0.0` is not a default.
     */
    private val DEFAULT_VALUES = setOf("bool:false", "byte:0", "char:0", "short:0", "int:0", "long:0", "float:0", "double:0", "null")

    class NotWellFormed(message: String, cause: Throwable? = null) : Exception(message, cause)

    fun read(bytes: ByteArray): DexFile = try {
        DexBackedDexFile(OPCODES, bytes)
    } catch (e: Exception) {
        throw NotWellFormed("DEX not readable", e)
    }

    /** The same program, written again by dexlib2. */
    fun rewrite(bytes: ByteArray): ByteArray = write(read(bytes))

    fun write(dex: DexFile): ByteArray {
        val store = MemoryDataStore(64 * 1024)
        DexPool.writeTo(store, dex)
        return store.data.copyOf(store.size)
    }

    /** Header checksum (Adler-32 of bytes 12..) and signature (SHA-1 of bytes 32..), as ART's verifier computes them. */
    fun headerIsConsistent(dex: ByteArray): Boolean {
        if (dex.size < 0x70 || dex[0] != 'd'.code.toByte() || dex[1] != 'e'.code.toByte() || dex[2] != 'x'.code.toByte()) return false
        val adler = Adler32().also { it.update(dex, 12, dex.size - 12) }.value
        val stored = (dex[8].toLong() and 0xff) or ((dex[9].toLong() and 0xff) shl 8) or
            ((dex[10].toLong() and 0xff) shl 16) or ((dex[11].toLong() and 0xff) shl 24)
        val sha1 = MessageDigest.getInstance("SHA-1").also { it.update(dex, 32, dex.size - 32) }.digest()
        return adler == stored && sha1.contentEquals(dex.copyOfRange(12, 32))
    }

    /** The differences between two DEX files in meaning, empty when the programs are the same. */
    fun differences(before: DexFile, after: DexFile): List<String> {
        val a = describe(before)
        val b = describe(after)
        val out = ArrayList<String>()
        for (key in (a.keys + b.keys).sorted()) {
            if (a[key] != b[key]) out += if (key !in a) "class added: $key" else if (key !in b) "class lost: $key" else "class changed: $key"
        }
        return out
    }

    /** Canonical text of each class, by its type descriptor. */
    fun describe(dex: DexFile): Map<String, String> = dex.classes.associate { it.type to describe(it) }

    private fun describe(cls: ClassDef): String = buildString {
        appendLine("class ${cls.type} flags=${cls.accessFlags} super=${cls.superclass} source=${cls.sourceFile}")
        appendLine("interfaces ${cls.interfaces.sorted()}")
        annotations(cls.annotations).forEach { appendLine("  @$it") }
        for (f in (cls.staticFields + cls.instanceFields).sortedBy { DexFormatter.INSTANCE.getReference(it) }) {
            appendLine("field ${DexFormatter.INSTANCE.getReference(f)} flags=${f.accessFlags} value=${f.initialValue?.let(::value)?.takeUnless { it in DEFAULT_VALUES }}")
            annotations(f.annotations).forEach { appendLine("  @$it") }
        }
        for (m in (cls.directMethods + cls.virtualMethods).sortedBy { DexFormatter.INSTANCE.getReference(it) }) {
            appendLine("method ${DexFormatter.INSTANCE.getReference(m)} flags=${m.accessFlags}")
            annotations(m.annotations).forEach { appendLine("  @$it") }
            m.parameters.forEachIndexed { i, p ->
                annotations(p.annotations).forEach { appendLine("  param$i @$it") }
                appendLine("  param$i name=${p.name}")
            }
            m.implementation?.let { implementation(it, this) }
        }
    }

    private fun annotations(set: Set<Annotation>): List<String> = set.map { a ->
        "v${a.visibility} ${a.type} " + a.elements.sortedBy { it.name }.joinToString(",") { "${it.name}=${value(it.value)}" }
    }.sorted()

    private fun implementation(impl: MethodImplementation, out: StringBuilder) {
        out.appendLine("  registers=${impl.registerCount}")
        var address = 0
        for (insn in impl.instructions) {
            out.appendLine("  $address: ${instruction(insn)}")
            address += insn.codeUnits
        }
        for (t in impl.tryBlocks) {
            val handlers = t.exceptionHandlers.joinToString(",") { "${it.exceptionType}@${it.handlerCodeAddress}" }
            out.appendLine("  try ${t.startCodeAddress}+${t.codeUnitCount} $handlers")
        }
        for (d in impl.debugItems) out.appendLine("  debug ${debug(d)}")
    }

    private fun debug(item: DebugItem): String =
        "${item.debugItemType}@${item.codeAddress} " + item.javaClass.interfaces.joinToString("+") { it.simpleName } + " " +
            detailsOf(item)

    // The debug items expose their payload through typed getters; reading them by interface keeps the dump independent
    // of the backing class (DexBacked or Immutable).
    private fun detailsOf(item: DebugItem): String = when (item) {
        is com.android.tools.smali.dexlib2.iface.debug.LineNumber -> "line=${item.lineNumber}"
        is com.android.tools.smali.dexlib2.iface.debug.StartLocal -> "reg=${item.register} name=${item.name} type=${item.type} sig=${item.signature}"
        is com.android.tools.smali.dexlib2.iface.debug.EndLocal -> "reg=${item.register}"
        is com.android.tools.smali.dexlib2.iface.debug.RestartLocal -> "reg=${item.register}"
        is com.android.tools.smali.dexlib2.iface.debug.SetSourceFile -> "file=${item.sourceFile}"
        else -> ""
    }

    private fun instruction(insn: Instruction): String {
        val parts = ArrayList<String>()
        parts += insn.opcode.name
        if (insn is OneRegisterInstruction) parts += "a=${insn.registerA}"
        if (insn is TwoRegisterInstruction) parts += "b=${insn.registerB}"
        if (insn is ThreeRegisterInstruction) parts += "c=${insn.registerC}"
        if (insn is FiveRegisterInstruction) {
            parts += "n=${insn.registerCount} c=${insn.registerC} d=${insn.registerD} e=${insn.registerE} f=${insn.registerF} g=${insn.registerG}"
        }
        if (insn is RegisterRangeInstruction) parts += "start=${insn.startRegister} n=${insn.registerCount}"
        if (insn is NarrowLiteralInstruction) parts += "lit=${insn.narrowLiteral}"
        if (insn is WideLiteralInstruction) parts += "lit=${insn.wideLiteral}"
        if (insn is OffsetInstruction) parts += "off=${insn.codeOffset}"
        if (insn is ReferenceInstruction) parts += "ref=${reference(insn.reference)}"
        if (insn is DualReferenceInstruction) parts += "ref2=${reference(insn.reference2)}"
        if (insn is VerificationErrorInstruction) parts += "verr=${insn.verificationError}"
        if (insn is SwitchPayload) parts += "switch=" + insn.switchElements.joinToString(",") { "${it.key}:${it.offset}" }
        if (insn is ArrayPayload) parts += "width=${insn.elementWidth} data=${insn.arrayElements.joinToString(",")}"
        return parts.joinToString(" ")
    }

    private fun reference(ref: Reference): String = DexFormatter.INSTANCE.getReference(ref)

    private fun value(v: EncodedValue): String = when (v) {
        is AnnotationEncodedValue -> "@${v.type}(" + v.elements.sortedBy { it.name }.joinToString(",") { "${it.name}=${value(it.value)}" } + ")"
        is ArrayEncodedValue -> "[" + v.value.joinToString(",") { value(it) } + "]"
        is BooleanEncodedValue -> "bool:${v.value}"
        is ByteEncodedValue -> "byte:${v.value}"
        is CharEncodedValue -> "char:${v.value.code}"
        is DoubleEncodedValue -> "double:${java.lang.Double.doubleToRawLongBits(v.value)}"
        is EnumEncodedValue -> "enum:${DexFormatter.INSTANCE.getReference(v.value)}"
        is FieldEncodedValue -> "field:${DexFormatter.INSTANCE.getReference(v.value)}"
        is FloatEncodedValue -> "float:${java.lang.Float.floatToRawIntBits(v.value)}"
        is IntEncodedValue -> "int:${v.value}"
        is LongEncodedValue -> "long:${v.value}"
        is MethodEncodedValue -> "method:${DexFormatter.INSTANCE.getReference(v.value)}"
        is MethodHandleEncodedValue -> "handle:${reference(v.value)}"
        is MethodTypeEncodedValue -> "proto:${reference(v.value)}"
        is NullEncodedValue -> "null"
        is ShortEncodedValue -> "short:${v.value}"
        is StringEncodedValue -> "string:${v.value}"
        is TypeEncodedValue -> "type:${v.value}"
        else -> "unknown:${v.valueType}"
    }
}
