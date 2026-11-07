package br.com.ebees.sentomaru.protect

import java.io.File
import java.nio.ByteBuffer
import java.nio.ByteOrder
import java.util.zip.ZipFile

/**
 * Read-only look at the app's DEX files (G-03c): which of the given classes the base module **defines**. Only the
 * header, `class_defs`, `type_ids`, `string_ids` and the string data of each defined class are read: a class counts when
 * a `class_def_item` points, through its type, to the descriptor. A string or a type reference alone is not a class.
 * Nothing is decoded further and nothing is written. A DEX that is not well formed, or above [MAX_DEX_BYTES],
 * contributes nothing: absence is never read as presence, so the control that asks refuses. D-08d: a package prefix
 * (`Lpkg/`) counts when a defined class descriptor starts with it.
 */
internal object DexScan {
    /** Real DEX files are a few MiB to about 16 MiB (one DEX holds at most 64K method references); 4x margin. */
    const val MAX_DEX_BYTES = 64 * 1024 * 1024
    const val MAX_DEX_FILES = 256
    private const val HEADER_SIZE = 0x70
    private const val STRING_IDS = 0x38
    private const val TYPE_IDS = 0x40
    private const val CLASS_DEFS = 0x60
    private const val CLASS_DEF_SIZE = 32
    private val APK_DEX = Regex("""classes\d*\.dex""")
    private val AAB_DEX = Regex("""base/dex/classes\d*\.dex""")

    /** What [scan] found, and whether a base DEX was skipped (above the limits or not well formed). */
    class Scan(val found: Set<String>, val skipped: Boolean)

    /**
     * The subset of [descriptors] (ASCII type descriptors, e.g. `Lpkg/Name;`) defined in the artifact's base DEX files,
     * plus the [prefixes] some defined class starts with. [control] names the asking control in a refusal.
     */
    fun present(file: File, kind: ArtifactKind, descriptors: Set<String>, prefixes: Set<String> = emptySet(),
        control: String = NetworkSigning.id): Set<String> = scan(file, kind, descriptors, prefixes, control).found

    /**
     * [present], plus whether some base DEX contributed nothing because it was skipped (D-08d: an absence then proves
     * nothing). The scan stops early once everything is found; a DEX after that is not looked at and not counted.
     */
    fun scan(file: File, kind: ArtifactKind, descriptors: Set<String>, prefixes: Set<String> = emptySet(),
        control: String = NetworkSigning.id): Scan {
        val pattern = if (kind == ArtifactKind.AAB) AAB_DEX else APK_DEX
        val wanted = descriptors + prefixes
        val found = HashSet<String>()
        var skipped = false
        try {
            ZipFile(file).use { zip ->
                val all = zip.entries().asSequence().filter { pattern.matches(it.name) }.toList()
                if (all.size > MAX_DEX_FILES) skipped = true
                for (entry in all.take(MAX_DEX_FILES)) {
                    if (entry.size > MAX_DEX_BYTES) { skipped = true; continue }
                    val bytes = zip.getInputStream(entry).use { it.readNBytes(MAX_DEX_BYTES + 1) }
                    if (bytes.size > MAX_DEX_BYTES || !wellFormed(bytes)) { skipped = true; continue }
                    found += classes(bytes, descriptors - found, prefixes - found)
                    if (found.size == wanted.size) break
                }
            }
        } catch (e: OutOfMemoryError) {
            throw ProtectException(ErrorCode.APP_INCOMPATIBLE, "$control: the app DEX could not be read within memory")
        }
        return Scan(found, skipped)
    }

    /** The DEX magic and the three tables [classes] reads within the file. */
    internal fun wellFormed(dex: ByteArray): Boolean {
        if (dex.size < HEADER_SIZE || !dex.copyOfRange(0, 4).contentEquals("dex\n".toByteArray())) return false
        val b = ByteBuffer.wrap(dex).order(ByteOrder.LITTLE_ENDIAN)
        return listOf(STRING_IDS to 4, TYPE_IDS to 4, CLASS_DEFS to CLASS_DEF_SIZE).all { (at, entry) ->
            val count = b.getInt(at).toLong() and 0xffffffffL
            val offset = b.getInt(at + 4).toLong() and 0xffffffffL
            offset >= HEADER_SIZE && offset + count * entry <= dex.size
        }
    }

    /**
     * The subset of [wanted] defined by a `class_def_item` of [dex], plus the [prefixes] a defined class starts with;
     * empty for anything not well formed.
     */
    internal fun classes(dex: ByteArray, wanted: Set<String>, prefixes: Set<String> = emptySet()): Set<String> {
        if ((wanted.isEmpty() && prefixes.isEmpty()) || dex.size < HEADER_SIZE || !dex.copyOfRange(0, 4).contentEquals("dex\n".toByteArray())) return emptySet()
        val b = ByteBuffer.wrap(dex).order(ByteOrder.LITTLE_ENDIAN)
        fun u32(at: Long): Long = b.getInt(at.toInt()).toLong() and 0xffffffffL
        fun table(at: Int, entry: Int): Pair<Long, Long>? {
            val count = u32(at.toLong())
            val offset = u32(at + 4L)
            return if (offset < HEADER_SIZE || offset + count * entry > dex.size) null else count to offset
        }
        val (stringCount, stringOff) = table(STRING_IDS, 4) ?: return emptySet()
        val (typeCount, typeOff) = table(TYPE_IDS, 4) ?: return emptySet()
        val (classCount, classOff) = table(CLASS_DEFS, CLASS_DEF_SIZE) ?: return emptySet()
        // A descriptor matches up to its terminating 0; a prefix only needs its bytes (it has no 0, so it stays in one string).
        val targets = wanted.map { Triple(it, it.toByteArray(Charsets.US_ASCII), true) } +
            prefixes.map { Triple(it, it.toByteArray(Charsets.US_ASCII), false) }
        val hit = HashSet<String>()
        for (i in 0 until classCount) {
            val typeIndex = u32(classOff + i * CLASS_DEF_SIZE)
            if (typeIndex >= typeCount) continue
            val stringIndex = u32(typeOff + typeIndex * 4)
            if (stringIndex >= stringCount) continue
            val at = u32(stringOff + stringIndex * 4)
            if (at >= dex.size) continue
            // string_data_item: uleb128 utf16 length (at most 5 bytes), then MUTF-8 bytes ending in 0.
            var p = at.toInt()
            var read = 0
            while (p < dex.size && read < 5) { val v = dex[p++].toInt(); read++; if (v and 0x80 == 0) break }
            for ((name, bytes, exact) in targets) {
                if (name in hit || p + bytes.size >= dex.size) continue
                if ((!exact || dex[p + bytes.size] == 0.toByte()) && bytes.indices.all { dex[p + it] == bytes[it] }) hit += name
            }
            if (hit.size == targets.size) break
        }
        return hit
    }
}
