package br.com.ebees.sentomaru.sdk.sealed

import java.io.File
import java.io.FileNotFoundException

/** The shared D-14a vectors (contracts/devsecops/sealed-v1-vectors.json), read once per test JVM. */
@Suppress("UNCHECKED_CAST")
object Vectors {
    val all: Map<String, Any?> by lazy {
        val path = requireNotNull(System.getProperty("sentomaru.sealedVectors")) { "sentomaru.sealedVectors not set" }
        MiniJson.parse(File(path).readText(Charsets.UTF_8)) as Map<String, Any?>
    }

    val cases: List<Map<String, Any?>> get() = all["cases"] as List<Map<String, Any?>>
    val negative: List<Map<String, Any?>> get() = all["negative"] as List<Map<String, Any?>>

    fun case(name: String): Map<String, Any?> = cases.single { it["name"] == name }

    fun hex(s: String): ByteArray = SealedFormat.hex(s)

    fun ByteArray.hex(): String = joinToString("") { "%02x".format(it.toInt() and 0xff) }

    fun header(case: Map<String, Any?>): Map<String, Any?> = case["header"] as Map<String, Any?>
    fun files(case: Map<String, Any?>): List<Map<String, Any?>> = case["files"] as List<Map<String, Any?>>
    fun versionCode(case: Map<String, Any?>): Long = case["versionCode"] as Long

    /** The installed `base` module of a case: `header.bin` and the sealed entries, by canonical name. */
    fun entries(case: Map<String, Any?>): MutableMap<String, ByteArray> {
        val out = linkedMapOf(header(case)["entry"] as String to hex(header(case)["sealedHex"] as String))
        for (f in files(case)) out[f["sealedEntry"] as String] = hex(f["sealedHex"] as String)
        return out
    }

    /** The vectors' mutation of one entry (`op`: delete, move, xor, set, truncate, pad, replace). */
    fun mutated(case: Map<String, Any?>, spec: Map<String, Any?>): MutableMap<String, ByteArray> {
        val entries = entries(case)
        val target = spec["target"] as String? ?: return entries
        val name = if (target == "header") header(case)["entry"] as String else SealedFormat.entryName(target)
        val op = spec["op"] as Map<String, Any?>
        val data = entries.getValue(name)
        fun at(offset: Long) = (if (offset < 0) data.size + offset else offset).toInt()
        entries[name] = when (op["kind"]) {
            "delete" -> return entries.also { it.remove(name) }
            "move" -> return entries.also { it[SealedFormat.entryName(op["to"] as String)] = it.remove(name)!! }
            "xor" -> data.copyOf().also { val i = at(op["offset"] as Long); it[i] = (it[i].toInt() xor (op["value"] as Long).toInt()).toByte() }
            "set" -> data.copyOf().also { val new = hex(op["hex"] as String); new.copyInto(it, at(op["offset"] as Long)) }
            "truncate" -> data.copyOf((op["length"] as Long).toInt())
            "pad" -> data + ByteArray((op["length"] as Long).toInt())
            "replace" -> hex(op["hex"] as String)
            else -> error("unknown op ${op["kind"]}")
        }
        return entries
    }
}

/** A [SealedSource] over a map of entries, counting the reads of each name. */
internal class MapSource(private val entries: Map<String, ByteArray>) : SealedSource {
    val reads = HashMap<String, Int>()

    override fun read(path: String, limit: Int): ByteArray? {
        reads.merge(path, 1, Int::plus)
        return entries[path]?.let { it.copyOf(minOf(it.size, limit + 1)) }
    }

    override fun readAll(path: String): ByteArray = entries[path]?.copyOf() ?: throw FileNotFoundException(path)
}

/** A [SealedSource] over a directory laid out as the APK's `assets/` (an unsealed debug build). */
internal class DirSource(private val assets: File) : SealedSource {
    private fun file(path: String) = File(assets, path.removePrefix("assets/"))

    override fun read(path: String, limit: Int): ByteArray? =
        file(path).takeIf { it.isFile }?.readBytes()?.let { it.copyOf(minOf(it.size, limit + 1)) }

    override fun readAll(path: String): ByteArray = file(path).takeIf { it.isFile }?.readBytes() ?: throw FileNotFoundException(path)
}
