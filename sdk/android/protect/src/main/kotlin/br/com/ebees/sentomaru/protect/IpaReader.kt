package br.com.ebees.sentomaru.protect

import java.io.File
import java.io.InputStream
import java.nio.ByteBuffer
import java.security.MessageDigest
import java.util.zip.ZipFile
import javax.xml.XMLConstants
import javax.xml.parsers.DocumentBuilderFactory
import org.w3c.dom.Element

/** What `protect --dry-run` reports about an IPA (G-03g1): names and versions only, no app content. */
data class IpaFacts(
    val sha256: String,
    val appDirectory: String,
    val bundleId: String,
    val shortVersion: String?,
    val buildVersion: String?,
    val minimumOsVersion: String?,
    val executable: String?,
    val frameworks: List<String>,
    /** A `Sentomaru*.framework` in `Frameworks/`; an SDK compiled into the app (the Flutter pod) is not seen. */
    val sentomaruFramework: Boolean,
    val hasProvisioningProfile: Boolean,
)

/**
 * Reads an IPA without changing it: the zip, the single `Payload/<name>.app`, its `Info.plist` (XML or binary) and the
 * frameworks it embeds. Reading the signature or the provisioning profile is not done here; the profile is only
 * reported as present.
 */
object IpaReader {
    private const val MAX_PLIST_BYTES = 8 * 1024 * 1024
    private val APP = Regex("""\APayload/([^/]+\.app)/""")

    fun read(file: File): IpaFacts {
        if (file.length() > ArtifactReader.MAX_BYTES) throw ProtectException(ErrorCode.INPUT_TOO_LARGE, "input above 512 MiB")
        val sha = sha256(file)
        try {
            ZipFile(file).use { zip ->
                val names = ArrayList<String>()
                val entries = zip.entries()
                while (entries.hasMoreElements()) {
                    val name = entries.nextElement().name
                    if (names.size >= ArtifactReader.MAX_ENTRIES) throw ProtectException(ErrorCode.INPUT_FORMAT, "more than ${ArtifactReader.MAX_ENTRIES} entries")
                    if (name.startsWith("/") || name.split('/').any { it == ".." }) throw ProtectException(ErrorCode.INPUT_FORMAT, "unsafe entry name")
                    names.add(name)
                }
                val apps = names.mapNotNull { APP.find(it)?.groupValues?.get(1) }.toSortedSet()
                if (apps.size != 1) throw ProtectException(ErrorCode.INPUT_FORMAT, "expected one Payload/<name>.app, found ${apps.size}")
                val dir = "Payload/${apps.first()}/"
                val entry = zip.getEntry(dir + "Info.plist") ?: throw ProtectException(ErrorCode.INPUT_FORMAT, "Info.plist missing")
                if (entry.size > MAX_PLIST_BYTES) throw ProtectException(ErrorCode.INPUT_FORMAT, "Info.plist above 8 MiB")
                val plist = zip.getInputStream(entry).use { parsePlist(it) }
                val bundleId = (plist["CFBundleIdentifier"] as? String)?.takeIf { it.isNotEmpty() }
                    ?: throw ProtectException(ErrorCode.INPUT_FORMAT, "CFBundleIdentifier missing")
                val frameworks = names.filter { it.startsWith(dir + "Frameworks/") }
                    .mapNotNull { Regex("""\AFrameworks/([^/]+\.framework)/""").find(it.removePrefix(dir))?.groupValues?.get(1) }
                    .toSortedSet().toList()
                return IpaFacts(sha, apps.first(), bundleId, plist["CFBundleShortVersionString"] as? String,
                    plist["CFBundleVersion"] as? String, plist["MinimumOSVersion"] as? String, plist["CFBundleExecutable"] as? String,
                    frameworks, frameworks.any { it.startsWith("Sentomaru") }, (dir + "embedded.mobileprovision") in names)
            }
        } catch (e: ProtectException) {
            throw e
        } catch (e: Exception) {
            throw ProtectException(ErrorCode.INPUT_FORMAT, "not a readable IPA")
        }
    }

    internal fun parsePlist(input: InputStream): Map<String, Any?> {
        val bytes = input.readNBytes(MAX_PLIST_BYTES + 1)
        if (bytes.size > MAX_PLIST_BYTES) throw ProtectException(ErrorCode.INPUT_FORMAT, "Info.plist above 8 MiB")
        val root = if (bytes.size > 8 && String(bytes, 0, 8, Charsets.ISO_8859_1) == "bplist00") Binary(bytes).root() else xml(bytes)
        @Suppress("UNCHECKED_CAST")
        return root as? Map<String, Any?> ?: throw ProtectException(ErrorCode.INPUT_FORMAT, "Info.plist is not a dictionary")
    }

    private fun xml(bytes: ByteArray): Any? {
        val factory = DocumentBuilderFactory.newInstance().apply {
            setFeature(XMLConstants.FEATURE_SECURE_PROCESSING, true)
            setFeature("http://apache.org/xml/features/disallow-doctype-decl", false)
            setFeature("http://apache.org/xml/features/nonvalidating/load-external-dtd", false)
            setFeature("http://xml.org/sax/features/external-general-entities", false)
            setFeature("http://xml.org/sax/features/external-parameter-entities", false)
            isXIncludeAware = false
            isExpandEntityReferences = false
        }
        val doc = factory.newDocumentBuilder().apply { setEntityResolver { _, _ -> org.xml.sax.InputSource(java.io.StringReader("")) } }
            .parse(bytes.inputStream())
        val top = doc.documentElement
        if (top.tagName != "plist") throw ProtectException(ErrorCode.INPUT_FORMAT, "Info.plist is not a plist")
        return node(elements(top).firstOrNull() ?: throw ProtectException(ErrorCode.INPUT_FORMAT, "empty plist"), 0)
    }

    private fun elements(e: Element): List<Element> =
        (0 until e.childNodes.length).mapNotNull { e.childNodes.item(it) as? Element }

    private fun node(e: Element, depth: Int): Any? {
        if (depth > 32) throw ProtectException(ErrorCode.INPUT_FORMAT, "plist nesting above 32")
        return when (e.tagName) {
            "dict" -> {
                val kids = elements(e)
                if (kids.size % 2 != 0) throw ProtectException(ErrorCode.INPUT_FORMAT, "malformed plist dictionary")
                kids.chunked(2).associate { (k, v) -> k.textContent to node(v, depth + 1) }
            }
            "array" -> elements(e).map { node(it, depth + 1) }
            "string" -> e.textContent
            "integer" -> e.textContent.trim().toLongOrNull()
            "true" -> true
            "false" -> false
            else -> null
        }
    }

    /** Binary property list (`bplist00`): only the object kinds an Info.plist uses; anything else reads as null. */
    private class Binary(private val b: ByteArray) {
        private val buf = ByteBuffer.wrap(b)
        private val offsetSize: Int
        private val refSize: Int
        private val count: Long
        private val top: Long
        private val table: Long

        init {
            if (b.size < 40) throw ProtectException(ErrorCode.INPUT_FORMAT, "truncated binary plist")
            val t = b.size - 32
            offsetSize = b[t + 6].toInt() and 0xFF
            refSize = b[t + 7].toInt() and 0xFF
            count = buf.getLong(t + 8)
            top = buf.getLong(t + 16)
            table = buf.getLong(t + 24)
            if (offsetSize !in 1..8 || refSize !in 1..8 || count <= 0 || count > b.size || top !in 0 until count ||
                table < 8 || table + count * offsetSize > t) throw ProtectException(ErrorCode.INPUT_FORMAT, "malformed binary plist")
        }

        fun root(): Any? = obj(top, 0)

        private fun uint(at: Long, size: Int): Long {
            if (at < 0 || at + size > b.size) throw ProtectException(ErrorCode.INPUT_FORMAT, "malformed binary plist")
            var v = 0L
            for (i in 0 until size) v = (v shl 8) or (b[(at + i).toInt()].toLong() and 0xFF)
            return v
        }

        private fun obj(index: Long, depth: Int): Any? {
            if (depth > 32) throw ProtectException(ErrorCode.INPUT_FORMAT, "plist nesting above 32")
            if (index !in 0 until count) throw ProtectException(ErrorCode.INPUT_FORMAT, "malformed binary plist")
            var p = uint(table + index * offsetSize, offsetSize)
            val marker = uint(p, 1).toInt()
            p += 1
            val kind = marker shr 4
            var n = (marker and 0xF).toLong()
            fun length(): Long {
                if (n != 0xFL) return n
                val m = uint(p, 1).toInt()
                if (m shr 4 != 1) throw ProtectException(ErrorCode.INPUT_FORMAT, "malformed binary plist")
                val size = 1 shl (m and 0xF)
                val v = uint(p + 1, size)
                p += 1 + size
                return v
            }
            return when (kind) {
                0x0 -> when (marker) { 0x08 -> false; 0x09 -> true; else -> null }
                0x1 -> uint(p, 1 shl (marker and 0xF))
                0x5 -> { val len = length(); checkRange(p, len); String(b, p.toInt(), len.toInt(), Charsets.US_ASCII) }
                0x6 -> { val len = length(); checkRange(p, len * 2); String(b, p.toInt(), (len * 2).toInt(), Charsets.UTF_16BE) }
                0xA -> { val len = length(); checkRange(p, len * refSize); (0 until len).map { obj(uint(p + it * refSize, refSize), depth + 1) } }
                0xD -> {
                    val len = length()
                    checkRange(p, len * refSize * 2)
                    (0 until len).associate { i ->
                        val key = obj(uint(p + i * refSize, refSize), depth + 1) as? String ?: throw ProtectException(ErrorCode.INPUT_FORMAT, "malformed binary plist")
                        key to obj(uint(p + (len + i) * refSize, refSize), depth + 1)
                    }
                }
                else -> null
            }
        }

        private fun checkRange(at: Long, len: Long) {
            if (len < 0 || at + len > b.size) throw ProtectException(ErrorCode.INPUT_FORMAT, "malformed binary plist")
        }
    }

    private fun sha256(file: File): String {
        val digest = MessageDigest.getInstance("SHA-256")
        file.inputStream().use { s -> val buf = ByteArray(65536); while (true) { val r = s.read(buf); if (r < 0) break; digest.update(buf, 0, r) } }
        return digest.digest().joinToString("") { "%02x".format(it) }
    }
}
