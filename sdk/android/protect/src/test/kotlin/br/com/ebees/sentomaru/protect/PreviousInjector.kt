package br.com.ebees.sentomaru.protect

import com.android.aapt.Resources
import java.io.File
import java.util.zip.ZipEntry
import java.util.zip.ZipFile
import java.util.zip.ZipOutputStream

/**
 * D-07b regression reference: the single-pass runtime-injection writer as it was before the per-control pipeline
 * (AabInjector.write at d58c9dda), kept verbatim in behaviour so the refactored pipeline can be compared byte for byte.
 * Only [AabInjector.provider] and the runtime DEX are shared (both unchanged by the refactor).
 */
internal object PreviousInjector {
    private const val MANIFEST = "base/manifest/AndroidManifest.xml"
    private const val FIXED_TIME = 315_619_200_000L
    private val BASE_DEX = Regex("""base/dex/classes(\d*)\.dex""")
    private val SIGNATURE_BLOCK = Regex("""META-INF/[^/]+\.(SF|RSA|DSA|EC)""", RegexOption.IGNORE_CASE)

    fun write(input: File, packageName: String, enrollmentUrl: String, temp: File) {
        ZipFile(input).use { zip ->
            val entries = zip.entries().toList()
            val dexIndices = entries.mapNotNull { e -> BASE_DEX.matchEntire(e.name)?.groupValues?.get(1)?.let { if (it.isEmpty()) 1 else it.toInt() } }
                .sorted()
            val dexName = "base/dex/classes${dexIndices.size + 1}.dex"
            val lastDex = entries.last { BASE_DEX.matches(it.name) }.name
            val manifest = AabInjector.provider(Resources.XmlNode.parseFrom(zip.getInputStream(zip.getEntry(MANIFEST)).readBytes()),
                packageName, enrollmentUrl).toByteArray()
            val signed = entries.any { SIGNATURE_BLOCK.matches(it.name) }
            ZipOutputStream(temp.outputStream().buffered()).use { out ->
                for (entry in entries) {
                    if (entry.isDirectory) continue
                    if (signed && (SIGNATURE_BLOCK.matches(entry.name) || entry.name.equals("META-INF/MANIFEST.MF", true))) continue
                    if (entry.name == MANIFEST) add(out, MANIFEST, manifest, entry.time) else copy(out, entry, zip)
                    if (entry.name == lastDex) add(out, dexName, AabInjector.runtimeDex, FIXED_TIME)
                }
            }
        }
    }

    private fun copy(out: ZipOutputStream, source: ZipEntry, zip: ZipFile) {
        val e = ZipEntry(source.name)
        e.time = source.time
        if (source.method == ZipEntry.STORED) {
            e.method = ZipEntry.STORED
            e.size = source.size
            e.compressedSize = source.size
            e.crc = source.crc
        }
        out.putNextEntry(e)
        zip.getInputStream(source).use { it.copyTo(out, 1 shl 16) }
        out.closeEntry()
    }

    private fun add(out: ZipOutputStream, name: String, bytes: ByteArray, time: Long) {
        out.putNextEntry(ZipEntry(name).apply { this.time = time })
        out.write(bytes)
        out.closeEntry()
    }
}
