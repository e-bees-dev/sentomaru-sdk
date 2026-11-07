package br.com.ebees.sentomaru.protect

import com.android.aapt.Resources
import com.android.apksig.ApkVerifier
import java.io.File
import java.io.InputStream
import java.nio.ByteBuffer
import java.nio.ByteOrder
import java.security.MessageDigest
import java.util.jar.JarFile
import java.util.zip.ZipFile

enum class ArtifactKind(val label: String) { APK("apk"), AAB("aab") }

/** What the CLI needs from the app's manifest (no other app content is read). */
data class ManifestFacts(
    val packageName: String,
    val versionCode: Long?,
    val minSdk: Int?,
    val targetSdk: Int?,
    val permissions: Set<String>,
    val hasApplication: Boolean,
    /** G-06: the app already declares the Sentomaru provider (an already-protected input). */
    val declaresSentomaruProvider: Boolean = false,
    /**
     * G-10: the `<activity>` and `<activity-alias>` classes the base manifest declares, as binary class names; null when the
     * manifest reader does not list them (an APK). A name written `.Main` or `Main` is resolved against the package.
     */
    val activities: Set<String>? = null,
    /** D-07b: `<application android:networkSecurityConfig>` is declared (any value). */
    val networkSecurityConfig: Boolean = false,
    /** D-07b: `<application android:usesCleartextTraffic>`: null when absent, else [Cleartext]. */
    val usesCleartextTraffic: Cleartext? = null,
    /** D-07b: `<application>` already has the meta-data of the pinned hosts (an input pinned before). */
    val declaresPinningHosts: Boolean = false,
    /**
     * D-08d: `<application android:debuggable>` of the base manifest. A literal `false` or no attribute is false; a
     * literal `true`, or a value that is not a literal boolean (a resource reference), counts as true (only a warning).
     */
    val debuggable: Boolean = false,
    /**
     * D-14c: `android:versionCodeMajor` is declared on `<manifest>` (any value). With it, `PackageInfo.longVersionCode`
     * is not the `versionCode`, so `asset-encryption` refuses the app (`version-code-missing`).
     */
    val versionCodeMajor: Boolean = false,
)

/** The literal value of `android:usesCleartextTraffic`, or [REFERENCE] when it is a resource reference (not copiable). */
enum class Cleartext { TRUE, FALSE, REFERENCE }

/** [signingCertSha256]: the input's first signer certificate (null for an unsigned AAB). */
data class Artifact(val kind: ArtifactKind, val sha256: String, val manifest: ManifestFacts, val modules: List<String>,
    val signingCertSha256: String?, val file: File? = null)

/**
 * Input inspection (contract "Entrada"): size, layout, manifest facts and the existing signature. Never modifies the
 * file. Everything read from the archive is bounded before it is allocated: the input is untrusted.
 */
object ArtifactReader {
    const val MAX_BYTES: Long = 512L * 1024 * 1024
    const val MAX_ENTRIES = 100_000
    const val MAX_MANIFEST_BYTES = 8 * 1024 * 1024
    /** Decompressed bytes the signature check may read (declared sizes for an APK, counted bytes for a signed AAB). */
    const val MAX_VERIFY_BYTES: Long = 2L * 1024 * 1024 * 1024
    private const val ANDROID_NS = "http://schemas.android.com/apk/res/android"
    private const val ATTR_NAME = 0x01010003
    private const val ATTR_VERSION_CODE = 0x0101021b
    private const val ATTR_VERSION_CODE_MAJOR = 0x01010576
    private const val ATTR_MIN_SDK = 0x0101020c
    private const val ATTR_TARGET_SDK = 0x01010270
    internal const val ATTR_USES_CLEARTEXT = 0x010104ec
    internal const val ATTR_NETWORK_SECURITY_CONFIG = 0x01010527
    internal const val ATTR_DEBUGGABLE = 0x0101000f
    private val DEX = Regex("""classes\d*\.dex""")
    private val JAR_SIGNATURE = Regex("""META-INF/[^/]+\.(SF|RSA|DSA|EC)""", RegexOption.IGNORE_CASE)

    fun read(file: File, warn: (String, String) -> Unit = { _, _ -> }): Artifact {
        if (!file.isFile) throw ProtectException(ErrorCode.INPUT_FORMAT, "input is not a file")
        if (file.length() > MAX_BYTES) throw ProtectException(ErrorCode.INPUT_TOO_LARGE, "input above 512 MiB")
        val zip = try {
            ZipFile(file)
        } catch (e: Exception) {
            throw ProtectException(ErrorCode.INPUT_FORMAT, "not a zip archive")
        }
        val (kind, manifest, modules, signed) = zip.use {
            val names = HashSet<String>()
            var inflated = 0L
            for (entry in zip.entries()) {
                // Declared sizes bound what the signature check will inflate (apksig digests every v1 entry).
                inflated += maxOf(entry.size, 0L)
                if (inflated > MAX_VERIFY_BYTES) throw ProtectException(ErrorCode.INPUT_TOO_LARGE, "entries above 2 GiB inflated")
                if (names.size >= MAX_ENTRIES) throw ProtectException(ErrorCode.INPUT_FORMAT, "more than $MAX_ENTRIES entries")
                // Two entries with one name are read differently by different tools: never accepted.
                if (!names.add(entry.name)) throw ProtectException(ErrorCode.INPUT_FORMAT, "duplicate entry name")
                if (!safeName(entry.name)) throw ProtectException(ErrorCode.INPUT_FORMAT, "unsafe entry name")
            }
            val signed = names.any(JAR_SIGNATURE::matches)
            when {
                "BundleConfig.pb" in names && "base/manifest/AndroidManifest.xml" in names -> Quad(
                    ArtifactKind.AAB,
                    protoManifest(entry(zip, "base/manifest/AndroidManifest.xml")),
                    names.filter { n -> n.endsWith("/manifest/AndroidManifest.xml") && n.count { it == '/' } == 2 }
                        .map { n -> n.substringBefore('/') }.sorted(),
                    signed,
                )
                "AndroidManifest.xml" in names && names.any(DEX::matches) -> Quad(
                    ArtifactKind.APK, binaryManifest(entry(zip, "AndroidManifest.xml")), listOf("base"), signed)
                else -> throw ProtectException(ErrorCode.INPUT_FORMAT, "neither an APK nor an AAB")
            }
        }
        val cert = when (kind) {
            ArtifactKind.APK -> apkSignature(file, warn)
            ArtifactKind.AAB -> if (signed) jarSignature(file) else null
        }
        return Artifact(kind, sha256(file), manifest, modules, cert, file)
    }

    private data class Quad(val kind: ArtifactKind, val manifest: ManifestFacts, val modules: List<String>, val signed: Boolean)

    /** An entry name every tool reads the same way: relative, no `..` segment, no backslash, no NUL. */
    internal fun safeName(name: String): Boolean =
        name.isNotEmpty() && !name.startsWith("/") && '\\' !in name && '\u0000' !in name &&
            name.split('/').none { it == ".." || it == "." } && !Regex("""^[A-Za-z]:""").containsMatchIn(name)

    /** Reads one entry, refusing a missing entry or a declared or actual size above [MAX_MANIFEST_BYTES]. */
    internal fun entry(zip: ZipFile, name: String): ByteArray {
        val e = zip.getEntry(name) ?: throw ProtectException(ErrorCode.INPUT_FORMAT, "missing $name")
        if (e.size > MAX_MANIFEST_BYTES) throw ProtectException(ErrorCode.INPUT_FORMAT, "manifest above 8 MiB")
        val bytes = try {
            zip.getInputStream(e).use { it.readNBytes(MAX_MANIFEST_BYTES + 1) }
        } catch (x: Exception) {
            throw ProtectException(ErrorCode.INPUT_FORMAT, "unreadable manifest entry")
        }
        if (bytes.size > MAX_MANIFEST_BYTES) throw ProtectException(ErrorCode.INPUT_FORMAT, "manifest above 8 MiB")
        return bytes
    }

    /** APK: v1/v2/v3 by apksig. Unsigned or invalid → `input-signature`; v1 only → a warning (contract "Entrada"). */
    private fun apkSignature(file: File, warn: (String, String) -> Unit): String {
        val result = try {
            ApkVerifier.Builder(file).build().verify()
        } catch (e: Exception) {
            throw ProtectException(ErrorCode.INPUT_SIGNATURE, "unverifiable signature (${e.javaClass.simpleName})")
        }
        if (!result.isVerified) throw ProtectException(ErrorCode.INPUT_SIGNATURE, result.errors.firstOrNull()?.issue?.name ?: "not verified")
        if (!result.isVerifiedUsingV2Scheme && !result.isVerifiedUsingV3Scheme && !result.isVerifiedUsingV31Scheme)
            warn("input-v1-only", "input APK is signed with the v1 scheme only")
        return sha256(result.signerCertificates.first().encoded)
    }

    /** AAB with a JAR signature: every entry outside META-INF must be signed by the same signer and its digest match. */
    private fun jarSignature(file: File): String {
        try {
            JarFile(file, true).use { jar ->
                var budget = MAX_VERIFY_BYTES
                var signer: java.security.cert.Certificate? = null
                val buffer = ByteArray(1 shl 16)
                for (entry in jar.entries()) {
                    if (entry.isDirectory) continue
                    jar.getInputStream(entry).use { input: InputStream ->
                        while (true) {
                            val n = input.read(buffer)
                            if (n < 0) break
                            budget -= n
                            if (budget < 0) throw ProtectException(ErrorCode.INPUT_TOO_LARGE, "signed bundle above 2 GiB inflated")
                        }
                    }
                    if (entry.name.startsWith("META-INF/")) continue
                    val certs = entry.codeSigners?.map { it.signerCertPath.certificates.first() }
                    if (certs.isNullOrEmpty()) throw ProtectException(ErrorCode.INPUT_SIGNATURE, "unsigned entry in a signed bundle")
                    if (certs.size != 1 || (signer != null && certs[0] != signer))
                        throw ProtectException(ErrorCode.INPUT_SIGNATURE, "bundle entries with different signers")
                    signer = certs[0]
                }
                return sha256((signer ?: throw ProtectException(ErrorCode.INPUT_SIGNATURE, "signed bundle without signed entries")).encoded)
            }
        } catch (e: ProtectException) {
            throw e
        } catch (e: Exception) {
            throw ProtectException(ErrorCode.INPUT_SIGNATURE, "invalid bundle signature")
        }
    }

    private fun sha256(bytes: ByteArray) = MessageDigest.getInstance("SHA-256").digest(bytes).joinToString("") { "%02x".format(it) }

    private fun sha256(file: File): String {
        val digest = MessageDigest.getInstance("SHA-256")
        file.inputStream().use { input ->
            val buffer = ByteArray(1 shl 16)
            while (true) {
                val n = input.read(buffer)
                if (n < 0) break
                digest.update(buffer, 0, n)
            }
        }
        return digest.digest().joinToString("") { "%02x".format(it) }
    }

    /** `minSdkVersion`/`targetSdkVersion` outside this range are not a real API level (and would wrap as Int). */
    private fun apiLevel(value: Long?): Int? = value?.let {
        if (it !in 1..10_000) throw ProtectException(ErrorCode.INPUT_FORMAT, "API level out of range")
        it.toInt()
    }

    private fun split(isSplit: Boolean) {
        if (isSplit) throw ProtectException(ErrorCode.INPUT_FORMAT, "split APK (install the full app or the bundle)")
    }

    // ---- AAB: protobuf manifest (aapt2 XmlNode)

    internal fun protoManifest(bytes: ByteArray): ManifestFacts {
        val root = try {
            Resources.XmlNode.parseFrom(bytes).element
        } catch (e: Exception) {
            throw ProtectException(ErrorCode.INPUT_FORMAT, "unreadable bundle manifest")
        }
        if (root.name != "manifest" || root.namespaceUri.isNotEmpty()) throw ProtectException(ErrorCode.INPUT_FORMAT, "bundle manifest root")
        fun attr(e: Resources.XmlElement, id: Int, name: String) = e.attributeList.firstOrNull {
            it.namespaceUri == ANDROID_NS && (it.resourceId == id || (it.resourceId == 0 && it.name == name))
        }
        fun plain(e: Resources.XmlElement, name: String) = e.attributeList.firstOrNull { it.name == name && it.namespaceUri.isEmpty() }
        fun number(a: Resources.XmlAttribute?): Long? = a?.let {
            if (it.hasCompiledItem() && it.compiledItem.hasPrim()) {
                val p = it.compiledItem.prim
                when {
                    p.hasIntDecimalValue() -> p.intDecimalValue.toLong()
                    p.hasIntHexadecimalValue() -> p.intHexadecimalValue.toLong()
                    else -> it.value.toLongOrNull()
                }
            } else it.value.toLongOrNull()
        }
        split(plain(root, "split") != null)
        val children = root.childList.filter { it.hasElement() && it.element.namespaceUri.isEmpty() }.map { it.element }
        val usesSdk = children.firstOrNull { it.name == "uses-sdk" }
        val application = children.firstOrNull { it.name == "application" }
        val cleartext = application?.let { attr(it, ATTR_USES_CLEARTEXT, "usesCleartextTraffic") }?.let { a ->
            val item = a.compiledItem
            when {
                a.hasCompiledItem() && item.hasPrim() && item.prim.hasBooleanValue() -> if (item.prim.booleanValue) Cleartext.TRUE else Cleartext.FALSE
                !a.hasCompiledItem() && a.value == "true" -> Cleartext.TRUE
                !a.hasCompiledItem() && a.value == "false" -> Cleartext.FALSE
                else -> Cleartext.REFERENCE
            }
        }
        return ManifestFacts(
            packageName = plain(root, "package")?.value ?: throw ProtectException(ErrorCode.INPUT_FORMAT, "bundle manifest without package"),
            versionCode = number(attr(root, ATTR_VERSION_CODE, "versionCode"))?.let { it and 0xffffffffL },
            minSdk = usesSdk?.let { apiLevel(number(attr(it, ATTR_MIN_SDK, "minSdkVersion"))) },
            targetSdk = usesSdk?.let { apiLevel(number(attr(it, ATTR_TARGET_SDK, "targetSdkVersion"))) },
            permissions = children.filter { it.name == "uses-permission" }.mapNotNull { attr(it, ATTR_NAME, "name")?.value }.toSet(),
            hasApplication = children.any { it.name == "application" },
            declaresSentomaruProvider = children.filter { it.name == "application" }.any { app ->
                app.childList.any { c -> c.hasElement() && c.element.name == "provider" &&
                    attr(c.element, ATTR_NAME, "name")?.value == RuntimeInjection.PROVIDER }
            },
            activities = children.filter { it.name == "application" }.flatMap { app ->
                app.childList.filter { c -> c.hasElement() && (c.element.name == "activity" || c.element.name == "activity-alias") }
                    .mapNotNull { c -> attr(c.element, ATTR_NAME, "name")?.value }
            }.map { name -> activityClass(plain(root, "package")?.value.orEmpty(), name) }.toSet(),
            networkSecurityConfig = application?.let { attr(it, ATTR_NETWORK_SECURITY_CONFIG, "networkSecurityConfig") } != null,
            usesCleartextTraffic = cleartext,
            declaresPinningHosts = application?.childList?.any { c -> c.hasElement() && c.element.name == "meta-data" &&
                attr(c.element, ATTR_NAME, "name")?.value == NetworkPinning.HOSTS_META_DATA } == true,
            // Every occurrence (a repeated attribute, a second <application>): true when any is.
            debuggable = children.filter { it.name == "application" }.flatMap { app -> app.attributeList.filter {
                it.namespaceUri == ANDROID_NS && (it.resourceId == ATTR_DEBUGGABLE || (it.resourceId == 0 && it.name == "debuggable"))
            } }.any { a ->
                val p = a.compiledItem.prim
                when {
                    a.hasCompiledItem() && a.compiledItem.hasPrim() && p.hasBooleanValue() -> p.booleanValue
                    a.hasCompiledItem() && a.compiledItem.hasPrim() && p.hasIntDecimalValue() -> p.intDecimalValue != 0
                    a.hasCompiledItem() && a.compiledItem.hasPrim() && p.hasIntHexadecimalValue() -> p.intHexadecimalValue != 0
                    else -> !(!a.hasCompiledItem() && a.value == "false")
                }
            },
            versionCodeMajor = attr(root, ATTR_VERSION_CODE_MAJOR, "versionCodeMajor") != null,
        )
    }

    /** G-10: an `android:name` of an activity as a binary class name (`.Main` and `Main` belong to the package). */
    internal fun activityClass(packageName: String, name: String): String = when {
        name.startsWith(".") -> packageName + name
        '.' !in name -> "$packageName.$name"
        else -> name
    }

    // ---- APK: Android binary XML (string pool, resource map, start/end-element chunks; nothing else is interpreted)

    internal fun binaryManifest(bytes: ByteArray): ManifestFacts {
        try {
            return BinaryXml(bytes).facts()
        } catch (e: ProtectException) {
            throw e
        } catch (e: RuntimeException) {
            throw ProtectException(ErrorCode.INPUT_FORMAT, "unreadable binary manifest")
        }
    }

    /**
     * Every offset is checked against its chunk before it is read, every count against the bytes that would hold it,
     * and strings are decoded lazily within a total budget: a hostile manifest is `input-format`, never an
     * `OutOfMemoryError` or an endless walk. Offsets are Long so a declared size cannot wrap.
     */
    private class BinaryXml(private val bytes: ByteArray) {
        private val b = ByteBuffer.wrap(bytes).order(ByteOrder.LITTLE_ENDIAN)
        private var pool: StringPool? = null
        private var resourceIds: IntArray = IntArray(0)

        private class Attribute(val namespace: Int, val name: Int, val raw: Int, val type: Int, val data: Int)
        private class Element(val namespace: Int, val name: Int, val depth: Int, val attributes: List<Attribute>)

        private fun bad(detail: String): Nothing = throw ProtectException(ErrorCode.INPUT_FORMAT, "binary manifest: $detail")

        private fun u8(o: Long, end: Long): Int { if (o < 0 || o + 1 > end) bad("truncated"); return b.get(o.toInt()).toInt() and 0xff }
        private fun u16(o: Long, end: Long): Int { if (o < 0 || o + 2 > end) bad("truncated"); return b.getShort(o.toInt()).toInt() and 0xffff }
        private fun u32(o: Long, end: Long): Long { if (o < 0 || o + 4 > end) bad("truncated"); return b.getInt(o.toInt()).toLong() and 0xffffffffL }
        private fun i32(o: Long, end: Long): Int = u32(o, end).toInt()

        fun facts(): ManifestFacts {
            val all = bytes.size.toLong()
            if (u16(0, all) != 0x0003) bad("header")
            val headerSize = u16(2, all).toLong()
            val end = minOf(u32(4, all), all)
            if (headerSize < 8 || headerSize > end) bad("header")
            val elements = mutableListOf<Element>()
            var depth = 0
            var offset = headerSize
            while (offset + 8 <= end) {
                val type = u16(offset, end)
                val hs = u16(offset + 2, end).toLong()
                val size = u32(offset + 4, end)
                if (hs < 8 || size < hs || offset + size > end) bad("chunk bounds")
                val chunkEnd = offset + size
                when (type) {
                    0x0001 -> { if (pool != null) bad("second string pool"); pool = StringPool(offset, hs, chunkEnd) }
                    0x0180 -> resourceIds = IntArray(((size - hs) / 4).toInt()) { b.getInt((offset + hs + it * 4L).toInt()) }
                    0x0102 -> { elements += element(offset, hs, chunkEnd, depth); depth++ }
                    0x0103 -> { depth--; if (depth < 0) bad("unbalanced elements") }
                }
                offset = chunkEnd
            }
            val strings = pool ?: bad("no string pool")
            val android = (0 until strings.count).firstOrNull { strings.matches(it, ANDROID_NS) } ?: -1
            fun named(e: Element, name: String) = strings.matches(e.name, name) && e.namespace == -1
            fun attr(e: Element, id: Int, name: String) = e.attributes.firstOrNull { a ->
                a.namespace == android && android >= 0 && (resourceIds.getOrNull(a.name) == id ||
                    (resourceIds.getOrNull(a.name) == null && strings.matches(a.name, name)))
            }
            fun plain(e: Element, name: String) = e.attributes.firstOrNull { it.namespace == -1 && strings.matches(it.name, name) }
            fun number(a: Attribute?): Long? = a?.let {
                if (it.type in 0x10..0x11) it.data.toLong() else if (it.raw >= 0) strings.get(it.raw).toLongOrNull() else null
            }
            fun value(a: Attribute?): String? = a?.takeIf { it.raw >= 0 }?.let { strings.get(it.raw) }
            val manifest = elements.firstOrNull { it.depth == 0 && named(it, "manifest") } ?: bad("root")
            split(plain(manifest, "split") != null)
            val children = elements.filter { it.depth == 1 }
            val usesSdk = children.firstOrNull { named(it, "uses-sdk") }
            // Elements are in document order: a depth-2 element belongs to the last depth-1 element before it.
            var parent: Element? = null
            val declaresProvider = elements.any { e ->
                if (e.depth == 1) parent = e
                e.depth == 2 && parent?.let { named(it, "application") } == true && named(e, "provider") &&
                    value(attr(e, ATTR_NAME, "name")) == RuntimeInjection.PROVIDER
            }
            parent = null
            val declaresHosts = elements.any { e ->
                if (e.depth == 1) parent = e
                e.depth == 2 && parent?.let { named(it, "application") } == true && named(e, "meta-data") &&
                    value(attr(e, ATTR_NAME, "name")) == NetworkPinning.HOSTS_META_DATA
            }
            val application = children.firstOrNull { named(it, "application") }
            // Res_value types: 0x12 int-boolean (data 0 = false); a string "true"/"false"; anything else (a reference) is not copiable.
            val cleartext = application?.let { attr(it, ATTR_USES_CLEARTEXT, "usesCleartextTraffic") }?.let { a ->
                when {
                    a.type == 0x12 -> if (a.data != 0) Cleartext.TRUE else Cleartext.FALSE
                    a.type == 0x03 && value(a) == "true" -> Cleartext.TRUE
                    a.type == 0x03 && value(a) == "false" -> Cleartext.FALSE
                    else -> Cleartext.REFERENCE
                }
            }
            return ManifestFacts(
                packageName = value(plain(manifest, "package")) ?: bad("no package"),
                versionCode = number(attr(manifest, ATTR_VERSION_CODE, "versionCode"))?.let { it and 0xffffffffL },
                minSdk = usesSdk?.let { apiLevel(number(attr(it, ATTR_MIN_SDK, "minSdkVersion"))) },
                targetSdk = usesSdk?.let { apiLevel(number(attr(it, ATTR_TARGET_SDK, "targetSdkVersion"))) },
                permissions = children.filter { named(it, "uses-permission") }.mapNotNull { value(attr(it, ATTR_NAME, "name")) }.toSet(),
                hasApplication = children.any { named(it, "application") },
                declaresSentomaruProvider = declaresProvider,
                networkSecurityConfig = application?.let { attr(it, ATTR_NETWORK_SECURITY_CONFIG, "networkSecurityConfig") } != null,
                usesCleartextTraffic = cleartext,
                declaresPinningHosts = declaresHosts,
                // 0x10/0x11 int and 0x12 int-boolean: data != 0; a string "false" is false; anything else (a reference,
                // "true") counts as debuggable. Every occurrence (a repeated attribute, a second <application>): any.
                debuggable = children.filter { named(it, "application") }.flatMap { app -> app.attributes.filter { a ->
                    a.namespace == android && android >= 0 && (resourceIds.getOrNull(a.name) == ATTR_DEBUGGABLE ||
                        (resourceIds.getOrNull(a.name) == null && strings.matches(a.name, "debuggable")))
                } }.any { a -> if (a.type in 0x10..0x12) a.data != 0 else !(a.type == 0x03 && value(a) == "false") },
                versionCodeMajor = attr(manifest, ATTR_VERSION_CODE_MAJOR, "versionCodeMajor") != null,
            )
        }

        private fun element(offset: Long, hs: Long, chunkEnd: Long, depth: Int): Element {
            val ext = offset + hs
            val namespace = i32(ext, chunkEnd)
            val name = i32(ext + 4, chunkEnd)
            val attributeStart = u16(ext + 8, chunkEnd).toLong()
            val attributeSize = u16(ext + 10, chunkEnd).toLong()
            val count = u16(ext + 12, chunkEnd)
            if (count > 0 && attributeSize < 20) bad("attribute size")
            if (ext + attributeStart + count * attributeSize > chunkEnd) bad("attributes beyond chunk")
            val attributes = (0 until count).map { i ->
                val a = ext + attributeStart + i * attributeSize
                Attribute(i32(a, chunkEnd), i32(a + 4, chunkEnd), i32(a + 8, chunkEnd), u8(a + 15, chunkEnd), i32(a + 16, chunkEnd))
            }
            return Element(namespace, name, depth, attributes)
        }

        /** The string pool, decoded on demand: indices and lengths are checked against the chunk, the total is capped. */
        private inner class StringPool(private val offset: Long, hs: Long, private val end: Long) {
            val count: Int
            private val utf8: Boolean
            private val stringsStart: Long
            private val offsets: Long
            private val cache = HashMap<Int, String>()
            private var budget = MAX_DECODED_CHARS

            init {
                if (hs < 28) bad("string pool header")
                val declared = u32(offset + 8, end)
                if (declared * 4 > end - offset - hs) bad("string count")
                count = declared.toInt()
                utf8 = u32(offset + 16, end) and 0x100L != 0L
                stringsStart = offset + u32(offset + 20, end)
                if (count > 0 && (stringsStart < offset + hs + count * 4L || stringsStart > end)) bad("strings start")
                offsets = offset + hs
            }

            fun matches(index: Int, expected: String) = index in 0 until count && get(index) == expected

            fun get(index: Int): String {
                if (index !in 0 until count) return ""
                return cache.getOrPut(index) {
                    var p = stringsStart + u32(offsets + index * 4L, end)
                    val s = if (utf8) {
                        p += if (u8(p, end) and 0x80 != 0) 2 else 1 // UTF-16 length (not used)
                        var len = u8(p, end)
                        if (len and 0x80 != 0) { len = ((len and 0x7f) shl 8) or u8(p + 1, end); p += 2 } else p += 1
                        take(len.toLong())
                        if (p + len > end) bad("string beyond pool")
                        String(bytes, p.toInt(), len, Charsets.UTF_8)
                    } else {
                        var len = u16(p, end).toLong()
                        if (len and 0x8000L != 0L) { len = ((len and 0x7fffL) shl 16) or u16(p + 2, end).toLong(); p += 4 } else p += 2
                        take(len)
                        if (p + len * 2 > end) bad("string beyond pool")
                        String(CharArray(len.toInt()) { b.getChar((p + it * 2L).toInt()) })
                    }
                    s
                }
            }

            private fun take(chars: Long) {
                budget -= chars
                if (budget < 0) bad("strings above budget")
            }
        }
    }

    private const val MAX_DECODED_CHARS: Long = 4L * 1024 * 1024
}
