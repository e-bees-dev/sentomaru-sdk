package br.com.ebees.sentomaru.protect

import com.google.gson.JsonElement
import com.google.gson.JsonObject
import java.io.ByteArrayOutputStream
import java.io.File
import java.nio.ByteBuffer
import java.security.MessageDigest
import java.security.SecureRandom
import java.util.zip.Deflater
import java.util.zip.ZipFile
import javax.crypto.Cipher
import javax.crypto.Mac
import javax.crypto.spec.GCMParameterSpec
import javax.crypto.spec.SecretKeySpec

/** The validated `asset-encryption` section: [assets] in profile order, then [strings]; [all] is what is sealed. */
data class SealedSection(val assets: List<String>, val strings: String?) {
    val all: List<String> get() = assets + listOfNotNull(strings)
}

/**
 * D-14 (`asset-encryption`, harden/20; contract "asset-encryption (D-14)", "Formato selado v1", ADR 0003). Behind the
 * laboratory gate from D-14c, in the distributed CLI (Controls.all) since D-14e. On an AAB, in the `base` module: every
 * marked file of `assets/` (and the strings file) is sealed into `assets/sentomaru/sealed/<sha256(path)>.bin` with
 * AES-256-GCM, `header.bin` holds the per-run `dek` under a `kek` derived from the public format constant, the package
 * and the `versionCode`, and the originals are removed. The app reads them by an explicit call of the SDK or the plugin (D-14x3); the reader's marker class must be linked.
 *
 * This is data obfuscation, not secrecy (D-14x1): whoever has the APK and the published scheme recovers the files.
 *
 * Randomness: `dek`, `salt` and every nonce come from a [SecureRandom] private to this object ([apply]). The shared
 * vectors and the golden tests pass their own source to the three-argument [apply], per call: there is no mutable
 * state to swap, no argument and no environment variable of the CLI. (Kotlin `internal` is public in the bytecode,
 * under a mangled name; what it takes is only that call's source.) Draw order: `dek` (32), `salt` (16), the header
 * nonce (12), then one nonce (12) per file in [SealedSection.all] order.
 */
object AssetEncryption : Control {
    override val id = "asset-encryption"
    override val version = "1"
    override val stage = "harden"
    override val order = 20
    override val prerequisites = emptyList<String>()
    override val changeIds = listOf("asset.sealed", "asset.removed", "sealed.header.added", "assets-config.updated")
    override val changesBinary = true

    const val SEALED_DIR = "assets/sentomaru/sealed/"
    const val HEADER = SEALED_DIR + "header.bin"
    const val ASSETS_CONFIG = "base/assets.pb"
    const val MAX_FILES = 64
    /**
     * D-14e (vendor decision, conservative): the CLI seals at most 1 MiB of plain bytes per file and refuses a larger one
     * at build time (`asset-too-large`), because the reader holds the whole file in memory (no streaming reader) and the
     * D-14d peak was measured above 3x the plain size. Only with the laboratory gate (`SENTOMARU_LAB=1`, not
     * contractual) does the format ceiling [FORMAT_MAX_FILE_BYTES] apply, so the D-14d proof can still seal its 4 MiB
     * canary on the emulator.
     */
    const val MAX_FILE_BYTES = 1024 * 1024
    /** The format v1 ceiling per file (the readers refuse a declared length above it; `readerLimits` in the vectors). */
    const val FORMAT_MAX_FILE_BYTES = 4 * 1024 * 1024
    const val MAX_TOTAL_BYTES = 32 * 1024 * 1024
    const val MAX_STRINGS = 1024
    /** The longest `.bin` a reader accepts (37 + 4 MiB + 4 KiB of DEFLATE overhead); the CLI never writes more. */
    const val MAX_ENTRY_BYTES = 37 + FORMAT_MAX_FILE_BYTES + 4096

    /** The per-file limit of this run: 1 MiB, or the format ceiling only with the laboratory gate. */
    fun maxFileBytes(lab: Boolean): Int = if (lab) FORMAT_MAX_FILE_BYTES else MAX_FILE_BYTES

    const val VERSION_CODE_MISSING = "version-code-missing"
    const val SEALED_PRESENT = "sealed-present"
    const val READER_MISSING = "sealed-reader-missing"
    const val ASSET_MISSING = "asset-missing"
    const val ENGINE_MANAGED = "asset-engine-managed"
    const val ASSET_TARGETED = "asset-targeted"
    /** A marked file above the per-file limit ([maxFileBytes]: 1 MiB in the distributed CLI). */
    const val TOO_LARGE = "asset-too-large"
    /** The marked files together above [MAX_TOTAL_BYTES] (32 MiB), each one within the per-file limit. */
    const val TOTAL_TOO_LARGE = "assets-total-too-large"
    const val STRINGS_INVALID = "strings-invalid"
    const val READ_LINE = "asset-encryption-read-line"

    /** `K_fmt` = SHA-256("Sentomaru sealed assets format v1 public constant"): public by design (in every reader). */
    internal val K_FMT: ByteArray = MessageDigest.getInstance("SHA-256")
        .digest("Sentomaru sealed assets format v1 public constant".toByteArray(Charsets.US_ASCII))

    /** The canonical path of the contract (the schema's pattern, matched on the whole text). */
    private val PATH = Regex("""\A(?=.{8,512}\z)assets/(?!sentomaru/)(?:(?!\.{1,2}/)[A-Za-z0-9._@+~-]+/)*(?!\.{1,2}\z)[A-Za-z0-9._@+~-]+\z""")
    private val STRING_KEY = Regex("""\A[a-z0-9_.]{1,64}\z""")
    private val FIELD = Regex("""\A[A-Za-z0-9_-]{1,64}\z""")
    private const val FLUTTER = "assets/flutter_assets/"
    private const val FONT_MANIFEST = FLUTTER + "FontManifest.json"
    private const val SMALL_FILE_BYTES = 8 * 1024 * 1024
    private val FLUTTER_ENGINE_DIRS = listOf("shaders/", "fonts/", "packages/").map { FLUTTER + it }
    private val FONT_EXTENSIONS = listOf(".ttf", ".otf", ".ttc")

    private val secure by lazy { SecureRandom() }

    /** The production source of `dek`, `salt` and nonces (a test checks that it is a [SecureRandom]). */
    internal val randomSource: SecureRandom get() = secure

    private fun secureBytes(n: Int): ByteArray = ByteArray(n).also { secure.nextBytes(it) }

    private fun bad(field: String): Nothing = throw ProtectException(ErrorCode.PROFILE_FORMAT, "$id.$field")

    private fun incompatible(detail: String): Nothing = throw ProtectException(ErrorCode.APP_INCOMPATIBLE, detail)

    private fun text(e: JsonElement?): String? = e?.takeIf { it.isJsonPrimitive && it.asJsonPrimitive.isString }?.asString

    /** The section's rules (contract table, exit 4). */
    fun parse(section: JsonObject): SealedSection {
        // Closed: an unknown member is named in `detail` only when it is a short plain name (the detail lands in the report).
        (section.keySet() - setOf("version", "assets", "strings")).sorted().firstOrNull()?.let { bad(if (FIELD.matches(it)) it else "unknown-field") }
        val list = section.get("assets")?.takeIf { it.isJsonArray }?.asJsonArray ?: bad("assets")
        val assets = list.map { item -> text(item)?.takeIf(PATH::matches) ?: bad("assets") }
        if (assets.isEmpty() || assets.size > MAX_FILES || assets.toSet().size != assets.size) bad("assets")
        val e = section.get("strings")
        val strings = if (e == null || e.isJsonNull) null else text(e)?.takeIf(PATH::matches) ?: bad("strings")
        if (strings != null && strings in assets) bad("strings")
        if (assets.size + (if (strings != null) 1 else 0) > MAX_FILES) bad("assets")
        return SealedSection(assets, strings)
    }

    override fun validate(section: JsonObject, context: ControlContext) {
        parse(section)
    }

    /** What the compatibility phase read: the plain bytes of every marked file and the number of strings. */
    internal class Plain(val files: LinkedHashMap<String, ByteArray>, val strings: Int) {
        val bytesIn: Long get() = files.values.sumOf { it.size.toLong() }
        fun clear() = files.values.forEach { it.fill(0) }
    }

    override fun plan(section: JsonObject, artifact: Artifact, context: ControlContext): ControlPlan {
        val parsed = parse(section)
        val file = artifact.file ?: throw ProtectException(ErrorCode.INTERNAL, "$id: artifact without its file")
        val plain = inspect(file, artifact, parsed, context.lab)
        try {
            context.warn(READ_LINE, "the app must read the sealed files through the SDK (SentomaruSealed) or the plugin; " +
                "the originals are removed, so a plain read fails")
            val prefix = if (artifact.kind == ArtifactKind.AAB) "base/" else ""
            val config = artifact.kind == ArtifactKind.AAB && ZipFile(file).use { assetsConfig(it, parsed, plannedNames(parsed)) != null }
            return ControlPlan(id, version, "planned", changes(parsed, prefix, config), evidence = evidence(section, parsed, plain, null))
        } finally {
            plain.clear()
        }
    }

    private fun changes(parsed: SealedSection, prefix: String, config: Boolean) = listOf(Change("sealed.header.added", prefix + HEADER)) +
        parsed.all.flatMap { listOf(Change("asset.sealed", sha256(it)), Change("asset.removed", sha256(it))) } +
        listOfNotNull(Change("assets-config.updated", ASSETS_CONFIG).takeIf { config })

    /** The names (without `base/`) of the sealed entries a run adds for [parsed]: `header.bin` and one `.bin` per file. */
    private fun plannedNames(parsed: SealedSection) = listOf(HEADER) + parsed.all.map { SEALED_DIR + sha256(it) + ".bin" }

    /**
     * `base/assets.pb` after the edit, or null when the bundle has none. bundletool lists there every directory of
     * `assets/` that has files directly in it, and refuses a listed directory left without one ("Targeted directory …
     * is empty"): each listed directory with an empty targeting whose last direct files are the sealed ones leaves the
     * list, and `assets/sentomaru/sealed` joins it with an empty targeting, as bundletool would write it. Nothing else
     * changes (a targeted directory never holds a sealed file: `asset-targeted`).
     */
    internal fun assetsConfig(zip: ZipFile, parsed: SealedSection, added: List<String>): ByteArray? {
        val entry = zip.getEntry(ASSETS_CONFIG) ?: return null
        val config = readAssetsConfig(zip, entry)
        val files = zip.entries().asSequence().filter { !it.isDirectory && it.name.startsWith("base/assets/") }.map { it.name.removePrefix("base/") }.toList()
        val removed = parsed.all.toSet()
        fun parent(p: String) = p.substringBeforeLast('/')
        val before = files.map(::parent).toSet()
        val after = (files.filter { it !in removed } + added).map(::parent).toSet()
        val sealedDir = SEALED_DIR.trimEnd('/')
        val kept = config.directoryList.filter { d ->
            val path = d.path.trimEnd('/')
            !(d.targeting == d.targeting.defaultInstanceForType && path in before && path !in after)
        }
        val builder = config.toBuilder().clearDirectory().addAllDirectory(kept)
        if (kept.none { it.path.trimEnd('/') == sealedDir })
            builder.addDirectory(com.android.bundle.Files.TargetedAssetsDirectory.newBuilder().setPath(sealedDir)
                .setTargeting(com.android.bundle.Targeting.AssetsDirectoryTargeting.getDefaultInstance()))
        return builder.build().toByteArray()
    }

    private fun readAssetsConfig(zip: ZipFile, entry: java.util.zip.ZipEntry): com.android.bundle.Files.Assets {
        if (entry.size > SMALL_FILE_BYTES) throw ProtectException(ErrorCode.INPUT_FORMAT, "assets.pb above 8 MiB")
        val bytes = read(zip, entry, SMALL_FILE_BYTES)
        if (bytes.size > SMALL_FILE_BYTES) throw ProtectException(ErrorCode.INPUT_FORMAT, "assets.pb above 8 MiB")
        return try {
            com.android.bundle.Files.Assets.parseFrom(bytes)
        } catch (e: Exception) {
            throw ProtectException(ErrorCode.INPUT_FORMAT, "unreadable assets.pb")
        }
    }

    private fun evidence(section: JsonObject, parsed: SealedSection, plain: Plain, bytesOut: Long?) = linkedMapOf(
        "files" to parsed.all.size.toString(),
        "bytesIn" to plain.bytesIn.toString(),
        "bytesOut" to (bytesOut?.toString() ?: "unknown"),
        "strings" to plain.strings.toString(),
        "format" to "v1",
        "sectionSha256" to hex(MessageDigest.getInstance("SHA-256").digest(Jcs.canonical(section).toByteArray(Charsets.UTF_8))))

    /**
     * The compatibility phase (exit 5), in the contract's order: `versionCode`, a sealed directory already there, the
     * reader marker, targeting, a missing file, an engine-managed file, sizes, the strings JSON. The first condition of
     * the order decides, over every marked path. Returns the plain bytes of every marked file (profile order).
     */
    internal fun inspect(file: File, artifact: Artifact, parsed: SealedSection, lab: Boolean = false): Plain {
        val maxFile = maxFileBytes(lab)
        val m = artifact.manifest
        if (m.versionCode == null || m.versionCodeMajor) incompatible(VERSION_CODE_MISSING)
        val prefix = if (artifact.kind == ArtifactKind.AAB) "base/" else ""
        ZipFile(file).use { zip ->
            val entries = zip.entries().toList()
            if (entries.any { it.name.startsWith(prefix + "assets/sentomaru/") }) incompatible(SEALED_PRESENT)
            val readers = DexScan.present(file, artifact.kind, setOf(BuildObfuscation.ANDROID_READER, BuildObfuscation.FLUTTER_READER), control = id)
            if (readers.isEmpty()) incompatible(READER_MISSING)
            val targeted = targetedDirectories(zip, entries.map { it.name }, prefix, artifact.kind)
            if (parsed.all.any { p -> directories(p).any { it in targeted } }) incompatible(ASSET_TARGETED)
            val sources = parsed.all.map { p -> zip.getEntry(prefix + p)?.takeIf { !it.isDirectory } ?: incompatible(ASSET_MISSING) }
            if (parsed.all.any { engineManaged(it) }) incompatible(ENGINE_MANAGED)
            if (parsed.all.any { it.startsWith(FLUTTER) }) {
                val cited = fontManifestAssets(zip, prefix)
                if (parsed.all.any { p -> p.startsWith(FLUTTER) && (cited == null || p in cited) }) incompatible(ENGINE_MANAGED)
            }
            // Declared sizes first (no read), then the bytes actually inflated (a central directory may lie).
            // Per file first (the clearer fix for the developer), then the sum.
            if (sources.any { it.size > maxFile }) incompatible(TOO_LARGE)
            if (sources.sumOf { maxOf(it.size, 0L) } > MAX_TOTAL_BYTES) incompatible(TOTAL_TOO_LARGE)
            val files = LinkedHashMap<String, ByteArray>()
            try {
                var total = 0L
                for ((path, entry) in parsed.all.zip(sources)) {
                    val bytes = read(zip, entry, maxFile)
                    files[path] = bytes
                    total += bytes.size
                    if (bytes.size > maxFile) incompatible(TOO_LARGE)
                    if (total > MAX_TOTAL_BYTES) incompatible(TOTAL_TOO_LARGE)
                }
                val strings = parsed.strings?.let { strings(files.getValue(it)) } ?: 0
                return Plain(files, strings)
            } catch (e: Throwable) {
                files.values.forEach { it.fill(0) }
                throw e
            }
        }
    }

    /** At most [limit] + 1 bytes of [entry] (one more than the limit tells it is above); an entry that does not inflate is the input's fault. */
    private fun read(zip: ZipFile, entry: java.util.zip.ZipEntry, limit: Int): ByteArray = try {
        zip.getInputStream(entry).use { it.readNBytes(limit + 1) }
    } catch (e: java.io.IOException) {
        throw ProtectException(ErrorCode.INPUT_FORMAT, "corrupt entry in the bundle")
    }

    /** `assets`, `assets/a`, `assets/a/b` for `assets/a/b/file`: every directory from `assets/` to the parent. */
    private fun directories(path: String): List<String> {
        val segments = path.split('/')
        return (1 until segments.size).map { segments.subList(0, it).joinToString("/") }
    }

    /**
     * The directories (canonical, without `base/`, every `#…` suffix stripped) that have a targeted variant: each one
     * cited in `base/assets.pb` with a non-empty targeting, and each directory of an entry under `assets/` whose segment
     * carries a `#` suffix.
     */
    private fun targetedDirectories(zip: ZipFile, names: List<String>, prefix: String, kind: ArtifactKind): Set<String> {
        fun strip(path: String) = path.split('/').joinToString("/") { it.substringBefore('#') }
        val out = HashSet<String>()
        for (name in names) {
            if (!name.startsWith(prefix + "assets/")) continue
            val segments = name.removePrefix(prefix).trimEnd('/').split('/')
            val dirs = if (name.endsWith("/")) segments.size else segments.size - 1
            for (i in 0 until dirs) if ('#' in segments[i]) out += strip(segments.subList(0, i + 1).joinToString("/"))
        }
        if (kind == ArtifactKind.AAB) zip.getEntry(ASSETS_CONFIG)?.let { entry ->
            val assets = readAssetsConfig(zip, entry)
            // bundletool lists every asset directory there, most with an empty targeting: only a targeted one counts.
            for (d in assets.directoryList) if (d.hasTargeting() && d.targeting != d.targeting.defaultInstanceForType)
                out += strip(d.path.trimEnd('/'))
        }
        return out
    }

    /** Read by the Flutter engine or the platform without the reader (contract list for `asset-engine-managed`). */
    internal fun engineManaged(path: String): Boolean =
        (path.startsWith(FLUTTER) && '/' !in path.removePrefix(FLUTTER)) ||
            FLUTTER_ENGINE_DIRS.any { path.startsWith(it) } ||
            FONT_EXTENSIONS.any { path.lowercase().endsWith(it) } ||
            path.startsWith("assets/dexopt/")

    /**
     * The canonical paths the base `FontManifest.json` cites (`asset` members, as written and percent-decoded); empty
     * without the file, null when it cannot be read as JSON within 8 MiB (then no Flutter asset is sealed).
     */
    private fun fontManifestAssets(zip: ZipFile, prefix: String): Set<String>? {
        val entry = zip.getEntry(prefix + FONT_MANIFEST)?.takeIf { !it.isDirectory } ?: return emptySet()
        if (entry.size > SMALL_FILE_BYTES) return null
        val bytes = read(zip, entry, SMALL_FILE_BYTES)
        if (bytes.size > SMALL_FILE_BYTES) return null
        val root = try { StrictJson.parse(bytes) } catch (e: ProtectException) { return null }
        val out = HashSet<String>()
        fun walk(e: JsonElement) {
            when {
                e.isJsonArray -> e.asJsonArray.forEach(::walk)
                e.isJsonObject -> for ((k, v) in e.asJsonObject.entrySet()) {
                    if (k == "asset" && v.isJsonPrimitive && v.asJsonPrimitive.isString) {
                        out += FLUTTER + v.asString
                        runCatching { java.net.URLDecoder.decode(v.asString.replace("+", "%2B"), Charsets.UTF_8) }.getOrNull()?.let { out += FLUTTER + it }
                    } else walk(v)
                }
            }
        }
        walk(root)
        return out
    }

    /** The strings file: strict UTF-8 JSON, a flat object of texts, keys of the contract, no repetition, at most 1024. */
    internal fun strings(bytes: ByteArray): Int {
        val root = try { StrictJson.parse(bytes) } catch (e: ProtectException) { incompatible(STRINGS_INVALID) }
        val o = root.takeIf { it.isJsonObject }?.asJsonObject ?: incompatible(STRINGS_INVALID)
        if (o.size() > MAX_STRINGS) incompatible(STRINGS_INVALID)
        for ((k, v) in o.entrySet()) if (!STRING_KEY.matches(k) || text(v) == null) incompatible(STRINGS_INVALID)
        return o.size()
    }

    override fun apply(section: JsonObject, edit: AabEdit, context: ControlContext): List<Change> =
        apply(section, edit, ::secureBytes, context.lab)

    /** [apply] with the randomness source of this call: [secureBytes] in the CLI, a fixed one in the vector tests. */
    internal fun apply(section: JsonObject, edit: AabEdit, random: (Int) -> ByteArray, lab: Boolean = false): List<Change> {
        val parsed = parse(section)
        val artifact = edit.artifact
        val file = artifact.file ?: throw ProtectException(ErrorCode.INTERNAL, "$id: artifact without its file")
        val plain = inspect(file, artifact, parsed, lab)
        try {
            val sealed = Sealer.seal(artifact.manifest.packageName, artifact.manifest.versionCode!!, parsed, plain.files, random)
            // The new entries go together, in name order, where the last entry of base/assets/ is (it may be removed).
            val anchor = edit.entries.last { !it.isDirectory && it.name.startsWith("base/assets/") }.name
            for (path in parsed.all) edit.remove("base/$path")
            for ((name, bytes) in sealed.toSortedMap()) edit.add(anchor, "base/$name", bytes)
            val config = assetsConfig(edit.zip, parsed, sealed.keys.toList())
            if (config != null) edit.replace(ASSETS_CONFIG, config)
            edit.evidence[id] = evidence(section, parsed, plain, sealed.values.sumOf { it.size.toLong() })
            return changes(parsed, "base/", config != null)
        } finally {
            plain.clear()
        }
    }

    internal fun sha256(path: String): String = hex(MessageDigest.getInstance("SHA-256").digest(path.toByteArray(Charsets.UTF_8)))

    internal fun hex(bytes: ByteArray) = bytes.joinToString("") { "%02x".format(it) }
}

/**
 * The writer of the sealed format v1 (contract "Formato selado v1"), with the platform's primitives only (D-14x9):
 * `HmacSHA256` (HKDF, RFC 5869) and `AES/GCM/NoPadding` from the JCA, raw DEFLATE from `java.util.zip`. The arrays this
 * code owns (`dek`, `kek`, every `k_i`, the header payload, the deflated bytes) are zeroed once written, also on a failure:
 * best effort of the JVM (copies inside the JCA, `SecretKeySpec`, the `Deflater` and the GC are out of reach).
 */
internal object Sealer {
    private val HEADER_MAGIC = "SNTS".toByteArray(Charsets.US_ASCII)
    private val ASSET_MAGIC = "SNTA".toByteArray(Charsets.US_ASCII)
    private const val VERSION: Byte = 1

    /** Entry name (without `base/`) to its bytes: `header.bin` and one `.bin` per file of [files] ([parsed] order). */
    fun seal(packageName: String, versionCode: Long, parsed: SealedSection, files: Map<String, ByteArray>,
        random: (Int) -> ByteArray): Map<String, ByteArray> {
        val app = "$packageName|$versionCode"
        val dek = draw(random, 32)
        val out = LinkedHashMap<String, ByteArray>()
        var key = ByteArray(0)
        try {
            val salt = draw(random, 16)
            val nonce = draw(random, 12)
            val kek = hkdf(AssetEncryption.K_FMT, salt, utf8("sentomaru-sealed-v1|$app"))
            try {
                val stringsPath = utf8(parsed.strings ?: "")
                val payload = dek + stringsPath
                try {
                    out[AssetEncryption.HEADER] = HEADER_MAGIC + VERSION + salt + nonce + gcm(kek, nonce, payload, utf8("header|v1|$app"))
                } finally {
                    payload.fill(0)
                }
            } finally {
                kek.fill(0)
            }
            for (path in parsed.all) {
                val plain = files.getValue(path)
                val fileNonce = draw(random, 12)
                key = hkdf(dek, ByteArray(0), utf8("asset|$path"))
                val deflated = deflate(plain)
                val sealed = try {
                    val length = ByteBuffer.allocate(4).putInt(plain.size).array()
                    ASSET_MAGIC + VERSION + length + fileNonce + gcm(key, fileNonce, deflated, utf8("asset|v1|$app|$path"))
                } finally {
                    deflated.fill(0)
                    key.fill(0)
                }
                if (sealed.size > AssetEncryption.MAX_ENTRY_BYTES) throw ProtectException(ErrorCode.INTERNAL, "${AssetEncryption.id}: sealed entry above the reader limit")
                out[AssetEncryption.SEALED_DIR + AssetEncryption.sha256(path) + ".bin"] = sealed
            }
            return out
        } finally {
            dek.fill(0)
            key.fill(0)
        }
    }

    private fun draw(random: (Int) -> ByteArray, n: Int): ByteArray = random(n).also {
        if (it.size != n) throw ProtectException(ErrorCode.INTERNAL, "random source returned ${it.size} bytes, not $n")
    }

    /** HKDF-SHA256 (RFC 5869) with a 32-byte output; an empty salt is 32 zero bytes, as the RFC says. */
    fun hkdf(ikm: ByteArray, salt: ByteArray, info: ByteArray, length: Int = 32): ByteArray {
        require(length in 1..255 * 32)
        val prk = hmac(if (salt.isEmpty()) ByteArray(32) else salt, ikm)
        val out = ByteArray(length)
        var previous = ByteArray(0)
        var at = 0
        var counter = 1
        try {
            while (at < length) {
                val mac = Mac.getInstance("HmacSHA256")
                mac.init(SecretKeySpec(prk, "HmacSHA256"))
                mac.update(previous)
                mac.update(info)
                mac.update(counter.toByte())
                previous.fill(0)
                previous = mac.doFinal()
                val n = minOf(32, length - at)
                System.arraycopy(previous, 0, out, at, n)
                at += n
                counter++
            }
            return out
        } finally {
            prk.fill(0)
            previous.fill(0)
        }
    }

    private fun hmac(key: ByteArray, data: ByteArray): ByteArray {
        val mac = Mac.getInstance("HmacSHA256")
        mac.init(SecretKeySpec(key, "HmacSHA256"))
        return mac.doFinal(data)
    }

    /** AES-256-GCM seal: 96-bit nonce, 128-bit tag at the end (the `javax.crypto` convention). */
    fun gcm(key: ByteArray, nonce: ByteArray, plain: ByteArray, aad: ByteArray): ByteArray {
        val cipher = Cipher.getInstance("AES/GCM/NoPadding")
        cipher.init(Cipher.ENCRYPT_MODE, SecretKeySpec(key, "AES"), GCMParameterSpec(128, nonce))
        cipher.updateAAD(aad)
        return cipher.doFinal(plain)
    }

    /** Raw DEFLATE (RFC 1951, no zlib or gzip wrapper), best compression. */
    fun deflate(plain: ByteArray): ByteArray {
        val deflater = Deflater(Deflater.BEST_COMPRESSION, true)
        try {
            deflater.setInput(plain)
            deflater.finish()
            val out = ByteArrayOutputStream(plain.size / 2 + 64)
            val buffer = ByteArray(1 shl 16)
            while (!deflater.finished()) {
                val n = deflater.deflate(buffer)
                out.write(buffer, 0, n)
            }
            buffer.fill(0)
            return out.toByteArray()
        } finally {
            deflater.end()
        }
    }

    private fun utf8(s: String) = s.toByteArray(Charsets.UTF_8)
}
