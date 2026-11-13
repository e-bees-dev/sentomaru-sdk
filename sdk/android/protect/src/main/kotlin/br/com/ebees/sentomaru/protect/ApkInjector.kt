package br.com.ebees.sentomaru.protect

import com.android.apksig.ApkSigner
import com.android.apksig.KeyConfig
import com.google.gson.JsonObject
import java.io.File
import java.io.FilterOutputStream
import java.io.OutputStream
import java.nio.file.Files
import java.nio.file.StandardCopyOption
import java.security.KeyStore
import java.security.MessageDigest
import java.security.cert.X509Certificate
import java.util.UUID
import java.util.zip.ZipEntry
import java.util.zip.ZipFile
import java.util.zip.ZipOutputStream

/**
 * The APK being edited by the controls of one run (G-03b3): the entry list of the input, the binary manifest (parsed on
 * first use, written only if a control changed it) and the entries to add, each right after a given source entry.
 */
class ApkEdit internal constructor(internal val zip: ZipFile, val entries: List<ZipEntry>, val artifact: Artifact) {
    val names: Set<String> = entries.map { it.name }.toSet()
    private var document: Axml? = null
    internal var manifestChanged = false
        private set
    internal val additions = mutableListOf<Pair<String, Pair<String, ByteArray>>>()
    internal val evidence = LinkedHashMap<String, Map<String, String>>()

    internal val manifest: Axml
        get() = document ?: Axml.parse(ArtifactReader.entry(zip, ApkInjector.MANIFEST)).also { document = it }

    /** A control that edits [manifest] says so; the document is written back in place of the source manifest. */
    internal fun manifestEdited() { manifestChanged = true }

    internal fun add(after: String, name: String, bytes: ByteArray) {
        if (after !in names || name in names || additions.any { it.second.first == name })
            throw ProtectException(ErrorCode.INTERNAL, "apk addition $name")
        additions += after to (name to bytes)
    }
}

/**
 * Applies the controls that change the binary to an APK (G-03b3). The runtime DEX becomes the next `classesN.dex` and the
 * binary manifest gains the init provider (exported=false, default process) and, for `ui-shield`, its three meta-data and
 * the optional overlay permission, the same changes as in an AAB. Every other entry is rewritten unchanged. The
 * existing signature (v1 files, v2/v3 block) cannot survive the change and is dropped; the output is aligned like
 * `zipalign` (4 bytes for stored entries, 16 KiB for stored `.so`) so a stored `resources.arsc` and native libraries still
 * load, and it is signed by the caller's `finish` (apksig v2/v3). It is validated by reading the result again (the
 * manifest facts and a complete zip) before it is moved into `<out>`; on any failure nothing is left there.
 * No other control (`asset-encryption`, `network-pinning`) edits an APK in this build: they answer `control-failed`.
 */
object ApkInjector {
    internal const val MANIFEST = "AndroidManifest.xml"
    private const val FIXED_TIME = 315_619_200_000L
    private val DEX = Regex("""classes(\d*)\.dex""")
    private val V1_SIGNATURE = Regex("""META-INF/([^/]+\.(SF|RSA|DSA|EC)|MANIFEST\.MF)""", RegexOption.IGNORE_CASE)
    private const val ALIGN_STORED = 4
    private const val ALIGN_NATIVE = 16384
    private const val PADDING_ID = 0xD935

    /** Test seam: called after each entry is written (a failure here must leave nothing in `<out>`). */
    internal var afterEntry: (String) -> Unit = {}

    /** Output name: `<input>.protected.apk`. */
    fun target(input: File, outDir: File) = File(outDir, input.name.removeSuffix(".apk") + ".protected.apk")

    fun inject(input: File, artifact: Artifact, steps: List<Pair<Control, JsonObject>>, context: ControlContext, outDir: File,
        finish: (File) -> Unit = {}): Injected {
        val target = target(input, outDir)
        val temp = File(outDir, ".${target.name}.${UUID.randomUUID()}.tmp")
        try {
            val (changes, evidence) = try {
                write(input, artifact, steps, context, temp)
            } catch (e: java.util.zip.ZipException) {
                throw ProtectException(ErrorCode.INPUT_FORMAT, "corrupt entry in the APK")
            }
            validate(temp, steps)
            finish(temp)
            val sha = sha256(temp)
            val size = temp.length()
            Files.move(temp.toPath(), target.toPath(), StandardCopyOption.REPLACE_EXISTING, StandardCopyOption.ATOMIC_MOVE)
            return Injected(target, changes, sha, size - input.length(), artifact.signingCertSha256 != null, evidence)
        } finally {
            temp.delete()
        }
    }

    private fun write(input: File, artifact: Artifact, steps: List<Pair<Control, JsonObject>>, context: ControlContext,
        temp: File): Pair<Map<String, List<Change>>, Map<String, Map<String, String>>> {
        ZipFile(input).use { zip ->
            val entries = zip.entries().toList()
            if (entries.size > ArtifactReader.MAX_ENTRIES) throw ProtectException(ErrorCode.INPUT_FORMAT, "too many entries")
            val names = HashSet<String>()
            for (e in entries) {
                if (!ArtifactReader.safeName(e.name) || !names.add(e.name)) throw ProtectException(ErrorCode.INPUT_FORMAT, "unsafe entry name")
            }
            val edit = ApkEdit(zip, entries, artifact)
            val changes = LinkedHashMap<String, List<Change>>()
            for ((control, section) in steps) changes[control.id] = control.applyApk(section, edit, context)
            val manifest = if (edit.manifestChanged) edit.manifest.toBytes() else null
            var budget = ArtifactReader.MAX_VERIFY_BYTES
            CountingOutput(temp.outputStream().buffered()).use { counting ->
                ZipOutputStream(counting).use { out ->
                    for (entry in entries) {
                        if (entry.isDirectory || V1_SIGNATURE.matches(entry.name)) continue
                        if (entry.name == MANIFEST && manifest != null) {
                            put(out, counting, ZipEntry(MANIFEST).apply { time = entry.time }, manifest.inputStream())
                        } else {
                            budget -= maxOf(entry.size, 0L)
                            if (budget < 0) throw ProtectException(ErrorCode.INPUT_TOO_LARGE, "entries above 2 GiB inflated")
                            zip.getInputStream(entry).use { put(out, counting, source(entry), it) }
                        }
                        afterEntry(entry.name)
                        for ((after, added) in edit.additions) if (after == entry.name)
                            put(out, counting, ZipEntry(added.first).apply { time = FIXED_TIME }, added.second.inputStream())
                    }
                }
            }
            return changes to edit.evidence
        }
    }

    /** A copy of the source entry's header: a stored one keeps its size and CRC (checked by ZipOutputStream on close). */
    private fun source(entry: ZipEntry): ZipEntry = ZipEntry(entry.name).apply {
        time = entry.time
        if (entry.method == ZipEntry.STORED) {
            method = ZipEntry.STORED
            size = entry.size
            compressedSize = entry.size
            crc = entry.crc
        }
    }

    /** Writes one entry; a stored one is padded (an extra field, like zipalign) so its data starts at the alignment. */
    private fun put(out: ZipOutputStream, counting: CountingOutput, entry: ZipEntry, data: java.io.InputStream) {
        if (entry.method == ZipEntry.STORED) {
            val alignment = if (entry.name.endsWith(".so")) ALIGN_NATIVE else ALIGN_STORED
            val dataStart = counting.count + 30 + entry.name.toByteArray(Charsets.UTF_8).size
            var padding = ((alignment - dataStart % alignment) % alignment).toInt()
            if (padding in 1..3) padding += alignment // an extra field is at least 4 bytes
            if (padding > 0) entry.extra = ByteArray(padding).also {
                it[0] = (PADDING_ID and 0xff).toByte(); it[1] = (PADDING_ID shr 8).toByte()
                it[2] = ((padding - 4) and 0xff).toByte(); it[3] = ((padding - 4) shr 8).toByte()
            }
        }
        out.putNextEntry(entry)
        data.copyTo(out, 1 shl 16)
        out.closeEntry()
    }

    /** Counts what reaches the file, so the next entry's data offset is known before its header is written. */
    private class CountingOutput(out: OutputStream) : FilterOutputStream(out) {
        var count = 0L
            private set
        override fun write(b: Int) { out.write(b); count++ }
        override fun write(b: ByteArray, off: Int, len: Int) { out.write(b, off, len); count += len }
    }

    /**
     * The result read again: a complete zip, the manifest facts of what the steps changed, contiguous DEX, and every
     * stored entry at its alignment. There is no APK validator in this CLI like bundletool for a bundle: this is the
     * same reader the input went through plus the checks that the rewrite itself could break.
     */
    private fun validate(file: File, steps: List<Pair<Control, JsonObject>>) {
        try {
            ZipFile(file).use { zip ->
                val dex = zip.entries().toList().mapNotNull { e -> DEX.matchEntire(e.name)?.groupValues?.get(1)?.let { if (it.isEmpty()) 1 else it.toInt() } }.sorted()
                if (dex != (1..dex.size).toList()) throw ProtectException(ErrorCode.CONTROL_FAILED, "non-contiguous DEX in the output")
                val facts = ArtifactReader.binaryManifest(ArtifactReader.entry(zip, MANIFEST))
                if (steps.any { it.first.id == RuntimeInjection.id } && !facts.declaresSentomaruProvider)
                    throw ProtectException(ErrorCode.CONTROL_FAILED, "runtime-injection: the provider is not in the output manifest")
            }
        } catch (e: ProtectException) {
            throw ProtectException(ErrorCode.CONTROL_FAILED, "${steps.joinToString("+") { it.first.id }}: apk validation (${e.detail})")
        } catch (e: Exception) {
            throw ProtectException(ErrorCode.CONTROL_FAILED, "${steps.joinToString("+") { it.first.id }}: apk validation (${e.javaClass.simpleName})")
        }
    }

    // ---- the changes of each control, on the binary manifest

    private const val ATTR_NAME = 0x01010003
    private const val ATTR_EXPORTED = 0x01010010
    private const val ATTR_AUTHORITIES = 0x01010018
    private const val ATTR_VALUE = 0x01010024

    private fun androidNs(doc: Axml): Int = doc.indexOf(AabInjector.ANDROID_NS).takeIf { it >= 0 }
        ?: throw ProtectException(ErrorCode.APP_INCOMPATIBLE, "manifest without the android namespace")

    private fun stringAttr(doc: Axml, ns: Int, name: String, id: Int, value: String): Axml.Attr {
        val v = doc.intern(value)
        return Axml.Attr(ns, doc.attributeName(name, id), v, Axml.TYPE_STRING, v)
    }

    private fun nameOf(doc: Axml, element: Axml.Element, androidNs: Int): String? = element.attributes.firstOrNull { a ->
        a.namespace == androidNs && (doc.resourceId(a.name) == ATTR_NAME || (doc.resourceId(a.name) == null && doc.string(a.name) == "name"))
    }?.takeIf { it.raw >= 0 }?.let { doc.string(it.raw) }

    private fun metaData(doc: Axml, ns: Int, key: String, value: String): List<Axml.Chunk> {
        val name = doc.intern("meta-data")
        return listOf(Axml.startElement(-1, name, listOf(stringAttr(doc, ns, "name", ATTR_NAME, key), stringAttr(doc, ns, "value", ATTR_VALUE, value))),
            Axml.endElement(-1, name))
    }

    /** runtime-injection's step: the runtime DEX after the last DEX and the provider as the last child of `<application>`. */
    internal fun injectRuntime(edit: ApkEdit, enrollmentUrl: String): List<Change> {
        val dexIndices = edit.entries.mapNotNull { e -> DEX.matchEntire(e.name)?.groupValues?.get(1)?.let { if (it.isEmpty()) 1 else it.toInt() } }.sorted()
        if (dexIndices.isEmpty()) throw ProtectException(ErrorCode.APP_INCOMPATIBLE, "APK without DEX")
        if (dexIndices != (1..dexIndices.size).toList()) throw ProtectException(ErrorCode.APP_INCOMPATIBLE, "non-contiguous DEX in the APK")
        val dexName = "classes${dexIndices.size + 1}.dex"
        val lastDex = edit.entries.last { DEX.matches(it.name) && !it.isDirectory }.name
        val doc = edit.manifest
        val ns = androidNs(doc)
        val spans = doc.spans()
        val application = spans.firstOrNull { (e, s) -> s.depth == 1 && doc.string(e.name) == "application" && e.namespace == -1 }
            ?: throw ProtectException(ErrorCode.APP_INCOMPATIBLE, "manifest without <application>")
        if (spans.any { (e, s) -> s.depth == 2 && s.start > application.second.start && s.end < application.second.end &&
                doc.string(e.name) == "provider" && nameOf(doc, e, ns) == RuntimeInjection.PROVIDER })
            throw ProtectException(ErrorCode.APP_INCOMPATIBLE, "the app already declares the Sentomaru provider")
        val providerName = doc.intern("provider")
        val authority = edit.artifact.manifest.packageName + AabInjector.AUTHORITY_SUFFIX
        val exported = Axml.Attr(ns, doc.attributeName("exported", ATTR_EXPORTED), -1, Axml.TYPE_BOOLEAN, 0)
        val provider = listOf(
            Axml.startElement(-1, providerName, listOf(stringAttr(doc, ns, "name", ATTR_NAME, RuntimeInjection.PROVIDER), exported,
                stringAttr(doc, ns, "authorities", ATTR_AUTHORITIES, authority))),
            *metaData(doc, ns, AabInjector.ENROLLMENT_URL_KEY, enrollmentUrl).toTypedArray(),
            Axml.endElement(-1, providerName))
        doc.insertBefore(application.second.end, provider)
        edit.manifestEdited()
        edit.add(lastDex, dexName, AabInjector.runtimeDex)
        return listOf(Change("dex.added", dexName), Change("manifest.provider.added", RuntimeInjection.PROVIDER))
    }

    /** ui-shield's step: three meta-data in the init provider and, when asked and missing, the overlay permission. */
    internal fun uiShield(edit: ApkEdit, all: Boolean, activities: List<String>, hideOverlay: Boolean): List<Change> {
        val doc = edit.manifest
        val ns = androidNs(doc)
        val spans = doc.spans()
        val providerSpan = spans.firstOrNull { (e, s) -> s.depth == 2 && doc.string(e.name) == "provider" && nameOf(doc, e, ns) == RuntimeInjection.PROVIDER }
            ?.second ?: throw ProtectException(ErrorCode.INTERNAL, "ui-shield: the init provider is not in the manifest")
        if (spans.any { (e, s) -> s.depth == 3 && s.start > providerSpan.start && s.end < providerSpan.end &&
                doc.string(e.name) == "meta-data" && nameOf(doc, e, ns) == UiShieldControl.MODE_KEY })
            throw ProtectException(ErrorCode.APP_INCOMPATIBLE, "the app already declares the ui-shield configuration")
        val meta = metaData(doc, ns, UiShieldControl.MODE_KEY, if (all) UiShieldControl.MODE_ALL else UiShieldControl.MODE_LISTED_ONLY) +
            metaData(doc, ns, UiShieldControl.ACTIVITIES_KEY, activities.joinToString(",")) +
            metaData(doc, ns, UiShieldControl.HIDE_OVERLAY_KEY, hideOverlay.toString())
        val changes = mutableListOf(Change("manifest.meta-data.added", "ui-shield"))
        // The meta-data goes in first, at the larger index; the permission then goes before <application>, at a smaller one.
        val declared = spans.any { (e, s) -> s.depth == 1 && doc.string(e.name) == "uses-permission" && nameOf(doc, e, ns) == UiShieldControl.OVERLAY_PERMISSION }
        doc.insertBefore(providerSpan.end, meta)
        if (hideOverlay && !declared) {
            val application = spans.first { (e, s) -> s.depth == 1 && doc.string(e.name) == "application" && e.namespace == -1 }.second
            val name = doc.intern("uses-permission")
            doc.insertBefore(application.start, listOf(
                Axml.startElement(-1, name, listOf(stringAttr(doc, ns, "name", ATTR_NAME, UiShieldControl.OVERLAY_PERMISSION))),
                Axml.endElement(-1, name)))
            changes += Change("manifest.permission.added", UiShieldControl.OVERLAY_PERMISSION)
        }
        edit.manifestEdited()
        return changes
    }

    private fun sha256(file: File): String {
        val digest = MessageDigest.getInstance("SHA-256")
        file.inputStream().use { input ->
            val buffer = ByteArray(1 shl 16)
            while (true) { val n = input.read(buffer); if (n < 0) break; digest.update(buffer, 0, n) }
        }
        return digest.digest().joinToString("") { "%02x".format(it) }
    }
}

/**
 * G-03b3 `--sign keystore` for an APK: apksig with v2 and v3 enabled and v1 disabled (the input's minSdk is 28 or more; apksig's own verifier reports the result as v3), from a keystore
 * whose passwords come only from the environment, as for an AAB. Signs [file] in place through a sibling temporary
 * file; returns the SHA-256 of the signer certificate.
 */
object ApkSignerKeystore {
    fun sign(file: File, keystore: File, alias: String, env: Map<String, String>, minSdk: Int): String {
        val storePassword = env["SENTOMARU_KEYSTORE_PASSWORD"]?.toCharArray()
            ?: throw ProtectException(ErrorCode.SIGN_FAILED, "SENTOMARU_KEYSTORE_PASSWORD missing")
        val keyPassword = env["SENTOMARU_KEY_PASSWORD"]?.toCharArray() ?: storePassword
        val entry = try {
            val store = KeyStore.getInstance(keystore, storePassword)
            store.getEntry(alias, KeyStore.PasswordProtection(keyPassword)) as? KeyStore.PrivateKeyEntry
        } catch (e: Exception) {
            throw ProtectException(ErrorCode.SIGN_FAILED, "keystore unreadable or wrong password (${e.javaClass.simpleName})")
        } finally {
            storePassword.fill('\u0000')
            keyPassword.fill('\u0000')
        } ?: throw ProtectException(ErrorCode.SIGN_FAILED, "no private key entry for the alias")
        val chain = entry.certificateChain.map { it as? X509Certificate ?: throw ProtectException(ErrorCode.SIGN_FAILED, "certificate chain is not X.509") }
        val signed = File(file.parentFile, ".${file.name}.${UUID.randomUUID()}.signing")
        try {
            val config = ApkSigner.SignerConfig.Builder("sentomaru", KeyConfig.Jca(entry.privateKey), chain).build()
            ApkSigner.Builder(listOf(config)).setInputApk(file).setOutputApk(signed).setMinSdkVersion(minSdk)
                .setV1SigningEnabled(false).setV2SigningEnabled(true).setV3SigningEnabled(true).build().sign()
            Files.move(signed.toPath(), file.toPath(), StandardCopyOption.REPLACE_EXISTING, StandardCopyOption.ATOMIC_MOVE)
        } catch (e: ProtectException) {
            throw e
        } catch (e: Exception) {
            throw ProtectException(ErrorCode.SIGN_FAILED, "APK signing (${e.javaClass.simpleName})")
        } finally {
            signed.delete()
        }
        return MessageDigest.getInstance("SHA-256").digest(chain.first().encoded).joinToString("") { "%02x".format(it) }
    }
}
