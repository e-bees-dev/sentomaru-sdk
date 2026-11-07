package br.com.ebees.sentomaru.protect

import com.android.aapt.Resources
import com.android.tools.build.bundletool.commands.ValidateBundleCommand
import com.google.gson.JsonObject
import java.io.File
import java.io.FilterInputStream
import java.io.InputStream
import java.nio.file.Files
import java.nio.file.Path
import java.nio.file.StandardCopyOption
import java.security.DigestInputStream
import java.security.MessageDigest
import java.util.UUID
import java.util.zip.ZipEntry
import java.util.zip.ZipFile
import java.util.zip.ZipOutputStream

/**
 * What one application changed, for the report: the changes of each control and the output facts; [evidence] is what a
 * control only knows once applied (D-14c: `asset-encryption`'s `bytesOut`), over the evidence of its plan.
 */
data class Injected(val output: File, val changes: Map<String, List<Change>>, val sha256: String, val sizeDeltaBytes: Long,
    val removedSignature: Boolean, val evidence: Map<String, Map<String, String>> = emptyMap())

/**
 * The bundle being edited by the controls of one run (D-07b): the entry list of the input, the base manifest and
 * resource table (parsed on first use, written only if a control changed them) and the entries to add, each right
 * after a given source entry. Everything else is streamed unchanged by [AabInjector].
 */
class AabEdit internal constructor(internal val zip: ZipFile, val entries: List<ZipEntry>, val artifact: Artifact) {
    val names: Set<String> = entries.map { it.name }.toSet()
    private var manifestNode: Resources.XmlNode? = null
    internal var manifestChanged = false
        private set
    private var table: Resources.ResourceTable? = null
    internal var resourcesChanged = false
        private set
    internal val additions = mutableListOf<Addition>()
    internal val removed = LinkedHashSet<String>()
    internal val replaced = LinkedHashMap<String, ByteArray>()
    /** Evidence a control's step adds to its plan's (control id to members), see [Injected.evidence]. */
    internal val evidence = LinkedHashMap<String, Map<String, String>>()

    internal class Addition(val after: String, val name: String, val bytes: ByteArray)

    var manifest: Resources.XmlNode
        get() = manifestNode ?: AabInjector.parseManifest(ArtifactReader.entry(zip, AabInjector.MANIFEST)).also { manifestNode = it }
        set(value) { manifestNode = value; manifestChanged = true }

    /** `base/resources.pb`; a bundle without it is refused by the caller (null here). */
    val resourceTableOrNull: Resources.ResourceTable?
        get() = table ?: zip.getEntry(AabInjector.RESOURCES)?.let { ResourceTables.read(zip, it) }?.also { table = it }

    var resourceTable: Resources.ResourceTable
        get() = resourceTableOrNull ?: throw ProtectException(ErrorCode.APP_INCOMPATIBLE, NetworkPinning.RESOURCE_TABLE_UNSUPPORTED)
        set(value) { table = value; resourcesChanged = true }

    /**
     * Adds [name] right after the source entry [after]. When [after] is [remove]d, the addition takes its place: right
     * before the next source entry that survives, or at the end when none does (D-14c, contract "asset-encryption").
     * A name already in the bundle and not removed, or added twice, is a defect of the control (`internal-error`).
     */
    internal fun add(after: String, name: String, bytes: ByteArray) {
        if (after !in names || (name in names && name !in removed) || additions.any { it.name == name })
            throw ProtectException(ErrorCode.INTERNAL, "bundle addition $name")
        additions += Addition(after, name, bytes)
    }

    /**
     * D-14c: marks the existing source entry [name] not to be copied. Removing an entry that is not in the bundle (a
     * directory entry included), one already removed or one added in this run is a defect of the control
     * (`internal-error`); the manifest and the resource table, which controls replace, are never removed.
     */
    internal fun remove(name: String) {
        val entry = entries.firstOrNull { it.name == name }
        if (entry == null || entry.isDirectory || name in removed || name in replaced || name == AabInjector.MANIFEST ||
            name == AabInjector.RESOURCES) throw ProtectException(ErrorCode.INTERNAL, "bundle removal $name")
        removed += name
    }

    /**
     * D-14c: writes [bytes] in place of the existing source entry [name] (its time kept), as the manifest and the
     * resource table are. An absent, removed or already replaced entry, or the manifest and the resource table (they
     * have their own properties), is a defect of the control (`internal-error`).
     */
    internal fun replace(name: String, bytes: ByteArray) {
        val entry = entries.firstOrNull { it.name == name }
        if (entry == null || entry.isDirectory || name in removed || name in replaced || name == AabInjector.MANIFEST ||
            name == AabInjector.RESOURCES) throw ProtectException(ErrorCode.INTERNAL, "bundle replacement $name")
        replaced[name] = bytes
    }
}

/**
 * Applies the controls that change the binary to an AAB (G-03b2, generalized in D-07b): each control's step edits the
 * same [AabEdit] in stage order, then one write and one validation. runtime-injection: the runtime DEX embedded in
 * this CLI becomes the next `base/dex/classesN.dex`, and the base manifest (protobuf) gains the init provider
 * (exported=false, default process) with the enrollment URL as its meta-data. network-pinning: see [NetworkPinning].
 * Every other entry is streamed unchanged (STORED entries keep the source CRC and size, every entry keeps its time;
 * added entries carry a fixed time, so the output is reproducible). A JAR signature, which the change invalidates, is
 * removed (the AAB leaves unsigned by default, contract "Assinatura"). The result is validated by bundletool before it
 * is moved into `<out>`; on any failure nothing is left there.
 */
object AabInjector {
    const val AUTHORITY_SUFFIX = ".sentomaru-init"
    const val ENROLLMENT_URL_KEY = "br.com.ebees.sentomaru.runtime.ENROLLMENT_URL"
    internal const val ANDROID_NS = "http://schemas.android.com/apk/res/android"
    internal const val ATTR_NAME = 0x01010003
    private const val ATTR_EXPORTED = 0x01010010
    private const val ATTR_AUTHORITIES = 0x01010018
    internal const val ATTR_VALUE = 0x01010024
    internal const val MANIFEST = "base/manifest/AndroidManifest.xml"
    internal const val RESOURCES = "base/resources.pb"
    /** 1980-01-01T00:00Z plus a day (the zip epoch, away from time-zone edge cases): the time of added entries. */
    private const val FIXED_TIME = 315_619_200_000L
    private val BASE_DEX = Regex("""base/dex/classes(\d*)\.dex""")
    private val SIGNATURE_BLOCK = Regex("""META-INF/[^/]+\.(SF|RSA|DSA|EC)""", RegexOption.IGNORE_CASE)

    /** Test seam: the bundle validation (bundletool, in process). */
    internal var validate: (Path) -> Unit = { path ->
        ValidateBundleCommand.builder().setBundlePath(path).setPrintOutput(false).build().execute()
    }

    /** Test seam: called after each entry is written (a failure here must leave nothing in `<out>`). */
    internal var afterEntry: (String) -> Unit = {}

    /** The runtime DEX of this CLI build (resource generated by :protect-runtime + d8). */
    val runtimeDex: ByteArray by lazy {
        AabInjector::class.java.getResourceAsStream("/br/com/ebees/sentomaru/protect/runtime/classes.dex")?.use { it.readBytes() }
            ?: throw ProtectException(ErrorCode.INTERNAL, "runtime DEX missing from this build")
    }

    val runtimeDexSha256: String by lazy { hex(MessageDigest.getInstance("SHA-256").digest(runtimeDex)) }

    /** Output name: `<input>.protected.aab` for a contract run, `<input>.lab.aab` for the laboratory run. */
    fun target(input: File, outDir: File, lab: Boolean = true) =
        File(outDir, input.name.removeSuffix(".aab") + if (lab) ".lab.aab" else ".protected.aab")

    /**
     * [steps] are the controls that change the binary, in application order, with their sections. [finish] runs on the
     * validated temporary file before it is measured and moved (G-03e: the signature), so a signing failure also leaves
     * nothing in `<out>`.
     */
    fun inject(input: File, artifact: Artifact, steps: List<Pair<Control, JsonObject>>, context: ControlContext, outDir: File,
        lab: Boolean = true, finish: (File) -> Unit = {}): Injected {
        val target = target(input, outDir, lab)
        val temp = File(outDir, ".${target.name}.${UUID.randomUUID()}.tmp")
        try {
            val (changes, removedSignature, evidence) = try {
                write(input, artifact, steps, context, temp)
            } catch (e: java.util.zip.ZipException) {
                throw ProtectException(ErrorCode.INPUT_FORMAT, "corrupt entry in the bundle")
            }
            try {
                validate(temp.toPath())
            } catch (e: Exception) {
                throw ProtectException(ErrorCode.CONTROL_FAILED,
                    "${steps.joinToString("+") { it.first.id }}: bundletool validation (${e.javaClass.simpleName})")
            }
            finish(temp)
            val sha = sha256(temp)
            val size = temp.length()
            Files.move(temp.toPath(), target.toPath(), StandardCopyOption.REPLACE_EXISTING, StandardCopyOption.ATOMIC_MOVE)
            return Injected(target, changes, sha, size - input.length(), removedSignature, evidence)
        } finally {
            temp.delete()
        }
    }

    private fun write(input: File, artifact: Artifact, steps: List<Pair<Control, JsonObject>>, context: ControlContext,
        temp: File): Triple<Map<String, List<Change>>, Boolean, Map<String, Map<String, String>>> {
        ZipFile(input).use { zip ->
            val entries = zip.entries().toList()
            if (entries.size > ArtifactReader.MAX_ENTRIES) throw ProtectException(ErrorCode.INPUT_FORMAT, "too many entries")
            val names = HashSet<String>()
            for (e in entries) {
                if (!ArtifactReader.safeName(e.name) || !names.add(e.name)) throw ProtectException(ErrorCode.INPUT_FORMAT, "unsafe entry name")
            }
            val edit = AabEdit(zip, entries, artifact)
            val changes = LinkedHashMap<String, List<Change>>()
            for ((control, section) in steps) changes[control.id] = control.apply(section, edit, context)
            val manifest = if (edit.manifestChanged) edit.manifest.toByteArray() else null
            val resources = if (edit.resourcesChanged) edit.resourceTable.toByteArray() else null
            val signed = entries.any { SIGNATURE_BLOCK.matches(it.name) }
            var budget = ArtifactReader.MAX_VERIFY_BYTES
            ZipOutputStream(temp.outputStream().buffered()).use { out ->
                for (entry in entries) {
                    if (entry.isDirectory) continue
                    // A signed bundle loses its signature (block and manifest digests); an unsigned one keeps META-INF as is.
                    if (signed && (SIGNATURE_BLOCK.matches(entry.name) || entry.name.equals("META-INF/MANIFEST.MF", true))) continue
                    if (entry.name in edit.removed) {
                        // D-14c: not copied; what was added after it takes its place.
                    } else if (entry.name in edit.replaced) {
                        add(out, entry.name, edit.replaced.getValue(entry.name), entry.time)
                    } else if (entry.name == MANIFEST && manifest != null) {
                        add(out, MANIFEST, manifest, entry.time)
                    } else if (entry.name == RESOURCES && resources != null) {
                        add(out, RESOURCES, resources, entry.time)
                    } else {
                        copy(out, entry, zip.getInputStream(entry)) { n ->
                            budget -= n
                            if (budget < 0) throw ProtectException(ErrorCode.INPUT_TOO_LARGE, "entries above 2 GiB inflated")
                        }
                    }
                    afterEntry(entry.name)
                    for (a in edit.additions) if (a.after == entry.name) add(out, a.name, a.bytes, FIXED_TIME)
                }
            }
            return Triple(changes, signed, edit.evidence)
        }
    }

    /** runtime-injection's step: the runtime DEX after the last base DEX and the provider in the base manifest. */
    internal fun injectRuntime(edit: AabEdit, enrollmentUrl: String): List<Change> {
        val dexIndices = edit.entries.mapNotNull { e -> BASE_DEX.matchEntire(e.name)?.groupValues?.get(1)?.let { if (it.isEmpty()) 1 else it.toInt() } }
            .sorted()
        if (dexIndices.isEmpty()) throw ProtectException(ErrorCode.APP_INCOMPATIBLE, "base module without DEX")
        // Android loads classes.dex, classes2.dex, … and stops at the first gap: a gap means an app that is already
        // broken, and a DEX added after it would never load.
        if (dexIndices != (1..dexIndices.size).toList()) throw ProtectException(ErrorCode.APP_INCOMPATIBLE, "non-contiguous DEX in base")
        val dexName = "base/dex/classes${dexIndices.size + 1}.dex"
        val lastDex = edit.entries.last { BASE_DEX.matches(it.name) && !it.isDirectory }.name
        edit.manifest = provider(edit.manifest, edit.artifact.manifest.packageName, enrollmentUrl)
        edit.add(lastDex, dexName, runtimeDex)
        return listOf(Change("dex.added", dexName), Change("manifest.provider.added", RuntimeInjection.PROVIDER))
    }

    /**
     * G-10: the three UI-shield meta-data values inside the init provider that runtime-injection added, and, when [hideOverlay]
     * is asked and the app lacks it, `<uses-permission HIDE_OVERLAY_WINDOWS>` before `<application>`. Refuses a manifest
     * without the provider (the control needs runtime-injection) or one that already carries the shield's meta-data.
     */
    internal fun uiShield(root: Resources.XmlNode, all: Boolean, activities: List<String>, hideOverlay: Boolean): Pair<Resources.XmlNode, List<Change>> {
        val manifest = root.element
        val appIndex = manifest.childList.indexOfFirst { it.hasElement() && it.element.name == "application" && it.element.namespaceUri.isEmpty() }
        if (appIndex < 0) throw ProtectException(ErrorCode.APP_INCOMPATIBLE, "manifest without <application>")
        val application = manifest.getChild(appIndex).element
        val providerIndex = application.childList.indexOfFirst { c ->
            c.hasElement() && c.element.name == "provider" && c.element.attributeList.any { it.resourceId == ATTR_NAME && it.value == RuntimeInjection.PROVIDER }
        }
        if (providerIndex < 0) throw ProtectException(ErrorCode.INTERNAL, "ui-shield: the init provider is not in the manifest")
        val provider = application.getChild(providerIndex).element
        if (provider.childList.any { c -> c.hasElement() && c.element.name == "meta-data" &&
                c.element.attributeList.any { it.resourceId == ATTR_NAME && it.value == UiShieldControl.MODE_KEY } })
            throw ProtectException(ErrorCode.APP_INCOMPATIBLE, "the app already declares the ui-shield configuration")
        fun meta(key: String, value: String) = Resources.XmlNode.newBuilder().setElement(Resources.XmlElement.newBuilder().setName("meta-data")
            .addAttribute(text("name", ATTR_NAME, key)).addAttribute(text("value", ATTR_VALUE, value)))
        val newProvider = provider.toBuilder()
            .addChild(meta(UiShieldControl.MODE_KEY, if (all) UiShieldControl.MODE_ALL else UiShieldControl.MODE_LISTED_ONLY))
            .addChild(meta(UiShieldControl.ACTIVITIES_KEY, activities.joinToString(",")))
            .addChild(meta(UiShieldControl.HIDE_OVERLAY_KEY, hideOverlay.toString()))
        val newApplication = application.toBuilder().setChild(providerIndex, application.getChild(providerIndex).toBuilder().setElement(newProvider))
        val changes = mutableListOf(Change("manifest.meta-data.added", "ui-shield"))
        val builder = manifest.toBuilder().setChild(appIndex, manifest.getChild(appIndex).toBuilder().setElement(newApplication))
        val declared = manifest.childList.any { c -> c.hasElement() && c.element.name == "uses-permission" &&
            c.element.attributeList.any { it.resourceId == ATTR_NAME && it.value == UiShieldControl.OVERLAY_PERMISSION } }
        if (hideOverlay && !declared) {
            val permission = Resources.XmlNode.newBuilder().setElement(Resources.XmlElement.newBuilder().setName("uses-permission")
                .addAttribute(text("name", ATTR_NAME, UiShieldControl.OVERLAY_PERMISSION)))
            // Before <application>, where aapt2 writes the permissions.
            val rebuilt = Resources.XmlElement.newBuilder(builder.build()).clearChild()
            builder.build().childList.forEachIndexed { i, node -> if (i == appIndex) rebuilt.addChild(permission); rebuilt.addChild(node) }
            changes += Change("manifest.permission.added", UiShieldControl.OVERLAY_PERMISSION)
            return root.toBuilder().setElement(rebuilt).build() to changes
        }
        return root.toBuilder().setElement(builder).build() to changes
    }

    internal fun parseManifest(bytes: ByteArray): Resources.XmlNode = parse(bytes)

    private fun parse(bytes: ByteArray): Resources.XmlNode = try {
        Resources.XmlNode.parseFrom(bytes)
    } catch (e: Exception) {
        throw ProtectException(ErrorCode.INPUT_FORMAT, "unreadable bundle manifest")
    }

    /** Streams one source entry; STORED keeps the source CRC and sizes (checked by ZipOutputStream on close). */
    private fun copy(out: ZipOutputStream, source: ZipEntry, data: InputStream, counted: (Int) -> Unit) {
        val e = ZipEntry(source.name)
        e.time = source.time
        if (source.method == ZipEntry.STORED) {
            e.method = ZipEntry.STORED
            e.size = source.size
            e.compressedSize = source.size
            e.crc = source.crc
        }
        out.putNextEntry(e)
        val counting = object : FilterInputStream(data) {
            override fun read(b: ByteArray, off: Int, len: Int): Int = super.read(b, off, len).also { if (it > 0) counted(it) }
        }
        counting.use { it.copyTo(out, 1 shl 16) }
        out.closeEntry()
    }

    private fun add(out: ZipOutputStream, name: String, bytes: ByteArray, time: Long) {
        out.putNextEntry(ZipEntry(name).apply { this.time = time })
        out.write(bytes)
        out.closeEntry()
    }

    /** The base manifest with the provider appended to <application>; refuses an app that already declares it. */
    internal fun provider(root: Resources.XmlNode, packageName: String, enrollmentUrl: String): Resources.XmlNode {
        val manifest = root.element
        val appIndex = manifest.childList.indexOfFirst { it.hasElement() && it.element.name == "application" && it.element.namespaceUri.isEmpty() }
        if (appIndex < 0) throw ProtectException(ErrorCode.APP_INCOMPATIBLE, "manifest without <application>")
        val application = manifest.getChild(appIndex).element
        val declared = application.childList.any { c ->
            c.hasElement() && c.element.name == "provider" &&
                c.element.attributeList.any { it.resourceId == ATTR_NAME && it.value == RuntimeInjection.PROVIDER }
        }
        if (declared) throw ProtectException(ErrorCode.APP_INCOMPATIBLE, "the app already declares the Sentomaru provider")
        // Attributes in resource-id order, as aapt2 writes them.
        val metaData = Resources.XmlElement.newBuilder().setName("meta-data")
            .addAttribute(text("name", ATTR_NAME, ENROLLMENT_URL_KEY))
            .addAttribute(text("value", ATTR_VALUE, enrollmentUrl))
        val provider = Resources.XmlElement.newBuilder().setName("provider")
            .addAttribute(text("name", ATTR_NAME, RuntimeInjection.PROVIDER))
            .addAttribute(Resources.XmlAttribute.newBuilder().setNamespaceUri(ANDROID_NS).setName("exported").setValue("false")
                .setResourceId(ATTR_EXPORTED)
                .setCompiledItem(Resources.Item.newBuilder().setPrim(Resources.Primitive.newBuilder().setBooleanValue(false))))
            .addAttribute(text("authorities", ATTR_AUTHORITIES, packageName + AUTHORITY_SUFFIX))
            .addChild(Resources.XmlNode.newBuilder().setElement(metaData))
        val newApplication = application.toBuilder().addChild(Resources.XmlNode.newBuilder().setElement(provider))
        return root.toBuilder().setElement(manifest.toBuilder().setChild(appIndex, manifest.getChild(appIndex).toBuilder().setElement(newApplication)))
            .build()
    }

    internal fun text(name: String, id: Int, value: String) =
        Resources.XmlAttribute.newBuilder().setNamespaceUri(ANDROID_NS).setName(name).setValue(value).setResourceId(id)

    private fun sha256(file: File): String {
        val digest = MessageDigest.getInstance("SHA-256")
        DigestInputStream(file.inputStream(), digest).use { it.copyTo(java.io.OutputStream.nullOutputStream(), 1 shl 16) }
        return hex(digest.digest())
    }

    private fun hex(bytes: ByteArray) = bytes.joinToString("") { "%02x".format(it) }
}
