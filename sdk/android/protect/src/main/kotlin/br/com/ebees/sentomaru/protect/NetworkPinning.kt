package br.com.ebees.sentomaru.protect

import com.android.aapt.Resources
import com.google.gson.JsonArray
import com.google.gson.JsonElement
import com.google.gson.JsonObject
import java.security.MessageDigest
import java.time.LocalDate
import java.time.format.DateTimeFormatter
import java.time.format.ResolverStyle
import java.time.temporal.ChronoUnit
import java.util.Base64

/** One validated domain of the `network-pinning` section. */
data class PinnedDomain(val host: String, val includeSubdomains: Boolean, val pins: List<String>, val backupPins: List<String>)

/** The validated `network-pinning` section: [pins] keep the profile's `sha256/` prefix. */
data class PinningSection(val expiration: LocalDate, val domains: List<PinnedDomain>)

/**
 * D-07 (`network-pinning`, harden/40; contract "network-pinning (D-07)", ADR 0002).
 * In the distributed CLI since D-07f (behind the laboratory gate from D-07b to D-07e); nothing here reads
 * `context.lab`. On an AAB, in the `base` module: a `network_security_config` XML resource (aapt2 proto XML) with one
 * `<domain-config>` per pinned host, its entry in `resources.pb` (new ids, nothing renumbered), the
 * `android:networkSecurityConfig` attribute on `<application>` and, when the base DEX has the Android SDK, a meta-data
 * with the pinned hosts for the SDK's local pin-failure event (D-07d).
 *
 * AOSP (`XmlConfigSource.parsePinSet`, `NetworkSecurityTrustManager.checkPins`, read on 26/10/2026): the `expiration`
 * is parsed with `SimpleDateFormat("yyyy-MM-dd")`, not lenient, in the device's default time zone, and the pins are
 * skipped once `System.currentTimeMillis() > expiration`: the pin-set stops at **00:00 local time of the expiration
 * date** (the date itself is not pinned). The CLI rule (contract) is unchanged by this.
 */
object NetworkPinning : Control {
    override val id = "network-pinning"
    override val version = "1"
    override val stage = "harden"
    override val order = 40
    override val prerequisites = emptyList<String>()
    override val changeIds = listOf("res.xml.added", "resources.entry.added", "manifest.network-security-config.set",
        "manifest.meta-data.added")
    override val changesBinary = true

    const val RESOURCE_NAME = "sentomaru_network_security_config"
    const val RESOURCE_PATH = "res/xml/$RESOURCE_NAME.xml"
    const val HOSTS_META_DATA = "br.com.ebees.sentomaru.pinning.hosts"
    const val NSC_PRESENT = "network-security-config-present"
    const val RESOURCE_TABLE_UNSUPPORTED = "resource-table-unsupported"
    const val CLEARTEXT_UNSUPPORTED = "cleartext-attribute-unsupported"
    const val MAX_DAYS = 180L
    const val NEAR_DAYS = 30L
    private const val MAX_DOMAINS = 16
    private const val MAX_PINS = 16
    private val HOST = Regex("""\A(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z](?:[a-z0-9-]{0,61}[a-z0-9])?\z""")
    private val PIN = Regex("""\Asha256/[A-Za-z0-9+/]{43}=\z""")
    private val DATE = Regex("""\A[0-9]{4}-[0-9]{2}-[0-9]{2}\z""")
    private val DATE_FORMAT = DateTimeFormatter.ofPattern("uuuu-MM-dd").withResolverStyle(ResolverStyle.STRICT)
    private val SDK_CLASSES = setOf(NetworkSigning.ANDROID_TRANSPORT, NetworkSigning.ANDROID_URLCONNECTION_TRANSPORT)

    private fun bad(field: String): Nothing = throw ProtectException(ErrorCode.PROFILE_FORMAT, "$id.$field")

    private val FIELD = Regex("""\A[A-Za-z0-9_-]{1,64}\z""")

    /** An unknown member is named in `detail` only when it is a short plain name (the detail lands in the report). */
    private fun closed(o: JsonObject, allowed: List<String>, prefix: String) {
        (o.keySet() - allowed.toSet()).sorted().firstOrNull()?.let { bad(prefix + if (FIELD.matches(it)) it else "unknown-field") }
        allowed.firstOrNull { it !in o.keySet() }?.let { bad("$prefix$it") }
    }

    private fun string(e: JsonElement?): String? = e?.takeIf { it.isJsonPrimitive && it.asJsonPrimitive.isString }?.asString

    /** The section's rules (contract table, exit 4); [today] is the UTC date of the run. */
    fun parse(section: JsonObject, today: LocalDate): PinningSection {
        closed(section, listOf("version", "expiration", "domains"), "")
        val text = string(section.get("expiration"))?.takeIf(DATE::matches) ?: bad("expiration")
        val expiration = runCatching { LocalDate.parse(text, DATE_FORMAT) }.getOrNull() ?: bad("expiration")
        val days = ChronoUnit.DAYS.between(today, expiration)
        if (days < 0 || days > MAX_DAYS) bad("expiration")
        val list = section.get("domains")?.takeIf { it.isJsonArray }?.asJsonArray ?: bad("domains")
        if (list.size() == 0 || list.size() > MAX_DOMAINS) bad("domains")
        val domains = list.map { item ->
            val d = item.takeIf { it.isJsonObject }?.asJsonObject ?: bad("domains")
            closed(d, listOf("host", "includeSubdomains", "pins", "backupPins"), "domains.")
            val host = string(d.get("host"))?.takeIf { it.length <= 253 && HOST.matches(it) } ?: bad("domains.host")
            val sub = d.get("includeSubdomains")?.takeIf { it.isJsonPrimitive && it.asJsonPrimitive.isBoolean }?.asBoolean
                ?: bad("domains.includeSubdomains")
            val pins = pins(d.get("pins"), "domains.pins")
            val backups = pins(d.get("backupPins"), "domains.backupPins")
            if (pins.size + backups.size > MAX_PINS) bad("domains.pins")
            if (backups.any { it in pins }) bad("domains.backupPins")
            PinnedDomain(host, sub, pins, backups)
        }
        if (domains.map { it.host }.toSet().size != domains.size) bad("domains")
        return PinningSection(expiration, domains)
    }

    /** A non-empty list of distinct pins, each `sha256/` + canonical base64 of 32 bytes. */
    private fun pins(e: JsonElement?, field: String): List<String> {
        val a: JsonArray = e?.takeIf { it.isJsonArray }?.asJsonArray ?: bad(field)
        val pins = a.map { p -> string(p)?.takeIf { PIN.matches(it) && canonical(it) } ?: bad(field) }
        if (pins.isEmpty() || pins.toSet().size != pins.size) bad(field)
        return pins
    }

    /** Strict decoding: 32 bytes and the base64 re-encodes to itself (the 2 bits left over by the last digit are zero). */
    internal fun canonical(pin: String): Boolean {
        val b64 = pin.removePrefix("sha256/")
        val bytes = runCatching { Base64.getDecoder().decode(b64) }.getOrNull() ?: return false
        return bytes.size == 32 && Base64.getEncoder().encodeToString(bytes) == b64
    }

    override fun validate(section: JsonObject, context: ControlContext) {
        val parsed = parse(section, context.today)
        if (ChronoUnit.DAYS.between(context.today, parsed.expiration) < NEAR_DAYS)
            context.warn("network-pinning-expiration-near", "the pin-set expires on ${parsed.expiration} (less than $NEAR_DAYS days)")
    }

    override fun plan(section: JsonObject, artifact: Artifact, context: ControlContext): ControlPlan {
        val parsed = parse(section, context.today)
        val m = artifact.manifest
        if (!m.hasApplication) throw ProtectException(ErrorCode.APP_INCOMPATIBLE, "manifest without <application>")
        // D-07x2: no merge with the app's own configuration in v1.
        if (m.networkSecurityConfig || m.declaresPinningHosts) throw ProtectException(ErrorCode.APP_INCOMPATIBLE, NSC_PRESENT)
        if (m.usesCleartextTraffic == Cleartext.REFERENCE) throw ProtectException(ErrorCode.APP_INCOMPATIBLE, CLEARTEXT_UNSUPPORTED)
        val file = artifact.file ?: throw ProtectException(ErrorCode.INTERNAL, "$id: artifact without its file")
        if (artifact.kind == ArtifactKind.AAB) java.util.zip.ZipFile(file).use { zip ->
            if (zip.getEntry("base/$RESOURCE_PATH") != null) throw ProtectException(ErrorCode.APP_INCOMPATIBLE, RESOURCE_TABLE_UNSUPPORTED)
            val entry = zip.getEntry(AabInjector.RESOURCES) ?: throw ProtectException(ErrorCode.APP_INCOMPATIBLE, RESOURCE_TABLE_UNSUPPORTED)
            ResourceTables.slot(ResourceTables.read(zip, entry))
        }
        val found = DexScan.present(file, artifact.kind, SDK_CLASSES + NetworkSigning.FLUTTER_TRANSPORT, control = id)
        val sdk = found.any { it in SDK_CLASSES }
        if (NetworkSigning.FLUTTER_TRANSPORT in found) context.warn("network-pinning-dart-line",
            "Flutter app: the Dart side (dart:io) does not read network_security_config; it needs the plugin's pinning line")
        val signed = context.sections.firstOrNull { it.id == NetworkSigning.id }?.fields?.get("hosts")
            ?.takeIf { it.isJsonArray }?.asJsonArray?.mapNotNull(::string).orEmpty().toSet()
        val unsigned = parsed.domains.map { it.host }.filter { it !in signed }
        if (unsigned.isNotEmpty()) context.warn("network-pinning-host-unsigned",
            "${unsigned.size} pinned host(s) outside network-signing.hosts")
        if (permitsCleartext(m)) context.warn("network-pinning-cleartext-blocked",
            "the app permits cleartext; the pinned hosts now refuse http (D-07x12)")
        val prefix = if (artifact.kind == ArtifactKind.AAB) "base/" else ""
        return ControlPlan(id, version, "planned", changes(prefix, sdk), evidence = evidence(section, parsed, m))
    }

    /**
     * With a configuration present the platform ignores `usesCleartextTraffic`; without the attribute its default follows
     * targetSdk (< 28 = true), and an absent targetSdk is the minSdk (Android's rule). A reference was refused before.
     */
    private fun permitsCleartext(m: ManifestFacts): Boolean = when (m.usesCleartextTraffic) {
        Cleartext.TRUE -> true
        Cleartext.FALSE -> false
        Cleartext.REFERENCE -> throw ProtectException(ErrorCode.APP_INCOMPATIBLE, CLEARTEXT_UNSUPPORTED)
        null -> (m.targetSdk ?: m.minSdk ?: 0) < 28
    }

    private fun changes(prefix: String, sdk: Boolean) = listOfNotNull(
        Change("res.xml.added", "$prefix$RESOURCE_PATH"),
        Change("resources.entry.added", "xml/$RESOURCE_NAME"),
        Change("manifest.network-security-config.set", "@xml/$RESOURCE_NAME"),
        Change("manifest.meta-data.added", HOSTS_META_DATA).takeIf { sdk })

    private fun evidence(section: JsonObject, parsed: PinningSection, m: ManifestFacts) = mapOf(
        "domains" to parsed.domains.size.toString(),
        "expiration" to parsed.expiration.toString(),
        "sectionSha256" to MessageDigest.getInstance("SHA-256").digest(Jcs.canonical(section).toByteArray(Charsets.UTF_8))
            .joinToString("") { "%02x".format(it) },
        "cleartextBase" to when (m.usesCleartextTraffic) { Cleartext.TRUE -> "true"; Cleartext.FALSE -> "false"; else -> "absent" })

    override fun apply(section: JsonObject, edit: AabEdit, context: ControlContext): List<Change> {
        val parsed = parse(section, context.today)
        val facts = edit.artifact.manifest
        if (edit.names.contains("base/$RESOURCE_PATH")) throw ProtectException(ErrorCode.APP_INCOMPATIBLE, RESOURCE_TABLE_UNSUPPORTED)
        val table = edit.resourceTableOrNull ?: throw ProtectException(ErrorCode.APP_INCOMPATIBLE, RESOURCE_TABLE_UNSUPPORTED)
        val slot = ResourceTables.slot(table)
        val cleartext = when (facts.usesCleartextTraffic) { Cleartext.TRUE -> true; Cleartext.FALSE -> false; null -> null
            Cleartext.REFERENCE -> throw ProtectException(ErrorCode.APP_INCOMPATIBLE, CLEARTEXT_UNSUPPORTED) }
        edit.resourceTable = ResourceTables.add(table, slot)
        edit.add(AabInjector.RESOURCES, "base/$RESOURCE_PATH", NetworkSecurityConfigXml.build(parsed, cleartext).toByteArray())
        val sdk = edit.artifact.file?.let { DexScan.present(it, ArtifactKind.AAB, SDK_CLASSES).isNotEmpty() } ?: false
        edit.manifest = NetworkSecurityConfigXml.manifest(edit.manifest, slot.resourceId, if (sdk) parsed.domains.map { it.host } else null)
        return changes("base/", sdk)
    }
}

/**
 * RFC 8785 (JCS) for what a validated profile section can hold: objects, arrays, strings, booleans and, since D-14c,
 * null (`asset-encryption` takes `"strings": null`). A number is refused, so the digest never depends on a number
 * format. Members are sorted by UTF-16 code units, as JCS asks; strings are escaped like ECMAScript's JSON.stringify.
 */
internal object Jcs {
    fun canonical(e: JsonElement): String = StringBuilder().also { write(e, it) }.toString()

    private fun write(e: JsonElement, out: StringBuilder) {
        when {
            e.isJsonObject -> {
                out.append('{')
                e.asJsonObject.entrySet().sortedWith { a, b -> a.key.compareTo(b.key) }.forEachIndexed { i, (k, v) ->
                    if (i > 0) out.append(',')
                    string(k, out); out.append(':'); write(v, out)
                }
                out.append('}')
            }
            e.isJsonArray -> {
                out.append('[')
                e.asJsonArray.forEachIndexed { i, v -> if (i > 0) out.append(','); write(v, out) }
                out.append(']')
            }
            e.isJsonPrimitive && e.asJsonPrimitive.isBoolean -> out.append(e.asBoolean)
            e.isJsonPrimitive && e.asJsonPrimitive.isString -> string(e.asString, out)
            e.isJsonNull -> out.append("null")
            else -> throw ProtectException(ErrorCode.INTERNAL, "JCS: a number in a validated section")
        }
    }

    private fun string(s: String, out: StringBuilder) {
        out.append('"')
        for (c in s) when (c) {
            '"' -> out.append("\\\"")
            '\\' -> out.append("\\\\")
            '\b' -> out.append("\\b")
            '\u000c' -> out.append("\\f")
            '\n' -> out.append("\\n")
            '\r' -> out.append("\\r")
            '\t' -> out.append("\\t")
            else -> if (c < ' ') out.append("\\u%04x".format(c.code)) else out.append(c)
        }
        out.append('"')
    }
}

/** The base resource table edit of `network-pinning`: where the new `xml` entry goes, and adding it. */
internal object ResourceTables {
    /**
     * Above this, `resources.pb` is not edited by this build (the manifest limit is 8 MiB; real tables stay far below).
     * The parsed table takes several times its bytes in memory: an `OutOfMemoryError` while parsing is a refusal too.
     */
    const val MAX_BYTES = 32 * 1024 * 1024
    private const val APP_PACKAGE_ID = 0x7f

    /** [typeIndex] is -1 when the `xml` type is new. */
    data class Slot(val typeIndex: Int, val typeId: Int, val entryId: Int) {
        val resourceId: Int get() = (APP_PACKAGE_ID shl 24) or (typeId shl 16) or entryId
    }

    private fun unsupported(): Nothing = throw ProtectException(ErrorCode.APP_INCOMPATIBLE, NetworkPinning.RESOURCE_TABLE_UNSUPPORTED)

    fun read(zip: java.util.zip.ZipFile, entry: java.util.zip.ZipEntry): Resources.ResourceTable {
        if (entry.size > MAX_BYTES) unsupported()
        val bytes = try {
            zip.getInputStream(entry).use { it.readNBytes(MAX_BYTES + 1) }
        } catch (e: Exception) {
            throw ProtectException(ErrorCode.INPUT_FORMAT, "unreadable resource table")
        }
        if (bytes.size > MAX_BYTES) unsupported()
        return try {
            Resources.ResourceTable.parseFrom(bytes)
        } catch (e: OutOfMemoryError) {
            unsupported()
        } catch (e: Exception) {
            throw ProtectException(ErrorCode.INPUT_FORMAT, "unreadable resource table")
        }
    }

    /**
     * One package, id 0x7f, every type and entry with an id; the `xml` type (at most one) gets the first free entry id,
     * or a new `xml` type the first free type id. A name of ours already in the table (or its `_debug` companion, which
     * the platform reads as debug-overrides in a debuggable app) is refused.
     */
    fun slot(table: Resources.ResourceTable): Slot {
        if (table.packageCount != 1) unsupported()
        val pkg = table.getPackage(0)
        if (!pkg.hasPackageId() || pkg.packageId.id != APP_PACKAGE_ID) unsupported()
        if (pkg.typeList.any { !it.hasTypeId() || it.typeId.id !in 1..0xff }) unsupported()
        if (pkg.typeList.map { it.typeId.id }.toSet().size != pkg.typeCount) unsupported()
        val xml = pkg.typeList.withIndex().filter { it.value.name == "xml" }
        if (xml.size > 1) unsupported()
        val type = xml.singleOrNull() ?: run {
            val used = pkg.typeList.map { it.typeId.id }.toSet()
            return Slot(-1, (1..0xff).firstOrNull { it !in used } ?: unsupported(), 0)
        }
        val entries = type.value.entryList
        if (entries.any { !it.hasEntryId() || it.entryId.id !in 0..0xffff }) unsupported()
        if (entries.any { it.name == NetworkPinning.RESOURCE_NAME || it.name == NetworkPinning.RESOURCE_NAME + "_debug" }) unsupported()
        val used = entries.map { it.entryId.id }.toSet()
        return Slot(type.index, type.value.typeId.id, (0..0xffff).firstOrNull { it !in used } ?: unsupported())
    }

    /** The table with the new entry (and type), inserted in id order; nothing existing is renumbered or changed. */
    fun add(table: Resources.ResourceTable, slot: Slot): Resources.ResourceTable {
        val entry = Resources.Entry.newBuilder()
            .setEntryId(Resources.EntryId.newBuilder().setId(slot.entryId))
            .setName(NetworkPinning.RESOURCE_NAME)
            .setVisibility(Resources.Visibility.getDefaultInstance())
            .addConfigValue(Resources.ConfigValue.newBuilder().setConfig(com.android.aapt.ConfigurationOuterClass.Configuration.getDefaultInstance())
                .setValue(Resources.Value.newBuilder().setItem(Resources.Item.newBuilder().setFile(
                    Resources.FileReference.newBuilder().setPath(NetworkPinning.RESOURCE_PATH).setType(Resources.FileReference.Type.PROTO_XML)))))
            .build()
        val pkg = table.getPackage(0).toBuilder()
        if (slot.typeIndex < 0) {
            val type = Resources.Type.newBuilder().setTypeId(Resources.TypeId.newBuilder().setId(slot.typeId)).setName("xml").addEntry(entry)
            val at = pkg.typeList.indexOfFirst { it.typeId.id > slot.typeId }.let { if (it < 0) pkg.typeCount else it }
            pkg.addType(at, type)
        } else {
            val type = pkg.getType(slot.typeIndex).toBuilder()
            val at = type.entryList.indexOfFirst { it.entryId.id > slot.entryId }.let { if (it < 0) type.entryCount else it }
            type.addEntry(at, entry)
            pkg.setType(slot.typeIndex, type)
        }
        return table.toBuilder().setPackage(0, pkg).build()
    }
}

/** The generated `network_security_config` (aapt2 proto XML, the shape `aapt2 compile` gives) and the manifest edit. */
internal object NetworkSecurityConfigXml {
    private const val ATTR_NETWORK_SECURITY_CONFIG = 0x01010527

    private fun element(name: String, vararg attributes: Resources.XmlAttribute) =
        Resources.XmlElement.newBuilder().setName(name).addAllAttribute(attributes.toList())

    private fun plain(name: String, value: String) = Resources.XmlAttribute.newBuilder().setName(name).setValue(value).build()

    private fun bool(name: String, value: Boolean) = Resources.XmlAttribute.newBuilder().setName(name).setValue(value.toString())
        .setCompiledItem(Resources.Item.newBuilder().setPrim(Resources.Primitive.newBuilder().setBooleanValue(value))).build()

    private fun node(e: Resources.XmlElement.Builder) = Resources.XmlNode.newBuilder().setElement(e).build()

    private fun text(t: String) = Resources.XmlNode.newBuilder().setText(t).build()

    /**
     * Fixed order: `<base-config cleartextTrafficPermitted>` only when [cleartext] is the app's literal value; then per
     * domain `<domain-config cleartextTrafficPermitted="false">` with `<domain includeSubdomains>`, `<pin-set
     * expiration>` (pins, then backups, `digest="SHA-256"`, without the `sha256/` prefix) and system trust anchors.
     * No `<debug-overrides>`, `overridePins` or `src="user"`.
     */
    fun build(section: PinningSection, cleartext: Boolean?): Resources.XmlNode {
        val root = element("network-security-config")
        if (cleartext != null) root.addChild(node(element("base-config", bool("cleartextTrafficPermitted", cleartext))))
        for (d in section.domains) {
            val pinSet = element("pin-set", plain("expiration", section.expiration.toString()))
            for (pin in d.pins + d.backupPins)
                pinSet.addChild(node(element("pin", plain("digest", "SHA-256")).addChild(text(pin.removePrefix("sha256/")))))
            val config = element("domain-config", bool("cleartextTrafficPermitted", false))
                .addChild(node(element("domain", bool("includeSubdomains", d.includeSubdomains)).addChild(text(d.host))))
                .addChild(node(pinSet))
                .addChild(node(element("trust-anchors").addChild(node(element("certificates", plain("src", "system"))))))
            root.addChild(node(config))
        }
        return node(root)
    }

    /**
     * `<application>` gains `android:networkSecurityConfig` (a reference to [resourceId], as aapt2 links it), inserted
     * before the first android attribute with a higher resource id; with [hosts], also the meta-data of the pinned hosts
     * (comma-separated, profile order). An app that already declares either is refused.
     */
    fun manifest(root: Resources.XmlNode, resourceId: Int, hosts: List<String>?): Resources.XmlNode {
        val manifest = root.element
        val appIndex = manifest.childList.indexOfFirst { it.hasElement() && it.element.name == "application" && it.element.namespaceUri.isEmpty() }
        if (appIndex < 0) throw ProtectException(ErrorCode.APP_INCOMPATIBLE, "manifest without <application>")
        val application = manifest.getChild(appIndex).element
        if (application.attributeList.any { it.namespaceUri == AabInjector.ANDROID_NS &&
                (it.resourceId == ATTR_NETWORK_SECURITY_CONFIG || (it.resourceId == 0 && it.name == "networkSecurityConfig")) })
            throw ProtectException(ErrorCode.APP_INCOMPATIBLE, NetworkPinning.NSC_PRESENT)
        if (application.childList.any { c -> c.hasElement() && c.element.name == "meta-data" &&
                c.element.attributeList.any { it.resourceId == AabInjector.ATTR_NAME && it.value == NetworkPinning.HOSTS_META_DATA } })
            throw ProtectException(ErrorCode.APP_INCOMPATIBLE, NetworkPinning.NSC_PRESENT)
        val attribute = Resources.XmlAttribute.newBuilder().setNamespaceUri(AabInjector.ANDROID_NS).setName("networkSecurityConfig")
            .setValue("@xml/${NetworkPinning.RESOURCE_NAME}").setResourceId(ATTR_NETWORK_SECURITY_CONFIG)
            .setCompiledItem(Resources.Item.newBuilder().setRef(Resources.Reference.newBuilder().setId(resourceId)
                .setName("xml/${NetworkPinning.RESOURCE_NAME}").setTypeFlags(1)))
            .build()
        val at = application.attributeList.indexOfFirst { it.namespaceUri == AabInjector.ANDROID_NS && it.resourceId != 0 &&
            Integer.compareUnsigned(it.resourceId, ATTR_NETWORK_SECURITY_CONFIG) > 0 }.let { if (it < 0) application.attributeCount else it }
        val newApplication = application.toBuilder().addAttribute(at, attribute)
        if (hosts != null) newApplication.addChild(Resources.XmlNode.newBuilder().setElement(Resources.XmlElement.newBuilder().setName("meta-data")
            .addAttribute(AabInjector.text("name", AabInjector.ATTR_NAME, NetworkPinning.HOSTS_META_DATA))
            .addAttribute(AabInjector.text("value", AabInjector.ATTR_VALUE, hosts.joinToString(",")))))
        return root.toBuilder().setElement(manifest.toBuilder().setChild(appIndex,
            manifest.getChild(appIndex).toBuilder().setElement(newApplication))).build()
    }
}
