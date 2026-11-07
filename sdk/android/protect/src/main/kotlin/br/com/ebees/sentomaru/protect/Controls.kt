package br.com.ebees.sentomaru.protect

import com.google.gson.JsonObject
import java.time.LocalDate

/** A planned change to the binary: [id] from the control's closed vocabulary, [target] a name (never app content). */
data class Change(val id: String, val target: String)

data class ControlPlan(val id: String, val version: String, val status: String, val changes: List<Change>,
    val notInstrumentable: List<Map<String, String>> = emptyList(), val evidence: Map<String, String> = emptyMap())

/**
 * What a control may look at besides its own section (D-07b): the UTC date of the run (the expiration rule), whether
 * the laboratory gate is on, the other sections of the profile (`network-pinning` warns about hosts that
 * `network-signing` does not sign) and the report's warnings.
 */
class ControlContext(val today: LocalDate, val lab: Boolean = false, val sections: List<ControlSection> = emptyList(),
    val warn: (String, String) -> Unit = { _, _ -> })

/**
 * A pluggable control (contract "Controles"): id, version, stage and order, prerequisites, the closed vocabulary of
 * changes and how it validates its profile section. [plan] runs in the dry-run and before a real run; a control that
 * changes the binary ([changesBinary]) also has an [apply] step on the bundle being edited (D-07b: one edit, one
 * write and one validation for every control, in stage order).
 */
interface Control {
    val id: String
    val version: String
    val stage: String
    val order: Int
    val prerequisites: List<String>
    val changeIds: List<String>
    val changesBinary: Boolean get() = false

    /** Validates the closed profile section (`profile-format`); no artifact is needed. */
    fun validate(section: JsonObject, context: ControlContext)

    /** Checks the app against the validated section (`permission-missing`, `app-incompatible`) and plans the changes. */
    fun plan(section: JsonObject, artifact: Artifact, context: ControlContext): ControlPlan

    /** Applies the validated and planned section to the bundle being edited; returns the changes made. */
    fun apply(section: JsonObject, edit: AabEdit, context: ControlContext): List<Change> =
        throw ProtectException(ErrorCode.INTERNAL, "$id changes nothing in the binary")
}

object Controls {
    /** Stage order of the contract; controls of later waves are not registered here (they answer control-not-available). */
    private val STAGES = listOf("inject", "instrument", "harden")

    /**
     * The controls of the distributed CLI (`controls --json`), in stage order. D-08f: `build-obfuscation` (read-only check, measured in
     * D-08e) joined it; it never changes the binary and never fails for a missing obfuscation (D-08x5). D-07f:
     * `network-pinning` joined it after the device and emulator proof (D-07e/C-03b).
     * Its behaviour does not depend on [ControlContext.lab] (only on the date, the other sections and the warnings), so
     * the D-16 rule (a control whose behaviour depends on `context.lab` waits for D-16-lab-gate) does not hold it back.
     * D-14e: `asset-encryption` (harden/20) joined it after the device, adversarial and emulator proof of D-14d
     * (device-and-emulator proof recorded as done) and its review R. It does read
     * [ControlContext.lab] (the per-file limit, [AssetEncryption.maxFileBytes]: 1 MiB, the format ceiling of 4 MiB only
     * with the gate); D-16-lab-gate already closed, so a registered run refuses SENTOMARU_LAB=1 (`lab-gate-registered`)
     * and only the dry run and the lab run ever see the gate (the vendor's check cli pipeline docs check, LAB_READ_AFTER_D16).
     * G-10c: `ui-shield` (harden/50) joined it after the device proof (the vendor's run g10c device gate check); it only edits the manifest and does
     * not read [ControlContext.lab]. It ships with build 0.6.0 (cli-v0.6.0 still to be published).
     */
    val all: List<Control> = listOf(RuntimeInjection, NetworkSigning, BuildObfuscation, AssetEncryption, NetworkPinning, UiShieldControl)

    /**
     * Controls behind the laboratory gate (`SENTOMARU_LAB=1`, not contractual): known only with the gate on, never
     * listed by `controls`. Empty since D-14e, and again since G-10c. `network-pinning` was here from D-07b until its release in D-07f,
     * `asset-encryption` from D-14c until its release in D-14e, and `ui-shield` from G-10a until its release in G-10c (build 0.6.0).
     */
    val laboratory: List<Control> = listOf()

    /** Controls that only read the app (`checked`, nothing applied): a registered run keeps their plan. */
    val checkOnly: Set<Control> = setOf(NetworkSigning, BuildObfuscation)

    fun byId(id: String, lab: Boolean = false): Control? = (if (lab) all + laboratory else all).firstOrNull { it.id == id }

    /** Full profile validation: sections to controls in application order, or a refusal with a stable code. */
    fun resolve(profile: Profile, context: ControlContext): List<Pair<Control, ControlSection>> {
        val resolved = profile.controls.map { section ->
            val control = byId(section.id, context.lab) ?: throw ProtectException(ErrorCode.CONTROL_NOT_AVAILABLE, section.id)
            if (control.version != section.version)
                throw ProtectException(ErrorCode.CONTROL_VERSION_UNSUPPORTED, "${section.id} ${section.version}")
            control.validate(section.fields, context)
            control to section
        }
        val ids = resolved.map { it.first.id }.toSet()
        for ((control, _) in resolved) for (needed in control.prerequisites)
            if (needed !in ids) throw ProtectException(ErrorCode.CONTROL_PREREQUISITE, "${control.id} needs $needed")
        return resolved.sortedWith(compareBy({ STAGES.indexOf(it.first.stage) }, { it.first.order }))
    }

    internal fun fields(section: JsonObject, allowed: Set<String>, control: String) {
        val unknown = section.keySet() - allowed
        if (unknown.isNotEmpty()) throw ProtectException(ErrorCode.PROFILE_FORMAT, "$control: unknown field ${unknown.sorted().first()}")
        val missing = allowed - section.keySet()
        if (missing.isNotEmpty()) throw ProtectException(ErrorCode.PROFILE_FORMAT, "$control: missing field ${missing.sorted().first()}")
    }

    internal fun text(section: JsonObject, name: String, control: String): String {
        val e = section.get(name)
        if (e == null || !e.isJsonPrimitive || !e.asJsonPrimitive.isString) throw ProtectException(ErrorCode.PROFILE_FORMAT, "$control.$name")
        return e.asString
    }
}

/** G-03b: the runtime (SDK DEX + init ContentProvider). Its network use needs INTERNET, which the app must declare. */
object RuntimeInjection : Control {
    override val id = "runtime-injection"
    override val version = "1"
    override val stage = "inject"
    override val order = 10
    override val prerequisites = emptyList<String>()
    override val changeIds = listOf("dex.added", "manifest.provider.added")
    const val PROVIDER = "br.com.ebees.sentomaru.runtime.InitProvider"
    /** Same limit as the runtime's Bootstrap.MAX_URL_LENGTH: a URL the runtime would refuse is refused here. */
    const val MAX_URL_LENGTH = 2048

    /** https, a host, no user info, at most [MAX_URL_LENGTH], no space or control character (the runtime's rule). */
    fun httpsUrl(url: String): Boolean {
        if (url.isEmpty() || url.length > MAX_URL_LENGTH || url.any { it <= ' ' || it == '\u007f' || Character.isISOControl(it) }) return false
        val uri = runCatching { java.net.URI(url) }.getOrNull() ?: return false
        return uri.scheme == "https" && !uri.host.isNullOrEmpty() && uri.rawUserInfo == null
    }
    val REQUIRED_PERMISSIONS = setOf("android.permission.INTERNET")

    override val changesBinary = true

    override fun validate(section: JsonObject, context: ControlContext) {
        Controls.fields(section, setOf("version", "enrollmentUrl"), id)
        if (!httpsUrl(Controls.text(section, "enrollmentUrl", id)))
            throw ProtectException(ErrorCode.PROFILE_FORMAT, "$id.enrollmentUrl must be an https URL with a host")
    }

    override fun plan(section: JsonObject, artifact: Artifact, context: ControlContext): ControlPlan {
        val missing = REQUIRED_PERMISSIONS - artifact.manifest.permissions
        if (missing.isNotEmpty()) throw ProtectException(ErrorCode.PERMISSION_MISSING, missing.sorted().joinToString(","))
        if (!artifact.manifest.hasApplication) throw ProtectException(ErrorCode.APP_INCOMPATIBLE, "manifest without <application>")
        // G-06: the same refusal as the real run (AabInjector.provider), so --dry-run never plans over a protected input.
        if (artifact.manifest.declaresSentomaruProvider)
            throw ProtectException(ErrorCode.APP_INCOMPATIBLE, "the app already declares the Sentomaru provider")
        val dexTarget = if (artifact.kind == ArtifactKind.AAB) "base/dex/" else "classesN.dex"
        return ControlPlan(id, version, "planned", listOf(Change("dex.added", dexTarget), Change("manifest.provider.added", PROVIDER)))
    }

    override fun apply(section: JsonObject, edit: AabEdit, context: ControlContext): List<Change> =
        AabInjector.injectRuntime(edit, Controls.text(section, "enrollmentUrl", id))
}

/**
 * G-03c (vendor decision 16/10/2026): network signing is the SDK's RFC 9421 transport, installed by the app in one line
 * with the profile's hosts and routes (Android `OkHttpClient.Builder.addSentomaru(client, routes)`, Flutter
 * `dio.addSentomaru(client, routes: ...)`; S2: Android `SentomaruUrlConnection.send(client, routes, ...)` for
 * HttpURLConnection). The CLI changes nothing in the binary for the network: it checks, read-only, that the base DEX
 * **defines** an SDK transport class or the plugin class, and refuses (`app-incompatible`) when it does not. That proves
 * the SDK or the plugin is **linked**, not that the table is in use: the SDK's consumer rules keep `SentomaruRoutes` in
 * any app with the SDK (the kept transport functions reference it), and the generated plugin registrant always
 * references the plugin. `SentomaruUrlConnection` keeps only its name (`-keepnames`): in a minified app it is there only
 * when the app calls it; without R8 it is there whenever the SDK is linked. Whether the app calls the install line, and
 * with which routes, is not visible in the binary; the server is what refuses an unsigned protected call. Status `checked` (never `applied`:
 * nothing is applied), in `--dry-run` too, since the check is the whole control.
 */
object NetworkSigning : Control {
    override val id = "network-signing"
    override val version = "1"
    override val stage = "instrument"
    override val order = 10
    override val prerequisites = listOf("runtime-injection")
    override val changeIds = emptyList<String>()
    /** Name kept by the SDK's consumer rules (`-keepnames`); present in any app linking the SDK, used or not. */
    const val ANDROID_TRANSPORT = "Lbr/com/ebees/sentomaru/sdk/transport/SentomaruRoutes;"
    /** S2: the SDK's HttpURLConnection transport, name kept by the SDK's consumer rules (`-keepnames`). */
    const val ANDROID_URLCONNECTION_TRANSPORT = "Lbr/com/ebees/sentomaru/sdk/transport/SentomaruUrlConnection;"
    /** The sentomaru_flutter plugin's Android entry point, name kept by the plugin's consumer rules (the Dart install
     *  line itself is not visible in the DEX). */
    const val FLUTTER_TRANSPORT = "Lbr/com/ebees/sentomaru/sentomaru_flutter/SentomaruFlutterPlugin;"
    private val HOST = Regex("""\A[a-z0-9.-]{1,253}\z""")
    private val OPERATION = Regex("""\A[a-z0-9_]{1,64}\z""")

    override fun validate(section: JsonObject, context: ControlContext) {
        Controls.fields(section, setOf("version", "hosts", "routes"), id)
        val hosts = section.get("hosts").takeIf { it.isJsonArray }?.asJsonArray ?: throw ProtectException(ErrorCode.PROFILE_FORMAT, "$id.hosts")
        val names = hosts.map { if (it.isJsonPrimitive && it.asJsonPrimitive.isString) it.asString else null }
        if (names.isEmpty() || names.any { it == null || !HOST.matches(it) } || names.toSet().size != names.size)
            throw ProtectException(ErrorCode.PROFILE_FORMAT, "$id.hosts")
        val routes = section.get("routes").takeIf { it.isJsonArray }?.asJsonArray ?: throw ProtectException(ErrorCode.PROFILE_FORMAT, "$id.routes")
        if (routes.size() == 0) throw ProtectException(ErrorCode.PROFILE_FORMAT, "$id.routes")
        for (route in routes) {
            val r = route.takeIf { it.isJsonObject }?.asJsonObject ?: throw ProtectException(ErrorCode.PROFILE_FORMAT, "$id.routes")
            Controls.fields(r, setOf("path", "operation"), "$id.routes")
            if (!Controls.text(r, "path", id).startsWith("/") || !OPERATION.matches(Controls.text(r, "operation", id)))
                throw ProtectException(ErrorCode.PROFILE_FORMAT, "$id.routes")
        }
    }

    override fun plan(section: JsonObject, artifact: Artifact, context: ControlContext): ControlPlan {
        val file = artifact.file ?: throw ProtectException(ErrorCode.INTERNAL, "$id: artifact without its file")
        val found = DexScan.present(file, artifact.kind, setOf(ANDROID_TRANSPORT, ANDROID_URLCONNECTION_TRANSPORT, FLUTTER_TRANSPORT))
        val transports = listOfNotNull("android-sdk".takeIf { ANDROID_TRANSPORT in found },
            "android-sdk-urlconnection".takeIf { ANDROID_URLCONNECTION_TRANSPORT in found },
            "flutter-plugin".takeIf { FLUTTER_TRANSPORT in found })
        if (transports.isEmpty()) throw ProtectException(ErrorCode.APP_INCOMPATIBLE,
            "$id: the app does not embed the Sentomaru signing transport (SDK addSentomaru with SentomaruRoutes, SDK SentomaruUrlConnection, or the sentomaru_flutter plugin)")
        return ControlPlan(id, version, "checked", emptyList(),
            evidence = mapOf("transport" to transports.joinToString(","), "check" to "dex-class-defined"))
    }
}
