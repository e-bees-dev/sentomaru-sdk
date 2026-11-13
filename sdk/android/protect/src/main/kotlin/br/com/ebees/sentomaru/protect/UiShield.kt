package br.com.ebees.sentomaru.protect

import com.android.aapt.Resources
import com.google.gson.JsonObject

/**
 * G-10 (`ui-shield`, HU-05 of the specialist review): the screens the app lists get `FLAG_SECURE`, a blank recents
 * thumbnail, hidden overlay windows (on request), touch filtering when obscured and accessibility-sensitive data, applied
 * by the injected runtime ([InitProvider] reads three provider meta-data values this control writes and
 * `UiShield` of `:protect-runtime` installs the activity-lifecycle shield). The DEX of the app is not rewritten: the
 * change is in the manifest only, so a screen is protected whether or not its class defines `onCreate`, and R8 or a
 * base class cannot hide it. `mode` is `listed_only` (default intent: only the listed activities, each declared in the
 * manifest) or `all_activities` (every screen; it can break a flow that needs a capture, so it is a warning). When
 * Limit (G10-1): the runtime acts on each listed Activity's own window only; a Dialog, DialogFragment, bottom sheet or
 * PopupWindow opens another window without these flags and stays capturable.
 * `hideOverlayWindows` is true the normal permission `HIDE_OVERLAY_WINDOWS` is declared if the app lacks it.
 * It reduces screen capture, overlay and accessibility reads on the screens it marks; it does NOT stop an external
 * camera, a hook, or a memory read, and it does not prove the app is safe.
 */
object UiShieldControl : Control {
    override val id = "ui-shield"
    override val version = "1"
    override val stage = "harden"
    override val order = 50
    override val prerequisites = listOf("runtime-injection")
    override val changeIds = listOf("manifest.meta-data.added", "manifest.permission.added")
    override val changesBinary = true

    const val MODE_LISTED_ONLY = "listed_only"
    const val MODE_ALL = "all_activities"
    const val MAX_ACTIVITIES = 64
    const val OVERLAY_PERMISSION = "android.permission.HIDE_OVERLAY_WINDOWS"
    /** The provider meta-data keys the runtime reads (`UiShield.java` of :protect-runtime; a test keeps them equal). */
    const val MODE_KEY = "br.com.ebees.sentomaru.runtime.UI_SHIELD_MODE"
    const val ACTIVITIES_KEY = "br.com.ebees.sentomaru.runtime.UI_SHIELD_ACTIVITIES"
    const val HIDE_OVERLAY_KEY = "br.com.ebees.sentomaru.runtime.UI_SHIELD_HIDE_OVERLAY"
    private val CLASS_NAME = Regex("""\A[A-Za-z_$][A-Za-z0-9_$]*(\.[A-Za-z_$][A-Za-z0-9_$]*)+\z""")

    private class Section(val all: Boolean, val activities: List<String>, val hideOverlay: Boolean)

    private fun read(section: JsonObject): Section {
        Controls.fields(section, setOf("version", "mode", "activities", "hideOverlayWindows"), id)
        val mode = Controls.text(section, "mode", id)
        if (mode != MODE_LISTED_ONLY && mode != MODE_ALL) throw ProtectException(ErrorCode.PROFILE_FORMAT, "$id.mode")
        val array = section.get("activities").takeIf { it.isJsonArray }?.asJsonArray ?: throw ProtectException(ErrorCode.PROFILE_FORMAT, "$id.activities")
        val names = array.map { if (it.isJsonPrimitive && it.asJsonPrimitive.isString) it.asString else null }
        if (names.any { it == null || it.length > 256 || !CLASS_NAME.matches(it) } || names.toSet().size != names.size || names.size > MAX_ACTIVITIES)
            throw ProtectException(ErrorCode.PROFILE_FORMAT, "$id.activities")
        if ((mode == MODE_LISTED_ONLY) == names.isEmpty()) throw ProtectException(ErrorCode.PROFILE_FORMAT, "$id.activities")
        val hide = section.get("hideOverlayWindows")
        if (hide == null || !hide.isJsonPrimitive || !hide.asJsonPrimitive.isBoolean) throw ProtectException(ErrorCode.PROFILE_FORMAT, "$id.hideOverlayWindows")
        return Section(mode == MODE_ALL, names.filterNotNull(), hide.asBoolean)
    }

    override fun validate(section: JsonObject, context: ControlContext) {
        read(section)
    }

    override fun plan(section: JsonObject, artifact: Artifact, context: ControlContext): ControlPlan {
        val s = read(section)
        if (!artifact.manifest.hasApplication) throw ProtectException(ErrorCode.APP_INCOMPATIBLE, "manifest without <application>")
        val declared = artifact.manifest.activities
        if (declared != null) {
            val missing = s.activities.filter { it !in declared }
            if (missing.isNotEmpty()) throw ProtectException(ErrorCode.APP_INCOMPATIBLE, "$id: activity not declared in the manifest: ${missing.first()}")
        }
        if (s.all) context.warn("ui-shield-all-activities",
            "every screen is protected: a flow that needs a capture (support, accessibility) stops working; list the screens instead")
        val changes = mutableListOf(Change("manifest.meta-data.added", "ui-shield"))
        if (s.hideOverlay && OVERLAY_PERMISSION !in artifact.manifest.permissions) changes += Change("manifest.permission.added", OVERLAY_PERMISSION)
        return ControlPlan(id, version, "planned", changes,
            evidence = mapOf("mode" to if (s.all) MODE_ALL else MODE_LISTED_ONLY, "activities" to s.activities.size.toString(),
                "hideOverlayWindows" to s.hideOverlay.toString(), "applies" to "activity-lifecycle"))
    }

    override val appliesToApk = true

    override fun applyApk(section: JsonObject, edit: ApkEdit, context: ControlContext): List<Change> {
        val s = read(section)
        return ApkInjector.uiShield(edit, s.all, s.activities, s.hideOverlay)
    }

    override fun apply(section: JsonObject, edit: AabEdit, context: ControlContext): List<Change> {
        val s = read(section)
        val (manifest, changes) = AabInjector.uiShield(edit.manifest, s.all, s.activities, s.hideOverlay)
        edit.manifest = manifest
        return changes
    }
}
