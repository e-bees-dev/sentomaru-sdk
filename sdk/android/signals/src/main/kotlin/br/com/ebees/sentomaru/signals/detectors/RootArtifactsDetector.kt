package br.com.ebees.sentomaru.signals.detectors

import android.content.Context
import br.com.ebees.sentomaru.signals.*
import java.time.Clock

/**
 * D-05: root artifacts without spawning a process. Hidden root (Magisk with Zygisk and DenyList, KernelSU, APatch)
 * hides exactly these and is expected not to be detected.
 */
class RootArtifactsDetector(
    private val clock: Clock = Clock.systemUTC(),
    private val env: PlatformEnvironment = AndroidPlatformEnvironment,
) : SignalDetector {
    override val capabilityId = "root_artifacts"
    override val version = "1.0.0"
    override val budgetMs = 11L

    companion object {
        // Locations an app can stat. /data/local and /data/adb are left out: an app is denied there, so the check
        // would never run (always `partial`).
        val SU_PATHS = listOf(
            "/system/bin/su",
            "/system/xbin/su",
            "/sbin/su",
            "/system/sbin/su",
            "/vendor/bin/su",
            "/system/bin/failsafe/su",
            "/system/sd/xbin/su",
            "/su/bin/su",
        )

        val ROOT_MANAGER_PATHS = listOf(
            "/system/app/Superuser.apk",
            "/system/app/SuperSU",
            "/system/app/SuperSU.apk",
            "/system/xbin/daemonsu",
            "/system/etc/init.d/99SuperSUDaemon",
            "/sbin/magisk",
            "/sbin/.magisk",
        )

        /**
         * Marker class of the opt-in artifact `signals-rasp`, which carries the `<queries>` of
         * `SignalsCatalog.ROOT_MANAGER_PACKAGES`. Without it those packages are invisible to the app, so the package
         * check did not run (`partial=root_package`), never "not installed".
         */
        const val QUERIES_MARKER = "br.com.ebees.sentomaru.signals.rasp.RootManagerQueries"

        // Case-insensitive substrings of a mountinfo field, plus the exact KernelSU mount source.
        val MOUNT_MARKERS = listOf("magisk", "zygisk", "kernelsu", "apatch")
        const val KERNELSU_MOUNT_SOURCE = "KSU"
        private val MARKERS = Regex(MOUNT_MARKERS.joinToString("|") { Regex.escape(it) }, RegexOption.IGNORE_CASE)
        private val KERNELSU_FIELD = Regex("(?:^|[ \\t\\n])${Regex.escape(KERNELSU_MOUNT_SOURCE)}(?:[ \\t\\n]|$)")
    }

    override fun detect(context: Context): SignalObservation =
        Evidence.collect(capabilityId, version, clock.instant().toString()) { e ->
            e.anyOf("su_path", SU_PATHS) { env.pathPresent(it) }
            e.anyOf("manager_path", ROOT_MANAGER_PATHS) { env.pathPresent(it) }
            val build = e.probe("build_props") { env.buildFields() }
            if (build != null) {
                val tags = build["TAGS"]
                val type = build["TYPE"]
                if (tags == null) e.notRun("test_keys") else if (tags.contains("test-keys")) e.found("test_keys")
                if (type == null) e.notRun("build_type") else if (type != "user") e.found("build_type")
            }
            // The packages are visible only through the signals-rasp <queries>; without its marker the check did not run.
            when (e.probe("root_package") { env.classLoadable(context, QUERIES_MARKER) }) {
                true -> e.anyOf("root_package", SignalsCatalog.ROOT_MANAGER_PACKAGES) { env.packageVisible(context, it) }
                false -> e.notRun("root_package")
                null -> Unit // the lookup failed: already `partial`
            }
            val mounts = e.probe("mountinfo") { env.mountInfoLines() }
            if (mounts != null && hasRootMarker(mounts)) e.found("mountinfo")
        }

    // The whole file as one text and two regex searches: the markers case-insensitive (no marker holds a separator, so
    // a match is inside one field) and the KernelSU source as a whole, case-sensitive field. Line by line, field by field
    // with contains(ignoreCase) it cost ~28 ms warm and ~0.3 s cold on the SM-A055M (169 lines, D-05c). Same answer
    // except on Android for a dotted or dotless I (ICU folding: "magİsk" no longer matches); real mount names are ASCII.
    private fun hasRootMarker(lines: List<String>): Boolean {
        val text = lines.joinToString("\n")
        return MARKERS.containsMatchIn(text) || KERNELSU_FIELD.containsMatchIn(text)
    }
}
