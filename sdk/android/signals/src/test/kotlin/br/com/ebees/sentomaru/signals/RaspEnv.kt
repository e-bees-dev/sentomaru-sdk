package br.com.ebees.sentomaru.signals

import android.content.Context
import br.com.ebees.sentomaru.signals.detectors.RootArtifactsDetector

/**
 * Double of the D-05 platform calls: a clean device by default. `failing` names calls that throw (the exception is
 * `failure`), and the per-item sets deny one path, package, class or setting.
 */
open class RaspEnv(
    var waitingForDebugger: Boolean = false,
    var fields: Map<String, String> = CLEAN_BUILD,
    var presentPaths: Set<String> = emptySet(),
    var deniedPaths: Set<String> = emptySet(),
    var settingsOn: Set<String> = emptySet(),
    var failingSettings: Set<String> = emptySet(),
    var visiblePackages: Set<String> = emptySet(),
    var failingPackages: Set<String> = emptySet(),
    var mountLines: List<String> = CLEAN_MOUNTS,
    var accelerometer: Boolean = true,
    // The signals-rasp marker is present by default (the app opted in to the <queries>).
    var loadableClasses: Set<String> = setOf(RootArtifactsDetector.QUERIES_MARKER),
    var failingClasses: Set<String> = emptySet(),
    var stackClasses: List<String> = CLEAN_STACK,
    var failing: Set<String> = emptySet(),
    var failure: () -> Throwable = { SecurityException("denied") },
) : DetectorsTest.FakeEnv() {
    private fun guard(call: String) {
        if (call in failing) throw failure()
    }

    override fun isDebuggerConnected(): Boolean = super.isDebuggerConnected().also { guard("isDebuggerConnected") }
    override fun isAppDebuggable(context: Context): Boolean =
        super.isAppDebuggable(context).also { guard("isAppDebuggable") }
    override fun isWaitingForDebugger(): Boolean = waitingForDebugger.also { guard("isWaitingForDebugger") }
    override fun buildFields(): Map<String, String> = fields.also { guard("buildFields") }
    override fun pathPresent(path: String): Boolean {
        guard("pathPresent")
        if (path in deniedPaths) throw failure()
        return path in presentPaths
    }
    override fun globalSettingOn(context: Context, name: String): Boolean {
        guard("globalSettingOn")
        if (name in failingSettings) throw failure()
        return name in settingsOn
    }
    override fun packageVisible(context: Context, packageName: String): Boolean {
        guard("packageVisible")
        if (packageName in failingPackages) throw failure()
        return packageName in visiblePackages
    }
    override fun mountInfoLines(): List<String> = mountLines.also { guard("mountInfoLines") }
    override fun hasDefaultSensor(context: Context, type: Int): Boolean = accelerometer.also { guard("hasDefaultSensor") }
    override fun classLoadable(context: Context, className: String): Boolean {
        guard("classLoadable")
        if (className in failingClasses) throw failure()
        return className in loadableClasses
    }
    override fun controlledStackTraceClassNames(): List<String> =
        stackClasses.also { guard("controlledStackTraceClassNames") }

    companion object {
        val CALLS = listOf(
            "isDebuggerConnected", "isWaitingForDebugger", "isAppDebuggable", "buildFields", "pathPresent",
            "globalSettingOn", "packageVisible", "mountInfoLines", "hasDefaultSensor", "classLoadable",
            "controlledStackTraceClassNames",
        )

        val CLEAN_BUILD = mapOf(
            "FINGERPRINT" to "samsung/a05mub/a05m:15/AP3A.240905.015.A2/A055MUBS6CYG1:user/release-keys",
            "MODEL" to "SM-T000Z",
            "MANUFACTURER" to "samsung",
            "BRAND" to "samsung",
            "DEVICE" to "a05m",
            "HARDWARE" to "mt6768",
            "PRODUCT" to "a05mub",
            "BOARD" to "a05m",
            "TAGS" to "release-keys",
            "TYPE" to "user",
        )

        val CLEAN_MOUNTS = listOf(
            "22 1 253:0 / / ro,relatime shared:1 - ext4 /dev/block/dm-0 ro,seclabel",
            "31 22 0:20 / /dev rw,nosuid,relatime shared:2 - tmpfs tmpfs rw,seclabel,mode=755",
            "48 22 259:12 / /data rw,nosuid,nodev,noatime shared:30 - f2fs /dev/block/by-name/userdata rw,seclabel",
        )

        val CLEAN_STACK = listOf(
            "br.com.ebees.sentomaru.signals.AndroidPlatformEnvironment",
            "br.com.ebees.sentomaru.signals.detectors.HookFrameworkJavaDetector",
            "java.util.concurrent.ThreadPoolExecutor\$Worker",
            "java.lang.Thread",
        )
    }
}
