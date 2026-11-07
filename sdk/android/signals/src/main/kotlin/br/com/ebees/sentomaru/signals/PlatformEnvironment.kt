package br.com.ebees.sentomaru.signals

import android.content.Context
import android.content.pm.ApplicationInfo
import android.content.pm.PackageManager
import android.hardware.SensorManager
import android.hardware.display.DisplayManager
import android.view.Display
import android.view.InputDevice
import android.view.accessibility.AccessibilityManager
import android.accessibilityservice.AccessibilityServiceInfo
import android.os.Build
import android.os.Debug
import android.provider.Settings
import android.system.ErrnoException
import android.system.Os
import android.system.OsConstants
import java.io.File
import java.security.MessageDigest

/**
 * Abstraction over Android framework calls for testability, deterministic fixtures and isolation.
 */
interface PlatformEnvironment {
    fun isDebuggerConnected(): Boolean
    fun isAppDebuggable(context: Context): Boolean
    fun buildProperties(): Map<String, String>
    fun fileExists(path: String): Boolean
    fun getAppSigningCertificateDigests(context: Context): List<String>
    fun getInstallerPackageName(context: Context): String?
    fun osVersion(): Pair<Int, String>

    // D-05 (opt-in RASP detectors). Each call either answers or throws: a call that throws (access denied, read
    // failed, not provided by this environment) is a check that did not run, which the detector reports as UNKNOWN
    // with detail `partial`, never NOT_DETECTED. The defaults throw, so an environment written before the D-05 reports
    // the new capabilities as not measured. The six frozen detectors never call these.

    /** `Debug.waitingForDebugger()`. */
    fun isWaitingForDebugger(): Boolean = throw UnsupportedOperationException("not provided")

    /** Build values the D-05 detectors read (`buildProperties()` stays as the frozen detectors read it). */
    fun buildFields(): Map<String, String> = throw UnsupportedOperationException("not provided")

    /** true = present, false = absent (ENOENT/ENOTDIR); throws when the path could not be measured (e.g. EACCES). */
    fun pathPresent(path: String): Boolean = throw UnsupportedOperationException("not provided")

    /** `Settings.Global` integer setting is on; an absent setting is off, as the platform reads it. */
    fun globalSettingOn(context: Context, name: String): Boolean = throw UnsupportedOperationException("not provided")

    /** Package visible through the SDK manifest `<queries>`; false = not installed or not visible. */
    fun packageVisible(context: Context, packageName: String): Boolean =
        throw UnsupportedOperationException("not provided")

    /** Lines of `/proc/self/mountinfo`. */
    fun mountInfoLines(): List<String> = throw UnsupportedOperationException("not provided")

    /** The device reports a default sensor of this `Sensor.TYPE_*`. */
    fun hasDefaultSensor(context: Context, type: Int): Boolean = throw UnsupportedOperationException("not provided")

    /** Class loadable by the app class loader (not initialized); false = ClassNotFoundException. */
    fun classLoadable(context: Context, className: String): Boolean = throw UnsupportedOperationException("not provided")

    /** Class names in the stack trace of an exception created (never thrown) at the call. */
    fun controlledStackTraceClassNames(): List<String> = throw UnsupportedOperationException("not provided")

    // D-12c (opt-in app integrity detectors). Same rule as the D-05 calls: each one answers or throws, and the defaults
    // throw, so an environment written before the D-12c reports the new capabilities as not measured.

    /**
     * Lowercase hex SHA-256 of every signing certificate: `apkContentsSigners` when the APK has several signers, else
     * the whole `signingCertificateHistory` (rotation lineage). Throws when the signing info could not be read or is
     * empty (never an empty list: that would read as "nothing unexpected").
     */
    fun signingCertificateDigests(context: Context): List<String> = throw UnsupportedOperationException("not provided")

    /** `InstallSourceInfo` of the app (API 30+); throws below API 30 or when the lookup fails. */
    fun installSource(context: Context): InstallSource = throw UnsupportedOperationException("not provided")

    /** The installed APK files and `lastUpdateTime`; throws when a path is missing or not a file. */
    fun installedApks(context: Context): InstalledApks = throw UnsupportedOperationException("not provided")

    // D-24 (opt-in device threat detectors). Same rule: each call answers or throws, and the defaults throw. None of
    // these returns a name that leaves the detector: the detector reduces it to a fixed enum.

    /** Package names of the enabled accessibility services (`AccessibilityManager`); empty = none enabled. */
    fun enabledAccessibilityServicePackages(context: Context): List<String> =
        throw UnsupportedOperationException("not provided")

    /** Package of the default input method (`Settings.Secure.DEFAULT_INPUT_METHOD`); null = none set or unreadable value. */
    fun defaultInputMethodPackage(context: Context): String? = throw UnsupportedOperationException("not provided")

    /** Number of virtual input devices with a touch or pointer source (`InputDevice.isVirtual`). */
    fun virtualPointerDeviceCount(): Int = throw UnsupportedOperationException("not provided")

    /** D-20: the displays visible to this app, reduced to the two facts the detector needs (no name, no id). */
    fun visibleDisplays(context: Context): List<DisplayFacts> = throw UnsupportedOperationException("not provided")

    /** D-20 (API 35): the platform reported a screen recording that shows this app's windows; throws when never reported. */
    fun screenRecordingVisible(): Boolean = throw UnsupportedOperationException("not provided")

    /** D-24d: package names of the installed apps visible to this app (limited by the manifest `<queries>`). */
    fun visiblePackageNames(context: Context): Collection<String> = throw UnsupportedOperationException("not provided")

    /** D-24d: lowercase hex SHA-256 of each signing certificate of [packageName] (the whole signer history is not read). */
    fun signingCertSha256(context: Context, packageName: String): Set<String> =
        throw UnsupportedOperationException("not provided")

    // F-07/F-08 (opt-in session context detectors). Same rule: each call answers or throws, and the defaults throw.

    /** F-07: the origin flag of the newest last known location, when the app already holds a location permission. */
    fun lastKnownLocation(context: Context): LocationFacts = throw UnsupportedOperationException("not provided")

    /** F-08: `AudioManager.getMode()`; throws when the service is unavailable. */
    fun audioMode(context: Context): Int = throw UnsupportedOperationException("not provided")
}

/**
 * F-07: what the last known location says about its own origin, nothing else. [permission] = the app already holds a
 * location permission (the SDK never asks); [fixAgeMs] = age of the newest fix, null when there is none; [mock] = the
 * platform's mock-provider flag of that fix, null when it could not be read. No coordinate, provider, accuracy or time.
 */
data class LocationFacts(val permission: Boolean, val fixAgeMs: Long?, val mock: Boolean?)

/**
 * F-07 (review A, F07-1): which location providers the SDK reads and how a refusal is treated. `gps` needs the fine
 * permission and throws SecurityException without it, so it is not asked with only the coarse one; a provider that still
 * refuses or does not exist is skipped without discarding the fixes of the others.
 */
internal object LocationProviders {
    fun forPermission(fine: Boolean): List<String> = if (fine) listOf("passive", "gps", "network") else listOf("passive", "network")

    fun <T : Any> readEach(providers: List<String>, read: (String) -> T?): List<T> = providers.mapNotNull {
        try { read(it) } catch (e: SecurityException) { null } catch (e: IllegalArgumentException) { null }
    }
}

/** D-20: one visible display, as much as the detector may know of it. */
data class DisplayFacts(val isDefault: Boolean, val presentation: Boolean)

object AndroidPlatformEnvironment : PlatformEnvironment {
    override fun isDebuggerConnected(): Boolean = Debug.isDebuggerConnected()

    override fun isAppDebuggable(context: Context): Boolean =
        (context.applicationInfo.flags and ApplicationInfo.FLAG_DEBUGGABLE) != 0

    override fun buildProperties(): Map<String, String> = mapOf(
        "FINGERPRINT" to Build.FINGERPRINT,
        "MODEL" to Build.MODEL,
        "MANUFACTURER" to Build.MANUFACTURER,
        "HARDWARE" to Build.HARDWARE,
        "PRODUCT" to Build.PRODUCT,
        "BOARD" to Build.BOARD,
        "TAGS" to (Build.TAGS ?: "")
    )

    // Exceptions propagate: the detector reports ERROR. An unreadable path is not measured, so it must never
    // become "not found" (NOT_DETECTED).
    override fun fileExists(path: String): Boolean = File(path).exists()

    override fun getAppSigningCertificateDigests(context: Context): List<String> = try {
        val pm = context.packageManager
        val packageName = context.packageName
        val info = if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.P) {
            pm.getPackageInfo(packageName, PackageManager.GET_SIGNING_CERTIFICATES)
        } else {
            @Suppress("DEPRECATION")
            pm.getPackageInfo(packageName, PackageManager.GET_SIGNATURES)
        }
        val signatures = if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.P) {
            val signingInfo = info.signingInfo
            if (signingInfo != null) {
                if (signingInfo.hasMultipleSigners()) {
                    signingInfo.apkContentsSigners
                } else {
                    signingInfo.signingCertificateHistory
                }
            } else emptyArray()
        } else {
            @Suppress("DEPRECATION")
            info.signatures ?: emptyArray()
        }

        signatures.map { sig ->
            val md = MessageDigest.getInstance("SHA-256")
            val digest = md.digest(sig.toByteArray())
            digest.joinToString("") { "%02x".format(it) }
        }
    } catch (_: Exception) {
        emptyList()
    }

    // null means "no installer recorded" (sideload/adb); a failed lookup throws and the detector reports ERROR.
    override fun getInstallerPackageName(context: Context): String? {
        val pm = context.packageManager
        val packageName = context.packageName
        return if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.R) {
            pm.getInstallSourceInfo(packageName).installingPackageName
        } else {
            @Suppress("DEPRECATION")
            pm.getInstallerPackageName(packageName)
        }
    }

    override fun osVersion(): Pair<Int, String> =
        Pair(Build.VERSION.SDK_INT, Build.VERSION.RELEASE)

    override fun isWaitingForDebugger(): Boolean = Debug.waitingForDebugger()

    override fun buildFields(): Map<String, String> = mapOf(
        "FINGERPRINT" to Build.FINGERPRINT,
        "MODEL" to Build.MODEL,
        "MANUFACTURER" to Build.MANUFACTURER,
        "BRAND" to Build.BRAND,
        "DEVICE" to Build.DEVICE,
        "HARDWARE" to Build.HARDWARE,
        "PRODUCT" to Build.PRODUCT,
        "BOARD" to Build.BOARD,
        "TAGS" to (Build.TAGS ?: ""),
        "TYPE" to Build.TYPE,
    )

    // Os.stat, not File.exists(): exists() answers false when SELinux denies the lookup, which would turn an
    // unmeasured path into "absent".
    override fun pathPresent(path: String): Boolean = try {
        Os.stat(path)
        true
    } catch (e: ErrnoException) {
        if (e.errno == OsConstants.ENOENT || e.errno == OsConstants.ENOTDIR) false else throw e
    }

    override fun globalSettingOn(context: Context, name: String): Boolean =
        Settings.Global.getInt(context.contentResolver, name, 0) != 0

    override fun packageVisible(context: Context, packageName: String): Boolean = try {
        val pm = context.packageManager
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.TIRAMISU) {
            pm.getPackageInfo(packageName, PackageManager.PackageInfoFlags.of(0))
        } else {
            @Suppress("DEPRECATION")
            pm.getPackageInfo(packageName, 0)
        }
        true
    } catch (_: PackageManager.NameNotFoundException) {
        false
    }

    override fun mountInfoLines(): List<String> = File("/proc/self/mountinfo").readLines()

    override fun hasDefaultSensor(context: Context, type: Int): Boolean {
        val sensors = context.getSystemService(SensorManager::class.java)
            ?: throw IllegalStateException("SensorManager unavailable")
        return sensors.getDefaultSensor(type) != null
    }

    // A linkage failure (verifier, static init) is not "absent": it propagates as a check that did not run.
    override fun classLoadable(context: Context, className: String): Boolean = try {
        Class.forName(className, false, context.classLoader)
        true
    } catch (_: ClassNotFoundException) {
        false
    } catch (e: LinkageError) {
        throw IllegalStateException("class probe failed", e)
    }

    override fun controlledStackTraceClassNames(): List<String> =
        Exception("sentomaru stack probe").stackTrace.map { it.className }

    // Exceptions propagate (unlike getAppSigningCertificateDigests, frozen with its catch-all): a failed read is UNKNOWN.
    override fun signingCertificateDigests(context: Context): List<String> {
        val info = context.packageManager.getPackageInfo(context.packageName, PackageManager.GET_SIGNING_CERTIFICATES)
        val signing = info.signingInfo ?: throw IllegalStateException("no signing info")
        val signatures = (if (signing.hasMultipleSigners()) signing.apkContentsSigners else signing.signingCertificateHistory)
            ?: throw IllegalStateException("no signers")
        if (signatures.isEmpty()) throw IllegalStateException("no signers")
        return signatures.map { sig ->
            MessageDigest.getInstance("SHA-256").digest(sig.toByteArray()).joinToString("") { "%02x".format(it) }
        }
    }

    override fun installSource(context: Context): InstallSource {
        if (Build.VERSION.SDK_INT < Build.VERSION_CODES.R) throw UnsupportedOperationException("InstallSourceInfo is API 30+")
        val info = context.packageManager.getInstallSourceInfo(context.packageName)
        return InstallSource(info.installingPackageName, info.initiatingPackageName)
    }

    @Suppress("DEPRECATION") // getPackageInfo(String, Int): the PackageInfoFlags overload is API 33+
    override fun installedApks(context: Context): InstalledApks {
        val app = context.applicationInfo
        val paths = listOf(app.sourceDir ?: throw IllegalStateException("no sourceDir")) + (app.splitSourceDirs?.toList() ?: emptyList())
        val files = paths.map { path ->
            val file = File(path)
            if (!file.isFile) throw IllegalStateException("installed APK not readable")
            ApkFile(path, file.length())
        }
        val updated = context.packageManager.getPackageInfo(context.packageName, 0).lastUpdateTime
        return InstalledApks(updated, files)
    }

    override fun enabledAccessibilityServicePackages(context: Context): List<String> {
        val manager = context.getSystemService(AccessibilityManager::class.java)
            ?: throw IllegalStateException("AccessibilityManager unavailable")
        return manager.getEnabledAccessibilityServiceList(AccessibilityServiceInfo.FEEDBACK_ALL_MASK)
            .mapNotNull { it.resolveInfo?.serviceInfo?.packageName }
    }

    override fun defaultInputMethodPackage(context: Context): String? {
        val value = Settings.Secure.getString(context.contentResolver, Settings.Secure.DEFAULT_INPUT_METHOD)
        if (value.isNullOrEmpty()) return null
        return value.substringBefore('/').takeIf { it.isNotEmpty() }
    }

    @Suppress("DEPRECATION") // the int-flag overloads are the only ones below API 33 (minSdk 28)
    override fun visiblePackageNames(context: Context): Collection<String> {
        val pm = context.packageManager
        val apps = if (Build.VERSION.SDK_INT >= 33) pm.getInstalledApplications(PackageManager.ApplicationInfoFlags.of(0L))
        else pm.getInstalledApplications(0)
        return apps.map { it.packageName }
    }

    @Suppress("DEPRECATION")
    override fun signingCertSha256(context: Context, packageName: String): Set<String> {
        val pm = context.packageManager
        val info = if (Build.VERSION.SDK_INT >= 33) {
            pm.getPackageInfo(packageName, PackageManager.PackageInfoFlags.of(PackageManager.GET_SIGNING_CERTIFICATES.toLong()))
        } else {
            pm.getPackageInfo(packageName, PackageManager.GET_SIGNING_CERTIFICATES)
        }
        val signers = info.signingInfo ?: throw IllegalStateException("no signing info")
        val certs = if (signers.hasMultipleSigners()) signers.apkContentsSigners else signers.signingCertificateHistory.take(1).toTypedArray()
        val sha = java.security.MessageDigest.getInstance("SHA-256")
        return certs.mapTo(HashSet()) { c -> sha.digest(c.toByteArray()).joinToString("") { "%02x".format(it) } }
    }

    override fun visibleDisplays(context: Context): List<DisplayFacts> {
        val manager = context.getSystemService(DisplayManager::class.java)
            ?: throw IllegalStateException("DisplayManager unavailable")
        return manager.displays.map {
            DisplayFacts(it.displayId == Display.DEFAULT_DISPLAY, (it.flags and Display.FLAG_PRESENTATION) != 0)
        }
    }

    override fun screenRecordingVisible(): Boolean =
        ScreenCaptureMonitor.shared.recordingVisible ?: throw IllegalStateException("recording state not reported")

    private val pointerSources = InputDevice.SOURCE_TOUCHSCREEN or InputDevice.SOURCE_MOUSE or InputDevice.SOURCE_STYLUS or
        InputDevice.SOURCE_TOUCHPAD

    @Suppress("DEPRECATION") // isVirtual is the only platform answer for "not backed by hardware"
    override fun virtualPointerDeviceCount(): Int = InputDevice.getDeviceIds().count { id ->
        val device = InputDevice.getDevice(id) ?: return@count false
        device.isVirtual && (device.sources and pointerSources) != 0
    }

    // F-07: never requests a permission and never starts a location request; getLastKnownLocation only reads the cache.
    @Suppress("DEPRECATION", "MissingPermission") // isFromMockProvider below API 31; the permission is checked just before
    override fun lastKnownLocation(context: Context): LocationFacts {
        val fine = context.checkSelfPermission(android.Manifest.permission.ACCESS_FINE_LOCATION) == PackageManager.PERMISSION_GRANTED
        val held = fine || context.checkSelfPermission(android.Manifest.permission.ACCESS_COARSE_LOCATION) == PackageManager.PERMISSION_GRANTED
        if (!held) return LocationFacts(permission = false, fixAgeMs = null, mock = null)
        val manager = context.getSystemService(Context.LOCATION_SERVICE) as? android.location.LocationManager
            ?: throw IllegalStateException("location service unavailable")
        val now = android.os.SystemClock.elapsedRealtimeNanos()
        val newest = LocationProviders.readEach(LocationProviders.forPermission(fine)) { manager.getLastKnownLocation(it) }
            .maxByOrNull { it.elapsedRealtimeNanos }
        val fix = newest ?: return LocationFacts(permission = true, fixAgeMs = null, mock = null)
        val age = maxOf(0L, (now - fix.elapsedRealtimeNanos) / 1_000_000L)
        val mock = if (Build.VERSION.SDK_INT >= 31) fix.isMock else fix.isFromMockProvider
        return LocationFacts(permission = true, fixAgeMs = age, mock = mock)
    }

    override fun audioMode(context: Context): Int =
        (context.getSystemService(Context.AUDIO_SERVICE) as? android.media.AudioManager)?.mode
            ?: throw IllegalStateException("audio service unavailable")
}
