package br.com.ebees.sentomaru.signals

import android.content.Context
import android.provider.Settings
import br.com.ebees.sentomaru.signals.detectors.*
import org.junit.Assert.*
import org.junit.Test
import java.time.Clock
import java.time.Instant
import java.time.ZoneOffset

/** D-05b: each indicator and each failure of the six RASP detectors, with doubles of `PlatformEnvironment`. */
class RaspDetectorsTest {
    private val clock = Clock.fixed(Instant.parse("2026-10-21T10:00:00Z"), ZoneOffset.UTC)
    private val dummyContext: Context = object : android.content.ContextWrapper(null) {}

    private fun detectors(env: PlatformEnvironment) = SignalsCollector.raspDetectors(clock, env)

    private fun observe(id: String, env: PlatformEnvironment): SignalObservation =
        detectors(env).single { it.capabilityId == id }.detect(dummyContext)

    private fun assertState(
        obs: SignalObservation,
        state: SignalState,
        indicators: String = "none",
        partial: String? = null,
    ) {
        assertEquals(obs.capabilityId, state, obs.state)
        assertEquals(obs.capabilityId, indicators, obs.detail["indicators"])
        assertEquals(obs.capabilityId, partial, obs.detail["partial"])
        assertEquals("client_observed", obs.source)
        assertEquals("1.0.0", obs.version)
        assertEquals("2026-10-21T10:00:00Z", obs.observedAt)
    }

    @Test
    fun cleanDoubleIsNotDetectedEverywhereWithTheCatalogFixtureDetail() {
        for (obs in detectors(RaspEnv()).map { it.detect(dummyContext) }) {
            assertState(obs, SignalState.NOT_DETECTED)
            assertEquals(mapOf("indicators" to "none"), obs.detail)
        }
        assertEquals(SignalsCatalog.RASP_CAPABILITY_IDS, detectors(RaspEnv()).map { it.capabilityId })
    }

    @Test
    fun debuggerAttachedReadsOnlyJdwp() {
        assertState(observe("debugger_attached", RaspEnv().apply { debuggerConnected = true }), SignalState.DETECTED, "jdwp_connected")
        assertState(observe("debugger_attached", RaspEnv(waitingForDebugger = true)), SignalState.DETECTED, "jdwp_waiting")
        // FLAG_DEBUGGABLE is app_debuggable, never debugger_attached.
        assertState(observe("debugger_attached", RaspEnv().apply { appDebuggable = true }), SignalState.NOT_DETECTED)
        assertState(observe("debugger_attached", RaspEnv(failing = setOf("isWaitingForDebugger"))), SignalState.UNKNOWN, partial = "jdwp_waiting")
        assertState(observe("debugger_attached", RaspEnv(failing = setOf("isDebuggerConnected"))), SignalState.UNKNOWN, partial = "jdwp_connected")
        // One call true is enough even when the other failed.
        assertState(
            observe("debugger_attached", RaspEnv(waitingForDebugger = true, failing = setOf("isDebuggerConnected"))),
            SignalState.DETECTED, "jdwp_waiting", "jdwp_connected",
        )
    }

    @Test
    fun appDebuggableReadsTheFlag() {
        assertState(observe("app_debuggable", RaspEnv().apply { appDebuggable = true }), SignalState.DETECTED, "flag_debuggable")
        assertState(observe("app_debuggable", RaspEnv(failing = setOf("isAppDebuggable"))), SignalState.UNKNOWN, partial = "flag_debuggable")
        assertState(observe("app_debuggable", RaspEnv().apply { debuggerConnected = true }), SignalState.NOT_DETECTED)
    }

    @Test
    fun devSettingsReadsAdbAndDeveloperOptions() {
        assertState(observe("dev_settings_enabled", RaspEnv(settingsOn = setOf(Settings.Global.ADB_ENABLED))), SignalState.DETECTED, "adb_enabled")
        assertState(
            observe("dev_settings_enabled", RaspEnv(settingsOn = setOf(Settings.Global.DEVELOPMENT_SETTINGS_ENABLED))),
            SignalState.DETECTED, "development_settings",
        )
        assertState(
            observe("dev_settings_enabled", RaspEnv(failingSettings = setOf(Settings.Global.ADB_ENABLED))),
            SignalState.UNKNOWN, partial = "adb_enabled",
        )
        assertState(
            observe("dev_settings_enabled", RaspEnv(failing = setOf("globalSettingOn"))),
            SignalState.UNKNOWN, partial = "adb_enabled,development_settings",
        )
    }

    @Test
    fun devSettingsDeveloperOptionsFailureAloneIsPartial() {
        // D-05d: the developer-options read failing alone, with adb measured and off, is UNKNOWN, never clean.
        val env = RaspEnv(failingSettings = setOf(Settings.Global.DEVELOPMENT_SETTINGS_ENABLED))
        assertState(observe("dev_settings_enabled", env), SignalState.UNKNOWN, partial = "development_settings")
        // adb on next to the failed read: the indicator wins, the gap stays visible.
        val mixed = RaspEnv(
            settingsOn = setOf(Settings.Global.ADB_ENABLED),
            failingSettings = setOf(Settings.Global.DEVELOPMENT_SETTINGS_ENABLED),
        )
        assertState(observe("dev_settings_enabled", mixed), SignalState.DETECTED, "adb_enabled", "development_settings")
    }

    @Test
    fun rootArtifactsEachIndicator() {
        for (path in RootArtifactsDetector.SU_PATHS) {
            assertState(observe("root_artifacts", RaspEnv(presentPaths = setOf(path))), SignalState.DETECTED, "su_path")
        }
        for (path in RootArtifactsDetector.ROOT_MANAGER_PATHS) {
            assertState(observe("root_artifacts", RaspEnv(presentPaths = setOf(path))), SignalState.DETECTED, "manager_path")
        }
        for (pkg in SignalsCatalog.ROOT_MANAGER_PACKAGES) {
            assertState(observe("root_artifacts", RaspEnv(visiblePackages = setOf(pkg))), SignalState.DETECTED, "root_package")
        }
        val testKeys = RaspEnv.CLEAN_BUILD + ("TAGS" to "test-keys")
        assertState(observe("root_artifacts", RaspEnv(fields = testKeys)), SignalState.DETECTED, "test_keys")
        for (type in listOf("userdebug", "eng")) {
            assertState(observe("root_artifacts", RaspEnv(fields = RaspEnv.CLEAN_BUILD + ("TYPE" to type))), SignalState.DETECTED, "build_type")
        }
        for (line in listOf(
            "1201 22 0:5 / /system/bin rw - tmpfs magisk rw,seclabel",
            "1202 22 0:5 / /debug_ramdisk rw - tmpfs .Magisk rw",
            "1203 22 0:6 / /system/lib rw - overlay KSU rw,lowerdir=/data/adb/modules",
            "1204 22 0:7 / /apex rw - tmpfs zygisk rw",
            "1205 22 0:8 / /data/adb/ap rw - tmpfs APatch rw",
        )) {
            assertState(observe("root_artifacts", RaspEnv(mountLines = RaspEnv.CLEAN_MOUNTS + line)), SignalState.DETECTED, "mountinfo")
        }
        // KSU only as a whole field (the KernelSU mount source), never inside another one.
        for (line in listOf("1208 22 0:9 / /x rw - tmpfs MAGISK rw", "1209 22 0:9 / /x rw - overlay KSU")) {
            assertState(observe("root_artifacts", RaspEnv(mountLines = RaspEnv.CLEAN_MOUNTS + line)), SignalState.DETECTED, "mountinfo")
        }
        for (line in listOf("1206 22 0:9 / /mnt/KSUX rw - tmpfs tmpfs rw", "1207 22 0:9 / /mnt rw - tmpfs xKSU rw",
            "1210 22 0:9 / /mnt rw - overlay ksu rw")) {
            assertEquals(SignalState.NOT_DETECTED, observe("root_artifacts", RaspEnv(mountLines = RaspEnv.CLEAN_MOUNTS + line)).state)
        }
        val everything = RaspEnv(
            presentPaths = setOf("/system/xbin/su", "/sbin/magisk"),
            visiblePackages = setOf("com.topjohnwu.magisk"),
            fields = RaspEnv.CLEAN_BUILD + ("TAGS" to "test-keys") + ("TYPE" to "userdebug"),
            mountLines = listOf("1 1 0:1 / /x rw - tmpfs magisk rw"),
        )
        assertState(
            observe("root_artifacts", everything), SignalState.DETECTED,
            "su_path,manager_path,test_keys,build_type,root_package,mountinfo",
        )
    }

    @Test
    fun rootArtifactsEachFailureIsPartialNeverClean() {
        val cases = listOf(
            RaspEnv(deniedPaths = setOf(RootArtifactsDetector.SU_PATHS.last())) to "su_path",
            RaspEnv(deniedPaths = setOf(RootArtifactsDetector.ROOT_MANAGER_PATHS.first())) to "manager_path",
            RaspEnv(failing = setOf("pathPresent")) to "su_path,manager_path",
            RaspEnv(failing = setOf("buildFields")) to "build_props",
            RaspEnv(fields = RaspEnv.CLEAN_BUILD - "TAGS") to "test_keys",
            RaspEnv(fields = RaspEnv.CLEAN_BUILD - "TYPE") to "build_type",
            RaspEnv(failingPackages = setOf(SignalsCatalog.ROOT_MANAGER_PACKAGES[3])) to "root_package",
            RaspEnv(failing = setOf("packageVisible")) to "root_package",
            RaspEnv(failing = setOf("mountInfoLines")) to "mountinfo",
        )
        for ((env, partial) in cases) {
            assertState(observe("root_artifacts", env), SignalState.UNKNOWN, partial = partial)
        }
        // A denied path next to a present one: the indicator wins, the gap stays visible.
        val mixed = RaspEnv(presentPaths = setOf("/system/bin/su"), failing = setOf("mountInfoLines"))
        assertState(observe("root_artifacts", mixed), SignalState.DETECTED, "su_path", "mountinfo")
    }

    @Test
    fun rootPackagesWithoutTheSignalsRaspOptInAreNotRunNeverNotInstalled() {
        // Without the signals-rasp marker the <queries> are absent: packages are invisible, so the check did not run.
        val queried = mutableListOf<String>()
        val noOptIn = object : RaspEnv(loadableClasses = emptySet(), visiblePackages = setOf("com.topjohnwu.magisk")) {
            override fun packageVisible(context: Context, packageName: String): Boolean =
                super.packageVisible(context, packageName).also { queried += packageName }
        }
        assertState(observe("root_artifacts", noOptIn), SignalState.UNKNOWN, partial = "root_package")
        assertEquals("no package lookup without the <queries>", emptyList<String>(), queried)
        assertState(
            observe("root_artifacts", RaspEnv(failingClasses = setOf(RootArtifactsDetector.QUERIES_MARKER))),
            SignalState.UNKNOWN, partial = "root_package",
        )
        // Another indicator still wins.
        assertState(
            observe("root_artifacts", RaspEnv(loadableClasses = emptySet(), presentPaths = setOf("/system/bin/su"))),
            SignalState.DETECTED, "su_path", "root_package",
        )
    }

    @Test
    fun linkageFailuresAndInterruptsAreNotRun() {
        val oldBinary = RaspEnv(failing = setOf("isWaitingForDebugger"), failure = { AbstractMethodError("old binary") })
        assertState(observe("debugger_attached", oldBinary), SignalState.UNKNOWN, partial = "jdwp_waiting")
        val missingClass = RaspEnv(failing = setOf("pathPresent"), failure = { NoClassDefFoundError("android/system/Os") })
        assertState(observe("root_artifacts", missingClass), SignalState.UNKNOWN, partial = "su_path,manager_path")
        assertState(observe("emulator_indicated", missingClass), SignalState.UNKNOWN, partial = "qemu_device")

        val interrupted = RaspEnv(failing = setOf("mountInfoLines"), failure = { InterruptedException("stop") })
        try {
            assertState(observe("root_artifacts", interrupted), SignalState.UNKNOWN, partial = "mountinfo")
            assertTrue("the interrupt is kept on the thread", Thread.interrupted())
            val deniedPath = RaspEnv(deniedPaths = setOf("/dev/qemu_pipe"), failure = { InterruptedException("stop") })
            assertState(observe("emulator_indicated", deniedPath), SignalState.UNKNOWN, partial = "qemu_device")
            assertTrue("the interrupt is kept on the thread", Thread.interrupted())
        } finally {
            Thread.interrupted()
        }
    }

    @Test
    fun emulatorIndicatedEachIndicator() {
        val emulatorBuilds = listOf(
            "FINGERPRINT" to "generic/sdk/generic:9/PSR1/1:userdebug/test-keys",
            "FINGERPRINT" to "google/sdk_gphone64_x86_64/emu64xa:14/UE1A/1:userdebug/dev-keys",
            "HARDWARE" to "ranchu",
            "HARDWARE" to "goldfish",
            "HARDWARE" to "vbox86",
            "BOARD" to "goldfish_x86_64",
            "PRODUCT" to "sdk_gphone64_arm64",
            "PRODUCT" to "google_sdk",
            "DEVICE" to "vbox86p",
            "MODEL" to "Android SDK built for x86",
            "MODEL" to "Emulator",
            "MANUFACTURER" to "Genymotion",
        )
        for (field in emulatorBuilds) {
            assertState(observe("emulator_indicated", RaspEnv(fields = RaspEnv.CLEAN_BUILD + field)), SignalState.DETECTED, "build_props")
        }
        for (path in EmulatorIndicatedDetector.EMULATOR_FILES) {
            assertState(observe("emulator_indicated", RaspEnv(presentPaths = setOf(path))), SignalState.DETECTED, "qemu_device")
        }
        assertState(observe("emulator_indicated", RaspEnv(accelerometer = false)), SignalState.DETECTED, "sensor_missing")
    }

    @Test
    fun emulatorIndicatedReviewedListDropsTheBareSdkSubstring() {
        // The frozen emulator_detected matched any PRODUCT containing "sdk"; the reviewed list does not.
        for (product in listOf("a05msdkub", "mysdkphone", "tsdk")) {
            assertState(observe("emulator_indicated", RaspEnv(fields = RaspEnv.CLEAN_BUILD + ("PRODUCT" to product))), SignalState.NOT_DETECTED)
        }
    }

    @Test
    fun emulatorIndicatedEachFailureIsPartialNeverClean() {
        val cases = listOf(
            RaspEnv(failing = setOf("buildFields")) to "build_props",
            RaspEnv(fields = RaspEnv.CLEAN_BUILD - "HARDWARE") to "build_props",
            RaspEnv(deniedPaths = setOf("/dev/socket/qemud")) to "qemu_device",
            RaspEnv(failing = setOf("pathPresent")) to "qemu_device",
            RaspEnv(failing = setOf("hasDefaultSensor")) to "sensor_missing",
        )
        for ((env, partial) in cases) {
            assertState(observe("emulator_indicated", env), SignalState.UNKNOWN, partial = partial)
        }
    }

    @Test
    fun hookFrameworkJavaClassesAndFrames() {
        for (cls in HookFrameworkJavaDetector.HOOK_CLASSES) {
            assertState(observe("hook_framework_java", RaspEnv(loadableClasses = setOf(cls))), SignalState.DETECTED, "xposed_class")
        }
        for (frame in listOf(
            "de.robv.android.xposed.XposedBridge",
            "org.lsposed.lspd.hooker.HandleBindAppHooker",
            "com.saurik.substrate.MS\$2",
            "LSPHooker_",
            "EdHooker_1234",
        )) {
            assertState(
                observe("hook_framework_java", RaspEnv(stackClasses = RaspEnv.CLEAN_STACK + frame)),
                SignalState.DETECTED, "hook_frame",
            )
        }
        assertState(observe("hook_framework_java", RaspEnv(failing = setOf("classLoadable"))), SignalState.UNKNOWN, partial = "xposed_class")
        assertState(
            observe("hook_framework_java", RaspEnv(failingClasses = setOf(HookFrameworkJavaDetector.HOOK_CLASSES[1]))),
            SignalState.UNKNOWN, partial = "xposed_class",
        )
        assertState(
            observe("hook_framework_java", RaspEnv(failing = setOf("controlledStackTraceClassNames"))),
            SignalState.UNKNOWN, partial = "hook_frame",
        )
    }

    @Test
    fun environmentWrittenBeforeTheD05ReportsTheNewChecksAsNotMeasured() {
        // DetectorsTest.FakeEnv does not implement the D-05 calls: their defaults throw, so nothing reads as clean.
        val legacy = DetectorsTest.FakeEnv()
        val states = detectors(legacy).associate { it.capabilityId to it.detect(dummyContext).state }
        assertEquals(SignalState.NOT_DETECTED, states["app_debuggable"]) // isAppDebuggable predates the D-05
        for (id in SignalsCatalog.RASP_CAPABILITY_IDS - "app_debuggable") assertEquals(id, SignalState.UNKNOWN, states[id])
    }

    @Test
    fun errorOnlyForAnUnexpectedExceptionInTheDetectorItself() {
        // The platform call returned; the detector's own processing of the value throws.
        val brokenMap = object : AbstractMap<String, String>() {
            override val entries: Set<Map.Entry<String, String>> get() = throw IllegalStateException("bug")
            override fun get(key: String): String = throw IllegalStateException("bug")
        }
        val brokenList = object : AbstractList<String>() {
            override val size = 1
            override fun get(index: Int): String = throw IllegalStateException("bug")
        }
        val env = RaspEnv(fields = brokenMap, mountLines = brokenList, stackClasses = brokenList)
        for (id in listOf("root_artifacts", "emulator_indicated", "hook_framework_java")) {
            val obs = observe(id, env)
            assertEquals(id, SignalState.ERROR, obs.state)
            assertTrue(obs.detail.isEmpty())
        }
    }

    @Test
    fun frozenDetectorsNeverCallTheD05Environment() {
        val calls = mutableListOf<String>()
        val recording = object : RaspEnv() {
            override fun isWaitingForDebugger() = super.isWaitingForDebugger().also { calls += "waiting" }
            override fun buildFields() = super.buildFields().also { calls += "fields" }
            override fun pathPresent(path: String) = super.pathPresent(path).also { calls += "path" }
            override fun mountInfoLines() = super.mountInfoLines().also { calls += "mounts" }
        }
        SignalsCollector.defaultDetectors(clock, recording).forEach { it.detect(dummyContext) }
        assertEquals(emptyList<String>(), calls)
    }
}
