package br.com.ebees.sentomaru.signals

import android.content.Context
import android.provider.Settings
import br.com.ebees.sentomaru.signals.detectors.*
import org.junit.Assert.*
import org.junit.Test
import java.io.IOException
import java.time.Clock
import java.time.Instant
import java.time.ZoneOffset
import kotlin.random.Random

/**
 * D-05 rule as a property: a double that throws or denies access in any check never yields NOT_DETECTED, and a
 * failing platform call is never ERROR (ERROR is only an unexpected exception in the detector itself).
 */
class RaspFailurePropertyTest {
    private val clock = Clock.fixed(Instant.parse("2026-10-21T10:00:00Z"), ZoneOffset.UTC)
    private val dummyContext: Context = object : android.content.ContextWrapper(null) {}

    private val failures: List<() -> Throwable> = listOf(
        { SecurityException("denied") },
        { IOException("read failed") },
        { IllegalStateException("unavailable") },
        { UnsupportedOperationException("not provided") },
        { NullPointerException("null service") },
        { RuntimeException("errno") },
        // Linkage failures: a class missing on the device, or an environment compiled before the D-05.
        { NoClassDefFoundError("missing") },
        { AbstractMethodError("old binary") },
    )

    /** Platform calls each detector depends on. */
    private val callsOf = mapOf(
        "debugger_attached" to setOf("isDebuggerConnected", "isWaitingForDebugger"),
        "app_debuggable" to setOf("isAppDebuggable"),
        "dev_settings_enabled" to setOf("globalSettingOn"),
        "root_artifacts" to setOf("pathPresent", "buildFields", "classLoadable", "packageVisible", "mountInfoLines"),
        "emulator_indicated" to setOf("buildFields", "pathPresent", "hasDefaultSensor"),
        "hook_framework_java" to setOf("classLoadable", "controlledStackTraceClassNames"),
    )

    private val allPaths = RootArtifactsDetector.SU_PATHS + RootArtifactsDetector.ROOT_MANAGER_PATHS +
        EmulatorIndicatedDetector.EMULATOR_FILES

    @Test
    fun everySingleFailingCallIsUnknownForEveryDetectorUsingIt() {
        for (call in RaspEnv.CALLS) for (failure in failures) {
            val env = RaspEnv(failing = setOf(call), failure = failure)
            for (detector in SignalsCollector.raspDetectors(clock, env)) {
                val obs = detector.detect(dummyContext)
                val uses = call in callsOf.getValue(detector.capabilityId)
                val expected = if (uses) SignalState.UNKNOWN else SignalState.NOT_DETECTED
                assertEquals("${detector.capabilityId} with $call failing", expected, obs.state)
                if (uses) assertNotNull(obs.detail["partial"])
            }
        }
    }

    @Test
    fun randomFailuresAndDenialsNeverReadAsClean() {
        val random = Random(20261021)
        repeat(3000) { round ->
            val failingCalls = RaspEnv.CALLS.filter { random.nextInt(4) == 0 }.toSet()
            val env = RaspEnv(
                failing = failingCalls,
                failure = failures[random.nextInt(failures.size)],
                deniedPaths = allPaths.filter { random.nextInt(8) == 0 }.toSet(),
                failingPackages = SignalsCatalog.ROOT_MANAGER_PACKAGES.filter { random.nextInt(8) == 0 }.toSet(),
                failingClasses = HookFrameworkJavaDetector.HOOK_CLASSES.filter { random.nextInt(6) == 0 }.toSet(),
                failingSettings = listOf(Settings.Global.ADB_ENABLED, Settings.Global.DEVELOPMENT_SETTINGS_ENABLED)
                    .filter { random.nextInt(6) == 0 }.toSet(),
                fields = RaspEnv.CLEAN_BUILD.filterKeys { random.nextInt(12) != 0 },
                // Some rounds also plant an indicator next to the failures.
                presentPaths = if (random.nextInt(5) == 0) setOf(allPaths[random.nextInt(allPaths.size)]) else emptySet(),
            )
            for (detector in SignalsCollector.raspDetectors(clock, env)) {
                val obs = detector.detect(dummyContext)
                assertNotEquals("round $round ${detector.capabilityId}", SignalState.ERROR, obs.state)
                val clean = RaspEnv(presentPaths = env.presentPaths)
                val unmeasured = obs.detail["partial"] != null
                if (unmeasured) assertNotEquals("round $round ${detector.capabilityId}", SignalState.NOT_DETECTED, obs.state)
                if (obs.state == SignalState.NOT_DETECTED) {
                    // NOT_DETECTED only when this round's faults did not touch the detector at all.
                    assertEquals(
                        "round $round ${detector.capabilityId}",
                        SignalState.NOT_DETECTED,
                        SignalsCollector.raspDetectors(clock, clean).single { it.capabilityId == detector.capabilityId }
                            .detect(dummyContext).state,
                    )
                    assertTrue(
                        "round $round ${detector.capabilityId} NOT_DETECTED with a failing call",
                        (callsOf.getValue(detector.capabilityId) intersect failingCalls).isEmpty(),
                    )
                }
            }
        }
    }

    @Test
    fun everyDeniedItemAloneIsUnknown() {
        for (path in RootArtifactsDetector.SU_PATHS + RootArtifactsDetector.ROOT_MANAGER_PATHS) {
            assertEquals(path, SignalState.UNKNOWN, RootArtifactsDetector(clock, RaspEnv(deniedPaths = setOf(path))).detect(dummyContext).state)
        }
        for (path in EmulatorIndicatedDetector.EMULATOR_FILES) {
            assertEquals(path, SignalState.UNKNOWN, EmulatorIndicatedDetector(clock, RaspEnv(deniedPaths = setOf(path))).detect(dummyContext).state)
        }
        for (pkg in SignalsCatalog.ROOT_MANAGER_PACKAGES) {
            assertEquals(pkg, SignalState.UNKNOWN, RootArtifactsDetector(clock, RaspEnv(failingPackages = setOf(pkg))).detect(dummyContext).state)
        }
        for (cls in HookFrameworkJavaDetector.HOOK_CLASSES) {
            assertEquals(cls, SignalState.UNKNOWN, HookFrameworkJavaDetector(clock, RaspEnv(failingClasses = setOf(cls))).detect(dummyContext).state)
        }
        for (key in EmulatorIndicatedDetector.BUILD_KEYS) {
            assertEquals(key, SignalState.UNKNOWN, EmulatorIndicatedDetector(clock, RaspEnv(fields = RaspEnv.CLEAN_BUILD - key)).detect(dummyContext).state)
        }
    }
}
