package br.com.ebees.sentomaru.signals

import android.content.Context
import android.provider.Settings
import br.com.ebees.sentomaru.signals.detectors.*
import org.junit.Assert.*
import org.junit.Test
import java.time.Clock
import java.time.Instant
import java.time.ZoneOffset

/** D-05b collector: monotonic timing, per-collection deadline, main-thread refusal and the 12-capability size. */
class SignalsCollectorDeadlineTest {
    private val clock = Clock.fixed(Instant.parse("2026-10-21T10:00:00Z"), ZoneOffset.UTC)
    private val dummyContext: Context = object : android.content.ContextWrapper(null) {}

    /** Monotonic double: each detector advances it by its own cost. */
    private class FakeNanos {
        var now = 7_000_000_000L
        fun read(): Long = now
    }

    private class CostlyDetector(
        override val capabilityId: String,
        private val nanos: FakeNanos,
        private val costMs: Long,
        private val state: SignalState = SignalState.DETECTED,
    ) : SignalDetector {
        override val version = "1.0.0"
        override val budgetMs = 5L
        var runs = 0
        override fun detect(context: Context): SignalObservation {
            runs++
            nanos.now += costMs * 1_000_000L
            return SignalObservation(capabilityId, version, state, observedAt = "2026-10-21T10:00:00Z")
        }
    }

    private fun collector(detectors: List<SignalDetector>, nanos: FakeNanos, deadlineMs: Long?, main: Boolean = false) =
        SignalsCollector(clock, detectors, deadlineMs, nanos::read) { main }

    @Test
    fun overrunningDetectorIsUnknownTimeoutAndCollectionGoesOn() {
        val nanos = FakeNanos()
        val fast = CostlyDetector("cap_fast", nanos, 10)
        val slow = CostlyDetector("cap_slow", nanos, 95)
        val late = CostlyDetector("cap_late", nanos, 1)
        val snapshot = collector(listOf(fast, slow, late), nanos, 100).snapshot(dummyContext)

        assertEquals(listOf("cap_fast", "cap_slow", "cap_late"), snapshot.observations.map { it.capabilityId })
        val (a, b, c) = snapshot.observations
        assertEquals(SignalState.DETECTED, a.state)
        assertEquals(SignalState.UNKNOWN, b.state)
        assertEquals(mapOf("timeout" to "overrun"), b.detail)
        assertEquals("1.0.0", b.version)
        assertEquals("client_observed", b.source)
        assertEquals(SignalState.UNKNOWN, c.state)
        assertEquals(mapOf("timeout" to "skipped"), c.detail)
        assertEquals("the detector past the deadline is not started", 0, late.runs)
        assertEquals(105L, snapshot.durationMs)
    }

    @Test
    fun detectorEndingExactlyAtTheDeadlineKeepsItsResult() {
        val nanos = FakeNanos()
        val snapshot = collector(listOf(CostlyDetector("cap_a", nanos, 40), CostlyDetector("cap_b", nanos, 60)), nanos, 100)
            .snapshot(dummyContext)
        assertTrue(snapshot.observations.all { it.state == SignalState.DETECTED })
        assertEquals(100L, snapshot.durationMs)
    }

    @Test
    fun timeoutNeverReadsAsCleanEvenWhenTheLateResultWasClean() {
        val nanos = FakeNanos()
        val obs = collector(listOf(CostlyDetector("cap_a", nanos, 150, SignalState.NOT_DETECTED)), nanos, 100)
            .snapshot(dummyContext).observations.single()
        assertEquals(SignalState.UNKNOWN, obs.state)
        assertEquals("timeout", obs.detail.keys.single())
    }

    @Test
    fun frozenPathWithoutDeadlineIsUnchanged() {
        // SignalsCollector() keeps the pre-D-05 behavior: no deadline, no thread refusal, results as detected.
        val nanos = FakeNanos()
        val slow = CostlyDetector("cap_slow", nanos, 500)
        val snapshot = collector(listOf(slow), nanos, null, main = true).snapshot(dummyContext)
        assertEquals(SignalState.DETECTED, snapshot.observations.single().state)
        assertEquals(500L, snapshot.durationMs)
        assertNull(SignalsCollector().deadlineMs)
        assertEquals(SignalsCatalog.DEFAULT_CAPABILITY_IDS, SignalsCollector().detectors.map { it.capabilityId })
    }

    @Test
    fun collectionWithDeadlineRefusesTheMainThreadBeforeAnyDetectorRuns() {
        val nanos = FakeNanos()
        val detector = CostlyDetector("cap_a", nanos, 1)
        val error = assertThrows(IllegalStateException::class.java) {
            collector(listOf(detector), nanos, 100, main = true).snapshot(dummyContext)
        }
        assertTrue(error.message!!.contains("main thread"))
        assertEquals(0, detector.runs)
        // Off the main thread the same collector runs.
        assertEquals(1, collector(listOf(detector), nanos, 100, main = false).snapshot(dummyContext).observations.size)
    }

    @Test
    fun realMonotonicClockCollectsAllTwelveWithinTheDeadline() {
        val env = RaspEnv()
        val collector = SignalsCollector(
            clock,
            SignalsCollector.defaultDetectors(clock, env) + SignalsCollector.raspDetectors(clock, env),
            SignalsCollector.RASP_DEADLINE_MS,
        )
        val snapshot = collector.snapshot(dummyContext)
        assertEquals(SignalsCatalog.DEFAULT_CAPABILITY_IDS + SignalsCatalog.RASP_CAPABILITY_IDS, snapshot.observations.map { it.capabilityId })
        assertTrue(snapshot.observations.none { "timeout" in it.detail })
        assertTrue(snapshot.durationMs < SignalsCollector.RASP_DEADLINE_MS)
        assertEquals("1.15.0", snapshot.catalogVersion)
    }

    private class ThrowingDetector(override val capabilityId: String, private val error: () -> Throwable) : SignalDetector {
        override val version = "1.0.0"
        override val budgetMs = 1L
        override fun detect(context: Context): SignalObservation = throw error()
    }

    @Test
    fun detectorThatThrowsIsErrorAndTheCollectionGoesOnInBothModes() {
        val env = DetectorsTest.FakeEnv()
        val frozenAlone = SignalsCollector(clock, SignalsCollector.defaultDetectors(clock, env)).snapshot(dummyContext).observations
        for (deadline in listOf(null, SignalsCollector.RASP_DEADLINE_MS)) {
            for (error in listOf<() -> Throwable>({ AbstractMethodError("old binary") }, { NoClassDefFoundError("x") }, { IllegalStateException("bug") })) {
                val detectors = SignalsCollector.defaultDetectors(clock, env) + ThrowingDetector("cap_broken", error)
                val observations = SignalsCollector(clock, detectors, deadline).snapshot(dummyContext).observations
                // The frozen six report exactly what they report alone.
                assertEquals(frozenAlone, observations.take(6))
                val broken = observations.last()
                assertEquals(SignalState.ERROR, broken.state)
                assertTrue(broken.detail.isEmpty())
                assertEquals("1.0.0", broken.version)
            }
        }
    }

    @Test
    fun virtualMachineErrorIsNeverSwallowed() {
        val collector = SignalsCollector(clock, listOf(ThrowingDetector("cap_oom") { OutOfMemoryError("oom") }))
        assertThrows(OutOfMemoryError::class.java) { collector.snapshot(dummyContext) }
    }

    @Test
    fun interruptedDetectorIsErrorAndTheInterruptIsKept() {
        try {
            val obs = SignalsCollector(clock, listOf(ThrowingDetector("cap_int") { InterruptedException("stop") }))
                .snapshot(dummyContext).observations.single()
            assertEquals(SignalState.ERROR, obs.state)
            assertTrue(Thread.interrupted())
        } finally {
            Thread.interrupted()
        }
    }

    @Test
    fun deadlineMustBePositive() {
        assertThrows(IllegalArgumentException::class.java) { SignalsCollector(clock, emptyList(), 0L) }
    }

    @Test
    fun snapshotWithAllTwelveCapabilitiesFitsIn3KiB() {
        // Worst cases: every indicator of every detector, every check unmeasured, every detector timed out; the
        // frozen six with their longest realistic values and nanosecond timestamps.
        val nanosClock = Clock.fixed(Instant.parse("2026-10-21T10:00:00.123456789Z"), ZoneOffset.UTC)
        val everyIndicator = RaspEnv(
            waitingForDebugger = true,
            fields = RaspEnv.CLEAN_BUILD + ("TAGS" to "test-keys") + ("TYPE" to "userdebug") + ("HARDWARE" to "ranchu"),
            presentPaths = setOf("/system/bin/su", "/sbin/magisk", "/dev/qemu_pipe"),
            settingsOn = setOf(Settings.Global.ADB_ENABLED, Settings.Global.DEVELOPMENT_SETTINGS_ENABLED),
            visiblePackages = SignalsCatalog.ROOT_MANAGER_PACKAGES.toSet(),
            mountLines = listOf("1 1 0:1 / /x rw - tmpfs magisk rw"),
            accelerometer = false,
            loadableClasses = HookFrameworkJavaDetector.HOOK_CLASSES.toSet() + RootArtifactsDetector.QUERIES_MARKER,
            stackClasses = listOf("de.robv.android.xposed.XposedBridge"),
        ).apply {
            debuggerConnected = true
            appDebuggable = true
            buildProps = mapOf("FINGERPRINT" to "generic/x", "MODEL" to "Emulator", "HARDWARE" to "goldfish",
                "PRODUCT" to "sdk_x86", "MANUFACTURER" to "Genymotion", "TAGS" to "test-keys")
            existingFiles = setOf("/system/bin/su")
            certDigests = listOf("e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855")
            installerPkg = "com.example.a.rather.long.installer.package.name.from.some.store.app"
            osVersionPair = Pair(36, "16.0.1")
        }
        val everyCheckFails = RaspEnv(failing = RaspEnv.CALLS.toSet() - "isDebuggerConnected" - "isAppDebuggable")
        for (env in listOf(everyIndicator, everyCheckFails)) {
            val detectors = SignalsCollector.defaultDetectors(nanosClock, env) + SignalsCollector.raspDetectors(nanosClock, env)
            val snapshot = SignalsCollector(nanosClock, detectors, SignalsCollector.RASP_DEADLINE_MS).snapshot(dummyContext)
            assertEquals(12, snapshot.observations.size)
            val bytes = snapshot.toJson().toByteArray(Charsets.UTF_8).size
            assertTrue("snapshot is $bytes bytes", bytes <= 3072)
        }
        val nanos = FakeNanos()
        val allTimedOut = SignalsCollector(
            nanosClock,
            listOf(CostlyDetector("debug_attached", nanos, 200)) +
                (SignalsCatalog.CAPABILITIES.take(12).drop(1).map { CostlyDetector(it.capabilityId, nanos, 1) }),
            SignalsCollector.RASP_DEADLINE_MS,
            nanos::read,
        ) { false }.snapshot(dummyContext)
        assertTrue(allTimedOut.observations.all { it.state == SignalState.UNKNOWN })
        assertTrue(allTimedOut.toJson().toByteArray(Charsets.UTF_8).size <= 3072)
    }

    @Test
    fun d05DetailCarriesOnlyFixedCodes() {
        val codes = setOf(
            "none", "jdwp_connected", "jdwp_waiting", "flag_debuggable", "adb_enabled", "development_settings",
            "su_path", "manager_path", "test_keys", "build_type", "build_props", "root_package", "mountinfo",
            "qemu_device", "sensor_missing", "xposed_class", "hook_frame",
        )
        val envs = listOf(
            RaspEnv(),
            RaspEnv(failing = RaspEnv.CALLS.toSet()),
            RaspEnv(
                waitingForDebugger = true, presentPaths = setOf("/system/bin/su", "/dev/qemu_pipe"),
                visiblePackages = setOf("com.topjohnwu.magisk"), accelerometer = false,
                loadableClasses = setOf("de.robv.android.xposed.XposedBridge"),
                settingsOn = setOf(Settings.Global.ADB_ENABLED),
                mountLines = listOf("1 1 0:1 / /x rw - tmpfs magisk rw"),
            ),
        )
        for (env in envs) for (obs in SignalsCollector.raspDetectors(clock, env).map { it.detect(dummyContext) }) {
            assertTrue(obs.detail.keys.all { it in setOf("indicators", "partial") })
            for (value in obs.detail.values) {
                assertTrue("${obs.capabilityId}: $value", value.split(",").all { it in codes })
            }
        }
    }
}
