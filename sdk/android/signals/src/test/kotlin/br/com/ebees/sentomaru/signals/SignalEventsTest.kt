package br.com.ebees.sentomaru.signals

import android.content.Context
import android.provider.Settings
import br.com.ebees.sentomaru.signals.detectors.EmulatorIndicatedDetector
import br.com.ebees.sentomaru.signals.detectors.HookFrameworkJavaDetector
import br.com.ebees.sentomaru.signals.detectors.RootArtifactsDetector
import org.junit.Assert.*
import org.junit.Test
import java.io.File
import java.time.Clock
import java.time.Instant
import java.time.ZoneOffset
import java.util.concurrent.Executor
import java.util.concurrent.RejectedExecutionException
import kotlin.random.Random

/**
 * D-15a: signal events. Transitions per capability (first observation and state changes), only the D-05/D-12c
 * capabilities, codes only from the allowlist, no PII (property test), no wall-clock field, a listener that throws never
 * reaches the collection, no scheduled work and nothing on disk, and nothing changes without opting in.
 */
class SignalEventsTest {
    private val clock = Clock.fixed(Instant.parse("2026-10-23T10:00:00Z"), ZoneOffset.UTC)
    private val context: Context = object : android.content.ContextWrapper(null) {}
    private val direct = Executor { it.run() }

    private class Recorder : SentomaruSignalEventListener {
        val events = mutableListOf<SentomaruSignalEvent>()
        override fun onSignalEvent(event: SentomaruSignalEvent) {
            events += event
        }
    }

    private fun obs(id: String, state: SignalState, detail: Map<String, String> = emptyMap()) =
        SignalObservation(capabilityId = id, version = "1.0.0", state = state, observedAt = "2026-10-23T10:00:00Z", detail = detail)

    private fun snapshot(vararg observations: SignalObservation) =
        SignalsSnapshot(SignalsCatalog.VERSION, "2026-10-23T10:00:00Z", 1, observations.toList())

    private val eventCapabilities = SignalsCatalog.RASP_CAPABILITY_IDS + SignalsCatalog.APP_INTEGRITY_CAPABILITY_IDS +
        SignalsCatalog.DEVICE_THREAT_CAPABILITY_IDS + SignalsCatalog.SCREEN_CAPABILITY_IDS +
        SignalsCatalog.SESSION_CAPABILITY_IDS

    @Test
    fun eventsAreEmittedOnTheFirstObservationAndOnEachStateChangeOnly() {
        val events = SentomaruSignalEvents()
        val recorder = Recorder().also { events.addListener(direct, it) }
        events.observe(snapshot(obs("root_artifacts", SignalState.NOT_DETECTED, mapOf("indicators" to "none"))))
        events.observe(snapshot(obs("root_artifacts", SignalState.NOT_DETECTED, mapOf("indicators" to "none"))))
        events.observe(snapshot(obs("root_artifacts", SignalState.DETECTED, mapOf("indicators" to "su_path,build_type"))))
        events.observe(snapshot(obs("root_artifacts", SignalState.DETECTED, mapOf("indicators" to "mountinfo"))))
        events.observe(snapshot(obs("root_artifacts", SignalState.UNKNOWN, mapOf("indicators" to "none", "partial" to "root_package"))))
        assertEquals(
            listOf(
                Triple(SignalState.NOT_DETECTED, emptyList<String>(), 1L),
                Triple(SignalState.DETECTED, listOf("su_path", "build_type"), 2L),
                Triple(SignalState.UNKNOWN, listOf("partial"), 3L),
            ),
            recorder.events.map { Triple(it.state, it.reasonCodes, it.sequence) },
        )
        val first = recorder.events.first()
        assertEquals(SentomaruSignalEvent.Kind.SIGNAL, first.kind)
        assertEquals(("root_artifacts" to "root_artifacts"), first.type to first.capabilityId)
        assertEquals(("1.0.0" to SignalsCatalog.VERSION), first.capabilityVersion to first.catalogVersion)
    }

    @Test
    fun theSixFrozenCapabilitiesAndUnknownIdsNeverEmit() {
        val events = SentomaruSignalEvents()
        val recorder = Recorder().also { events.addListener(direct, it) }
        events.observe(snapshot(*SignalsCatalog.DEFAULT_CAPABILITY_IDS.map { obs(it, SignalState.DETECTED) }.toTypedArray()))
        events.observe(snapshot(obs("frida_detected", SignalState.DETECTED), obs("play_integrity_failed", SignalState.DETECTED)))
        assertTrue(recorder.events.isEmpty())
        assertEquals(eventCapabilities.toSet(), SignalsCatalog.EVENT_TYPES.keys)
        assertEquals(eventCapabilities.toSet(), SignalsCatalog.EVENT_REASON_CODES.keys)
        assertTrue(SignalsCatalog.DEFAULT_CAPABILITY_IDS.none { it in SignalsCatalog.EVENT_TYPES })
    }

    @Test
    fun theTypesAreTheClosedVocabulary() {
        assertEquals(
            listOf("debugger", "debuggable_build", "developer_options", "root_artifacts", "emulator", "hook_framework_java",
                "app_signer", "code_integrity", "installer_class", "accessibility_risk", "overlay", "ime_untrusted",
                "synthetic_input", "known_malware", "screen_capture", "screen_shared", "location_mock", "call_active").sorted(),
            SignalsCatalog.EVENT_TYPES.values.sorted(),
        )
        // Every allowed code is a fixed lowercase identifier (never free text).
        val code = Regex("^[a-z0-9_]{3,32}$")
        for ((id, codes) in SignalsCatalog.EVENT_REASON_CODES) for (c in codes) assertTrue("$id $c", code.matches(c))
    }

    @Test
    fun theEventHasNoWallClockNoVerdictAndNoThreatName() {
        val fields = SentomaruSignalEvent::class.java.declaredFields.filterNot { java.lang.reflect.Modifier.isStatic(it.modifiers) }
            .map { it.name }.sorted()
        assertEquals(listOf("capabilityId", "capabilityVersion", "catalogVersion", "kind", "reasonCodes", "sequence", "state", "type"), fields)
        val members = (SentomaruSignalEvents::class.java.declaredMethods + SentomaruSignalEvent::class.java.declaredMethods +
            SentomaruServerResponseEvent::class.java.declaredMethods + ServerResponseCodes::class.java.declaredMethods)
            .map { it.name.lowercase() }
        for (forbidden in listOf("safe", "compromised", "score", "summary", "verdict", "threat")) {
            assertTrue(forbidden, members.none { forbidden in it })
        }
        assertEquals(listOf(SentomaruSignalEvent.Kind.SIGNAL), SentomaruSignalEvent.Kind.entries)
    }

    /** Every code a detector writes in its detail is in the allowlist (none is dropped by accident). */
    @Test
    fun theAllowlistCoversEveryCodeTheDetectorsEmit() {
        val envs = listOf(
            RaspEnv(),
            RaspEnv(waitingForDebugger = true, settingsOn = setOf(Settings.Global.ADB_ENABLED, Settings.Global.DEVELOPMENT_SETTINGS_ENABLED),
                presentPaths = (RootArtifactsDetector.SU_PATHS + RootArtifactsDetector.ROOT_MANAGER_PATHS + EmulatorIndicatedDetector.EMULATOR_FILES).toSet(),
                fields = RaspEnv.CLEAN_BUILD + mapOf("TAGS" to "test-keys", "TYPE" to "userdebug", "HARDWARE" to "ranchu"),
                visiblePackages = SignalsCatalog.ROOT_MANAGER_PACKAGES.toSet(), mountLines = listOf("1 1 0:1 / /x rw - magisk magisk rw"),
                accelerometer = false, loadableClasses = HookFrameworkJavaDetector.HOOK_CLASSES.toSet() + RootArtifactsDetector.QUERIES_MARKER),
            RaspEnv(loadableClasses = emptySet()),
        ) + RaspEnv.CALLS.map { RaspEnv(failing = setOf(it)) }
        for (env in envs) {
            for (detector in SignalsCollector.raspDetectors(clock, env)) {
                val o = detector.detect(context)
                val raw = SentomaruSignalEvents.rawReasonCodes(o.capabilityId, o.detail)
                assertTrue("${o.capabilityId} $raw", SignalsCatalog.EVENT_REASON_CODES.getValue(o.capabilityId).containsAll(raw))
            }
        }
        // Collector replacements (deadline) and the D-12c result/class/reason codes.
        for (id in eventCapabilities) {
            val allowed = SignalsCatalog.EVENT_REASON_CODES.getValue(id)
            assertTrue(id, allowed.containsAll(SentomaruSignalEvents.rawReasonCodes(id, mapOf("timeout" to "overrun"))))
        }
        for (result in listOf("match", "mismatch", "no_reference", "unreadable"))
            assertEquals(listOf(result), SentomaruSignalEvents.reasonCodes("app_signer_mismatch", mapOf("result" to result, "signers" to "2", "unexpected" to "1")))
        for (c in listOf("play", "none", "other", "unknown"))
            assertEquals(listOf("class_$c", "initiator_$c"), SentomaruSignalEvents.reasonCodes("installer_class", mapOf("class" to c, "initiator" to c)))
        for (reason in listOf("not_compared", "timeout", "partial", "main_thread"))
            assertEquals(listOf(reason), SentomaruSignalEvents.reasonCodes("code_integrity",
                mapOf("reason" to reason, "algorithm" to "apk-code-sha256-v1", "aggregate" to "ab".repeat(32), "files" to "3")))
        for (cause in listOf("apk_list", "executor", "hash_failed", "apk_unreadable", "duplicate_entry", "entry_unreadable",
                "no_code_files", "too_large", "too_many_files"))
            assertEquals(listOf("partial", cause), SentomaruSignalEvents.reasonCodes("code_integrity", mapOf("reason" to "partial", "cause" to cause)))
    }

    /**
     * Property: whatever a detail carries (package names, paths, digests, serials, ids, arbitrary text, under any key),
     * no event field contains it, and every reason code is one of the capability's allowed codes.
     */
    @Test
    fun noEventFieldEverCarriesWhatTheDetailCarries() {
        val random = Random(20261023)
        val secrets = listOf(
            "com.topjohnwu.magisk", "com.android.vending", "br.com.ebees.exampleapp", "/system/xbin/su", "/data/adb/magisk",
            "a1b2c3d4e5f6" + "0".repeat(52), "R58N123ABCD", "358240051111110", "9774d56d682e549c",
            "11111111-2222-4333-8444-555555555555", "Maria da Silva", "maria@example.com",
        )
        val keys = listOf("indicators", "partial", "timeout", "result", "class", "initiator", "reason", "cause", "aggregate",
            "files", "signers", "package", "path", "serial", "installationId")
        repeat(500) { round ->
            val events = SentomaruSignalEvents()
            val recorder = Recorder().also { events.addListener(direct, it) }
            val injected = mutableSetOf<String>()
            val observations = eventCapabilities.map { id ->
                val detail = keys.shuffled(random).take(random.nextInt(1, keys.size)).associateWith {
                    val secret = secrets.random(random) + if (random.nextBoolean()) "" else random.nextInt().toString()
                    val text = when (random.nextInt(4)) {
                        0 -> secret
                        1 -> "su_path,$secret"
                        2 -> "$secret,partial"
                        else -> String(CharArray(random.nextInt(1, 40)) { (random.nextInt(32, 0x24F)).toChar() })
                    }
                    injected += text.split(',').filter { it.length >= 6 }
                    text
                }
                obs(id, SignalState.entries.filter { it != SignalState.STALE }.random(random), detail)
            }
            events.observe(snapshot(*observations.toTypedArray()))
            assertEquals("round $round", eventCapabilities.size, recorder.events.size)
            for (event in recorder.events) {
                assertTrue(event.reasonCodes.toString(), SignalsCatalog.EVENT_REASON_CODES.getValue(event.capabilityId).containsAll(event.reasonCodes))
                val text = event.toString()
                for (secret in injected) if (secret !in SignalsCatalog.EVENT_REASON_CODES.getValue(event.capabilityId)) {
                    assertFalse("round $round: $secret in $text", secret in text)
                }
            }
        }
    }

    /** The same through the real detectors and the collector: a dirty device double never leaks its values. */
    @Test
    fun theRealDetectorsNeverLeakPackagesPathsOrDigestsIntoEvents() {
        val env = RaspEnv(
            presentPaths = setOf("/system/xbin/su", "/data/adb/magisk"), visiblePackages = SignalsCatalog.ROOT_MANAGER_PACKAGES.toSet(),
            mountLines = listOf("9 1 0:9 / /debug_ramdisk rw - magisk magisk rw"), waitingForDebugger = true,
        ).apply { certDigests = listOf("a1b2c3d4e5f6"); installerPkg = "com.example.thirdparty.store" }
        val events = SentomaruSignalEvents()
        val recorder = Recorder().also { events.addListener(direct, it) }
        val collector = SignalsCollector(clock, SignalsCollector.defaultDetectors(clock, env) + SignalsCollector.raspDetectors(clock, env)).apply { this.events = events }
        val snapshot = collector.snapshot(context)
        assertTrue(snapshot.toJson().contains("com.example.thirdparty.store")) // the frozen installer_source still sends it
        assertEquals(SignalsCatalog.RASP_CAPABILITY_IDS.toSet(), recorder.events.map { it.capabilityId }.toSet())
        val text = recorder.events.joinToString()
        for (leak in SignalsCatalog.ROOT_MANAGER_PACKAGES + listOf("/system/xbin/su", "/data/adb/magisk", "debug_ramdisk", "a1b2c3d4e5f6",
                "com.example.thirdparty.store", "com.android.vending", "samsung", "SM-T000Z", "2026-10-23")) {
            assertFalse(leak, leak in text)
        }
        assertEquals(listOf("su_path", "root_package", "mountinfo"),
            recorder.events.single { it.capabilityId == "root_artifacts" }.reasonCodes)
    }

    @Test
    fun aThrowingListenerOrRejectingExecutorNeverReachesTheCollection() {
        val events = SentomaruSignalEvents()
        events.addListener(direct) { throw IllegalStateException("app bug") }
        events.addListener(direct) { throw LinkageError("old app binary") }
        events.addListener({ throw RejectedExecutionException("shut down") }) { fail("never runs") }
        val recorder = Recorder().also { events.addListener(direct, it) }
        val env = RaspEnv(waitingForDebugger = true)
        val collector = SignalsCollector(clock, SignalsCollector.raspDetectors(clock, env)).apply { this.events = events }
        val snapshot = collector.snapshot(context)
        assertEquals(6, snapshot.observations.size)
        assertEquals(6, recorder.events.size)
        assertTrue(events.removeListener(recorder))
        assertFalse(events.removeListener(recorder))
        env.waitingForDebugger = false
        collector.snapshot(context)
        assertEquals(6, recorder.events.size) // removed: nothing more
    }

    @Test
    fun deliveryUsesOnlyTheListenersExecutorsAndNoListenerMeansNoWork() {
        var executed = 0
        val counting = Executor { executed++; it.run() }
        val events = SentomaruSignalEvents()
        val collector = SignalsCollector(clock, SignalsCollector.raspDetectors(clock, RaspEnv())).apply { this.events = events }
        collector.snapshot(context)
        assertEquals(0, executed)
        events.addListener(counting) {}
        collector.snapshot(context) // same states: no transition, no event
        assertEquals(0, executed)
        events.addListener(counting) {}
        events.observe(snapshot(obs("debugger_attached", SignalState.DETECTED, mapOf("indicators" to "jdwp_connected"))))
        assertEquals(2, executed) // one event, two listeners
    }

    /** Nothing on disk, no thread, timer, alarm or clock: the source of the events uses none of those APIs. */
    @Test
    fun theEventsSourceSchedulesNothingAndWritesNothing() {
        val source = File("src/main/kotlin/br/com/ebees/sentomaru/signals/SentomaruSignalEvents.kt").readText() +
            File("src/main/kotlin/br/com/ebees/sentomaru/signals/SentomaruServerResponseEvent.kt").readText()
        for (api in listOf("java.io", "java.nio", "SharedPreferences", "openFileOutput", "Thread(", "Executors.", "Timer",
                "Handler", "AlarmManager", "WorkManager", "ScheduledExecutor", "Instant", "Clock", "currentTimeMillis", "nanoTime",
                "OkHttp", "HttpURLConnection", "Socket")) {
            assertFalse(api, api in source)
        }
    }

    @Test
    fun withoutOptingInNothingChanges() {
        assertNull(SignalsCollector().events)
        assertNull(SignalsCollector(clock, SignalsCollector.raspDetectors(clock, RaspEnv())).events)
        assertEquals(SignalsCatalog.DEFAULT_CAPABILITY_IDS, SignalsCollector.defaultDetectors(clock).map { it.capabilityId })
    }
}
