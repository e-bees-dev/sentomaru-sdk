package br.com.ebees.sentomaru.signals

import android.content.Context
import br.com.ebees.sentomaru.signals.detectors.*
import org.junit.Assert.*
import org.junit.Test
import java.io.IOException
import java.time.Clock
import java.time.Instant
import java.time.ZoneOffset

/**
 * D-24 (a, b, c, e): the four consultive device threat detectors by doubles. Every state and every failure; no failure
 * gives NOT_DETECTED; no service, keyboard or package name, and no device name, goes in detail or in an event.
 */
class DeviceThreatDetectorsTest {
    private val clock = Clock.fixed(Instant.parse("2026-11-04T10:00:00Z"), ZoneOffset.UTC)
    private val context: Context = object : android.content.ContextWrapper(null) {}

    class ThreatEnv(
        var services: List<String> = emptyList(),
        var ime: String? = "com.google.android.inputmethod.latin",
        var virtualPointers: Int = 0,
        var failure: Throwable? = null,
    ) : DetectorsTest.FakeEnv() {
        private fun guard() { failure?.let { throw it } }
        override fun enabledAccessibilityServicePackages(context: Context): List<String> { guard(); return services }
        override fun defaultInputMethodPackage(context: Context): String? { guard(); return ime }
        override fun virtualPointerDeviceCount(): Int { guard(); return virtualPointers }
    }

    private val failures: List<Throwable> = listOf(
        SecurityException("denied"), IOException("read failed"), IllegalStateException("manager unavailable"),
        UnsupportedOperationException("not provided"), NoClassDefFoundError("missing"), AbstractMethodError("old binary"),
    )

    private fun a11y(env: PlatformEnvironment, risky: Collection<String> = listOf("com.bad.service")) =
        A11yRiskDetector(risky, clock, env).detect(context)

    @Test
    fun a11yNoneListedAndUnlistedPresent() {
        val none = a11y(ThreatEnv())
        assertEquals(SignalState.NOT_DETECTED, none.state)
        assertEquals(mapOf("result" to "none"), none.detail)

        val listed = a11y(ThreatEnv(services = listOf("com.google.android.marvin.talkback", "com.bad.service")))
        assertEquals(SignalState.DETECTED, listed.state)
        assertEquals(mapOf("result" to "listed"), listed.detail)

        // A screen reader that is not on the list is not judged: UNKNOWN, never DETECTED and never a name.
        val unlisted = a11y(ThreatEnv(services = listOf("com.google.android.marvin.talkback")))
        assertEquals(SignalState.UNKNOWN, unlisted.state)
        assertEquals(mapOf("result" to "unlisted_present"), unlisted.detail)

        // An empty list never gives `listed`.
        assertEquals("unlisted_present", a11y(ThreatEnv(services = listOf("com.bad.service")), emptyList()).detail["result"])
    }

    @Test
    fun a11yNeverSendsAServiceNameOrCount() {
        val services = listOf("com.bad.service", "com.google.android.marvin.talkback", "com.other.helper")
        for (obs in listOf(a11y(ThreatEnv(services = services)), a11y(ThreatEnv(services = services.drop(1))))) {
            val text = obs.detail.toString()
            for (name in services) assertFalse(name, name in text)
            assertTrue(obs.detail.keys.all { it == "result" })
        }
    }

    @Test
    fun a11yFailureIsUnknownPartialNeverClean() {
        for (error in failures) {
            val obs = a11y(ThreatEnv(failure = error))
            assertEquals(error.toString(), SignalState.UNKNOWN, obs.state)
            assertEquals(mapOf("partial" to "services"), obs.detail)
        }
    }

    @Test
    fun injectedTouchComesOnlyFromMarkedScreenTouchesAndIsClearedByTheRead() {
        val monitor = ObscuredTouchMonitor()
        val detector = SyntheticInputDetector(clock, ThreatEnv(), monitor)
        monitor.record(isDown = true, flags = 0, deviceId = 4) // a real touchscreen
        monitor.record(isDown = false, flags = 0x800, deviceId = -1) // not a DOWN
        assertEquals(SignalState.NOT_DETECTED, detector.detect(context).state)
        assertEquals(mapOf("indicators" to "none"), detector.detect(context).detail)

        monitor.record(isDown = true, flags = 0x800, deviceId = 4) // FLAG_IS_ACCESSIBILITY_EVENT
        val a11y = detector.detect(context)
        assertEquals(SignalState.DETECTED, a11y.state)
        assertEquals(mapOf("indicators" to "injected_touch"), a11y.detail)
        assertEquals(SignalState.NOT_DETECTED, detector.detect(context).state) // the read cleared it

        monitor.record(isDown = true, flags = 0, deviceId = -1) // a virtual input device
        assertEquals(mapOf("indicators" to "injected_touch"), detector.detect(context).detail)

        val both = SyntheticInputDetector(clock, ThreatEnv(virtualPointers = 1), monitor)
        monitor.record(isDown = true, flags = 0x800)
        assertEquals(mapOf("indicators" to "virtual_pointer,injected_touch"), both.detect(context).detail)
        val text = a11y.toString() + a11y.detail
        assertFalse(text, text.contains("x=") || text.contains("pressure"))
    }

    @Test
    fun overlayStatesFollowTheWindowAndTheWindowIsCleared() {
        val monitor = ObscuredTouchMonitor()
        val detector = OverlayDetector(monitor, clock)
        val nothing = detector.detect(context)
        assertEquals(SignalState.UNKNOWN, nothing.state)
        assertEquals(mapOf("result" to "no_touches"), nothing.detail)

        monitor.record(isDown = true, flags = 0)
        monitor.record(isDown = true, flags = 0)
        monitor.record(isDown = false, flags = 1) // not a DOWN: not a touch
        val clear = detector.detect(context)
        assertEquals(SignalState.NOT_DETECTED, clear.state)
        assertEquals(mapOf("result" to "clear", "obscured" to "0", "touches" to "2"), clear.detail)

        monitor.record(isDown = true, flags = 1) // FLAG_WINDOW_IS_OBSCURED
        monitor.record(isDown = true, flags = 2) // FLAG_WINDOW_IS_PARTIALLY_OBSCURED
        monitor.record(isDown = true, flags = 0)
        val hit = detector.detect(context)
        assertEquals(SignalState.DETECTED, hit.state)
        assertEquals(mapOf("result" to "obscured", "obscured" to "2", "touches" to "3"), hit.detail)

        // The read cleared the window.
        assertEquals("no_touches", detector.detect(context).detail["result"])
    }

    @Test
    fun overlayMonitorsAreIndependent() {
        val a = ObscuredTouchMonitor()
        val b = ObscuredTouchMonitor()
        a.record(true, 1)
        assertEquals("obscured", OverlayDetector(a, clock).detect(context).detail["result"])
        assertEquals("no_touches", OverlayDetector(b, clock).detect(context).detail["result"])
    }

    private fun ime(env: PlatformEnvironment, known: Collection<String> = listOf("com.google.android.inputmethod.latin")) =
        ImeUntrustedDetector(known, clock, env).detect(context)

    @Test
    fun imeKnownUnknownNoReferenceAndPartial() {
        val known = ime(ThreatEnv())
        assertEquals(SignalState.NOT_DETECTED, known.state)
        assertEquals(mapOf("result" to "known"), known.detail)

        val unknown = ime(ThreatEnv(ime = "com.third.party.keyboard"))
        assertEquals(SignalState.DETECTED, unknown.state)
        assertEquals(mapOf("result" to "unknown"), unknown.detail)
        assertFalse("com.third.party.keyboard" in unknown.detail.toString())

        val noReference = ime(ThreatEnv(), emptyList())
        assertEquals(SignalState.UNKNOWN, noReference.state)
        assertEquals(mapOf("result" to "no_reference"), noReference.detail)

        val unset = ime(ThreatEnv(ime = null))
        assertEquals(SignalState.UNKNOWN, unset.state)
        assertEquals(mapOf("partial" to "input_method"), unset.detail)
    }

    @Test
    fun imeFailureIsUnknownPartialNeverClean() {
        for (error in failures) {
            val obs = ime(ThreatEnv(failure = error))
            assertEquals(error.toString(), SignalState.UNKNOWN, obs.state)
            assertEquals(mapOf("partial" to "input_method"), obs.detail)
        }
    }

    private fun synthetic(env: PlatformEnvironment) = SyntheticInputDetector(clock, env).detect(context)

    @Test
    fun syntheticInputDetectedCleanAndFailure() {
        val clean = synthetic(ThreatEnv())
        assertEquals(SignalState.NOT_DETECTED, clean.state)
        assertEquals(mapOf("indicators" to "none"), clean.detail)

        val hit = synthetic(ThreatEnv(virtualPointers = 2))
        assertEquals(SignalState.DETECTED, hit.state)
        assertEquals(mapOf("indicators" to "virtual_pointer"), hit.detail) // a code, never a count or a device name

        for (error in failures) {
            val obs = synthetic(ThreatEnv(failure = error))
            assertEquals(error.toString(), SignalState.UNKNOWN, obs.state)
            assertEquals(mapOf("indicators" to "none", "partial" to "virtual_pointer"), obs.detail)
        }
    }

    @Test
    fun defaultsOfAnOlderEnvironmentReportNotMeasuredNeverClean() {
        val old = DetectorsTest.FakeEnv()
        assertEquals(SignalState.UNKNOWN, a11y(old).state)
        assertEquals(SignalState.UNKNOWN, ime(old).state)
        assertEquals(SignalState.UNKNOWN, synthetic(old).state)
    }

    @Test
    fun theCollectorRunsThemOptInAndEventsCarryOnlyFixedCodes() {
        val env = ThreatEnv(services = listOf("com.bad.service"), ime = "com.third.party.keyboard", virtualPointers = 1)
        val monitor = ObscuredTouchMonitor().apply { record(true, 1, deviceId = -1) }
        val collector = SignalsCollector(
            clock,
            SignalsCollector.deviceThreatDetectors(listOf("com.bad.service"), listOf("com.known.keyboard"), monitor, clock, env, MalwareListStore()),
            SignalsCollector.DEVICE_THREAT_BUDGET_MS * 10,
        )
        val events = SentomaruSignalEvents()
        val received = ArrayList<SentomaruSignalEvent>()
        events.addListener({ it.run() }) { received += it }
        collector.events = events
        val snapshot = collector.snapshot(context)
        assertEquals(SignalsCatalog.DEVICE_THREAT_CAPABILITY_IDS, snapshot.observations.map { it.capabilityId })
        // known_malware: no list loaded here, so UNKNOWN no_reference (KnownMalwareTest covers the match).
        assertTrue(snapshot.observations.filter { it.capabilityId != "known_malware" }.all { it.state == SignalState.DETECTED })
        assertEquals(SignalState.UNKNOWN, snapshot.observations.single { it.capabilityId == "known_malware" }.state)
        assertEquals(
            mapOf(
                "a11y_risk" to listOf("listed"), "overlay" to listOf("obscured"), "ime_untrusted" to listOf("unknown"),
                "synthetic_input" to listOf("virtual_pointer", "injected_touch"), "known_malware" to listOf("no_reference"),
            ),
            received.associate { it.capabilityId to it.reasonCodes },
        )
        assertEquals(listOf("accessibility_risk", "overlay", "ime_untrusted", "synthetic_input", "known_malware"), received.map { it.type })
        val text = received.joinToString { it.toString() } + snapshot.toJson()
        for (name in listOf("com.bad.service", "com.third.party.keyboard", "com.known.keyboard")) assertFalse(name, name in text)
    }

    // Revisao cruzada Shield #14 e #15: a read the collector discards must not erase the finding; the counts have a ceiling.

    /** A detector placed after [inner] that burns the whole budget, so [inner]'s read ends past the deadline. */
    private class Clockwork(var now: Long = 7_000_000_000L) { fun read() = now }

    private class SlowOverlay(private val inner: OverlayDetector, private val nanos: Clockwork) : SignalDetector by inner {
        override fun detect(context: Context): SignalObservation = inner.detect(context).also { nanos.now += 500_000_000L }
    }

    private class SlowSynthetic(private val inner: SyntheticInputDetector, private val nanos: Clockwork) : SignalDetector by inner {
        override fun detect(context: Context): SignalObservation = inner.detect(context).also { nanos.now += 500_000_000L }
    }

    @Test
    fun anOverrunReadGivesTheObscuredCountsBack() {
        val monitor = ObscuredTouchMonitor()
        monitor.record(true, 1); monitor.record(true, 0)
        val nanos = Clockwork()
        val overrun = SignalsCollector(clock, listOf(SlowOverlay(OverlayDetector(monitor, clock), nanos)), 100, nanos::read) { false }
            .snapshot(context)
        assertEquals(mapOf("timeout" to "overrun"), overrun.observations.single().detail)
        val next = OverlayDetector(monitor, clock).detect(context)
        assertEquals(SignalState.DETECTED, next.state)
        assertEquals(mapOf("result" to "obscured", "obscured" to "1", "touches" to "2"), next.detail)
    }

    @Test
    fun anOverrunReadGivesTheInjectedMarkBack() {
        val monitor = ObscuredTouchMonitor()
        monitor.record(true, 0x800)
        val nanos = Clockwork()
        SignalsCollector(clock, listOf(SlowSynthetic(SyntheticInputDetector(clock, ThreatEnv(), monitor), nanos)), 100, nanos::read) { false }
            .snapshot(context)
        assertEquals(mapOf("indicators" to "injected_touch"), SyntheticInputDetector(clock, ThreatEnv(), monitor).detect(context).detail)
    }

    @Test
    fun aGivenBackWindowAddsToTheTouchesThatArrivedMeanwhile() {
        val monitor = ObscuredTouchMonitor()
        monitor.record(true, 1)
        val detector = OverlayDetector(monitor, clock)
        detector.detect(context)               // drains 1/1
        monitor.record(true, 1)                // arrives while the read is being discarded
        detector.discarded(); detector.discarded()   // the second give-back has nothing left to give
        assertEquals(mapOf("result" to "obscured", "obscured" to "2", "touches" to "2"), detector.detect(context).detail)
    }

    @Test
    fun aReadThatWasKeptIsNotGivenBack() {
        val monitor = ObscuredTouchMonitor()
        monitor.record(true, 1)
        val collector = SignalsCollector(clock, listOf(OverlayDetector(monitor, clock)), null)
        assertEquals("obscured", collector.snapshot(context).observations.single().detail["result"])
        assertEquals("no_touches", OverlayDetector(monitor, clock).detect(context).detail["result"])
    }

    @Test
    fun theCountsSaturateAtTheCeiling() {
        val monitor = ObscuredTouchMonitor()
        repeat(ObscuredTouchMonitor.MAX_COUNT + 500) { monitor.record(true, 1) }
        val hit = OverlayDetector(monitor, clock).detect(context)
        val max = ObscuredTouchMonitor.MAX_COUNT.toString()
        assertEquals(mapOf("result" to "obscured", "obscured" to max, "touches" to max), hit.detail)
        // a give-back near the ceiling cannot pass it either
        repeat(ObscuredTouchMonitor.MAX_COUNT) { monitor.record(true, 1) }
        monitor.restore(ObscuredTouchMonitor.Window(ObscuredTouchMonitor.MAX_COUNT, ObscuredTouchMonitor.MAX_COUNT))
        assertEquals(mapOf("result" to "obscured", "obscured" to max, "touches" to max), OverlayDetector(monitor, clock).detect(context).detail)
    }
}
