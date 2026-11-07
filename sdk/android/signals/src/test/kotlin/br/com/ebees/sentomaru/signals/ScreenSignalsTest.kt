package br.com.ebees.sentomaru.signals

import android.content.Context
import br.com.ebees.sentomaru.signals.detectors.ScreenCaptureDetector
import br.com.ebees.sentomaru.signals.detectors.ScreenSharedDetector
import org.junit.Assert.*
import org.junit.Test
import java.io.IOException
import java.time.Clock
import java.time.Instant
import java.time.ZoneOffset

/**
 * D-20 (Android, runtime): `screen_capture` and `screen_shared` by doubles, and the decisions of the [ScreenShield]
 * ([ScreenShieldCore]) without a device. Every state and every failure; a failure never gives NOT_DETECTED; no screen,
 * display or app name goes in detail or in an event.
 */
class ScreenSignalsTest {
    private val clock = Clock.fixed(Instant.parse("2026-11-04T20:00:00Z"), ZoneOffset.UTC)
    private val context: Context = object : android.content.ContextWrapper(null) {}

    open class ScreenEnv(
        var sdk: Int = 35,
        var displays: List<DisplayFacts> = listOf(DisplayFacts(isDefault = true, presentation = false)),
        var recording: Boolean? = false,
        var failure: Throwable? = null,
    ) : DetectorsTest.FakeEnv() {
        override fun osVersion(): Pair<Int, String> = Pair(sdk, sdk.toString())
        override fun visibleDisplays(context: Context): List<DisplayFacts> { failure?.let { throw it }; return displays }
        override fun screenRecordingVisible(): Boolean = recording ?: throw IllegalStateException("not reported")
    }

    private val failures: List<Throwable> = listOf(
        SecurityException("denied"), IOException("read failed"), IllegalStateException("manager unavailable"),
        UnsupportedOperationException("not provided"), NoClassDefFoundError("missing"), AbstractMethodError("old binary"),
    )

    private fun capture(monitor: ScreenCaptureMonitor, env: PlatformEnvironment = ScreenEnv()) =
        ScreenCaptureDetector(monitor, clock, env).detect(context)

    private fun shared(env: PlatformEnvironment) = ScreenSharedDetector(clock, env).detect(context)

    // --- screen_capture -------------------------------------------------------------------------------------------

    // Revisão A (G-02), SC-01: a janela que o coletor descarta (prazo estourado) volta ao monitor, como a do `overlay`;
    // sem isso a captura feita nela some e a janela seguinte diz "none".
    @Test
    fun a_window_the_collector_discards_gives_its_captures_back() {
        val monitor = ScreenCaptureMonitor().apply { arm(); onCapture(); onCapture() }
        val detector = ScreenCaptureDetector(monitor, clock, ScreenEnv())
        val first = detector.detect(context)
        assertEquals("2", first.detail["captures"])
        detector.discarded()
        val again = detector.detect(context)
        assertEquals(SignalState.DETECTED, again.state)
        assertEquals("2", again.detail["captures"])
        detector.discarded(); detector.discarded() // a second give-back adds nothing
        assertEquals(SignalState.DETECTED, detector.detect(context).state)
        assertEquals("none", detector.detect(context).detail["result"]) // taken, not given back: cleared
    }

    @Test
    fun captureWithoutAMarkedScreenIsUnknownNeverClean() {
        val o = capture(ScreenCaptureMonitor())
        assertEquals(SignalState.UNKNOWN, o.state)
        assertEquals(mapOf("result" to "no_screens"), o.detail)
    }

    @Test
    fun captureNoneNeedsAMarkedScreenInTheWindow() {
        val monitor = ScreenCaptureMonitor().also { it.arm() }
        val o = capture(monitor)
        assertEquals(SignalState.NOT_DETECTED, o.state)
        assertEquals(mapOf("result" to "none", "captures" to "0"), o.detail)
        // Still in front in the next window: the screen is still measured.
        assertEquals(SignalState.NOT_DETECTED, capture(monitor).state)
        // After the screen left, the window after the one in which it left is not measured.
        monitor.disarm()
        capture(monitor)
        assertEquals(SignalState.UNKNOWN, capture(monitor).state)
    }

    @Test
    fun captureCountsAreCappedAndClearedByTheRead() {
        val monitor = ScreenCaptureMonitor().also { it.arm() }
        repeat(25) { monitor.onCapture() }
        val o = capture(monitor)
        assertEquals(SignalState.DETECTED, o.state)
        assertEquals(mapOf("result" to "captured", "captures" to "9"), o.detail)
        assertEquals("none", capture(monitor).detail["result"])
    }

    @Test
    fun captureBelowApi34IsUnsupportedAndKeepsTheCount() {
        val monitor = ScreenCaptureMonitor().also { it.arm(); it.onCapture() }
        val o = capture(monitor, ScreenEnv(sdk = 33))
        assertEquals(SignalState.UNSUPPORTED, o.state)
        assertTrue(o.detail.isEmpty())
        assertEquals(SignalState.DETECTED, capture(monitor, ScreenEnv(sdk = 34)).state)
    }

    @Test
    fun captureFailureOfTheOsReadIsUnknown() {
        for (failure in failures.filterIsInstance<Exception>()) {
            val env = object : ScreenEnv() { override fun osVersion(): Pair<Int, String> = throw failure }
            val o = capture(ScreenCaptureMonitor().also { it.arm() }, env)
            assertEquals(failure.toString(), SignalState.UNKNOWN, o.state)
        }
    }

    // --- screen_shared --------------------------------------------------------------------------------------------

    @Test
    fun sharedCleanOnlyWhenDisplaysAndRecordingWereRead() {
        val o = shared(ScreenEnv())
        assertEquals(SignalState.NOT_DETECTED, o.state)
        assertEquals(mapOf("indicators" to "none"), o.detail)
    }

    @Test
    fun sharedIndicatorsAreFixedCodes() {
        val presentation = shared(ScreenEnv(displays = listOf(DisplayFacts(true, false), DisplayFacts(false, true))))
        assertEquals(SignalState.DETECTED, presentation.state)
        assertEquals("presentation_display", presentation.detail["indicators"])

        val secondary = shared(ScreenEnv(displays = listOf(DisplayFacts(true, false), DisplayFacts(false, false))))
        assertEquals(SignalState.DETECTED, secondary.state)
        assertEquals("secondary_display", secondary.detail["indicators"])

        val recording = shared(ScreenEnv(recording = true))
        assertEquals(SignalState.DETECTED, recording.state)
        assertEquals("screen_recording", recording.detail["indicators"])

        val all = shared(ScreenEnv(displays = listOf(DisplayFacts(true, false), DisplayFacts(false, true),
            DisplayFacts(false, false)), recording = true))
        assertEquals("presentation_display,secondary_display,screen_recording", all.detail["indicators"])
    }

    @Test
    fun sharedRecordingNotReportedNeverGivesClean() {
        // Below API 35 (or no permission) the recording state is never reported: nothing found stays UNKNOWN.
        val o = shared(ScreenEnv(recording = null))
        assertEquals(SignalState.UNKNOWN, o.state)
        assertEquals("screen_recording", o.detail["partial"])
        // A display found is still evidence, with the unmeasured check marked.
        val found = shared(ScreenEnv(recording = null, displays = listOf(DisplayFacts(true, false), DisplayFacts(false, true))))
        assertEquals(SignalState.DETECTED, found.state)
        assertEquals("screen_recording", found.detail["partial"])
    }

    @Test
    fun sharedDisplayReadFailureIsUnknownNeverClean() {
        for (failure in failures) {
            val o = shared(ScreenEnv(failure = failure))
            assertEquals(failure.toString(), SignalState.UNKNOWN, o.state)
            assertEquals("display", o.detail["partial"])
        }
    }

    // --- events and what leaves the detector ----------------------------------------------------------------------

    @Test
    fun everyCodeTheDetectorsEmitIsAnAllowedEventCode() {
        val monitor = ScreenCaptureMonitor().also { it.arm() }
        val observations = listOf(
            capture(ScreenCaptureMonitor()), capture(monitor),
            capture(ScreenCaptureMonitor().also { it.arm(); it.onCapture() }),
            shared(ScreenEnv()), shared(ScreenEnv(recording = true)), shared(ScreenEnv(recording = null)),
            shared(ScreenEnv(failure = SecurityException("denied"))),
            shared(ScreenEnv(displays = listOf(DisplayFacts(true, false), DisplayFacts(false, true), DisplayFacts(false, false)))),
        )
        for (o in observations) {
            val raw = SentomaruSignalEvents.rawReasonCodes(o.capabilityId, o.detail)
            assertTrue("${o.capabilityId} $raw", SignalsCatalog.EVENT_REASON_CODES.getValue(o.capabilityId).containsAll(raw))
            assertEquals(raw.distinct(), SentomaruSignalEvents.reasonCodes(o.capabilityId, o.detail))
        }
    }

    @Test
    fun noNameOrIdentifierGoesInDetail() {
        val monitor = ScreenCaptureMonitor().also { it.arm(); it.onCapture() }
        val all = listOf(
            capture(monitor), shared(ScreenEnv(recording = true, displays = listOf(DisplayFacts(false, true)))),
        )
        for (o in all) for ((k, v) in o.detail) {
            assertTrue("$k=$v", k in setOf("result", "captures", "indicators", "partial"))
            assertTrue("$k=$v", Regex("^[a-z0-9_,]{1,64}$").matches(v))
        }
    }

    // --- ScreenShield decisions -----------------------------------------------------------------------------------

    private class FakePlatform(var captureApi: Boolean = true) : ShieldPlatform<String> {
        val secured = ArrayList<String>()
        val registered = ArrayList<String>()
        val unregistered = ArrayList<String>()
        var callbacks = HashMap<String, () -> Unit>()
        var failSecure = false
        override fun secure(screen: String) { if (failSecure) throw IllegalStateException("window"); secured += screen }
        override fun registerCapture(screen: String, onCapture: () -> Unit): Any? {
            if (!captureApi) return null
            registered += screen; callbacks[screen] = onCapture; return "handle-$screen"
        }
        override fun unregisterCapture(screen: String, handle: Any) { unregistered += screen; assertEquals("handle-$screen", handle) }
    }

    @Test
    fun shieldTouchesOnlyTheListedScreens() {
        val platform = FakePlatform()
        val core = ScreenShieldCore(setOf("app.Pay"), platform, ScreenCaptureMonitor())
        core.created("pay-1", "app.Pay"); core.created("home-1", "app.Home")
        core.started("pay-1", "app.Pay"); core.started("home-1", "app.Home")
        assertEquals(listOf("pay-1"), platform.secured)
        assertEquals(listOf("pay-1"), platform.registered)
        core.stopped("home-1")
        assertTrue(platform.unregistered.isEmpty())
    }

    @Test
    fun shieldCountsACaptureOnlyWhileTheMarkedScreenIsStarted() {
        val monitor = ScreenCaptureMonitor()
        val platform = FakePlatform()
        val core = ScreenShieldCore(setOf("app.Pay"), platform, monitor)
        core.started("pay-1", "app.Pay")
        platform.callbacks.getValue("pay-1")()
        assertEquals(SignalState.DETECTED, capture(monitor).state)
        core.stopped("pay-1")
        assertEquals(listOf("pay-1"), platform.unregistered)
        // Stopped twice (stop and destroy) unregisters once and never drives the armed count below zero.
        core.stopped("pay-1")
        assertEquals(listOf("pay-1"), platform.unregistered)
        capture(monitor)
        assertEquals(SignalState.UNKNOWN, capture(monitor).state)
    }

    @Test
    fun shieldStartedTwiceRegistersOnce() {
        val platform = FakePlatform()
        val core = ScreenShieldCore(setOf("app.Pay"), platform, ScreenCaptureMonitor())
        core.started("pay-1", "app.Pay"); core.started("pay-1", "app.Pay")
        assertEquals(1, platform.registered.size)
    }

    @Test
    fun shieldWithoutACaptureApiStillSecuresAndNeverArms() {
        val monitor = ScreenCaptureMonitor()
        val platform = FakePlatform(captureApi = false)
        val core = ScreenShieldCore(setOf("app.Pay"), platform, monitor)
        core.created("pay-1", "app.Pay"); core.started("pay-1", "app.Pay")
        assertEquals(listOf("pay-1"), platform.secured)
        assertEquals(SignalState.UNKNOWN, capture(monitor).state)
    }

    @Test
    fun shieldAWindowThatRefusesTheFlagDoesNotCrashTheApp() {
        val platform = FakePlatform().also { it.failSecure = true }
        val core = ScreenShieldCore(setOf("app.Pay"), platform, ScreenCaptureMonitor())
        core.created("pay-1", "app.Pay")
        assertTrue(platform.secured.isEmpty())
    }

    // --- D-20 scope `all` (bloco 18) ---------------------------------------------------------------------------------

    @Test
    fun scopeMarkedKeepsTheOldShapeEvenWhenAnUnmarkedScreenIsStarted() {
        val monitor = ScreenCaptureMonitor()
        val platform = FakePlatform()
        val core = ScreenShieldCore(setOf("app.Pay"), platform, monitor) // default scope = MARKED
        core.started("home-1", "app.Home")
        assertTrue(platform.registered.isEmpty())
        val seen = capture(monitor)
        assertEquals(SignalState.UNKNOWN, seen.state)
        assertEquals(linkedMapOf("result" to "no_screens"), seen.detail)
        core.started("pay-1", "app.Pay"); platform.callbacks.getValue("pay-1")()
        val captured = capture(monitor)
        assertEquals(linkedMapOf("result" to "captured", "captures" to "1"), captured.detail) // no captures_other
        assertEquals("1.1.0", captured.version)
    }

    @Test
    fun scopeAllCountsAnUnmarkedCaptureApartAndNeverSecuresIt() {
        val monitor = ScreenCaptureMonitor().apply { scopeAll = true }
        val platform = FakePlatform()
        val core = ScreenShieldCore(setOf("app.Pay"), platform, monitor, CaptureScope.ALL)
        core.created("home-1", "app.Home"); core.created("pay-1", "app.Pay")
        core.started("home-1", "app.Home")
        assertEquals(listOf("pay-1"), platform.secured) // FLAG_SECURE only where marked
        assertEquals(listOf("home-1"), platform.registered)
        platform.callbacks.getValue("home-1")(); platform.callbacks.getValue("home-1")()
        val observation = capture(monitor)
        assertEquals(SignalState.DETECTED, observation.state)
        assertEquals(linkedMapOf("result" to "captured", "captures" to "0", "captures_other" to "2"), observation.detail)
        // the window is cleared by the read; the home screen is still registered, so it is "none", not "no_screens"
        val next = capture(monitor)
        assertEquals(SignalState.NOT_DETECTED, next.state)
        assertEquals(linkedMapOf("result" to "none", "captures" to "0", "captures_other" to "0"), next.detail)
        core.stopped("home-1")
        capture(monitor)
        assertEquals(SignalState.UNKNOWN, capture(monitor).state)
    }

    @Test
    fun scopeAllKeepsMarkedAndUnmarkedCountsSeparateAndCapped() {
        val monitor = ScreenCaptureMonitor().apply { scopeAll = true }
        val platform = FakePlatform()
        val core = ScreenShieldCore(setOf("app.Pay"), platform, monitor, CaptureScope.ALL)
        core.started("pay-1", "app.Pay"); core.started("home-1", "app.Home")
        platform.callbacks.getValue("pay-1")()
        repeat(15) { platform.callbacks.getValue("home-1")() }
        val detail = capture(monitor).detail
        assertEquals("1", detail["captures"])
        assertEquals("9", detail["captures_other"])
    }

    @Test
    fun scopeAllDiscardedWindowGivesBothCountsBack() {
        val monitor = ScreenCaptureMonitor().apply { scopeAll = true; arm(false); onCapture(false); onCapture(true) }
        val detector = ScreenCaptureDetector(monitor, clock, ScreenEnv())
        assertEquals("1", detector.detect(context).detail["captures_other"])
        detector.discarded()
        val again = detector.detect(context)
        assertEquals("1", again.detail["captures"])
        assertEquals("1", again.detail["captures_other"])
    }

    @Test
    fun scopeAllAddsOnlyANumberToDetailNeverANameOrId() {
        val monitor = ScreenCaptureMonitor().apply { scopeAll = true; arm(false); onCapture(false) }
        val detail = capture(monitor).detail
        assertEquals(setOf("result", "captures", "captures_other"), detail.keys)
        assertTrue(detail.values.all { it.length <= 8 })
    }

    @Test
    fun hostEntryParsesOnlyTheTwoScopeNames() {
        assertEquals(CaptureScope.MARKED, ScreenShieldHost.parseScope("marked"))
        assertEquals(CaptureScope.ALL, ScreenShieldHost.parseScope("all"))
        for (bad in listOf("ALL", "Marked", "", " all", "everything", null)) {
            assertThrows(IllegalArgumentException::class.java) { ScreenShieldHost.parseScope(bad) }
        }
    }

    // Revisor B (bloco 22): a second install with another scope or set used to return the first shield in silence.
    @Test
    fun aSecondInstallWithAnotherScopeOrActivitiesIsRefusedAndTheSameOneIsIdempotent() {
        ScreenShieldHost.resetForTest()
        try {
            val first = ScreenShield(setOf("app.Pay"), ScreenCaptureMonitor(), CaptureScope.MARKED)
            var created = 0
            val make = { created++; first }
            assertSame(first, ScreenShieldHost.register(CaptureScope.MARKED, setOf("app.Pay"), make))
            assertSame(first, ScreenShieldHost.register(CaptureScope.MARKED, setOf("app.Pay"), make))
            assertEquals(1, created)
            assertThrows(IllegalStateException::class.java) { ScreenShieldHost.register(CaptureScope.ALL, setOf("app.Pay"), make) }
            assertThrows(IllegalStateException::class.java) { ScreenShieldHost.register(CaptureScope.MARKED, setOf("app.Pay", "app.Other"), make) }
            assertEquals(1, created)
        } finally {
            ScreenShieldHost.resetForTest()
        }
    }
}
