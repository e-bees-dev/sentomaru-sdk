package br.com.ebees.sentomaru.signals

import android.content.Context
import br.com.ebees.sentomaru.signals.detectors.*
import org.junit.Assert.*
import org.junit.Test
import java.time.Clock
import java.time.Instant
import java.time.ZoneOffset

class SignalsCollectorTest {
    private val clock = Clock.fixed(Instant.parse("2026-10-09T10:00:00Z"), ZoneOffset.UTC)
    private val dummyContext: Context = object : android.content.ContextWrapper(null) {}

    private val fakeEnv = DetectorsTest.FakeEnv()

    @Test
    fun snapshotCollectsAllSixCapabilitiesWithinBudget() {
        val detectors = listOf(
            DebugAttachedDetector(clock, fakeEnv),
            EmulatorDetector(clock, fakeEnv),
            RootIndicatedDetector(clock, fakeEnv),
            AppSigningDigestDetector(clock, fakeEnv),
            InstallerSourceDetector(clock, fakeEnv),
            OsVersionDetector(clock, fakeEnv),
        )
        val collector = SignalsCollector(clock, detectors)

        val snapshot = collector.snapshot(dummyContext)
        assertEquals(SignalsCatalog.VERSION, snapshot.catalogVersion)
        assertEquals("2026-10-09T10:00:00Z", snapshot.collectedAt)
        assertEquals(6, snapshot.observations.size)

        // SDK-SIG-4: Budget check
        assertTrue("Snapshot execution must be within overall budget", snapshot.durationMs < SignalsCollector.OVERALL_BUDGET_MS)

        val capabilityIds = snapshot.observations.map { it.capabilityId }.toSet()
        assertEquals(
            setOf("debug_attached", "emulator_detected", "root_indicated", "app_signing_digest", "installer_source", "os_version"),
            capabilityIds,
        )

        for (obs in snapshot.observations) {
            assertEquals("client_observed", obs.source)
            assertEquals("1.0.0", obs.version)
            assertEquals("2026-10-09T10:00:00Z", obs.observedAt)
            assertNotNull(obs.state)
        }
    }

    @Test
    fun privacyGuardrailEnsuresNoSensitiveIdentifiersCollected() {
        // SDK-SIG-6: Ensure no IMEI, serial, MAC, IP, location, account, token or key in observations
        val forbiddenTerms = listOf("imei", "serial", "mac", "ip", "latitude", "longitude", "token", "secret", "private_key")

        val detectors = listOf(
            DebugAttachedDetector(clock, fakeEnv),
            EmulatorDetector(clock, fakeEnv),
            RootIndicatedDetector(clock, fakeEnv),
            AppSigningDigestDetector(clock, fakeEnv),
            InstallerSourceDetector(clock, fakeEnv),
            OsVersionDetector(clock, fakeEnv),
        )
        val collector = SignalsCollector(clock, detectors)
        val snapshot = collector.snapshot(dummyContext)

        for (obs in snapshot.observations) {
            for ((key, value) in obs.detail) {
                val keyLower = key.lowercase()
                val valLower = value.lowercase()
                for (term in forbiddenTerms) {
                    assertFalse("Detail key '$key' must not contain sensitive term '$term'", keyLower.contains(term))
                }
            }
        }
    }

    @Test
    fun productionDetectorsAreExactlyTheCatalogAndNoUnmeasuredCapabilityIsReported() {
        val production = SignalsCollector.defaultDetectors(clock, fakeEnv).map { it.capabilityId }
        // D-05: the default set stays the frozen six; the RASP set is opt-in and completes the catalog.
        assertEquals(SignalsCatalog.DEFAULT_CAPABILITY_IDS, production)
        val rasp = SignalsCollector.raspDetectors(clock, fakeEnv).map { it.capabilityId }
        assertEquals(SignalsCatalog.DEFAULT_CAPABILITY_IDS + SignalsCatalog.RASP_CAPABILITY_IDS, production + rasp)
        // D-12c: the app integrity set is opt-in too and completes the catalog.
        val appIntegrity = SignalsCollector.appIntegrityDetectors(emptyList(), clock, fakeEnv).map { it.capabilityId }
        // D-24: the device threat set is opt-in too and completes the catalog.
        val deviceThreat = SignalsCollector.deviceThreatDetectors(emptyList(), emptyList(), ObscuredTouchMonitor(), clock, fakeEnv)
            .map { it.capabilityId }
        assertEquals(SignalsCatalog.DEVICE_THREAT_CAPABILITY_IDS, deviceThreat)
        // D-20: the screen set is opt-in too and completes the catalog.
        val screen = SignalsCollector.screenDetectors(ScreenCaptureMonitor(), clock, fakeEnv).map { it.capabilityId }
        assertEquals(SignalsCatalog.SCREEN_CAPABILITY_IDS, screen)
        // F-07/F-08: the session set is opt-in too and completes the catalog.
        val session = SignalsCollector.sessionDetectors(clock, fakeEnv).map { it.capabilityId }
        assertEquals(SignalsCatalog.SESSION_CAPABILITY_IDS, session)
        assertEquals(SignalsCatalog.CAPABILITIES.map { it.capabilityId }, production + rasp + appIntegrity + deviceThreat + screen + session)
        assertTrue(rasp.none { it in production })
        for (stub in listOf("mock_location_detected", "accessibility_bot_detected", "virtual_sandbox_detected")) {
            assertFalse("$stub is not measured and must not be reported", stub in production)
        }
    }

    @Test
    fun duplicateCapabilityIdsAreRejectedInCollectorAndSnapshot() {
        assertThrows(IllegalArgumentException::class.java) {
            SignalsCollector(clock, listOf(OsVersionDetector(clock, fakeEnv), OsVersionDetector(clock, fakeEnv)))
        }
        val obs = SignalObservation("root_indicated", "1.0.0", SignalState.NOT_DETECTED, observedAt = "2026-10-09T10:00:00Z")
        assertThrows(IllegalArgumentException::class.java) {
            SignalsSnapshot("1.0.0", "2026-10-09T10:00:00Z", 1, listOf(obs, obs.copy(capabilityId = "ROOT_INDICATED")))
        }
    }

    @Test
    fun observedAtIsTheDetectionInstantOfEachDetector() {
        val ticking = object : Clock() {
            private var t = Instant.parse("2026-10-09T10:00:00Z")
            override fun instant(): Instant = t.also { t = t.plusSeconds(1) }
            override fun getZone() = ZoneOffset.UTC
            override fun withZone(zone: java.time.ZoneId?) = this
        }
        val snapshot = SignalsCollector(ticking, SignalsCollector.defaultDetectors(ticking, fakeEnv)).snapshot(dummyContext)
        val collected = Instant.parse(snapshot.collectedAt)
        val observed = snapshot.observations.map { Instant.parse(it.observedAt) }
        assertTrue(observed.all { !it.isBefore(collected) })
        assertEquals("each detector stamps its own run", observed.size, observed.toSet().size)
    }
}
