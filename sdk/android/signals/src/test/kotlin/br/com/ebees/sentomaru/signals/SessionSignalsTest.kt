package br.com.ebees.sentomaru.signals

import android.content.Context
import br.com.ebees.sentomaru.signals.detectors.CallActiveDetector
import br.com.ebees.sentomaru.signals.detectors.LocationMockDetector
import org.junit.Assert.*
import org.junit.Test
import java.io.IOException
import java.time.Clock
import java.time.Instant
import java.time.ZoneOffset

/**
 * F-07 (`location_mock`) and F-08 (`call_active`), catalog 1.13.0, Android, by doubles. Every state and every failure;
 * a failure never gives NOT_DETECTED; no coordinate, provider, accuracy, time, number or app name goes in detail.
 */
class SessionSignalsTest {
    private val clock = Clock.fixed(Instant.parse("2026-11-05T12:00:00Z"), ZoneOffset.UTC)
    private val context: Context = object : android.content.ContextWrapper(null) {}

    open class SessionEnv(
        var sdk: Int = 34,
        var location: LocationFacts = LocationFacts(permission = true, fixAgeMs = 1_000, mock = false),
        var audioMode: Int = 0,
        var failure: Throwable? = null,
    ) : DetectorsTest.FakeEnv() {
        override fun osVersion(): Pair<Int, String> = Pair(sdk, sdk.toString())
        override fun lastKnownLocation(context: Context): LocationFacts { failure?.let { throw it }; return location }
        override fun audioMode(context: Context): Int { failure?.let { throw it }; return audioMode }
    }

    private val failures: List<Exception> = listOf(
        SecurityException("denied"), IOException("read failed"), IllegalStateException("service unavailable"),
        UnsupportedOperationException("not provided"),
    )

    private fun location(env: PlatformEnvironment) = LocationMockDetector(clock, env).detect(context)
    private fun call(env: PlatformEnvironment) = CallActiveDetector(clock, env).detect(context)

    // --- location_mock --------------------------------------------------------------------------------------------

    @Test
    fun aFixFlaggedAsMockIsDetected() {
        val o = location(SessionEnv(location = LocationFacts(true, 1_000, mock = true)))
        assertEquals(SignalState.DETECTED, o.state)
        assertEquals(mapOf("result" to "mock_flagged"), o.detail)
        assertEquals("location_mock", o.capabilityId)
        assertEquals("client_observed", o.source)
    }

    @Test
    fun aFreshFixNotFlaggedIsCleanForThatFixOnly() {
        val o = location(SessionEnv())
        assertEquals(SignalState.NOT_DETECTED, o.state)
        assertEquals(mapOf("result" to "clean"), o.detail)
    }

    @Test
    fun withoutThePermissionTheAppAlreadyHoldsItIsUnknownNeverClean() {
        val o = location(SessionEnv(location = LocationFacts(permission = false, fixAgeMs = null, mock = null)))
        assertEquals(SignalState.UNKNOWN, o.state)
        assertEquals(mapOf("result" to "no_permission"), o.detail)
    }

    @Test
    fun noFixOrAStaleFixIsUnknownNeverClean() {
        for (facts in listOf(LocationFacts(true, null, null), LocationFacts(true, 10 * 60_000L + 1, false), LocationFacts(true, 10 * 60_000L + 1, true))) {
            val o = location(SessionEnv(location = facts))
            assertEquals(facts.toString(), SignalState.UNKNOWN, o.state)
            assertEquals(mapOf("result" to "no_fix"), o.detail)
        }
        // The edge: exactly ten minutes old is still measured.
        assertEquals(SignalState.NOT_DETECTED, location(SessionEnv(location = LocationFacts(true, 10 * 60_000L, false))).state)
    }

    @Test
    fun aFixOfUnknownOriginIsUnknownNotClean() {
        val o = location(SessionEnv(location = LocationFacts(true, 1_000, mock = null)))
        assertEquals(SignalState.UNKNOWN, o.state)
        assertEquals(mapOf("result" to "partial"), o.detail)
    }

    @Test
    fun aFailedReadIsUnknownPartial() {
        for (failure in failures) {
            val o = location(SessionEnv(failure = failure))
            assertEquals(failure.toString(), SignalState.UNKNOWN, o.state)
            assertEquals(mapOf("result" to "partial"), o.detail)
        }
    }

    @Test
    fun locationBelowTheFirstSupportedApiIsUnsupported() {
        val o = location(SessionEnv(sdk = 27))
        assertEquals(SignalState.UNSUPPORTED, o.state)
        assertTrue(o.detail.isEmpty())
    }

    // --- call_active ----------------------------------------------------------------------------------------------

    @Test
    fun aCellularCallModeIsDetected() {
        val o = call(SessionEnv(audioMode = 2))
        assertEquals(SignalState.DETECTED, o.state)
        assertEquals(mapOf("result" to "cellular"), o.detail)
        assertEquals("call_active", o.capabilityId)
    }

    @Test
    fun aCommunicationModeIsDetectedAsCommunication() {
        val o = call(SessionEnv(audioMode = 3))
        assertEquals(SignalState.DETECTED, o.state)
        assertEquals(mapOf("result" to "communication"), o.detail)
    }

    @Test
    fun normalRingingAndScreeningAreNotAnActiveCall() {
        for (mode in listOf(0, 1, 4)) {
            val o = call(SessionEnv(audioMode = mode))
            assertEquals("mode $mode", SignalState.NOT_DETECTED, o.state)
            assertEquals(mapOf("result" to "none"), o.detail)
        }
    }

    @Test
    fun anUnknownModeIsUnknownNotClean() {
        for (mode in listOf(-2, -1, 5, 99)) {
            val o = call(SessionEnv(audioMode = mode))
            assertEquals("mode $mode", SignalState.UNKNOWN, o.state)
            assertEquals(mapOf("result" to "partial"), o.detail)
        }
    }

    @Test
    fun aFailedAudioReadIsUnknownPartial() {
        for (failure in failures) {
            val o = call(SessionEnv(failure = failure))
            assertEquals(failure.toString(), SignalState.UNKNOWN, o.state)
            assertEquals(mapOf("result" to "partial"), o.detail)
        }
    }

    // --- collector ------------------------------------------------------------------------------------------------

    @Test
    fun theSessionListHoldsExactlyTheTwoNewCapabilitiesAndIsOptIn() {
        val ids = SignalsCollector.sessionDetectors(clock, SessionEnv()).map { it.capabilityId }
        assertEquals(listOf("location_mock", "call_active"), ids)
        assertEquals(SignalsCatalog.SESSION_CAPABILITY_IDS, ids)
        for (other in listOf(
            SignalsCollector.defaultDetectors(), SignalsCollector.raspDetectors(),
            SignalsCollector.deviceThreatDetectors(), SignalsCollector.screenDetectors(),
        )) assertTrue(other.none { it.capabilityId in ids })
        assertEquals("1.15.0", SignalsCatalog.VERSION)
        assertEquals(SignalsCollector.SESSION_BUDGET_MS, SignalsCatalog.SESSION_CAPABILITY_IDS.sumOf { id ->
            SignalsCatalog.CAPABILITIES.first { it.capabilityId == id }.budgetMs
        })
    }
}

/**
 * Review A, F07-1: with only ACCESS_COARSE_LOCATION the GPS provider throws SecurityException; that must not discard the
 * fixes of the other providers, and GPS is not even asked without the fine permission.
 */
class LocationProvidersTest {
    @Test
    fun withOnlyCoarseTheGpsProviderIsNotAsked() {
        assertEquals(listOf("passive", "network"), LocationProviders.forPermission(fine = false))
        assertEquals(listOf("passive", "gps", "network"), LocationProviders.forPermission(fine = true))
    }

    @Test
    fun aProviderThatRefusesOrIsUnknownDoesNotDiscardTheOthers() {
        val read = { provider: String ->
            when (provider) {
                "gps" -> throw SecurityException("fine location needed")
                "network" -> throw IllegalArgumentException("no such provider")
                else -> provider.length
            }
        }
        assertEquals(listOf(7), LocationProviders.readEach(listOf("passive", "gps", "network"), read))
    }

    @Test
    fun everyProviderRefusingGivesNoFixNotAnError() {
        assertEquals(emptyList<Int>(), LocationProviders.readEach(listOf("passive", "network")) { throw SecurityException("denied") })
    }
}
