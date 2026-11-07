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
 * D-12c: `app_signer_mismatch` and `installer_class` by doubles, every state and every failure. No failure gives
 * NOT_DETECTED; no digest nor package name goes in detail.
 */
class AppIntegrityDetectorsTest {
    private val clock = Clock.fixed(Instant.parse("2026-10-23T10:00:00Z"), ZoneOffset.UTC)
    private val context: Context = object : android.content.ContextWrapper(null) {}

    private val a = "a".repeat(64)
    private val b = "b".repeat(64)
    private val c = "c".repeat(64)

    /** Double of the D-12c platform calls; [failure] non-null makes the call throw it. */
    class IntegrityEnv(
        var signers: List<String> = listOf("a".repeat(64)),
        var source: InstallSource = InstallSource("com.android.vending", "com.android.vending"),
        var apks: InstalledApks = InstalledApks(1L, listOf(ApkFile("/data/app/base.apk", 10L))),
        var failure: Throwable? = null,
    ) : DetectorsTest.FakeEnv() {
        private fun guard() { failure?.let { throw it } }
        override fun signingCertificateDigests(context: Context): List<String> { guard(); return signers }
        override fun installSource(context: Context): InstallSource { guard(); return source }
        override fun installedApks(context: Context): InstalledApks { guard(); return apks }
    }

    private val failures: List<Throwable> = listOf(
        SecurityException("denied"), IOException("read failed"), IllegalStateException("no signing info"),
        UnsupportedOperationException("API 30+"), RuntimeException("NameNotFound"), NoClassDefFoundError("missing"),
        AbstractMethodError("old binary"),
    )

    private fun signer(expected: List<String>, env: PlatformEnvironment) =
        AppSignerMismatchDetector(expected, clock, env).detect(context)

    @Test
    fun signerMatchWhenEveryDigestReadIsExpected() {
        val obs = signer(listOf(a, b), IntegrityEnv(signers = listOf(a, b)))
        assertEquals(SignalState.NOT_DETECTED, obs.state)
        assertEquals(mapOf("result" to "match", "signers" to "2", "unexpected" to "0"), obs.detail)
        assertEquals("client_observed", obs.source)
    }

    @Test
    fun signerMismatchWhenAnyDigestIsNotExpectedWithCountsOnly() {
        val obs = signer(listOf(a), IntegrityEnv(signers = listOf(c)))
        assertEquals(SignalState.DETECTED, obs.state)
        assertEquals(mapOf("result" to "mismatch", "signers" to "1", "unexpected" to "1"), obs.detail)
        // Rotation lineage: the old certificate is in the history and not expected → mismatch (all must be expected).
        val rotated = signer(listOf(b), IntegrityEnv(signers = listOf(a, b)))
        assertEquals(SignalState.DETECTED, rotated.state)
        assertEquals("1", rotated.detail["unexpected"])
        for (o in listOf(obs, rotated)) assertTrue(o.detail.values.none { it.length >= 32 })
    }

    @Test
    fun signerAcceptsKeytoolFormAndUppercaseInBothLists() {
        val keytool = a.uppercase().chunked(2).joinToString(":")
        assertEquals(SignalState.NOT_DETECTED, signer(listOf(keytool), IntegrityEnv(signers = listOf(a.uppercase()))).state)
    }

    @Test
    fun signerRefusesAnExpectedValueThatIsNotASha256() {
        for (bad in listOf("", "abc", "g".repeat(64), "a".repeat(63), "a".repeat(65))) {
            assertThrows(IllegalArgumentException::class.java) { AppSignerMismatchDetector(listOf(bad), clock, IntegrityEnv()) }
        }
    }

    @Test
    fun signerWithoutReferenceIsUnknownAndDoesNotRead() {
        val env = IntegrityEnv(failure = AssertionError("must not read"))
        val obs = signer(emptyList(), env)
        assertEquals(SignalState.UNKNOWN, obs.state)
        assertEquals(mapOf("result" to "no_reference"), obs.detail)
    }

    @Test
    fun signerReadFailureIsUnknownNeverNotDetected() {
        for (failure in failures) {
            val obs = signer(listOf(a), IntegrityEnv(failure = failure))
            assertEquals(failure.toString(), SignalState.UNKNOWN, obs.state)
            assertEquals(mapOf("result" to "unreadable"), obs.detail)
        }
        for (read in listOf(emptyList(), listOf("not-a-digest"), listOf(a, "zz"))) {
            val obs = signer(listOf(a), IntegrityEnv(signers = read))
            assertEquals(read.toString(), SignalState.UNKNOWN, obs.state)
            assertEquals("unreadable", obs.detail["result"])
        }
    }

    @Test
    fun signerEnvironmentWrittenBeforeD12cIsUnknown() {
        // FakeEnv does not override the D-12c calls: the interface default throws.
        val obs = signer(listOf(a), DetectorsTest.FakeEnv())
        assertEquals(SignalState.UNKNOWN, obs.state)
        assertEquals("unreadable", obs.detail["result"])
    }

    @Test
    fun installerClassIsAValueSignalWithFixedClasses() {
        fun detect(installing: String?, initiating: String?) =
            InstallerClassDetector(clock, IntegrityEnv(source = InstallSource(installing, initiating))).detect(context)
        val play = detect("com.android.vending", "com.android.vending")
        assertEquals(SignalState.DETECTED, play.state)
        assertEquals(mapOf("class" to "play", "initiator" to "play"), play.detail)
        val sideload = detect(null, null)
        assertEquals(SignalState.DETECTED, sideload.state)
        assertEquals(mapOf("class" to "none", "initiator" to "none"), sideload.detail)
        val other = detect("com.google.android.packageinstaller", "com.android.shell")
        assertEquals(mapOf("class" to "other", "initiator" to "other"), other.detail)
        assertEquals(mapOf("class" to "none", "initiator" to "none"), detect("", "").detail)
        for (o in listOf(play, sideload, other)) assertTrue(o.detail.values.none { it.contains('.') })
    }

    @Test
    fun installerClassFailureIsUnknownNeverNotDetected() {
        for (failure in failures) {
            val obs = InstallerClassDetector(clock, IntegrityEnv(failure = failure)).detect(context)
            assertEquals(failure.toString(), SignalState.UNKNOWN, obs.state)
            assertEquals(mapOf("class" to "unknown", "initiator" to "unknown"), obs.detail)
        }
        assertEquals(SignalState.UNKNOWN, InstallerClassDetector(clock, DetectorsTest.FakeEnv()).detect(context).state)
    }

    @Test
    fun appIntegrityDetectorsAreOptInAndMatchTheCatalog() {
        val ids = SignalsCollector.appIntegrityDetectors(listOf(a), clock, IntegrityEnv()).map { it.capabilityId }
        assertEquals(SignalsCatalog.APP_INTEGRITY_CAPABILITY_IDS, ids)
        val defaults = SignalsCollector.defaultDetectors(clock, IntegrityEnv()).map { it.capabilityId }
        val rasp = SignalsCollector.raspDetectors(clock, IntegrityEnv()).map { it.capabilityId }
        assertEquals(SignalsCatalog.DEFAULT_CAPABILITY_IDS, defaults)
        assertEquals(SignalsCatalog.RASP_CAPABILITY_IDS, rasp)
        assertTrue(ids.none { it in defaults || it in rasp })
        assertEquals(6, SignalsCollector().detectors.size)
    }

    @Test
    fun everyAppIntegrityObservationStateIsInItsCatalogEntry() {
        val states = SignalsCatalog.CAPABILITIES.associate { it.capabilityId to it.supportedStates }
        val envs = listOf(IntegrityEnv(), IntegrityEnv(signers = listOf(c)), IntegrityEnv(source = InstallSource(null, null))) +
            failures.map { IntegrityEnv(failure = it) }
        val cache = CodeDigestCache(executor = { it.run() }) { ApkCodeDigests.Result.Refused("apk_unreadable") }
        for (env in envs) for (detector in SignalsCollector.appIntegrityDetectors(listOf(a), clock, env, cache)) {
            val obs = detector.detect(context)
            assertTrue("${detector.capabilityId} ${obs.state}", obs.state in states.getValue(detector.capabilityId))
            assertEquals(detector.version, SignalsCatalog.CAPABILITIES.single { it.capabilityId == detector.capabilityId }.version)
        }
    }

    @Test
    fun allFifteenFitTheFourKibSignalsHeader() {
        val env = IntegrityEnv(signers = listOf(a, b, c))
        val computed = ApkCodeDigests.Result.Computed(listOf(ApkCodeDigests.CodeFile("classes.dex", a)), "f".repeat(64))
        val cache = CodeDigestCache(executor = { it.run() }) { computed }
        val detectors = SignalsCollector.defaultDetectors(clock, env) + SignalsCollector.raspDetectors(clock, env) +
            SignalsCollector.appIntegrityDetectors(listOf(a), clock, env, cache)
        val snapshot = SignalsCollector(clock, detectors).snapshot(context)
        assertEquals(15, snapshot.observations.size)
        assertEquals("f".repeat(64), snapshot.observations.single { it.capabilityId == "code_integrity" }.detail["aggregate"])
        val bytes = snapshot.toJson().toByteArray(Charsets.UTF_8).size
        assertTrue("snapshot is $bytes bytes", bytes <= 4096) // SignalsHeader.MAX_LENGTH in the sdk module
    }
}
