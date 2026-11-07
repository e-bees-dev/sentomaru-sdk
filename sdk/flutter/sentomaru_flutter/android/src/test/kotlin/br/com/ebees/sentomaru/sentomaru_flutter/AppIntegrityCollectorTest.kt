package br.com.ebees.sentomaru.sentomaru_flutter

import android.content.Context
import br.com.ebees.sentomaru.signals.ApkFile
import br.com.ebees.sentomaru.signals.CodeDigestCache
import br.com.ebees.sentomaru.signals.InstallSource
import br.com.ebees.sentomaru.signals.InstalledApks
import br.com.ebees.sentomaru.signals.PlatformEnvironment
import br.com.ebees.sentomaru.signals.SignalState
import br.com.ebees.sentomaru.signals.SignalsCatalog
import br.com.ebees.sentomaru.signals.SignalsCollector
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNotEquals
import org.junit.Assert.assertNull
import org.junit.Assert.assertThrows
import org.junit.Assert.assertTrue
import org.junit.Test
import java.io.IOException
import java.util.concurrent.Executor

/**
 * D-12e: the collector `collectSignalsSnapshot` builds with `expectedSignerDigests`, and what it reports through doubles
 * of the platform. Without the list both 0.12.0 collectors are unchanged; no failure becomes NOT_DETECTED.
 */
class AppIntegrityCollectorTest {
    private val context: Context = object : android.content.ContextWrapper(null) {}
    private val digest = "a".repeat(64)
    private val direct = CodeDigestCache(executor = Executor { it.run() })

    /** Every platform call throws [failure]; the D-12c ones too (an old environment throws by default). */
    private class FailingEnv(private val failure: Throwable) : PlatformEnvironment {
        override fun isDebuggerConnected(): Boolean = throw failure
        override fun isAppDebuggable(context: Context): Boolean = throw failure
        override fun buildProperties(): Map<String, String> = throw failure
        override fun fileExists(path: String): Boolean = throw failure
        override fun getAppSigningCertificateDigests(context: Context): List<String> = throw failure
        override fun getInstallerPackageName(context: Context): String? = throw failure
        override fun osVersion(): Pair<Int, String> = throw failure
        override fun signingCertificateDigests(context: Context): List<String> = throw failure
        override fun installSource(context: Context): InstallSource = throw failure
        override fun installedApks(context: Context): InstalledApks = throw failure
    }

    /** The three D-12c calls answer; the six default ones throw (they are not under test here). */
    private class IntegrityEnv(val signers: List<String>, val source: InstallSource, val apks: InstalledApks) : PlatformEnvironment {
        override fun isDebuggerConnected(): Boolean = throw UnsupportedOperationException()
        override fun isAppDebuggable(context: Context): Boolean = throw UnsupportedOperationException()
        override fun buildProperties(): Map<String, String> = throw UnsupportedOperationException()
        override fun fileExists(path: String): Boolean = throw UnsupportedOperationException()
        override fun getAppSigningCertificateDigests(context: Context): List<String> = throw UnsupportedOperationException()
        override fun getInstallerPackageName(context: Context): String? = throw UnsupportedOperationException()
        override fun osVersion(): Pair<Int, String> = throw UnsupportedOperationException()
        override fun signingCertificateDigests(context: Context) = signers
        override fun installSource(context: Context) = source
        override fun installedApks(context: Context) = apks
    }

    @Test fun withoutTheListBothOldCollectorsAreUnchanged() {
        val plain = SentomaruFlutterPlugin.signalsCollector(rasp = false, expectedSignerDigests = null)
        assertEquals(SignalsCatalog.DEFAULT_CAPABILITY_IDS, plain.detectors.map { it.capabilityId })
        assertNull(plain.deadlineMs)
        val rasp = SentomaruFlutterPlugin.signalsCollector(rasp = true, expectedSignerDigests = null)
        assertEquals(SignalsCatalog.DEFAULT_CAPABILITY_IDS + SignalsCatalog.RASP_CAPABILITY_IDS, rasp.detectors.map { it.capabilityId })
        assertEquals(SignalsCollector.RASP_DEADLINE_MS, rasp.deadlineMs)
    }

    @Test fun theListAddsTheThreeLastAndThirtyFiveMsMoreOnlyWithRasp() {
        val deadline = SignalsCollector.RASP_DEADLINE_MS + SignalsCollector.APP_INTEGRITY_BUDGET_MS
        assertEquals(135L, deadline)
        val only = SentomaruFlutterPlugin.signalsCollector(rasp = false, expectedSignerDigests = listOf(digest))
        assertEquals(SignalsCatalog.DEFAULT_CAPABILITY_IDS + SignalsCatalog.APP_INTEGRITY_CAPABILITY_IDS,
            only.detectors.map { it.capabilityId })
        assertNull(only.deadlineMs) // review R: the six frozen ones never get a deadline without rasp
        val all = SentomaruFlutterPlugin.signalsCollector(rasp = true, expectedSignerDigests = emptyList())
        assertEquals(SignalsCatalog.DEFAULT_CAPABILITY_IDS + SignalsCatalog.RASP_CAPABILITY_IDS +
            SignalsCatalog.APP_INTEGRITY_CAPABILITY_IDS, all.detectors.map { it.capabilityId })
        assertEquals(deadline, all.deadlineMs)
    }

    @Test fun theChannelListIsReadStrictly() {
        assertNull(SentomaruFlutterPlugin.expectedSignerDigests(null))
        assertEquals(listOf(digest), SentomaruFlutterPlugin.expectedSignerDigests(listOf(digest)))
        for (bad in listOf<Any>(digest, listOf(digest, 1), mapOf("a" to digest), listOf(null)))
            assertThrows(IllegalArgumentException::class.java) { SentomaruFlutterPlugin.expectedSignerDigests(bad) }
        // A value that is not a SHA-256 is refused when the collector is built (the plugin replies ConfigurationError).
        assertThrows(IllegalArgumentException::class.java) {
            SentomaruFlutterPlugin.signalsCollector(rasp = false, expectedSignerDigests = listOf("abc"))
        }
    }

    @Test fun noPlatformFailureBecomesNotDetected() {
        val failures = listOf(SecurityException("denied"), IOException("read"), IllegalStateException("x"),
            UnsupportedOperationException("API 30+"), RuntimeException("NameNotFound"), NoClassDefFoundError("missing"),
            AbstractMethodError("old binary"))
        for (failure in failures) for (rasp in listOf(false, true)) {
            val snapshot = SentomaruFlutterPlugin.signalsCollector(rasp, listOf(digest), FailingEnv(failure), direct)
                .snapshot(context)
            val byId = snapshot.observations.associateBy { it.capabilityId }
            assertTrue(byId.keys.containsAll(SignalsCatalog.APP_INTEGRITY_CAPABILITY_IDS))
            for (o in snapshot.observations) assertNotEquals("$failure ${o.capabilityId}", SignalState.NOT_DETECTED, o.state)
            assertEquals("unreadable", byId.getValue("app_signer_mismatch").detail["result"])
            assertEquals("unknown", byId.getValue("installer_class").detail["class"])
            assertEquals(SignalState.UNKNOWN, byId.getValue("code_integrity").state)
            val reply = SentomaruFlutterPlugin.snapshotReply(snapshot)
            @Suppress("UNCHECKED_CAST")
            val states = (reply["observations"] as List<Map<String, Any>>).map { it["state"] }
            assertTrue(states.none { it == "not_detected" })
        }
    }

    @Test fun eachReadingReachesTheReplyWithoutDigestsNorPackageNames() {
        val other = "c".repeat(64)
        val apk = InstalledApks(1L, listOf(ApkFile("/data/app/does-not-exist/base.apk", 10L)))
        val cases = listOf(
            Triple(listOf(digest), InstallSource("com.android.vending", "com.android.vending"), "not_detected"),
            Triple(listOf(other), InstallSource(null, "com.android.shell"), "detected"),
        )
        for ((signers, source, signerState) in cases) {
            val snapshot = SentomaruFlutterPlugin.signalsCollector(false, listOf(digest), IntegrityEnv(signers, source, apk), direct)
                .snapshot(context)
            @Suppress("UNCHECKED_CAST")
            val obs = (SentomaruFlutterPlugin.snapshotReply(snapshot)["observations"] as List<Map<String, Any>>)
                .associateBy { it["capabilityId"] }
            assertEquals(signerState, obs.getValue("app_signer_mismatch")["state"])
            assertEquals("detected", obs.getValue("installer_class")["state"])
            assertEquals("unknown", obs.getValue("code_integrity")["state"]) // the APK cannot be read: partial
            val text = obs.values.joinToString { it["data"].toString() }
            for (secret in listOf(digest, other, "com.android", "/data/app")) assertTrue(text, secret !in text)
        }
    }
}
