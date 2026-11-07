package br.com.ebees.sentomaru.signals

import android.content.Context
import br.com.ebees.sentomaru.signals.detectors.*
import org.junit.Assert.*
import org.junit.Test
import java.time.Clock
import java.time.Instant
import java.time.ZoneOffset

class DetectorsTest {
    private val clock = Clock.fixed(Instant.parse("2026-10-09T10:00:00Z"), ZoneOffset.UTC)
    private val dummyContext: Context = object : android.content.ContextWrapper(null) {}

    open class FakeEnv(
        var debuggerConnected: Boolean = false,
        var appDebuggable: Boolean = false,
        var buildProps: Map<String, String> = mapOf(
            "FINGERPRINT" to "google/oriole/oriole:14/UP1A.231005.007/10754064:user/release-keys",
            "MODEL" to "Pixel 6",
            "MANUFACTURER" to "Google",
            "HARDWARE" to "oriole",
            "PRODUCT" to "oriole",
            "BOARD" to "oriole",
            "TAGS" to "release-keys",
        ),
        var existingFiles: Set<String> = emptySet(),
        var certDigests: List<String> = listOf("a1b2c3d4e5f6"),
        var installerPkg: String? = "com.android.vending",
        var osVersionPair: Pair<Int, String> = Pair(35, "15"),
        var throwOnOperation: Boolean = false,
    ) : PlatformEnvironment {
        override fun isDebuggerConnected(): Boolean {
            if (throwOnOperation) throw RuntimeException("Simulated error")
            return debuggerConnected
        }
        override fun isAppDebuggable(context: Context): Boolean {
            if (throwOnOperation) throw RuntimeException("Simulated error")
            return appDebuggable
        }
        override fun buildProperties(): Map<String, String> {
            if (throwOnOperation) throw RuntimeException("Simulated error")
            return buildProps
        }
        override fun fileExists(path: String): Boolean {
            if (throwOnOperation) throw RuntimeException("Simulated error")
            return existingFiles.contains(path)
        }
        override fun getAppSigningCertificateDigests(context: Context): List<String> {
            if (throwOnOperation) throw RuntimeException("Simulated error")
            return certDigests
        }
        override fun getInstallerPackageName(context: Context): String? {
            if (throwOnOperation) throw RuntimeException("Simulated error")
            return installerPkg
        }
        override fun osVersion(): Pair<Int, String> {
            if (throwOnOperation) throw RuntimeException("Simulated error")
            return osVersionPair
        }
    }

    @Test
    fun debugAttachedDetectorDetectsDebuggerOrDebuggableFlag() {
        val env = FakeEnv(debuggerConnected = true, appDebuggable = false)
        val detector = DebugAttachedDetector(clock, env)
        val obs = detector.detect(dummyContext)
        assertEquals(SignalState.DETECTED, obs.state)
        assertEquals("true", obs.detail["debugger_connected"])

        val env2 = FakeEnv(debuggerConnected = false, appDebuggable = true)
        val obs2 = DebugAttachedDetector(clock, env2).detect(dummyContext)
        assertEquals(SignalState.DETECTED, obs2.state)

        val envClean = FakeEnv(debuggerConnected = false, appDebuggable = false)
        val obsClean = DebugAttachedDetector(clock, envClean).detect(dummyContext)
        assertEquals(SignalState.NOT_DETECTED, obsClean.state)

        val envError = FakeEnv(throwOnOperation = true)
        val obsError = DebugAttachedDetector(clock, envError).detect(dummyContext)
        assertEquals(SignalState.ERROR, obsError.state)
    }

    @Test
    fun emulatorDetectorFlagsKnownEmulatorIndicators() {
        val envClean = FakeEnv()
        val detector = EmulatorDetector(clock, envClean)
        val obsClean = detector.detect(dummyContext)
        assertEquals(SignalState.NOT_DETECTED, obsClean.state)
        assertEquals("none", obsClean.detail["matched_indicators"])

        val envEmu = FakeEnv(buildProps = mapOf(
            "FINGERPRINT" to "generic/sdk_gphone64_arm64/sdk_gphone64_arm64:14",
            "MODEL" to "sdk_gphone64_arm64",
            "HARDWARE" to "ranchu",
            "PRODUCT" to "sdk_gphone64_arm64",
            "MANUFACTURER" to "Google",
            "BOARD" to "goldfish_arm64",
            "TAGS" to "test-keys",
        ))
        val obsEmu = EmulatorDetector(clock, envEmu).detect(dummyContext)
        assertEquals(SignalState.DETECTED, obsEmu.state)
        assertTrue(obsEmu.detail["matched_indicators"]!!.contains("hardware"))

        val envError = FakeEnv(throwOnOperation = true)
        val obsError = EmulatorDetector(clock, envError).detect(dummyContext)
        assertEquals(SignalState.ERROR, obsError.state)
    }

    @Test
    fun rootIndicatedDetectorChecksTestKeysAndSuPathsWithoutShellExec() {
        val envClean = FakeEnv()
        val detector = RootIndicatedDetector(clock, envClean)
        val obsClean = detector.detect(dummyContext)
        assertEquals(SignalState.NOT_DETECTED, obsClean.state)
        assertEquals("false", obsClean.detail["su_found"])
        assertEquals("false", obsClean.detail["test_keys"])

        val envTestKeys = FakeEnv(buildProps = mapOf("TAGS" to "test-keys"))
        val obsTestKeys = RootIndicatedDetector(clock, envTestKeys).detect(dummyContext)
        assertEquals(SignalState.DETECTED, obsTestKeys.state)
        assertEquals("true", obsTestKeys.detail["test_keys"])

        val envSu = FakeEnv(existingFiles = setOf("/system/bin/su"))
        val obsSu = RootIndicatedDetector(clock, envSu).detect(dummyContext)
        assertEquals(SignalState.DETECTED, obsSu.state)
        assertEquals("true", obsSu.detail["su_found"])

        val envError = FakeEnv(throwOnOperation = true)
        val obsError = RootIndicatedDetector(clock, envError).detect(dummyContext)
        assertEquals(SignalState.ERROR, obsError.state)
    }

    @Test
    fun appSigningDigestDetectorComputesSha256Hex() {
        val env = FakeEnv(certDigests = listOf("abcd1234ef5678"))
        val detector = AppSigningDigestDetector(clock, env)
        val obs = detector.detect(dummyContext)
        assertEquals(SignalState.DETECTED, obs.state)
        assertEquals("abcd1234ef5678", obs.detail["sha256"])

        val envEmpty = FakeEnv(certDigests = emptyList())
        val obsEmpty = AppSigningDigestDetector(clock, envEmpty).detect(dummyContext)
        assertEquals(SignalState.UNKNOWN, obsEmpty.state)

        val envError = FakeEnv(throwOnOperation = true)
        val obsError = AppSigningDigestDetector(clock, envError).detect(dummyContext)
        assertEquals(SignalState.ERROR, obsError.state)
    }

    @Test
    fun installerSourceDetectorIdentifiesStoreOrSideload() {
        val envPlay = FakeEnv(installerPkg = "com.android.vending")
        val obsPlay = InstallerSourceDetector(clock, envPlay).detect(dummyContext)
        assertEquals(SignalState.DETECTED, obsPlay.state)
        assertEquals("com.android.vending", obsPlay.detail["installer_package"])

        val envSideload = FakeEnv(installerPkg = null)
        val obsSideload = InstallerSourceDetector(clock, envSideload).detect(dummyContext)
        assertEquals(SignalState.NOT_DETECTED, obsSideload.state)

        val envError = FakeEnv(throwOnOperation = true)
        val obsError = InstallerSourceDetector(clock, envError).detect(dummyContext)
        assertEquals(SignalState.ERROR, obsError.state)
    }

    @Test
    fun osVersionDetectorCapturesSdkAndRelease() {
        val env = FakeEnv(osVersionPair = Pair(35, "15"))
        val obs = OsVersionDetector(clock, env).detect(dummyContext)
        assertEquals(SignalState.DETECTED, obs.state)
        assertEquals("35", obs.detail["sdk_int"])
        assertEquals("15", obs.detail["release"])

        val envError = FakeEnv(throwOnOperation = true)
        val obsError = OsVersionDetector(clock, envError).detect(dummyContext)
        assertEquals(SignalState.ERROR, obsError.state)
    }

    @Test
    fun unmeasuredRootPathOrInstallerLookupIsErrorNeverNotDetected() {
        val fileCheckFails = object : FakeEnv() {
            override fun fileExists(path: String): Boolean = throw SecurityException("denied")
        }
        assertEquals(SignalState.ERROR, RootIndicatedDetector(clock, fileCheckFails).detect(dummyContext).state)

        val installerLookupFails = object : FakeEnv() {
            override fun getInstallerPackageName(context: Context): String? = throw IllegalStateException("lookup")
        }
        assertEquals(SignalState.ERROR, InstallerSourceDetector(clock, installerLookupFails).detect(dummyContext).state)
    }
}
