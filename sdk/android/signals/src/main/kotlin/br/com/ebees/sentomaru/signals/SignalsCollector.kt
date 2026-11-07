package br.com.ebees.sentomaru.signals

import android.content.Context
import android.os.Looper
import br.com.ebees.sentomaru.signals.detectors.*
import java.time.Clock

/**
 * Coordinator for collecting signals snapshot within budgeted time constraints.
 *
 * With `deadlineMs` (the D-05 opt-in) the collector refuses the main thread (`snapshot` throws
 * `IllegalStateException` before any detector runs) and times each detector on a monotonic clock. The deadline is
 * not preemptive: detectors run in order on the calling thread and none is interrupted, so a detector that hangs
 * stalls the collection. A detector that ends past the deadline is reported UNKNOWN with detail `timeout=overrun`,
 * even when it had found something (the late result is deliberately discarded: past the deadline the collector does
 * not vouch for it, and it is never read as clean); the ones not started before the deadline are UNKNOWN
 * `timeout=skipped`, and the collection goes on. With `defaultDetectors() + raspDetectors()` the D-05 detectors come
 * last, so they are the ones skipped under a tight deadline. Without `deadlineMs` (`SignalsCollector()`, the frozen
 * path the J-04 measures) nothing is refused or replaced, as before the D-05.
 *
 * In both modes a detector that throws (an `Error` included, e.g. `AbstractMethodError` from an environment compiled
 * before the D-05; never a `VirtualMachineError`) is reported ERROR with an empty detail, and the collection goes on.
 * The main-thread refusal is covered on the JVM by `SignalsCollectorDeadlineTest`; the StrictMode test
 * (`perf-app`, `SignalsStrictModeInstrumentedTest`) runs only on a device, with the D-05c.
 */
class SignalsCollector @JvmOverloads constructor(
    private val clock: Clock = Clock.systemUTC(),
    val detectors: List<SignalDetector> = defaultDetectors(clock),
    val deadlineMs: Long? = null,
    private val monotonicNanos: () -> Long = System::nanoTime,
    private val onMainThread: () -> Boolean = ::isAndroidMainThread,
) {
    /**
     * D-15a, opt-in: receives every snapshot this collector makes and emits signal events (see [SentomaruSignalEvents]),
     * e.g. `SignalsCollector(...).apply { events = signalEvents }`. Null (the default) = no events, as before. A property,
     * not a constructor parameter, so the constructor (and a trailing lambda for `onMainThread`) is unchanged.
     */
    @Volatile
    var events: SentomaruSignalEvents? = null

    init {
        val ids = detectors.map { it.capabilityId.lowercase() }
        require(ids.size == ids.toSet().size) { "Duplicate capabilityId in detectors" }
        require(deadlineMs == null || deadlineMs > 0) { "deadlineMs must be positive" }
    }

    companion object {
        const val CATALOG_VERSION = SignalsCatalog.VERSION
        const val OVERALL_BUDGET_MS = 50L

        /**
         * Per-collection deadline for a collection with the D-05 detectors: the cold p95 goal of the D-05c, and at
         * least the sum of the catalog `budgetMs` of all twelve capabilities. Kept after the D-05c measurement on the
         * the reference device (cold p95 84 ms; a cold run that overruns is reported, not failed).
         */
        const val RASP_DEADLINE_MS = 100L

        fun defaultDetectors(
            clock: Clock = Clock.systemUTC(),
            env: PlatformEnvironment = AndroidPlatformEnvironment,
        ): List<SignalDetector> = listOf(
            DebugAttachedDetector(clock, env),
            EmulatorDetector(clock, env),
            RootIndicatedDetector(clock, env),
            AppSigningDigestDetector(clock, env),
            InstallerSourceDetector(clock, env),
            OsVersionDetector(clock, env),
        )

        /**
         * D-05 RASP detectors (catalog 1.3.0), opt-in: never part of `defaultDetectors()`. Use with a deadline, e.g.
         * `SignalsCollector(detectors = defaultDetectors() + raspDetectors(), deadlineMs = RASP_DEADLINE_MS)`.
         */
        fun raspDetectors(
            clock: Clock = Clock.systemUTC(),
            env: PlatformEnvironment = AndroidPlatformEnvironment,
        ): List<SignalDetector> = listOf(
            DebuggerAttachedDetector(clock, env),
            AppDebuggableDetector(clock, env),
            DevSettingsEnabledDetector(clock, env),
            RootArtifactsDetector(clock, env),
            EmulatorIndicatedDetector(clock, env),
            HookFrameworkJavaDetector(clock, env),
        )

        /**
         * D-12c: sum of the catalog `budgetMs` of the three app integrity capabilities. A collection that adds them
         * gives its deadline this much more, e.g. `deadlineMs = RASP_DEADLINE_MS + APP_INTEGRITY_BUDGET_MS`.
         * Provisional until the D-12d measures them.
         */
        const val APP_INTEGRITY_BUDGET_MS = 35L

        /**
         * D-12c app integrity detectors (catalog 1.5.0), opt-in: never part of `defaultDetectors()` nor of
         * `raspDetectors()`. `app_signer_mismatch` compares the signing certificates with [expectedSignerDigests]
         * (empty = UNKNOWN `no_reference`), `installer_class` reads the installer class and `code_integrity` sends the
         * aggregate of the installed code, hashed in the background ([codeDigests]) and never on the main thread.
         * Use with a deadline, e.g. `SignalsCollector(detectors = defaultDetectors() + appIntegrityDetectors(listOf(digest)),
         * deadlineMs = RASP_DEADLINE_MS + APP_INTEGRITY_BUDGET_MS)`.
         */
        @JvmStatic
        @JvmOverloads
        fun appIntegrityDetectors(
            expectedSignerDigests: Collection<String>,
            clock: Clock = Clock.systemUTC(),
            env: PlatformEnvironment = AndroidPlatformEnvironment,
            codeDigests: CodeDigestCache = CodeDigestCache.shared,
        ): List<SignalDetector> = listOf(
            AppSignerMismatchDetector(expectedSignerDigests, clock, env),
            InstallerClassDetector(clock, env),
            CodeIntegrityDetector(clock, env, codeDigests),
        )

        /**
         * D-24: sum of the catalog `budgetMs` of the five device threat capabilities. A collection that adds them gives
         * its deadline this much more. Provisional until measured on a device.
         */
        const val DEVICE_THREAT_BUDGET_MS = 22L

        /**
         * D-24 device threat detectors (catalog 1.8.0; `known_malware` in 1.9.0), consultive and opt-in: never part of
         * the other lists.
         * [riskyAccessibilityPackages] is the app's list for `a11y_risk` (empty: it never gives `listed`),
         * [knownInputMethodPackages] the app's list of keyboards for `ime_untrusted` (empty: UNKNOWN `no_reference`);
         * `overlay` reads [touchMonitor], fed by the app's marked screens; `known_malware` reads [malwareLists] (no
         * valid list: UNKNOWN `no_reference`). No service, keyboard or package name leaves the detectors. Use with a deadline, e.g. `deadlineMs = RASP_DEADLINE_MS + DEVICE_THREAT_BUDGET_MS`.
         */
        @JvmStatic
        @JvmOverloads
        fun deviceThreatDetectors(
            riskyAccessibilityPackages: Collection<String> = emptyList(),
            knownInputMethodPackages: Collection<String> = emptyList(),
            touchMonitor: ObscuredTouchMonitor = ObscuredTouchMonitor.shared,
            clock: Clock = Clock.systemUTC(),
            env: PlatformEnvironment = AndroidPlatformEnvironment,
            malwareLists: MalwareListStore = MalwareListStore.shared,
        ): List<SignalDetector> = listOf(
            A11yRiskDetector(riskyAccessibilityPackages, clock, env),
            OverlayDetector(touchMonitor, clock),
            ImeUntrustedDetector(knownInputMethodPackages, clock, env),
            SyntheticInputDetector(clock, env, touchMonitor),
            KnownMalwareDetector(malwareLists, clock, env),
        )

        /**
         * D-20: sum of the catalog `budgetMs` of the two screen capabilities. Provisional until measured on a device.
         */
        const val SCREEN_BUDGET_MS = 4L

        /**
         * D-20 screen detectors (catalog 1.10.0), consultive and opt-in: never part of the other lists. `screen_capture`
         * reads [captureMonitor], fed by the [ScreenShield] the app installs on its marked screens; `screen_shared`
         * reads the visible displays and (API 35) the recording state. Only fixed codes leave the detectors. Use with
         * a deadline, e.g. `deadlineMs = RASP_DEADLINE_MS + SCREEN_BUDGET_MS`.
         */
        @JvmStatic
        @JvmOverloads
        fun screenDetectors(
            captureMonitor: ScreenCaptureMonitor = ScreenCaptureMonitor.shared,
            clock: Clock = Clock.systemUTC(),
            env: PlatformEnvironment = AndroidPlatformEnvironment,
        ): List<SignalDetector> = listOf(
            ScreenCaptureDetector(captureMonitor, clock, env),
            ScreenSharedDetector(clock, env),
        )

        /** F-07/F-08: sum of the catalog `budgetMs` of the two session capabilities. Provisional until measured on a device. */
        const val SESSION_BUDGET_MS = 6L

        /**
         * F-07/F-08 session context detectors (catalog 1.13.0), consultive and opt-in: never part of the other lists.
         * `location_mock` reads the origin flag of the last known location only when the app already holds a location
         * permission (the SDK never asks for it); `call_active` reads the system audio mode. Only fixed result codes
         * leave the detectors. Use with a deadline, e.g. `deadlineMs = RASP_DEADLINE_MS + SESSION_BUDGET_MS`.
         */
        @JvmStatic
        @JvmOverloads
        fun sessionDetectors(
            clock: Clock = Clock.systemUTC(),
            env: PlatformEnvironment = AndroidPlatformEnvironment,
        ): List<SignalDetector> = listOf(
            LocationMockDetector(clock, env),
            CallActiveDetector(clock, env),
        )

        private fun isAndroidMainThread(): Boolean = Looper.getMainLooper()?.isCurrentThread == true
    }

    /**
     * Each observation's `observedAt` is the instant its own detector ran in this call (never a cached or reused
     * value); `collectedAt` is the start of the collection, so `observedAt >= collectedAt`.
     */
    fun snapshot(context: Context): SignalsSnapshot {
        val deadline = deadlineMs
        if (deadline != null) check(!onMainThread()) { "Signals collection must not run on the main thread" }
        val start = monotonicNanos()
        val collectedAt = clock.instant().toString()
        val observations = if (deadline == null) {
            detectors.map { detectGuarded(it, context) }
        } else {
            val deadlineAt = start + deadline * 1_000_000L
            detectors.map { detector ->
                if (monotonicNanos() - deadlineAt >= 0) return@map timedOut(detector, "skipped")
                val observation = detectGuarded(detector, context)
                if (monotonicNanos() - deadlineAt > 0) { giveBack(detector); timedOut(detector, "overrun") } else observation
            }
        }
        val durationMs = (monotonicNanos() - start) / 1_000_000L

        val snapshot = SignalsSnapshot(
            catalogVersion = CATALOG_VERSION,
            collectedAt = collectedAt,
            durationMs = durationMs,
            observations = observations,
        )
        events?.observe(snapshot) // never throws: a listener's failure never reaches the collection
        return snapshot
    }

    // Backstop: a detector that throws costs only its own capability. The frozen detectors catch Exception themselves,
    // so for them this only changes an Error (which used to escape the collection) into ERROR.
    private fun detectGuarded(detector: SignalDetector, context: Context): SignalObservation = try {
        detector.detect(context)
    } catch (e: VirtualMachineError) {
        throw e
    } catch (e: Throwable) {
        if (e is InterruptedException) Thread.currentThread().interrupt()
        giveBack(detector)
        SignalObservation(
            capabilityId = detector.capabilityId,
            version = detector.version,
            state = SignalState.ERROR,
            source = "client_observed",
            observedAt = clock.instant().toString(),
        )
    }

    // The late result is discarded: past the deadline the collector does not vouch for it, and it is never clean.
    private fun giveBack(detector: SignalDetector) { try { detector.discarded() } catch (_: Exception) { /* a failed give-back costs only that window */ } }

    private fun timedOut(detector: SignalDetector, reason: String) = SignalObservation(
        capabilityId = detector.capabilityId,
        version = detector.version,
        state = SignalState.UNKNOWN,
        source = "client_observed",
        observedAt = clock.instant().toString(),
        detail = mapOf("timeout" to reason),
    )
}
