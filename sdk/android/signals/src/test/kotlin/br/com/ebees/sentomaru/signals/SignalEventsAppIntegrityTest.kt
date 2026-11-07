package br.com.ebees.sentomaru.signals

import android.content.Context
import br.com.ebees.sentomaru.signals.AppIntegrityDetectorsTest.IntegrityEnv
import br.com.ebees.sentomaru.signals.detectors.AppSignerMismatchDetector
import br.com.ebees.sentomaru.signals.detectors.CodeIntegrityDetector
import br.com.ebees.sentomaru.signals.detectors.InstallerClassDetector
import org.junit.Assert.*
import org.junit.Test
import java.io.IOException
import java.time.Clock
import java.time.Instant
import java.time.ZoneOffset
import java.util.concurrent.RejectedExecutionException

/**
 * D-15a: the allowlist against the real D-12c detectors run by doubles (every result, class, reason and cause they can
 * write), the lists locked, and reason codes that a listener cannot change.
 */
class SignalEventsAppIntegrityTest {
    private val clock = Clock.fixed(Instant.parse("2026-10-23T10:00:00Z"), ZoneOffset.UTC)
    private val context: Context = object : android.content.ContextWrapper(null) {}
    private val a = "a".repeat(64)
    private val c = "c".repeat(64)
    private val failures: List<Throwable> = listOf(
        SecurityException("denied"), IOException("read failed"), IllegalStateException("no signing info"),
        UnsupportedOperationException("API 30+"), NoClassDefFoundError("missing"), AbstractMethodError("old binary"),
    )

    /** Raw codes of [o] are all allowed, and none of them is dropped by the filter. */
    private fun assertCovered(o: SignalObservation): List<String> {
        val raw = SentomaruSignalEvents.rawReasonCodes(o.capabilityId, o.detail)
        assertTrue("${o.capabilityId} $raw", SignalsCatalog.EVENT_REASON_CODES.getValue(o.capabilityId).containsAll(raw))
        assertEquals(raw.distinct(), SentomaruSignalEvents.reasonCodes(o.capabilityId, o.detail))
        return raw
    }

    private fun cache(compute: (InstalledApks) -> ApkCodeDigests.Result) = CodeDigestCache(executor = { it.run() }, compute = compute)

    @Test
    fun theAllowlistCoversEverySignerResult() {
        val seen = mutableSetOf<String>()
        val runs = listOf(
            emptyList<String>() to IntegrityEnv(),
            listOf(a) to IntegrityEnv(),
            listOf(a) to IntegrityEnv(signers = listOf(a, c)),
            listOf(a) to IntegrityEnv(signers = emptyList()),
        ) + failures.map { listOf(a) to IntegrityEnv(failure = it) }
        for ((expected, env) in runs) seen += assertCovered(AppSignerMismatchDetector(expected, clock, env).detect(context))
        assertEquals(setOf("match", "mismatch", "no_reference", "unreadable"), seen)
    }

    @Test
    fun theAllowlistCoversEveryInstallerClass() {
        val seen = mutableSetOf<String>()
        val sources = listOf(
            InstallSource("com.android.vending", "com.android.vending"), InstallSource(null, null),
            InstallSource("com.example.store", "com.android.shell"), InstallSource("com.android.vending", null),
        )
        for (source in sources) seen += assertCovered(InstallerClassDetector(clock, IntegrityEnv(source = source)).detect(context))
        for (failure in failures) seen += assertCovered(InstallerClassDetector(clock, IntegrityEnv(failure = failure)).detect(context))
        assertTrue(seen.toString(), seen.containsAll(listOf("class_play", "class_none", "class_other", "class_unknown",
            "initiator_play", "initiator_none", "initiator_other", "initiator_unknown")))
    }

    @Test
    fun theAllowlistCoversEveryCodeIntegrityReasonAndCause() {
        val seen = mutableSetOf<String>()
        val computed = ApkCodeDigests.Result.Computed(listOf(ApkCodeDigests.CodeFile("classes.dex", a)), "f".repeat(64))
        fun run(env: PlatformEnvironment = IntegrityEnv(), cache: CodeDigestCache = cache { computed },
                mainThread: Boolean = false) {
            seen += assertCovered(CodeIntegrityDetector(clock, env, cache, waitMs = 0, onMainThread = { mainThread }).detect(context))
        }
        run()
        run(mainThread = true)
        run(env = IntegrityEnv(apks = InstalledApks(1L, emptyList())))
        for (failure in failures) run(env = IntegrityEnv(failure = failure))
        run(cache = CodeDigestCache(executor = { throw RejectedExecutionException("shut down") }) { computed })
        run(cache = CodeDigestCache(executor = { }) { computed }) // never completes: timeout
        run(cache = cache { throw IllegalStateException("hash") })
        val causes = listOf("apk_unreadable", "entry_unreadable", "duplicate_entry", "no_code_files", "too_many_files", "too_large")
        for (cause in causes) run(cache = cache { ApkCodeDigests.Result.Refused(cause) })
        assertEquals(SignalsCatalog.EVENT_REASON_CODES.getValue("code_integrity"), seen)
    }

    @Test
    fun theAllowlistsAreLocked() {
        val expected = mapOf(
            "debugger_attached" to "jdwp_connected,jdwp_waiting,partial,timeout",
            "app_debuggable" to "flag_debuggable,partial,timeout",
            "dev_settings_enabled" to "adb_enabled,development_settings,partial,timeout",
            "root_artifacts" to "build_props,build_type,manager_path,mountinfo,partial,root_package,su_path,test_keys,timeout",
            "emulator_indicated" to "build_props,partial,qemu_device,sensor_missing,timeout",
            "hook_framework_java" to "hook_frame,partial,timeout,xposed_class",
            "app_signer_mismatch" to "match,mismatch,no_reference,timeout,unreadable",
            "installer_class" to "class_none,class_other,class_play,class_unknown,initiator_none,initiator_other,initiator_play,initiator_unknown,timeout",
            "a11y_risk" to "listed,none,partial,timeout,unlisted_present",
            "overlay" to "clear,no_touches,obscured,timeout",
            "ime_untrusted" to "known,no_reference,partial,timeout,unknown",
            "synthetic_input" to "injected_touch,partial,timeout,virtual_pointer",
            "known_malware" to "clear,matched,no_reference,partial,timeout",
            "screen_capture" to "captured,no_screens,none,timeout",
            "screen_shared" to "partial,presentation_display,screen_recording,secondary_display,timeout",
            "location_mock" to "clean,mock_flagged,no_fix,no_permission,partial,timeout",
            "call_active" to "cellular,communication,none,partial,timeout",
            "code_integrity" to "apk_list,apk_unreadable,duplicate_entry,entry_unreadable,executor,hash_failed,main_thread,no_code_files,not_compared,partial,timeout,too_large,too_many_files",
        )
        assertEquals(expected, SignalsCatalog.EVENT_REASON_CODES.mapValues { it.value.sorted().joinToString(",") })
        assertEquals(SignalsCatalog.EVENT_TYPES.keys, SignalsCatalog.EVENT_REASON_CODES.keys)
    }

    @Test
    fun aListenerCannotChangeTheReasonCodes() {
        val codes = SentomaruSignalEvents.reasonCodes("app_signer_mismatch", mapOf("result" to "mismatch"))
        assertThrows(UnsupportedOperationException::class.java) { (codes as MutableList<String>).add("match") }
    }
}
