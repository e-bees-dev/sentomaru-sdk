package br.com.ebees.sentomaru.perf

import android.content.Context
import android.os.Bundle
import android.os.Debug
import android.os.SystemClock
import androidx.test.ext.junit.runners.AndroidJUnit4
import androidx.test.platform.app.InstrumentationRegistry
import br.com.ebees.sentomaru.core.SentomaruException
import br.com.ebees.sentomaru.sdk.AndroidInstallationKeys
import br.com.ebees.sentomaru.signals.AndroidPlatformEnvironment
import br.com.ebees.sentomaru.signals.ApkCodeDigests
import br.com.ebees.sentomaru.signals.CodeDigestCache
import br.com.ebees.sentomaru.signals.SignalsCollector
import org.json.JSONObject
import org.junit.Test
import org.junit.runner.RunWith
import java.io.File
import java.security.SecureRandom
import java.util.concurrent.TimeUnit

/**
 * D-12d cost of the D-12c app integrity signals and of the reattestation key, driven by the vendor's run d12d cost check
 * (never in CI). Arguments:
 * - `d12d` = `warm` or `cold`; absent, the test returns at once (as `RaspCostInstrumentedTest`);
 * - `signer`: the lowercase hex SHA-256 of the lab signing certificate, the list `app_signer_mismatch` expects;
 * - cold: `target`, one run, the first call of a fresh process:
 *   - `code_integrity_hash`: `ApkCodeDigests.compute` over the installed APKs, on this thread (the hash itself, wall and
 *     CPU; right after an install when the runner reinstalled the app first);
 *   - `code_integrity`: the detector as an app calls it (its 15 ms wait on the shared cache), then `code_integrity_ready`:
 *     wall time from that call until the background hash (minimum priority thread) is done, and `code_integrity_cached`:
 *     the next call, served from the cache;
 *   - `app_signer_mismatch`, `installer_class`: the detector's first call;
 *   - `reattest_key`: what `SentomaruReattestation` does to the Keystore (delete the alias, generate the attested
 *     EC P-256 key with a 32-byte challenge and read its chain, delete it), through the SDK's `AndroidInstallationKeys`;
 * - warm: the cache filled first; `warmup` (default 30) then `runs` (default 300) rounds of the three detectors and of
 *   `collection` (defaultDetectors() + raspDetectors() + appIntegrityDetectors(), deadline RASP + APP_INTEGRITY), built
 *   once and reused; then `keyWarmup` (default 5) and `keyRuns` (default 100) `reattest_key`; one StrongBox attempt.
 * Every result carries `installSource` (the platform names behind `installer_class`, allowlisted, else `redacted`).
 * Off the main thread (checked). The JSON goes to the instrumentation result `d12d`.
 */
@RunWith(AndroidJUnit4::class)
class AppIntegrityCostInstrumentedTest {

    @Test
    fun app_integrity_cost() {
        val instrumentation = InstrumentationRegistry.getInstrumentation()
        val arguments = InstrumentationRegistry.getArguments()
        val mode = arguments.getString("d12d") ?: return
        RaspCost.requireWorkerThread()
        val context = instrumentation.targetContext
        val signer = requireNotNull(arguments.getString("signer")) { "signer argument required" }
        val result = JSONObject().put("mode", mode).put("selinuxDomain", RaspCost.selinuxDomain())
            .put("installSource", installSource(context))
        val targets = JSONObject()
        try {
            when (mode) {
                "cold" -> {
                    val target = requireNotNull(arguments.getString("target")) { "target argument required" }
                    cold(context, signer, target, targets)
                }
                "warm" -> {
                    val runs = arguments.getString("runs")?.toInt() ?: 300
                    val warmup = arguments.getString("warmup")?.toInt() ?: 30
                    val keyRuns = arguments.getString("keyRuns")?.toInt() ?: 100
                    val keyWarmup = arguments.getString("keyWarmup")?.toInt() ?: 5
                    warm(context, signer, runs, warmup, keyRuns, keyWarmup, targets, result)
                    result.put("runs", runs).put("warmup", warmup).put("keyRuns", keyRuns).put("keyWarmup", keyWarmup)
                }
                else -> throw IllegalArgumentException("d12d must be warm or cold")
            }
        } finally {
            instrumentation.addResults(Bundle().apply { putString("d12d", result.put("targets", targets).toString()) })
        }
    }

    private fun cold(context: Context, signer: String, target: String, targets: JSONObject) {
        val tally = Tally()
        when (target) {
            HASH -> {
                val files = AndroidPlatformEnvironment.installedApks(context).files.map { File(it.path) }
                var outcome: ApkCodeDigests.Result? = null
                RaspCost.timed(tally) { outcome = ApkCodeDigests.compute(files); emptyList() }
                targets.put(HASH, tally.toJson().put("result", describe(outcome)))
            }
            CODE -> {
                val detector = detectors(signer).first { it.capabilityId == CODE }
                val start = SystemClock.elapsedRealtimeNanos()
                RaspCost.timed(tally) { RaspCost.detectOnce(detector, context) }
                val apks = AndroidPlatformEnvironment.installedApks(context)
                CodeDigestCache.shared.resultFor(apks).get(120, TimeUnit.SECONDS)
                val readyUs = (SystemClock.elapsedRealtimeNanos() - start) / 1_000
                targets.put(CODE, tally.toJson())
                targets.put("${CODE}_ready", Tally().apply { add(readyUs, -1, emptyList()) }.toJson())
                val cached = Tally()
                RaspCost.timed(cached) { RaspCost.detectOnce(detector, context) }
                targets.put("${CODE}_cached", cached.toJson())
            }
            SIGNER, INSTALLER -> {
                val detector = detectors(signer).first { it.capabilityId == target }
                RaspCost.timed(tally) { RaspCost.detectOnce(detector, context) }
                targets.put(target, tally.toJson())
            }
            KEY -> {
                val keys = AndroidInstallationKeys()
                var chain = 0
                timedKey(tally) { chain = reattestKey(keys, strongBox = false) }
                targets.put(KEY, tally.toJson().put("chainLength", chain))
            }
            else -> throw IllegalArgumentException("unknown target")
        }
    }

    private fun warm(context: Context, signer: String, runs: Int, warmup: Int, keyRuns: Int, keyWarmup: Int,
                     targets: JSONObject, result: JSONObject) {
        val detectors = detectors(signer)
        val collector = SignalsCollector(
            detectors = SignalsCollector.defaultDetectors() + SignalsCollector.raspDetectors() + detectors,
            deadlineMs = SignalsCollector.RASP_DEADLINE_MS + SignalsCollector.APP_INTEGRITY_BUDGET_MS,
        )
        CodeDigestCache.shared.resultFor(AndroidPlatformEnvironment.installedApks(context)).get(120, TimeUnit.SECONDS)
        val tallies = (detectors.map { it.capabilityId } + RaspCost.COLLECTION).associateWith { Tally() }
        val discard = Tally()
        repeat(warmup + runs) { round ->
            for (detector in detectors) {
                RaspCost.timed(if (round < warmup) discard else tallies.getValue(detector.capabilityId)) {
                    RaspCost.detectOnce(detector, context)
                }
            }
            RaspCost.timed(if (round < warmup) discard else tallies.getValue(RaspCost.COLLECTION)) {
                collector.snapshot(context).observations
            }
        }
        tallies.forEach { (id, tally) -> targets.put(id, tally.toJson()) }

        val keys = AndroidInstallationKeys()
        val key = Tally()
        val discardKey = Tally()
        var chain = 0
        repeat(keyWarmup + keyRuns) { round ->
            timedKey(if (round < keyWarmup) discardKey else key) { chain = reattestKey(keys, strongBox = false) }
        }
        targets.put(KEY, key.toJson().put("chainLength", chain))

        // One StrongBox attempt (the SDK's `strongBox = true`): reported, never timed into the key samples.
        val strongBox = Tally()
        val outcome = try {
            timedKey(strongBox) { reattestKey(keys, strongBox = true) }
            "generated"
        } catch (e: Exception) {
            // A SentomaruException carries a fixed code (e.g. `StrongBoxUnavailable`); anything else, its class name.
            val name = (e as? SentomaruException)?.message ?: e.javaClass.simpleName
            name.takeIf { Regex("[A-Za-z]{1,60}").matches(it) } ?: "redacted"
        } finally {
            try { keys.delete(ALIAS) } catch (_: Exception) { }
        }
        result.put("strongBox", JSONObject().put("outcome", outcome).put("tally", strongBox.toJson()))
    }

    private fun detectors(signer: String) = SignalsCollector.appIntegrityDetectors(listOf(signer))

    /**
     * The Keystore steps of `SentomaruReattestation.freeze` (delete, generate with the challenge and read the chain,
     * delete), in order; returns the chain length. The challenge request, `client.sign` and both network calls are not
     * measured.
     */
    private fun reattestKey(keys: AndroidInstallationKeys, strongBox: Boolean): Int {
        keys.delete(ALIAS)
        val challenge = ByteArray(32).also { SecureRandom().nextBytes(it) }
        val material = try {
            keys.generate(ALIAS, challenge, strongBox)
        } finally {
            keys.delete(ALIAS)
        }
        return material.chain().size
    }

    private inline fun timedKey(tally: Tally, block: () -> Unit) {
        val cpu0 = Debug.threadCpuTimeNanos()
        val wall0 = SystemClock.elapsedRealtimeNanos()
        block()
        val wall = SystemClock.elapsedRealtimeNanos() - wall0
        val cpu1 = Debug.threadCpuTimeNanos()
        tally.add(wall / 1_000, if (cpu0 < 0 || cpu1 < 0) -1 else (cpu1 - cpu0) / 1_000, emptyList())
    }

    private fun describe(outcome: ApkCodeDigests.Result?): JSONObject = when (outcome) {
        is ApkCodeDigests.Result.Computed -> JSONObject().put("computed", true).put("files", outcome.files.size)
            .put("aggregate", outcome.aggregate)
        is ApkCodeDigests.Result.Refused -> JSONObject().put("computed", false).put("cause", outcome.cause)
        null -> JSONObject().put("computed", false)
    }

    /** The names behind `installer_class` (API 30+), each allowlisted or `redacted`; null = none recorded. */
    private fun installSource(context: Context): JSONObject = try {
        val info = context.packageManager.getInstallSourceInfo(context.packageName)
        JSONObject().put("installing", known(info.installingPackageName))
            .put("initiating", known(info.initiatingPackageName))
            .put("originating", known(info.originatingPackageName))
    } catch (e: Exception) {
        JSONObject().put("error", e.javaClass.simpleName)
    }

    private fun known(name: String?): Any = when (name) {
        null -> JSONObject.NULL
        in KNOWN_INSTALLERS -> name
        else -> "redacted"
    }

    private companion object {
        const val HASH = "code_integrity_hash"
        const val CODE = "code_integrity"
        const val SIGNER = "app_signer_mismatch"
        const val INSTALLER = "installer_class"
        const val KEY = "reattest_key"
        // The SDK's alias shape (`sentomaru.v1.<scope>.reattest`) in this lab app's own Keystore namespace (its uid).
        const val ALIAS = "sentomaru.v1.00000000000000000000000000000000000000000000000000000000000d12d0.reattest"
        val KNOWN_INSTALLERS = setOf("com.android.shell", "com.android.vending", "com.google.android.packageinstaller",
            "com.android.packageinstaller", "com.samsung.android.packageinstaller")
    }
}
