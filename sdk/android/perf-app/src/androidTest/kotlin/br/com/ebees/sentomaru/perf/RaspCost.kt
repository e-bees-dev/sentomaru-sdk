package br.com.ebees.sentomaru.perf

import android.content.Context
import android.os.Debug
import android.os.Looper
import android.os.SystemClock
import br.com.ebees.sentomaru.signals.SignalDetector
import br.com.ebees.sentomaru.signals.SignalObservation
import br.com.ebees.sentomaru.signals.SignalState
import br.com.ebees.sentomaru.signals.SignalsCollector
import org.json.JSONArray
import org.json.JSONObject
import java.io.File

/**
 * D-05c measurement helpers shared by `RaspCostInstrumentedTest` and `RaspBatterySessionInstrumentedTest`.
 * The targets are the twelve client_observed capabilities (`defaultDetectors()` then `raspDetectors()`, the catalog
 * order) and `collection`: `defaultDetectors() + raspDetectors()` with `RASP_DEADLINE_MS`, the D-05 opt-in.
 */
internal object RaspCost {
    const val COLLECTION = "collection"

    fun detectors(): List<SignalDetector> = SignalsCollector.defaultDetectors() + SignalsCollector.raspDetectors()

    fun collector(): SignalsCollector =
        SignalsCollector(detectors = detectors(), deadlineMs = SignalsCollector.RASP_DEADLINE_MS)

    /** The D-05 collection never runs on the main thread (the collector refuses it; the cost is measured off it). */
    fun requireWorkerThread() {
        check(Looper.myLooper() != Looper.getMainLooper()) { "D-05c measures off the main thread" }
    }

    /**
     * Wall time on the monotonic clock (`elapsedRealtimeNanos`) and CPU time of this thread
     * (`Debug.threadCpuTimeNanos`, -1 when the device does not support it), in microseconds.
     */
    inline fun timed(tally: Tally, block: () -> List<SignalObservation>) {
        val cpu0 = Debug.threadCpuTimeNanos()
        val wall0 = SystemClock.elapsedRealtimeNanos()
        val observations = block()
        val wall = SystemClock.elapsedRealtimeNanos() - wall0
        val cpu1 = Debug.threadCpuTimeNanos()
        tally.add(wall / 1_000, if (cpu0 < 0 || cpu1 < 0) -1 else (cpu1 - cpu0) / 1_000, observations)
    }

    /** One detector, guarded like the collector does: a throw is ERROR with detail `thrown=1` (never clean). */
    fun detectOnce(detector: SignalDetector, context: Context): List<SignalObservation> = listOf(
        try {
            detector.detect(context)
        } catch (e: VirtualMachineError) {
            throw e
        } catch (e: Throwable) {
            SignalObservation(detector.capabilityId, detector.version, SignalState.ERROR,
                observedAt = "", detail = mapOf("thrown" to "1"))
        }
    )

    /** SELinux domain of this process (e.g. `untrusted_app`), the access context of the stat and read checks. */
    fun selinuxDomain(): String? = try {
        File("/proc/self/attr/current").readText().trim().trimEnd('\u0000').split(":").getOrNull(2)
            ?.takeIf { Regex("[a-z_]{1,40}").matches(it) }
    } catch (e: Exception) {
        null
    }
}

/**
 * Samples and outcomes of one target. `states` and `details` count per capability (one for a single detector,
 * twelve for the collection); `details` keys are `key=value` of the fixed detail codes (never a path or package).
 */
internal class Tally {
    private val wallUs = JSONArray()
    private val cpuUs = JSONArray()
    private val states = sortedMapOf<String, MutableMap<String, Int>>()
    private val details = sortedMapOf<String, MutableMap<String, Int>>()

    fun add(wall: Long, cpu: Long, observations: List<SignalObservation>) {
        wallUs.put(wall)
        cpuUs.put(cpu)
        countOnly(observations)
    }

    fun countOnly(observations: List<SignalObservation>) {
        for (o in observations) {
            states.getOrPut(o.capabilityId) { sortedMapOf() }.merge(o.state.name, 1, Int::plus)
            for ((k, v) in o.detail) details.getOrPut(o.capabilityId) { sortedMapOf() }.merge("$k=$v", 1, Int::plus)
        }
    }

    fun toJson(samples: Boolean = true): JSONObject = JSONObject().apply {
        if (samples) put("wallUs", wallUs).put("cpuUs", cpuUs)
        put("states", JSONObject(states.mapValues { JSONObject(it.value as Map<*, *>) }))
        put("details", JSONObject(details.mapValues { JSONObject(it.value as Map<*, *>) }))
    }
}
