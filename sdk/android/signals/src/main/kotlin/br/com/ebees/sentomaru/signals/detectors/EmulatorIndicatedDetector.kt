package br.com.ebees.sentomaru.signals.detectors

import android.content.Context
import android.hardware.Sensor
import br.com.ebees.sentomaru.signals.*
import java.time.Clock

/**
 * D-05: emulator indicators. A reviewed Build list (no bare "sdk" substring, which matched real products), QEMU and
 * goldfish device files, and a missing accelerometer. An image that spoofs all three is not detected.
 */
class EmulatorIndicatedDetector(
    private val clock: Clock = Clock.systemUTC(),
    private val env: PlatformEnvironment = AndroidPlatformEnvironment,
) : SignalDetector {
    override val capabilityId = "emulator_indicated"
    override val version = "1.0.0"
    override val budgetMs = 10L

    companion object {
        val EMULATOR_FILES = listOf(
            "/dev/qemu_pipe",
            "/dev/goldfish_pipe",
            "/dev/socket/qemud",
            "/sys/qemu_trace",
            "/system/bin/qemu-props",
            "/vendor/bin/qemu-props",
            "/system/lib/libc_malloc_debug_qemu.so",
            "/dev/socket/genyd",
            "/dev/socket/baseband_genyd",
        )

        val EMULATOR_HARDWARE = setOf("goldfish", "ranchu", "vbox86", "ttvm_x86")
        val EMULATOR_PRODUCT_PREFIXES = listOf("sdk_gphone", "sdk_google", "sdk_x86", "sdk_phone", "vbox86p")
        val EMULATOR_PRODUCTS = setOf("sdk", "google_sdk", "emulator", "simulator")
        val EMULATOR_MODEL_MARKERS = listOf("google_sdk", "emulator", "android sdk built for", "sdk_gphone")

        /** The Build fields the reviewed list reads; a missing one means the check did not run. */
        val BUILD_KEYS = listOf("FINGERPRINT", "MODEL", "MANUFACTURER", "HARDWARE", "PRODUCT", "DEVICE", "BOARD")

        // Only the accelerometer: entry-level devices (the reference device among them) can lack gyroscope or magnetometer.
        const val BASIC_SENSOR = Sensor.TYPE_ACCELEROMETER
    }

    override fun detect(context: Context): SignalObservation =
        Evidence.collect(capabilityId, version, clock.instant().toString()) { e ->
            val build = e.probe("build_props") { env.buildFields() }
            if (build != null) {
                if (BUILD_KEYS.any { build[it] == null }) e.notRun("build_props")
                else if (emulatorBuild(build)) e.found("build_props")
            }
            e.anyOf("qemu_device", EMULATOR_FILES) { env.pathPresent(it) }
            val sensor = e.probe("sensor_missing") { env.hasDefaultSensor(context, BASIC_SENSOR) }
            if (sensor == false) e.found("sensor_missing")
        }

    private fun emulatorBuild(build: Map<String, String>): Boolean {
        val fingerprint = build.getValue("FINGERPRINT").lowercase()
        val model = build.getValue("MODEL").lowercase()
        val hardware = build.getValue("HARDWARE").lowercase()
        val products = listOf(build.getValue("PRODUCT").lowercase(), build.getValue("DEVICE").lowercase())
        return fingerprint.startsWith("generic") ||
            fingerprint.contains("/sdk_gphone") ||
            hardware in EMULATOR_HARDWARE ||
            build.getValue("BOARD").lowercase().startsWith("goldfish") ||
            products.any { p -> p in EMULATOR_PRODUCTS || EMULATOR_PRODUCT_PREFIXES.any { p.startsWith(it) } } ||
            EMULATOR_MODEL_MARKERS.any { model.contains(it) } ||
            build.getValue("MANUFACTURER").contains("Genymotion", ignoreCase = true)
    }
}
