package br.com.ebees.sentomaru.lab

import android.app.Activity
import android.content.Context
import android.content.Intent
import android.location.Location
import android.location.LocationManager
import android.os.Bundle
import android.os.SystemClock
import androidx.test.ext.junit.runners.AndroidJUnit4
import androidx.test.platform.app.InstrumentationRegistry
import br.com.ebees.sentomaru.signals.SignalsCollector
import org.junit.Test
import org.junit.runner.RunWith

/**
 * LAB ONLY. Proof on a real device of F-07 `location_mock` and F-08 `call_active` (catalog 1.13.0), driven by
 * `docs/fraud/F07_F08_ROTEIRO_APARELHO.md`:
 * `am instrument -w -r -e class br.com.ebees.sentomaru.lab.SessionSignalsDeviceTest -e sentomaruStep <label> ...`.
 * Runs the real `SignalsCollector.sessionDetectors()` once and reports, per capability, the state and the fixed
 * `result` code (`sentomaru.<capability>.state` / `.result`) plus `sentomaru.step`. Nothing else: no coordinate,
 * provider, accuracy, time, number or app name is read or reported. Without `sentomaruStep` the test returns early
 * (guard clause, no Assume), so `connectedDebugAndroidTest` stays green.
 *
 * `-e sentomaruMock on` makes the lab app itself the mock-location source for this one observation: it needs
 * `adb shell appops set br.com.ebees.sentomaru.lab android:mock_location allow`, registers a test GPS provider with a
 * fixed point (0.0, 0.0: not a real place), observes, and removes the provider in `finally`. It touches nothing else.
 */
@RunWith(AndroidJUnit4::class)
class SessionSignalsDeviceTest {
    @Test
    fun observeOnce() {
        val args = InstrumentationRegistry.getArguments()
        val step = args.getString("sentomaruStep") ?: return // not a roteiro invocation
        require(STEP.matches(step)) { "step must match ${STEP.pattern}" }
        val context = InstrumentationRegistry.getInstrumentation().targetContext
        // Android 10+: a background process gets no last location. The proof therefore holds an empty lab Activity in the
        // foreground while it observes (the screen must be on and unlocked on a real device).
        val host: Activity? = if (args.getString("sentomaruForeground") == "off") null else
            InstrumentationRegistry.getInstrumentation().startActivitySync(
                Intent(context, LabActivity::class.java).addFlags(Intent.FLAG_ACTIVITY_NEW_TASK))
        val mock = args.getString("sentomaruMock") == "on"
        val manager = context.getSystemService(Context.LOCATION_SERVICE) as LocationManager
        val out = Bundle().apply { putString("sentomaru.step", step) }
        // Diagnosis only (booleans, no coordinate): is a GPS last location there before/after the harness acts?
        if (args.getString("sentomaruWarm") == "on") warm(manager)
        if (mock) startMock(manager)
        out.putString("sentomaru.harness.gpsLast", if (lastGps(manager) != null) "present" else "absent")
        val snapshot = try {
            SignalsCollector(detectors = SignalsCollector.sessionDetectors()).snapshot(context)
        } finally {
            if (mock) stopMock(manager)
            host?.finish()
        }
        for (o in snapshot.observations) {
            out.putString("sentomaru.${o.capabilityId}.state", o.state.name)
            out.putString("sentomaru.${o.capabilityId}.result", o.detail["result"] ?: "-")
        }
        InstrumentationRegistry.getInstrumentation().sendStatus(STATUS_CODE, out)
    }

    private fun startMock(manager: LocationManager) {
        manager.addTestProvider(GPS, false, false, false, false, true, true, true,
            POWER_LOW, ACCURACY_FINE)
        manager.setTestProviderEnabled(GPS, true)
        val fix = Location(GPS).apply {
            latitude = 0.0; longitude = 0.0; accuracy = 5f
            time = System.currentTimeMillis(); elapsedRealtimeNanos = SystemClock.elapsedRealtimeNanos()
        }
        manager.setTestProviderLocation(GPS, fix)
        // Delivery is asynchronous: wait (2 s at most) until the last known location is there. The detector is not touched.
        val until = SystemClock.elapsedRealtime() + 2_000L
        while (SystemClock.elapsedRealtime() < until && lastGps(manager) == null) Thread.sleep(50L)
    }

    @Suppress("MissingPermission") // the lab app declares ACCESS_FINE_LOCATION and the roteiro grants it before this step
    private fun lastGps(manager: LocationManager): Location? = try { manager.getLastKnownLocation(GPS) } catch (_: SecurityException) { null }

    // Lab-only: some platforms keep the GPS last location only while a client has an active request; ask for one for 8 s.
    @Suppress("MissingPermission")
    private fun warm(manager: LocationManager) {
        val listener = android.location.LocationListener { }
        manager.requestLocationUpdates(GPS, 0L, 0f, listener, android.os.Looper.getMainLooper())
        try { Thread.sleep(8_000L) } finally { manager.removeUpdates(listener) }
    }

    private fun stopMock(manager: LocationManager) {
        try { manager.removeTestProvider(GPS) } catch (_: Exception) { /* nothing to remove */ }
    }

    private companion object {
        const val GPS = LocationManager.GPS_PROVIDER
        const val POWER_LOW = 1 // Criteria.POWER_LOW (the class is deprecated; -Werror)
        const val ACCURACY_FINE = 1 // Criteria.ACCURACY_FINE
        val STEP = Regex("[a-z0-9_]{1,32}")
        const val STATUS_CODE = 7
    }
}
