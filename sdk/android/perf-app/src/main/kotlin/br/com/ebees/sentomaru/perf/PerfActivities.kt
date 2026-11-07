package br.com.ebees.sentomaru.perf

import android.app.Activity
import android.os.Bundle
import android.util.Log
import android.widget.TextView
import br.com.ebees.sentomaru.sdk.InstallationState
import br.com.ebees.sentomaru.sdk.SentomaruClient

/**
 * Same layout in both activities. With the `exercise` extra (and `cert`, `run`), a worker thread runs one journey
 * and logs `J03 ready <run>` (or `J03 fail <run> <error class>`), so the runner reads memory after real work.
 */
abstract class PerfActivity : Activity() {
    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        setContentView(TextView(this).apply { text = label() })
        val certificate = intent.getStringExtra("cert")
        val run = intent.getStringExtra("run") ?: "-"
        if (!intent.getBooleanExtra("exercise", false) || certificate == null) return
        Thread {
            try {
                exercise(Journey(certificate))
                Log.i(TAG, "ready $run")
            } catch (error: Exception) {
                Log.i(TAG, "fail $run ${error.javaClass.simpleName}")
            }
        }.start()
    }

    abstract fun label(): String
    abstract fun exercise(journey: Journey)

    companion object {
        const val TAG = "J03"
    }
}

/** Without the SDK: the same network round trip, unsigned. */
class BaselineActivity : PerfActivity() {
    override fun label() = "baseline"
    override fun exercise(journey: Journey) = journey.health()
}

/** With the SDK: initialize and read the installation state on the main thread; the journey enrolls and signs. */
class SdkActivity : PerfActivity() {
    private lateinit var client: SentomaruClient
    private var state: InstallationState = InstallationState.NotEnrolled

    override fun onCreate(savedInstanceState: Bundle?) {
        client = PerfScope.client(applicationContext)
        state = client.state()
        super.onCreate(savedInstanceState)
    }

    override fun label() = "sdk ${state.name}"

    override fun exercise(journey: Journey) {
        journey.health()
        if (client.state() != InstallationState.Enrolled) journey.enroll(client, journey.challenge())
        val body = "{\"j03\":true}".toByteArray()
        val signed = client.sign("POST", PerfScope.OPERATION_URL, "submit", body)
        val status = journey.submit(signed.targetUri, signed.headers, body)
        if (status != "valid") throw IllegalStateException(status)
    }
}
