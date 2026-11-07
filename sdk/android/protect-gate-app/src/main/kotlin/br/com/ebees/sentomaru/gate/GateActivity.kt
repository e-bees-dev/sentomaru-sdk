package br.com.ebees.sentomaru.gate

import android.app.Activity
import android.os.Bundle
import android.util.Log

/**
 * Reports, through logcat, whether the runtime injected by `sentomaru protect` is present and initialized in this
 * process. The app is compiled without the runtime, so it is reached by reflection; absent means "not injected".
 */
class GateActivity : Activity() {
    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        val state = try {
            val runtime = Class.forName("br.com.ebees.sentomaru.runtime.SentomaruRuntime")
            val initialized = runtime.getMethod("isInitialized").invoke(null) as Boolean
            "present=true isInitialized=$initialized"
        } catch (e: ClassNotFoundException) {
            "present=false isInitialized=false"
        }
        Log.i(TAG, "$state pid=${android.os.Process.myPid()}")
        GateUi.draw(this)
    }

    override fun onResume() {
        super.onResume()
        GateUi.report(this)
    }

    companion object {
        const val TAG = "SentomaruGate"
    }
}
