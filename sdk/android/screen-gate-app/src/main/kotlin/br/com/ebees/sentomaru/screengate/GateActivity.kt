package br.com.ebees.sentomaru.screengate

import android.app.Activity
import android.graphics.Color
import android.os.Bundle
import android.os.Handler
import android.os.Looper
import android.util.Log
import android.view.WindowManager
import android.widget.TextView
import br.com.ebees.sentomaru.signals.detectors.ScreenCaptureDetector
import br.com.ebees.sentomaru.signals.detectors.ScreenSharedDetector

/**
 * D-20 gate screen. Every 500 ms, while in front, it reads the two detectors and logs one line (the gate parses it):
 *   `SentomaruGateScreen api=<n> secure=<bool> capture=<state>/<result> captures=<n> shared=<state>/<codes>`
 * A read of `screen_capture` clears its window, so a capture shows up in exactly one line. Nothing here triggers a capture.
 */
open class GateActivity : Activity() {
    private val handler = Handler(Looper.getMainLooper())
    private val capture = ScreenCaptureDetector()
    private val shared = ScreenSharedDetector()
    private val tick = object : Runnable {
        override fun run() {
            report()
            handler.postDelayed(this, 500)
        }
    }

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        setContentView(TextView(this).apply {
            text = "D20 ${javaClass.simpleName}"
            textSize = 32f
            setTextColor(Color.BLACK)
            setBackgroundColor(Color.WHITE)
        })
    }

    override fun onResume() {
        super.onResume()
        handler.post(tick)
    }

    override fun onPause() {
        handler.removeCallbacks(tick)
        super.onPause()
    }

    private fun report() {
        val c = capture.detect(this)
        val s = shared.detect(this)
        val secure = window.attributes.flags and WindowManager.LayoutParams.FLAG_SECURE != 0
        Log.i(TAG, "screen=${javaClass.simpleName} api=${android.os.Build.VERSION.SDK_INT} secure=$secure " +
            "capture=${c.state}/${c.detail["result"] ?: "-"} captures=${c.detail["captures"] ?: "0"} " +
            "shared=${s.state}/${s.detail.values.joinToString("+").ifEmpty { "-" }}")
    }

    companion object {
        const val TAG = "SentomaruGateScreen"
    }
}

/** Not marked by the shield: its window must not get FLAG_SECURE and no capture is counted while it is in front. */
class OtherActivity : GateActivity()
