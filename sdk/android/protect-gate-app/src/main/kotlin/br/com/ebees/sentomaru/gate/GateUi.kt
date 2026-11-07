package br.com.ebees.sentomaru.gate

import android.app.Activity
import android.graphics.Color
import android.util.Log
import android.view.WindowManager
import android.widget.TextView

/**
 * G-10c: what the window of an activity looks like to the platform after `onActivityStarted`, as the app itself can read
 * it. Only reads: the app never sets a flag, so every `true` was put there by the injected runtime. The recents
 * screenshot and `setHideOverlayWindows` have no public getter and are not reported.
 */
internal object GateUi {
    const val TAG = "SentomaruGateUi"

    fun draw(activity: Activity) {
        // A screen with plenty of non-black pixels, so a black screenshot can only mean a secure window.
        activity.setContentView(TextView(activity).apply {
            text = "GATE ${activity.javaClass.simpleName}"
            textSize = 32f
            setTextColor(Color.BLACK)
            setBackgroundColor(Color.WHITE)
        })
    }

    fun report(activity: Activity) {
        val window = activity.window
        val secure = window.attributes.flags and WindowManager.LayoutParams.FLAG_SECURE != 0
        val filter = window.decorView.filterTouchesWhenObscured
        val a11y = if (android.os.Build.VERSION.SDK_INT >= 34) {
            window.decorView.isAccessibilityDataSensitive
        } else null
        Log.i(TAG, "activity=${activity.javaClass.simpleName} secure=$secure filterObscured=$filter a11ySensitive=$a11y pid=${android.os.Process.myPid()}")
    }
}
