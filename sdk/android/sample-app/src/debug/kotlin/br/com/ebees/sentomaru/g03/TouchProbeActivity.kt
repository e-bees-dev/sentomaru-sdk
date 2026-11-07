package br.com.ebees.sentomaru.g03

import android.app.Activity
import android.os.Bundle
import android.view.MotionEvent
import android.view.View
import br.com.ebees.sentomaru.signals.ObscuredTouchMonitor

/** G-03 P-4: forwards every touch to [monitor], as an app does for a screen it marks. */
class TouchProbeActivity : Activity() {
    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        setContentView(View(this).apply { setBackgroundColor(0xFF202020.toInt()) })
    }

    override fun dispatchTouchEvent(ev: MotionEvent): Boolean {
        if (ev.actionMasked == MotionEvent.ACTION_DOWN) downs.incrementAndGet()
        monitor?.onTouch(ev)
        return super.dispatchTouchEvent(ev)
    }

    companion object {
        @Volatile var monitor: ObscuredTouchMonitor? = null
        val downs = java.util.concurrent.atomic.AtomicInteger()
    }
}
