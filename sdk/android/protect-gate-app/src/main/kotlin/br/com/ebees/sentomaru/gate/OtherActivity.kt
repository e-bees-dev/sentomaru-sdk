package br.com.ebees.sentomaru.gate

import android.app.Activity
import android.os.Bundle

/** G-10c: a second screen the UI-shield profile does NOT list; the gate checks it stays unprotected. */
class OtherActivity : Activity() {
    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        GateUi.draw(this)
    }

    override fun onResume() {
        super.onResume()
        GateUi.report(this)
    }
}
