package br.com.ebees.sentomaru.screengate

import android.app.Application
import br.com.ebees.sentomaru.signals.ScreenShield

/** D-20 gate host: only [GateActivity] is marked; [OtherActivity] is the control that must stay untouched. */
class GateApp : Application() {
    override fun onCreate() {
        super.onCreate()
        ScreenShield(setOf(GateActivity::class.java.name)).install(this)
    }
}
