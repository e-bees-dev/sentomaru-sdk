package br.com.ebees.sentomaru.signals

import android.app.Application

/**
 * D-20 / D-22c: a plain-types entry for hosts that cannot build a Kotlin `Set` or enum (Unity through `AndroidJavaClass`, .NET for
 * Android bindings): `ScreenShieldHost.install(application, arrayOf("app.PayActivity"), "marked")`. The scope is the lower-case name of
 * [CaptureScope]: `marked` (the approved default) or `all` (opt-in, needs the privacy review of the scope-all data sheet).
 * Anything else is refused with [IllegalArgumentException], never turned into a default. Installs
 * once per process; a second call with the same scope and the same Activities returns the first shield, and one that differs is refused with
 * [IllegalStateException]: the installed shield keeps what it observes, so a caller that asks for another scope or set must not believe it got it.
 */
object ScreenShieldHost {
    private class Installed(val shield: ScreenShield, val scope: CaptureScope, val activities: Set<String>)

    private var installed: Installed? = null

    /** `marked` -> [CaptureScope.MARKED], `all` -> [CaptureScope.ALL]; any other text (including a different case) is refused. */
    @JvmStatic
    fun parseScope(scope: String?): CaptureScope = when (scope) {
        "marked" -> CaptureScope.MARKED
        "all" -> CaptureScope.ALL
        else -> throw IllegalArgumentException("captureScope must be \"marked\" or \"all\"")
    }

    @JvmStatic
    fun install(application: Application, markedActivities: Array<String>, captureScope: String): ScreenShield =
        register(parseScope(captureScope), markedActivities.toSet()) {
            ScreenShield(markedActivities.toSet(), ScreenCaptureMonitor.shared, parseScope(captureScope)).also { it.install(application) }
        }

    /** The once-per-process decision, apart from the Application so a JVM test can drive it. */
    @Synchronized
    internal fun register(scope: CaptureScope, activities: Set<String>, create: () -> ScreenShield): ScreenShield {
        installed?.let {
            check(it.scope == scope && it.activities == activities) {
                "the screen shield is already installed with scope ${it.scope.name.lowercase()} and ${it.activities.size} Activities; " +
                    "a different scope or set cannot be applied in this process"
            }
            return it.shield
        }
        return create().also { installed = Installed(it, scope, activities) }
    }

    @Synchronized
    internal fun resetForTest() { installed = null }
}
