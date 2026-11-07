package br.com.ebees.sentomaru.signals

import android.annotation.SuppressLint
import android.app.Activity
import android.app.Application
import android.content.Context
import android.content.pm.PackageManager
import android.os.Build
import android.os.Bundle
import android.view.WindowManager
import java.util.IdentityHashMap
import java.util.concurrent.Executor
import java.util.function.Consumer

/** The platform calls [ScreenShieldCore] makes, kept apart so that the decisions are tested without a device. */
internal interface ShieldPlatform<T : Any> {
    /** `FLAG_SECURE` on the window, and the recents snapshot off where the platform allows it. */
    fun secure(screen: T)

    /** Registers the screenshot callback; null = this API level has none. The handle goes back to [unregisterCapture]. */
    fun registerCapture(screen: T, onCapture: () -> Unit): Any?

    fun unregisterCapture(screen: T, handle: Any)
}

/**
 * D-20: which screens the capture callback watches. [MARKED] (default, the approved scope): only the screens the app lists.
 * [ALL]: every visible `Activity`, so a capture with an unmarked screen in front is counted too, in a separate number
 * (`captures_other`). [ALL] changes what is observed, not what is protected: an unmarked screen still gets no `FLAG_SECURE`
 * and nothing about it (name, content) is kept. It needs the privacy review of the new ficha (`D20_TELA_FICHA.md`, scope
 * `all`); the app opts in on purpose.
 */
enum class CaptureScope { MARKED, ALL }

/**
 * D-20: the decisions of the shield. A screen the app does not list is never touched. A listed screen gets
 * `FLAG_SECURE` when it is created, and the screenshot callback while it is started (so a capture counts only with the
 * marked screen in front).
 */
internal class ScreenShieldCore<T : Any>(
    private val marked: Set<String>,
    private val platform: ShieldPlatform<T>,
    private val monitor: ScreenCaptureMonitor,
    private val scope: CaptureScope = CaptureScope.MARKED,
) {
    private class Armed(val handle: Any, val marked: Boolean)

    private val handles = IdentityHashMap<T, Armed>()

    fun isMarked(className: String): Boolean = className in marked

    fun created(screen: T, className: String) {
        if (!isMarked(className)) return
        try {
            platform.secure(screen)
        } catch (_: Exception) {
            // a window that refuses the flag costs only this screen's protection
        }
    }

    fun started(screen: T, className: String) {
        val marked = isMarked(className)
        if (!marked && scope != CaptureScope.ALL) return
        synchronized(handles) {
            if (handles.containsKey(screen)) return
            val handle = try {
                platform.registerCapture(screen) { monitor.onCapture(marked) }
            } catch (_: Exception) {
                null
            } ?: return
            handles[screen] = Armed(handle, marked)
        }
        monitor.arm(marked)
    }

    fun stopped(screen: T) {
        val armed = synchronized(handles) { handles.remove(screen) } ?: return
        try {
            platform.unregisterCapture(screen, armed.handle)
        } catch (_: Exception) {
            // already unregistered by the platform
        }
        monitor.disarm(armed.marked)
    }
}

/**
 * D-20 (Android, runtime): protects the screens the app lists and feeds the `screen_capture` and `screen_shared`
 * signals. [install] once, from `Application.onCreate`. [markedActivities] are fully qualified `Activity` class names
 * (`listed_only`: any other screen is left alone). It changes how the app behaves: a listed screen cannot be captured
 * by the system, and its recents thumbnail is blank (a support or accessibility flow that needs a capture must not be
 * listed). `FLAG_SECURE` does not stop an external camera, a hook, or a memory read.
 *
 * Uses only public APIs: `Window.addFlags`, `Activity.setRecentsScreenshotEnabled` (API 33),
 * `Activity.registerScreenCaptureCallback` (API 34, permission `DETECT_SCREEN_CAPTURE`) and
 * `WindowManager.addScreenRecordingCallback` (API 35, permission `DETECT_SCREEN_RECORDING`). Callbacks do a counter
 * increment on the calling thread and nothing else.
 *
 * The app that installs this declares both permissions in its own manifest; the library manifest declares none, so a
 * host that only reads signals inherits nothing (Shield #2).
 */
class ScreenShield @JvmOverloads constructor(
    markedActivities: Set<String>,
    private val monitor: ScreenCaptureMonitor = ScreenCaptureMonitor.shared,
    private val captureScope: CaptureScope = CaptureScope.MARKED,
) {
    private val core = ScreenShieldCore(markedActivities.toSet(), AndroidShieldPlatform, monitor, captureScope)
    private val installed = java.util.concurrent.atomic.AtomicBoolean()

    fun install(application: Application) {
        if (!installed.compareAndSet(false, true)) return
        monitor.scopeAll = captureScope == CaptureScope.ALL
        application.registerActivityLifecycleCallbacks(object : Application.ActivityLifecycleCallbacks {
            override fun onActivityCreated(activity: Activity, savedInstanceState: Bundle?) =
                core.created(activity, activity.javaClass.name)

            override fun onActivityStarted(activity: Activity) = core.started(activity, activity.javaClass.name)
            override fun onActivityStopped(activity: Activity) = core.stopped(activity)
            override fun onActivityDestroyed(activity: Activity) = core.stopped(activity)
            override fun onActivityResumed(activity: Activity) {}
            override fun onActivityPaused(activity: Activity) {}
            override fun onActivitySaveInstanceState(activity: Activity, outState: Bundle) {}
        })
        watchScreenRecording(application)
    }

    // The permission is the host app's to declare (Shield #2: the library manifest declares none). Checked at run time just
    // before the call; without it the recording state stays "not measured" (UNKNOWN), never "not detected".
    @SuppressLint("MissingPermission")
    private fun watchScreenRecording(application: Application) {
        if (Build.VERSION.SDK_INT < Build.VERSION_CODES.VANILLA_ICE_CREAM) return
        if (!ScreenPermissions.granted(application, ScreenPermissions.RECORDING)) return
        try {
            val windows = application.getSystemService(WindowManager::class.java) ?: return
            val state = windows.addScreenRecordingCallback(DirectExecutor, Consumer { value ->
                monitor.recordingVisible = value == WindowManager.SCREEN_RECORDING_STATE_VISIBLE
            })
            monitor.recordingVisible = state == WindowManager.SCREEN_RECORDING_STATE_VISIBLE
        } catch (_: Exception) {
            // no permission or no service: the recording state stays "not measured"
        }
    }

    private object DirectExecutor : Executor {
        override fun execute(command: Runnable) = command.run()
    }
}

/** Run-time check of the two normal-protection permissions the host app declares for the screen shield (Shield #2). */
internal object ScreenPermissions {
    const val CAPTURE = "android.permission.DETECT_SCREEN_CAPTURE"
    const val RECORDING = "android.permission.DETECT_SCREEN_RECORDING"

    fun granted(context: Context, permission: String, check: (Context, String) -> Int = { c, p -> c.checkSelfPermission(p) }): Boolean =
        try { check(context, permission) == PackageManager.PERMISSION_GRANTED } catch (_: Exception) { false }
}

internal object AndroidShieldPlatform : ShieldPlatform<Activity> {
    override fun secure(screen: Activity) {
        screen.window.addFlags(WindowManager.LayoutParams.FLAG_SECURE)
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.TIRAMISU) screen.setRecentsScreenshotEnabled(false)
    }

    // Host-declared permission (Shield #2), checked just before the call; without it no screen is armed: `no_screens` (UNKNOWN).
    @SuppressLint("MissingPermission")
    override fun registerCapture(screen: Activity, onCapture: () -> Unit): Any? {
        if (Build.VERSION.SDK_INT < Build.VERSION_CODES.UPSIDE_DOWN_CAKE) return null
        if (!ScreenPermissions.granted(screen, ScreenPermissions.CAPTURE)) return null
        val callback = Activity.ScreenCaptureCallback { onCapture() }
        screen.registerScreenCaptureCallback(DirectCaptureExecutor, callback)
        return callback
    }

    // A handle exists only if registerCapture passed the permission check above.
    @SuppressLint("MissingPermission")
    override fun unregisterCapture(screen: Activity, handle: Any) {
        if (Build.VERSION.SDK_INT < Build.VERSION_CODES.UPSIDE_DOWN_CAKE) return
        screen.unregisterScreenCaptureCallback(handle as Activity.ScreenCaptureCallback)
    }

    private object DirectCaptureExecutor : Executor {
        override fun execute(command: Runnable) = command.run()
    }
}
