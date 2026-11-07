package br.com.ebees.sentomaru.signals.detectors

import android.content.Context
import br.com.ebees.sentomaru.signals.*
import java.time.Clock

/**
 * D-05: Java-layer hook frameworks only (Xposed, LSPosed, EdXposed, Substrate). Frida, native hooks and trampolines
 * are D-19; a framework that hides its classes and frames is not detected.
 */
class HookFrameworkJavaDetector(
    private val clock: Clock = Clock.systemUTC(),
    private val env: PlatformEnvironment = AndroidPlatformEnvironment,
) : SignalDetector {
    override val capabilityId = "hook_framework_java"
    override val version = "1.0.0"
    override val budgetMs = 5L

    companion object {
        val HOOK_CLASSES = listOf(
            "de.robv.android.xposed.XposedBridge",
            "de.robv.android.xposed.XposedHelpers",
            "com.saurik.substrate.MS",
        )

        val HOOK_FRAME_MARKERS = listOf(
            "de.robv.android.xposed.",
            "org.lsposed.",
            "io.github.lsposed.",
            "com.saurik.substrate.",
            "LSPHooker_",
            "EdHooker_",
        )
    }

    override fun detect(context: Context): SignalObservation =
        Evidence.collect(capabilityId, version, clock.instant().toString()) { e ->
            e.anyOf("xposed_class", HOOK_CLASSES) { env.classLoadable(context, it) }
            val frames = e.probe("hook_frame") { env.controlledStackTraceClassNames() }
            if (frames != null && frames.any { name -> HOOK_FRAME_MARKERS.any { name.contains(it) } }) {
                e.found("hook_frame")
            }
        }
}
