package br.com.ebees.sentomaru.d08b

import android.app.Activity
import android.os.Bundle

/**
 * D-08b lab-only crash trigger. Present only in the `d08bRelease` build (`-Psentomaru.d08bRelease=true`); never in the
 * default build, the CI lockfile or any published artifact. Launched with the action
 * `br.com.ebees.sentomaru.d08b.LAB_CRASH`, it throws a deterministic exception through a two-level private call chain.
 *
 * The `d08bRelease` build keeps `SourceFile,LineNumberTable` (its `proguard-rules-d08b.pro`), so the uncaught stack in
 * logcat carries the R8 map id. R8 INLINES this short chain into the kept `onCreate` (the volatile guard only keeps the
 * helpers from being optimized away entirely); because the line tables are kept, `retrace` reconstructs the inlined
 * frames and recovers `detonateLevel2` and `detonateLevel1` at `LabCrashActivity.kt` — that reconstruction is the
 * proof. The emulator job captures the real stack; `check_retrace.py` proves the same offline. Nothing here runs unless
 * the lab action launches it.
 */
class LabCrashActivity : Activity() {
    // A side effect keeps each helper from being optimized away entirely; R8 still inlines them into onCreate, and the
    // kept line tables let retrace reconstruct the frames (the proof).
    @Volatile
    private var guard: Int = 0

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        if (intent?.action == ACTION_LAB_CRASH) {
            detonateLevel1()
        } else {
            finish()
        }
    }

    private fun detonateLevel1() {
        guard += 1
        detonateLevel2()
    }

    private fun detonateLevel2(): Nothing {
        guard += 1
        throw IllegalStateException("$LAB_CRASH_MARK $guard")
    }

    companion object {
        const val ACTION_LAB_CRASH = "br.com.ebees.sentomaru.d08b.LAB_CRASH"

        /** The message the emulator job greps for in the retraced stack. */
        const val LAB_CRASH_MARK = "sentomaru-d08b-lab-crash"
    }
}
