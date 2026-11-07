package br.com.ebees.sentomaru.signals

import java.io.File
import java.util.concurrent.Executor
import java.util.concurrent.ExecutionException
import java.util.concurrent.Executors
import java.util.concurrent.Future
import java.util.concurrent.FutureTask

/**
 * D-12c: the `code_integrity` hash, computed once per [InstalledApks] (lastUpdateTime, paths and sizes) on a background
 * executor and kept in memory for the process. A collection waits for it only up to the detector's wait; past that
 * the hash goes on in the background and a later collection reads the cached result. Nothing is written to disk.
 *
 * What is kept (review R I3): a computed aggregate and a refusal that the same APKs always give (`duplicate_entry`,
 * `no_code_files`, `too_many_files`, `too_large`). A refusal that may be transient (`apk_unreadable`,
 * `entry_unreadable`: an I/O failure) or a hash that threw is kept only [transientRetryNanos] after it ended; the
 * first collection after that computes again. A new key (update, another split set) computes again at once.
 *
 * Executor (review R minor 1): by default one daemon thread of minimum priority, created on the first hash and kept for
 * the process (it idles when nothing is pending); hashes run one at a time, so a burst of collections never reads the
 * APKs twice in parallel. An app may pass its own executor; a rejection propagates to the detector (`executor`).
 */
class CodeDigestCache @JvmOverloads constructor(
    private val executor: Executor = defaultExecutor(),
    private val transientRetryNanos: Long = DEFAULT_TRANSIENT_RETRY_NANOS,
    private val nanos: () -> Long = System::nanoTime,
    private val compute: (InstalledApks) -> ApkCodeDigests.Result = { apks -> ApkCodeDigests.compute(apks.files.map { File(it.path) }) },
) {
    private inner class Task(val key: InstalledApks) : FutureTask<ApkCodeDigests.Result>({ compute(key) }) {
        @Volatile var endedAt: Long? = null
        override fun done() { endedAt = nanos() }
    }

    private var pending: Task? = null

    /** The hash for [apks]: the cached one when the key is the same and it may be kept, else a new task. */
    @Synchronized
    fun resultFor(apks: InstalledApks): Future<ApkCodeDigests.Result> {
        val current = pending
        if (current != null && current.key == apks && !expiredFailure(current)) return current
        val task = Task(apks)
        executor.execute(task) // a rejection propagates and nothing is cached
        pending = task
        return task
    }

    private fun expiredFailure(task: Task): Boolean {
        val ended = task.endedAt ?: return false // still running
        if (!transient(task)) return false
        return nanos() - ended >= transientRetryNanos
    }

    private fun transient(task: Task): Boolean = try {
        (task.get() as? ApkCodeDigests.Result.Refused)?.cause in TRANSIENT_CAUSES
    } catch (_: ExecutionException) {
        true
    } catch (_: java.util.concurrent.CancellationException) {
        true
    }

    companion object {
        /** One cache per process, shared by every collector the app builds. */
        val shared: CodeDigestCache by lazy { CodeDigestCache() }

        /** Refusals that may not repeat (I/O); the others depend only on the APK bytes. */
        val TRANSIENT_CAUSES: Set<String> = setOf("apk_unreadable", "entry_unreadable")

        /** 30 s: a failing read is not retried on every collection, and does not stay for the whole process. */
        const val DEFAULT_TRANSIENT_RETRY_NANOS = 30_000_000_000L

        private fun defaultExecutor(): Executor = Executors.newSingleThreadExecutor { runnable ->
            Thread(runnable, "sentomaru-code-digests").apply {
                isDaemon = true
                priority = Thread.MIN_PRIORITY
            }
        }
    }
}
