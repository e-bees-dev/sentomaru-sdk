package br.com.ebees.sentomaru.signals

import android.content.Context
import br.com.ebees.sentomaru.signals.detectors.CodeIntegrityDetector
import org.junit.Assert.*
import org.junit.Rule
import org.junit.Test
import org.junit.rules.TemporaryFolder
import java.io.File
import java.time.Clock
import java.time.Instant
import java.time.ZoneOffset
import java.util.concurrent.CountDownLatch
import java.util.concurrent.Executor
import java.util.concurrent.RejectedExecutionException
import java.util.concurrent.TimeUnit
import java.util.concurrent.atomic.AtomicInteger
import java.util.zip.CRC32
import java.util.zip.ZipEntry
import java.util.zip.ZipOutputStream

/**
 * D-12c: `code_integrity` over real zip files (JVM `ZipFile`), the shared D-12a vectors, splits, cache, wait and every
 * failure. The state is always UNKNOWN (or ERROR): the SDK never says match nor mismatch.
 */
class CodeIntegrityTest {
    @get:Rule val tmp = TemporaryFolder()

    private val clock = Clock.fixed(Instant.parse("2026-10-23T10:00:00Z"), ZoneOffset.UTC)
    private val context: Context = object : android.content.ContextWrapper(null) {}
    private val direct = Executor { it.run() }

    @Suppress("UNCHECKED_CAST")
    private val vectors: Map<String, Any?> by lazy {
        val path = requireNotNull(System.getProperty("sentomaru.codeDigestVectors")) { "sentomaru.codeDigestVectors not set" }
        StrictJson.parse(File(path).readText()) as Map<String, Any?>
    }

    @Suppress("UNCHECKED_CAST")
    private val vectorEntries: List<Pair<String, ByteArray>>
        get() = (vectors["entries"] as List<Map<String, Any?>>).map { it["path"] as String to hex(it["bytesHex"] as String) }

    private fun hex(s: String) = ByteArray(s.length / 2) { s.substring(it * 2, it * 2 + 2).toInt(16).toByte() }

    private fun zip(name: String, entries: List<Pair<String, ByteArray>>, stored: Boolean = false): File {
        val file = tmp.newFile(name)
        ZipOutputStream(file.outputStream()).use { out ->
            for ((path, bytes) in entries) {
                val entry = ZipEntry(path)
                if (stored) {
                    entry.method = ZipEntry.STORED
                    entry.size = bytes.size.toLong()
                    entry.compressedSize = bytes.size.toLong()
                    entry.crc = CRC32().apply { update(bytes) }.value
                }
                out.putNextEntry(entry)
                out.write(bytes)
                out.closeEntry()
            }
        }
        return file
    }

    private fun apks(vararg files: File, updated: Long = 1L) =
        InstalledApks(updated, files.map { ApkFile(it.absolutePath, it.length()) })

    private class Env(var apks: InstalledApks? = null, var failure: Throwable? = null) : DetectorsTest.FakeEnv() {
        override fun installedApks(context: Context): InstalledApks { failure?.let { throw it }; return apks!! }
    }

    private fun detector(env: PlatformEnvironment, cache: CodeDigestCache = CodeDigestCache(direct), waitMs: Long = 1000,
        main: Boolean = false) = CodeIntegrityDetector(clock, env, cache, waitMs) { main }

    private val ignored: List<Pair<String, ByteArray>>
        @Suppress("UNCHECKED_CAST")
        get() = (vectors["ignoredEntries"] as List<String>).map { it to "ignored $it".toByteArray() }

    @Test
    fun aggregateOfTheSharedVectorsMatchesTheContract() {
        val apk = zip("base.apk", (vectorEntries + ignored).shuffled(java.util.Random(7)))
        val result = ApkCodeDigests.compute(listOf(apk)) as ApkCodeDigests.Result.Computed
        @Suppress("UNCHECKED_CAST")
        val expected = ((vectors["codeDigests"] as Map<String, Any?>)["files"] as List<Map<String, Any?>>)
            .map { ApkCodeDigests.CodeFile(it["path"] as String, it["sha256"] as String) }
        assertEquals(expected, result.files)
        assertEquals(vectors["aggregate"], result.aggregate)
        assertEquals(vectors["algorithm"], ApkCodeDigests.ALGORITHM)
        // Stored or deflated entries give the same digests.
        val stored = ApkCodeDigests.compute(listOf(zip("stored.apk", vectorEntries, stored = true))) as ApkCodeDigests.Result.Computed
        assertEquals(vectors["aggregate"], stored.aggregate)
    }

    @Test
    fun computedIsUnknownNotComparedWithAggregateAlgorithmAndCount() {
        val obs = detector(Env(apks(zip("base.apk", vectorEntries)))).detect(context)
        assertEquals(SignalState.UNKNOWN, obs.state)
        assertEquals(linkedMapOf("reason" to "not_compared", "algorithm" to "apk-code-sha256-v1",
            "aggregate" to vectors["aggregate"], "files" to "7"), obs.detail)
        assertEquals("client_observed", obs.source)
    }

    @Test
    fun splitsAreHashedTogetherAndGiveTheSameAggregateAsOneApk() {
        val all = vectorEntries
        val dex = all.filter { it.first.endsWith(".dex") }
        val arm = all.filter { it.first.startsWith("lib/arm64") }
        val rest = all.filter { it !in dex && it !in arm }
        val result = ApkCodeDigests.compute(listOf(zip("base.apk", dex + ignored), zip("split_config.arm64_v8a.apk", arm),
            zip("split_other.apk", rest)))
        assertEquals(vectors["aggregate"], (result as ApkCodeDigests.Result.Computed).aggregate)
    }

    @Test
    fun everyRefusalIsUnknownPartialWithAFixedCause() {
        val notZip = tmp.newFile("broken.apk").apply { writeText("not a zip") }
        val many = (2..258).map { "classes$it.dex" to byteArrayOf(it.toByte()) }
        val cases = mapOf(
            "apk_unreadable" to listOf(notZip),
            "apk_unreadable " to listOf(File(tmp.root, "missing.apk")),
            "duplicate_entry" to listOf(zip("a.apk", vectorEntries.take(1)), zip("b.apk", vectorEntries.take(1))),
            "no_code_files" to listOf(zip("res.apk", ignored)),
            "too_many_files" to listOf(zip("many.apk", many)),
        )
        for ((cause, files) in cases) {
            val obs = detector(Env(apks(*files.toTypedArray()))).detect(context)
            assertEquals(cause, SignalState.UNKNOWN, obs.state)
            assertEquals(cause, mapOf("reason" to "partial", "cause" to cause.trim()), obs.detail)
        }
    }

    @Test
    fun apkListFailureIsUnknownPartial() {
        for (failure in listOf(SecurityException("denied"), IllegalStateException("no sourceDir"),
            UnsupportedOperationException("not provided"), NoClassDefFoundError("missing"))) {
            val obs = detector(Env(failure = failure)).detect(context)
            assertEquals(SignalState.UNKNOWN, obs.state)
            assertEquals(mapOf("reason" to "partial", "cause" to "apk_list"), obs.detail)
        }
        assertEquals(mapOf("reason" to "partial", "cause" to "apk_list"),
            detector(Env(InstalledApks(1L, emptyList()))).detect(context).detail)
        // An environment from before the D-12c: the default throws.
        assertEquals("apk_list", detector(DetectorsTest.FakeEnv()).detect(context).detail["cause"])
    }

    @Test
    fun mainThreadNeverHashesNorWaits() {
        val calls = AtomicInteger()
        val cache = CodeDigestCache(direct) { calls.incrementAndGet(); ApkCodeDigests.Result.Refused("apk_unreadable") }
        val env = Env(failure = AssertionError("must not list the APKs on the main thread"))
        val obs = detector(env, cache, main = true).detect(context)
        assertEquals(SignalState.UNKNOWN, obs.state)
        assertEquals(mapOf("reason" to "main_thread"), obs.detail)
        assertEquals(0, calls.get())
    }

    @Test
    fun coldHashPastTheWaitIsTimeoutThenTheCachedResultIsRead() {
        val release = CountDownLatch(1)
        val done = CountDownLatch(1)
        val apk = zip("base.apk", vectorEntries)
        val background = Executor { task -> Thread { task.run(); done.countDown() }.apply { isDaemon = true }.start() }
        val calls = AtomicInteger()
        val cache = CodeDigestCache(background) {
            calls.incrementAndGet()
            release.await(5, TimeUnit.SECONDS)
            ApkCodeDigests.compute(it.files.map { f -> File(f.path) })
        }
        val env = Env(apks(apk))
        val cold = detector(env, cache, waitMs = 10).detect(context)
        assertEquals(SignalState.UNKNOWN, cold.state)
        assertEquals(mapOf("reason" to "timeout"), cold.detail)
        release.countDown()
        assertTrue(done.await(5, TimeUnit.SECONDS))
        val warm = detector(env, cache, waitMs = 0).detect(context)
        assertEquals("not_compared", warm.detail["reason"])
        assertEquals(vectors["aggregate"], warm.detail["aggregate"])
        assertEquals(1, calls.get())
    }

    @Test
    fun cacheIsKeyedByUpdateTimePathsAndSizes() {
        val calls = AtomicInteger()
        val cache = CodeDigestCache(direct) { calls.incrementAndGet(); ApkCodeDigests.compute(it.files.map { f -> File(f.path) }) }
        val apk = zip("base.apk", vectorEntries)
        val env = Env(apks(apk))
        repeat(3) { detector(env, cache).detect(context) }
        assertEquals(1, calls.get())
        env.apks = apks(apk, updated = 2L) // an update
        detector(env, cache).detect(context)
        assertEquals(2, calls.get())
        env.apks = InstalledApks(2L, listOf(ApkFile(apk.absolutePath, apk.length() + 1))) // another size
        detector(env, cache).detect(context)
        assertEquals(3, calls.get())
        // A refusal the same APKs always give is cached too.
        val refused = CodeDigestCache(direct) { calls.incrementAndGet(); ApkCodeDigests.Result.Refused("no_code_files") }
        repeat(2) { assertEquals("no_code_files", detector(env, refused).detect(context).detail["cause"]) }
        assertEquals(4, calls.get())
    }

    @Test
    fun executorRejectionAndHashFailureAreUnknownPartial() {
        val env = Env(apks(zip("base.apk", vectorEntries)))
        val rejecting = CodeDigestCache(Executor { throw RejectedExecutionException("shut down") })
        assertEquals(mapOf("reason" to "partial", "cause" to "executor"), detector(env, rejecting).detect(context).detail)
        val throwing = CodeDigestCache(direct) { throw OutOfMemoryError("big") }
        assertEquals(mapOf("reason" to "partial", "cause" to "hash_failed"), detector(env, throwing).detect(context).detail)
    }

    @Test
    fun interruptedWaitIsTimeoutAndKeepsTheInterrupt() {
        val never = CodeDigestCache(Executor { /* never runs */ })
        Thread.currentThread().interrupt()
        try {
            val obs = detector(Env(apks(zip("base.apk", vectorEntries))), never).detect(context)
            assertEquals(mapOf("reason" to "timeout"), obs.detail)
            assertTrue(Thread.currentThread().isInterrupted)
        } finally {
            Thread.interrupted()
        }
    }

    @Test
    fun noPathOfTheCodeIsEverReportedAsCleanOrTampered() {
        val states = mutableSetOf<SignalState>()
        val envs = listOf(Env(apks(zip("ok.apk", vectorEntries))), Env(failure = SecurityException("x")),
            Env(apks(tmp.newFile("bad.apk"))), Env(InstalledApks(1L, emptyList())))
        for (env in envs) for (main in listOf(false, true)) states += detector(env, main = main).detect(context).state
        assertEquals(setOf(SignalState.UNKNOWN), states)
    }

    @Test
    fun negativeWaitIsRefused() {
        assertThrows(IllegalArgumentException::class.java) { CodeIntegrityDetector(clock, Env(), CodeDigestCache(direct), -1) }
    }

    @Test
    fun transientFailuresAreComputedAgainAfterTheRetryInterval() {
        val env = Env(apks(zip("base.apk", vectorEntries)))
        for (cause in CodeDigestCache.TRANSIENT_CAUSES + "hash_failed") {
            var now = 0L
            val calls = AtomicInteger()
            val cache = CodeDigestCache(direct, transientRetryNanos = 1_000, nanos = { now }) {
                if (calls.incrementAndGet() == 1) {
                    if (cause == "hash_failed") throw java.io.UncheckedIOException(java.io.IOException("eio"))
                    ApkCodeDigests.Result.Refused(cause)
                } else ApkCodeDigests.compute(it.files.map { f -> File(f.path) })
            }
            assertEquals(cause, cause, detector(env, cache).detect(context).detail["cause"])
            now = 999
            assertEquals(cause, cause, detector(env, cache).detect(context).detail["cause"]) // within the interval: kept
            assertEquals(1, calls.get())
            now = 1_000
            assertEquals(cause, "not_compared", detector(env, cache).detect(context).detail["reason"])
            assertEquals(2, calls.get())
            now = 10_000_000
            detector(env, cache).detect(context) // a computed result stays
            assertEquals(2, calls.get())
        }
    }

    @Test
    fun permanentRefusalsStayCachedAfterTheInterval() {
        var now = 0L
        val calls = AtomicInteger()
        val cache = CodeDigestCache(direct, transientRetryNanos = 1, nanos = { now }) {
            calls.incrementAndGet(); ApkCodeDigests.Result.Refused("duplicate_entry")
        }
        val env = Env(apks(zip("base.apk", vectorEntries)))
        detector(env, cache).detect(context)
        now = 1_000_000
        detector(env, cache).detect(context)
        assertEquals(1, calls.get())
    }
}
