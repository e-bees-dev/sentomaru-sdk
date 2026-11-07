package br.com.ebees.sentomaru.d14d;

import android.app.Instrumentation;
import android.content.Context;
import android.os.Bundle;
import android.os.Debug;
import android.os.Looper;

import androidx.test.ext.junit.runners.AndroidJUnit4;
import androidx.test.platform.app.InstrumentationRegistry;

import br.com.ebees.sentomaru.sdk.sealed.SentomaruSealed;

import org.json.JSONException;
import org.json.JSONObject;
import org.junit.Test;
import org.junit.runner.RunWith;

import java.util.ArrayList;
import java.util.Collections;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.concurrent.atomic.AtomicLong;

/**
 * D-14d, item 13: cost of reading the sealed assets on one real device, driven by verification/run_d14d_read_cost.py
 * (never in CI). The sample-app must be its sealed {@code d14dSealed} build ({@code sentomaru protect} ran: the four
 * {@code assets/d14d/<n>.bin} canary files are sealed and the plain originals are gone), installed with this test APK.
 *
 * <p>Java on purpose: this test APK is built against the R8 build (testBuildType {@code d14dSealed}); a Kotlin test
 * would call Kotlin runtime classes the app's R8 removed. It uses only the platform, JUnit, androidx.test and the
 * kept public API of {@link SentomaruSealed}.
 *
 * <p>Arguments (as RaspCostInstrumentedTest/AppIntegrityCostInstrumentedTest):
 * <ul>
 * <li>{@code d14d} = {@code cold} or {@code warm}; absent, the test returns at once, so a plain run measures nothing;
 * <li>{@code cold}: {@code target} = {@code 1k|100k|1m|4m}; ONE timed read, the first {@code SentomaruSealed.bytes} of
 * a fresh process (the runner force-stops the app before each instrumentation), so it carries the one-time header read
 * and the {@code kek} derivation (the spec's "primeira leitura");
 * <li>{@code warm}: {@code runs} (default 200) and {@code warmup} (default 20) subsequent reads per size in one process
 * (the spec's "leituras seguintes"); then the memory of the 4 MiB read: {@code allocatedVolume4m} (what one read
 * allocates, no GC) and {@code livePeak4m} (an upper bound of the live heap from back-to-back collections over
 * {@code liveReads}, default 20, reads), for the "até 3× o tamanho do claro" limit (see memoryOfFourMiB).
 * <li>{@code livepeak} (lab build with {@code -Psentomaru.d14dLiveProbe=true}): {@code reads} (default 5) 4 MiB reads
 * through the production reader wired with checkpoints (SealedLivePeakProbe): the live heap at fixed points and an
 * upper bound per interval from the allocation counter, the precise live peak of the report.
 * </ul>
 * Off the main thread (the instrumentation thread). The JSON goes to the instrumentation result {@code d14d}.
 */
@RunWith(AndroidJUnit4.class)
public class SealedReadCostInstrumentedTest {

    private static final Map<String, String> LADDER = new LinkedHashMap<>();

    static {
        LADDER.put("1k", "assets/d14d/1k.bin");
        LADDER.put("100k", "assets/d14d/100k.bin");
        LADDER.put("1m", "assets/d14d/1m.bin");
        LADDER.put("4m", "assets/d14d/4m.bin");
    }

    @Test
    public void sealed_read_cost() throws Exception {
        Instrumentation instrumentation = InstrumentationRegistry.getInstrumentation();
        Bundle arguments = InstrumentationRegistry.getArguments();
        String mode = arguments.getString("d14d");
        if (mode == null) return;
        if (Looper.myLooper() == Looper.getMainLooper()) throw new IllegalStateException("must run off the main thread");
        Context context = instrumentation.getTargetContext();
        // Sealed package: no plain fallback (a sealed build never falls back, D-14x10). The reader derives the kek lazily.
        SentomaruSealed.configure(false, null);
        JSONObject result = new JSONObject().put("mode", mode);
        JSONObject sizes = new JSONObject();
        try {
            if (mode.equals("cold")) {
                String target = arguments.getString("target");
                String path = target == null ? null : LADDER.get(target);
                if (path == null) throw new IllegalArgumentException("target must be one of " + LADDER.keySet());
                long start = System.nanoTime();
                byte[] bytes = SentomaruSealed.bytes(context, path);
                long micros = (System.nanoTime() - start) / 1_000;
                sizes.put(target, new JSONObject().put("firstReadMicros", micros).put("plainBytes", bytes.length));
            } else if (mode.equals("warm")) {
                int runs = intArg(arguments, "runs", 200);
                int warmup = intArg(arguments, "warmup", 20);
                for (Map.Entry<String, String> e : LADDER.entrySet()) {
                    long firstStart = System.nanoTime();
                    byte[] first = SentomaruSealed.bytes(context, e.getValue());
                    long firstMicros = (System.nanoTime() - firstStart) / 1_000;
                    List<Long> samples = new ArrayList<>();
                    for (int round = 0; round < warmup + runs; round++) {
                        long s = System.nanoTime();
                        byte[] b = SentomaruSealed.bytes(context, e.getValue());
                        long took = System.nanoTime() - s;
                        if (b.length != first.length) throw new IllegalStateException("read " + e.getKey() + " changed size");
                        if (round >= warmup) samples.add(took);
                    }
                    sizes.put(e.getKey(), tally(samples).put("firstReadMicros", firstMicros).put("plainBytes", first.length));
                }
                int liveReads = intArg(arguments, "liveReads", 20);
                result.put("runs", runs).put("warmup", warmup).put("memory4m", memoryOfFourMiB(context, liveReads));
            } else if (mode.equals("livepeak")) {
                // Lab build with -Psentomaru.d14dLiveProbe=true only (SealedLivePeakProbe): checkpoints in the reader.
                result.put("livePeak4mPrecise", SealedLivePeakProbe.run(context, intArg(arguments, "reads", 5)));
            } else {
                throw new IllegalArgumentException("d14d must be cold, warm or livepeak");
            }
        } finally {
            Bundle out = new Bundle();
            out.putString("d14d", result.put("sizes", sizes).toString());
            instrumentation.addResults(out);
        }
    }

    private static int intArg(Bundle arguments, String name, int fallback) {
        String v = arguments.getString(name);
        return v == null ? fallback : Integer.parseInt(v);
    }

    private static long jvmUsed() {
        Runtime runtime = Runtime.getRuntime();
        return runtime.totalMemory() - runtime.freeMemory();
    }

    /**
     * Memory of a 4 MiB read, two separate measures (review R, I-1):
     * <ul>
     * <li>{@code allocatedVolume4m}: JVM used heap (total - free) after minus before ONE read, and the highest value a
     * ~1 ms sampler saw during it, with NO garbage collection: it counts every allocation of the read still uncollected
     * (the asset bytes, the ciphertext copy, the GCM output, the inflater buffer and the returned copy), i.e. the volume
     * the read allocates, NOT the memory alive at one instant;
     * <li>{@code livePeak4m}: an UPPER bound of the live heap, NOT the live peak. A sampler thread runs
     * {@code Runtime.gc()} back to back while the instrumentation thread reads, and after each collection takes JVM used
     * heap (and, separately, {@code Debug.getNativeHeapAllocatedSize()}) above a baseline taken after GC with nothing
     * read; one more sample after the read, with the returned array still referenced. ART's collector is concurrent
     * and the read keeps allocating while it runs, so a sample also counts what the read allocated during that
     * collection: on the SM-A055M the maximum reached ~94% of all the read allocates, impossible as live memory.
     * The JVM and native maxima are reported apart (never summed: they may come from different instants).
     * </ul>
     * The precise live peak is the {@code livepeak} mode (SealedLivePeakProbe, checkpoints on the reading thread).
     */
    private static JSONObject memoryOfFourMiB(Context context, int liveReads) throws Exception {
        String path = LADDER.get("4m");
        // allocatedVolume4m: no GC during the read.
        gcSettle();
        final long nativeBefore = Debug.getNativeHeapAllocatedSize();
        final long jvmBefore = jvmUsed();
        final AtomicBoolean running = new AtomicBoolean(true);
        final AtomicLong jvmMax = new AtomicLong(jvmBefore);
        final AtomicLong nativeMax = new AtomicLong(nativeBefore);
        final AtomicInteger count = new AtomicInteger();
        Thread sampler = new Thread(() -> {
            while (running.get()) {
                long j = jvmUsed();
                long n = Debug.getNativeHeapAllocatedSize();
                if (j > jvmMax.get()) jvmMax.set(j);
                if (n > nativeMax.get()) nativeMax.set(n);
                count.incrementAndGet();
                try {
                    Thread.sleep(1);
                } catch (InterruptedException e) {
                    return;
                }
            }
        });
        sampler.setDaemon(true);
        sampler.start();
        byte[] bytes;
        try {
            bytes = SentomaruSealed.bytes(context, path);
        } finally {
            running.set(false);
            sampler.join();
        }
        long jvmDelta = jvmUsed() - jvmBefore;
        long nativeDelta = Debug.getNativeHeapAllocatedSize() - nativeBefore;
        int plain = bytes.length;
        JSONObject allocated = new JSONObject()
                .put("jvmUsedDeltaBytes", jvmDelta)
                .put("sampledJvmUsedMaxBytes", jvmMax.get() - jvmBefore)
                .put("nativeHeapDeltaBytes", nativeDelta)
                .put("sampledNativeHeapMaxBytes", nativeMax.get() - nativeBefore)
                .put("samples", count.get())
                .put("note", "volume allocated by one read: JVM used heap with no GC during the read, so garbage the "
                        + "read created is still counted; not the live memory at one instant");
        bytes = null;

        // livePeak4m: back-to-back explicit GCs while reading; live heap after each collection.
        gcSettle();
        final long liveBase = jvmUsed();
        final long nativeBase = Debug.getNativeHeapAllocatedSize();
        final AtomicLong liveMax = new AtomicLong(0);
        final AtomicLong liveNativeMax = new AtomicLong(0);
        final AtomicInteger gcs = new AtomicInteger();
        List<Long> perRead = new ArrayList<>();
        for (int r = 0; r < liveReads; r++) {
            final AtomicBoolean reading = new AtomicBoolean(true);
            final AtomicLong readMax = new AtomicLong(0);
            Thread collector = new Thread(() -> {
                while (reading.get()) {
                    Runtime.getRuntime().gc();
                    long live = jvmUsed() - liveBase;
                    long nat = Debug.getNativeHeapAllocatedSize() - nativeBase;
                    if (live > readMax.get()) readMax.set(live);
                    if (nat > liveNativeMax.get()) liveNativeMax.set(nat);
                    gcs.incrementAndGet();
                }
            });
            collector.setDaemon(true);
            collector.start();
            byte[] held;
            try {
                held = SentomaruSealed.bytes(context, path);
            } finally {
                reading.set(false);
                collector.join();
            }
            Runtime.getRuntime().gc(); // after the read, the returned array still referenced
            long after = jvmUsed() - liveBase;
            if (after > readMax.get()) readMax.set(after);
            if (held.length != plain) throw new IllegalStateException("4 MiB read changed size");
            held = null;
            perRead.add(readMax.get());
            if (readMax.get() > liveMax.get()) liveMax.set(readMax.get());
        }
        List<Long> sorted = new ArrayList<>(perRead);
        Collections.sort(sorted);
        JSONObject live = new JSONObject()
                .put("jvmLiveMaxBytes", liveMax.get())
                .put("nativeHeapMaxBytes", liveNativeMax.get())
                .put("perReadJvmLiveMaxP50Bytes", nearestRank(sorted, 50))
                .put("reads", liveReads)
                .put("gcSamples", gcs.get())
                .put("method", "Runtime.gc() back to back on a sampler thread during each read; JVM used heap and "
                        + "native heap above a post-GC baseline after each collection; plus one sample after the read "
                        + "with the returned array referenced")
                .put("note", "upper bound, overestimates: ART collects concurrently and the read keeps allocating "
                        + "during each collection, so what it allocated meanwhile is counted too; JVM and native "
                        + "maxima reported apart");
        return new JSONObject()
                .put("plainBytes", plain)
                .put("allocatedVolume4m", allocated)
                .put("livePeak4m", live)
                .put("limitBytes", 3L * plain)
                .put("limitComparedWith", "the live-peak interval of the report (lower bound from the reader's buffers, "
                        + "upper bound livePeak4m.jvmLiveMaxBytes)");
    }

    private static void gcSettle() throws InterruptedException {
        for (int i = 0; i < 3; i++) {
            Runtime.getRuntime().gc();
            Thread.sleep(20);
        }
    }

    /** Nearest-rank p50/p90/p99 over nanosecond samples, reported in microseconds (as J-03/D-05c). */
    private static JSONObject tally(List<Long> samples) throws JSONException {
        List<Long> sorted = new ArrayList<>(samples);
        Collections.sort(sorted);
        return new JSONObject().put("count", sorted.size()).put("p50", nearestRank(sorted, 50) / 1_000)
                .put("p90", nearestRank(sorted, 90) / 1_000).put("p99", nearestRank(sorted, 99) / 1_000)
                .put("maxMicros", sorted.isEmpty() ? 0 : sorted.get(sorted.size() - 1) / 1_000);
    }

    /** Nearest rank: the ceil(p/100 * n)-th smallest value (1-based), as run_j03_perf.percentile; 0 when empty. */
    static long nearestRank(List<Long> sorted, int p) {
        if (sorted.isEmpty()) return 0;
        int rank = (int) Math.ceil(p / 100.0 * sorted.size());
        return sorted.get(Math.max(0, Math.min(sorted.size(), rank) - 1));
    }
}
