package br.com.ebees.sentomaru.d14d;

import android.content.Context;
import android.content.res.AssetManager;
import android.os.Debug;

import br.com.ebees.sentomaru.sdk.sealed.AeadOpen;
import br.com.ebees.sentomaru.sdk.sealed.AssetSource;
import br.com.ebees.sentomaru.sdk.sealed.Inflate;
import br.com.ebees.sentomaru.sdk.sealed.Inflated;
import br.com.ebees.sentomaru.sdk.sealed.SealedReader;

import org.json.JSONArray;
import org.json.JSONException;
import org.json.JSONObject;

import java.io.IOException;
import java.io.InputStream;

/**
 * D-14d, item 13 (pending {@code livePeakPrecise}, the emulator window): the live heap of ONE 4 MiB sealed read at fixed
 * points, measured on the instrumentation thread that reads, so nothing allocates while it collects.
 *
 * <p>The production reader ({@code SealedReader} over {@code AssetSource}, the same objects {@code assetsOf} builds for
 * {@code SentomaruSealed}) is wired through its own seams: the {@code AssetManager} stream, {@code AeadOpen.GCM} and
 * {@code Inflate.RAW} are the real ones, each wrapped so a checkpoint runs at every stream read (64 KiB chunks), right
 * before and after the GCM open, right before and after the inflation, and after the read with the returned array still
 * referenced. A checkpoint takes the allocation counter ({@code art.gc.bytes-allocated}, bytes allocated ever), then
 * {@code Runtime.gc()} on this thread, then JVM used heap: the LIVE heap at that point (lower bound of the peak). The
 * peak between two checkpoints is at most the live heap at the first plus everything allocated until the second (no
 * GC needed for that bound, background collections included): an UPPER bound per interval. The live peak of the read is
 * in [max live at a checkpoint, max interval bound]; with a checkpoint at every stream chunk the interval bound is tight
 * wherever nothing is freed inside the interval (the {@code ByteArrayOutputStream} growth, the copies of the reader).
 *
 * <p>Calibration in the same process: a plain {@code new byte[4 MiB]} between two checkpoints must show up as ~4 MiB in
 * both the live heap and the interval bound. Native heap ({@code Debug.getNativeHeapAllocatedSize()}) is sampled at
 * each checkpoint, apart (never summed with the JVM). Lab only, built with -Psentomaru.d14dLiveProbe=true (the app keeps
 * the sealed package's internal classes by name, proguard-rules-d14d-liveprobe.pro); never in CI, never published.
 */
final class SealedLivePeakProbe {
    static final String PATH = "assets/d14d/4m.bin";
    private static final int MAX_POINTS = 512;

    private final String[] names = new String[MAX_POINTS];
    private final String[] from = new String[MAX_POINTS];
    private final long[] live = new long[MAX_POINTS];
    private final long[] bound = new long[MAX_POINTS];
    private final long[] nativeHeap = new long[MAX_POINTS];
    private int count;
    private boolean armed;
    private long base;
    private long nativeBase;
    private long lastLive;
    private long lastEver;
    private String lastName;

    private static long jvmUsed() {
        Runtime runtime = Runtime.getRuntime();
        return runtime.totalMemory() - runtime.freeMemory();
    }

    /** Bytes the runtime allocated since it started (ART {@code GetBytesAllocatedEver}); -1 when not reported. */
    static long allocatedEver() {
        String v = Debug.getRuntimeStat("art.gc.bytes-allocated");
        try {
            return v == null ? -1 : Long.parseLong(v.trim());
        } catch (NumberFormatException e) {
            return -1;
        }
    }

    /** Collect on this thread and start counting from here: the baseline of a measured read. */
    void arm() {
        for (int i = 0; i < 3; i++) Runtime.getRuntime().gc();
        count = 0;
        base = jvmUsed();
        nativeBase = Debug.getNativeHeapAllocatedSize();
        lastLive = 0;
        lastEver = allocatedEver();
        if (lastEver < 0) throw new IllegalStateException("art.gc.bytes-allocated not reported");
        lastName = "armed";
        armed = true;
    }

    void disarm() {
        armed = false;
    }

    /** One checkpoint (no-op when not armed): interval bound since the previous one, then the live heap here. */
    void mark(String name) {
        if (!armed) return;
        long ever = allocatedEver();
        long nat = Debug.getNativeHeapAllocatedSize() - nativeBase;
        Runtime.getRuntime().gc();
        System.runFinalization(); // objects only waiting for finalization (Cipher, Inflater) are not live
        Runtime.getRuntime().gc();
        long everAfter = allocatedEver(); // before reading the heap: a TLAB taken after this is in the next interval
        long here = jvmUsed() - base;
        if (count < MAX_POINTS) {
            names[count] = name;
            from[count] = lastName;
            live[count] = here;
            bound[count] = lastLive + (ever - lastEver);
            nativeHeap[count] = nat;
            count++;
        }
        lastLive = here;
        lastEver = everAfter;
        lastName = name;
    }

    int points() {
        return count;
    }

    /** {liveMaxBytes, liveMaxAt, boundMaxBytes, boundMaxAt, nativeMaxBytes, points[, detail]} of the armed span. */
    JSONObject summary(boolean detail) throws JSONException {
        int liveAt = 0, boundAt = 0;
        long nativeMax = 0;
        for (int i = 0; i < count; i++) {
            if (live[i] > live[liveAt]) liveAt = i;
            if (bound[i] > bound[boundAt]) boundAt = i;
            nativeMax = Math.max(nativeMax, nativeHeap[i]);
        }
        boolean ordered = true;
        for (int i = 0; i < count; i++) ordered &= bound[i] >= live[i];
        JSONObject out = new JSONObject().put("points", count).put("overflow", count >= MAX_POINTS)
                .put("boundAtLeastLiveEverywhere", ordered);
        if (count > 0) {
            out.put("liveMaxBytes", live[liveAt]).put("liveMaxAt", names[liveAt])
                    .put("boundMaxBytes", bound[boundAt]).put("boundMaxAt", from[boundAt] + " -> " + names[boundAt])
                    .put("nativeMaxBytes", nativeMax)
                    .put("nativeNote", "native heap sampled at the checkpoints only, not a bound of the native peak");
        }
        if (detail) {
            JSONArray rows = new JSONArray();
            for (int i = 0; i < count; i++) {
                rows.put(new JSONArray().put(from[i] + " -> " + names[i]).put(live[i]).put(bound[i]).put(nativeHeap[i]));
            }
            out.put("detailColumns", new JSONArray().put("interval").put("liveBytes").put("intervalBoundBytes")
                    .put("nativeHeapBytes")).put("detail", rows);
        }
        return out;
    }

    /** The production reader of this package, with the checkpoints around the real stream, GCM and inflation. */
    SealedReader reader(Context context) throws Exception {
        Context app = context.getApplicationContext() != null ? context.getApplicationContext() : context;
        AssetManager manager = app.getAssets();
        long versionCode = app.getPackageManager().getPackageInfo(app.getPackageName(), 0).getLongVersionCode();
        AssetSource source = new AssetSource(path -> {
            try {
                return new MarkedStream(manager.open(path, AssetManager.ACCESS_STREAMING));
            } catch (IOException e) {
                throw sneaky(e); // FileNotFoundException must reach AssetSource.read as is
            }
        });
        AeadOpen gcm = AeadOpen.Companion.getGCM();
        Inflate raw = Inflate.Companion.getRAW();
        AeadOpen aead = (key, nonce, sealed, aad) -> {
            mark("gcm:before");
            byte[] plain = gcm.open(key, nonce, sealed, aad);
            mark("gcm:after");
            return plain;
        };
        Inflate inflate = (data, max) -> {
            mark("inflate:before");
            Inflated out = raw.inflate(data, max);
            mark("inflate:after");
            return out;
        };
        return new SealedReader(source, app.getPackageName(), versionCode, aead, inflate);
    }

    /** {@code Throwable} rethrown unchecked (the Kotlin lambda of AssetSource declares no checked exception). */
    @SuppressWarnings("unchecked")
    private static <T extends Throwable> RuntimeException sneaky(Throwable t) throws T {
        throw (T) t;
    }

    /** The asset stream, with a checkpoint before every read call (the reader asks for 64 KiB at a time). */
    private final class MarkedStream extends InputStream {
        private final InputStream in;

        MarkedStream(InputStream in) {
            this.in = in;
        }

        @Override
        public int read() throws IOException {
            SealedLivePeakProbe.this.mark("stream");
            return in.read();
        }

        @Override
        public int read(byte[] b, int off, int len) throws IOException {
            SealedLivePeakProbe.this.mark("stream");
            return in.read(b, off, len);
        }

        @Override
        public void close() throws IOException {
            // AssetSource closes the stream (`use`) right after readAtMost returned: its ByteArrayOutputStream is out
            // of scope here, so this point splits the interval between the last read and the GCM copy (review R A4).
            SealedLivePeakProbe.this.mark("stream:close");
            in.close();
        }
    }

    /**
     * The measure: one unarmed read (header opened and kept, code warmed), a calibration, then {@code reads} armed 4 MiB
     * reads through the wired reader. The first armed read carries every checkpoint ({@code detail}).
     */
    static JSONObject run(Context context, int reads) throws Exception {
        if (reads < 1) throw new IllegalArgumentException("reads must be >= 1");
        SealedLivePeakProbe probe = new SealedLivePeakProbe();
        SealedReader reader = probe.reader(context);
        byte[] warm = reader.bytes(PATH);
        int plain = warm.length;
        warm = null;
        long everProbe = allocatedEver();

        probe.arm();
        probe.mark("calibration:start");
        byte[] ballast = new byte[plain];
        probe.mark("calibration:allocated");
        ballast[plain - 1] = 1; // still referenced at the checkpoint above
        ballast = null;
        probe.mark("calibration:dropped");
        JSONObject calibration = probe.summary(true).put("allocatedBytes", plain);
        probe.disarm();

        JSONArray perRead = new JSONArray();
        long liveMax = -1, boundMax = -1, nativeMax = 0;
        String liveAt = null, boundAt = null;
        JSONObject first = null;
        for (int r = 0; r < reads; r++) {
            probe.arm();
            byte[] held = reader.bytes(PATH);
            probe.mark("returned");
            probe.disarm();
            if (held.length != plain) throw new IllegalStateException("4 MiB read changed size");
            JSONObject s = probe.summary(r == 0);
            held = null;
            if (r == 0) first = s;
            else perRead.put(s);
            long l = s.getLong("liveMaxBytes"), b = s.getLong("boundMaxBytes");
            if (l > liveMax) {
                liveMax = l;
                liveAt = s.getString("liveMaxAt");
            }
            if (b > boundMax) {
                boundMax = b;
                boundAt = s.getString("boundMaxAt");
            }
            nativeMax = Math.max(nativeMax, s.getLong("nativeMaxBytes"));
        }
        return new JSONObject()
                .put("plainBytes", plain)
                .put("reads", reads)
                .put("allocationCounter", everProbe >= 0 ? "art.gc.bytes-allocated" : "unavailable")
                .put("build", "d14dLiveProbe")
                .put("vmVersion", String.valueOf(System.getProperty("java.vm.version")))
                .put("liveMaxBytes", liveMax).put("liveMaxAt", liveAt)
                .put("boundMaxBytes", boundMax).put("boundMaxAt", boundAt)
                .put("nativeMaxBytes", nativeMax)
                .put("calibration", calibration)
                .put("firstRead", first)
                .put("otherReads", perRead);
    }
}
