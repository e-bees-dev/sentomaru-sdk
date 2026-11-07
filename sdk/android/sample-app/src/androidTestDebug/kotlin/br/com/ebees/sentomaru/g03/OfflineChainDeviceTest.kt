package br.com.ebees.sentomaru.g03

import androidx.test.ext.junit.runners.AndroidJUnit4
import br.com.ebees.sentomaru.sdk.AndroidInstallationKeys
import br.com.ebees.sentomaru.sdk.AndroidInstallationStore
import br.com.ebees.sentomaru.sdk.AndroidOfflineChainStore
import br.com.ebees.sentomaru.sdk.AndroidOfflineClocks
import br.com.ebees.sentomaru.sdk.OfflineChain
import br.com.ebees.sentomaru.sdk.OfflinePermit
import br.com.ebees.sentomaru.sdk.SentomaruClient
import br.com.ebees.sentomaru.sdk.SentomaruOfflineChain
import org.junit.After
import org.junit.Assert.*
import org.junit.Before
import org.junit.Test
import org.junit.runner.RunWith
import java.security.MessageDigest
import java.security.Signature
import java.time.Instant
import java.util.UUID

/**
 * G-03 P-3 (OFF-01..03 on a device): the offline proof chain with the REAL clocks, the REAL
 * installation key (Keystore) and the real store. The permit is synthetic (no server). No finger needed. Checks what a device
 * adds over the JVM test: the monotonic clock, `bootCount` as the device reports it, the Keystore signature over the record.
 */
@RunWith(AndroidJUnit4::class)
class OfflineChainDeviceTest {
    private val permitId = UUID.fromString("aaaaaaaa-bbbb-4ccc-8ddd-eeeeeeeeeeee")
    private val seed = ByteArray(32) { 5 }
    private lateinit var client: SentomaruClient
    private lateinit var chain: SentomaruOfflineChain
    private lateinit var store: AndroidOfflineChainStore

    @Before fun setUp() {
        client = SentomaruClient(G03Support.config, AndroidInstallationKeys(), AndroidInstallationStore(G03Support.context, G03Support.config))
        client.reset()
        client.enroll(G03Support.challenge()) { G03Support.grant() }
        store = AndroidOfflineChainStore(G03Support.context)
        store.delete(permitId)
        chain = SentomaruOfflineChain(client, store, AndroidOfflineClocks(G03Support.context))
    }

    @After fun tearDown() { store.delete(permitId); client.reset() }

    private fun permit(max: Int = 5) = OfflinePermit(permitId, seed, Instant.now().minusSeconds(60), Instant.now().plusSeconds(3600), max, 120)
    private fun digest(n: Int) = MessageDigest.getInstance("SHA-256").digest("g03-op-$n".toByteArray())

    private fun installationKey(): java.security.PublicKey {
        val ks = java.security.KeyStore.getInstance("AndroidKeyStore").apply { load(null) }
        return ks.getCertificate(ks.aliases().toList().single()).publicKey
    }

    /** OFF-01: seals in order, linked by hash, signed by the Keystore key; the monotonic clock never goes back. */
    @Test fun off01_sealsAreOrderedLinkedAndSignedOnTheDevice() {
        val p = permit(); chain.begin(p)
        val seals = (0..2).map { Thread.sleep(300); chain.sealOfflineOperation(p, digest(it)) }
        assertEquals(listOf(0L, 1L, 2L), seals.map { it.seq })
        assertArrayEquals(OfflineChain.seedHash(permitId, seed), seals[0].prevHash())
        assertArrayEquals(seals[0].hash(), seals[1].prevHash()); assertArrayEquals(seals[1].hash(), seals[2].prevHash())
        assertTrue("elapsedRealtime strictly increases", seals.zipWithNext().all { (a, b) -> b.elapsedRealtimeNanos > a.elapsedRealtimeNanos })
        for (s in seals) {
            val record = OfflineChain.record(permitId, s.seq, s.bootCount, s.elapsedRealtimeNanos, s.wallClockMillis, s.operationDigest(), s.prevHash())
            assertArrayEquals(OfflineChain.hash(record), s.hash())
            val v = Signature.getInstance("SHA256withECDSA").apply { initVerify(installationKey()); update(record) }
            assertTrue("Keystore signature of seal ${s.seq}", v.verify(s.signature()))
        }
        G03Support.report("OFF-01", "PASS")
    }

    /**
     * OFF-02: wall clock against the monotonic one. With the device clock untouched the drift between the first and last seal stays
     * well below the permit tolerance (120 s). The test does not change the clock (that needs the owner at Settings); it MEASURES
     * the drift and prints it. Moving the wall clock is the manual step of the roteiro, repeated and logged by hand.
     */
    @Test fun off02_wallVersusMonotonicDriftIsMeasured() {
        val p = permit(); chain.begin(p)
        val a = chain.sealOfflineOperation(p, digest(0)); Thread.sleep(2_000); val b = chain.sealOfflineOperation(p, digest(1))
        val wallMs = b.wallClockMillis - a.wallClockMillis
        val monoMs = (b.elapsedRealtimeNanos - a.elapsedRealtimeNanos) / 1_000_000
        val driftMs = Math.abs(wallMs - monoMs)
        G03Support.report("OFF-02", "MEASURED", "wallMs=$wallMs monoMs=$monoMs driftMs=$driftMs toleranceMs=${p.driftToleranceSeconds * 1000}")
        assertTrue("drift $driftMs ms under the tolerance", driftMs < p.driftToleranceSeconds * 1000L)
    }

    /**
     * OFF-02 with the wall clock MOVED by the owner (Settings, automatic date and time off, time changed by several minutes). The test
     * seals once, then waits up to 150 s for the wall clock to leave the monotonic one by more than 5 s, then seals again. It MEASURES the
     * drift of the two signed seals and whether it passes the permit tolerance (the server verifier then answers `offline_clock_tampered`;
     * that part is covered by the .NET vectors, not here). If the clock never moved it reports NOT_MOVED, which is not a pass of OFF-02.
     */
    @Test fun off02_wallClockMovedByTheOwnerIsMeasured() {
        val p = permit(); chain.begin(p)
        val a = chain.sealOfflineOperation(p, digest(0))
        G03Support.report("OFF-02-MOVED", "READY", "first seal done: move the wall clock NOW")
        val t0 = System.currentTimeMillis(); val m0 = android.os.SystemClock.elapsedRealtime()
        var moved = false
        for (i in 0 until 150) {
            Thread.sleep(1_000)
            val d = Math.abs((System.currentTimeMillis() - t0) - (android.os.SystemClock.elapsedRealtime() - m0))
            if (d > 5_000) { moved = true; break }
        }
        val b = chain.sealOfflineOperation(p, digest(1))
        val wallMs = b.wallClockMillis - a.wallClockMillis
        val monoMs = (b.elapsedRealtimeNanos - a.elapsedRealtimeNanos) / 1_000_000
        val driftMs = Math.abs(wallMs - monoMs)
        val tolMs = p.driftToleranceSeconds * 1000L
        for (s in listOf(a, b)) {
            val record = OfflineChain.record(permitId, s.seq, s.bootCount, s.elapsedRealtimeNanos, s.wallClockMillis, s.operationDigest(), s.prevHash())
            val v = Signature.getInstance("SHA256withECDSA").apply { initVerify(installationKey()); update(record) }
            assertTrue("Keystore signature of seal ${s.seq}", v.verify(s.signature()))
        }
        G03Support.report("OFF-02-MOVED", "MEASURED", "moved=$moved wallMs=$wallMs monoMs=$monoMs driftMs=$driftMs toleranceMs=$tolMs overTolerance=${driftMs >= tolMs}")
    }

    /** OFF-03: `bootCount` as the device reports it: a real value or the documented sentinel, never negative noise; stable between seals. */
    @Test fun off03_bootCountIsARealValueOrTheSentinelAndStable() {
        val p = permit(); chain.begin(p)
        val a = chain.sealOfflineOperation(p, digest(0)); val b = chain.sealOfflineOperation(p, digest(1))
        assertEquals("bootCount does not change between two seals", a.bootCount, b.bootCount)
        val sentinel = OfflineChain.BOOT_COUNT_UNAVAILABLE
        assertTrue("bootCount=${a.bootCount} is a count or the sentinel $sentinel", a.bootCount == sentinel || a.bootCount in 0..4_294_967_294L)
        G03Support.report("OFF-03", "MEASURED", "bootCount=${a.bootCount} sentinel=${a.bootCount == sentinel}")
    }
}
