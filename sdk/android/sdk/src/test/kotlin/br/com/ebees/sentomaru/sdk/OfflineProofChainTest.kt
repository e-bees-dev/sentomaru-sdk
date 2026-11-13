package br.com.ebees.sentomaru.sdk

import br.com.ebees.sentomaru.core.SentomaruException
import java.io.File
import java.security.KeyFactory
import java.security.KeyPair
import java.security.KeyPairGenerator
import java.security.MessageDigest
import java.security.Signature
import java.security.spec.ECGenParameterSpec
import java.security.spec.X509EncodedKeySpec
import java.time.Clock
import java.time.Instant
import java.time.ZoneOffset
import java.util.Base64
import java.util.UUID
import org.junit.Assert.*
import org.junit.Test

/**
 * D-26c: the Android side of the OfflineProofChain by JVM doubles. The golden vectors of the contract pin the bytes
 * (record, hashes, seed, signature check); a flow with JDK keys pins sealing, order, limits and the reconcile exchange.
 * Nothing here runs on a device: clocks and storage are doubles, so the drift tolerance and BOOT_COUNT are NOT measured.
 */
class OfflineProofChainTest {
    private val b64 = Base64.getUrlEncoder().withoutPadding()
    private val dec = Base64.getUrlDecoder()

    // ---- golden vectors ----
    private val vectors: String = listOf("contracts/sdk/offline-proof-chain-v1-vectors.json", "../../../contracts/sdk/offline-proof-chain-v1-vectors.json",
        "../../contracts/sdk/offline-proof-chain-v1-vectors.json").map { File(it) }.first { it.isFile }.readText()

    private fun top(name: String) = Regex("\"$name\"\\s*:\\s*\"([^\"]+)\"").find(vectors.substringBefore("\"cases\""))!!.groupValues[1]

    private class VItem(val seq: Long, val boot: Long, val elapsed: Long, val wall: Long, val digest: String, val prev: String, val hash: String, val sig: String, val hex: String)

    private fun caseItems(id: String): List<VItem> {
        val block = vectors.substringAfter("\"id\": \"$id\"").let { it.substringBefore("\"id\": \"").ifEmpty { it } }
        fun f(o: String, n: String) = Regex("\"$n\"\\s*:\\s*\"?([^\",}\\s]+)\"?").find(o)!!.groupValues[1]
        return Regex("\\{[^{}]*\"seq\"[^{}]*}").findAll(block).map { m ->
            val o = m.value
            VItem(f(o, "seq").toLong(), f(o, "bootCount").toLong(), f(o, "elapsedRealtimeNanos").toLong(), f(o, "wallClockMillis").toLong(),
                f(o, "operationDigest"), f(o, "prevHash"), f(o, "hash"), f(o, "signature"), f(o, "recordHex"))
        }.toList()
    }

    private fun hex(b: ByteArray) = b.joinToString("") { "%02x".format(it) }

    @Test fun seedHashEqualsTheVector() {
        val seed = OfflineChain.seedHash(UUID.fromString(top("permitId")), dec.decode(top("chainSeed")))
        assertEquals(top("seedHashHex").take(64), hex(seed))
    }

    @Test fun everyVectorRecordHashAndSignatureHoldInTheSdkCode() {
        val permit = UUID.fromString(top("permitId"))
        val key = KeyFactory.getInstance("EC").generatePublic(X509EncodedKeySpec(Base64.getDecoder().decode(top("installationPublicKeySpki"))))
        for (id in listOf("honest", "OFF-01", "OFF-03a", "OFF-03b")) {
            val items = caseItems(id)
            assertTrue(id, items.isNotEmpty())
            for (i in items) {
                val record = OfflineChain.record(permit, i.seq, i.boot, i.elapsed, i.wall, dec.decode(i.digest), dec.decode(i.prev))
                assertEquals("$id/${i.seq} record", i.hex, hex(record))
                assertEquals("$id/${i.seq} hash", i.hash, b64.encodeToString(OfflineChain.hash(record)))
                val v = Signature.getInstance("SHA256withECDSA").apply { initVerify(key); update(record) }
                assertTrue("$id/${i.seq} signature", v.verify(dec.decode(i.sig)))
            }
        }
        assertEquals(110, OfflineChain.RECORD_BYTES)
    }

    // ---- flow with JDK keys ----
    private class Clocks(var wall: Long, var elapsed: Long, var boot: Long = 7) : OfflineClocks {
        override fun elapsedRealtimeNanos() = elapsed
        override fun wallClockMillis() = wall
        override fun bootCount() = boot
    }
    private class Memory : OfflineChainStore {
        val map = HashMap<UUID, OfflineChainState>(); var fail = false
        override fun read(permitId: UUID) = map[permitId]
        override fun write(permitId: UUID, state: OfflineChainState) { if (fail) throw IllegalStateException("x"); map[permitId] = state }
        override fun delete(permitId: UUID) { map.remove(permitId) }
    }
    private class State : InstallationStore {
        var value: InstallationRecord? = null
        override fun read() = value
        override fun write(record: InstallationRecord?) { value = record }
    }
    private class Keys : InstallationKeys {
        val keys = HashMap<String, KeyPair>()
        override fun exists(alias: String) = keys.containsKey(alias)
        override fun generate(alias: String, challenge: ByteArray, strongBox: Boolean): KeyMaterial {
            keys[alias] = KeyPairGenerator.getInstance("EC").apply { initialize(ECGenParameterSpec("secp256r1")) }.generateKeyPair(); return material(alias)
        }
        override fun material(alias: String) = KeyMaterial(keys.getValue(alias).public.encoded, emptyList())
        override fun sign(alias: String, bytes: ByteArray) = Signature.getInstance("SHA256withECDSAinP1363Format")
            .run { initSign(keys.getValue(alias).private); update(bytes); sign() }
        override fun delete(alias: String) { keys.remove(alias) }
        override fun deleteOwned(prefix: String) { keys.keys.filter { it.startsWith(prefix) }.forEach { keys.remove(it) } }
    }

    private val now = Instant.parse("2026-11-05T08:00:00Z")
    private val config = SentomaruConfig("org", "app", "hml", setOf("consumer.example"), "https://consumer.example/enroll")
    private val keys = Keys()
    private val store = Memory()
    private val clocks = Clocks(now.toEpochMilli() + 60_000, 600_000_000_000L)
    private val client: SentomaruClient = SentomaruClient(config, keys, State(), Clock.fixed(now, ZoneOffset.UTC)).also { c ->
        c.enroll(EnrollmentChallenge(UUID.randomUUID().toString(), Base64.getEncoder().encodeToString(ByteArray(32) { 1 }), ByteArray(32) { 8 }, now.plusSeconds(120))) { m ->
            EnrollmentGrant(UUID.randomUUID().toString(), m.header("x-sentomaru-session")!!, UUID.randomUUID().toString(), "hardware", "verified")
        }
    }
    private val chain = SentomaruOfflineChain(client, store, clocks)
    private val permitId = UUID.fromString("6f1c0000-0000-4000-8000-00000000d026")
    private val seed = ByteArray(32) { (it + 1).toByte() }
    private fun permit(max: Int = 3) = OfflinePermit(permitId, seed, now, now.plusSeconds(86400), max, 120).also {
        store.write(permitId, OfflineChainState(0, OfflineChain.seedHash(permitId, seed)))
    }
    private fun digest(n: Int) = MessageDigest.getInstance("SHA-256").digest("op$n".toByteArray())
    private fun publicKey() = keys.keys.values.single().public

    private fun code(block: () -> Unit): String = try { block(); "none" } catch (e: SentomaruException) { e.error.code }

    @Test fun sealsAreOrderedChainedAndSignedByTheInstallationKey() {
        val p = permit()
        val seals = (0..2).map { clocks.wall += 1000; clocks.elapsed += 1_000_000_000L; chain.sealOfflineOperation(p, digest(it)) }
        assertEquals(listOf(0L, 1L, 2L), seals.map { it.seq })
        assertArrayEquals(OfflineChain.seedHash(permitId, seed), seals[0].prevHash())
        assertArrayEquals(seals[0].hash(), seals[1].prevHash()); assertArrayEquals(seals[1].hash(), seals[2].prevHash())
        for (s in seals) {
            val record = OfflineChain.record(permitId, s.seq, s.bootCount, s.elapsedRealtimeNanos, s.wallClockMillis, s.operationDigest(), s.prevHash())
            assertArrayEquals(OfflineChain.hash(record), s.hash())
            val v = Signature.getInstance("SHA256withECDSA").apply { initVerify(publicKey()); update(record) }
            assertTrue(v.verify(s.signature())) // DER, as the server verifies
        }
    }

    @Test fun aSealIsNotAValidRequestSignatureBase() {
        // Every record starts with the SMOFF1 domain tag; a request signature base starts with a component line.
        val record = OfflineChain.record(permitId, 0, 7, 1, 1, digest(0), ByteArray(32))
        assertEquals("SMOFF1", String(record, 0, 6, Charsets.US_ASCII))
    }

    @Test fun refusalsSealNothingAndKeepTheState() {
        val p = permit(max = 1)
        assertEquals("OfflineBadDigest", code { chain.sealOfflineOperation(p, ByteArray(31)) })
        chain.sealOfflineOperation(p, digest(0))
        val after = store.map.getValue(permitId)
        assertEquals("OfflineChainFull", code { chain.sealOfflineOperation(p, digest(1)) })
        assertSame(after, store.map.getValue(permitId))
        val p2 = permit(max = 3)
        clocks.wall = p2.validUntil.toEpochMilli()
        assertEquals("OfflinePermitExpired", code { chain.sealOfflineOperation(p2, digest(2)) })
        store.map.remove(permitId)
        assertEquals("OfflineStateUnavailable", code { chain.sealOfflineOperation(p2, digest(2)) })
    }

    @Test fun aStateWriteFailureIsAnErrorNotASilentSeal() {
        val p = permit(); store.fail = true
        assertEquals("OfflineStateUnavailable", code { chain.sealOfflineOperation(p, digest(0)) })
    }

    @Test fun bootCountUnavailableIsSealedAsTheSentinel() {
        val p = permit(); clocks.boot = OfflineChain.BOOT_COUNT_UNAVAILABLE
        val s = chain.sealOfflineOperation(p, digest(0))
        assertEquals(0xFFFFFFFFL, s.bootCount)
        assertEquals(0xFF.toByte(), OfflineChain.record(permitId, 0, s.bootCount, 1, 1, digest(0), ByteArray(32))[26])
    }

    @Test fun permitParsesAndRefusesMalformedBodies() {
        val ok = "{\"permitId\":\"$permitId\",\"chainSeed\":\"${b64.encodeToString(seed)}\",\"issuedAt\":\"2026-11-05T08:00:00Z\"," +
            "\"validUntil\":\"2026-11-06T08:00:00Z\",\"maxItems\":50,\"driftToleranceSeconds\":120}"
        val p = OfflinePermit.parse(ok)!!
        assertEquals(50, p.maxItems); assertEquals(120, p.driftToleranceSeconds); assertArrayEquals(seed, p.chainSeed())
        assertNull(OfflinePermit.parse(ok.replace("\"maxItems\":50", "\"maxItems\":500")))
        assertNull(OfflinePermit.parse(ok.replace(b64.encodeToString(seed), "AAAA")))
        assertNull(OfflinePermit.parse("{}"))
        assertNull(OfflinePermit.parse(ok + ok))
    }

    @Test fun requestPermitStoresTheStateAndMapsRefusals() {
        val ok = "{\"permitId\":\"$permitId\",\"chainSeed\":\"${b64.encodeToString(seed)}\",\"issuedAt\":\"2026-11-05T08:00:00Z\"," +
            "\"validUntil\":\"2026-11-06T08:00:00Z\",\"maxItems\":50,\"driftToleranceSeconds\":120}"
        val issued = chain.requestPermit("https://consumer.example/offline-permits") { TransactionAnswer(201, ok) }
        assertTrue(issued is OfflinePermitOutcome.Issued)
        assertEquals(0L, store.map.getValue(permitId).nextSeq)
        val refused = chain.requestPermit("https://consumer.example/offline-permits") { TransactionAnswer(403, "{\"code\":\"offline-disabled\"}") }
        assertEquals(403, (refused as OfflinePermitOutcome.Refused).status)
        assertTrue(chain.requestPermit("https://consumer.example/offline-permits") { TransactionAnswer(503, "") } is OfflinePermitOutcome.Unavailable)
        assertTrue(chain.requestPermit("https://consumer.example/offline-permits") { throw java.io.IOException() } is OfflinePermitOutcome.Unavailable)
        assertThrows(SentomaruException::class.java) { chain.requestPermit("https://evil.example/x") { TransactionAnswer(201, ok) } }
    }

    // Shield #12: a 429 on the permit or on the batch of seals hands back the server's Retry-After (bounded); the seals stay.
    @Test fun aRateLimitedPermitOrReconciliationCarriesTheBoundedRetryAfter() {
        val permitWait = chain.requestPermit("https://consumer.example/offline-permits") { TransactionAnswer(429, "", 45L) } as OfflinePermitOutcome.Unavailable
        assertEquals(45L, permitWait.retryAfterSeconds)
        val p = permit(); val seals = (0..1).map { clocks.wall += 1000; clocks.elapsed += 1_000_000_000L; chain.sealOfflineOperation(p, digest(it)) }
        fun reconcile(status: Int, wait: Long?) = chain.reconcileOfflineChain(p, seals, "https://consumer.example/r") { TransactionAnswer(status, "", wait) }
        assertEquals(1L, (reconcile(429, 0L) as OfflineReconcileOutcome.Unavailable).retryAfterSeconds)
        assertEquals(86_400L, (reconcile(503, 86_400L) as OfflineReconcileOutcome.Unavailable).retryAfterSeconds)
        assertNull((reconcile(429, -1L) as OfflineReconcileOutcome.Unavailable).retryAfterSeconds)    // RC-07
        val negPermit = chain.requestPermit("https://consumer.example/offline-permits") { TransactionAnswer(429, "", -1L) }
        assertNull((negPermit as OfflinePermitOutcome.Unavailable).retryAfterSeconds)
        assertNull((reconcile(429, null) as OfflineReconcileOutcome.Unavailable).retryAfterSeconds)
    }

    @Test fun reconcileBodyCarriesTheSealsAndTheVerdictIsParsed() {
        val p = permit(); val seals = (0..1).map { clocks.wall += 1000; clocks.elapsed += 1_000_000_000L; chain.sealOfflineOperation(p, digest(it)) }
        val body = String(chain.reconcileBody(p, seals))
        assertTrue(body.startsWith("{\"permitId\":\"$permitId\",\"items\":[{\"seq\":0,\"bootCount\":7,"))
        assertEquals(2, Regex("\"signature\"").findAll(body).count())
        var sent = ""
        val accepted = "{\"permitId\":\"$permitId\",\"status\":\"accepted\",\"itemCount\":2,\"signals\":[],\"bootCount\":\"available\",\"items\":[]}"
        val v = chain.reconcileOfflineChain(p, seals, "https://consumer.example/offline-permits/reconciliations") { sent = String(it.body()); TransactionAnswer(200, accepted) }
        assertEquals(body, sent)
        assertTrue((v as OfflineReconcileOutcome.Verdict).accepted)
        assertNull(store.map[permitId]) // dropped after a verdict
    }

    @Test fun aRejectedVerdictKeepsItsSignalsAndOddAnswersAreRefused() {
        val p = permit(); val seals = listOf(chain.sealOfflineOperation(p, digest(0)))
        fun run(status: Int, body: String) = chain.reconcileOfflineChain(p, seals, "https://consumer.example/r") { TransactionAnswer(status, body) }
        val rejected = "{\"permitId\":\"$permitId\",\"status\":\"rejected\",\"itemCount\":1,\"signals\":[\"offline_clock_tampered\"],\"items\":[]}"
        val r = run(200, rejected) as OfflineReconcileOutcome.Verdict
        assertFalse(r.accepted); assertEquals(listOf("offline_clock_tampered"), r.signals)
        for (bad in listOf(
            rejected.replace("offline_clock_tampered", "raw_device_value"),           // a code outside the contract
            rejected.replace("rejected", "accepted"),                                    // accepted with signals
            rejected.replace("[\"offline_clock_tampered\"]", "[]"),                      // rejected with none
            rejected.replace("rejected", "pending"),
        )) assertTrue(bad, run(200, bad) is OfflineReconcileOutcome.Refused)
        assertEquals("permit-expired", (run(410, "{\"code\":\"permit-expired\"}") as OfflineReconcileOutcome.Refused).code)
        store.write(permitId, OfflineChainState(1, ByteArray(32)))
        assertTrue(run(500, "") is OfflineReconcileOutcome.Unavailable)
        assertNotNull(store.map[permitId]) // no verdict: state kept
    }

    @Test fun advisoriesAreReadWithoutChangingTheVerdict() {
        val p = permit(); val seals = listOf(chain.sealOfflineOperation(p, digest(0)))
        fun run(body: String) = chain.reconcileOfflineChain(p, seals, "https://consumer.example/r") { TransactionAnswer(200, body) } as OfflineReconcileOutcome.Verdict
        val head = "{\"permitId\":\"$permitId\",\"status\":\"accepted\",\"itemCount\":1,\"signals\":[],\"bootCount\":\"unavailable\",\"items\":[],"
        val boot = run("$head\"advisories\":[\"offline_boot_unavailable\"]}")
        assertTrue(boot.accepted); assertTrue(boot.signals.isEmpty())                       // not a signal: the verdict stands
        assertEquals(listOf("offline_boot_unavailable"), boot.advisories)
        assertEquals(listOf("offline_boot_unavailable", "future_code"), run("$head\"advisories\":[\"offline_boot_unavailable\",\"future_code\",\"offline_boot_unavailable\"]}").advisories)
        assertTrue(run("$head\"advisories\":[]}").advisories.isEmpty())
        assertTrue(run(head.trimEnd(',') + "}").advisories.isEmpty())                       // an older server: no field
        for (odd in listOf("[\"Bad Code\"]", "[1]", "[\"a\",]", "[\"" + "x".repeat(65) + "\"]"))
            assertTrue(odd, run("$head\"advisories\":$odd}").advisories.isEmpty())        // malformed: none, never a refusal
        assertEquals(8, run("$head\"advisories\":[" + (1..12).joinToString(",") { "\"code_${"abcdefghijkl"[it - 1]}\"" } + "]}").advisories.size)
    }

    @Test fun beginStartsOnceAndNeverOverwritesProgress() {
        val p = OfflinePermit(permitId, seed, now, now.plusSeconds(86400), 3, 120)
        chain.begin(p)
        chain.sealOfflineOperation(p, digest(0))
        chain.begin(p) // a second call does not rewind the chain
        assertEquals(1L, store.map.getValue(permitId).nextSeq)
        assertEquals(1L, chain.sealOfflineOperation(p, digest(1)).seq)
    }
}
