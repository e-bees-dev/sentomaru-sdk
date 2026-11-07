package br.com.ebees.sentomaru.sdk

import br.com.ebees.sentomaru.core.SentomaruError
import java.nio.ByteBuffer
import java.security.MessageDigest
import java.time.Instant
import java.util.Base64
import java.util.UUID

/**
 * D-26c: why an offline operation was not sealed. Nothing is sealed and the stored chain state is untouched.
 * Contract `offline-proof-chain-v1`, section 3.
 */
abstract class OfflineChainError(code: String) : SentomaruError(code) {
    /** The permit's `validUntil` has passed by the wall clock. */
    class PermitExpired : OfflineChainError("OfflinePermitExpired")
    /** The permit already holds `maxItems` seals. */
    class ChainFull : OfflineChainError("OfflineChainFull")
    /** The permit body is not a valid permit. */
    class PermitInvalid : OfflineChainError("OfflinePermitInvalid")
    /** The digest is not 32 bytes. */
    class BadDigest : OfflineChainError("OfflineBadDigest")
    /** The saved chain state could not be read or written; sealing without it would break the chain. */
    class StateUnavailable : OfflineChainError("OfflineStateUnavailable")
}

/** The permit issued by `POST offline-permits` (contract section 2). */
class OfflinePermit(
    val permitId: UUID, chainSeed: ByteArray, val issuedAt: Instant, val validUntil: Instant,
    val maxItems: Int, val driftToleranceSeconds: Int,
) {
    private val seed: ByteArray = chainSeed.copyOf()
    init {
        require(seed.size == OfflineChain.HASH_BYTES) { "chainSeed must be ${OfflineChain.HASH_BYTES} bytes" }
        require(maxItems in 1..OfflineChain.MAX_ITEMS) { "maxItems" }
        require(driftToleranceSeconds in 1..900) { "driftToleranceSeconds" }
        require(issuedAt.isBefore(validUntil)) { "validUntil" }
    }
    fun chainSeed(): ByteArray = seed.copyOf()

    companion object {
        /** Parses the `201` body, or null when a field is absent, repeated or malformed. */
        @JvmStatic
        fun parse(text: String): OfflinePermit? {
            if (text.length > 4096) return null
            return try {
                OfflinePermit(
                    UUID.fromString(ReattestationJson.string(text, "permitId") ?: return null),
                    Base64.getUrlDecoder().decode(ReattestationJson.string(text, "chainSeed") ?: return null),
                    Instant.parse(ReattestationJson.string(text, "issuedAt") ?: return null),
                    Instant.parse(ReattestationJson.string(text, "validUntil") ?: return null),
                    number(text, "maxItems") ?: return null,
                    number(text, "driftToleranceSeconds") ?: return null,
                )
            } catch (_: RuntimeException) { null }
        }

        private fun number(text: String, name: String): Int? {
            val all = Regex("\"${Regex.escape(name)}\"\\s*:\\s*(\\d{1,6})\\b").findAll(text).toList()
            return all.singleOrNull()?.groupValues?.get(1)?.toIntOrNull()
        }
    }
}

/** One sealed operation (contract section 3). All byte fields are copies. */
class OfflineSeal(
    val seq: Long, val bootCount: Long, val elapsedRealtimeNanos: Long, val wallClockMillis: Long,
    operationDigest: ByteArray, prevHash: ByteArray, hash: ByteArray, signature: ByteArray,
) {
    private val digest = operationDigest.copyOf()
    private val prev = prevHash.copyOf()
    private val hashBytes = hash.copyOf()
    private val sig = signature.copyOf()
    fun operationDigest(): ByteArray = digest.copyOf()
    fun prevHash(): ByteArray = prev.copyOf()
    fun hash(): ByteArray = hashBytes.copyOf()
    fun signature(): ByteArray = sig.copyOf()

    internal fun toJson(): String {
        val b64 = Base64.getUrlEncoder().withoutPadding()
        return "{\"seq\":$seq,\"bootCount\":$bootCount,\"elapsedRealtimeNanos\":$elapsedRealtimeNanos," +
            "\"wallClockMillis\":$wallClockMillis,\"operationDigest\":\"${b64.encodeToString(digest)}\"," +
            "\"prevHash\":\"${b64.encodeToString(prev)}\",\"hash\":\"${b64.encodeToString(hashBytes)}\"," +
            "\"signature\":\"${b64.encodeToString(sig)}\"}"
    }
}

/** The byte rules of the chain. The golden vectors in `contracts/sdk/offline-proof-chain-v1-vectors.json` pin them. */
object OfflineChain {
    const val HASH_BYTES = 32
    const val MAX_ITEMS = 128
    const val RECORD_BYTES = 6 + 16 + 4 + 4 + 8 + 8 + 32 + 32
    /** `bootCount` when the platform does not give one (contract section 4). */
    const val BOOT_COUNT_UNAVAILABLE = 0xFFFFFFFFL
    private val TAG = "SMOFF1".toByteArray(Charsets.US_ASCII)
    private val SEED_TAG = "SMOFF1-seed".toByteArray(Charsets.US_ASCII)

    /** `prevHash` of item 0: SHA-256("SMOFF1-seed" || permitId || chainSeed). */
    fun seedHash(permitId: UUID, chainSeed: ByteArray): ByteArray =
        MessageDigest.getInstance("SHA-256").run {
            update(SEED_TAG); update(uuidBytes(permitId)); update(chainSeed); digest()
        }

    /** The 110 bytes that are hashed and signed. */
    fun record(permitId: UUID, seq: Long, bootCount: Long, elapsedNanos: Long, wallMillis: Long,
               operationDigest: ByteArray, prevHash: ByteArray): ByteArray {
        require(seq in 0 until MAX_ITEMS) { "seq" }
        require(bootCount in 0..BOOT_COUNT_UNAVAILABLE) { "bootCount" }
        require(elapsedNanos >= 0 && wallMillis >= 0) { "clock" }
        require(operationDigest.size == HASH_BYTES && prevHash.size == HASH_BYTES) { "digest" }
        return ByteBuffer.allocate(RECORD_BYTES).put(TAG).put(uuidBytes(permitId))
            .putInt(seq.toInt()).putInt(bootCount.toInt()).putLong(elapsedNanos).putLong(wallMillis)
            .put(operationDigest).put(prevHash).array()
    }

    fun hash(record: ByteArray): ByteArray = MessageDigest.getInstance("SHA-256").digest(record)

    /** RFC 4122 big-endian, as the server writes it. */
    internal fun uuidBytes(id: UUID): ByteArray =
        ByteBuffer.allocate(16).putLong(id.mostSignificantBits).putLong(id.leastSignificantBits).array()
}

/** Next position of one permit's chain. */
class OfflineChainState(val nextSeq: Long, lastHash: ByteArray) {
    private val last = lastHash.copyOf()
    fun lastHash(): ByteArray = last.copyOf()
}

/**
 * Where the chain state lives between seals: private app storage, one entry per permit. [write] must be durable before
 * it returns (a seal handed out and not recorded would be sealed twice after a crash).
 */
interface OfflineChainStore {
    fun read(permitId: UUID): OfflineChainState?
    fun write(permitId: UUID, state: OfflineChainState)
    fun delete(permitId: UUID)
}

/** The clocks of a seal. [bootCount] is [OfflineChain.BOOT_COUNT_UNAVAILABLE] when the platform has none. */
interface OfflineClocks {
    fun elapsedRealtimeNanos(): Long
    fun wallClockMillis(): Long
    fun bootCount(): Long
}

/** Android clocks: `SystemClock.elapsedRealtimeNanos()`, `System.currentTimeMillis()`, `Settings.Global.BOOT_COUNT` (API 24+). */
class AndroidOfflineClocks(private val context: android.content.Context) : OfflineClocks {
    override fun elapsedRealtimeNanos(): Long = android.os.SystemClock.elapsedRealtimeNanos()
    override fun wallClockMillis(): Long = System.currentTimeMillis()
    override fun bootCount(): Long = try {
        val n = android.provider.Settings.Global.getInt(context.contentResolver, "boot_count", -1)
        if (n < 0) OfflineChain.BOOT_COUNT_UNAVAILABLE else n.toLong()
    } catch (_: RuntimeException) { OfflineChain.BOOT_COUNT_UNAVAILABLE }
}

/** Private SharedPreferences store; `commit()` so the write is durable when it returns. */
class AndroidOfflineChainStore(context: android.content.Context) : OfflineChainStore {
    private val prefs = context.getSharedPreferences("br.com.ebees.sentomaru.offline", android.content.Context.MODE_PRIVATE)
    override fun read(permitId: UUID): OfflineChainState? {
        val raw = prefs.getString(permitId.toString(), null) ?: return null
        val parts = raw.split(':')
        if (parts.size != 2) return null
        return try {
            OfflineChainState(parts[0].toLong(), Base64.getUrlDecoder().decode(parts[1]))
        } catch (_: RuntimeException) { null }
    }
    override fun write(permitId: UUID, state: OfflineChainState) {
        val v = "${state.nextSeq}:${Base64.getUrlEncoder().withoutPadding().encodeToString(state.lastHash())}"
        if (!prefs.edit().putString(permitId.toString(), v).commit()) throw IllegalStateException("offline state not committed")
    }
    override fun delete(permitId: UUID) { prefs.edit().remove(permitId.toString()).commit() }
}

/** Result of [SentomaruOfflineChain.requestPermit]. */
sealed class OfflinePermitOutcome {
    class Issued(val permit: OfflinePermit) : OfflinePermitOutcome()
    /** The server refused; [code] is its stable code (`offline-disabled`, `permit-open`, ...). */
    class Refused(val code: String, val status: Int) : OfflinePermitOutcome()
    /** Network, 429 or 5xx: try again later; [retryAfterSeconds] is the server's wait (bounded), `null` if none. */
    class Unavailable @JvmOverloads constructor(val retryAfterSeconds: Long? = null) : OfflinePermitOutcome()
}

/** Result of [SentomaruOfflineChain.reconcileOfflineChain]. [signals] only ever holds the three contract codes. */
sealed class OfflineReconcileOutcome {
    class Verdict(val permitId: UUID, val accepted: Boolean, val itemCount: Int, val signals: List<String>) : OfflineReconcileOutcome()
    class Refused(val code: String, val status: Int) : OfflineReconcileOutcome()
    /** Network, 429 or 5xx: the items stay; [retryAfterSeconds] is the server's wait (bounded), `null` if none. */
    class Unavailable @JvmOverloads constructor(val retryAfterSeconds: Long? = null) : OfflineReconcileOutcome()
}

/**
 * D-26c: the Android side of the OfflineProofChain (contract `offline-proof-chain-v1`).
 *
 * What it gives the server: the operations were sealed IN ORDER, none from the start or middle was removed, and the wall
 * clock did not move against the monotonic one beyond the tolerance (120 s by default, provisional: no device has
 * measured it). What it does NOT give: proof that the content is true (a hooked SDK signs anything); protection of the
 * tail (seals never sent are invisible); proof of the real time (root or kernel can move both clocks); and `bootCount`
 * may be missing or fixed on some devices. The payload never goes to Sentomaru, only its SHA-256.
 */
class SentomaruOfflineChain(
    private val client: SentomaruClient,
    private val store: OfflineChainStore,
    private val clocks: OfflineClocks,
) {
    /** Asks for a permit while online (operation `offline_permit`). Must not run on the main thread. */
    fun requestPermit(url: String, send: (br.com.ebees.sentomaru.core.SignedMessage) -> TransactionAnswer): OfflinePermitOutcome {
        client.config.checkHost(url)
        val answer = try { send(client.sign("POST", url, PERMIT_OPERATION, "{}".toByteArray(Charsets.UTF_8))) }
        catch (_: java.io.IOException) { return OfflinePermitOutcome.Unavailable() }
        if (answer.status == 429 || answer.status >= 500) return OfflinePermitOutcome.Unavailable(answer.retryWaitSeconds)
        if (answer.status !in 200..299) return OfflinePermitOutcome.Refused(code(answer), answer.status)
        val permit = OfflinePermit.parse(answer.body) ?: return OfflinePermitOutcome.Refused(UNEXPECTED, answer.status)
        store.delete(permit.permitId)
        store.write(permit.permitId, OfflineChainState(0, OfflineChain.seedHash(permit.permitId, permit.chainSeed())))
        return OfflinePermitOutcome.Issued(permit)
    }

    /**
     * Starts the chain of a permit received by another path (a hybrid layer that signs the permit request itself): writes
     * the initial state if there is none and leaves an existing one alone, so it is safe to call before every seal.
     * Limit: if the saved state was lost, this starts the chain again at 0 and the server will see a broken chain.
     */
    @Synchronized
    fun begin(permit: OfflinePermit) {
        try {
            if (store.read(permit.permitId) == null)
                store.write(permit.permitId, OfflineChainState(0, OfflineChain.seedHash(permit.permitId, permit.chainSeed())))
        } catch (_: RuntimeException) { fail(OfflineChainError.StateUnavailable()) }
    }

    /**
     * Seals one operation. [operationDigest] is the SHA-256 of the operation payload (32 bytes). Works offline.
     * Throws [br.com.ebees.sentomaru.core.SentomaruException] with an [OfflineChainError] (expired, full, bad digest,
     * state unavailable) and seals nothing in that case.
     */
    @Synchronized
    fun sealOfflineOperation(permit: OfflinePermit, operationDigest: ByteArray): OfflineSeal {
        if (operationDigest.size != OfflineChain.HASH_BYTES) fail(OfflineChainError.BadDigest())
        val state = try { store.read(permit.permitId) } catch (_: RuntimeException) { null }
            ?: fail(OfflineChainError.StateUnavailable())
        if (state.nextSeq >= permit.maxItems) fail(OfflineChainError.ChainFull())
        val wall = clocks.wallClockMillis()
        if (wall >= permit.validUntil.toEpochMilli()) fail(OfflineChainError.PermitExpired())
        val elapsed = clocks.elapsedRealtimeNanos()
        val boot = clocks.bootCount()
        val prev = state.lastHash()
        val record = OfflineChain.record(permit.permitId, state.nextSeq, boot, elapsed, wall, operationDigest, prev)
        val hash = OfflineChain.hash(record)
        val signature = client.signInstallationDer(record)
        val seal = OfflineSeal(state.nextSeq, boot, elapsed, wall, operationDigest, prev, hash, signature)
        try { store.write(permit.permitId, OfflineChainState(state.nextSeq + 1, hash)) }
        catch (_: RuntimeException) { fail(OfflineChainError.StateUnavailable()) }
        return seal
    }

    /** The JSON body of `reconciliations` (contract section 5). */
    fun reconcileBody(permit: OfflinePermit, seals: List<OfflineSeal>): ByteArray {
        require(seals.isNotEmpty() && seals.size <= OfflineChain.MAX_ITEMS) { "seals" }
        return "{\"permitId\":\"${permit.permitId}\",\"items\":[${seals.joinToString(",") { it.toJson() }}]}"
            .toByteArray(Charsets.UTF_8)
    }

    /**
     * Sends the batch (operation `offline_reconcile`). The caller renews the grant first (`POST /sessions`): the batch
     * never renews it. The chain state of the permit is dropped only after a verdict (accepted or rejected); a
     * rejection does not erase anything on the server and the consumer decides what to do with it.
     */
    fun reconcileOfflineChain(permit: OfflinePermit, seals: List<OfflineSeal>, url: String,
                              send: (br.com.ebees.sentomaru.core.SignedMessage) -> TransactionAnswer): OfflineReconcileOutcome {
        client.config.checkHost(url)
        val body = reconcileBody(permit, seals)
        val answer = try { send(client.sign("POST", url, RECONCILE_OPERATION, body)) }
        catch (_: java.io.IOException) { return OfflineReconcileOutcome.Unavailable() }
        if (answer.status == 429 || answer.status >= 500) return OfflineReconcileOutcome.Unavailable(answer.retryWaitSeconds)
        if (answer.status !in 200..299) return OfflineReconcileOutcome.Refused(code(answer), answer.status)
        val verdict = parseVerdict(answer.body) ?: return OfflineReconcileOutcome.Refused(UNEXPECTED, answer.status)
        store.delete(permit.permitId)
        return verdict
    }

    private fun parseVerdict(text: String): OfflineReconcileOutcome.Verdict? {
        if (text.length > MAX_ANSWER_CHARS) return null
        return try {
            val id = UUID.fromString(ReattestationJson.string(text, "permitId") ?: return null)
            val status = ReattestationJson.string(text, "status") ?: return null
            val count = Regex("\"itemCount\"\\s*:\\s*(\\d{1,4})\\b").find(text)?.groupValues?.get(1)?.toInt() ?: return null
            val list = Regex("\"signals\"\\s*:\\s*\\[([^\\]]*)]").find(text)?.groupValues?.get(1) ?: return null
            val signals = Regex("\"([a-z_]+)\"").findAll(list).map { it.groupValues[1] }.toList()
            if (signals.any { it !in SIGNALS }) return null
            if (status != "accepted" && status != "rejected") return null
            if ((status == "accepted") != signals.isEmpty()) return null
            OfflineReconcileOutcome.Verdict(id, status == "accepted", count, signals)
        } catch (_: RuntimeException) { null }
    }

    private fun code(answer: TransactionAnswer): String =
        br.com.ebees.sentomaru.sdk.transport.SentomaruWire.errorCode(answer.body.take(MAX_ANSWER_CHARS)) ?: UNEXPECTED

    private companion object {
        const val PERMIT_OPERATION = "offline_permit"
        const val RECONCILE_OPERATION = "offline_reconcile"
        const val UNEXPECTED = "unexpected-response"
        const val MAX_ANSWER_CHARS = 16 * 1024
        val SIGNALS = setOf("offline_clock_tampered", "offline_chain_broken", "offline_chain_gap_detected")
    }
}
