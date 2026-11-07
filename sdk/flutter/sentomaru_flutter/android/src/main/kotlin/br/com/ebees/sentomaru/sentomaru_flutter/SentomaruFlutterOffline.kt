package br.com.ebees.sentomaru.sentomaru_flutter

import android.content.Context
import br.com.ebees.sentomaru.core.SentomaruException
import br.com.ebees.sentomaru.sdk.AndroidOfflineChainStore
import br.com.ebees.sentomaru.sdk.AndroidOfflineClocks
import br.com.ebees.sentomaru.sdk.OfflineChainError
import br.com.ebees.sentomaru.sdk.OfflinePermit
import br.com.ebees.sentomaru.sdk.OfflineSeal
import br.com.ebees.sentomaru.sdk.SentomaruClient
import br.com.ebees.sentomaru.sdk.SentomaruOfflineChain
import io.flutter.plugin.common.MethodCall
import io.flutter.plugin.common.MethodChannel.Result
import java.util.Base64
import java.util.concurrent.ExecutorService
import java.util.concurrent.Executors
import java.util.concurrent.RejectedExecutionException

/**
 * D-26 (Android): the Flutter-only methods `offlineSeal` and `offlineReconcileBody` of `SentomaruOfflineChain` in Dart, over
 * the SDK's [SentomaruOfflineChain]; the same channel contract the iOS plugin answers. The permit request and the
 * reconciliation are signed with the normal `sign` (operations `offline_permit` and `offline_reconcile`): only the seal and
 * the body are here. Errors reach Dart as the closed codes `Offline:<CASE>` of `SentomaruOfflineError`.
 *
 * What it gives and does not give is the SDK's (contract `offline-proof-chain-v1`): order and absence of removal, not
 * truth; the tail is not protected. Works with no network and no grant. Runs on its own worker thread (Keystore).
 */
class SentomaruFlutterOffline internal constructor(
    private val port: () -> Port?,
    private val post: (Runnable) -> Unit,
    private val executor: ExecutorService = Executors.newSingleThreadExecutor(),
) {
    /** The two operations, by channel types; a seam for the plugin's JVM tests. */
    internal interface Port {
        fun seal(permitJson: String, operationDigest: ByteArray): Map<String, Any>
        fun reconcileBody(permitJson: String, seals: List<Map<*, *>>): ByteArray
    }

    internal constructor(context: Context, client: () -> SentomaruClient?, post: (Runnable) -> Unit) :
        this({ client()?.let { sdkPort(context, it) } }, post)

    fun handles(method: String): Boolean = method in METHODS

    fun onMethodCall(call: MethodCall, result: Result) {
        val args = call.arguments as? Map<*, *>
        val permit = when (val raw = args?.get("permit")) {
            is String -> raw
            is ByteArray -> String(raw, Charsets.UTF_8)
            else -> null
        }
        val task = Runnable {
            val outcome: Outcome = try {
                val p = port() ?: return@Runnable reply { result.error(NOT_INITIALIZED, "Sentomaru native client not initialized", null) }
                when (call.method) {
                    SEAL -> {
                        val digest = args?.get("operationDigest") as? ByteArray
                        if (permit == null || digest == null) Outcome.Error(INVALID_PARAMS)
                        else Outcome.Value(p.seal(permit, digest))
                    }
                    else -> {
                        val seals = (args?.get("seals") as? List<*>)?.map { it as? Map<*, *> }
                        if (permit == null || seals == null || seals.any { it == null }) Outcome.Error(INVALID_PARAMS)
                        else Outcome.Value(p.reconcileBody(permit, seals.filterNotNull()))
                    }
                }
            } catch (e: SentomaruException) {
                Outcome.Error(code(e.error.code))
            } catch (e: IllegalArgumentException) {
                Outcome.Error(INVALID_PARAMS)
            } catch (e: Exception) {
                Outcome.Error(CHANNEL_ERROR)
            }
            reply {
                when (outcome) {
                    is Outcome.Value -> result.success(outcome.value)
                    is Outcome.Error -> result.error(outcome.code, outcome.code, null)
                }
            }
        }
        try { executor.execute(task) } catch (_: RejectedExecutionException) {
            reply { result.error(CHANNEL_ERROR, "Sentomaru plugin detached", null) }
        }
    }

    fun shutdown() { executor.shutdownNow() }

    private sealed class Outcome {
        class Value(val value: Any) : Outcome()
        class Error(val code: String) : Outcome()
    }

    private fun reply(block: () -> Unit) = post(Runnable { block() })

    internal companion object {
        const val SEAL = "offlineSeal"
        const val RECONCILE_BODY = "offlineReconcileBody"
        val METHODS = setOf(SEAL, RECONCILE_BODY)
        const val NOT_INITIALIZED = "NotInitialized"
        const val CHANNEL_ERROR = "ChannelError"
        const val INVALID_PARAMS = "InvalidRequest:PARAMS"
        private val b64 = Base64.getUrlEncoder().withoutPadding()
        private val dec = Base64.getUrlDecoder()

        /** The SDK error code as the code Dart's `SentomaruOfflineError` maps; other codes (NotEnrolled, ...) pass as they are. */
        fun code(sdkCode: String): String = when (sdkCode) {
            "OfflinePermitInvalid" -> "Offline:PERMIT_INVALID"
            "OfflinePermitExpired" -> "Offline:PERMIT_EXPIRED"
            "OfflineChainFull" -> "Offline:CHAIN_FULL"
            "OfflineBadDigest" -> "Offline:INVALID_DIGEST"
            "OfflineStateUnavailable" -> "StorageUnavailable"
            else -> sdkCode
        }

        /** The item of the reconciliation body: numbers as numbers, binary fields base64url without padding. */
        fun sealReply(seal: OfflineSeal): Map<String, Any> = mapOf(
            "seq" to seal.seq, "bootCount" to seal.bootCount, "elapsedRealtimeNanos" to seal.elapsedRealtimeNanos,
            "wallClockMillis" to seal.wallClockMillis, "operationDigest" to b64.encodeToString(seal.operationDigest()),
            "prevHash" to b64.encodeToString(seal.prevHash()), "hash" to b64.encodeToString(seal.hash()),
            "signature" to b64.encodeToString(seal.signature()),
        )

        /** A seal from the map Dart sends back; [IllegalArgumentException] for anything that is not a seal. */
        fun seal(map: Map<*, *>): OfflineSeal {
            fun number(key: String): Long {
                val v = map[key]
                require(v is Int || v is Long) { key }
                return (v as Number).toLong()
            }
            fun bytes(key: String, size: Int?): ByteArray {
                val v = map[key] as? String ?: throw IllegalArgumentException(key)
                val out = dec.decode(v)
                require(if (size != null) out.size == size else out.size in 8..80) { key }
                return out
            }
            val seq = number("seq"); val boot = number("bootCount"); val elapsed = number("elapsedRealtimeNanos"); val wall = number("wallClockMillis")
            require(seq in 0 until 128 && boot in 0..0xFFFFFFFFL && elapsed >= 0 && wall >= 0) { "range" }
            return OfflineSeal(seq, boot, elapsed, wall, bytes("operationDigest", 32), bytes("prevHash", 32), bytes("hash", 32), bytes("signature", null))
        }

        fun sdkPort(context: Context, client: SentomaruClient): Port {
            val chain = SentomaruOfflineChain(client, AndroidOfflineChainStore(context), AndroidOfflineClocks(context))
            return object : Port {
                override fun seal(permitJson: String, operationDigest: ByteArray): Map<String, Any> {
                    val permit = OfflinePermit.parse(permitJson) ?: throw SentomaruException(OfflineChainError.PermitInvalid())
                    chain.begin(permit)
                    return sealReply(chain.sealOfflineOperation(permit, operationDigest))
                }
                override fun reconcileBody(permitJson: String, seals: List<Map<*, *>>): ByteArray {
                    val permit = OfflinePermit.parse(permitJson) ?: throw SentomaruException(OfflineChainError.PermitInvalid())
                    return chain.reconcileBody(permit, seals.map(::seal))
                }
            }
        }
    }
}
