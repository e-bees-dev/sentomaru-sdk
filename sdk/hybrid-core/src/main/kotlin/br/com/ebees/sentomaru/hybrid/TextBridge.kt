package br.com.ebees.sentomaru.hybrid

import android.content.Context
import android.os.Looper
import org.json.JSONArray
import org.json.JSONObject
import java.util.concurrent.CountDownLatch
import java.util.concurrent.TimeUnit

/**
 * D-22c: the only conversions a text-only channel makes over [SentomaruBridge] (contracts/sdk/hybrid-bridge-v1.json), the
 * same rule every other layer's own `BridgeValues` applies: a call is JSON, so a byte value crosses as canonical Base64
 * ([CanonicalBase64]) — the `body` argument of `sign` comes in that way, a `bytes` reply (`sealedLoad`) goes out that way.
 * JSON turns into the Maps/Lists [SentomaruBridge] expects and back; integral numbers stay `Int`/`Long`, a fractional one
 * stays `Double` (the core refuses it where it wants an integer). `internal`: a seam for [TextBridgeJsonTest]-style tests in
 * whichever layer hosts them, not part of the public surface a binding calls.
 */
internal object TextBridgeJson {
    private val BYTE_ARGUMENTS = setOf("body")

    /** The arguments of one call, from a JSON object text (`{}` for none). Throws on anything that is not a JSON object:
     * the caller turns that into `InvalidRequest:PARAMS` before any native work starts. */
    fun arguments(argsJson: String): Map<String, Any?> {
        val raw = JSONObject(argsJson)
        val out = LinkedHashMap<String, Any?>()
        for (key in raw.keys()) {
            val value = fromJson(raw.get(key))
            out[key] = if (key in BYTE_ARGUMENTS && value is String) CanonicalBase64.decode(value) else value
        }
        return out
    }

    private fun fromJson(value: Any?): Any? = when (value) {
        JSONObject.NULL, null -> null
        is JSONObject -> value.keys().asSequence().associateWith { fromJson(value.get(it)) }
        is JSONArray -> (0 until value.length()).map { fromJson(value.get(it)) }
        else -> value // String, Boolean, Int, Long, Double
    }

    /** `{"value": ...}`: bytes become Base64, collections convert element by element, exactly as [errorReply]'s shape
     * never overlaps it (a caller tells a success from a refusal by which key is present). */
    fun successReply(value: Any?): String = JSONObject().put("value", toJson(value)).toString()

    /** `{"code": ..., "message": ...}`, the contract's wire shape for a refusal. */
    fun errorReply(code: String, message: String?): String = JSONObject().put("code", code).put("message", message ?: code).toString()

    private fun toJson(value: Any?): Any? = when (value) {
        null -> JSONObject.NULL
        is ByteArray -> java.util.Base64.getEncoder().encodeToString(value)
        is Map<*, *> -> JSONObject().also { o -> value.forEach { (k, v) -> o.put(k.toString(), toJson(v)) } }
        is Iterable<*> -> JSONArray().also { a -> value.forEach { a.put(toJson(it)) } }
        else -> value
    }
}

/**
 * D-22c: a blocking, text-only entry point over the shared [SentomaruBridge], for a binding that can only pass a method
 * name and a JSON object across JNI — Unity's `AndroidJavaObject.Call<string>`, chiefly, and any other caller in the same
 * position (RN, Capacitor and Cordova instead call [SentomaruBridge] directly with real Kotlin objects: this class exists
 * only for the ones that cannot).
 *
 * [call] BLOCKS the calling thread until the native side answers, because [SentomaruBridge] replies by posting to the main
 * looper: calling this FROM the main thread would make it wait for a message its own block prevents that looper from ever
 * processing — a guaranteed deadlock, caught here before any native work starts rather than left to hang the app. Unity's
 * own JNI bridge already runs a blocking native call off its main thread; any other caller must do the same.
 *
 * Nothing here is cryptography: every reply is [SentomaruBridge]'s, converted to text by [TextBridgeJson]. The instance
 * owns one [SentomaruBridge]; [shutdown] stops it the same way a plugin's `onDestroy` does for the others.
 */
class SentomaruTextBridge @JvmOverloads constructor(
    context: Context,
    feed: SignalEventFeed = SignalEventFeed { null },
    sealed: SealedReader? = null,
) {
    private val core = SentomaruBridge(feed, sealed).also { it.context = context.applicationContext }

    /**
     * [method] and [argsJson] exactly as contracts/sdk/hybrid-bridge-v1.json names them (`"{}"` for a method with no
     * arguments). [timeoutMs] bounds the block (default [DEFAULT_TIMEOUT_MS], longer than the SDK's own longest wait, the
     * 30 s reattestation retry); past it the reply is `{"code":"ChannelError","message":"timeout"}` and a native answer
     * that still arrives later is simply dropped (the latch already released; the caller is never answered twice).
     *
     * @throws IllegalStateException called from the main thread (see the class doc): never caught by [call] itself, so a
     *   binding that gets this wrong fails loudly in its own tests rather than deadlocking in the field.
     */
    @JvmOverloads
    fun call(method: String, argsJson: String, timeoutMs: Long = DEFAULT_TIMEOUT_MS): String {
        check(!onMainThread()) { "SentomaruTextBridge.call must not run on the main thread: SentomaruBridge replies by " +
            "posting to it, so blocking it here would wait forever for a message it can no longer process." }
        val arguments = try {
            TextBridgeJson.arguments(argsJson)
        } catch (e: Exception) {
            return TextBridgeJson.errorReply("InvalidRequest:PARAMS", "argsJson is not a JSON object of the contract's arguments: ${e.message}")
        }
        val latch = CountDownLatch(1)
        // Not @Volatile (illegal on a local): CountDownLatch.countDown()/await() already establish the happens-before
        // edge the Java Memory Model requires for a write before countDown() to be visible to the thread await() releases.
        var reply = TextBridgeJson.errorReply("ChannelError", "timeout")
        core.onMethodCall(
            object : BridgeCall {
                override val method: String = method
                @Suppress("UNCHECKED_CAST")
                override fun <T> argument(key: String): T? = arguments[key] as T?
            },
            object : BridgeResult {
                override fun success(value: Any?) { reply = TextBridgeJson.successReply(value); latch.countDown() }
                override fun error(code: String, message: String?, details: Any?) { reply = TextBridgeJson.errorReply(code, message); latch.countDown() }
                override fun notImplemented() { reply = TextBridgeJson.errorReply("NotImplemented", method); latch.countDown() }
            },
        )
        latch.await(timeoutMs, TimeUnit.MILLISECONDS)
        return reply
    }

    fun shutdown() = core.shutdown()

    private fun onMainThread(): Boolean {
        val looper = Looper.myLooper()
        return looper != null && looper == Looper.getMainLooper()
    }

    companion object {
        const val DEFAULT_TIMEOUT_MS = 35_000L
    }
}
