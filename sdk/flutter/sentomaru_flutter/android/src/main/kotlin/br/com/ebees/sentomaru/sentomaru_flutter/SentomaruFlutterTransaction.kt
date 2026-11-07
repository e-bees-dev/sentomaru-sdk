package br.com.ebees.sentomaru.sentomaru_flutter

import br.com.ebees.sentomaru.core.SentomaruException
import io.flutter.plugin.common.MethodCall
import io.flutter.plugin.common.MethodChannel.Result
import java.util.concurrent.ExecutorService
import java.util.concurrent.Executors
import java.util.concurrent.RejectedExecutionException

/**
 * D-25 (Android): the Flutter methods `txKeyCreate`, `txKeyCommit`, `txKeyAbort`, `txSign`, `txIsEnrolled` and `txDiscard` of `SentomaruTransactionSigner`
 * in Dart, over the SDK's transaction signer; the same channel and the same closed error codes `Transaction:<CASE>` the iOS
 * plugin answers. Differences from iOS:
 *  - `txKeyCreate` needs the enrollment `challenge` (the key is attested by the platform) and returns the enrollment request
 *    body for `POST transaction-keys`, not a bare public key. The new key does not replace a key the server holds until the
 *    app calls `txKeyCommit` after the server's 201; `txKeyAbort` drops it and keeps the old one.
 *  - `txSign` shows `BiometricPrompt` with the key in a `CryptoObject` (the key works only after the person authenticates).
 *  - Without a foreground `FragmentActivity`, without enrolled biometrics or with an unavailable sensor the result is a typed
 *    error, never a signature. There is no path that signs without the prompt.
 * A signature proves a person who can unlock the device was present; it does not prove the person saw the value.
 */
class SentomaruFlutterTransaction internal constructor(
    private val port: () -> Port?,
    private val post: (Runnable) -> Unit,
    private val executor: ExecutorService = Executors.newSingleThreadExecutor(),
) {
    /** One signature outcome: exactly one of [onSigned] or [onError] is called, from any thread. */
    internal interface Port {
        fun isEnrolled(): Boolean
        fun discard()
        /** The server accepted the key made by [createKey]: it replaces the previous one. */
        fun commitKey()
        /** The server refused it (or the app gave up): the new key goes and the previous one stays. */
        fun abortKey()
        /** The enrollment request body (JSON bytes). Throws [SentomaruException] with an enrollment error. */
        fun createKey(challenge: Challenge, biometricOnly: Boolean, strongBox: Boolean): ByteArray
        fun sign(operationId: String, body: ByteArray, reason: String, cancelLabel: String, biometricOnly: Boolean,
                 onSigned: (String) -> Unit, onError: (String) -> Unit)
    }

    /** The server challenge as Dart sends it back (`challengeId`, `token`, `attestationChallenge`, `expiresAt`). */
    internal class Challenge(val id: String, val token: String, val attestationChallenge: ByteArray, val expiresAt: String)

    fun handles(method: String): Boolean = method in METHODS

    fun onMethodCall(call: MethodCall, result: Result) {
        val args = call.arguments as? Map<*, *>
        val task = Runnable {
            val p = port() ?: return@Runnable reply { result.error(NOT_INITIALIZED, "Sentomaru native client not initialized", null) }
            try {
                when (call.method) {
                    IS_ENROLLED -> ok(result, p.isEnrolled())
                    DISCARD -> { p.discard(); ok(result, null) }
                    KEY_COMMIT -> { p.commitKey(); ok(result, null) }
                    KEY_ABORT -> { p.abortKey(); ok(result, null) }
                    KEY_CREATE -> {
                        val challenge = challenge(args?.get("challenge"))
                        val flag = flag(args, "biometricOnly")
                        val strongBox = flag(args, "strongBox", default = false)
                        if (challenge == null || flag == null || strongBox == null) fail(result, INVALID_PARAMS)
                        else ok(result, p.createKey(challenge, flag, strongBox))
                    }
                    else -> {
                        val operationId = args?.get("operationId") as? String
                        val body = args?.get("body") as? ByteArray
                        val biometricOnly = flag(args, "biometricOnly")
                        val reason = (args?.get("reason") as? String) ?: DEFAULT_REASON
                        val cancel = (args?.get("cancelLabel") as? String) ?: DEFAULT_CANCEL
                        if (operationId == null || body == null || biometricOnly == null) fail(result, INVALID_PARAMS)
                        else p.sign(operationId, body, reason, cancel, biometricOnly, { ok(result, it) }, { fail(result, it) })
                    }
                }
            } catch (e: SentomaruException) {
                fail(result, code(e.error.code))
            } catch (e: IllegalArgumentException) {
                fail(result, INVALID_PARAMS)
            } catch (e: Exception) {
                fail(result, CHANNEL_ERROR)
            }
        }
        try { executor.execute(task) } catch (_: RejectedExecutionException) {
            reply { result.error(CHANNEL_ERROR, "Sentomaru plugin detached", null) }
        }
    }

    fun shutdown() { executor.shutdownNow() }

    private fun ok(result: Result, value: Any?) = reply { result.success(value) }
    private fun fail(result: Result, code: String) = reply { result.error(code, code, null) }
    private fun reply(block: () -> Unit) = post(Runnable { block() })

    internal companion object {
        const val KEY_CREATE = "txKeyCreate"
        const val SIGN = "txSign"
        const val IS_ENROLLED = "txIsEnrolled"
        const val DISCARD = "txDiscard"
        const val KEY_COMMIT = "txKeyCommit"
        const val KEY_ABORT = "txKeyAbort"
        val METHODS = setOf(KEY_CREATE, SIGN, IS_ENROLLED, DISCARD, KEY_COMMIT, KEY_ABORT)
        const val NOT_INITIALIZED = "NotInitialized"
        const val CHANNEL_ERROR = "ChannelError"
        const val INVALID_PARAMS = "InvalidRequest:PARAMS"
        const val DEFAULT_REASON = "Confirmar a operação"
        const val DEFAULT_CANCEL = "Cancelar"

        /** A missing flag is [default]; a present non-boolean is invalid (null). */
        private fun flag(args: Map<*, *>?, key: String, default: Boolean = true): Boolean? {
            if (args == null || !args.containsKey(key) || args[key] == null) return default
            return args[key] as? Boolean
        }

        private fun challenge(raw: Any?): Challenge? {
            val m = raw as? Map<*, *> ?: return null
            return Challenge(
                m["challengeId"] as? String ?: return null, m["token"] as? String ?: return null,
                m["attestationChallenge"] as? ByteArray ?: return null, m["expiresAt"] as? String ?: return null,
            )
        }

        /** The SDK transaction error code as the closed code Dart's `SentomaruTransactionError` maps. */
        fun transactionCode(sdkCode: String): String = when (sdkCode) {
            "TxNotEnrolled" -> "Transaction:NOT_ENROLLED"
            "TxKeyInvalidated" -> "Transaction:KEY_INVALIDATED"
            "TxCancelled" -> "Transaction:CANCELLED"
            "TxLockedOut" -> "Transaction:LOCKED_OUT"
            "TxNoUserAuthentication" -> "Transaction:NO_USER_AUTHENTICATION"
            "TxUnavailable" -> "Transaction:UNAVAILABLE"
            "TxSigningFailed" -> "Transaction:SIGNING_FAILED"
            else -> code(sdkCode)
        }

        /** Enrollment errors of the key itself: no installation grant is "no transaction key"; a key the platform will not make is unavailable. */
        fun code(sdkCode: String): String = when (sdkCode) {
            "EnrollmentRequired", "NotEnrolled" -> "Transaction:NOT_ENROLLED"
            "KeyInvalidated" -> "Transaction:KEY_INVALIDATED"
            "StrongBoxUnavailable", "KeyUnavailable" -> "Transaction:UNAVAILABLE"
            else -> sdkCode
        }
    }
}
