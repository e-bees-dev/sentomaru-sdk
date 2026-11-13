package br.com.ebees.sentomaru.cordova

import br.com.ebees.sentomaru.hybrid.BridgeCall
import br.com.ebees.sentomaru.hybrid.BridgeResult
import br.com.ebees.sentomaru.hybrid.SealedReadError
import br.com.ebees.sentomaru.hybrid.SealedReader
import br.com.ebees.sentomaru.hybrid.SentomaruBridge
import br.com.ebees.sentomaru.sdk.sealed.SentomaruSealed
import br.com.ebees.sentomaru.sdk.sealed.SentomaruSealedException
import org.apache.cordova.CallbackContext
import org.apache.cordova.CordovaInterface
import org.apache.cordova.CordovaPlugin
import org.apache.cordova.CordovaWebView
import org.json.JSONArray
import org.json.JSONObject
import android.content.Context
import java.io.FileNotFoundException

/**
 * Cordova plugin `Sentomaru`. One action, `call`, with `[method, args]` and the method names and arguments of
 * contracts/sdk/hybrid-bridge-v1.json; the answer is `{value}`. No logic of its own: the answer is the shared [SentomaruBridge]'s,
 * an error is `{code, message}` with the contract's error code (JavaScript turns it into SentomaruError).
 */
class SentomaruPlugin : CordovaPlugin() {
    private var core: SentomaruBridge? = null

    override fun initialize(cordova: CordovaInterface, webView: CordovaWebView) {
        super.initialize(cordova, webView)
        val ctx = cordova.activity.applicationContext
        core = SentomaruBridge({ null }, sealedReader(ctx)).also { it.context = ctx }
    }

    override fun execute(action: String, args: JSONArray, callbackContext: CallbackContext): Boolean {
        if (action != "call") return false
        val method = args.optString(0, "")
        val bridge = core
        if (method.isEmpty() || bridge == null) {
            callbackContext.error(failure("ChannelError", "method missing or plugin not loaded"))
            return true
        }
        val arguments = BridgeValues.arguments(args.optJSONObject(1))
        bridge.onMethodCall(
            object : BridgeCall {
                override val method: String = method
                @Suppress("UNCHECKED_CAST")
                override fun <T> argument(key: String): T? = arguments[key] as T?
            },
            object : BridgeResult {
                override fun success(value: Any?) = callbackContext.success(JSONObject().put("value", BridgeValues.reply(value)))
                override fun error(code: String, message: String?, details: Any?) = callbackContext.error(failure(code, message ?: code))
                override fun notImplemented() = callbackContext.error(failure("NotImplemented", method))
            },
        )
        return true
    }

    override fun onDestroy() {
        core?.shutdown()
        super.onDestroy()
    }

    private fun failure(code: String, message: String) = JSONObject().put("code", code).put("message", message)
}

/**
 * D-14b: the production [SealedReader] for the Cordova layer. Cordova has no bundler step over the native `assets/`
 * folder (`www/` is a separate asset directory), so the `key` a page passes is already the canonical path
 * `SentomaruSealed` expects: no translation, unlike the Flutter plugin's pubspec prefix. The SDK's own exception
 * becomes [SealedReadError] (the stable bridge code), so `SentomaruBridge` itself never needs to import
 * `sdk/android/sealed`.
 */
internal fun sealedReader(context: Context): SealedReader = object : SealedReader {
    override fun configure(allowPlainFallback: Boolean, plainStringsKey: String?) =
        SentomaruSealed.configure(allowPlainFallback, plainStringsKey)
    override fun bytes(key: String): ByteArray = wrapSealedRead { SentomaruSealed.bytes(context, key) }
    override fun string(key: String): String? = wrapSealedRead { SentomaruSealed.string(context, key) }
}

internal fun <T> wrapSealedRead(read: () -> T): T = try {
    read()
} catch (e: SentomaruSealedException) {
    throw SealedReadError(e.code.wire, e.code.wire)
} catch (e: FileNotFoundException) {
    // Only with the plain fallback (an unsealed debug build): the asset is not in the package.
    throw SealedReadError("AssetNotFound", "Asset not found")
}
