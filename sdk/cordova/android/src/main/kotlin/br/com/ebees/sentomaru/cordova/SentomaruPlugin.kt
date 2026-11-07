package br.com.ebees.sentomaru.cordova

import br.com.ebees.sentomaru.hybrid.BridgeCall
import br.com.ebees.sentomaru.hybrid.BridgeResult
import br.com.ebees.sentomaru.hybrid.SentomaruBridge
import org.apache.cordova.CallbackContext
import org.apache.cordova.CordovaInterface
import org.apache.cordova.CordovaPlugin
import org.apache.cordova.CordovaWebView
import org.json.JSONArray
import org.json.JSONObject

/**
 * Cordova plugin `Sentomaru`. One action, `call`, with `[method, args]` and the method names and arguments of
 * contracts/sdk/hybrid-bridge-v1.json; the answer is `{value}`. No logic of its own: the answer is the shared [SentomaruBridge]'s,
 * an error is `{code, message}` with the contract's error code (JavaScript turns it into SentomaruError).
 */
class SentomaruPlugin : CordovaPlugin() {
    private var core: SentomaruBridge? = null

    override fun initialize(cordova: CordovaInterface, webView: CordovaWebView) {
        super.initialize(cordova, webView)
        core = SentomaruBridge { null }.also { it.context = cordova.activity.applicationContext }
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
