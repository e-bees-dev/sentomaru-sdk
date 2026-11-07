package br.com.ebees.sentomaru.capacitor

import br.com.ebees.sentomaru.hybrid.BridgeCall
import br.com.ebees.sentomaru.hybrid.BridgeResult
import br.com.ebees.sentomaru.hybrid.SentomaruBridge
import com.getcapacitor.JSObject
import com.getcapacitor.Plugin
import com.getcapacitor.PluginCall
import com.getcapacitor.annotation.CapacitorPlugin
import com.getcapacitor.PluginMethod

/**
 * Capacitor plugin `Sentomaru`. One entry point, [call], with the method names and arguments of
 * contracts/sdk/hybrid-bridge-v1.json: `{method, args}` in, `{value}` out (Capacitor resolves objects only). No logic of its
 * own: the answer is the shared [SentomaruBridge]'s, an error is a rejection carrying the contract's error code.
 */
@CapacitorPlugin(name = "Sentomaru")
class SentomaruPlugin : Plugin() {
    private var core: SentomaruBridge? = null

    override fun load() {
        core = SentomaruBridge { null }.also { it.context = context.applicationContext }
    }

    @PluginMethod
    fun call(call: PluginCall) {
        val method = call.getString("method")
        val bridge = core
        if (method == null || bridge == null) {
            call.reject("method missing or plugin not loaded", "ChannelError")
            return
        }
        val arguments = BridgeValues.arguments(call.getObject("args"))
        bridge.onMethodCall(
            object : BridgeCall {
                override val method: String = method
                @Suppress("UNCHECKED_CAST")
                override fun <T> argument(key: String): T? = arguments[key] as T?
            },
            object : BridgeResult {
                override fun success(value: Any?) = call.resolve(JSObject().also { it.put("value", BridgeValues.reply(value)) })
                override fun error(code: String, message: String?, details: Any?) = call.reject(message ?: code, code)
                override fun notImplemented() = call.reject(method, "NotImplemented")
            },
        )
    }

    override fun handleOnDestroy() {
        core?.shutdown()
        super.handleOnDestroy()
    }
}
