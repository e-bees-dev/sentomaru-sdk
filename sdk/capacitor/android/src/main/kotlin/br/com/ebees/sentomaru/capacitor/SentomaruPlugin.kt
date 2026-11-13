package br.com.ebees.sentomaru.capacitor

import android.content.Context
import br.com.ebees.sentomaru.hybrid.BridgeCall
import br.com.ebees.sentomaru.hybrid.BridgeResult
import br.com.ebees.sentomaru.hybrid.SealedReadError
import br.com.ebees.sentomaru.hybrid.SealedReader
import br.com.ebees.sentomaru.hybrid.SentomaruBridge
import br.com.ebees.sentomaru.sdk.sealed.SentomaruSealed
import br.com.ebees.sentomaru.sdk.sealed.SentomaruSealedException
import com.getcapacitor.JSObject
import com.getcapacitor.Plugin
import com.getcapacitor.PluginCall
import com.getcapacitor.annotation.CapacitorPlugin
import com.getcapacitor.PluginMethod
import java.io.FileNotFoundException

/**
 * Capacitor plugin `Sentomaru`. One entry point, [call], with the method names and arguments of
 * contracts/sdk/hybrid-bridge-v1.json: `{method, args}` in, `{value}` out (Capacitor resolves objects only). No logic of its
 * own: the answer is the shared [SentomaruBridge]'s, an error is a rejection carrying the contract's error code.
 */
@CapacitorPlugin(name = "Sentomaru")
class SentomaruPlugin : Plugin() {
    private var core: SentomaruBridge? = null

    override fun load() {
        val ctx = context.applicationContext
        core = SentomaruBridge({ null }, sealedReader(ctx)).also { it.context = ctx }
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

/**
 * D-14b: the production [SealedReader] for the Capacitor layer. Capacitor has no bundler step over the native
 * `assets/` folder, so the `key` a page passes is already the canonical path `SentomaruSealed` expects: no
 * translation, unlike the Flutter plugin's pubspec prefix. The SDK's own exception becomes [SealedReadError] (the
 * stable bridge code), so `SentomaruBridge` itself never needs to import `sdk/android/sealed`.
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
