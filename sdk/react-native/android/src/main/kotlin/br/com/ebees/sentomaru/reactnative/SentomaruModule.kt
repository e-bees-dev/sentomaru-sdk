package br.com.ebees.sentomaru.reactnative

import br.com.ebees.sentomaru.hybrid.BridgeCall
import br.com.ebees.sentomaru.hybrid.BridgeResult
import br.com.ebees.sentomaru.hybrid.SentomaruBridge
import com.facebook.react.bridge.Arguments
import com.facebook.react.bridge.Promise
import com.facebook.react.bridge.ReactApplicationContext
import com.facebook.react.bridge.ReactMethod
import com.facebook.react.bridge.ReadableMap
import com.facebook.react.bridge.WritableArray
import com.facebook.react.module.annotations.ReactModule

/**
 * React Native module `Sentomaru`. One entry point, [call], with the method names and arguments of
 * contracts/sdk/hybrid-bridge-v1.json; the TypeScript layer gives each its typed function. No logic of its own: the
 * answer is the shared [SentomaruBridge]'s, an error is a rejected promise with the contract's error code.
 *
 * a TurboModule when the app uses the new architecture (it extends the class the codegen makes from
 * `src/NativeSentomaru.ts`), the classic module otherwise (the hand-written `NativeSentomaruSpec` of `src/oldarch`).
 */
@ReactModule(name = SentomaruModule.NAME)
class SentomaruModule(context: ReactApplicationContext) : NativeSentomaruSpec(context) {
    private val core = SentomaruBridge { null }.also { it.context = context.applicationContext }

    override fun getName(): String = NAME

    @ReactMethod
    override fun call(method: String, args: ReadableMap?, promise: Promise) {
        val arguments = BridgeValues.arguments(args?.toHashMap() ?: emptyMap())
        core.onMethodCall(
            object : BridgeCall {
                override val method: String = method
                @Suppress("UNCHECKED_CAST")
                override fun <T> argument(key: String): T? = arguments[key] as T?
            },
            object : BridgeResult {
                override fun success(value: Any?) = promise.resolve(toJs(BridgeValues.reply(value)))
                override fun error(code: String, message: String?, details: Any?) = promise.reject(code, message ?: code, null)
                override fun notImplemented() = promise.reject("NotImplemented", method, null)
            },
        )
    }

    override fun invalidate() {
        core.shutdown()
        super.invalidate()
    }

    private fun toJs(value: Any?): Any? = when (value) {
        is Map<*, *> -> Arguments.makeNativeMap(value.entries.associate { (k, v) -> k.toString() to v })
        is List<*> -> Arguments.makeNativeArray(value) as WritableArray
        else -> value
    }

    companion object {
        const val NAME = "Sentomaru"
    }
}
