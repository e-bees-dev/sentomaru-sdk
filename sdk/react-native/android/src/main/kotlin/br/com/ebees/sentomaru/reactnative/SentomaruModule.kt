package br.com.ebees.sentomaru.reactnative

import br.com.ebees.sentomaru.hybrid.BridgeCall
import br.com.ebees.sentomaru.hybrid.BridgeResult
import br.com.ebees.sentomaru.hybrid.SealedReadError
import br.com.ebees.sentomaru.hybrid.SealedReader
import br.com.ebees.sentomaru.hybrid.SentomaruBridge
import br.com.ebees.sentomaru.sdk.sealed.SentomaruSealed
import br.com.ebees.sentomaru.sdk.sealed.SentomaruSealedException
import com.facebook.react.bridge.Arguments
import com.facebook.react.bridge.Promise
import com.facebook.react.bridge.ReactApplicationContext
import com.facebook.react.bridge.ReactMethod
import com.facebook.react.bridge.ReadableMap
import com.facebook.react.bridge.WritableArray
import com.facebook.react.module.annotations.ReactModule
import android.content.Context
import java.io.FileNotFoundException

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
    private val core = SentomaruBridge({ null }, sealedReader(context.applicationContext)).also { it.context = context.applicationContext }

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

/**
 * D-14b: the production [SealedReader] for the React Native layer. RN has no bundler step over the native `assets/`
 * folder (the JS bundle itself is `assets/index.android.bundle`, a different file), so the `key` a page passes is
 * already the canonical path `SentomaruSealed` expects: no translation, unlike the Flutter plugin's pubspec prefix.
 * The SDK's own exception becomes [SealedReadError] (the stable bridge code), so `SentomaruBridge` itself never
 * needs to import `sdk/android/sealed`.
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
