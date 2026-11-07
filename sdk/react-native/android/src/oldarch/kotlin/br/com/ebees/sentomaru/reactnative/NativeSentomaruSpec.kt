package br.com.ebees.sentomaru.reactnative

import com.facebook.react.bridge.Promise
import com.facebook.react.bridge.ReactApplicationContext
import com.facebook.react.bridge.ReactContextBaseJavaModule
import com.facebook.react.bridge.ReactMethod
import com.facebook.react.bridge.ReadableMap

/**
 * the spec class of the old architecture. With the new architecture the React Native codegen generates a
 * class of the same name and shape from `src/NativeSentomaru.ts` (`call(method: string, args: Object): Promise<Object>`);
 * [SentomaruModule] extends whichever one the build selects, so the module's code is the same in both.
 */
abstract class NativeSentomaruSpec(context: ReactApplicationContext) : ReactContextBaseJavaModule(context) {
    @ReactMethod
    abstract fun call(method: String, args: ReadableMap?, promise: Promise)
}
