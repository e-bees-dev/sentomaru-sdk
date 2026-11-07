package br.com.ebees.sentomaru.reactnative

import com.facebook.react.BaseReactPackage
import com.facebook.react.bridge.NativeModule
import com.facebook.react.bridge.ReactApplicationContext
import com.facebook.react.module.model.ReactModuleInfo
import com.facebook.react.module.model.ReactModuleInfoProvider

/**
 * registers [SentomaruModule]; the app adds it to `getPackages()` (autolinking does it). The module is
 * declared a TurboModule exactly when the app builds with the new architecture (`newArchEnabled`).
 */
class SentomaruPackage : BaseReactPackage() {
    override fun getModule(name: String, reactContext: ReactApplicationContext): NativeModule? =
        if (name == SentomaruModule.NAME) SentomaruModule(reactContext) else null

    override fun getReactModuleInfoProvider(): ReactModuleInfoProvider = ReactModuleInfoProvider {
        mapOf(
            SentomaruModule.NAME to ReactModuleInfo(
                SentomaruModule.NAME, SentomaruModule::class.java.name,
                false, // canOverrideExistingModule
                false, // needsEagerInit
                false, // isCxxModule
                BuildConfig.IS_NEW_ARCHITECTURE_ENABLED, // isTurboModule
            ),
        )
    }
}
