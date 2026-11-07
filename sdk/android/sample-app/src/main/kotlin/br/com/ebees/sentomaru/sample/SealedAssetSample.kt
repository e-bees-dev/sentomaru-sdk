package br.com.ebees.sentomaru.sample

import android.content.Context
import br.com.ebees.sentomaru.sdk.sealed.SentomaruSealed

/**
 * D-14b, lab only: how an app reads the assets `sentomaru protect` (asset-encryption) seals. The profile marks
 * `assets/d14b/regras.json` and the strings file `assets/d14b/sentomaru-strings.json`; the app reads them through
 * [SentomaruSealed] by canonical path instead of `assets.open`. Without the CLI (debug builds) the plain fallback is on,
 * and only there (D-14x10). Kept by `proguard-rules.pro`; never run in CI and has no UI (D-14d runs it on a device).
 */
object SealedAssetSample {
    const val RULES = "assets/d14b/regras.json"
    const val STRINGS = "assets/d14b/sentomaru-strings.json"

    /** Call once with `BuildConfig.DEBUG` (this lab app has no BuildConfig, so the caller passes it). */
    fun configure(debug: Boolean) {
        SentomaruSealed.configure(allowPlainFallback = debug, plainStringsPath = STRINGS)
    }

    fun rules(context: Context): String = SentomaruSealed.bytes(context, RULES).toString(Charsets.UTF_8)

    fun greeting(context: Context): String? = SentomaruSealed.string(context, "saudacao")
}
