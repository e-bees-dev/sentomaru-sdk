@file:Suppress("DEPRECATION") // androidx.security:security-crypto is deprecated upstream; see the class doc below.

package br.com.ebees.sentomaru.sdk

import android.content.Context
import android.content.SharedPreferences
import androidx.security.crypto.EncryptedSharedPreferences
import androidx.security.crypto.MasterKey

/**
 * [PrincipalStore.secure]: `EncryptedSharedPreferences` (Jetpack Security Crypto), the exact store whose key can
 * be lost or fail to decrypt — the failure mode [PrincipalStore] guards against with its mirror.
 * `androidx.security:security-crypto` is deprecated upstream (no actively-developed replacement with the same
 * shape at the time of writing); suppressed deliberately at the file level, same spirit as
 * [SentomaruClient.appVersionCode]'s own `@Suppress("DEPRECATION")` for a different, still-necessary deprecated
 * Android API.
 */
class EncryptedSharedPreferencesStore(context: Context, fileName: String = "sentomaru_enrollment_secure") : SentomaruKeyValueStore {
    private val prefs: SharedPreferences = EncryptedSharedPreferences.create(
        context,
        fileName,
        MasterKey.Builder(context).setKeyScheme(MasterKey.KeyScheme.AES256_GCM).build(),
        EncryptedSharedPreferences.PrefKeyEncryptionScheme.AES256_SIV,
        EncryptedSharedPreferences.PrefValueEncryptionScheme.AES256_GCM,
    )

    override fun read(key: String): String? = prefs.getString(key, null)
    override fun write(key: String, value: String) {
        prefs.edit().putString(key, value).apply()
    }
    override fun delete(key: String) {
        prefs.edit().remove(key).apply()
    }
}

/** [PrincipalStore.mirror]: plain `SharedPreferences`, read when [EncryptedSharedPreferencesStore] comes back empty. */
class PlainSharedPreferencesStore(context: Context, fileName: String = "sentomaru_enrollment_mirror") : SentomaruKeyValueStore {
    private val prefs: SharedPreferences = context.getSharedPreferences(fileName, Context.MODE_PRIVATE)

    override fun read(key: String): String? = prefs.getString(key, null)
    override fun write(key: String, value: String) {
        prefs.edit().putString(key, value).apply()
    }
    override fun delete(key: String) {
        prefs.edit().remove(key).apply()
    }
}

/** [PrincipalStore] backed by the two stores above — the usual way to build one on a real device. */
fun PrincipalStore(context: Context): PrincipalStore =
    PrincipalStore(EncryptedSharedPreferencesStore(context), PlainSharedPreferencesStore(context))
