package br.com.ebees.sentomaru.sentomaru_flutter

import android.content.Context
import android.os.Build
import androidx.biometric.BiometricManager
import androidx.biometric.BiometricPrompt
import androidx.core.content.ContextCompat
import androidx.fragment.app.FragmentActivity
import br.com.ebees.sentomaru.sdk.BiometricErrors
import br.com.ebees.sentomaru.sdk.TransactionAuthenticator
import br.com.ebees.sentomaru.sdk.TransactionError
import java.security.Signature

/**
 * D-25 (Android): the system prompt for one signature. The [Signature] goes into a `CryptoObject`, so the key works only
 * after the person authenticates: the prompt cannot be skipped by calling `sign`. Not unit-tested on the JVM (it needs a
 * device); the decision logic around it is in [prerequisite] and is.
 *
 * The activity must be a [FragmentActivity] (a Flutter host uses `FlutterFragmentActivity`); anything else is a typed error.
 */
internal class BiometricPromptAuthenticator(
    private val activity: () -> FragmentActivity?,
    private val title: String,
    private val cancelLabel: String,
    private val biometricOnly: Boolean,
) : TransactionAuthenticator {

    override fun authenticate(signature: Signature, onAuthenticated: (Signature) -> Unit, onError: (TransactionError) -> Unit) {
        val host = activity() ?: return onError(TransactionError.Unavailable(NO_ACTIVITY))
        val context: Context = host
        val allowed = allowedAuthenticators(biometricOnly)
        val refusal = prerequisite(BiometricManager.from(context).canAuthenticate(allowed))
        if (refusal != null) return onError(refusal)
        val executor = ContextCompat.getMainExecutor(context)
        executor.execute {
            val prompt = BiometricPrompt(host, executor, object : BiometricPrompt.AuthenticationCallback() {
                override fun onAuthenticationSucceeded(result: BiometricPrompt.AuthenticationResult) {
                    val authenticated = result.cryptoObject?.signature
                    if (authenticated == null) onError(TransactionError.SigningFailed()) else onAuthenticated(authenticated)
                }
                override fun onAuthenticationError(errorCode: Int, errString: CharSequence) {
                    onError(BiometricErrors.map(errorCode))
                }
            })
            val info = BiometricPrompt.PromptInfo.Builder().setTitle(title).setAllowedAuthenticators(allowed).apply {
                if (allowed and BiometricManager.Authenticators.DEVICE_CREDENTIAL == 0) setNegativeButtonText(cancelLabel)
            }.build()
            try { prompt.authenticate(info, BiometricPrompt.CryptoObject(signature)) }
            catch (_: IllegalArgumentException) { onError(TransactionError.Unavailable(BAD_PROMPT)) }
        }
    }

    internal companion object {
        /** Not a platform code: no foreground activity, or the activity is not a FragmentActivity. */
        const val NO_ACTIVITY = -1001
        /** Not a platform code: the platform refused this prompt configuration. */
        const val BAD_PROMPT = -1002

        /** Strong biometric only; with a credential allowed, only from API 30 (earlier, a CryptoObject cannot use it). */
        fun allowedAuthenticators(biometricOnly: Boolean): Int =
            if (biometricOnly || Build.VERSION.SDK_INT < Build.VERSION_CODES.R) BiometricManager.Authenticators.BIOMETRIC_STRONG
            else BiometricManager.Authenticators.BIOMETRIC_STRONG or BiometricManager.Authenticators.DEVICE_CREDENTIAL

        /** The `BiometricManager.canAuthenticate` answer as an error, or null when the prompt can run. */
        fun prerequisite(status: Int): TransactionError? = when (status) {
            BiometricManager.BIOMETRIC_SUCCESS -> null
            BiometricManager.BIOMETRIC_ERROR_NONE_ENROLLED -> TransactionError.NoUserAuthentication()
            BiometricManager.BIOMETRIC_ERROR_NO_HARDWARE -> TransactionError.NoUserAuthentication()
            else -> TransactionError.Unavailable(status)
        }
    }
}
