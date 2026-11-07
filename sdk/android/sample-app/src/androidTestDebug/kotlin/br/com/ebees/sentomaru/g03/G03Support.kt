package br.com.ebees.sentomaru.g03

import android.app.Activity
import android.content.Context
import android.hardware.biometrics.BiometricPrompt
import android.os.Bundle
import android.os.CancellationSignal
import android.util.Log
import android.view.MotionEvent
import android.view.View
import androidx.test.platform.app.InstrumentationRegistry
import br.com.ebees.sentomaru.sdk.SentomaruConfig
import br.com.ebees.sentomaru.sdk.EnrollmentChallenge
import br.com.ebees.sentomaru.sdk.EnrollmentGrant
import br.com.ebees.sentomaru.sdk.TransactionAuthenticator
import br.com.ebees.sentomaru.sdk.TransactionError
import br.com.ebees.sentomaru.signals.ObscuredTouchMonitor
import java.security.Signature
import java.time.Instant
import java.util.Base64
import java.util.concurrent.CountDownLatch
import java.util.concurrent.Executors
import java.util.concurrent.TimeUnit

/** G-03: shared pieces of the device proofs. Nothing here talks to a server; results go to logcat as `G03 <id> PASS|FAIL|MEASURED`. */
internal object G03Support {
    const val TAG = "G03"
    val context: Context get() = InstrumentationRegistry.getInstrumentation().targetContext

    val config = SentomaruConfig(
        organization = "org-a", app = "app-a", environment = "hml", allowedHosts = setOf("127.0.0.1"),
        enrollmentUrl = "https://127.0.0.1:8443/v1/org-a/app-a/hml/installations",
    )

    fun challenge() = EnrollmentChallenge(
        id = "33333333-4444-4555-8666-777777777777",
        token = Base64.getEncoder().encodeToString(ByteArray(32) { 11 }),
        attestationChallenge = ByteArray(32) { 22 },
        expiresAt = Instant.now().plusSeconds(300),
    )

    fun grant() = EnrollmentGrant("88888888-9999-4aaa-8bbb-cccccccccccc", "33333333-4444-4555-8666-777777777777",
        "88888888-9999-4aaa-8bbb-cccccccccccc", "hardware", "verified")

    /**
     * `-e g03_credential 1` (instrumentation argument): the key is made with `strongBiometricOnly = false` (biometric OR the device PIN,
     * pattern or password) and the prompt accepts the device credential. For a device with no strong biometric (the reference device has face
     * unlock only). The server tells the two apart by the attested `userAuthType`.
     */
    val credentialMode: Boolean get() = InstrumentationRegistry.getArguments().getString("g03_credential") == "1"

    fun prepare(signer: br.com.ebees.sentomaru.sdk.SentomaruTransactionSigner): ByteArray =
        signer.prepareEnrollment(challenge(), strongBox = false, strongBiometricOnly = !credentialMode)

    fun report(id: String, verdict: String, note: String = "") { Log.i(TAG, "$id $verdict $note".trim()) }

    /**
     * The platform `android.hardware.biometrics.BiometricPrompt` (API 28+, no extra dependency) with the key in a CryptoObject. The
     * person must touch the sensor; the call waits [waitSeconds]. Exactly one of the two callbacks of the SDK is called.
     */
    class PlatformPromptAuthenticator(private val waitSeconds: Long = 90) : TransactionAuthenticator {
        override fun authenticate(signature: Signature, onAuthenticated: (Signature) -> Unit, onError: (TransactionError) -> Unit) {
            // The system shows a BiometricPrompt only for an app in the FOREGROUND: instrumentation alone has no activity, and the prompt
            // is cancelled at once (ERROR_CANCELED, seen on the reference device in 0.7 s). The probe activity (debug build) is the foreground.
            val inst = InstrumentationRegistry.getInstrumentation()
            val foreground = inst.startActivitySync(
                android.content.Intent(inst.targetContext, TouchProbeActivity::class.java).addFlags(android.content.Intent.FLAG_ACTIVITY_NEW_TASK))
            inst.waitForIdleSync()
            val done = CountDownLatch(1)
            val executor = Executors.newSingleThreadExecutor()
            val cancel = CancellationSignal()
            val builder = BiometricPrompt.Builder(context).setTitle("G-03: confirmar assinatura de teste")
            if (credentialMode && android.os.Build.VERSION.SDK_INT >= 30) {
                // PIN allowed: the system shows its own cancel/back; a cancel arrives through onAuthenticationError (USER_CANCELED).
                builder.setAllowedAuthenticators(android.hardware.biometrics.BiometricManager.Authenticators.BIOMETRIC_STRONG or
                    android.hardware.biometrics.BiometricManager.Authenticators.DEVICE_CREDENTIAL)
            } else {
                builder.setNegativeButton("Cancelar", executor) { _, _ -> onError(TransactionError.Cancelled()); done.countDown() }
            }
            val prompt = builder.build()
            prompt.authenticate(BiometricPrompt.CryptoObject(signature), cancel, executor, object : BiometricPrompt.AuthenticationCallback() {
                override fun onAuthenticationSucceeded(result: BiometricPrompt.AuthenticationResult) {
                    val authenticated = result.cryptoObject?.signature
                    if (authenticated == null) onError(TransactionError.SigningFailed()) else onAuthenticated(authenticated)
                    done.countDown()
                }
                override fun onAuthenticationError(errorCode: Int, errString: CharSequence?) {
                    report("PROMPT", "MEASURED", "authenticationError code=$errorCode")
                    onError(br.com.ebees.sentomaru.sdk.BiometricErrors.map(errorCode)); done.countDown()
                }
            })
            if (!done.await(waitSeconds, TimeUnit.SECONDS)) { cancel.cancel(); onError(TransactionError.Cancelled()) }
            executor.shutdown()
            inst.runOnMainSync { foreground.finish() }
        }
    }
}

