package br.com.ebees.sentomaru.sentomaru_flutter

import androidx.biometric.BiometricManager
import br.com.ebees.sentomaru.sdk.TransactionError
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test

/** D-25 (Android): what `BiometricManager.canAuthenticate` says before the prompt; the prompt itself needs a device. */
class BiometricPromptAuthenticatorTest {
    @Test
    fun onlyBiometricSuccessLetsThePromptRun() {
        assertNull(BiometricPromptAuthenticator.prerequisite(BiometricManager.BIOMETRIC_SUCCESS))
    }

    @Test
    fun noEnrolledBiometricOrNoSensorIsNoUserAuthentication() {
        assertTrue(BiometricPromptAuthenticator.prerequisite(BiometricManager.BIOMETRIC_ERROR_NONE_ENROLLED) is TransactionError.NoUserAuthentication)
        assertTrue(BiometricPromptAuthenticator.prerequisite(BiometricManager.BIOMETRIC_ERROR_NO_HARDWARE) is TransactionError.NoUserAuthentication)
    }

    @Test
    fun everyOtherStatusIsUnavailableAndCarriesThePlatformCode() {
        for (status in listOf(BiometricManager.BIOMETRIC_ERROR_HW_UNAVAILABLE, BiometricManager.BIOMETRIC_ERROR_SECURITY_UPDATE_REQUIRED,
            BiometricManager.BIOMETRIC_ERROR_UNSUPPORTED, BiometricManager.BIOMETRIC_STATUS_UNKNOWN, 12345)) {
            val error = BiometricPromptAuthenticator.prerequisite(status)
            assertTrue(status.toString(), error is TransactionError.Unavailable)
            assertEquals(status, (error as TransactionError.Unavailable).platformCode)
        }
    }

    @Test
    fun theDefaultNeverAllowsTheDeviceCredential() {
        assertEquals(BiometricManager.Authenticators.BIOMETRIC_STRONG, BiometricPromptAuthenticator.allowedAuthenticators(true))
    }
}
