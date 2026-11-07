package br.com.ebees.sentomaru.signer

import android.os.Build
import android.security.keystore.KeyGenParameterSpec
import android.security.keystore.KeyPermanentlyInvalidatedException
import android.security.keystore.KeyProperties
import android.security.keystore.StrongBoxUnavailableException
import java.security.KeyPairGenerator
import java.security.KeyStore
import java.security.PrivateKey
import java.security.ProviderException
import java.security.Signature
import java.security.spec.ECGenParameterSpec

/** D-25: the transaction key does not exist, or biometrics changed and the platform dropped it for good. */
class TransactionKeyInvalidatedException(cause: Throwable? = null) : IllegalStateException("transaction key invalidated", cause)

/**
 * D-25 (HU-01): the second Keystore key, EC P-256, that signs one transaction at a time only after the person
 * authenticated at that moment (`setUserAuthenticationRequired(true)` with a validity of zero: every use needs a fresh
 * authentication through a `BiometricPrompt.CryptoObject`).
 *
 * What it proves is presence of a person who can unlock the device at the time of the signature. It does not prove that
 * the person saw the value of the transaction. The key is non-exportable; the private key never leaves the Keystore.
 *
 * `strongBiometricOnly` (the default) accepts Class 3 biometrics only. With it false, the device credential (PIN,
 * pattern, password) is also accepted, which the server can tell apart only through the attested `userAuthType`; below
 * API 30 a key cannot be both, so the key then accepts biometrics only.
 */
class TransactionKeySigner {
    /** Generates the key under [alias] (deleting an existing one first) and returns the attestation chain, DER, leaf first. */
    fun generate(alias: String, challenge: ByteArray, strongBox: Boolean, strongBiometricOnly: Boolean = true): List<ByteArray> {
        require(alias.isNotEmpty()) { "alias must not be empty" }
        require(challenge.size == KeystoreSigner.ATTESTATION_CHALLENGE_BYTES) {
            "attestationChallenge must be ${KeystoreSigner.ATTESTATION_CHALLENGE_BYTES} raw bytes"
        }
        KeystoreSigner.deleteKey(alias)
        val builder = KeyGenParameterSpec.Builder(alias, KeyProperties.PURPOSE_SIGN)
            .setAlgorithmParameterSpec(ECGenParameterSpec("secp256r1"))
            .setDigests(KeyProperties.DIGEST_SHA256)
            .setAttestationChallenge(challenge.copyOf())
            .setUserAuthenticationRequired(true)
            .setInvalidatedByBiometricEnrollment(true)
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.R) {
            val types = if (strongBiometricOnly) KeyProperties.AUTH_BIOMETRIC_STRONG
            else KeyProperties.AUTH_BIOMETRIC_STRONG or KeyProperties.AUTH_DEVICE_CREDENTIAL
            builder.setUserAuthenticationParameters(0, types)
        } else {
            @Suppress("DEPRECATION") // before API 30 a validity of -1 is the per-use (CryptoObject) form
            builder.setUserAuthenticationValidityDurationSeconds(-1)
        }
        if (strongBox) builder.setIsStrongBoxBacked(true)
        try {
            KeyPairGenerator.getInstance(KeyProperties.KEY_ALGORITHM_EC, ANDROID_KEYSTORE).run {
                initialize(builder.build())
                generateKeyPair()
            }
        } catch (e: StrongBoxUnavailableException) {
            KeystoreSigner.deleteKey(alias)
            throw StrongBoxUnavailableError()
        } catch (e: ProviderException) {
            KeystoreSigner.deleteKey(alias)
            if (strongBox && e.cause is StrongBoxUnavailableException) throw StrongBoxUnavailableError()
            throw e
        }
        val chain = keyStore().getCertificateChain(alias) ?: error("AndroidKeyStore returned no certificate chain")
        return chain.map { it.encoded }
    }

    /**
     * A `Signature` initialised for signing with the key, to wrap in `BiometricPrompt.CryptoObject`. The signature is
     * usable only after the prompt authenticates. [TransactionKeyInvalidatedException] when the key is gone or the
     * platform invalidated it (a new fingerprint or face was enrolled).
     */
    fun initSign(alias: String): Signature {
        val key = try {
            keyStore().getKey(alias, null) as? PrivateKey
        } catch (e: java.security.GeneralSecurityException) {
            throw TransactionKeyInvalidatedException(e)
        } ?: throw TransactionKeyInvalidatedException()
        return try {
            Signature.getInstance(SIGNATURE_ALGORITHM).apply { initSign(key) }
        } catch (e: KeyPermanentlyInvalidatedException) {
            throw TransactionKeyInvalidatedException(e)
        }
    }

    companion object {
        private const val ANDROID_KEYSTORE = "AndroidKeyStore"
        private const val SIGNATURE_ALGORITHM = "SHA256withECDSA"
        private fun keyStore(): KeyStore = KeyStore.getInstance(ANDROID_KEYSTORE).apply { load(null) }

        fun containsAlias(alias: String): Boolean = keyStore().containsAlias(alias)
        fun deleteKey(alias: String) = KeystoreSigner.deleteKey(alias)

        /** Creation time of the key in epoch milliseconds, or 0 when the platform gives none. */
        fun createdAtMillis(alias: String): Long = keyStore().getCreationDate(alias)?.time ?: 0L
    }
}
