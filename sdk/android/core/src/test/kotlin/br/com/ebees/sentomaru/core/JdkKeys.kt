package br.com.ebees.sentomaru.core

import java.security.KeyFactory
import java.security.KeyPair
import java.security.KeyPairGenerator
import java.security.PublicKey
import java.security.Signature
import java.security.spec.ECGenParameterSpec
import java.security.spec.X509EncodedKeySpec

/** JDK (SunEC) helpers for tests: P-256 keys and P1363 ECDSA. No crypto is implemented here. */
object JdkKeys {
    private const val P1363 = "SHA256withECDSAinP1363Format"

    fun generate(): KeyPair = KeyPairGenerator.getInstance("EC").run {
        initialize(ECGenParameterSpec("secp256r1"))
        generateKeyPair()
    }

    fun publicKey(spki: ByteArray): PublicKey = KeyFactory.getInstance("EC").generatePublic(X509EncodedKeySpec(spki))

    fun signer(pair: KeyPair) = SignatureFunction { base ->
        Signature.getInstance(P1363).run {
            initSign(pair.private)
            update(base)
            sign()
        }
    }

    fun verify(key: PublicKey, base: ByteArray, signature: ByteArray): Boolean = Signature.getInstance(P1363).run {
        initVerify(key)
        update(base)
        verify(signature)
    }
}
