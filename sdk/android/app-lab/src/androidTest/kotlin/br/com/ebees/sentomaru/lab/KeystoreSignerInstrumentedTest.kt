package br.com.ebees.sentomaru.lab

import android.content.pm.PackageManager
import android.os.Build
import android.security.keystore.KeyInfo
import android.util.Log
import androidx.test.ext.junit.runners.AndroidJUnit4
import androidx.test.platform.app.InstrumentationRegistry
import br.com.ebees.sentomaru.signer.EcdsaSignatureFormat
import br.com.ebees.sentomaru.signer.GenerationResult
import br.com.ebees.sentomaru.signer.KeystoreSigner
import java.io.ByteArrayInputStream
import java.math.BigInteger
import java.security.KeyFactory
import java.security.KeyStore
import java.security.NoSuchAlgorithmException
import java.security.PrivateKey
import java.security.PublicKey
import java.security.Signature
import java.security.cert.CertificateFactory
import java.security.cert.X509Certificate
import java.security.interfaces.ECPublicKey
import org.junit.After
import org.junit.BeforeClass
import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertNull
import org.junit.Assert.assertThrows
import org.junit.Assert.assertTrue
import org.junit.Test
import org.junit.runner.RunWith

/**
 * Runs on a real device against AndroidKeyStore. Lab only: asserts shape and local
 * self-consistency; trust in the attestation chain is verified server-side (Task 5).
 * Logs only model class, Android release and SDK int — never device identifiers.
 */
@RunWith(AndroidJUnit4::class)
class KeystoreSignerInstrumentedTest {

    private val alias = "sentomaru-lab-test-key"
    private val strongBoxAlias = "sentomaru-lab-test-key-sb"
    private val challenge = ByteArray(32) { it.toByte() } // fixed: 0x00..0x1f
    private val signatureBase = "\"@method\": POST\n\"@signature-params\": (\"@method\")".toByteArray()

    private fun certs(chain: List<ByteArray>): List<X509Certificate> {
        val cf = CertificateFactory.getInstance("X.509")
        return chain.map { cf.generateCertificate(ByteArrayInputStream(it)) as X509Certificate }
    }

    /** Independent P1363 verification: platform P1363 if present, else P1363->DER + SHA256withECDSA. */
    private fun verifyP1363(publicKey: PublicKey, data: ByteArray, sig: ByteArray): Boolean {
        val key = KeyFactory.getInstance("EC").generatePublic(java.security.spec.X509EncodedKeySpec(publicKey.encoded))
        return try {
            Signature.getInstance("SHA256withECDSAinP1363Format").run { initVerify(key); update(data); verify(sig) }
        } catch (e: NoSuchAlgorithmException) {
            Signature.getInstance("SHA256withECDSA").run {
                initVerify(key); update(data); verify(EcdsaSignatureFormat.p1363ToDer(sig))
            }
        }
    }

    @After
    fun cleanup() {
        KeystoreSigner.deleteKey(alias)
        KeystoreSigner.deleteKey(strongBoxAlias)
        assertFalse(KeystoreSigner.containsAlias(alias))
        assertFalse(KeystoreSigner.containsAlias(strongBoxAlias))
    }

    @Test
    fun t1_generateReturnsLeafFirstChainWithinProfileCapsAndP256Leaf() {
        val chain = KeystoreSigner().generate(alias, challenge, strongBox = false)
        assertTrue("chain non-empty", chain.isNotEmpty())
        assertTrue("chain <= 5 certs (got ${chain.size})", chain.size <= 5)
        chain.forEachIndexed { i, der -> assertTrue("cert $i DER <= 4096 (got ${der.size})", der.size <= 4096) }
        val x509 = certs(chain)
        val leaf = x509[0]
        val pub = leaf.publicKey as ECPublicKey
        assertEquals(256, pub.params.curve.field.fieldSize)
        assertEquals(P256_ORDER, pub.params.order)
        // leaf-first: leaf is the key's own certificate and each cert is issued by the next one
        assertArrayEquals(keyStore().getCertificate(alias).encoded, chain[0])
        for (i in 0 until x509.size - 1) assertEquals(x509[i].issuerX500Principal, x509[i + 1].subjectX500Principal)
        // non-exportable private key
        val priv = keyStore().getKey(alias, null) as PrivateKey
        assertNull("AndroidKeyStore private key must not expose encoded material", priv.encoded)
        val info = KeyFactory.getInstance(priv.algorithm, "AndroidKeyStore").getKeySpec(priv, KeyInfo::class.java)
        assertFalse(info.isUserAuthenticationRequired)
        Log.i(TAG, "chainSize=${chain.size} securityLevel=${if (Build.VERSION.SDK_INT >= 31) info.securityLevel else -99}")
    }

    @Test
    fun t2_signReturns64BytesP1363VerifiableWithLeafKey() {
        val signer = KeystoreSigner()
        val chain = signer.generate(alias, challenge, strongBox = false)
        val sig = signer.sign(signatureBase)
        assertEquals(64, sig.size)
        assertTrue(verifyP1363(certs(chain)[0].publicKey, signatureBase, sig))
    }

    @Test
    fun t3_signatureDoesNotVerifyOverDifferentBytes() {
        val signer = KeystoreSigner()
        val chain = signer.generate(alias, challenge, strongBox = false)
        val sig = signer.sign(signatureBase)
        val other = signatureBase.copyOf().also { it[0] = (it[0].toInt() xor 1).toByte() }
        assertFalse(verifyP1363(certs(chain)[0].publicKey, other, sig))
    }

    @Test
    fun t4_leafCarriesAttestationExtensionWithChallenge_smoke() {
        val chain = KeystoreSigner().generate(alias, challenge, strongBox = false)
        val ext = certs(chain)[0].getExtensionValue(ATTESTATION_OID)
        assertNotNull("attestation extension on leaf", ext)
        assertTrue("challenge bytes present in extension (smoke only; Task 5 parses)", indexOf(ext!!, challenge) >= 0)
    }

    @Test
    fun t5_strongBoxRequestReturnsTypedResultWithoutCrash() {
        val r = KeystoreSigner().generateResult(strongBoxAlias, challenge, strongBox = true)
        if (!hasStrongBox()) assertTrue("no StrongBox feature -> typed unavailable", r === GenerationResult.StrongBoxUnavailable)
        else assertTrue(r is GenerationResult.Generated)
        Log.i(TAG, "strongBox=${if (r is GenerationResult.Generated) "generated" else "unavailable"}")
    }

    @Test
    fun t5b_strongBoxGeneratesAndSignsWhenAvailable() {
        if (!hasStrongBox()) { Log.i(TAG, "SKIP t5b: no StrongBox"); return }
        val signer = KeystoreSigner()
        val r = signer.generateResult(strongBoxAlias, challenge, strongBox = true)
        assertTrue(r is GenerationResult.Generated)
        val chain = (r as GenerationResult.Generated).chain
        assertTrue(chain.isNotEmpty() && chain.size <= 5)
        val sig = signer.sign(signatureBase)
        assertEquals(64, sig.size)
        assertTrue(verifyP1363(certs(chain)[0].publicKey, signatureBase, sig))
    }

    @Test
    fun t6_rejectsWrongChallengeLengthAndSignBeforeGenerate() {
        assertThrows(IllegalArgumentException::class.java) { KeystoreSigner().generate(alias, ByteArray(16), false) }
        assertThrows(IllegalStateException::class.java) { KeystoreSigner().sign(signatureBase) }
        assertFalse(KeystoreSigner.containsAlias(alias))
    }

    @Test
    fun t7_failedStrongBoxGenerationForOtherAliasUnbindsSigner() {
        if (hasStrongBox()) { Log.i(TAG, "SKIP t7: StrongBox present, generation would not fail"); return }
        val signer = KeystoreSigner()
        signer.generate(alias, challenge, strongBox = false)
        assertEquals(64, signer.sign(signatureBase).size)
        assertTrue(signer.generateResult(strongBoxAlias, challenge, strongBox = true) === GenerationResult.StrongBoxUnavailable)
        val e = assertThrows(IllegalStateException::class.java) { signer.sign(signatureBase) }
        assertEquals("no key generated", e.message)
    }

    @Test
    fun t8_failedStrongBoxRegenerationOfSameAliasUnbindsSigner() {
        if (hasStrongBox()) { Log.i(TAG, "SKIP t8: StrongBox present, generation would not fail"); return }
        val signer = KeystoreSigner()
        signer.generate(alias, challenge, strongBox = false)
        assertTrue(signer.generateResult(alias, challenge, strongBox = true) === GenerationResult.StrongBoxUnavailable)
        val e = assertThrows(IllegalStateException::class.java) { signer.sign(signatureBase) }
        assertEquals("no key generated", e.message)
        assertFalse("previous key under the alias is lost (documented)", KeystoreSigner.containsAlias(alias))
    }

    @Test
    fun t9_useExistingBindsAKeyGeneratedByAnotherInstance() {
        val chain = KeystoreSigner().generate(alias, challenge, strongBox = false)
        val other = KeystoreSigner()
        other.useExisting(alias)
        val sig = other.sign(signatureBase)
        assertEquals(64, sig.size)
        assertTrue(verifyP1363(certs(chain)[0].publicKey, signatureBase, sig))
        KeystoreSigner.deleteKey(alias)
        assertThrows(IllegalStateException::class.java) { other.useExisting(alias) }
        val e = assertThrows(IllegalStateException::class.java) { other.sign(signatureBase) }
        assertEquals("no key generated", e.message)
        assertThrows(IllegalArgumentException::class.java) { other.useExisting("") }
    }

    private fun hasStrongBox(): Boolean = InstrumentationRegistry.getInstrumentation().targetContext
        .packageManager.hasSystemFeature(PackageManager.FEATURE_STRONGBOX_KEYSTORE)

    private fun keyStore() = KeyStore.getInstance("AndroidKeyStore").apply { load(null) }

    private fun indexOf(haystack: ByteArray, needle: ByteArray): Int {
        outer@ for (i in 0..haystack.size - needle.size) {
            for (j in needle.indices) if (haystack[i + j] != needle[j]) continue@outer
            return i
        }
        return -1
    }

    companion object {
        /** Environment log only (not a test): model class, release, SDK int; never device identifiers. */
        @BeforeClass
        @JvmStatic
        fun logEnvironment() {
            val p1363 = try { Signature.getInstance("SHA256withECDSAinP1363Format"); true } catch (e: NoSuchAlgorithmException) { false }
            Log.i(TAG, "model=${Build.MODEL} release=${Build.VERSION.RELEASE} sdk=${Build.VERSION.SDK_INT} platformP1363=$p1363")
        }

        private const val TAG = "SentomaruLab"
        private const val ATTESTATION_OID = "1.3.6.1.4.1.11129.2.1.17"
        private val P256_ORDER = BigInteger("ffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632551", 16)
    }
}
