package br.com.ebees.sentomaru.g03

import androidx.test.ext.junit.runners.AndroidJUnit4
import br.com.ebees.sentomaru.sdk.AndroidInstallationKeys
import br.com.ebees.sentomaru.sdk.AndroidInstallationStore
import br.com.ebees.sentomaru.sdk.AndroidTransactionKeys
import br.com.ebees.sentomaru.sdk.SentomaruClient
import br.com.ebees.sentomaru.sdk.SentomaruTransactionSigner
import br.com.ebees.sentomaru.sdk.TransactionError
import br.com.ebees.sentomaru.sdk.TransactionSignature
import org.junit.After
import org.junit.Assert.*
import org.junit.Before
import org.junit.Test
import org.junit.runner.RunWith
import java.security.KeyFactory
import java.security.Signature
import java.security.spec.X509EncodedKeySpec
import java.util.Base64

/**
 * G-03 P-1 and P-2: the transaction key in the real Android Keystore with the real platform
 * BiometricPrompt. P-1 needs a finger on the sensor (biometric enrolled on the device); P-2 does not. No server: enrollment bodies
 * are built and never sent. The keys are deleted at the end.
 */
@RunWith(AndroidJUnit4::class)
class TransactionKeyDeviceTest {
    private val keys = AndroidTransactionKeys()
    private lateinit var client: SentomaruClient

    @Before fun setUp() {
        client = SentomaruClient(G03Support.config, AndroidInstallationKeys(), AndroidInstallationStore(G03Support.context, G03Support.config))
        client.reset()
        client.enroll(G03Support.challenge()) { G03Support.grant() }
    }

    @After fun tearDown() {
        SentomaruTransactionSigner(client, keys).discard()
        client.reset()
    }

    private fun publicKeyOf(body: ByteArray): java.security.PublicKey {
        val b64 = Regex("\"publicKey\":\"([^\"]+)\"").find(String(body))!!.groupValues[1]
        return KeyFactory.getInstance("EC").generatePublic(X509EncodedKeySpec(Base64.getDecoder().decode(b64)))
    }

    /** P-1: the key is usable only after the person authenticates; the header verifies with the public key of the enrollment body. */
    @Test fun p1_keystoreKeyAndBiometricPromptSignAHeaderThatVerifies() {
        val signer = SentomaruTransactionSigner(client, keys)
        val body = G03Support.prepare(signer)
        signer.commitEnrollment()
        assertTrue("key exists after commit", signer.isEnrolled())
        val operationId = "g03-operation-0123456789"
        val payload = "{\"amount\":10}".toByteArray()
        var header: String? = null; var error: TransactionError? = null
        signer.sign(operationId, payload, G03Support.PlatformPromptAuthenticator(), { header = it }, { error = it })
        assertNull("prompt error (a finger must touch the sensor within 90 s): ${error?.code}", error)
        val parts = header!!.split('.')
        assertEquals("sentomaru-tx-v2", parts[0])
        val nonce = Base64.getUrlDecoder().decode(parts[1]); val issuedAt = parts[2].toLong(); val sig = Base64.getUrlDecoder().decode(parts[3])
        val verify = Signature.getInstance("SHA256withECDSA").apply {
            initVerify(publicKeyOf(body)); update(TransactionSignature.message(nonce, issuedAt, operationId, payload))
        }
        assertTrue("signature over the v2 bytes", verify.verify(p1363ToDer(sig)))
        assertTrue("issuedAt within a minute of the device clock", Math.abs(System.currentTimeMillis() / 1000 - issuedAt) < 60)
        val created = keys.createdAt("$base.tx")
        assertTrue("getCreationDate returned a date (0 = unreadable)", created > 0)
        G03Support.report("P-1", "PASS", "creationDateMillis=$created")
    }

    /** P-1b: cancelling the prompt is recoverable and spends nothing; the key stays. (Touch Cancelar when asked.) */
    @Test fun p1b_cancellingThePromptKeepsTheKey() {
        val signer = SentomaruTransactionSigner(client, keys)
        G03Support.prepare(signer); signer.commitEnrollment()
        var header: String? = null; var error: TransactionError? = null
        signer.sign("g03-operation-0123456789", "{}".toByteArray(), G03Support.PlatformPromptAuthenticator(waitSeconds = 20), { header = it }, { error = it })
        if (header != null) { G03Support.report("P-1b", "MEASURED", "the person authenticated instead of cancelling"); return }
        assertTrue("recoverable: ${error?.code}", error!!.recoverable)
        assertTrue(signer.isEnrolled())
        G03Support.report("P-1b", "PASS", "code=${error!!.code}")
    }

    /**
     * P-2: two keys exist (the process "died" between the server's 201 and `commitEnrollment`). A fresh signer, as after a restart,
     * must sign with the OLDER one: the header is verified against the public key of each slot. The test records both creation dates;
     * equal dates are the finding of fech-sdk (the choice then falls to slot order and may elect the wrong key). Needs a finger.
     */
    @Test fun p2_two_keys_older_signs() {
        val first = SentomaruTransactionSigner(client, keys)
        G03Support.prepare(first); first.commitEnrollment()
        Thread.sleep(1_500) // a visible gap between the creation dates, as in a real re-enrollment
        G03Support.prepare(first) // second key made, `commitEnrollment` never called: "death"
        val restarted = SentomaruTransactionSigner(client, keys) // a new process: `pending` is lost
        val slots = listOf("$base.tx", "$base.tx.next")
        assertEquals("both keys exist", 2, slots.count { keys.exists(it) })
        val dates = slots.associateWith { keys.createdAt(it) }
        G03Support.report("P-2", "MEASURED", "creationDates=$dates")
        assertNotEquals("the creation dates differ (equal = the choice falls to slot order)", dates.getValue(slots[0]), dates.getValue(slots[1]))
        val older = dates.minBy { it.value }.key; val newer = slots.first { it != older }

        val operationId = "g03-operation-0123456789"; val payload = "{}".toByteArray()
        var header: String? = null; var error: TransactionError? = null
        restarted.sign(operationId, payload, G03Support.PlatformPromptAuthenticator(), { header = it }, { error = it })
        assertNull("prompt error (touch the sensor): ${error?.code}", error)
        val parts = header!!.split('.')
        val nonce = Base64.getUrlDecoder().decode(parts[1]); val issuedAt = parts[2].toLong()
        val der = p1363ToDer(Base64.getUrlDecoder().decode(parts[3]))
        fun verifiesWith(alias: String) = Signature.getInstance("SHA256withECDSA").apply {
            initVerify(publicKeyOfAlias(alias)); update(TransactionSignature.message(nonce, issuedAt, operationId, payload))
        }.verify(der)
        assertTrue("the older key signed", verifiesWith(older))
        assertFalse("the newer key did not", verifiesWith(newer))

        restarted.commitEnrollment()
        assertEquals("commit keeps one key", 1, slots.count { keys.exists(it) })
        assertTrue("and it is the newer", keys.exists(newer))
        G03Support.report("P-2", "PASS")
    }

    private fun publicKeyOfAlias(alias: String): java.security.PublicKey =
        java.security.KeyStore.getInstance("AndroidKeyStore").apply { load(null) }.getCertificate(alias).publicKey

    // The installation alias is internal to the SDK module: it is the only app key that does not end in `.tx` or `.tx.next`.
    private val base: String by lazy {
        val ks = java.security.KeyStore.getInstance("AndroidKeyStore").apply { load(null) }
        ks.aliases().toList().first { !it.endsWith(".tx") && !it.endsWith(".tx.next") }
    }

    /** IEEE P1363 (r || s) to the DER the JCA verifier wants; the SDK's own converter is in a module the sample app does not see. */
    private fun p1363ToDer(sig: ByteArray): ByteArray {
        fun der(half: ByteArray): ByteArray {
            var v: ByteArray = half.dropWhile { it == 0.toByte() }.toByteArray()
            if (v.isEmpty()) v = byteArrayOf(0)
            if (v[0] < 0) v = byteArrayOf(0) + v
            return byteArrayOf(0x02, v.size.toByte()) + v
        }
        val body = der(sig.copyOfRange(0, sig.size / 2)) + der(sig.copyOfRange(sig.size / 2, sig.size))
        return byteArrayOf(0x30, body.size.toByte()) + body
    }
}
