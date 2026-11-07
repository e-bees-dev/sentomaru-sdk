package br.com.ebees.sentomaru.core

import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Assert.fail
import org.junit.Test
import java.io.File
import java.util.Base64

/**
 * SDK-VEC-1..4 on the JVM side. Inputs and expectations come from the vendor's vector generator (independent
 * Python implementation, http-message-signatures). ECDSA is randomized: bases, digests and Signature-Input are
 * compared byte for byte; signatures are verified, never compared.
 */
class SharedVectorsTest {
    private val file = VectorFile.load()

    @Test
    fun atLeastThirtyPositiveMessages() {
        assertTrue("positives: ${file.positives.size}", file.positives.size >= 30)
        assertTrue("negatives: ${file.negatives.size}", file.negatives.isNotEmpty())
    }

    /** SDK-VEC-1: Content-Digest identical. */
    @Test
    fun contentDigestMatchesPython() {
        for (v in file.vectors) assertEquals(v.id, v.contentDigest, ContentDigest.sha256(v.body))
    }

    /** SDK-VEC-2: signature base bytes identical. */
    @Test
    fun signatureBaseMatchesPython() {
        for (v in file.positives) {
            val base = SignatureBase.build(v.method, v.targetUri, v.headers, ContentDigest.sha256(v.body), v.params())
            assertArrayEquals(v.id, v.signatureBase, base)
        }
    }

    /** SDK-VEC-2: Signature-Input identical, and the whole signing path yields the same base and headers. */
    @Test
    fun signedMessageMatchesPython() {
        val pair = JdkKeys.generate()
        for (v in file.positives) {
            val signed = MessageSigner.sign(CoreSignedVectors.request(v), v.params(), JdkKeys.signer(pair))
            assertEquals(v.id, v.signatureInput, signed.header(Profile.SIGNATURE_INPUT))
            assertEquals(v.id, v.contentDigest, signed.header(Profile.CONTENT_DIGEST))
            assertArrayEquals(v.id, v.signatureBase, signed.signatureBase())
            assertArrayEquals(v.id, v.body, signed.body())
            assertEquals(v.id, Profile.components(v.headers).drop(2) + listOf(Profile.SIGNATURE_INPUT, Profile.SIGNATURE),
                signed.headers.map { it.first })
            val signature = signed.header(Profile.SIGNATURE)!!.removePrefix("sig1=:").removeSuffix(":")
            assertTrue(v.id, JdkKeys.verify(pair.public, v.signatureBase, Base64.getDecoder().decode(signature)))
        }
    }

    /** SDK-VEC-3: the Python library's signature verifies (JDK) over the CORE's base. */
    @Test
    fun pythonSignatureVerifiesOverCoreBase() {
        val key = JdkKeys.publicKey(file.pythonPublicKeySpki)
        for (v in file.positives) {
            val base = SignatureBase.build(v.method, v.targetUri, v.headers, ContentDigest.sha256(v.body), v.params())
            val signature = Base64.getDecoder().decode(v.pythonSignature.removePrefix("sig1=:").removeSuffix(":"))
            assertEquals(64, signature.size)
            assertTrue(v.id, JdkKeys.verify(key, base, signature))
            val flipped = base.copyOf().also { it[it.size / 2] = (it[it.size / 2].toInt() xor 1).toByte() }
            assertTrue(v.id, !JdkKeys.verify(key, flipped, signature))
        }
    }

    /** SDK-VEC-4 (core side): every negative is refused with the expected typed error, before the signer runs. */
    @Test
    fun negativesAreRefusedWithTypedErrors() {
        for (v in file.negatives) {
            try {
                MessageSigner.sign(CoreSignedVectors.request(v), v.params()) { fail("${v.id}: signer reached"); ByteArray(0) }
                fail("${v.id}: accepted")
            } catch (e: SentomaruException) {
                assertEquals(v.id, v.coreError, e.error.code)
                assertEquals(v.id, e.error.code, e.message)
            }
        }
    }

    /** The checked-in core-signed fixture is what this core produces (same envelopes) and its signatures verify. */
    @Test
    fun coreSignedFixtureIsCurrent() {
        val (spki, entries) = CoreSignedVectors.read(File(VectorFile.dir(), CoreSignedVectors.NAME))
        val key = JdkKeys.publicKey(spki)
        assertEquals(file.positives.map { it.id }, entries.map { it.id })
        for ((v, entry) in file.positives.zip(entries)) {
            assertEquals(v.id, v.route, entry.route)
            val signature = entry.signature()
            val signed = MessageSigner.sign(CoreSignedVectors.request(v), v.params()) { signature }
            assertEquals("${v.id}: fixture stale, run ./gradlew :core:exportCoreSignedVectors", entry.envelope,
                String(CoreSignedVectors.envelope(v, signed), Charsets.UTF_8))
            assertTrue(v.id, JdkKeys.verify(key, signed.signatureBase(), signature))
        }
    }
}
