package br.com.ebees.sentomaru.lab

import android.content.pm.PackageManager
import androidx.test.ext.junit.runners.AndroidJUnit4
import androidx.test.platform.app.InstrumentationRegistry
import br.com.ebees.sentomaru.core.FrozenRequest
import br.com.ebees.sentomaru.core.SentomaruException
import br.com.ebees.sentomaru.sdk.*
import br.com.ebees.sentomaru.signer.EcdsaSignatureFormat
import br.com.ebees.sentomaru.signer.KeystoreSigner
import org.junit.Assert.*
import org.junit.Test
import org.junit.runner.RunWith
import java.io.ByteArrayInputStream
import java.io.IOException
import java.security.KeyStore
import java.security.PrivateKey
import java.security.Signature
import java.security.cert.CertificateFactory
import java.time.Clock
import java.time.Instant
import java.time.ZoneOffset
import java.util.Base64

/** Real Keystore + durable local state; network is injected. Trust/API acceptance belongs to Task 5. */
@RunWith(AndroidJUnit4::class)
class EnrollmentInstrumentedTest {
    private val context = InstrumentationRegistry.getInstrumentation().targetContext
    private val config = SentomaruConfig("lab", "enrollment", "test", setOf("consumer.example"), "https://consumer.example/enroll")
    private val now = Instant.parse("2026-10-08T12:00:00Z")
    private val clock = Clock.fixed(now, ZoneOffset.UTC)
    private val id = "11111111-2222-4333-8444-555555555555"
    private val session = "aaaaaaaa-bbbb-4ccc-8ddd-eeeeeeeeeeee"
    private fun challenge() = EnrollmentChallenge(id, Base64.getEncoder().encodeToString(ByteArray(32) { 17 }),
        ByteArray(32) { 23 }, now.plusSeconds(120))
    private fun grant() = EnrollmentGrant(session, id, session, "unknown", "notEvaluated")

    @Test fun durablePendingEnrollmentRecoversWithoutExportingOrReplacingKey() {
        val store = AndroidInstallationStore(context, config)
        val keys = AndroidInstallationKeys()
        val client = SentomaruClient(config, keys, store, clock)
        client.reset()
        try {
            assertSame(SentomaruClient.initialize(context, config), SentomaruClient.initialize(context, config))
            var original: ByteArray? = null
            val error = assertThrows(SentomaruException::class.java) {
                client.enroll(challenge()) {
                    original = it.body()
                    val material = keys.material(store.read()!!.alias)
                    val certificate = CertificateFactory.getInstance("X.509")
                        .generateCertificate(ByteArrayInputStream(material.chain()[0]))
                    val signature = Base64.getDecoder().decode(it.header("signature")!!.removePrefix("sig1=:").removeSuffix(":"))
                    assertTrue(Signature.getInstance("SHA256withECDSA").run {
                        initVerify(certificate.publicKey); update(it.signatureBase())
                        verify(EcdsaSignatureFormat.p1363ToDer(signature))
                    })
                    val ks = KeyStore.getInstance("AndroidKeyStore").apply { load(null) }
                    assertNull((ks.getKey(store.read()!!.alias, null) as PrivateKey).encoded)
                    throw IOException("lost response")
                }
            }
            assertEquals("NetworkUnavailable", error.error.code)
            val persistedAlias = store.read()!!.alias
            val recreated = SentomaruClient(config, AndroidInstallationKeys(), AndroidInstallationStore(context, config), clock)
            recreated.enroll(challenge()) { assertArrayEquals(original, it.body()); grant() }
            assertEquals(persistedAlias, store.read()!!.alias)
            assertEquals(InstallationState.Enrolled, recreated.state())
            keys.delete(persistedAlias)
            assertEquals(InstallationState.KeyInvalidated, recreated.state())
            assertEquals("KeyInvalidated", assertThrows(SentomaruException::class.java) {
                recreated.enroll(challenge()) { grant() }
            }.error.code)
        } finally { client.reset(); assertNull(store.read()) }
    }

    @Test fun absentStrongBoxIsTypedAndDoesNotLeaveEnrollmentState() {
        if (context.packageManager.hasSystemFeature(PackageManager.FEATURE_STRONGBOX_KEYSTORE)) return
        val store = AndroidInstallationStore(context, config)
        val client = SentomaruClient(config, AndroidInstallationKeys(), store, clock)
        client.reset()
        try {
            assertEquals("StrongBoxUnavailable", assertThrows(SentomaruException::class.java) {
                client.enroll(challenge(), strongBox = true) { grant() }
            }.error.code)
            assertEquals(InstallationState.NotEnrolled, client.state())
        } finally { client.reset() }
    }

    @Test fun explicitResetRecoversCorruptedStateAndDeletesOnlyOwnedKey() {
        val store = AndroidInstallationStore(context, config)
        val keys = AndroidInstallationKeys()
        val client = SentomaruClient(config, keys, store, clock)
        client.reset()
        var alias: String? = null
        val unrelated = "sentomaru-unrelated-lab-key"
        try {
            KeystoreSigner().generate(unrelated, ByteArray(32) { 42 }, false)
            client.enroll(challenge()) { grant() }
            alias = store.read()!!.alias
            val directory = java.io.File(context.noBackupFilesDir, "sentomaru")
            val file = directory.listFiles()!!.single { it.name.endsWith(".json") }
            file.writeText("{\"version\":999}")
            assertEquals("KeyInvalidated", assertThrows(SentomaruException::class.java) { client.state() }.error.code)
            client.reset()
            assertEquals(InstallationState.NotEnrolled, client.state())
            assertFalse(keys.exists(alias))
            assertTrue("reset preserves unrelated key", KeystoreSigner.containsAlias(unrelated))
            client.enroll(challenge()) { grant() }
            assertEquals(InstallationState.Enrolled, client.state())
        } finally {
            // Test-owned cleanup must run even against broken reset implementation.
            alias?.let { keys.delete(it) }
            KeystoreSigner.deleteKey(unrelated)
            store.write(null)
            client.reset()
        }
    }

    @Test fun rotationKeepsOldKeyInKeystoreForCoexistenceAndSwitchesActiveSigning() {
        val store = AndroidInstallationStore(context, config)
        val keys = AndroidInstallationKeys()
        val client = SentomaruClient(config, keys, store, clock)
        client.reset()
        var oldAlias: String? = null
        var newAlias: String? = null
        try {
            client.enroll(challenge()) { grant() }
            oldAlias = store.read()!!.alias
            val rotateId = "22222222-3333-4444-8555-666666666666"
            val rotateChallenge = EnrollmentChallenge(rotateId, Base64.getEncoder().encodeToString(ByteArray(32) { 31 }),
                ByteArray(32) { 32 }, now.plusSeconds(120))
            client.rotate(rotateChallenge) { EnrollmentGrant(session, rotateId, session, "unknown", "notEvaluated") }
            newAlias = store.read()!!.alias
            assertNotEquals(oldAlias, newAlias)
            assertTrue("old key remains in Android Keystore for coexistence", keys.exists(oldAlias))
            assertTrue("new key exists in Android Keystore", keys.exists(newAlias))
            assertEquals(1, client.retiredKeys().size)
            assertEquals(oldAlias, client.retiredKeys().first().alias)
            val headers = linkedMapOf("content-type" to "application/json", "x-sentomaru-profile" to "sentomaru-p0",
                "x-sentomaru-org" to "lab", "x-sentomaru-app" to "enrollment", "x-sentomaru-environment" to "test",
                "x-sentomaru-session" to session, "x-sentomaru-operation" to "submit")
            val req = FrozenRequest("POST", "https://consumer.example/submit",
                headers, "{}".toByteArray())
            val signed = client.signRequest(req)
            val material = keys.material(newAlias)
            val certificate = CertificateFactory.getInstance("X.509")
                .generateCertificate(ByteArrayInputStream(material.chain()[0]))
            val signature = Base64.getDecoder().decode(signed.header("signature")!!.removePrefix("sig1=:").removeSuffix(":"))
            assertTrue(Signature.getInstance("SHA256withECDSA").run {
                initVerify(certificate.publicKey); update(signed.signatureBase())
                verify(EcdsaSignatureFormat.p1363ToDer(signature))
            })
            client.reset()
            assertFalse(keys.exists(oldAlias))
            assertFalse(keys.exists(newAlias))
        } finally {
            oldAlias?.let { keys.delete(it) }
            newAlias?.let { keys.delete(it) }
            client.reset()
        }
    }
}
