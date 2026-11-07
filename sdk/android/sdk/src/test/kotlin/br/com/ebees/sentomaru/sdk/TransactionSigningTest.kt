package br.com.ebees.sentomaru.sdk

import br.com.ebees.sentomaru.core.*
import br.com.ebees.sentomaru.signer.EcdsaSignatureFormat
import br.com.ebees.sentomaru.signer.TransactionKeyInvalidatedException
import java.security.KeyPair
import java.security.KeyPairGenerator
import java.security.Signature
import java.security.SecureRandom
import java.security.spec.ECGenParameterSpec
import java.time.Clock
import java.time.Instant
import java.time.ZoneOffset
import java.util.Base64
import java.util.UUID
import org.junit.Assert.*
import org.junit.Test

private fun pair(): KeyPair = KeyPairGenerator.getInstance("EC").apply { initialize(ECGenParameterSpec("secp256r1")) }.generateKeyPair()

/**
 * D-25 slice (c): the transaction signature against JDK keys (the Keystore and the system prompt are doubles). Checks
 * the signed bytes, the header grammar, the recoverable cancel (nothing spent, installation untouched) and the errors.
 */
class TransactionSigningTest {
    private val now = Instant.parse("2026-11-04T12:00:00Z")
    private val clock = Clock.fixed(now, ZoneOffset.UTC)
    private val config = SentomaruConfig("org", "app", "hml", setOf("consumer.example"), "https://consumer.example/enroll")
    private val opId = "0123456789abcdef-op"
    private val body = "{\"amount\":10}".toByteArray()

    private class MemoryState : InstallationStore {
        var value: InstallationRecord? = null
        var writes = 0
        override fun read() = value
        override fun write(record: InstallationRecord?) { value = record; writes++ }
    }
    private class JcaKeys : InstallationKeys {
        val keys = mutableMapOf<String, KeyPair>()
        override fun exists(alias: String) = keys.containsKey(alias)
        override fun generate(alias: String, challenge: ByteArray, strongBox: Boolean): KeyMaterial {
            keys[alias] = pair(); return material(alias)
        }
        override fun material(alias: String) = KeyMaterial(keys.getValue(alias).public.encoded, emptyList())
        override fun sign(alias: String, bytes: ByteArray) = Signature.getInstance("SHA256withECDSAinP1363Format")
            .run { initSign(keys.getValue(alias).private); update(bytes); sign() }
        override fun delete(alias: String) { keys.remove(alias) }
        override fun deleteOwned(prefix: String) { keys.keys.filter { it.startsWith(prefix) }.forEach { keys.remove(it) } }
    }
    private class TxKeys : TransactionKeys {
        val keys = mutableMapOf<String, KeyPair>()
        var invalidated = false
        var lastAuth: Boolean? = null
        var failNextGenerate = false
        private val born = mutableMapOf<String, Long>()
        private var clockTicks = 0L
        override fun createdAt(alias: String) = born.getValue(alias)
        override fun exists(alias: String) = keys.containsKey(alias)
        override fun generate(alias: String, challenge: ByteArray, strongBox: Boolean, strongBiometricOnly: Boolean): KeyMaterial {
            lastAuth = strongBiometricOnly
            if (failNextGenerate) { failNextGenerate = false; throw IllegalStateException("keystore") }
            keys[alias] = pair(); born[alias] = ++clockTicks
            return KeyMaterial(keys.getValue(alias).public.encoded, listOf(byteArrayOf(1, 2, 3), byteArrayOf(4, 5)))
        }
        override fun initSign(alias: String): Signature {
            if (invalidated) throw TransactionKeyInvalidatedException()
            return Signature.getInstance("SHA256withECDSA").apply { initSign(keys.getValue(alias).private) }
        }
        override fun delete(alias: String) { keys.remove(alias); born.remove(alias) }
    }
    private class Prompt(val outcome: TransactionError? = null) : TransactionAuthenticator {
        var shown = 0
        override fun authenticate(signature: Signature, onAuthenticated: (Signature) -> Unit, onError: (TransactionError) -> Unit) {
            shown++
            if (outcome == null) onAuthenticated(signature) else onError(outcome)
        }
    }

    private val installationKeys = JcaKeys()
    private val state = MemoryState()
    private val txKeys = TxKeys()
    private fun client() = SentomaruClient(config, installationKeys, state, clock)
    private fun challenge() = EnrollmentChallenge(UUID.randomUUID().toString(), Base64.getEncoder().encodeToString(ByteArray(32) { 1 }),
        ByteArray(32) { 8 }, now.plusSeconds(120))
    private fun enrolledClient(): SentomaruClient = client().also { c ->
        c.enroll(challenge()) { m -> EnrollmentGrant(UUID.randomUUID().toString(), m.header("x-sentomaru-session")!!, UUID.randomUUID().toString(), "hardware", "verified") }
    }
    private val issuedAt = 1_793_000_000L // 2026-10-26, fixed so the signed bytes are checkable
    private fun signer(c: SentomaruClient = enrolledClient(), version: TransactionSignatureVersion = TransactionSignatureVersion.V2) =
        SentomaruTransactionSigner(c, txKeys, SecureRandom(), version, { issuedAt }, { false })

    private fun signed(s: SentomaruTransactionSigner, prompt: TransactionAuthenticator): Pair<String?, TransactionError?> {
        var value: String? = null; var error: TransactionError? = null
        s.sign(opId, body, prompt, { value = it }, { error = it })
        return value to error
    }

    @Test fun theV1HeaderVerifiesWithThePublicKeyOverTheSpecifiedBytes() {
        val s = signer(version = TransactionSignatureVersion.V1); s.prepareEnrollment(challenge())
        val (value, error) = signed(s, Prompt())
        assertNull(error)
        val parts = value!!.split('.')
        assertEquals(listOf("sentomaru-tx-v1"), parts.take(1))
        assertEquals(3, parts.size)
        val dec = Base64.getUrlDecoder()
        val nonce = dec.decode(parts[1]); val sig = dec.decode(parts[2])
        assertEquals(16, nonce.size); assertEquals(64, sig.size)
        val alias = txKeys.keys.keys.single()
        val v = Signature.getInstance("SHA256withECDSA").apply { initVerify(txKeys.keys.getValue(alias).public) }
        v.update(TransactionSignature.message(nonce, opId, body))
        assertTrue(v.verify(EcdsaSignatureFormat.p1363ToDer(sig)))
        assertTrue(alias.endsWith(".tx"))
    }

    @Test fun theV2HeaderCarriesTheClockAndVerifiesOverTheV2Bytes() {
        val s = signer(); s.prepareEnrollment(challenge())
        val (value, error) = signed(s, Prompt())
        assertNull(error)
        val parts = value!!.split('.')
        assertEquals(listOf("sentomaru-tx-v2"), parts.take(1))
        assertEquals(4, parts.size)
        assertEquals(issuedAt.toString(), parts[2])
        val dec = Base64.getUrlDecoder()
        val nonce = dec.decode(parts[1]); val sig = dec.decode(parts[3])
        assertEquals(16, nonce.size); assertEquals(64, sig.size)
        val key = txKeys.keys.getValue(txKeys.keys.keys.single()).public
        fun ok(bytes: ByteArray) = Signature.getInstance("SHA256withECDSA").apply { initVerify(key); update(bytes) }
            .verify(EcdsaSignatureFormat.p1363ToDer(sig))
        assertTrue(ok(TransactionSignature.message(nonce, issuedAt, opId, body)))
        // The v1 bytes do not verify: a v2 signature cannot be replayed as v1, nor with another time.
        assertFalse(ok(TransactionSignature.message(nonce, opId, body)))
        assertFalse(ok(TransactionSignature.message(nonce, issuedAt + 1, opId, body)))
    }

    // G-16: the version is NOT passed here, so this exercises the constructor default an app gets from `SentomaruTransactionSigner(client)`.
    @Test fun aSignerBuiltWithTheDefaultVersionEmitsV2() {
        val s = SentomaruTransactionSigner(enrolledClient(), txKeys, SecureRandom(), nowSeconds = { issuedAt }, onMainThread = { false })
        s.prepareEnrollment(challenge())
        val (value, error) = signed(s, Prompt())
        assertNull(error)
        val parts = value!!.split('.')
        assertEquals("sentomaru-tx-v2", parts[0])
        assertEquals(4, parts.size)
        assertEquals(issuedAt.toString(), parts[2])
    }

    @Test fun aClockBeforeTheV2RangeIsRefusedAndNothingIsSigned() {
        val c = enrolledClient()
        val s = SentomaruTransactionSigner(c, txKeys, SecureRandom(), TransactionSignatureVersion.V2, { 0L }, { false })
        s.prepareEnrollment(challenge())
        val (value, error) = signed(s, Prompt())
        assertNull(value)
        assertTrue(error is TransactionError.SigningFailed)
    }

    // Review B (RC-10): the shared vector is READ from the Sentomaru transaction keys contract (the server test and the Python gate read the same
    // file), never copied as a literal: a change of the file or of the code breaks this test.
    private val v2Vector: String = listOf("contracts/api/transaction-keys-v2-vector.json", "../../../contracts/api/transaction-keys-v2-vector.json",
        "../../contracts/api/transaction-keys-v2-vector.json").map { java.io.File(it) }.first { it.isFile }.readText()

    private fun v2Text(name: String): String = Regex("\"$name\"\\s*:\\s*\"((?:[^\"\\\\]|\\\\.)*)\"").find(v2Vector)!!.groupValues[1]
        .replace("\\n", "\n").replace("\\\"", "\"")

    @Test fun theV2MessageEqualsTheVectorTheServerTestChecks() {
        val issuedAt = Regex("\"issuedAt\"\\s*:\\s*(\\d+)").find(v2Vector)!!.groupValues[1].toLong()
        val nonce = Base64.getUrlDecoder().decode(v2Text("nonceBase64Url"))
        val message = TransactionSignature.message(nonce, issuedAt, v2Text("operationId"), v2Text("bodyUtf8").toByteArray())
        assertEquals(v2Text("signedBytes"), String(message))
        // The vector's signature (made by a key outside the SDK) verifies over the bytes the SDK builds, and not over other bytes.
        val key = java.security.KeyFactory.getInstance("EC").generatePublic(
            java.security.spec.X509EncodedKeySpec(Base64.getDecoder().decode(v2Text("publicKeySpkiBase64"))))
        val der = EcdsaSignatureFormat.p1363ToDer(Base64.getUrlDecoder().decode(v2Text("signatureP1363Base64Url")))
        fun verifies(bytes: ByteArray) = Signature.getInstance("SHA256withECDSA").run { initVerify(key); update(bytes); verify(der) }
        assertTrue(verifies(message))
        assertFalse(verifies(TransactionSignature.message(nonce, issuedAt + 1, v2Text("operationId"), v2Text("bodyUtf8").toByteArray())))
        val parts = v2Text("header").split('.')
        assertEquals(listOf("sentomaru-tx-v2", v2Text("nonceBase64Url"), issuedAt.toString(), v2Text("signatureP1363Base64Url")), parts)
    }

    @Test fun theMessageEqualsTheVectorTheServerTestChecks() {
        // The same literal is in the server's TransactionSignature.Message.
        assertEquals("sentomaru-tx-v1\nAQEBAQEBAQEBAQEBAQEBAQ\n0123456789abcdef-op\nqLiLgv6QoWBI64hR_jgkBTlc05Xa-qfKm-kOwA-Cpys",
            String(TransactionSignature.message(ByteArray(16) { 1 }, "0123456789abcdef-op", "{\"amount\":10}".toByteArray())))
    }

    @Test fun theMessageBindsOperationBodyAndNonce() {
        val n = ByteArray(16) { 1 }
        val base = String(TransactionSignature.message(n, opId, body))
        assertEquals(4, base.split('\n').size)
        assertTrue(base.startsWith("sentomaru-tx-v1\n"))
        assertNotEquals(base, String(TransactionSignature.message(n, "other-operation-id0", body)))
        assertNotEquals(base, String(TransactionSignature.message(n, opId, "x".toByteArray())))
        assertNotEquals(base, String(TransactionSignature.message(ByteArray(16) { 2 }, opId, body)))
        assertThrows(IllegalArgumentException::class.java) { TransactionSignature.message(ByteArray(15), opId, body) }
        assertThrows(IllegalArgumentException::class.java) { TransactionSignature.message(n, "bad\nid-bad-id-bad-id", body) }
    }

    @Test fun everyHeaderHasTheProfileGrammarAndNoncesDiffer() {
        val s = signer(); s.prepareEnrollment(challenge())
        val a = signed(s, Prompt()).first!!; val b = signed(s, Prompt()).first!!
        assertNotEquals(a, b)
        val rule = Regex("""\Asentomaru-tx-v2\.[A-Za-z0-9_-]{22}\.[0-9]{10}\.[A-Za-z0-9_-]{86}\z""") // the core rule, MessageRules
        for (h in listOf(a, b)) assertTrue(rule.matches(h))
    }

    @Test fun cancelIsRecoverableAndLeavesTheInstallationAlone() {
        val c = enrolledClient(); val s = signer(c); s.prepareEnrollment(challenge())
        val writes = state.writes; val record = state.value; val keysBefore = installationKeys.keys.keys.toSet()
        for (cancel in listOf(BiometricErrors.map(10), BiometricErrors.map(13))) {
            val (value, error) = signed(s, Prompt(cancel))
            assertNull(value)
            assertEquals("TxCancelled", error!!.code); assertTrue(error.recoverable)
        }
        assertEquals(writes, state.writes); assertSame(record, state.value)
        assertEquals(keysBefore, installationKeys.keys.keys.toSet())
        assertEquals(InstallationState.Enrolled::class, c.state()::class)
        assertNotNull(signed(s, Prompt()).first) // the same call works after the cancel
    }

    @Test fun errorCodesMapToStableErrors() {
        assertEquals("TxLockedOut", BiometricErrors.map(7).code); assertTrue(BiometricErrors.map(7).recoverable)
        assertFalse(BiometricErrors.map(9).recoverable)
        for (c in listOf(11, 12, 14)) assertEquals("TxNoUserAuthentication", BiometricErrors.map(c).code)
        val other = BiometricErrors.map(3)
        assertEquals("TxUnavailable", other.code); assertTrue(other.recoverable)
        assertEquals("TxUnavailable", BiometricErrors.map(999).code)
    }

    @Test fun withoutAKeyOrWithAnInvalidatedKeyThereIsNoSignatureAndNoPrompt() {
        val s = signer(); val prompt = Prompt()
        assertEquals("TxNotEnrolled", signed(s, prompt).second!!.code)
        assertFalse(s.isEnrolled())
        s.prepareEnrollment(challenge()); assertTrue(s.isEnrolled())
        txKeys.invalidated = true
        val (value, error) = signed(s, prompt)
        assertNull(value); assertEquals("TxKeyInvalidated", error!!.code); assertFalse(error.recoverable)
        assertEquals(0, prompt.shown)
        val bare = SentomaruTransactionSigner(SentomaruClient(config, JcaKeys(), MemoryState(), clock), txKeys) // no installation at all
        assertEquals("TxNotEnrolled", signed(bare, prompt).second!!.code)
    }

    @Test fun enrollmentBodyCarriesKeyChainAndTheAuthenticationClassOnly() {
        val s = signer()
        val text = String(s.prepareEnrollment(challenge()), Charsets.UTF_8)
        assertTrue(text, Regex("""\A\{"challenge":"[A-Za-z0-9+/=]+","publicKey":"[A-Za-z0-9+/=]+","attestationChain":\["[A-Za-z0-9+/=]+","[A-Za-z0-9+/=]+"],"userAuthentication":"biometric-strong"}\z""").matches(text))
        assertTrue(String(s.prepareEnrollment(challenge(), strongBiometricOnly = false)).contains("\"biometric-or-credential\""))
        assertEquals(false, txKeys.lastAuth)
        s.discard(); assertFalse(s.isEnrolled())
    }

    @Test fun enrollmentNeedsAnEnrolledInstallation() {
        val e = assertThrows(SentomaruException::class.java) { SentomaruTransactionSigner(client(), txKeys).prepareEnrollment(challenge()) }
        assertEquals("EnrollmentRequired", e.error.code)
    }

    private val challengeJson = "{\"challengeId\":\"${UUID.randomUUID()}\",\"token\":\"${Base64.getEncoder().encodeToString(ByteArray(32) { 3 })}\"," +
        "\"attestationChallenge\":\"${Base64.getEncoder().encodeToString(ByteArray(32) { 8 })}\",\"expiresAt\":\"2026-11-04T12:02:00Z\"}"
    private val urls = "https://consumer.example/tx/challenges" to "https://consumer.example/tx"

    @Test fun enrollRunsChallengeThenKeyThenSubmit() {
        val s = signer(); val sent = mutableListOf<SignedMessage>()
        val out = s.enroll(urls.first, urls.second) { m ->
            sent += m
            if (sent.size == 1) TransactionAnswer(201, challengeJson)
            else TransactionAnswer(201, "{\"txKeyId\":\"11111111-1111-1111-1111-111111111111\",\"userAuthentication\":\"biometric-strong\",\"attestationStatus\":\"hardware\"}")
        }
        assertTrue(out is TransactionEnrollOutcome.Enrolled)
        assertEquals(listOf("tx_key_challenge", "tx_key_enroll"), sent.map { it.header("x-sentomaru-operation") })
        assertTrue(String(sent[1].body()).contains("\"userAuthentication\":\"biometric-strong\""))
        assertTrue(s.isEnrolled())
    }

    @Test fun aRefusedEnrollmentRemovesTheNewKey() {
        val s = signer(); var n = 0
        val out = s.enroll(urls.first, urls.second) {
            if (++n == 1) TransactionAnswer(201, challengeJson) else TransactionAnswer(422, "{\"code\":\"user-auth-not-proven\"}")
        }
        assertEquals("user-auth-not-proven", (out as TransactionEnrollOutcome.Refused).code)
        assertEquals(422, out.status); assertFalse(s.isEnrolled())
    }

    // Shield #12: a 429 or 5xx hands the app the server's Retry-After (bounded), never a tight loop and never a parked app.
    @Test fun aRateLimitedEnrollmentCarriesTheBoundedRetryAfter() {
        val s = signer()
        for ((sent, expected) in listOf<Pair<Long?, Long?>>(30L to 30L, 0L to 1L, 999_999L to 86_400L, 86_400L to 86_400L, -1L to null, null to null)) {
            val out = s.enroll(urls.first, urls.second) { TransactionAnswer(429, "", sent) }
            assertTrue(out is TransactionEnrollOutcome.Unavailable)
            assertEquals("Retry-After $sent", expected, (out as TransactionEnrollOutcome.Unavailable).retryAfterSeconds)
        }
        val server = s.enroll(urls.first, urls.second) { TransactionAnswer(503, "", 12L) } as TransactionEnrollOutcome.Unavailable
        assertEquals(12L, server.retryAfterSeconds)
        assertNull(TransactionAnswer(429, "", -1L).retryAfterSeconds)   // RC-07: a negative value never throws
    }

    @Test fun networkAndServerFailuresAreUnavailableAndKeepNothing() {
        val s = signer()
        assertTrue(s.enroll(urls.first, urls.second) { throw java.io.IOException("down") } is TransactionEnrollOutcome.Unavailable)
        assertTrue(s.enroll(urls.first, urls.second) { TransactionAnswer(503, "") } is TransactionEnrollOutcome.Unavailable)
        var n = 0
        assertTrue(s.enroll(urls.first, urls.second) { if (++n == 1) TransactionAnswer(201, challengeJson) else throw java.io.IOException() }
            is TransactionEnrollOutcome.Unavailable)
        assertFalse(s.isEnrolled())
        val bad = s.enroll(urls.first, urls.second) { TransactionAnswer(201, "{}") }
        assertEquals("unexpected-response", (bad as TransactionEnrollOutcome.Refused).code)
    }

    @Test fun enrollRefusesForeignHostsAndTheMainThread() {
        val c = enrolledClient(); val s = signer(c)
        assertThrows(SentomaruException::class.java) { s.enroll("https://evil.example/c", urls.second) { TransactionAnswer(200, "") } }
        val onMain = SentomaruTransactionSigner(c, txKeys, SecureRandom()) { true }
        assertThrows(IllegalStateException::class.java) { onMain.enroll(urls.first, urls.second) { TransactionAnswer(200, "") } }
    }

    // D-25 / revisao cruzada Shield #5: a new key never replaces the one the server holds before the server accepted it.

    private fun enrollWith(s: SentomaruTransactionSigner, second: () -> TransactionAnswer): TransactionEnrollOutcome {
        var n = 0
        return s.enroll(urls.first, urls.second) { if (++n == 1) TransactionAnswer(201, challengeJson) else second() }
    }
    private val accepted = "{\"txKeyId\":\"11111111-1111-1111-1111-111111111111\",\"userAuthentication\":\"biometric-strong\"}"

    private fun verifies(header: String, key: KeyPair): Boolean {
        val parts = header.split('.'); val dec = Base64.getUrlDecoder()
        val v = Signature.getInstance("SHA256withECDSA").apply { initVerify(key.public) }
        if (parts.size == 4) v.update(TransactionSignature.message(dec.decode(parts[1]), parts[2].toLong(), opId, body))
        else v.update(TransactionSignature.message(dec.decode(parts[1]), opId, body))
        return v.verify(EcdsaSignatureFormat.p1363ToDer(dec.decode(parts.last())))
    }

    @Test fun aRefusedReenrollmentKeepsTheKeyTheServerHolds() {
        val s = signer(); s.prepareEnrollment(challenge())
        val before = txKeys.keys.entries.single().let { it.key to it.value }
        val out = enrollWith(s) { TransactionAnswer(422, "{\"code\":\"user-auth-not-proven\"}") }
        assertTrue(out is TransactionEnrollOutcome.Refused)
        assertTrue(s.isEnrolled())
        assertEquals(setOf(before.first), txKeys.keys.keys)
        val (value, error) = signed(s, Prompt())
        assertNull(error); assertTrue(verifies(value!!, before.second))
    }

    @Test fun aNetworkFailureDuringReenrollmentKeepsTheOldKey() {
        val s = signer(); s.prepareEnrollment(challenge())
        val old = txKeys.keys.values.single()
        assertTrue(enrollWith(s) { throw java.io.IOException("down") } is TransactionEnrollOutcome.Unavailable)
        assertTrue(enrollWith(s) { TransactionAnswer(503, "") } is TransactionEnrollOutcome.Unavailable)
        assertTrue(enrollWith(s) { TransactionAnswer(201, "{}") } is TransactionEnrollOutcome.Refused)
        assertEquals(1, txKeys.keys.size)
        assertTrue(verifies(signed(s, Prompt()).first!!, old))
    }

    @Test fun anAcceptedReenrollmentReplacesTheKeyOnlyAfterTheAnswer() {
        val s = signer(); s.prepareEnrollment(challenge())
        val old = txKeys.keys.values.single()
        var duringSubmit = 0
        val out = enrollWith(s) { duringSubmit = txKeys.keys.size; TransactionAnswer(201, accepted) }
        assertTrue(out is TransactionEnrollOutcome.Enrolled)
        assertEquals("both keys exist while the server decides", 2, duringSubmit)
        assertEquals(1, txKeys.keys.size)
        val fresh = txKeys.keys.values.single()
        assertNotEquals(old.public, fresh.public)
        assertTrue(verifies(signed(s, Prompt()).first!!, fresh))
        // and the next re-enrollment can use the freed slot
        assertTrue(enrollWith(s) { TransactionAnswer(201, accepted) } is TransactionEnrollOutcome.Enrolled)
        assertEquals(1, txKeys.keys.size)
    }

    @Test fun whileTheNewKeyIsPendingTheOlderOneStillSigns() {
        val s = signer(); s.prepareEnrollment(challenge())
        val old = txKeys.keys.values.single()
        s.prepareEnrollment(challenge())          // pending: not committed (for example the process died here)
        assertEquals(2, txKeys.keys.size)
        assertTrue(verifies(signed(s, Prompt()).first!!, old))
        s.abortEnrollment()
        assertEquals(setOf(old.public), txKeys.keys.values.map { it.public }.toSet())
    }

    @Test fun commitDropsTheOlderOfTwoAndDiscardDropsBoth() {
        val s = signer(); s.prepareEnrollment(challenge())
        s.prepareEnrollment(challenge()); val fresh = txKeys.keys.values.maxBy { txKeys.createdAt(txKeys.keys.entries.first { e -> e.value === it }.key) }
        s.commitEnrollment()
        assertEquals(1, txKeys.keys.size); assertSame(fresh, txKeys.keys.values.single())
        s.prepareEnrollment(challenge()); assertEquals(2, txKeys.keys.size)
        s.discard(); assertTrue(txKeys.keys.isEmpty()); assertFalse(s.isEnrolled())
    }

    @Test fun aFailedGenerationLeavesTheLiveKeyAlone() {
        val s = signer(); s.prepareEnrollment(challenge())
        val old = txKeys.keys.values.single()
        txKeys.failNextGenerate = true
        assertThrows(IllegalStateException::class.java) { s.prepareEnrollment(challenge()) }
        assertEquals(1, txKeys.keys.size)
        assertTrue(verifies(signed(s, Prompt()).first!!, old))
    }
}
