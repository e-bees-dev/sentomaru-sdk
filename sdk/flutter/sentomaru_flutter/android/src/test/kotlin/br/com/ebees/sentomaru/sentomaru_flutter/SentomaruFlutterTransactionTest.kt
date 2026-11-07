package br.com.ebees.sentomaru.sentomaru_flutter

import br.com.ebees.sentomaru.core.SentomaruException
import br.com.ebees.sentomaru.sdk.EnrollmentError
import io.flutter.plugin.common.MethodCall
import io.flutter.plugin.common.MethodChannel.Result
import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test
import java.util.concurrent.CountDownLatch
import java.util.concurrent.TimeUnit

/**
 * D-25 (Android): the channel side of `SentomaruTransactionSigner` in Dart. Failure classes: a call before `initialize`, a
 * malformed argument reaching the SDK, an SDK error under a code Dart does not map, a signature reported when the prompt
 * failed, work on the caller's thread, and a missing flag silently turning the strong-biometric default off. The prompt
 * itself, the Keystore and the signature are the SDK's and the device's, not tested here.
 */
class SentomaruFlutterTransactionTest {
    private class Recorder : Result {
        val done = CountDownLatch(1)
        @Volatile var value: Any? = null
        @Volatile var error: String? = null
        @Volatile var replies = 0
        override fun success(result: Any?) { value = result; replies++; done.countDown() }
        override fun error(errorCode: String, errorMessage: String?, errorDetails: Any?) { error = errorCode; replies++; done.countDown() }
        override fun notImplemented() { error = "notImplemented"; replies++; done.countDown() }
        fun await() = assertTrue("no reply", done.await(5, TimeUnit.SECONDS))
    }

    private class FakePort(var enrolled: Boolean = true, var failure: Throwable? = null) : SentomaruFlutterTransaction.Port {
        @Volatile var thread: Thread? = null
        var challenge: SentomaruFlutterTransaction.Challenge? = null
        var biometricOnly: Boolean? = null
        var strongBox: Boolean? = null
        var signed: List<Any?>? = null
        var signOutcome: (((String) -> Unit, (String) -> Unit) -> Unit) = { ok, _ -> ok("sentomaru-tx-v1.n.s") }
        var discarded = false
        val lifecycle = mutableListOf<String>()
        override fun commitKey() { thread = Thread.currentThread(); failure?.let { throw it }; lifecycle += "commit" }
        override fun abortKey() { thread = Thread.currentThread(); lifecycle += "abort" }
        override fun isEnrolled(): Boolean { thread = Thread.currentThread(); failure?.let { throw it }; return enrolled }
        override fun discard() { thread = Thread.currentThread(); discarded = true }
        override fun createKey(challenge: SentomaruFlutterTransaction.Challenge, biometricOnly: Boolean, strongBox: Boolean): ByteArray {
            thread = Thread.currentThread(); failure?.let { throw it }
            this.challenge = challenge; this.biometricOnly = biometricOnly; this.strongBox = strongBox
            return "{}".toByteArray()
        }
        override fun sign(operationId: String, body: ByteArray, reason: String, cancelLabel: String, biometricOnly: Boolean,
                          onSigned: (String) -> Unit, onError: (String) -> Unit) {
            thread = Thread.currentThread()
            signed = listOf(operationId, body, reason, cancelLabel, biometricOnly)
            signOutcome(onSigned, onError)
        }
    }

    private val challengeMap = mapOf(
        "challengeId" to "11111111-1111-4111-8111-111111111111", "token" to "dG9rZW4=",
        "attestationChallenge" to ByteArray(32) { 7 }, "expiresAt" to "2026-11-04T10:05:00+00:00",
    )

    private fun run(port: SentomaruFlutterTransaction.Port?, method: String, args: Map<String, Any?>?): Recorder {
        val plugin = SentomaruFlutterTransaction({ port }, { it.run() })
        val r = Recorder()
        plugin.onMethodCall(MethodCall(method, args), r)
        r.await()
        plugin.shutdown()
        return r
    }

    @Test
    fun handlesExactlyTheSixMethods() {
        val plugin = SentomaruFlutterTransaction({ null }, { it.run() })
        for (m in listOf("txKeyCreate", "txSign", "txIsEnrolled", "txDiscard", "txKeyCommit", "txKeyAbort")) assertTrue(m, plugin.handles(m))
        for (m in listOf("sign", "offlineSeal", "txSignX", "")) assertFalse(m, plugin.handles(m))
        plugin.shutdown()
    }

    @Test
    fun beforeInitializeEveryMethodIsNotInitialized() {
        for (m in listOf("txKeyCreate", "txSign", "txIsEnrolled", "txDiscard", "txKeyCommit", "txKeyAbort")) {
            assertEquals(m, "NotInitialized", run(null, m, mapOf("operationId" to "x", "body" to ByteArray(0), "challenge" to challengeMap)).error)
        }
    }

    @Test
    fun isEnrolledAndDiscardRunOffTheCallerThread() {
        val port = FakePort(enrolled = false)
        assertEquals(false, run(port, "txIsEnrolled", null).value)
        assertNotNull(port.thread); assertTrue(port.thread !== Thread.currentThread())
        val r = run(port, "txDiscard", null)
        assertNull(r.error); assertNull(r.value); assertTrue(port.discarded)
    }

    @Test
    fun commitAndAbortReachThePortAndReplyWithNothing() {
        val port = FakePort()
        for (m in listOf("txKeyCommit", "txKeyAbort")) { val r = run(port, m, null); assertNull(r.error); assertNull(r.value) }
        assertEquals(listOf("commit", "abort"), port.lifecycle)
        assertEquals("Transaction:NOT_ENROLLED", run(FakePort(failure = SentomaruException(EnrollmentError.EnrollmentRequired())), "txKeyCommit", null).error)
    }

    @Test
    fun keyCreateDefaultsToStrongBiometricAndNoStrongBox() {
        val port = FakePort()
        val r = run(port, "txKeyCreate", mapOf("challenge" to challengeMap))
        assertArrayEquals("{}".toByteArray(), r.value as ByteArray)
        assertEquals(true, port.biometricOnly)
        assertEquals(false, port.strongBox)
        assertEquals("dG9rZW4=", port.challenge!!.token)
        assertEquals(32, port.challenge!!.attestationChallenge.size)
    }

    @Test
    fun keyCreateHonoursExplicitFlagsAndRefusesNonBooleans() {
        val port = FakePort()
        run(port, "txKeyCreate", mapOf("challenge" to challengeMap, "biometricOnly" to false, "strongBox" to true))
        assertEquals(false, port.biometricOnly); assertEquals(true, port.strongBox)
        val bad = FakePort()
        assertEquals("InvalidRequest:PARAMS", run(bad, "txKeyCreate", mapOf("challenge" to challengeMap, "biometricOnly" to "false")).error)
        assertEquals("InvalidRequest:PARAMS", run(bad, "txKeyCreate", mapOf("challenge" to challengeMap, "strongBox" to 1)).error)
        assertNull(bad.challenge)
    }

    @Test
    fun keyCreateNeedsACompleteChallenge() {
        val port = FakePort()
        assertEquals("InvalidRequest:PARAMS", run(port, "txKeyCreate", null).error)
        assertEquals("InvalidRequest:PARAMS", run(port, "txKeyCreate", mapOf("biometricOnly" to true)).error)
        for (missing in challengeMap.keys) {
            val partial = challengeMap - missing
            assertEquals(missing, "InvalidRequest:PARAMS", run(port, "txKeyCreate", mapOf("challenge" to partial)).error)
        }
        assertEquals("InvalidRequest:PARAMS", run(port, "txKeyCreate", mapOf("challenge" to challengeMap + ("token" to 5))).error)
        assertNull(port.challenge)
    }

    @Test
    fun signPassesTheArgumentsAndReturnsTheHeaderValue() {
        val port = FakePort()
        val body = byteArrayOf(1, 2, 3)
        val r = run(port, "txSign", mapOf("operationId" to "op-0123456789abcdef", "body" to body, "reason" to "Pagar", "cancelLabel" to "Voltar", "biometricOnly" to false))
        assertEquals("sentomaru-tx-v1.n.s", r.value)
        assertEquals(listOf("op-0123456789abcdef", body, "Pagar", "Voltar", false), port.signed)
    }

    @Test
    fun signDefaultsAreStrongBiometricAndFixedTexts() {
        val port = FakePort()
        run(port, "txSign", mapOf("operationId" to "op", "body" to ByteArray(0)))
        val s = port.signed!!
        assertEquals(true, s[4]); assertEquals("Confirmar a operação", s[2]); assertEquals("Cancelar", s[3])
    }

    @Test
    fun signRefusesMissingOrWrongTypedArgumentsBeforeTheSdk() {
        val port = FakePort()
        for (args in listOf(null, mapOf("body" to ByteArray(0)), mapOf("operationId" to "op"),
            mapOf("operationId" to "op", "body" to "text"), mapOf("operationId" to 5, "body" to ByteArray(0)),
            mapOf("operationId" to "op", "body" to ByteArray(0), "biometricOnly" to "yes"))) {
            assertEquals(args.toString(), "InvalidRequest:PARAMS", run(port, "txSign", args).error)
        }
        assertNull(port.signed)
    }

    @Test
    fun everyPromptFailureIsItsTypedErrorAndNeverASignature() {
        val codes = mapOf(
            "TxNotEnrolled" to "Transaction:NOT_ENROLLED", "TxKeyInvalidated" to "Transaction:KEY_INVALIDATED",
            "TxCancelled" to "Transaction:CANCELLED", "TxLockedOut" to "Transaction:LOCKED_OUT",
            "TxNoUserAuthentication" to "Transaction:NO_USER_AUTHENTICATION", "TxUnavailable" to "Transaction:UNAVAILABLE",
            "TxSigningFailed" to "Transaction:SIGNING_FAILED",
        )
        for ((sdk, channel) in codes) {
            assertEquals(channel, SentomaruFlutterTransaction.transactionCode(sdk))
            val port = FakePort().apply { signOutcome = { _, err -> err(SentomaruFlutterTransaction.transactionCode(sdk)) } }
            val r = run(port, "txSign", mapOf("operationId" to "op", "body" to ByteArray(0)))
            assertEquals(channel, r.error); assertNull(r.value)
        }
    }

    @Test
    fun anErrorFromTheSdkReachesDartUnderADartCode() {
        for ((sdk, channel) in mapOf(
            "EnrollmentRequired" to "Transaction:NOT_ENROLLED", "NotEnrolled" to "Transaction:NOT_ENROLLED",
            "KeyInvalidated" to "Transaction:KEY_INVALIDATED", "StrongBoxUnavailable" to "Transaction:UNAVAILABLE",
            "KeyUnavailable" to "Transaction:UNAVAILABLE",
        )) assertEquals(sdk, channel, SentomaruFlutterTransaction.code(sdk))
        val port = FakePort(failure = SentomaruException(EnrollmentError.StrongBoxUnavailable()))
        assertEquals("Transaction:UNAVAILABLE", run(port, "txKeyCreate", mapOf("challenge" to challengeMap)).error)
        assertEquals("Transaction:NOT_ENROLLED", run(FakePort(failure = SentomaruException(EnrollmentError.EnrollmentRequired())), "txIsEnrolled", null).error)
    }

    @Test
    fun anUnexpectedFailureIsAChannelErrorNotACrashAndNotASuccess() {
        val r = run(FakePort(failure = IllegalStateException("boom")), "txIsEnrolled", null)
        assertEquals("ChannelError", r.error); assertNull(r.value)
        assertEquals("InvalidRequest:PARAMS", run(FakePort(failure = IllegalArgumentException("expiresAt")), "txKeyCreate", mapOf("challenge" to challengeMap)).error)
    }

    @Test
    fun aCallAfterShutdownIsAnErrorReply() {
        val plugin = SentomaruFlutterTransaction({ FakePort() }, { it.run() })
        plugin.shutdown()
        val r = Recorder()
        plugin.onMethodCall(MethodCall("txIsEnrolled", null), r)
        r.await()
        assertEquals("ChannelError", r.error); assertEquals(1, r.replies)
    }

    @Test
    fun theReplyIsPostedOnTheMainHandler() {
        val posted = ArrayList<Runnable>()
        val plugin = SentomaruFlutterTransaction({ FakePort() }, { posted += it })
        val r = Recorder()
        plugin.onMethodCall(MethodCall("txIsEnrolled", null), r)
        val deadline = System.nanoTime() + TimeUnit.SECONDS.toNanos(5)
        while (posted.isEmpty() && System.nanoTime() < deadline) Thread.sleep(5)
        assertEquals(0, r.replies)
        posted.forEach { it.run() }
        assertEquals(1, r.replies)
        plugin.shutdown()
    }
}
