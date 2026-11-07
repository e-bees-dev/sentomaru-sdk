package br.com.ebees.sentomaru.sentomaru_flutter

import br.com.ebees.sentomaru.core.SentomaruException
import br.com.ebees.sentomaru.sdk.OfflineChainError
import io.flutter.plugin.common.MethodCall
import io.flutter.plugin.common.MethodChannel.Result
import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNotEquals
import org.junit.Assert.assertNull
import org.junit.Assert.assertThrows
import org.junit.Assert.assertTrue
import org.junit.Test
import java.util.Base64
import java.util.concurrent.CountDownLatch
import java.util.concurrent.TimeUnit

/**
 * D-26 (Android): the channel side of `SentomaruOfflineChain` in Dart. Failure classes: an SDK error reaching Dart under a
 * code Dart does not map, a malformed seal or permit reaching the SDK, a call before `initialize`, work on the caller's
 * thread, and a seal rebuilt from the map Dart sends back that differs from the one issued. The chain itself (bytes,
 * hashes, signature) is the SDK's and is tested there against the golden vectors.
 */
class SentomaruFlutterOfflineTest {
    private class Recorder : Result {
        val done = CountDownLatch(1)
        @Volatile var value: Any? = null
        @Volatile var error: String? = null
        override fun success(result: Any?) { value = result; done.countDown() }
        override fun error(errorCode: String, errorMessage: String?, errorDetails: Any?) { error = errorCode; done.countDown() }
        override fun notImplemented() { error = "notImplemented"; done.countDown() }
        fun await() = assertTrue("no reply", done.await(5, TimeUnit.SECONDS))
    }

    private val b64 = Base64.getUrlEncoder().withoutPadding()
    private fun item(seq: Int = 0) = mapOf<String, Any>(
        "seq" to seq, "bootCount" to 7, "elapsedRealtimeNanos" to 600_000_000_000L, "wallClockMillis" to 1_793_866_200_000L,
        "operationDigest" to b64.encodeToString(ByteArray(32) { 1 }), "prevHash" to b64.encodeToString(ByteArray(32) { 2 }),
        "hash" to b64.encodeToString(ByteArray(32) { 3 }), "signature" to b64.encodeToString(ByteArray(70) { 4 }),
    )

    private class FakePort(val fail: Throwable? = null) : SentomaruFlutterOffline.Port {
        @Volatile var thread: Thread? = null
        var permit: String? = null
        var seals: List<Map<*, *>>? = null
        override fun seal(permitJson: String, operationDigest: ByteArray): Map<String, Any> {
            thread = Thread.currentThread(); permit = permitJson; fail?.let { throw it }
            return mapOf("seq" to 0, "digest" to operationDigest.size)
        }
        override fun reconcileBody(permitJson: String, seals: List<Map<*, *>>): ByteArray {
            thread = Thread.currentThread(); permit = permitJson; this.seals = seals; fail?.let { throw it }
            return "{}".toByteArray()
        }
    }

    private fun run(port: SentomaruFlutterOffline.Port?, method: String, args: Map<String, Any?>?): Recorder {
        val plugin = SentomaruFlutterOffline({ port }, { it.run() })
        val r = Recorder()
        plugin.onMethodCall(MethodCall(method, args), r)
        r.await()
        plugin.shutdown()
        return r
    }

    @Test fun handlesOnlyItsTwoMethods() {
        val o = SentomaruFlutterOffline({ null }, { it.run() })
        assertTrue(o.handles("offlineSeal")); assertTrue(o.handles("offlineReconcileBody"))
        for (m in listOf("sign", "txSign", "sealedLoad", "offline")) assertFalse(m, o.handles(m))
        o.shutdown()
    }

    @Test fun sealRunsOffTheCallerThreadAndReturnsThePortsMap() {
        val port = FakePort()
        val r = run(port, "offlineSeal", mapOf("permit" to "{\"p\":1}", "operationDigest" to ByteArray(32)))
        assertEquals(mapOf("seq" to 0, "digest" to 32), r.value)
        assertEquals("{\"p\":1}", port.permit)
        assertNotEquals(Thread.currentThread(), port.thread)
    }

    @Test fun aPermitMayArriveAsBytes() {
        val port = FakePort()
        run(port, "offlineSeal", mapOf("permit" to "{\"p\":2}".toByteArray(), "operationDigest" to ByteArray(32)))
        assertEquals("{\"p\":2}", port.permit)
    }

    @Test fun reconcileBodyPassesTheSealsInOrderAndReturnsBytes() {
        val port = FakePort()
        val r = run(port, "offlineReconcileBody", mapOf("permit" to "{}", "seals" to listOf(item(0), item(1))))
        assertArrayEquals("{}".toByteArray(), r.value as ByteArray)
        assertEquals(listOf(0, 1), port.seals!!.map { it["seq"] })
    }

    @Test fun missingOrWrongArgumentsAreInvalidRequestAndNeverReachThePort() {
        val port = FakePort()
        for (args in listOf<Map<String, Any?>?>(null, mapOf("operationDigest" to ByteArray(32)), mapOf("permit" to "{}"),
            mapOf("permit" to 5, "operationDigest" to ByteArray(32)), mapOf("permit" to "{}", "operationDigest" to "x"))) {
            assertEquals("InvalidRequest:PARAMS", run(port, "offlineSeal", args).error)
        }
        for (args in listOf<Map<String, Any?>?>(null, mapOf("permit" to "{}"), mapOf("permit" to "{}", "seals" to listOf("x")),
            mapOf("permit" to "{}", "seals" to "x"))) {
            assertEquals("InvalidRequest:PARAMS", run(port, "offlineReconcileBody", args).error)
        }
        assertNull(port.thread)
    }

    @Test fun beforeInitializeIsNotInitialized() {
        assertEquals("NotInitialized", run(null, "offlineSeal", mapOf("permit" to "{}", "operationDigest" to ByteArray(32))).error)
    }

    @Test fun everySdkErrorReachesDartUnderACodeDartMaps() {
        val expected = mapOf(
            OfflineChainError.PermitInvalid() to "Offline:PERMIT_INVALID", OfflineChainError.PermitExpired() to "Offline:PERMIT_EXPIRED",
            OfflineChainError.ChainFull() to "Offline:CHAIN_FULL", OfflineChainError.BadDigest() to "Offline:INVALID_DIGEST",
            OfflineChainError.StateUnavailable() to "StorageUnavailable",
        )
        for ((error, code) in expected) {
            val r = run(FakePort(SentomaruException(error)), "offlineSeal", mapOf("permit" to "{}", "operationDigest" to ByteArray(32)))
            assertEquals(error.code, code, r.error)
        }
        assertEquals("ChannelError", run(FakePort(IllegalStateException("x")), "offlineSeal", mapOf("permit" to "{}", "operationDigest" to ByteArray(32))).error)
        assertEquals("InvalidRequest:PARAMS", run(FakePort(IllegalArgumentException("x")), "offlineReconcileBody", mapOf("permit" to "{}", "seals" to listOf(item()))).error)
    }

    @Test fun sealRoundTripsThroughTheMapDartKeeps() {
        val seal = SentomaruFlutterOffline.seal(item(2))
        // Dart reads whole numbers as ints of any width, so compare by value.
        fun norm(m: Map<String, Any>) = m.mapValues { (_, v) -> if (v is Number) v.toLong() else v }
        assertEquals(norm(item(2)), norm(SentomaruFlutterOffline.sealReply(seal)))
    }

    @Test fun malformedSealsAreRefused() {
        val bad = listOf(
            item().minus("hash"), item() + ("seq" to "0"), item() + ("seq" to 128), item() + ("seq" to -1), item() + ("bootCount" to 4_294_967_296L),
            item() + ("operationDigest" to b64.encodeToString(ByteArray(31))), item() + ("prevHash" to "***"), item() + ("signature" to ""),
            item() + ("wallClockMillis" to 1.5), item() + ("elapsedRealtimeNanos" to -1L),
        )
        for (b in bad) assertThrows(b.toString(), IllegalArgumentException::class.java) { SentomaruFlutterOffline.seal(b) }
        // The sentinel boot count (boot_count unavailable) is valid.
        SentomaruFlutterOffline.seal(item() + ("bootCount" to 0xFFFFFFFFL))
    }
}
