package br.com.ebees.sentomaru.capacitor

import br.com.ebees.sentomaru.hybrid.SealedReadError
import br.com.ebees.sentomaru.hybrid.SentomaruBridge
import br.com.ebees.sentomaru.sdk.sealed.SentomaruSealedException
import org.junit.Assert.assertEquals
import org.junit.Assert.assertThrows
import org.junit.Test
import java.io.FileNotFoundException

/**
 * D-14b: the pure logic the Capacitor layer adds around the shared [SentomaruBridge.SealedReader] (`sealedReader`,
 * `wrapSealedRead`). Not the dispatch itself: `SentomaruBridge.onMethodCall` posts every reply through a real
 * `android.os.Handler(Looper.getMainLooper())`, which the Android unit-test stub jar no-ops (same limitation as
 * `sign`, `initialize` and every other method of that class; nothing new here). A real `sealedLoad`/`sealedString`
 * round trip needs a device or an instrumented test, not covered by this change.
 */
class SealedReaderTest {
    @Test fun aSuccessfulReadPassesThrough() {
        assertEquals("ok", wrapSealedRead { "ok" })
    }

    @Test fun theSdksSealedExceptionBecomesTheWireCode() {
        val error = assertThrows(SealedReadError::class.java) {
            wrapSealedRead<Unit> { throw SentomaruSealedException(SentomaruSealedException.Code.INTEGRITY) }
        }
        assertEquals("integrity", error.code)
    }

    @Test fun aMissingAssetWithThePlainFallbackIsAssetNotFound() {
        val error = assertThrows(SealedReadError::class.java) {
            wrapSealedRead<Unit> { throw FileNotFoundException("x") }
        }
        assertEquals("AssetNotFound", error.code)
    }

    @Test fun theSharedKeyRuleRefusesAnEmptyOrTraversingOrOversizedKey() {
        val bridge = SentomaruBridge({ null })
        assertEquals(true, bridge.validSealedKey("assets/dados/x.bin"))
        for (bad in listOf("", ".", "..", "a/./b", "a/../b", "a".repeat(513))) {
            assertEquals(bad, false, bridge.validSealedKey(bad))
        }
    }
}
