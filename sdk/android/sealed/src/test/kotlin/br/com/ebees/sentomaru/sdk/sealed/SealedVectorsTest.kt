package br.com.ebees.sentomaru.sdk.sealed

import br.com.ebees.sentomaru.sdk.sealed.Vectors.hex
import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Assert.fail
import org.junit.Test
import java.nio.ByteBuffer
import java.security.MessageDigest
import java.util.zip.Deflater
import javax.crypto.Cipher
import javax.crypto.spec.GCMParameterSpec
import javax.crypto.spec.SecretKeySpec

/**
 * D-14b: the SDK reader against every case of the shared D-14a vectors, the same way the reference reader of
 * `verification/devsecops/test_sealed_vectors.py` does: each positive case opens to its plaintext, each negative case
 * fails with the listed code, and the two `probe` rules (sizes before AEAD, inflation capped at declared + 1) are
 * observed through the reader's seams. HKDF is checked against RFC 5869 (copied from the RFC, and in the vectors).
 */
class SealedVectorsTest {
    private fun reader(case: Map<String, Any?>, entries: Map<String, ByteArray> = Vectors.entries(case),
                       packageName: String = case["package"] as String, versionCode: Long = Vectors.versionCode(case),
                       aead: AeadOpen = AeadOpen.GCM, inflate: Inflate = Inflate.RAW) =
        SealedReader(MapSource(entries), packageName, versionCode, aead, inflate)

    private fun code(block: () -> Unit): String = try {
        block()
        fail("expected SentomaruSealedException")
        error("unreachable")
    } catch (e: SentomaruSealedException) {
        e.code.wire
    }

    @Test
    fun `HKDF reproduces RFC 5869 appendix A (SHA-256 cases)`() {
        // Copied from RFC 5869, Appendix A; the vectors carry the same values.
        val rfc = mapOf(
            "A.1" to "3cb25f25faacd57a90434f64d0362f2a2d2d0a90cf1a5a4c5db02d56ecc4c5bf34007208d5b887185865",
            "A.2" to "b11e398dc80327a1c8e7f78c596a49344f012eda2d4efad8a050cc4c19afa97c59045a99cac7827271cb41c65e590e09" +
                "da3275600c2f09b8367793a9aca3db71cc30c58179ec3e87c14c01d5c1f3434f1d87",
            "A.3" to "8da4e775a563c18f715f802a063c5a31b8a11f5c5ee1879ec3454e5f3c738d2d9d201395faa4b61a96c8",
        )
        @Suppress("UNCHECKED_CAST")
        val cases = Vectors.all["hkdfRfc5869"] as List<Map<String, Any?>>
        assertEquals(rfc.keys, cases.map { it["case"] }.toSet())
        for (v in cases) {
            val okm = Hkdf.derive(Vectors.hex(v["ikmHex"] as String), Vectors.hex(v["saltHex"] as String),
                Vectors.hex(v["infoHex"] as String), (v["length"] as Long).toInt())
            assertEquals(v["case"] as String, rfc[v["case"]], okm.hex())
            assertEquals(v["okmHex"], okm.hex())
        }
    }

    @Test
    fun `K_fmt is the published constant`() {
        @Suppress("UNCHECKED_CAST")
        val kFmt = Vectors.all["kFmt"] as Map<String, Any?>
        assertEquals(kFmt["hex"], SealedFormat.K_FMT.hex())
        val text = "Sentomaru sealed assets format v1 public constant"
        assertTrue(kFmt["derivation"].toString().contains(text))
        assertEquals(kFmt["hex"], MessageDigest.getInstance("SHA-256").digest(text.toByteArray(Charsets.US_ASCII)).hex())
    }

    @Test
    fun `reader limits match the published ones`() {
        assertEquals(
            mapOf("headerBytes" to SealedFormat.MAX_HEADER.toLong(), "entryBytes" to SealedFormat.MAX_ENTRY.toLong(),
                "declaredLength" to SealedFormat.MAX_FILE.toLong(), "inflateStopsAt" to "declared + 1"),
            Vectors.all["readerLimits"])
    }

    @Test
    fun `key derivations and entry names match the vectors`() {
        for (case in Vectors.cases) {
            @Suppress("UNCHECKED_CAST")
            val kek = case["kek"] as Map<String, Any?>
            @Suppress("UNCHECKED_CAST")
            val testOnly = case["testOnly"] as Map<String, Any?>
            val salt = Vectors.hex(testOnly["saltHex"] as String)
            assertEquals(kek["kekHex"], Hkdf.derive(SealedFormat.K_FMT, salt, utf8(kek["hkdfInfo"] as String)).hex())
            val dek = Vectors.hex(testOnly["dekHex"] as String)
            for (f in Vectors.files(case)) {
                assertEquals(f["keyHex"], Hkdf.derive(dek, ByteArray(0), utf8("asset|${f["path"]}")).hex())
                assertEquals(f["sealedEntry"], SealedFormat.entryName(f["path"] as String))
            }
        }
    }

    @Test
    fun `every file of every case opens to its plaintext`() {
        var opened = 0
        for (case in Vectors.cases) {
            val reader = reader(case)
            for (f in Vectors.files(case)) {
                assertEquals(f["path"] as String, f["plainHex"], reader.bytes(f["path"] as String).hex())
                opened++
            }
            @Suppress("UNCHECKED_CAST")
            for (lookup in case["lookups"] as List<Map<String, Any?>>) {
                assertEquals(lookup["key"] as String, lookup["value"], reader.string(lookup["key"] as String))
            }
            if (Vectors.header(case)["stringsPath"] == null) assertEquals("not-sealed", code { reader.string("qualquer") })
        }
        assertEquals(4, opened)
    }

    @Test
    fun `the header is opened once per reader, the entries on every call`() {
        val case = Vectors.case("android-assets-and-strings")
        val source = MapSource(Vectors.entries(case))
        val reader = SealedReader(source, case["package"] as String, Vectors.versionCode(case))
        val path = Vectors.files(case)[0]["path"] as String
        repeat(3) { reader.bytes(path) }
        assertEquals(1, source.reads[SealedFormat.HEADER])
        assertEquals(3, source.reads[SealedFormat.entryName(path)])
    }

    @Test
    fun `every negative case fails with the listed code`() {
        val names = Vectors.negative.map { it["name"] }
        assertEquals(names.size, names.toSet().size)
        assertEquals(setOf("not-sealed", "integrity", "format-unsupported"), Vectors.negative.map { it["error"] }.toSet())
        for (spec in Vectors.negative) {
            val case = Vectors.case(spec["case"] as String)
            @Suppress("UNCHECKED_CAST")
            val asOther = spec["as"] as Map<String, Any?>? ?: emptyMap()
            val inflateCalls = mutableListOf<Int>()
            val probe = spec["probe"] as String?
            var armed = false
            val aead = AeadOpen { key, nonce, sealed, aad ->
                if (armed) throw AssertionError("AEAD ran before the size check")
                AeadOpen.GCM.open(key, nonce, sealed, aad)
            }
            val inflate = Inflate { data, max -> inflateCalls += max; Inflate.RAW.inflate(data, max) }
            val packageName = asOther["package"] as String? ?: case["package"] as String
            val versionCode = asOther["versionCode"] as Long? ?: Vectors.versionCode(case)
            val reader = reader(case, Vectors.mutated(case, spec), packageName, versionCode, aead, inflate)
            // The header is opened (and kept) first with the real AEAD; a probe on an entry watches only the entry.
            if (probe != null && spec["target"] != "header") reader.headerOrNull()
            armed = probe == "before-aead"
            val read = spec["read"]
            @Suppress("UNCHECKED_CAST")
            val got = try {
                code {
                    if (read is Map<*, *>) reader.string((read as Map<String, Any?>)["string"] as String) else reader.bytes(read as String)
                }
            } catch (e: AssertionError) {
                throw AssertionError("${spec["name"]}: ${e.message}")   // name the case that opened
            }
            assertEquals(spec["name"] as String, spec["error"], got)
            if (probe == "inflate-cap") assertEquals(spec["name"] as String, listOf(101), inflateCalls)
        }
    }

    @Test
    fun `the reader is not bound to the compressed bytes`() {
        val case = Vectors.case("android-assets-and-strings")
        val f = Vectors.files(case)[0]
        val plain = Vectors.hex(f["plainHex"] as String)
        val deflater = Deflater(1, true)
        deflater.setInput(plain)
        deflater.finish()
        val buf = ByteArray(plain.size + 64)
        val deflated = buf.copyOf(deflater.deflate(buf))
        deflater.end()
        assertTrue(deflated.hex() != f["deflatedHex"])
        val nonce = Vectors.hex(f["nonceHex"] as String)
        val cipher = Cipher.getInstance("AES/GCM/NoPadding")
        cipher.init(Cipher.ENCRYPT_MODE, SecretKeySpec(Vectors.hex(f["keyHex"] as String), "AES"), GCMParameterSpec(128, nonce))
        cipher.updateAAD(utf8(f["aad"] as String))
        val sealed = cipher.doFinal(deflated)
        val entries = Vectors.entries(case)
        entries[f["sealedEntry"] as String] = "SNTA".toByteArray() + byteArrayOf(1) +
            ByteBuffer.allocate(4).putInt(plain.size).array() + nonce + sealed
        assertArrayEquals(plain, reader(case, entries).bytes(f["path"] as String))
    }

    @Test
    fun `an absent strings key is null, a present empty value is empty`() {
        val reader = reader(Vectors.case("android-assets-and-strings"))
        assertNull(reader.string("ausente"))
        assertEquals("", reader.string("z_9"))
    }
}
