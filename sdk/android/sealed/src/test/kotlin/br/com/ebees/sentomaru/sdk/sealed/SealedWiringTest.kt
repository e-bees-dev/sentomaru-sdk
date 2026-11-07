package br.com.ebees.sentomaru.sdk.sealed

import android.content.pm.PackageManager
import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Assert.fail
import org.junit.Test
import java.io.ByteArrayInputStream
import java.io.FileNotFoundException
import java.io.InputStream

/**
 * I3 of the review: the production wiring of [SentomaruSealed] ([assetsOf], [AssetSource], [readAtMost]) without a
 * `Context`. Failure classes: the canonical prefix not removed for the `AssetManager`, the package or `versionCode` not
 * the ones derived into the key, a missing asset not turned into "absent", an entry read whole before its size check,
 * and an unknown own package.
 */
class SealedWiringTest {
    private val case = Vectors.case("android-assets-and-strings")
    private val pkg = case["package"] as String

    /** `AssetManager.open` over the vectors: relative names only, as the platform takes them. */
    private class FakeAssets(entries: Map<String, ByteArray>) {
        val files = entries.mapKeys { (k, _) -> k.removePrefix("assets/") }
        val opened = mutableListOf<String>()
        fun open(name: String): InputStream {
            opened += name
            require(!name.startsWith("assets/")) { "AssetManager names are relative to assets/" }
            return ByteArrayInputStream(files[name] ?: throw FileNotFoundException(name))
        }
    }

    private fun code(block: () -> Unit): String = try {
        block()
        fail("expected SentomaruSealedException")
        error("unreachable")
    } catch (e: SentomaruSealedException) {
        e.code.wire
    }

    @Test
    fun `the wiring opens the vectors with the app's package and versionCode`() {
        val fake = FakeAssets(Vectors.entries(case))
        val seen = mutableListOf<String>()
        val assets = assetsOf(pkg, { seen += it; Vectors.versionCode(case) }, fake::open)
        val f = Vectors.files(case)[0]
        assertArrayEquals(Vectors.hex(f["plainHex"] as String), assets.bytes(f["path"] as String, allowPlainFallback = false))
        assertEquals("Olá, técnico", assets.string("saudacao", allowPlainFallback = false, plainStringsPath = null))
        assertEquals(listOf(pkg), seen)
        assertTrue(fake.opened.contains("sentomaru/sealed/header.bin"))
    }

    @Test
    fun `another versionCode or package derives another key`() {
        val f = Vectors.files(case)[0]["path"] as String
        val entries = Vectors.entries(case)
        assertEquals("integrity", code { assetsOf(pkg, { 8L }, FakeAssets(entries)::open).bytes(f, false) })
        assertEquals("integrity", code { assetsOf("br.com.ebees.outro", { 7L }, FakeAssets(entries)::open).bytes(f, false) })
    }

    @Test
    fun `a missing asset is absent, not an error of the format`() {
        val none = assetsOf(pkg, { 7L }, FakeAssets(emptyMap())::open)
        assertEquals("not-sealed", code { none.bytes("assets/regras/tabela.json", false) })
        try {
            none.bytes("assets/regras/tabela.json", true)
            fail("expected FileNotFoundException")
        } catch (e: FileNotFoundException) {
            // plain fallback of a missing file: as AssetManager.open
        }
    }

    @Test
    fun `an unknown own package is IllegalStateException`() {
        try {
            assetsOf(pkg, { throw PackageManager.NameNotFoundException() }, FakeAssets(emptyMap())::open)
            fail("expected IllegalStateException")
        } catch (e: IllegalStateException) {
            // documented on SentomaruSealed: no versionCode, no key
        }
    }

    @Test
    fun `readAtMost never reads past the limit`() {
        var read = 0
        val big = object : InputStream() {
            override fun read(): Int = if (read++ < 10_000_000) 0 else -1
            override fun read(b: ByteArray, off: Int, len: Int): Int {
                val n = minOf(len, 10_000_000 - read)
                if (n <= 0) return -1
                read += n
                return n
            }
        }
        assertEquals(SealedFormat.MAX_ENTRY + 1, readAtMost(big, SealedFormat.MAX_ENTRY + 1).size)
        assertEquals(SealedFormat.MAX_ENTRY + 1, read)
        assertEquals(3, readAtMost(ByteArrayInputStream(byteArrayOf(1, 2, 3)), 10).size)
    }

    @Test
    fun `an oversized entry is read only up to limit + 1 through the AssetSource`() {
        val entries = Vectors.entries(case)
        val name = SealedFormat.entryName(Vectors.files(case)[0]["path"] as String)
        entries[name] = entries.getValue(name) + ByteArray(SealedFormat.MAX_ENTRY)
        val source = AssetSource(FakeAssets(entries)::open)
        assertEquals(SealedFormat.MAX_ENTRY + 1, source.read(name, SealedFormat.MAX_ENTRY)!!.size)
        val reader = SealedReader(source, pkg, 7)
        assertEquals("integrity", code { reader.bytes(Vectors.files(case)[0]["path"] as String) })
    }
}
